import os
import random
import string
import time
from functools import wraps

import bcrypt
import pymysql
import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

load_dotenv()

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("APP_KEY", "dev-secret")
app.permanent_session_lifetime = int(os.getenv("SESSION_LIFETIME", "480")) * 60
app.config["SESSION_COOKIE_HTTPONLY"] = os.getenv("SESSION_HTTP_ONLY", "true").lower() == "true"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_SECURE_COOKIE", "false").lower() == "true"
app.config["SESSION_COOKIE_SAMESITE"] = os.getenv("SESSION_SAME_SITE", "lax")

APP_NAME = os.getenv("APP_NAME", "后台管理").strip('"')
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "").strip()
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "").strip()
TG_ADMIN_ID = os.getenv("TG_ADMIN_ID", "").strip()
TG_NOTIFY_ENABLED = os.getenv("TG_NOTIFY_ENABLED", "false").lower() == "true"

# 内存验证码：{name: {"code": "123456", "expire": ts}}
login_codes = {}


def db():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USERNAME", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_DATABASE", "collector"),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


def check_password(plain: str, stored: str) -> bool:
    if not plain or not stored:
        return False
    stored = stored.strip()
    if stored.startswith("$2"):
        try:
            return bcrypt.checkpw(plain.encode("utf-8"), stored.encode("utf-8"))
        except Exception:
            return False
    return plain == stored


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(
        plain.encode("utf-8"),
        bcrypt.gensalt(rounds=BCRYPT_ROUNDS),
    ).decode("utf-8")


def get_operator(name: str):
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT name, password FROM operators WHERE name=%s LIMIT 1", (name,))
            return cur.fetchone()
    finally:
        conn.close()


def update_operator_password(name: str, new_password: str):
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE operators SET password=%s WHERE name=%s",
                (hash_password(new_password), name),
            )
    finally:
        conn.close()


def send_telegram(text: str) -> bool:
    if not TG_BOT_TOKEN:
        return False
    chat_ids = []
    if TG_ADMIN_ID:
        chat_ids.append(TG_ADMIN_ID)
    if TG_CHAT_ID and TG_CHAT_ID not in chat_ids:
        chat_ids.append(TG_CHAT_ID)
    if not chat_ids:
        return False
    ok = False
    for chat_id in chat_ids:
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": text},
                timeout=10,
            )
            if r.ok and r.json().get("ok"):
                ok = True
        except Exception:
            pass
    return ok


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("operator"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    if session.get("operator"):
        return redirect(url_for("devices"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("operator"):
        return redirect(url_for("devices"))

    if request.method == "POST":
        action = request.form.get("action", "login")
        name = (request.form.get("name") or "").strip()
        password = request.form.get("password") or ""
        code = (request.form.get("code") or "").strip()

        want_json = (
            action == "send_code"
            or request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or "application/json" in (request.headers.get("Accept") or "")
        )

        if not name or not password:
            if want_json and action == "send_code":
                return jsonify(ok=False, msg="请输入账号和密码")
            flash("请输入账号和密码", "error")
            return render_template("login.html", app_name=APP_NAME, name=name)

        op = get_operator(name)
        if not op or not check_password(password, op.get("password", "")):
            if want_json and action == "send_code":
                return jsonify(ok=False, msg="账号或密码错误")
            flash("账号或密码错误", "error")
            return render_template("login.html", app_name=APP_NAME, name=name)

        if action == "send_code":
            verify_code = "".join(random.choices(string.digits, k=6))
            login_codes[name] = {"code": verify_code, "expire": time.time() + 300}
            msg = f"【{APP_NAME}】登录验证码：{verify_code}\n账号：{name}\n5分钟内有效"
            if send_telegram(msg):
                return jsonify(ok=True, msg="验证码已发送到 Telegram")
            return jsonify(ok=False, msg="验证码发送失败，请检查 Telegram 配置")

        # 登录
        cached = login_codes.get(name)
        if not cached or time.time() > cached["expire"]:
            flash("请先获取验证码", "error")
            return render_template("login.html", app_name=APP_NAME, name=name)
        if code != cached["code"]:
            flash("验证码错误", "error")
            return render_template("login.html", app_name=APP_NAME, name=name)

        login_codes.pop(name, None)
        session.permanent = True
        session["operator"] = name
        return redirect(url_for("devices"))

    return render_template("login.html", app_name=APP_NAME, name="")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    name = session["operator"]
    current = request.form.get("current_password") or ""
    new_pwd = request.form.get("new_password") or ""
    confirm = request.form.get("confirm_password") or ""
    next_url = request.form.get("next") or url_for("devices")

    if not new_pwd or len(new_pwd) < 4:
        flash("新密码至少 4 位", "error")
        return redirect(next_url)
    if new_pwd != confirm:
        flash("两次输入的新密码不一致", "error")
        return redirect(next_url)

    op = get_operator(name)
    if not op or not check_password(current, op.get("password", "")):
        flash("当前密码错误", "error")
        return redirect(next_url)

    update_operator_password(name, new_pwd)
    flash("密码修改成功", "ok")
    return redirect(next_url)


@app.route("/devices")
@login_required
def devices():
    rows = []
    error = None
    try:
        conn = db()
        try:
            with conn.cursor() as cur:
                cur.execute("SHOW TABLES LIKE 'devices'")
                if cur.fetchone():
                    cur.execute("SELECT * FROM devices ORDER BY id DESC LIMIT 200")
                    rows = cur.fetchall()
        finally:
            conn.close()
    except Exception as e:
        error = str(e)
    return render_template(
        "devices.html",
        app_name=APP_NAME,
        operator=session["operator"],
        rows=rows,
        error=error,
        active="devices",
    )


@app.route("/wallets")
@login_required
def wallets():
    rows = []
    error = None
    try:
        conn = db()
        try:
            with conn.cursor() as cur:
                cur.execute("SHOW TABLES LIKE 'wallets'")
                if cur.fetchone():
                    cur.execute("SELECT * FROM wallets ORDER BY id DESC LIMIT 200")
                    rows = cur.fetchall()
        finally:
            conn.close()
    except Exception as e:
        error = str(e)
    return render_template(
        "wallets.html",
        app_name=APP_NAME,
        operator=session["operator"],
        rows=rows,
        error=error,
        active="wallets",
    )


if __name__ == "__main__":
    # 本地开发可把 SESSION_SECURE_COOKIE 设为 false
    debug = os.getenv("APP_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug)
