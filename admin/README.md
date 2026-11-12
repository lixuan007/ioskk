# 后台管理（Flask）

最简 Flask 后台：MySQL + Telegram 登录验证码。

## 目录

```
admin/
  app.py
  .env
  requirements.txt
  templates/
  static/
```

## 安装

```bash
cd admin
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # 已有 .env 可跳过
```

## 运行

本地开发建议把 `.env` 里 `SESSION_SECURE_COOKIE=false`（否则非 HTTPS 下 session cookie 可能写不进去）。

```bash
python app.py
```

访问：http://127.0.0.1:5000

## 登录

1. 输入 `operators` 表里的 `name` / `password`
2. 点「发送验证码」→ 验证码发到 Telegram（`TG_ADMIN_ID` / `TG_CHAT_ID`）
3. 填验证码后登录

管理员需先给 Bot 发过 `/start`，否则私聊发不出消息。

## 功能

- 左上角：后台管理
- 右上角：登录账号 / 修改密码 / 退出
- 左侧菜单：设备管理、钱包管理
- 右侧：对应列表（读 `devices` / `wallets` 表，没有表则显示空）
