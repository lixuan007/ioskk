"""Official permissionless liquidation keeper for public lending protocols.

Legal scope only: Aave V2/V3, Radiant, and Compound-style pools that already
expose public liquidate functions. The operator wallet is the caller's own
address. Every path is eth_call-simulated before any broadcast.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import html
import json
import logging
import os
import signal
import sys
import time
from collections import deque
from collections.abc import MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Iterable, Protocol

import aiohttp
from eth_abi import decode, encode
from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_utils import (
    event_signature_to_log_topic,
    function_signature_to_4byte_selector,
    to_checksum_address,
)
from web3 import AsyncWeb3
from web3.middleware import ExtraDataToPOAMiddleware
from web3.providers.persistent import WebSocketProvider
from web3.providers.rpc import AsyncHTTPProvider
from web3.types import HexBytes, RPCEndpoint, TxParams

try:
    from solana.rpc.async_api import AsyncClient as SolanaAsyncClient
except ImportError:  # pragma: no cover
    SolanaAsyncClient = None  # type: ignore[misc, assignment]


# ---------------------------------------------------------------------------
# Official function / event signatures (well-known public ABIs only)
# ---------------------------------------------------------------------------

AAVE_LIQUIDATION_SIG: Final = "liquidationCall(address,address,address,uint256,bool)"
COMPOUND_LIQUIDATE_SIG: Final = "liquidateBorrow(address,uint256,address)"
CETHER_LIQUIDATE_SIG: Final = "liquidateBorrow(address,address)"
AAVE_ACCOUNT_DATA_SIG: Final = "getUserAccountData(address)"
AAVE_USER_CONFIG_SIG: Final = "getUserConfiguration(address)"
AAVE_RESERVES_LIST_SIG: Final = "getReservesList()"
COMPTROLLER_LIQUIDITY_SIG: Final = "getAccountLiquidity(address)"
COMPTROLLER_MARKETS_SIG: Final = "getAllMarkets()"
COMPTROLLER_ASSETS_IN_SIG: Final = "getAssetsIn(address)"
COMPTROLLER_ORACLE_SIG: Final = "oracle()"
CTOKEN_SNAPSHOT_SIG: Final = "getAccountSnapshot(address)"
ORACLE_UNDERLYING_PRICE_SIG: Final = "getUnderlyingPrice(address)"

AAVE_LIQUIDATION_TOPIC: Final = event_signature_to_log_topic(
    "LiquidationCall(address,address,address,uint256,uint256,address,bool)"
)
AAVE_BORROW_TOPIC_V3: Final = event_signature_to_log_topic(
    "Borrow(address,address,address,uint256,uint8,uint256,uint16)"
)
AAVE_BORROW_TOPIC_V2: Final = event_signature_to_log_topic(
    "Borrow(address,address,address,uint256,uint256,uint256,uint16)"
)
COMPOUND_BORROW_TOPIC: Final = event_signature_to_log_topic(
    "Borrow(address,uint256,uint256,uint256)"
)
COMPOUND_LIQUIDATE_TOPIC: Final = event_signature_to_log_topic(
    "LiquidateBorrow(address,address,uint256,address,uint256)"
)

AAVE_LIQUIDATION_SELECTOR: Final = function_signature_to_4byte_selector(AAVE_LIQUIDATION_SIG)
COMPOUND_LIQUIDATE_SELECTOR: Final = function_signature_to_4byte_selector(COMPOUND_LIQUIDATE_SIG)
CETHER_LIQUIDATE_SELECTOR: Final = function_signature_to_4byte_selector(CETHER_LIQUIDATE_SIG)

WAD: Final = 10**18
USD8: Final = 10**8
UINT256_MAX: Final = 2**256 - 1

# Official public JSON-RPC gateways (no API key). Override with ETH/BNB/SOL_RPC_URL.
OFFICIAL_ETH_HTTP: Final = "https://ethereum.publicnode.com"
OFFICIAL_BNB_HTTP: Final = "https://bsc-dataseed.binance.org"
OFFICIAL_SOL_HTTP: Final = "https://api.mainnet-beta.solana.com"


# ---------------------------------------------------------------------------
# Testable helpers
# ---------------------------------------------------------------------------

def selector_hex(signature: str) -> str:
    return "0x" + function_signature_to_4byte_selector(signature).hex()


def encode_aave_liquidation_call(
    collateral_asset: str,
    debt_asset: str,
    user: str,
    debt_to_cover: int,
    receive_a_token: bool = False,
) -> bytes:
    """Encode official Aave / Radiant Pool.liquidationCall."""
    return AAVE_LIQUIDATION_SELECTOR + encode(
        ["address", "address", "address", "uint256", "bool"],
        [
            to_checksum_address(collateral_asset),
            to_checksum_address(debt_asset),
            to_checksum_address(user),
            int(debt_to_cover),
            bool(receive_a_token),
        ],
    )


def encode_compound_liquidate_borrow(
    borrower: str,
    repay_amount: int,
    ctoken_collateral: str,
) -> bytes:
    """Encode official CToken/vToken.liquidateBorrow(borrower, repayAmount, cTokenCollateral)."""
    return COMPOUND_LIQUIDATE_SELECTOR + encode(
        ["address", "uint256", "address"],
        [
            to_checksum_address(borrower),
            int(repay_amount),
            to_checksum_address(ctoken_collateral),
        ],
    )


def encode_cether_liquidate_borrow(borrower: str, ctoken_collateral: str) -> bytes:
    """Encode official CEther.liquidateBorrow(borrower, cTokenCollateral)."""
    return CETHER_LIQUIDATE_SELECTOR + encode(
        ["address", "address"],
        [to_checksum_address(borrower), to_checksum_address(ctoken_collateral)],
    )


def encode_address_call(signature: str, address: str) -> bytes:
    return function_signature_to_4byte_selector(signature) + encode(
        ["address"], [to_checksum_address(address)]
    )


def exceeds_min_usd(value_usd: float, min_usd: float) -> bool:
    """Prefilter: only positions/markets at or above the USD floor proceed to simulation."""
    if min_usd <= 0:
        return True
    return value_usd >= min_usd


CHAIN_ALIASES: Final[dict[str, str]] = {
    "ethereum": "【ETH 链】",
    "eth": "【ETH 链】",
    "bsc": "【BNB 链】",
    "bnb": "【BNB 链】",
    "binance": "【BNB 链】",
    "solana": "【SOL 链】",
    "sol": "【SOL 链】",
}


def chain_alias(chain: Any) -> str:
    """User-facing chain label from the per-chain object, never a shared global.

    Concurrent ETH/BNB scanners must each print their own bound alias.
    """
    bound = getattr(chain, "alias", None)
    if isinstance(bound, str) and bound.startswith("【"):
        return bound
    raw = getattr(chain, "name", None)
    key = str(raw if raw is not None else chain).strip().lower()
    key = key.replace("【", "").replace("】", "").replace(" 链", "").replace("链", "")
    return CHAIN_ALIASES.get(key, f"【{key} 链】")


def native_ether_amount(wei: int) -> float:
    """Convert wei with the same `from_wei(..., 'ether')` path as web3.py."""
    return float(AsyncWeb3.from_wei(int(wei), "ether"))


def exceeds_native_floor(wei: int, min_native: float) -> bool:
    """True only when official pool/cToken native coin is strictly greater than the floor."""
    if min_native <= 0:
        return True
    return native_ether_amount(wei) > min_native


def normalize_tx_to(tx_to: Any) -> str | None:
    """Return checksum `to`, or None for contract-creation / empty destination."""
    if tx_to is None:
        return None
    text = str(tx_to).strip()
    if text in {"", "0x", "0X", "None", "none"}:
        return None
    try:
        return to_checksum_address(text)
    except (ValueError, TypeError):
        return None


def keep_protocol_tx(tx_to: Any, watched: set[str]) -> bool:
    """Keep txs whose `to` is a watched official pool/cToken.

    Drops EOA-to-EOA, unknown contracts, and empty-`to` creations. Creations are
    never liquidation targets.
    """
    addr = normalize_tx_to(tx_to)
    if addr is None:
        return False
    watched_l = {item.lower() for item in watched}
    return addr.lower() in watched_l


async def await_block_number(w3: AsyncWeb3) -> int:
    """web3.py 7: `block_number` is awaitable; prefer get_block_number when present."""
    getter = getattr(w3.eth, "get_block_number", None)
    if callable(getter):
        value = getter()
        if asyncio.iscoroutine(value):
            return int(await value)
        return int(value)
    return int(await w3.eth.block_number)


def fingerprint(*parts: object) -> str:
    raw = "|".join(str(p).lower() for p in parts)
    return hashlib.md5(raw.encode("utf-8")).hexdigest()


def address_from_topic(topic: bytes | HexBytes | str) -> str:
    if isinstance(topic, str):
        data = bytes.fromhex(topic[2:] if topic.startswith("0x") else topic)
    else:
        data = bytes(topic)
    return to_checksum_address(data[-20:])


def decode_user_config_bits(
    data: int, reserves: list[str]
) -> tuple[list[str], list[str]]:
    """Split Aave UserConfigurationMap into collateral vs debt underlyings."""
    collaterals: list[str] = []
    debts: list[str] = []
    for index, reserve in enumerate(reserves):
        if (data >> (index * 2)) & 1:
            collaterals.append(reserve)
        if (data >> (index * 2 + 1)) & 1:
            debts.append(reserve)
    return collaterals, debts


def parse_compound_borrow_borrower(data: bytes | HexBytes | str) -> str:
    raw = (
        bytes.fromhex(data[2:] if data.startswith("0x") else data)
        if isinstance(data, str)
        else bytes(data)
    )
    borrower, _amount, _account_borrows, _total = decode(
        ["address", "uint256", "uint256", "uint256"], raw
    )
    return to_checksum_address(borrower)


def env_str(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def script_dir_env_path() -> Path:
    """`.env` next to this file — not the process cwd (BaoTa often differs)."""
    return Path(__file__).resolve().parent / ".env"


def parse_dotenv_text(text: str) -> dict[str, str]:
    """Minimal KEY=VALUE parser. Comments/blanks skipped; optional quotes stripped."""
    parsed: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        parsed[key] = value
    return parsed


def apply_parsed_env(
    values: dict[str, str],
    environ: MutableMapping[str, str] | None = None,
) -> int:
    """Apply parsed pairs. Do not overwrite already-set non-empty environment values."""
    env = os.environ if environ is None else environ
    applied = 0
    for key, value in values.items():
        if str(env.get(key, "")).strip():
            continue
        env[key] = value
        applied += 1
    return applied


def load_script_dir_env(
    path: Path | None = None,
    environ: MutableMapping[str, str] | None = None,
) -> tuple[Path, bool]:
    """Always load script-dir `.env`. Built-in parser; python-dotenv is optional extra."""
    env_path = path if path is not None else script_dir_env_path()
    exists = env_path.is_file()
    if exists:
        try:
            text = env_path.read_text(encoding="utf-8")
        except OSError:
            text = ""
        else:
            apply_parsed_env(parse_dotenv_text(text), environ)
    try:
        from dotenv import load_dotenv as _load_dotenv

        _load_dotenv(dotenv_path=str(env_path), override=False)
    except Exception:
        pass
    return env_path, env_path.is_file()


def resolve_rpc_url(configured: str, official: str) -> str:
    """Use the operator URL when set; otherwise the official public JSON-RPC gateway."""
    url = (configured or "").strip()
    return url or official


def missing_rpc_hint(alias: str, env_path: Path | str, exists: bool) -> str:
    status = "存在" if exists else "不存在"
    return f"{alias} 未配置 JSON-RPC HTTP，已尝试 {env_path}（{status}）"


def env_int(name: str, default: int | None = None) -> int | None:
    raw = os.environ.get(name, "").strip()
    if raw == "":
        return default
    return int(raw, 0)


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    return float(raw) if raw else default


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if raw == "":
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean for {name}: {raw!r}")


def csv_addresses(raw: str) -> list[str]:
    out: list[str] = []
    for part in raw.split(","):
        item = part.strip()
        if not item:
            continue
        out.append(to_checksum_address(item))
    return out


def is_execution_revert(exc: BaseException) -> bool:
    name = type(exc).__name__.lower()
    msg = _exc_head(exc).lower()
    return (
        "revert" in msg
        or "execution reverted" in msg
        or name in {"contractlogicerror", "contractcustomerror"}
    )


def _exc_head(exc: BaseException, limit: int = 400) -> str:
    """First characters of an exception only — never the full HTML body."""
    try:
        text = str(exc)
    except Exception:
        return type(exc).__name__
    return text[:limit]


def body_head(raw: Any, limit: int = 240) -> str:
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray, memoryview)):
        chunk = bytes(raw[:limit])
        return chunk.decode("utf-8", errors="replace")
    return str(raw)[:limit]


def looks_like_html(text: str) -> bool:
    sample = text.lstrip().lower()
    return (
        sample.startswith("<!doctype")
        or sample.startswith("<html")
        or "<!doctype html" in sample
        or sample.startswith("<head")
        or "<html" in sample[:160]
    )


def looks_like_non_json_rpc(text: str) -> bool:
    sample = text.lstrip()
    if not sample:
        return False
    if looks_like_html(sample):
        return True
    if sample[0] in "{[":
        return False
    lowered = sample.lower()
    return (
        "expecting value" in lowered
        or "not valid json" in lowered
        or "could not decode" in lowered
        or "badresponseformat" in lowered
    )


class NonJsonRpcError(RuntimeError):
    """JSON-RPC endpoint returned HTML or other non-JSON. Message never includes the body."""

    def __init__(self, kind: str = "nonjson") -> None:
        self.kind = kind
        super().__init__(kind)


def rpc_url_env_for_alias(alias: str) -> str:
    if "ETH" in alias:
        return "ETH_RPC_URL"
    if "BNB" in alias:
        return "BNB_RPC_URL"
    if "SOL" in alias:
        return "SOL_RPC_URL"
    return "RPC_URL"


def classify_rpc_error(exc: BaseException) -> str | None:
    """html | nonjson | ratelimit | transient, or None for logic/revert."""
    if is_execution_revert(exc):
        return None
    if isinstance(exc, NonJsonRpcError):
        return exc.kind if exc.kind in {"html", "nonjson"} else "nonjson"
    if isinstance(
        exc,
        (
            TimeoutError,
            asyncio.TimeoutError,
            ConnectionError,
            aiohttp.ClientError,
            json.JSONDecodeError,
            OSError,
        ),
    ):
        head = _exc_head(exc)
        if looks_like_html(head):
            return "html"
        if isinstance(exc, json.JSONDecodeError) or looks_like_non_json_rpc(head):
            return "nonjson"
        if _is_rate_limit_text(head):
            return "ratelimit"
        return "transient"
    head = _exc_head(exc)
    if looks_like_html(head):
        return "html"
    if looks_like_non_json_rpc(head) or "badresponseformat" in head.lower():
        return "nonjson"
    if _is_rate_limit_text(head):
        return "ratelimit"
    if _is_poa_extradata(exc):
        return "transient"
    needles = (
        "timeout",
        "timed out",
        "connection",
        "reset by peer",
        "broken pipe",
        "503",
        "502",
        "504",
        "cloudflare",
        "-32005",
        "server error",
        "temporary",
        "econnreset",
        "eai_again",
    )
    lowered = head.lower()
    if any(needle in lowered for needle in needles):
        return "transient"
    return None


def _is_rate_limit_text(text: str) -> bool:
    lowered = text.lower()
    return "429" in lowered or "too many requests" in lowered or "rate limit" in lowered


def _is_poa_extradata(exc: BaseException) -> bool:
    name = type(exc).__name__.lower()
    head = _exc_head(exc).lower()
    return "extradatalengtherror" in name or (
        "extradata" in head and ("poa" in head or "should be 32" in head)
    )


def attach_poa_middleware(w3: AsyncWeb3) -> None:
    """BNB and other POA chains return extraData > 32 bytes; required for get_block."""
    onion = getattr(w3, "middleware_onion", None)
    if onion is None:
        return
    try:
        onion.inject(ExtraDataToPOAMiddleware, "poa", layer=0)
    except ValueError:
        return
    except Exception:
        try:
            onion.inject(ExtraDataToPOAMiddleware, layer=0)
        except Exception:
            return


def is_transient_rpc_error(exc: BaseException) -> bool:
    """Network / 429 / HTML / non-JSON: reconnect and continue. Not used for logic bugs."""
    return classify_rpc_error(exc) is not None


def short_rpc_hint(alias: str, kind: str) -> str:
    env_name = rpc_url_env_for_alias(alias)
    if kind == "html":
        return f"{alias}收到网页而非 JSON-RPC，请检查 {env_name}"
    if kind == "nonjson":
        return f"{alias}收到非 JSON 响应，请检查 {env_name}"
    if kind == "ratelimit":
        return f"{alias}请求过于频繁(429)，将重连"
    return f"{alias}RPC 瞬时错误，将重连"


def log_rpc_issue(
    logger: logging.Logger,
    alias: str,
    kind: str,
    seen: dict[tuple[str, str], float],
    *,
    cooldown_sec: float = 20.0,
) -> None:
    """One short Chinese line per chain/kind; never the HTML body."""
    key = (alias, kind)
    now = time.monotonic()
    last = seen.get(key, 0.0)
    if now - last < cooldown_sec:
        return
    seen[key] = now
    logger.warning("%s", short_rpc_hint(alias, kind))


class OmitHtmlLogFilter(logging.Filter):
    """Drop records that embed webpage/HTML bodies so stdout cannot flood."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            record.msg = "log record omitted"
            record.args = ()
            return True
        if looks_like_html(msg):
            return False
        if len(msg) > 400 and ("<html" in msg.lower() or "<!doctype" in msg.lower()):
            return False
        return True


class TransientRpcError(RuntimeError):
    """Raised after retries are exhausted on a transient RPC failure. Short text only."""


# ---------------------------------------------------------------------------
# Config + protocol registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProtocolMarket:
    chain: str
    name: str
    style: str  # "aave" | "compound"
    address: str
    base: str = "usd8"  # "usd8" | "eth18"


def _checksum(addr: str) -> str:
    return to_checksum_address(addr)


def builtin_protocols() -> list[ProtocolMarket]:
    return [
        ProtocolMarket("ethereum", "aave_v3", "aave", _checksum("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"), "usd8"),
        ProtocolMarket("ethereum", "aave_v2", "aave", _checksum("0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9"), "eth18"),
        ProtocolMarket("ethereum", "compound_v2", "compound", _checksum("0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B"), "usd8"),
        ProtocolMarket("bsc", "aave_v3", "aave", _checksum("0x6807dc923806fE8Fd134338EABCA509979a7e0cB"), "usd8"),
        ProtocolMarket("bsc", "radiant_v2", "aave", _checksum("0xCcf31D54C3A94f67b8cEFF8DD771DE5846dA032c"), "usd8"),
        ProtocolMarket("bsc", "venus", "compound", _checksum("0xfD36E2c2a6789Db23113685031d7F16329158384"), "usd8"),
    ]


@dataclass
class AppConfig:
    eth_rpc_url: str
    bnb_rpc_url: str
    sol_rpc_url: str
    eth_ws_url: str
    bnb_ws_url: str
    evm_address: str
    evm_private_key: str = field(repr=False, default="")
    sol_address: str = ""
    sol_private_key: str = field(repr=False, default="")
    telegram_bot_token: str = field(repr=False, default="")
    telegram_chat_id: str = ""
    start_block: int | None = None
    end_block: int | None = None
    min_usd: float = 2.0
    min_native: float = 0.05
    eth_usd: float = 3000.0
    concurrency: int = 1
    log_chunk_blocks: int = 2000
    poll_interval_sec: float = 4.0
    live_lookback_blocks: int = 3
    dry_run: bool = True
    live_after_historical: bool = True
    log_file: str = "keeper.log"
    log_level: str = "INFO"
    extra_aave_eth: list[str] = field(default_factory=list)
    extra_aave_bnb: list[str] = field(default_factory=list)
    extra_compound_eth: list[str] = field(default_factory=list)
    extra_compound_bnb: list[str] = field(default_factory=list)
    env_file_path: str = ""
    env_file_exists: bool = False

    @classmethod
    def from_env(cls) -> "AppConfig":
        evm_addr = env_str("EVM_ADDRESS")
        return cls(
            eth_rpc_url=resolve_rpc_url(env_str("ETH_RPC_URL"), OFFICIAL_ETH_HTTP),
            bnb_rpc_url=resolve_rpc_url(
                env_str("BNB_RPC_URL") or env_str("BSC_RPC_URL"), OFFICIAL_BNB_HTTP
            ),
            sol_rpc_url=resolve_rpc_url(env_str("SOL_RPC_URL"), OFFICIAL_SOL_HTTP),
            eth_ws_url=env_str("ETH_WS_URL"),
            bnb_ws_url=env_str("BNB_WS_URL"),
            evm_address=to_checksum_address(evm_addr) if evm_addr else "",
            evm_private_key=env_str("EVM_PRIVATE_KEY"),
            sol_address=env_str("SOL_ADDRESS"),
            sol_private_key=env_str("SOL_PRIVATE_KEY"),
            telegram_bot_token=env_str("TELEGRAM_BOT_TOKEN"),
            telegram_chat_id=env_str("TELEGRAM_CHAT_ID"),
            start_block=env_int("START_BLOCK"),
            end_block=env_int("END_BLOCK"),
            min_usd=env_float("MIN_USD", 2.0),
            min_native=env_float("MIN_NATIVE", 0.05),
            eth_usd=env_float("ETH_USD", 3000.0),
            concurrency=max(1, env_int("CONCURRENCY", 1) or 1),
            log_chunk_blocks=max(1, env_int("LOG_CHUNK_BLOCKS", 2000) or 2000),
            poll_interval_sec=env_float("POLL_INTERVAL_SEC", 4.0),
            live_lookback_blocks=max(0, env_int("LIVE_LOOKBACK_BLOCKS", 3) or 0),
            dry_run=env_bool("DRY_RUN", True),
            live_after_historical=env_bool("LIVE_AFTER_HISTORICAL", True),
            log_file=env_str("LOG_FILE", "keeper.log"),
            log_level=env_str("LOG_LEVEL", "INFO").upper(),
            extra_aave_eth=csv_addresses(env_str("EXTRA_AAVE_POOLS_ETH")),
            extra_aave_bnb=csv_addresses(env_str("EXTRA_AAVE_POOLS_BNB")),
            extra_compound_eth=csv_addresses(env_str("EXTRA_COMPOUND_COMPTROLLERS_ETH")),
            extra_compound_bnb=csv_addresses(env_str("EXTRA_COMPOUND_COMPTROLLERS_BNB")),
        )

    def protocols_for(self, chain: str) -> list[ProtocolMarket]:
        extras: list[ProtocolMarket] = []
        if chain == "ethereum":
            extras.extend(
                ProtocolMarket(chain, f"extra_aave_{i}", "aave", addr, "usd8")
                for i, addr in enumerate(self.extra_aave_eth)
            )
            extras.extend(
                ProtocolMarket(chain, f"extra_compound_{i}", "compound", addr, "usd8")
                for i, addr in enumerate(self.extra_compound_eth)
            )
        elif chain == "bsc":
            extras.extend(
                ProtocolMarket(chain, f"extra_aave_{i}", "aave", addr, "usd8")
                for i, addr in enumerate(self.extra_aave_bnb)
            )
            extras.extend(
                ProtocolMarket(chain, f"extra_compound_{i}", "compound", addr, "usd8")
                for i, addr in enumerate(self.extra_compound_bnb)
            )
        return [p for p in builtin_protocols() if p.chain == chain] + extras


# ---------------------------------------------------------------------------
# Module C — realtime logger + Telegram (same process, shared session)
# ---------------------------------------------------------------------------

class RealtimeStreamHandler(logging.StreamHandler):
    """Flush after every record so BaoTa / process-manager stdout updates immediately."""

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()


class RealtimeFileHandler(logging.FileHandler):
    """Flush after every record so tail -f / 宝塔日志 does not buffer."""

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()


# Back-compat aliases for earlier helper names.
FlushingStreamHandler = RealtimeStreamHandler
FlushingFileHandler = RealtimeFileHandler


def setup_logging(config: AppConfig) -> logging.Logger:
    html_filter = OmitHtmlLogFilter()
    logger = logging.getLogger("keeper")
    logger.setLevel(getattr(logging, config.log_level, logging.INFO))
    logger.handlers.clear()
    logger.propagate = False
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    stream = RealtimeStreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    stream.addFilter(html_filter)
    logger.addHandler(stream)
    if config.log_file:
        file_handler = RealtimeFileHandler(config.log_file, encoding="utf-8")
        file_handler.setFormatter(fmt)
        file_handler.addFilter(html_filter)
        logger.addHandler(file_handler)
    for name in ("web3", "web3.providers", "web3.providers.HTTPProvider", "aiohttp"):
        noisy = logging.getLogger(name)
        noisy.addFilter(html_filter)
    return logger


class DedupCache:
    def __init__(self, maxlen: int = 200) -> None:
        self._order: deque[str] = deque(maxlen=maxlen)
        self._seen: set[str] = set()

    def __contains__(self, item: str) -> bool:
        return item in self._seen

    def add(self, item: str) -> bool:
        """Return True if *item* was already present."""
        if item in self._seen:
            return True
        if self._order.maxlen is not None and len(self._order) == self._order.maxlen:
            evicted = self._order[0]
            self._seen.discard(evicted)
        self._order.append(item)
        self._seen.add(item)
        return False

    def __len__(self) -> int:
        return len(self._seen)


class TelegramAlerter:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        token: str,
        chat_id: str,
        logger: logging.Logger,
    ) -> None:
        self.session = session
        self._token = token
        self._chat_id = chat_id
        self._logger = logger
        self._dedup = DedupCache(200)
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def enabled(self) -> bool:
        return bool(self._token and self._chat_id)

    def notify(self, fp_parts: Iterable[object], body_html: str) -> None:
        fp = fingerprint(*fp_parts)
        if self._dedup.add(fp):
            return
        if not self.enabled:
            return
        task = asyncio.create_task(self._send(body_html), name="telegram-alert")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _send(self, body_html: str) -> None:
        url = f"https://api.telegram.org/bot{self._token}/sendMessage"
        payload = {
            "chat_id": self._chat_id,
            "text": body_html,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            timeout = aiohttp.ClientTimeout(total=2)
            async with self.session.post(url, json=payload, timeout=timeout) as resp:
                if resp.status >= 400:
                    self._logger.warning("telegram http %s", resp.status)
        except Exception as exc:
            self._logger.warning("telegram send failed: %s", type(exc).__name__)

    async def drain(self) -> None:
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CandidatePosition:
    chain: str
    protocol: str
    style: str
    target: str  # pool or cToken to call
    user: str
    collateral: str
    debt: str
    repay_amount: int
    collateral_usd: float
    health_factor: float
    receive_a_token: bool = False
    native_repay: bool = False


@dataclass
class SolanaPosition:
    obligation: str
    repay_reserve: str
    withdraw_reserve: str
    liquidity_amount: int
    collateral_usd: float = 0.0


class SolanaPublicLiquidator(Protocol):
    """Clear interface for Solend / Kamino-style public liquidate."""

    async def connect(self) -> int: ...

    async def close(self) -> None: ...

    async def fetch_liquidatable(self, min_usd: float) -> list[SolanaPosition]: ...

    async def simulate_liquidate(self, position: SolanaPosition) -> bool: ...

    async def submit_liquidate(self, position: SolanaPosition) -> str: ...


class SolanaLiquidationStub:
    """Connectivity-only stub. Does not encode a Solend/Kamino IDL."""

    def __init__(
        self,
        rpc_url: str,
        logger: logging.Logger,
        env_file_path: str = "",
        env_file_exists: bool = False,
    ) -> None:
        self._rpc_url = rpc_url
        self._logger = logger
        self._client: Any = None
        self._rpc_issue_seen: dict[tuple[str, str], float] = {}
        self.alias = chain_alias("solana")
        self._env_file_path = env_file_path
        self._env_file_exists = env_file_exists

    async def connect(self) -> int:
        if not self._rpc_url:
            self._logger.info(
                "%s",
                missing_rpc_hint(self.alias, self._env_file_path, self._env_file_exists),
            )
            return 0
        if SolanaAsyncClient is None:
            self._logger.warning("solana stub: solana-py not installed")
            return 0
        self._client = SolanaAsyncClient(self._rpc_url, timeout=20)
        try:
            slot_resp = await self._client.get_slot()
            slot = int(getattr(slot_resp, "value", 0) or 0)
            self._logger.info("[solana] 区块高度 %s (slot) 已连接 AsyncClient；公开清算 IDL 未接线", slot)
            return slot
        except Exception as exc:
            kind = classify_rpc_error(exc)
            if kind is not None:
                log_rpc_issue(self._logger, self.alias, kind, self._rpc_issue_seen)
                return 0
            raise

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def fetch_liquidatable(self, min_usd: float) -> list[SolanaPosition]:
        self._logger.info(
            "[solana] 清算状态 状态=未接线IDL min_usd=%s 返回空",
            min_usd,
        )
        return []

    async def simulate_liquidate(self, position: SolanaPosition) -> bool:
        self._logger.info("[solana] 清算状态 obligation=%s 状态=模拟跳过", position.obligation)
        return False

    async def submit_liquidate(self, position: SolanaPosition) -> str:
        raise RuntimeError("solana public liquidate is stubbed; refusing to submit")

    async def run_live(self, stop: asyncio.Event, poll_interval: float) -> None:
        """Sequential slot monitor. Does not invent Solend/Kamino instruction accounts."""
        if self._client is None:
            return
        last = 0
        while not stop.is_set():
            try:
                slot_resp = await self._client.get_slot()
                slot = int(getattr(slot_resp, "value", 0) or 0)
                if slot and slot != last:
                    self._logger.info(
                        "[solana] 区块高度 %s 顺序监视 公开清算未接线IDL",
                        slot,
                    )
                    last = slot
            except Exception as exc:
                kind = classify_rpc_error(exc)
                if kind is not None:
                    log_rpc_issue(self._logger, self.alias, kind, self._rpc_issue_seen)
                else:
                    raise
            try:
                await asyncio.wait_for(stop.wait(), timeout=poll_interval)
            except TimeoutError:
                continue


# ---------------------------------------------------------------------------
# EVM RPC session
# ---------------------------------------------------------------------------

class SanitizingAsyncHTTPProvider(AsyncHTTPProvider):
    """Decode JSON-RPC only. HTTP 200 HTML/non-JSON becomes NonJsonRpcError (no body)."""

    async def make_request(self, method: RPCEndpoint, params: Any) -> Any:
        self.logger.debug("Making request HTTP. Method: %s", method)
        request_data = self.encode_rpc_request(method, params)
        raw_response = await self._make_request(method, request_data)
        head = body_head(raw_response)
        if looks_like_html(head):
            raise NonJsonRpcError("html")
        if looks_like_non_json_rpc(head):
            raise NonJsonRpcError("nonjson")
        try:
            return self.decode_rpc_response(raw_response)
        except Exception as exc:
            kind = classify_rpc_error(exc) or ("html" if looks_like_html(_exc_head(exc)) else "nonjson")
            if kind in {"html", "nonjson"}:
                raise NonJsonRpcError(kind) from None
            raise


class EvmChain:
    def __init__(
        self,
        name: str,
        rpc_url: str,
        ws_url: str,
        session: aiohttp.ClientSession,
        logger: logging.Logger,
    ) -> None:
        self.name = name
        self.alias = chain_alias(name)
        self.rpc_url = rpc_url
        self.ws_url = ws_url
        self._session = session
        self._logger = logger
        self.w3 = self._make_w3()
        self.chain_id: int | None = None
        self._rpc_issue_seen: dict[tuple[str, str], float] = {}

    def _make_w3(self) -> AsyncWeb3:
        provider = SanitizingAsyncHTTPProvider(
            self.rpc_url,
            request_kwargs={"timeout": 25},
        )
        w3 = AsyncWeb3(provider)
        attach_poa_middleware(w3)
        return w3

    async def attach_session(self) -> None:
        cache = getattr(self.w3.provider, "cache_async_session", None)
        if cache is not None:
            await cache(self._session)

    def _log_rpc(self, kind: str) -> None:
        log_rpc_issue(self._logger, self.alias, kind, self._rpc_issue_seen)

    async def reconnect(self) -> None:
        disconnect = getattr(self.w3.provider, "disconnect", None)
        if disconnect is not None:
            try:
                result = disconnect()
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                pass
        self.w3 = self._make_w3()
        await self.attach_session()
        self.chain_id = None

    async def rpc(self, factory: Any, *, attempts: int = 5, label: str = "rpc") -> Any:
        delay = 1.0
        last_kind = "transient"
        for attempt in range(1, attempts + 1):
            try:
                return await factory()
            except Exception as exc:
                if is_execution_revert(exc):
                    raise
                kind = classify_rpc_error(exc)
                if kind is None:
                    raise
                last_kind = kind
                self._log_rpc(kind)
                if attempt == attempts:
                    break
                await asyncio.sleep(delay)
                delay = min(delay * 2, 16.0)
                await self.reconnect()
        raise TransientRpcError(short_rpc_hint(self.alias, last_kind))


# ---------------------------------------------------------------------------
# Module B — static simulation + optional send
# ---------------------------------------------------------------------------

class SimulationEngine:
    def __init__(
        self,
        chain: EvmChain,
        operator: str,
        account: LocalAccount | None,
        dry_run: bool,
        logger: logging.Logger,
        telegram: TelegramAlerter,
        min_native: float = 0.05,
    ) -> None:
        self.chain = chain
        self.operator = operator
        self.account = account
        self.dry_run = dry_run
        self.min_native = min_native
        self._logger = logger
        self._telegram = telegram

    def _calldata(self, position: CandidatePosition) -> bytes:
        if position.style == "aave":
            return encode_aave_liquidation_call(
                position.collateral,
                position.debt,
                position.user,
                position.repay_amount,
                position.receive_a_token,
            )
        if position.native_repay:
            return encode_cether_liquidate_borrow(position.user, position.collateral)
        return encode_compound_liquidate_borrow(
            position.user, position.repay_amount, position.collateral
        )

    async def _target_native_ok(self, contract: str) -> bool:
        """Last gate before eth_call: watched official contract native coin > MIN_NATIVE."""
        addr = to_checksum_address(contract)
        w3 = self.chain.w3

        async def _bal() -> int:
            return int(await w3.eth.get_balance(addr))

        try:
            wei = int(await self.chain.rpc(_bal, label="get_balance"))
        except TransientRpcError:
            return False
        if exceeds_native_floor(wei, self.min_native):
            return True
        self._logger.info(
            "%s 清算状态 合约=%s 状态=低于原生币门槛 已丢弃 native=%.6f 门槛=%s",
            self.chain.alias,
            addr,
            native_ether_amount(wei),
            self.min_native,
        )
        return False

    async def simulate(self, position: CandidatePosition) -> bool:
        if not self.operator:
            self._logger.warning("skip sim: EVM_ADDRESS empty")
            return False
        if not await self._target_native_ok(position.target):
            return False
        data = self._calldata(position)
        tx: TxParams = {
            "from": self.operator,
            "to": to_checksum_address(position.target),
            "data": HexBytes(data),
            "value": 0,
        }
        try:
            await self.chain.w3.eth.call(tx, "latest")
        except Exception as exc:
            if is_execution_revert(exc):
                self._logger.info(
                    "%s 清算状态 协议=%s 用户=%s 状态=模拟回退已丢弃",
                    self.chain.alias,
                    position.protocol,
                    position.user,
                )
                return False
            kind = classify_rpc_error(exc)
            if kind is not None:
                self.chain._log_rpc(kind)
                return False
            raise
        self._logger.info(
            "%s 清算状态 协议=%s 用户=%s 状态=模拟成功 目标=%s",
            self.chain.alias,
            position.protocol,
            position.user,
            position.target,
        )
        self._telegram.notify(
            ("sim", self.chain.alias, position.protocol, position.user, position.target),
            (
                f"<b>模拟成功</b>\n"
                f"chain: {html.escape(self.chain.alias)}\n"
                f"protocol: {html.escape(position.protocol)}\n"
                f"user: <code>{html.escape(position.user)}</code>\n"
                f"hf: {position.health_factor:.6f}\n"
                f"collateral_usd: {position.collateral_usd:.2f}\n"
                f"dry_run: {self.dry_run}"
            ),
        )
        return True

    async def maybe_send(self, position: CandidatePosition) -> str | None:
        if self.dry_run:
            return None
        if self.account is None:
            raise RuntimeError("DRY_RUN=false requires EVM_PRIVATE_KEY for the operator")
        if self.account.address.lower() != self.operator.lower():
            raise RuntimeError("EVM_PRIVATE_KEY does not match EVM_ADDRESS")
        data = self._calldata(position)
        w3 = self.chain.w3
        chain_id = self.chain.chain_id or await w3.eth.chain_id
        self.chain.chain_id = int(chain_id)
        nonce = await w3.eth.get_transaction_count(self.operator)
        tx: dict[str, Any] = {
            "from": self.operator,
            "to": to_checksum_address(position.target),
            "data": HexBytes(data),
            "value": 0,
            "nonce": nonce,
            "chainId": int(chain_id),
        }
        await self._fill_fees(tx)
        tx["gas"] = int(await w3.eth.estimate_gas(tx) * 12 // 10)
        signed = self.account.sign_transaction(tx)
        raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
        tx_hash = await w3.eth.send_raw_transaction(raw)
        hex_hash = tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash)
        self._logger.info("%s 清算状态 协议=%s 用户=%s 状态=已发送 tx=%s", self.chain.alias, position.protocol, position.user, hex_hash)
        self._telegram.notify(
            ("sent", hex_hash),
            (
                f"<b>已发送清算</b>\n"
                f"chain: {html.escape(self.chain.alias)}\n"
                f"tx: <code>{html.escape(hex_hash)}</code>"
            ),
        )
        return hex_hash

    async def _fill_fees(self, tx: dict[str, Any]) -> None:
        w3 = self.chain.w3
        try:
            block = await w3.eth.get_block("latest")
            base = block.get("baseFeePerGas")
            if base:
                prio = await w3.eth.max_priority_fee
                tx["maxPriorityFeePerGas"] = int(prio)
                tx["maxFeePerGas"] = int(base) * 2 + int(prio)
                return
        except Exception as exc:
            if not is_transient_rpc_error(exc) and not is_execution_revert(exc):
                self._logger.warning("eip1559 fee lookup failed, using gasPrice: %s", type(exc).__name__)
        tx["gasPrice"] = int(await w3.eth.gas_price)


# ---------------------------------------------------------------------------
# Module A — market liquidation scanner
# ---------------------------------------------------------------------------

class MarketScanner:
    def __init__(
        self,
        chain: EvmChain,
        config: AppConfig,
        protocols: list[ProtocolMarket],
        engine: SimulationEngine,
        logger: logging.Logger,
        telegram: TelegramAlerter,
    ) -> None:
        self.chain = chain
        self.config = config
        self.protocols = protocols
        self.engine = engine
        self._logger = logger
        self._telegram = telegram
        self._markets: dict[str, list[str]] = {}
        self._reserves: dict[str, list[str]] = {}
        self._watched: set[str] = set()
        self._to_proto: dict[str, ProtocolMarket] = {}
        self._eval_seen = DedupCache(200)
        self._native_ok: dict[str, bool] = {}

    async def refresh_markets(self) -> None:
        self._watched.clear()
        self._to_proto.clear()
        for proto in self.protocols:
            try:
                if proto.style == "compound":
                    self._markets[proto.address] = await self._get_all_markets(proto.address)
                else:
                    self._reserves[proto.address] = await self._get_reserves(proto.address)
            except TransientRpcError:
                self._logger.warning("skip market refresh %s %s", proto.name, proto.address)
            except Exception:
                self._logger.exception("market refresh bug %s", proto.name)
                raise
            for addr in self._watch_addresses(proto):
                key = addr.lower()
                self._watched.add(key)
                self._to_proto[key] = proto
        self._logger.info(
            "%s 监视合约 %s 个（官方池/cToken，不含创建合约扫描）",
            self.chain.alias,
            len(self._watched),
        )

    def _watch_addresses(self, proto: ProtocolMarket) -> list[str]:
        if proto.style == "compound":
            return [proto.address, *self._markets.get(proto.address, [])]
        return [proto.address]

    async def _eth_call(self, to: str, data: bytes, label: str) -> bytes:
        tx: TxParams = {
            "from": self.engine.operator or None,
            "to": to_checksum_address(to),
            "data": HexBytes(data),
        }
        if tx["from"] is None:
            tx.pop("from")

        async def _do() -> HexBytes:
            return await self.chain.w3.eth.call(tx, "latest")

        result = await self.chain.rpc(_do, label=label)
        return bytes(result)

    async def _get_reserves(self, pool: str) -> list[str]:
        raw = await self._eth_call(
            pool, function_signature_to_4byte_selector(AAVE_RESERVES_LIST_SIG), "getReservesList"
        )
        decoded = decode(["address[]"], raw)[0]
        return [to_checksum_address(a) for a in decoded]

    async def _get_all_markets(self, comptroller: str) -> list[str]:
        raw = await self._eth_call(
            comptroller,
            function_signature_to_4byte_selector(COMPTROLLER_MARKETS_SIG),
            "getAllMarkets",
        )
        decoded = decode(["address[]"], raw)[0]
        return [to_checksum_address(a) for a in decoded]

    async def scan_range(self, start: int, end: int) -> None:
        """Scan Aave-spec lending state in block order. No unbounded fan-out."""
        if end < start:
            return
        self._logger.info("%s 区块高度 %s..%s 顺序扫描", self.chain.alias, start, end)
        for height in range(start, end + 1):
            await self.scan_block(height)

    async def scan_block(self, height: int) -> None:
        async def _fetch() -> Any:
            return await self.chain.w3.eth.get_block(height, full_transactions=True)

        try:
            block = await self.chain.rpc(_fetch, label="get_block")
        except TransientRpcError:
            self._logger.warning("%s 区块高度 %s 读取失败已跳过", self.chain.alias, height)
            return
        txs = list(block["transactions"] if isinstance(block, dict) else block.transactions)
        kept = 0
        dropped = 0
        found: dict[tuple[str, str], set[str]] = {}
        self._native_ok.clear()
        for tx in txs:
            tx_to = tx["to"] if isinstance(tx, dict) else getattr(tx, "to", None)
            if not keep_protocol_tx(tx_to, self._watched):
                dropped += 1
                continue
            target = normalize_tx_to(tx_to)
            if target is None:
                dropped += 1
                continue
            if not await self._official_native_ok(target):
                continue
            kept += 1
            proto = self._to_proto.get(target.lower())
            if proto is None:
                continue
            users = await self._users_from_kept_tx(proto, tx)
            found.setdefault((proto.name, proto.address), set()).update(users)
        self._logger.info(
            "%s 区块高度 %s 保留协议交易=%s 丢弃普通转账=%s",
            self.chain.alias,
            height,
            kept,
            dropped,
        )
        for (name, address), users in found.items():
            proto = next(p for p in self.protocols if p.address == address and p.name == name)
            for user in users:
                await self._evaluate_user(proto, user)

    async def _official_native_ok(self, contract: str) -> bool:
        """Pre-sim: only watched official pool/cToken native coin strictly above MIN_NATIVE."""
        key = contract.lower()
        cached = self._native_ok.get(key)
        if cached is not None:
            return cached
        addr = to_checksum_address(contract)
        w3 = self.chain.w3

        async def _bal() -> int:
            return int(await w3.eth.get_balance(addr))

        try:
            wei = int(await self.chain.rpc(_bal, label="get_balance"))
        except TransientRpcError:
            self._native_ok[key] = False
            return False
        amount = native_ether_amount(wei)
        ok = exceeds_native_floor(wei, self.config.min_native)
        self._native_ok[key] = ok
        if not ok:
            self._logger.info(
                "%s 清算状态 合约=%s 状态=低于原生币门槛 已丢弃 native=%.6f 门槛=%s",
                self.chain.alias,
                addr,
                amount,
                self.config.min_native,
            )
        return ok

    async def _users_from_kept_tx(self, proto: ProtocolMarket, tx: Any) -> set[str]:
        users: set[str] = set()
        tx_from = tx["from"] if isinstance(tx, dict) else getattr(tx, "from", None)
        if tx_from:
            try:
                users.add(to_checksum_address(str(tx_from)))
            except (ValueError, TypeError):
                pass
        tx_hash = tx["hash"] if isinstance(tx, dict) else getattr(tx, "hash", None)
        if tx_hash is None:
            return users

        async def _receipt() -> Any:
            return await self.chain.w3.eth.get_transaction_receipt(tx_hash)

        try:
            receipt = await self.chain.rpc(_receipt, label="get_receipt")
        except TransientRpcError:
            return users
        logs = receipt["logs"] if isinstance(receipt, dict) else receipt.logs
        for log in logs:
            user = self._user_from_log(proto, log)
            if user:
                users.add(user)
        return users

    def _user_from_log(self, proto: ProtocolMarket, log: Any) -> str | None:
        topics = list(log["topics"] if isinstance(log, dict) else log.topics)
        if not topics:
            return None
        topic0 = bytes(topics[0])
        try:
            if proto.style == "aave":
                if topic0 == AAVE_LIQUIDATION_TOPIC and len(topics) >= 4:
                    return address_from_topic(topics[3])
                if topic0 in {AAVE_BORROW_TOPIC_V2, AAVE_BORROW_TOPIC_V3} and len(topics) >= 3:
                    return address_from_topic(topics[2])
                return None
            data = log["data"] if isinstance(log, dict) else log.data
            if topic0 == COMPOUND_BORROW_TOPIC:
                return parse_compound_borrow_borrower(data)
            if topic0 == COMPOUND_LIQUIDATE_TOPIC:
                raw = bytes(data) if not isinstance(data, str) else bytes.fromhex(data[2:])
                _liq, borrower, _repay, _col, _seize = decode(
                    ["address", "address", "uint256", "address", "uint256"], raw
                )
                return to_checksum_address(borrower)
        except Exception:
            self._logger.exception("log decode bug %s", proto.name)
            raise
        return None

    async def _evaluate_user(self, proto: ProtocolMarket, user: str) -> None:
        fp = fingerprint("eval", proto.chain, proto.name, user)
        if self._eval_seen.add(fp):
            return
        try:
            if proto.style == "aave":
                await self._evaluate_aave(proto, user)
            else:
                await self._evaluate_compound(proto, user)
        except TransientRpcError:
            self._logger.warning("evaluate transient %s %s", proto.name, user)
        except Exception:
            self._logger.exception("evaluate bug %s %s", proto.name, user)
            raise

    def _collateral_usd(self, proto: ProtocolMarket, total_collateral_base: int) -> float:
        if proto.base == "eth18":
            return (total_collateral_base / WAD) * self.config.eth_usd
        return total_collateral_base / USD8

    async def _evaluate_aave(self, proto: ProtocolMarket, user: str) -> None:
        raw = await self._eth_call(proto.address, encode_address_call(AAVE_ACCOUNT_DATA_SIG, user), "getUserAccountData")
        (
            total_collateral_base,
            total_debt_base,
            _avail,
            _threshold,
            _ltv,
            health_factor,
        ) = decode(["uint256", "uint256", "uint256", "uint256", "uint256", "uint256"], raw)
        collateral_usd = self._collateral_usd(proto, int(total_collateral_base))
        if not exceeds_min_usd(collateral_usd, self.config.min_usd):
            self._logger.info(
                "%s 清算状态 协议=%s 用户=%s 状态=低于美元门槛 已丢弃 usd=%.2f",
                self.chain.alias,
                proto.name,
                user,
                collateral_usd,
            )
            return
        if int(total_debt_base) == 0 or int(health_factor) >= WAD:
            self._logger.info(
                "%s 清算状态 协议=%s 用户=%s 状态=安全",
                self.chain.alias,
                proto.name,
                user,
            )
            return
        hf = int(health_factor) / WAD
        self._logger.info(
            "%s 清算状态 协议=%s 用户=%s 状态=可清算 hf=%.6f usd=%.2f",
            self.chain.alias,
            proto.name,
            user,
            hf,
            collateral_usd,
        )
        self._telegram.notify(
            ("liq", proto.chain, proto.name, user),
            (
                f"<b>可清算仓位</b>\n"
                f"chain: {html.escape(self.chain.alias)}\n"
                f"protocol: {html.escape(proto.name)}\n"
                f"user: <code>{html.escape(user)}</code>\n"
                f"hf: {hf:.6f}\n"
                f"collateral_usd: {collateral_usd:.2f}"
            ),
        )
        reserves = self._reserves.get(proto.address) or await self._get_reserves(proto.address)
        self._reserves[proto.address] = reserves
        cfg_raw = await self._eth_call(
            proto.address, encode_address_call(AAVE_USER_CONFIG_SIG, user), "getUserConfiguration"
        )
        cfg = int(decode(["uint256"], cfg_raw)[0])
        collaterals, debts = decode_user_config_bits(cfg, reserves)
        if not collaterals or not debts:
            return
        for collateral in collaterals:
            for debt in debts:
                if collateral.lower() == debt.lower():
                    continue
                position = CandidatePosition(
                    chain=proto.chain,
                    protocol=proto.name,
                    style="aave",
                    target=proto.address,
                    user=user,
                    collateral=collateral,
                    debt=debt,
                    repay_amount=UINT256_MAX,
                    collateral_usd=collateral_usd,
                    health_factor=hf,
                )
                if await self.engine.simulate(position):
                    await self.engine.maybe_send(position)
                    return

    async def _evaluate_compound(self, proto: ProtocolMarket, user: str) -> None:
        raw = await self._eth_call(
            proto.address, encode_address_call(COMPTROLLER_LIQUIDITY_SIG, user), "getAccountLiquidity"
        )
        error, _liquidity, shortfall = decode(["uint256", "uint256", "uint256"], raw)
        if int(error) != 0 or int(shortfall) == 0:
            self._logger.info(
                "%s 清算状态 协议=%s 用户=%s 状态=安全",
                self.chain.alias,
                proto.name,
                user,
            )
            return
        markets = self._markets.get(proto.address) or await self._get_all_markets(proto.address)
        self._markets[proto.address] = markets
        assets_in = markets
        try:
            ai_raw = await self._eth_call(
                proto.address, encode_address_call(COMPTROLLER_ASSETS_IN_SIG, user), "getAssetsIn"
            )
            assets_in = [to_checksum_address(a) for a in decode(["address[]"], ai_raw)[0]]
        except Exception as exc:
            if is_execution_revert(exc) or is_transient_rpc_error(exc):
                self._logger.warning("getAssetsIn fallback to all markets: %s", type(exc).__name__)
            else:
                raise
        collaterals: list[tuple[str, int]] = []
        debts: list[tuple[str, int]] = []
        collateral_usd = 0.0
        oracle = await self._try_oracle(proto.address)
        for market in assets_in:
            snap = await self._eth_call(
                market, encode_address_call(CTOKEN_SNAPSHOT_SIG, user), "getAccountSnapshot"
            )
            err, ctoken_bal, borrow_bal, exch = decode(
                ["uint256", "uint256", "uint256", "uint256"], snap
            )
            if int(err) != 0:
                continue
            underlying_bal = int(ctoken_bal) * int(exch) // WAD
            if int(ctoken_bal) > 0:
                collaterals.append((market, underlying_bal))
            if int(borrow_bal) > 0:
                debts.append((market, int(borrow_bal)))
            if oracle:
                try:
                    price_raw = await self._eth_call(
                        oracle,
                        encode_address_call(ORACLE_UNDERLYING_PRICE_SIG, market),
                        "getUnderlyingPrice",
                    )
                    price = int(decode(["uint256"], price_raw)[0])
                    collateral_usd += underlying_bal * price / WAD / WAD
                except Exception as exc:
                    if not is_execution_revert(exc) and not is_transient_rpc_error(exc):
                        raise
        if collateral_usd <= 0:
            collateral_usd = int(shortfall) / WAD
        if not exceeds_min_usd(collateral_usd, self.config.min_usd):
            self._logger.info(
                "%s 清算状态 协议=%s 用户=%s 状态=低于美元门槛 已丢弃 usd=%.2f",
                self.chain.alias,
                proto.name,
                user,
                collateral_usd,
            )
            return
        if not collaterals or not debts:
            return
        hf = 0.0
        self._logger.info(
            "%s 清算状态 协议=%s 用户=%s 状态=可清算 shortfall=%s usd=%.2f",
            self.chain.alias,
            proto.name,
            user,
            shortfall,
            collateral_usd,
        )
        self._telegram.notify(
            ("liq", proto.chain, proto.name, user),
            (
                f"<b>可清算仓位</b>\n"
                f"chain: {html.escape(self.chain.alias)}\n"
                f"protocol: {html.escape(proto.name)}\n"
                f"user: <code>{html.escape(user)}</code>\n"
                f"shortfall_wad: {int(shortfall)}\n"
                f"collateral_usd: {collateral_usd:.2f}"
            ),
        )
        for debt_market, borrow_bal in debts:
            for col_market, _bal in collaterals:
                if debt_market.lower() == col_market.lower():
                    continue
                repay = max(borrow_bal // 2, 1)
                position = CandidatePosition(
                    chain=proto.chain,
                    protocol=proto.name,
                    style="compound",
                    target=debt_market,
                    user=user,
                    collateral=col_market,
                    debt=debt_market,
                    repay_amount=repay,
                    collateral_usd=collateral_usd,
                    health_factor=hf,
                )
                if await self.engine.simulate(position):
                    await self.engine.maybe_send(position)
                    return

    async def _try_oracle(self, comptroller: str) -> str | None:
        try:
            raw = await self._eth_call(
                comptroller,
                function_signature_to_4byte_selector(COMPTROLLER_ORACLE_SIG),
                "oracle",
            )
            return to_checksum_address(decode(["address"], raw)[0])
        except Exception as exc:
            if is_execution_revert(exc) or is_transient_rpc_error(exc):
                return None
            raise

    async def run_historical(self) -> None:
        start = self.config.start_block
        if start is None:
            return
        head = int(await self.chain.rpc(lambda w3=self.chain.w3: await_block_number(w3), label="block_number"))
        end = self.config.end_block if self.config.end_block is not None else head
        end = min(end, head)
        await self.scan_range(start, end)

    async def _handle_new_head(self, last: int, head: int) -> int:
        if head <= last:
            return last
        from_block = last + 1
        lookback = self.config.live_lookback_blocks
        if lookback:
            from_block = max(0, last + 1 - lookback)
        await self.scan_range(from_block, head)
        return head

    async def _run_live_ws(self, stop: asyncio.Event, last: int) -> int:
        """newHeads subscription signals height; blocks are still read in order over HTTP."""
        self._logger.info("%s 订阅 newHeads websocket", self.chain.alias)
        async with AsyncWeb3(WebSocketProvider(self.chain.ws_url)) as ws_w3:
            await ws_w3.eth.subscribe("newHeads")
            waiter = asyncio.create_task(stop.wait())
            try:
                async for msg in ws_w3.socket.process_subscriptions():
                    if stop.is_set():
                        break
                    result = msg.get("result") if isinstance(msg, dict) else None
                    number = None
                    if isinstance(result, dict):
                        number = result.get("number")
                    if number is None:
                        number = await self.chain.rpc(
                            lambda w3=self.chain.w3: await_block_number(w3),
                            label="block_number",
                        )
                    last = await self._handle_new_head(last, int(number))
                    if waiter.done():
                        break
            finally:
                if not waiter.done():
                    waiter.cancel()
                try:
                    await waiter
                except (asyncio.CancelledError, Exception):
                    pass
        return last

    async def run_live(self, stop: asyncio.Event) -> None:
        head = int(await self.chain.rpc(lambda w3=self.chain.w3: await_block_number(w3), label="block_number"))
        last = head
        self._logger.info("%s 区块高度 %s 进入实时顺序监视", self.chain.alias, last)
        while not stop.is_set():
            try:
                if self.chain.ws_url:
                    try:
                        last = await self._run_live_ws(stop, last)
                        if stop.is_set():
                            return
                    except Exception as exc:
                        if not is_transient_rpc_error(exc) and type(exc).__name__ not in {
                            "WebSocketException",
                            "ConnectionClosed",
                            "ProviderConnectionError",
                            "PersistentConnectionClosedOK",
                        }:
                            raise
                        self._logger.warning(
                            "%s newHeads 失败 (%s)，改用 HTTP 轮询",
                            self.chain.alias,
                            type(exc).__name__,
                        )
                head = int(await self.chain.rpc(lambda w3=self.chain.w3: await_block_number(w3), label="block_number"))
                last = await self._handle_new_head(last, head)
            except TransientRpcError:
                self._logger.warning("%s 实时循环瞬时错误，重试", self.chain.alias)
            except Exception as exc:
                kind = classify_rpc_error(exc)
                if kind is not None:
                    self.chain._log_rpc(kind)
                    continue
                self._logger.warning("%s 实时循环逻辑错误: %s", self.chain.alias, type(exc).__name__)
                raise
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.config.poll_interval_sec)
            except TimeoutError:
                continue


# ---------------------------------------------------------------------------
# Process entry
# ---------------------------------------------------------------------------

def operator_account(config: AppConfig) -> LocalAccount | None:
    key = config.evm_private_key
    if not key:
        return None
    account = Account.from_key(key)
    if config.evm_address and account.address.lower() != config.evm_address.lower():
        raise SystemExit("EVM_PRIVATE_KEY does not match EVM_ADDRESS")
    return account


class Keeper:
    """Single-process keeper: shared aiohttp session, sequential EVM/Solana monitors."""

    def __init__(self, config: AppConfig, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger
        self.session: aiohttp.ClientSession | None = None
        self.telegram: TelegramAlerter | None = None

    async def run(self) -> None:
        config = self.config
        logger = self.logger
        if not config.dry_run and not config.evm_private_key:
            raise SystemExit("DRY_RUN=false requires EVM_PRIVATE_KEY (operator key only)")
        account = operator_account(config)
        operator = config.evm_address or (account.address if account else "")
        if account and not config.evm_address:
            operator = account.address

        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:
                pass

        async with aiohttp.ClientSession(timeout=timeout) as session:
            self.session = session
            self.telegram = TelegramAlerter(
                session, config.telegram_bot_token, config.telegram_chat_id, logger
            )
            telegram = self.telegram
            if telegram.enabled:
                logger.info("Telegram 推送已启用")
                telegram.notify(
                    ("startup", config.dry_run, operator or "<unset>"),
                    (
                        "<b>官方清算 Keeper 已启动</b>\n"
                        f"dry_run: {config.dry_run}\n"
                        f"operator: <code>{html.escape(operator or '&lt;unset&gt;')}</code>\n"
                        f"min_native: {config.min_native}"
                    ),
                )
            else:
                logger.info("Telegram 未配置 TELEGRAM_BOT_TOKEN/CHAT_ID，告警仅写日志")
            chains: list[tuple[EvmChain, MarketScanner]] = []
            mapping = (
                ("ethereum", config.eth_rpc_url, config.eth_ws_url),
                ("bsc", config.bnb_rpc_url, config.bnb_ws_url),
            )
            for name, url, ws in mapping:
                bound_name = name
                if not url:
                    logger.info(
                        "%s",
                        missing_rpc_hint(
                            chain_alias(bound_name),
                            config.env_file_path,
                            config.env_file_exists,
                        ),
                    )
                    continue
                chain = EvmChain(bound_name, url, ws, session, logger)
                bound_alias = chain.alias
                bound_w3 = chain.w3
                await chain.attach_session()
                try:
                    chain.chain_id = int(
                        await chain.rpc(lambda w3=bound_w3: w3.eth.chain_id, label="chain_id")
                    )
                    head = int(
                        await chain.rpc(
                            lambda w3=bound_w3: await_block_number(w3), label="block_number"
                        )
                    )
                    logger.info("%s 区块高度 %s 已连接 chain_id=%s", bound_alias, head, chain.chain_id)
                except TransientRpcError:
                    logger.warning("%s 初始连接失败，循环内重试", bound_alias)
                engine = SimulationEngine(
                    chain, operator, account, config.dry_run, logger, telegram, config.min_native
                )
                scanner = MarketScanner(
                    chain, config, config.protocols_for(bound_name), engine, logger, telegram
                )
                await scanner.refresh_markets()
                chains.append((chain, scanner))

            sol = SolanaLiquidationStub(
                config.sol_rpc_url,
                logger,
                config.env_file_path,
                config.env_file_exists,
            )
            try:
                await sol.connect()
                await sol.fetch_liquidatable(config.min_usd)
            except Exception as exc:
                kind = classify_rpc_error(exc)
                if kind is not None:
                    log_rpc_issue(logger, chain_alias("solana"), kind, {})
                else:
                    raise

            if not chains and not config.sol_rpc_url:
                raise SystemExit("no RPC URLs configured (set ETH_RPC_URL / BNB_RPC_URL / SOL_RPC_URL)")

            logger.info(
                "keeper start dry_run=%s operator=%s min_usd=%s min_native=%s sequential=true",
                config.dry_run,
                operator or "<unset>",
                config.min_usd,
                config.min_native,
            )
            if not config.dry_run:
                logger.warning("DRY_RUN 已关闭 — 模拟成功后将用操作者私钥广播")

            try:
                if config.start_block is not None:
                    for _chain, scanner in chains:
                        await scanner.run_historical()
                run_live = config.start_block is None or (
                    config.live_after_historical and config.end_block is None
                )
                if run_live and not stop.is_set():
                    async with asyncio.TaskGroup() as group:
                        for _chain, scanner in chains:
                            group.create_task(scanner.run_live(stop))
                        if config.sol_rpc_url:
                            group.create_task(sol.run_live(stop, config.poll_interval_sec))
                        group.create_task(stop.wait())
            finally:
                await sol.close()
                await telegram.drain()
                self.session = None


async def run_keeper(config: AppConfig, logger: logging.Logger) -> None:
    await Keeper(config, logger).run()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Official public-liquidation keeper")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Force simulation-only (overrides DRY_RUN=false)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    env_path, env_exists = load_script_dir_env()
    args = parse_args(argv)
    config = AppConfig.from_env()
    config.env_file_path = str(env_path)
    config.env_file_exists = env_exists
    if args.dry_run:
        config.dry_run = True
    logger = setup_logging(config)
    try:
        asyncio.run(run_keeper(config, logger))
    except KeyboardInterrupt:
        logger.info("interrupted")


if __name__ == "__main__":
    main()
