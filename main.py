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
from collections import deque
from dataclasses import dataclass, field
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
from web3.providers.persistent import WebSocketProvider
from web3.providers.rpc import AsyncHTTPProvider
from web3.types import HexBytes, TxParams

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional at runtime
    def load_dotenv() -> bool:  # type: ignore[misc]
        return False

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
    msg = str(exc).lower()
    return (
        "revert" in msg
        or "execution reverted" in msg
        or name in {"contractlogicerror", "contractcustomerror"}
    )


def is_transient_rpc_error(exc: BaseException) -> bool:
    """Network / 429 / non-JSON: reconnect and continue. Not used for logic bugs."""
    if is_execution_revert(exc):
        return False
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
        return True
    msg = str(exc).lower()
    needles = (
        "429",
        "too many requests",
        "rate limit",
        "timeout",
        "timed out",
        "connection",
        "reset by peer",
        "broken pipe",
        "expecting value",
        "not valid json",
        "badresponseformat",
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
    return any(needle in msg for needle in needles)


class TransientRpcError(RuntimeError):
    """Raised after retries are exhausted on a transient RPC failure."""


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
    eth_usd: float = 3000.0
    concurrency: int = 4
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

    @classmethod
    def from_env(cls) -> "AppConfig":
        evm_addr = env_str("EVM_ADDRESS")
        return cls(
            eth_rpc_url=env_str("ETH_RPC_URL"),
            bnb_rpc_url=env_str("BNB_RPC_URL") or env_str("BSC_RPC_URL"),
            sol_rpc_url=env_str("SOL_RPC_URL"),
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
            eth_usd=env_float("ETH_USD", 3000.0),
            concurrency=max(1, env_int("CONCURRENCY", 4) or 4),
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
# Module C — flushing logger + Telegram
# ---------------------------------------------------------------------------

class FlushingStreamHandler(logging.StreamHandler):
    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()


class FlushingFileHandler(logging.FileHandler):
    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()


def setup_logging(config: AppConfig) -> logging.Logger:
    logger = logging.getLogger("keeper")
    logger.setLevel(getattr(logging, config.log_level, logging.INFO))
    logger.handlers.clear()
    logger.propagate = False
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    stream = FlushingStreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    logger.addHandler(stream)
    if config.log_file:
        file_handler = FlushingFileHandler(config.log_file, encoding="utf-8")
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
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
        self._session = session
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
            async with self._session.post(url, json=payload, timeout=timeout) as resp:
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

    def __init__(self, rpc_url: str, logger: logging.Logger) -> None:
        self._rpc_url = rpc_url
        self._logger = logger
        self._client: Any = None

    async def connect(self) -> int:
        if not self._rpc_url:
            self._logger.info("solana stub: SOL_RPC_URL empty, skipped")
            return 0
        if SolanaAsyncClient is None:
            self._logger.warning("solana stub: solana-py not installed")
            return 0
        self._client = SolanaAsyncClient(self._rpc_url, timeout=20)
        try:
            slot_resp = await self._client.get_slot()
            slot = int(getattr(slot_resp, "value", 0) or 0)
            self._logger.info("solana stub connected slot=%s (liquidate not wired)", slot)
            return slot
        except Exception as exc:
            if is_transient_rpc_error(exc):
                self._logger.warning("solana stub transient connect error: %s", exc)
                return 0
            raise

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def fetch_liquidatable(self, min_usd: float) -> list[SolanaPosition]:
        self._logger.info(
            "solana stub: fetch_liquidatable(min_usd=%s) returns [] until IDL is configured",
            min_usd,
        )
        return []

    async def simulate_liquidate(self, position: SolanaPosition) -> bool:
        self._logger.info("solana stub: simulate skipped for %s", position.obligation)
        return False

    async def submit_liquidate(self, position: SolanaPosition) -> str:
        raise RuntimeError("solana public liquidate is stubbed; refusing to submit")


# ---------------------------------------------------------------------------
# EVM RPC session
# ---------------------------------------------------------------------------

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
        self.rpc_url = rpc_url
        self.ws_url = ws_url
        self._session = session
        self._logger = logger
        self.w3 = self._make_w3()
        self.chain_id: int | None = None

    def _make_w3(self) -> AsyncWeb3:
        provider = AsyncHTTPProvider(
            self.rpc_url,
            request_kwargs={"timeout": 25},
        )
        return AsyncWeb3(provider)

    async def attach_session(self) -> None:
        cache = getattr(self.w3.provider, "cache_async_session", None)
        if cache is not None:
            await cache(self._session)

    async def reconnect(self) -> None:
        self._logger.warning("%s rpc reconnect", self.name)
        disconnect = getattr(self.w3.provider, "disconnect", None)
        if disconnect is not None:
            try:
                result = disconnect()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                self._logger.warning("%s provider disconnect: %s", self.name, exc)
        self.w3 = self._make_w3()
        await self.attach_session()
        self.chain_id = None

    async def rpc(self, factory: Any, *, attempts: int = 5, label: str = "rpc") -> Any:
        delay = 1.0
        last: BaseException | None = None
        for attempt in range(1, attempts + 1):
            try:
                return await factory()
            except Exception as exc:
                last = exc
                if is_execution_revert(exc):
                    raise
                if not is_transient_rpc_error(exc):
                    raise
                self._logger.warning(
                    "%s %s transient (%s/%s): %s",
                    self.name,
                    label,
                    attempt,
                    attempts,
                    type(exc).__name__,
                )
                if attempt == attempts:
                    break
                await asyncio.sleep(delay)
                delay = min(delay * 2, 16.0)
                if attempt >= 2:
                    await self.reconnect()
        raise TransientRpcError(f"{self.name} {label} failed: {last}")


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
    ) -> None:
        self.chain = chain
        self.operator = operator
        self.account = account
        self.dry_run = dry_run
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

    async def simulate(self, position: CandidatePosition) -> bool:
        if not self.operator:
            self._logger.warning("skip sim: EVM_ADDRESS empty")
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
                    "sim revert %s %s user=%s",
                    position.chain,
                    position.protocol,
                    position.user,
                )
                return False
            if is_transient_rpc_error(exc):
                self._logger.warning("sim transient: %s", type(exc).__name__)
                return False
            raise
        self._logger.info(
            "sim ok %s %s user=%s target=%s",
            position.chain,
            position.protocol,
            position.user,
            position.target,
        )
        self._telegram.notify(
            ("sim", position.chain, position.protocol, position.user, position.target),
            (
                f"<b>Simulation ok</b>\n"
                f"chain: {html.escape(position.chain)}\n"
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
        self._logger.info("sent liquidation %s", hex_hash)
        self._telegram.notify(
            ("sent", hex_hash),
            (
                f"<b>Liquidation sent</b>\n"
                f"chain: {html.escape(position.chain)}\n"
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
        self._sem = asyncio.Semaphore(config.concurrency)
        self._markets: dict[str, list[str]] = {}
        self._reserves: dict[str, list[str]] = {}
        self._eval_seen = DedupCache(200)

    async def refresh_markets(self) -> None:
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

    def _watch_addresses(self, proto: ProtocolMarket) -> list[str]:
        if proto.style == "compound":
            return [proto.address, *self._markets.get(proto.address, [])]
        return [proto.address]

    def _topics(self, proto: ProtocolMarket) -> list[bytes]:
        if proto.style == "aave":
            return [AAVE_LIQUIDATION_TOPIC, AAVE_BORROW_TOPIC_V3, AAVE_BORROW_TOPIC_V2]
        return [COMPOUND_BORROW_TOPIC, COMPOUND_LIQUIDATE_TOPIC]

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
        if end < start:
            return
        chunk = self.config.log_chunk_blocks
        windows = [(s, min(s + chunk - 1, end)) for s in range(start, end + 1, chunk)]
        self._logger.info("%s scan blocks %s..%s (%s windows)", self.chain.name, start, end, len(windows))

        async def _window(lo: int, hi: int) -> None:
            async with self._sem:
                await self._scan_window(lo, hi)

        async with asyncio.TaskGroup() as group:
            for lo, hi in windows:
                group.create_task(_window(lo, hi))

    async def _scan_window(self, start: int, end: int) -> None:
        users: dict[tuple[str, str], set[str]] = {}
        for proto in self.protocols:
            addresses = self._watch_addresses(proto)
            if not addresses:
                continue
            logs = await self._get_logs(start, end, addresses, self._topics(proto))
            for log in logs:
                user = self._user_from_log(proto, log)
                if user:
                    users.setdefault((proto.name, proto.address), set()).add(user)
        if not users:
            return
        self._logger.info("%s window %s..%s users=%s", self.chain.name, start, end, sum(len(v) for v in users.values()))
        for (name, address), addrs in users.items():
            proto = next(p for p in self.protocols if p.address == address and p.name == name)
            async with asyncio.TaskGroup() as group:
                for user in addrs:
                    group.create_task(self._evaluate_user(proto, user))

    async def _get_logs(
        self,
        start: int,
        end: int,
        addresses: list[str],
        topics: list[bytes],
    ) -> list[Any]:
        topic0 = ["0x" + t.hex() for t in topics]
        collected: list[Any] = []
        # Chunk address lists — some RPCs reject large filters.
        step = 20
        for i in range(0, len(addresses), step):
            batch = addresses[i : i + step]
            params = {
                "fromBlock": start,
                "toBlock": end,
                "address": batch if len(batch) > 1 else batch[0],
                "topics": [topic0],
            }

            async def _do(p: dict[str, Any] = params) -> list[Any]:
                return await self.chain.w3.eth.get_logs(p)

            try:
                collected.extend(await self.chain.rpc(_do, label="get_logs"))
            except TransientRpcError:
                self._logger.warning("%s get_logs %s..%s skipped after retries", self.chain.name, start, end)
        return collected

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
            return
        if int(total_debt_base) == 0 or int(health_factor) >= WAD:
            return
        hf = int(health_factor) / WAD
        self._logger.info(
            "liquidatable %s %s user=%s hf=%.6f usd=%.2f",
            proto.chain,
            proto.name,
            user,
            hf,
            collateral_usd,
        )
        self._telegram.notify(
            ("liq", proto.chain, proto.name, user),
            (
                f"<b>Liquidatable position</b>\n"
                f"chain: {html.escape(proto.chain)}\n"
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
            return
        if not collaterals or not debts:
            return
        hf = 0.0
        self._logger.info(
            "liquidatable %s %s user=%s shortfall=%s usd=%.2f",
            proto.chain,
            proto.name,
            user,
            shortfall,
            collateral_usd,
        )
        self._telegram.notify(
            ("liq", proto.chain, proto.name, user),
            (
                f"<b>Liquidatable position</b>\n"
                f"chain: {html.escape(proto.chain)}\n"
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
        head = int(await self.chain.rpc(lambda: self.chain.w3.eth.block_number, label="block_number"))
        end = self.config.end_block if self.config.end_block is not None else head
        end = min(end, head)
        await self.scan_range(start, end)

    async def _handle_new_head(self, last: int, head: int) -> int:
        if head <= last:
            return last
        from_block = max(0, last + 1 - self.config.live_lookback_blocks)
        await self.scan_range(from_block, head)
        return head

    async def _run_live_ws(self, stop: asyncio.Event, last: int) -> int:
        """newHeads subscription. HTTP get_logs still does the work; WS only signals heads."""
        self._logger.info("%s subscribing newHeads on websocket", self.chain.name)
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
                            lambda: self.chain.w3.eth.block_number, label="block_number"
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
        head = int(await self.chain.rpc(lambda: self.chain.w3.eth.block_number, label="block_number"))
        last = head
        self._logger.info("%s live from block %s", self.chain.name, last)
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
                            "%s newHeads websocket failed (%s), polling instead",
                            self.chain.name,
                            type(exc).__name__,
                        )
                head = int(await self.chain.rpc(lambda: self.chain.w3.eth.block_number, label="block_number"))
                last = await self._handle_new_head(last, head)
            except TransientRpcError:
                self._logger.warning("%s live loop transient, retrying", self.chain.name)
            except Exception:
                self._logger.exception("%s live loop bug", self.chain.name)
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


async def run_keeper(config: AppConfig, logger: logging.Logger) -> None:
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
        telegram = TelegramAlerter(session, config.telegram_bot_token, config.telegram_chat_id, logger)
        chains: list[tuple[EvmChain, MarketScanner]] = []
        mapping = (
            ("ethereum", config.eth_rpc_url, config.eth_ws_url),
            ("bsc", config.bnb_rpc_url, config.bnb_ws_url),
        )
        for name, url, ws in mapping:
            if not url:
                logger.info("chain %s disabled (no RPC URL)", name)
                continue
            chain = EvmChain(name, url, ws, session, logger)
            await chain.attach_session()
            try:
                chain.chain_id = int(await chain.rpc(lambda: chain.w3.eth.chain_id, label="chain_id"))
                head = int(await chain.rpc(lambda: chain.w3.eth.block_number, label="block_number"))
                logger.info("%s connected chain_id=%s head=%s", name, chain.chain_id, head)
            except TransientRpcError:
                logger.warning("%s initial connect failed, will retry in loop", name)
            engine = SimulationEngine(chain, operator, account, config.dry_run, logger, telegram)
            scanner = MarketScanner(chain, config, config.protocols_for(name), engine, logger, telegram)
            await scanner.refresh_markets()
            chains.append((chain, scanner))

        sol = SolanaLiquidationStub(config.sol_rpc_url, logger)
        try:
            await sol.connect()
            await sol.fetch_liquidatable(config.min_usd)
        except Exception as exc:
            if is_transient_rpc_error(exc):
                logger.warning("solana stub transient: %s", type(exc).__name__)
            else:
                raise

        if not chains and not config.sol_rpc_url:
            raise SystemExit("no RPC URLs configured (set ETH_RPC_URL / BNB_RPC_URL / SOL_RPC_URL)")

        logger.info(
            "keeper start dry_run=%s operator=%s min_usd=%s concurrency=%s",
            config.dry_run,
            operator or "<unset>",
            config.min_usd,
            config.concurrency,
        )
        if not config.dry_run:
            logger.warning("DRY_RUN is off — successful simulations will broadcast from the operator key")

        try:
            historical_jobs = [scanner.run_historical() for _chain, scanner in chains if config.start_block is not None]
            if historical_jobs:
                async with asyncio.TaskGroup() as group:
                    for job in historical_jobs:
                        group.create_task(job)
            run_live = config.start_block is None or (
                config.live_after_historical and config.end_block is None
            )
            if run_live and not stop.is_set():
                async with asyncio.TaskGroup() as group:
                    for _chain, scanner in chains:
                        group.create_task(scanner.run_live(stop))
                    group.create_task(stop.wait())
        finally:
            await sol.close()
            await telegram.drain()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Official public-liquidation keeper")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Force simulation-only (overrides DRY_RUN=false)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    load_dotenv()
    args = parse_args(argv)
    config = AppConfig.from_env()
    if args.dry_run:
        config.dry_run = True
    logger = setup_logging(config)
    try:
        asyncio.run(run_keeper(config, logger))
    except KeyboardInterrupt:
        logger.info("interrupted")


if __name__ == "__main__":
    main()
