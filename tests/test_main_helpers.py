"""Unit tests for encoder, dedup, filter, and classifier helpers in main.py."""

from __future__ import annotations

import io
import logging
from unittest.mock import patch

import pytest
from eth_utils import function_signature_to_4byte_selector

import main


def test_aave_liquidation_selector_is_official() -> None:
    assert main.AAVE_LIQUIDATION_SELECTOR == function_signature_to_4byte_selector(
        "liquidationCall(address,address,address,uint256,bool)"
    )
    assert main.selector_hex(main.AAVE_LIQUIDATION_SIG) == "0x00a718a9"


def test_compound_liquidate_selector_is_official() -> None:
    assert main.COMPOUND_LIQUIDATE_SELECTOR == function_signature_to_4byte_selector(
        "liquidateBorrow(address,uint256,address)"
    )
    assert main.selector_hex(main.COMPOUND_LIQUIDATE_SIG) == "0xf5e3c462"


def test_encode_aave_liquidation_call_layout() -> None:
    data = main.encode_aave_liquidation_call(
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "0x1111111111111111111111111111111111111111",
        10**6,
        False,
    )
    assert data[:4] == main.AAVE_LIQUIDATION_SELECTOR
    assert len(data) == 4 + 32 * 5


def test_encode_compound_liquidate_borrow_layout() -> None:
    data = main.encode_compound_liquidate_borrow(
        "0x2222222222222222222222222222222222222222",
        123,
        "0x3333333333333333333333333333333333333333",
    )
    assert data[:4] == main.COMPOUND_LIQUIDATE_SELECTOR
    assert len(data) == 4 + 32 * 3


def test_exceeds_min_usd_floor() -> None:
    assert main.exceeds_min_usd(2.0, 2.0) is True
    assert main.exceeds_min_usd(1.99, 2.0) is False
    assert main.exceeds_min_usd(0.0, 0.0) is True
    assert main.exceeds_min_usd(0.5, 0.0) is True


def test_dedup_cache_evicts_and_fingerprints() -> None:
    cache = main.DedupCache(maxlen=3)
    fp = main.fingerprint("eth", "aave_v3", "0xAbc")
    assert fp == main.fingerprint("ETH", "AAVE_V3", "0xabc")
    assert cache.add(fp) is False
    assert cache.add(fp) is True
    assert cache.add("a") is False
    assert cache.add("b") is False
    assert cache.add("c") is False  # evicts fp
    assert fp not in cache
    assert cache.add(fp) is False


def test_decode_user_config_bits() -> None:
    reserves = [f"0x{i:040x}" for i in range(4)]
    # reserve 0 collateral, reserve 1 debt, reserve 3 both
    data = 0b00_11_00_01  # index 0 is low bits
    # wait: index0 bits 0-1, index1 bits 2-3, index2 bits 4-5, index3 bits 6-7
    # 0b 11 00 10 01 = index0 col, index1 debt, index3 both
    data = 0b11001001
    cols, debts = main.decode_user_config_bits(data, reserves)
    assert cols[0].lower().endswith("00")
    assert any(x.lower().endswith("03") for x in cols)
    assert any(x.lower().endswith("01") for x in debts)
    assert any(x.lower().endswith("03") for x in debts)
    assert not any(x.lower().endswith("02") for x in cols + debts)


def test_parse_compound_borrow_borrower() -> None:
    from eth_abi import encode

    borrower = "0x4444444444444444444444444444444444444444"
    payload = encode(
        ["address", "uint256", "uint256", "uint256"],
        [borrower, 10, 20, 30],
    )
    assert main.parse_compound_borrow_borrower(payload) == main.to_checksum_address(borrower)
    assert main.parse_compound_borrow_borrower("0x" + payload.hex()) == main.to_checksum_address(
        borrower
    )


def test_env_bool_and_csv_addresses() -> None:
    with patch.dict("os.environ", {"DRY_RUN": "false", "X": "yes"}, clear=False):
        assert main.env_bool("DRY_RUN", True) is False
        assert main.env_bool("X", False) is True
    with patch.dict("os.environ", {"BAD": "maybe"}):
        with pytest.raises(ValueError):
            main.env_bool("BAD", True)
    addrs = main.csv_addresses(
        "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2, 0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9"
    )
    assert len(addrs) == 2
    assert addrs[0].startswith("0x")


def test_transient_vs_revert_classifier() -> None:
    class ContractLogicError(Exception):
        pass

    revert = ContractLogicError("execution reverted: HF")
    assert main.is_execution_revert(revert) is True
    assert main.is_transient_rpc_error(revert) is False
    assert main.is_transient_rpc_error(TimeoutError("timed out")) is True
    assert main.is_transient_rpc_error(RuntimeError("429 Too Many Requests")) is True
    assert main.is_transient_rpc_error(RuntimeError("Expecting value: line 1")) is True
    assert main.is_transient_rpc_error(ValueError("unexpected keyword")) is False


def test_flushing_stream_handler_flushes() -> None:
    buf = io.StringIO()
    handler = main.FlushingStreamHandler(buf)
    handler.setFormatter(logging.Formatter("%(message)s"))
    record = logging.LogRecord("keeper", logging.INFO, __file__, 1, "hello-flush", None, None)
    handler.emit(record)
    assert "hello-flush" in buf.getvalue()


@pytest.mark.asyncio
async def test_solana_stub_refuses_submit() -> None:
    stub = main.SolanaLiquidationStub("", logging.getLogger("test"))
    assert await stub.fetch_liquidatable(2.0) == []
    pos = main.SolanaPosition("ob", "repay", "withdraw", 1)
    assert await stub.simulate_liquidate(pos) is False
    with pytest.raises(RuntimeError, match="stubbed"):
        await stub.submit_liquidate(pos)


def test_config_from_env_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ETH_RPC_URL", raising=False)
    monkeypatch.delenv("EVM_ADDRESS", raising=False)
    monkeypatch.delenv("DRY_RUN", raising=False)
    monkeypatch.delenv("MIN_USD", raising=False)
    monkeypatch.delenv("START_BLOCK", raising=False)
    cfg = main.AppConfig.from_env()
    assert cfg.dry_run is True
    assert cfg.min_usd == 2.0
    assert cfg.start_block is None
    assert any(p.name == "aave_v3" for p in cfg.protocols_for("ethereum"))
    assert any(p.name == "venus" for p in cfg.protocols_for("bsc"))
