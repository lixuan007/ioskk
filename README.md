# Official public-liquidation keeper

Single-file Python 3.12 asyncio keeper for **permissionless liquidations** on known public lending protocols:

- Ethereum: Aave V2, Aave V3, Compound V2
- BNB Chain: Aave V3, Radiant V2, Venus (Compound-style)
- Solana: `AsyncClient` connectivity plus a **stub** `SolanaPublicLiquidator` interface (Solend/Kamino IDLs are not encoded here)

It uses **your** operator address/key only. It never sweeps random contracts, never scans contract-creation txs, and never fuzzes 4-byte selectors.

## Safety

1. Every liquidation is simulated first with `eth_call` at `latest` (`from` = your operator).
2. Reverts are skipped. Gas is never spent on a failing path.
3. A real transaction is sent only when `DRY_RUN=false` **and** that simulation succeeded.
4. `DRY_RUN` defaults to `true`.

The operator must already hold and approve the debt asset on the pool/cToken. Simulation does not use state overrides, so a liquidatable position still reverts if your wallet cannot pay the debt.

## Setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env — RPC URLs, your EVM address, optional Telegram
```

## Dry-run (default)

```bash
python main.py
```

With no `START_BLOCK`, the process polls new heads (or subscribes if `ETH_WS_URL` / `BNB_WS_URL` is set), reads protocol logs for known pools only, prefilters by `MIN_USD`, and simulates official `liquidationCall` / `liquidateBorrow`.

Historical backfill:

```bash
START_BLOCK=19000000 END_BLOCK=19001000 DRY_RUN=true python main.py
```

## Live send (explicit)

Only if you intend to liquidate with **your** funds:

```bash
DRY_RUN=false EVM_PRIVATE_KEY=0xYourKey python main.py
```

`EVM_PRIVATE_KEY` must match `EVM_ADDRESS`. The key is never logged.

## Tests

```bash
pytest -q
```

Helpers (`encode_*`, dedup, USD filter, user-config bits, revert vs transient RPC) are imported from `main.py`.

## Architecture

| Module | Role |
| --- | --- |
| A Scanner | Live new-heads poll/subscribe + optional `start_block..end_block`. Sliding-window concurrent `eth_getLogs` on configured pool/cToken addresses and official Borrow/Liquidation topics. |
| B Simulator | Encodes Aave-style `liquidationCall` and Compound-style `liquidateBorrow`. `eth_call` from the operator. Send only after success and `DRY_RUN=false`. |
| C Logger / Telegram | Flushing stream + file handlers (immediate flush for process managers). Telegram HTML via `asyncio.create_task`, 2s timeout, MD5 deque(200) dedup. |

Solana stays behind `SolanaPublicLiquidator`: the stub connects and reports slot height, then returns no positions until a specific program IDL is wired.
