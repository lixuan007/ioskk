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

With no `START_BLOCK`, the process follows new heads (WebSocket `newHeads` when `ETH_WS_URL` / `BNB_WS_URL` is set, otherwise HTTP poll). Each height is read **in block order**. Ordinary transfers are dropped by inspecting `tx.to` (empty-`to` creations and EOA-to-EOA never become targets). Only txs to configured official pools/cTokens are kept. Before `eth_call`, the watched pool/cToken native balance must be **greater than** `MIN_NATIVE` (default `0.05` ETH or 0.05 BNB). Dust contracts log `低于原生币门槛` and are not simulated.

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
| A Scanner | Sequential block-order `get_block(full_transactions=True)`. Pre-filter by `tx.to` against watched official pools/cTokens. Native coin of that official contract must be `> MIN_NATIVE` (default 0.05) before any `eth_call`. Logs use bound 【ETH 链】 / 【BNB 链】 aliases. Live new-heads poll/subscribe + optional `start_block..end_block`. |
| B Simulator | Official `getUserAccountData` / `liquidationCall` / `liquidateBorrow` via `eth_call` from the operator. Revert = safe, discard. Send only after success and `DRY_RUN=false` with a matching operator key. |
| C Logger / Telegram | `RealtimeStreamHandler` / `RealtimeFileHandler` flush every record (BaoTa). Chinese 区块高度 / 清算状态 lines. Telegram uses the process `self.session`, `create_task`, 2s timeout, MD5 deque(200). |

Solana stays behind `SolanaPublicLiquidator`: the stub connects and reports slot height, then returns no positions until a specific program IDL is wired.
