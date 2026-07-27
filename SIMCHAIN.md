# Running BitVMX against Simchain

[Simchain](https://github.com/danielemiliogarcia/simchain) is a Docker stack of three P2P-connected
Bitcoin Core nodes in regtest mode. It is regtest at the consensus/encoding level but
behaves like a live network at the operational level.

---

## Why the `bitcoin::Network` enum does not fit

| | Encoding identity | Capability profile |
|---|---|---|
| regtest | `Regtest` | we own the chain: mine, `createwallet`, `sendtoaddress` |
| **simchain** | **`Regtest`** | **live-like: no node wallet, no mining, funds pre-exist** |
| testnet / testnet4 | `Testnet` / `Testnet4` | live: no node wallet, no mining, funds pre-exist |

Read the simchain row across: it encodes like regtest but behaves like testnet. Every
other chain sits in one column consistently. Regtest is regtest in both, testnet is
testnet in both. So a single `Network` value describes them completely. Simchain is
the only one that splits, which is exactly why no `Network` variant can express it, and
why forking the `bitcoin` crate to add one would not help either.

**Decision: keep `Network` for encoding, and introduce a superset type that answers
the capability question.**


### Simchain facts that drive the design

| Fact | Consequence |
|---|---|
| node1 RPC `localhost:18443`, user `foo`, pass `rpcpassword` | identical to our regtest config. URL/creds need no special casing |
| node1 runs `-disablewallet=1` | `createwallet` / `sendtoaddress` / `getnewaddress` **fail** (fail-fast, good) |
| node1 runs `-txindex` | BDK `Emitter` block scan works unchanged |
| `getblockchaininfo.chain == "regtest"` | the three `chain != Network::Regtest` guards in `bitvmx-bitcoin-rpc` **pass** |
| **`generatetoaddress` is a mining RPC, not a wallet RPC** | it **succeeds** on node1 even with `-disablewallet`. We must gate mining in our code. We cannot rely on the RPC erroring. This is the single most dangerous silent-failure in the port. |
| mining is external (poisson ~10s) | tests must *wait* for blocks, never request them |
| `USER_ADDRESS` funded 2×50 BTC at bootstrap | initial funding solved with zero code |
| spammer floor `SPAM_FEE=0.00015` = 15 sat/vB | a 1 sat/vB tx never confirms. Our default fee rates must clear the floor |
| control plane on `:8090` (dashboard / CLI / HTTP / MCP), live-retunable | fee ladder experiments without restarting the chain |

Simchain is treated as **read-only** here. We configure it via its `.env` and control
plane; we do not modify that repo.

---

## Integration design

One type. [`NetworkFlavor`] is a **superset of `bitcoin::Network`**. Every variant it
has, plus `Simchain`. And it carries the capability predicates alongside.

### The type

Lives in `rust-bitvmx-bitcoin-rpc/src/network_flavor.rs`, next to `RpcConfig`, so every
crate that already sees a network sees this instead.

### Two rules that keep the split from eroding

**1. No `Deref`, no implicit narrowing.** Widening is lossless so
`impl From<Network> for NetworkFlavor` is implicit; narrowing is *lossy*. `Simchain`
and `Regtest` both map to `Network::Regtest`. So it stays an explicit
`bitcoin_network()` call. The moment a flavor can silently stand in for a `Network`,
the two questions collapse back into one and simchain becomes indistinguishable from
regtest again, which is the bug this whole change exists to prevent.

**2. Never match on the variant when a capability says it better.** `is_simchain()`
exists for the guard rails that must name simchain specifically; everywhere else, ask
`can_mine_on_demand()`. If a site needs a distinction none of the predicates express,
add a predicate. That is the point.

### Config, and keeping the addon out of the way

One field, which cannot contradict itself:

```yaml
bitcoin:
  network: simchain      # regtest | simchain | testnet | testnet4 | signet | bitcoin
```

`Regtest` is the `Default`, so every existing YAML is unchanged.

On the Rust side the field is deliberately **not** called `network`:

```rust
pub struct RpcConfig {
    #[serde(rename = "network")]        // YAML key unchanged
    pub network_flavor: NetworkFlavor,  // the addon: you have to name it
}

impl RpcConfig {
    pub fn network(&self) -> Network { self.network_flavor.bitcoin_network() }
}
```

`config.network()` gives the plain `bitcoin::Network` that nearly everything wants;
`config.network_flavor` is reached only when asking a capability question. The naming
does the enforcing: a component cannot pick up simnet awareness by accident, it has to
ask.

**Choosing a predicate: match the original's membership, not its vibe.**

Every `network == Network::Regtest` this change replaced means "a chain we run
ourselves", which is `Regtest | Simchain`. That is [`is_local_chain`].

The membership table, for picking correctly:

| Predicate | Members |
|---|---|
| `can_mine_on_demand`, `has_node_wallet`, `spawns_own_bitcoind` | `Regtest` |
| `needs_prefunded_wallet` | everything except `Regtest` |
| `is_local_chain`, `is_disposable_chain` | `Regtest`, `Simchain` |
| `is_real_money` | `Bitcoin`, `Testnet`, `Testnet4`. **note: not `Signet`** |

**Environment variables follow existing practice.** `BITVMX_NETWORK_FLAVOR` selects the
run target for tests, examples and the union CLI. That is the same shape this repo
already uses. `bitvmx-settings` reads `BITVMX_ENV` (a config path) and `BITVMX_AGE_KEY`,
resolves `(env:NAME)` inside YAML values, and the union example already reads
`{PREFIX}_MASTER_WALLET_PRIVKEY` and `{PREFIX}_BITCOIN_API` keyed off the network.


**Naming rule, no exceptions.** Both words keep "network" in them, because both *are*
networks. The suffix says which notion:

| Identifier | Always means |
|---|---|
| `network`, `network()` | `bitcoin::Network`. The encoding |
| `network_flavor`, `network_flavor()` | `NetworkFlavor`. Encoding + capabilities |

So `BitcoinWrapper::network()` and `MasterWallet::network()` return `Network` like
everything else, and their `network_flavor()` siblings return the richer type. An
earlier pass had `network()` returning `NetworkFlavor` on two of these and `Network` on
three others, which made `wallet.network()` unreadable at the call site.

That matters because most of this workspace should never learn simnets exist. The key
manager derives keys, the coordinator tracks confirmations, the indexer reads blocks.
All of them want an encoding and nothing more. Concretely, after this change:

| Crate | Knows `NetworkFlavor`? |
|---|---|
| key-manager, indexer, transaction-monitor, protocol-builder, bitcoin-coordinator, bitcoind, broker | **no**. `Network` only |
| bitvmx-client `src/` (production) | **no** |
| bitvmx-wallet | one *private* field, read only by `check_network` |
| bitvmx-bitcoin-rpc | the type's home, plus the guard rails |
| bitvmx-client `tests/` + `examples/` | yes. This is the mine-or-wait code |

`key_manager.network` is a *separate* plain string parsed as a `bitcoin::Network`; it
stays `regtest` for simchain, because it only ever wanted the encoding (coin type, key
version bytes).

### Selection

`NetworkFlavor::from_env()` reads `BITVMX_NETWORK_FLAVOR`. Unset means regtest, so every existing
command line still works:

```bash
# unchanged
RUST_BACKTRACE=1 cargo test --release -- --ignored test_all

# against simchain
BITVMX_NETWORK_FLAVOR=simchain RUST_BACKTRACE=1 cargo test --release -- --ignored test_all
```

A value that is set but unrecognized **panics**, listing the valid names. A typo like
`BITVMX_NETWORK_FLAVOR=simchian` must never silently fall back to regtest. The regtest path spawns
its own bitcoind and mines, which is exactly what the caller was trying to avoid.

---

## Configuration files

### New files in `config/`

**`config/wallet_simchain.yaml`**. Modeled on `wallet_testnet4.yaml` (local node, no
node wallet), but regtest encoding:

Use **fresh keys**, not the ones in `wallet_regtest.yaml`, so a stray regtest run can
never touch simchain coins and vice versa.

**`config/simchain_op_{1,2,3,4}.yaml`**. Modeled on `testnet_op_1.yaml`, **not** on
`op_1.yaml`, because the operational profile is the testnet one


### Deriving `USER_ADDRESS`

The bootstrap funding target must be the simchain master wallet's receive address.

1. Generate two regtest WIFs, put them in `wallet_simchain.yaml`.
2. Print the derived P2WPKH address. No node required, this is key derivation only:

   ```bash
   cargo test --release --test print_env_address -- --nocapture print_simchain_address
   ```
3. Set that `bcrt1…` value as `USER_ADDRESS` in simchain's `.env`, then bring the stack
   up fresh (`./scripts/fresh-chain.sh --profile all-tools`) or just (`./scripts/fresh-chain.sh`)
   for reduced stack . The wallet holds 100 BTC before the first test runs.

Faucet integration (control-plane HTTP API for mid-run top-ups) is deliberately **out
of scope for this pass**. Bootstrap funding is deterministic and needs no code here.
Revisit if a long run drains the wallet.

---

## Bringing the stack up

### Block cadence vs. wall-clock. Read this before the first run

`TIMELOCK_BLOCKS = 15` (`src/program/protocols/dispute/mod.rs:73`), and the dispute
protocol chains several timelocks. At simchain's default
`BLOCK_INTERVAL_MEAN_SECS=10`, that is **150 s per timelock**, and every
`mine_and_wait_blocks(10)` becomes 100 s of real waiting. `test_all` goes from minutes
to hours.

For the first simchain runs, set in simchain's `.env`:

```
BLOCK_INTERVAL_MODE=fixed
BLOCK_INTERVAL_MEAN_SECS=1
```

Raise to 10 s once the suite is green. That is where the timing realism lives, and it
is exactly the regime the replacer is built for. Mining cadence is live-retunable
(`simchainctl config set`), no restart needed.

---

## Fee ladder. The experiments this unlocks

Entirely configuration; no code beyond the above. Simchain's price level is set by
`SPAM_FEE` (BTC/kvB) in its `.env`; BitVMX's response comes from
`coordinator_settings.fee` + `.speedup` in `config/simchain_op_N.yaml`.

> `SPAM_FEE`, not `FALLBACK_FEE`. Simchain split the two: `FALLBACK_FEE` is now a
> boot-only node flag (`-fallbackfee`, the wallet estimator's fallback), while `SPAM_FEE`
> is the live price the spammer actually pays and is retunable without a restart. An
> `.env` that sets only `FALLBACK_FEE` still seeds `SPAM_FEE` from it at first boot, with
> a migration warning. So an old `.env` works, but sets the price by accident.

The whole ladder is aimed at one number: **`max_feerate_sat_vb`, the replacer's cap** (see
[Where the cap lives](#where-the-cap-lives) below). Each rung places the spam floor
relative to it.

| Run | simchain `.env` | Block interval | `min_safe_fee_rate` / `max_feerate_sat_vb` | Expected behavior |
|---|---|---|---|---|
| **1. Baseline** | `ENABLE_SPAM=false` | `fixed`, **1s** | 20 / 100 (as shipped) | empty mempool, everything confirms first try. **Start here**. Proves the port with fee behavior held constant. |
| 2. Default | `ENABLE_SPAM=true`, `SPAM_FEE=0.00015` (15 sat/vB) | `fixed`, **15s** | 20 / 100 | confirms; occasional speedup. Floor sits well under the cap. |
| 3. Under the cap | `ENABLE_SPAM=true`, `SPAM_FEE=0.0005` (**50** sat/vB) | `fixed`, **15s** | 20 / **100** | **replacer must bump and must win.** Floor at half the cap leaves real headroom, so CPFP/RBF is exercised for real and still lands. `MaxFeeRateReached` must **not** appear. If it does, the bump ladder is overshooting. |
| 4. Over the cap | `ENABLE_SPAM=true`, `SPAM_FEE=0.0015` (**150** sat/vB) | `fixed`, **15s** | 20 / **100** | **replacer must hit the cap and stop.** The floor is above anything the coordinator is allowed to pay. Expect `EstimateFeerateTooHigh`, then `MaxFeeRateReached`, then boosting to cease and the tx to stay unconfirmed. **This run is expected to fail the suite**. That is the result, not a regression. |
| 5. Live squeeze | start at run 3, then raise the floor mid-run: `simchainctl config set SPAM_FEE=0.0015` | `fixed`, **15s** | 20 / 100 | already-broadcast txs get stranded mid-flight and must be rescued, or demonstrably cannot be. |

150 sat/vB is verified to run comfortably on this stack. Simchain's docs do warn that
`SPAM_FEE` can push the spammer into `capacity_degraded`, but the numbers there are for
`0.1` (10,000 sat/vB); the branch reserve scales with the fee, so `0.0015` sits one to two
orders of magnitude below the level that actually degrades. The real constraint is not the
price, it is warm-up. See below.

If you would rather not spend the faucet reserve at all, an equivalent way to reach the
same code path is to leave `SPAM_FEE` at run 3's `0.0005` and lower `max_feerate_sat_vb`
to **40** in `config/simchain_op_N.yaml`. Same three log lines, no cost to the simnet, but
it proves the cap logic rather than the fee market. Keep it as a cross-check, not the
primary.

#### Give the spammer time to reach the target price

**A freshly started simchain is not yet at the fee level you configured.** The spammer
starts cold: it has to fan its funds out into branch UTXOs, fill blocks, and let the
mempool build the backlog `SPAM_FILL_BLOCK_RATIO` asks for, before `estimatesmartfee`
reflects the floor. Start a run into that window and the coordinator sees a low estimate,
prices its transactions under the intended floor, and the rung silently tests nothing.
Run 4 in particular will look like it passed.

This applies to snapshot starts too. A snapshot restores the chain and its funds, but the
spammer still resumes cold and needs a few cycles to get back on target.

Before starting runs 2 to 5:

- watch the spammer report a healthy, on-target status on the control plane (`:8090`),
  not `capacity_degraded` and not still provisioning;
- confirm `estimatesmartfee` from node1 actually reports something close to `SPAM_FEE`.
  This is the check that matters, because it is the number the coordinator reads;
- give it several block intervals of margin either way. At 15s blocks that is under a
  minute of waiting, against runs that take minutes to hours.


#### Block cadence with the spammer running

For runs 2 to 5, use:

```bash
ENABLE_SPAM=true
SPAM_FILL_BLOCK_RATIO=5        # full blocks + ~4 blocks of backlog in the mempool
BLOCK_INTERVAL_MODE=fixed
BLOCK_INTERVAL_MEAN_SECS=15
```

The interval is not a free knob once the spammer is on, and 1s from run 1 must not be
carried over. Two separate limits bite:

- **The spammer needs time to refill.** Its send cycle takes tens of seconds
  (simchain's `SETTINGS.md` measures ~13-54s on a fresh chain and says to keep the
  interval above it). Outrun it and the mempool stays shallow, the fee floor leaks, and
  runs 2 to 5 pass without ever applying the pressure they exist to apply.
- **The nodes have to assemble those blocks.** No proof of work is involved, but
  building a template from a deep mempool, relaying it, and reconnecting it across three
  nodes is real work. Push the cadence too hard and they fall behind, the mempool gets
  drained faster than it refills, and the backlog you configured never materialises.

`SPAM_FILL_BLOCK_RATIO=5` asks for full blocks plus roughly four blocks of pending
weight, which is what keeps a floor-priced supply permanently in front of every
template. That is what the replacer has to bid against.

15s per block feels slow next to run 1, and it is worth being clear about why that is
fine: **simchain is a preflight for testnet and mainnet**, not a speed target. Testnet
blocks arrive in minutes and mainnet in tens of minutes, so a 15s cadence is still one
to two orders of magnitude faster than the environments this is rehearsing for. Buying
correct fee behavior at that price is a good trade; buying a fast green run that proved
nothing is not.

The shipped `min_safe_fee_rate: 20` is a floor *we* impose, not one the chain demands.
With spam off the mempool will accept 1 sat/vB, so run 1 overpays. Harmless, and it
means the same config files work for runs 1-3 without editing. Operator funding is
sized generously (see `speedup_funding_factor` in `tests/common/helper.rs`) precisely so
that fee changes never turn into a funding failure halfway through a run.

Runs 3 to 5 are where `bump_fee_percentage`, `min_blocks_before_resend_speedup` and
`max_unconfirmed_speedups` earn their keep: run 3 proves the ladder climbs, run 4 proves
it stops where it was told to, and run 5 proves it copes with the floor moving underneath
an in-flight transaction. Run 5 is only possible because simchain retunes `SPAM_FEE` live.

---


## Quick start

### Build before the chain is up

`rustc` will use every core it can get, and simchain's miners and transaction spammer
are ordinary processes competing for the same CPU. A compile racing the simnet starves
the spammer: blocks come out emptier than configured, the fee pressure a run is supposed
to exercise never appears, and the run *passes* having proved less than it looks like.
A long enough stall can also trip the harness block-wait timeout and read as a protocol
bug. Neither failure announces itself.

Two ways out, best first:

1. **Run simchain on another machine.** Point `url` in `config/wallet_simchain.yaml` and
   `config/simchain_op_*.yaml` at that host instead of `127.0.0.1`. Removes the
   contention entirely and is closest to how a real node is reached.
2. **Compile with the chain down**, then bring it up, then run.

For 2, `--no-run` compiles the test binaries and stops. Do this while simchain is down:

```bash
cargo test --release --no-run
```

With no `--test` filter this builds *every* test binary, including the two simchain
helpers used later in this section. Every `cargo test` invocation from here on then
starts instantly instead of compiling against a live chain.


### Bring the chain up

Set `USER_ADDRESS` in simchain's `.env` to the master wallet's receive address, then
start a fresh chain. The address below is committed in `config/wallet_simchain.yaml`;
print it yourself to confirm the wallet really derives it:

```bash
cargo test --release --test print_env_address -- --nocapture print_simchain_address
```

Prebuilt by the `--no-run` step above, so it compiles nothing. Then in simchain's `.env`:

```bash
USER_ADDRESS=bcrt1qmj09uwj7rulcf7cc899t627wl2gq4ujt5vpxkg

# Start without fee pressure. The spammer is what makes the replacer interesting, but
# it is a *later* experiment (see the fee ladder): it raises the fee floor, which raises what every
# speedup costs, which is a second variable on top of "does the port work at all".
ENABLE_SPAM=false

# With no spammer to starve, go as fast as the nodes allow. Timelocks are 15 blocks and
# the dispute protocol chains several, so cadence dominates the wall clock. Fixed rather
# than poisson: nothing here benefits from jitter, and fixed intervals make a run's
# duration reproducible.
BLOCK_INTERVAL_MODE=fixed
BLOCK_INTERVAL_MEAN_SECS=1     # exact seconds in fixed mode; MIN/MAX are ignored
```

> **Do not carry `BLOCK_INTERVAL_MEAN_SECS=1` over to the ts spam enabled runs.** With the spammer on, both it and the nodes
> need time per block. Refilling the mempool, and assembling and relaying full blocks
> from it. At 1s neither keeps up, the mempool stays shallow, and runs 2 to 5 pass without
> ever applying fee pressure. Use **`fixed`, 15s** with spam on; see
> [the cadence notes](#block-cadence-with-the-spammer-running) for why, and check
> `docker logs btc-simnet-spammer` for the `Spam cycle done in ...` line if you want to
> tune it for your machine.

then to get a new fresh simchain, the the simchain project dir execute:
```bash
./scripts/fresh-chain.sh --profile all-tools
```
or if you dont want the full simchain tools:
```bash
./scripts/fresh-chain.sh
```

`USER_ADDRESS` is only honoured at bootstrap, so this must be a *fresh* chain. A plain
`docker compose up` on an existing chain will not re-fund. Than can be achieved using the
faucet and even using simchain scenarios, but that are more advanced features

### Prove the premise

Before spending time on a full run. The chain is up now, so this relies on the `--no-run`
build above having already produced the binary:

```bash
cargo test --release --test simchain_smoke -- --ignored --nocapture --test-threads=1
```

Three checks: the BDK wallet scans a `-disablewallet` node and finds the bootstrap funds;
a raw broadcast at 20 sat/vB confirms without anyone being asked to mine; and every
mining / node-wallet call is refused *without the height moving*.

No `BITVMX_NETWORK_FLAVOR` here. This suite hardcodes `NetworkFlavor::Simchain`,
because a smoke test that silently ran against regtest would be worse than useless.

### Run the suite

```bash
# against simchain. Build first with the chain down, see above
BITVMX_NETWORK_FLAVOR=simchain RUST_BACKTRACE=1 \
    cargo test --release -- --ignored test_all
```

> **Take simchain down before running the regtest suite.** Regtest spawns its own
> bitcoind container on `127.0.0.1:18443`, which is the same port simchain's node1
> publishes. With both up the container fails to bind, and the failure surfaces as a
> confusing connection error rather than a port conflict. `docker compose --profile "*"
> down` in the simchain repo first.

The same variable selects the run target for the binary and the examples, which read it
through the same `NetworkFlavor::from_env()`. An unrecognized value panics rather than
defaulting to regtest. A typo must never silently start mining.
