# Castor

Castor is a Utreexo bridge node. It maintains the Bitcoin UTXO accumulator, produces compact
inclusion proofs for every new block, and serves them to Utreexo-aware peers over P2P.

It has three components:

- **Bootstrap builder**: builds the historical accumulator (flat forest), leaf map and header
  index in parallel from a synced Bitcoin Core node.
- **Steady-state prover**: follows the chain tip and persists a compact proof for each block.
- **P2P server**: a BIP324 (P2PV2-only) server that serves BIP183 block proofs and headers.

If you're interested in how the bridge is designed, see the [design document](docs/design.md).

### Why do we need a bridge?

In theory, Utreexo can work without bridges. In practice, every wallet and wallet backend
(e.g. every Electrum server) would have to be Utreexo-aware and generate proofs for the
transactions it produces. That is possible, but it requires all wallets to be updated, not
just a subset.

A bridge node, although not ideal, lets a few nodes generate proofs for the entire network. So
Utreexo nodes and wallets can work today, even if some wallets never adopt Utreexo. If you need
a bridge that is also a full node, see [utreexod](https://github.com/utreexo/utreexod).

## Requirements

- Linux x86-64 (the bootstrap builder is Linux-only)
- Rust 1.89.0 or later
- A C++20 toolchain, CMake 3.22 or later, and Boost (to compile `rust-bitcoinkernel`)
- At least 16 GB of RAM
- At least 500 GB of free disk space (1 TB recommended)
- A fully synced, **unpruned** Bitcoin Core node running with **`txindex=1`**. Castor trusts it
  as its source of blocks.

## Building

### From source

```bash
git clone https://github.com/getfloresta/castor
cd castor
cargo build --release
```

This builds two binaries: `bridge` (the node) and `bridge-hints` (the hintsfile generator).

### Docker

```bash
docker build -t bridge .
# or
docker pull dlsz/bridge
```

For a ready-to-run Signet setup with Docker Compose, see [docs/signet-setup.md](docs/signet-setup.md).

### Esplora backend (optional)

Castor can fetch blocks and transactions from an Esplora server instead of Bitcoin Core:

```bash
cargo build --release --features esplora
export ESPLORA_URL=https://blockstream.info/api
```

This removes the need for a local Bitcoin Core node, but it is slower and less secure. You must
trust the Esplora server to return correct blocks and transactions, because Castor has no way
to verify them.

## Quick start

Running Castor takes three steps. The examples use Signet. Files go to `$DATA_DIR`, which
defaults to `~/.bridge`.

**1. Get a hintsfile.** You can generate one yourself or download a pre-built one.

To generate it from your Bitcoin Core datadir, run `bridge-hints`. It reads Core's files directly
with `rust-bitcoinkernel`, so no RPC credentials are needed. By default it scans up to Core's
current tip; use `--stop-height` to choose a different height.

```bash
./target/release/bridge-hints --network signet --output /path/to/utxo.hints
```

Alternatively, download a pre-built one from a hintsfile server. For mainnet:

```bash
curl -L https://hints.lab.vinteum.org/bridge_hints_mainnet -o ./bitcoin.hints
```

Downloaded files must be bridge-format hintsfiles (starting with the `BRLFCT01` prefix); raw
`UTXO` hintsfiles are rejected. Only use a hintsfile from a source you trust.

**2. Build the forest** up to the hintsfile's stop height. This runs once and then exits:

```bash
ulimit -l unlimited   # lets the builder keep the forest in RAM (see Operations)
./target/release/bridge --network signet --build-forest /path/to/utxo.hints
```

**3. Run in steady state.** Castor continues from the stop height, follows the chain tip and
serves proofs to peers:

```bash
./target/release/bridge --network signet --steady-state /path/to/utxo.hints
```

Starting `bridge` without either `--build-forest` or `--steady-state` is an error.

## Configuration

### Command-line options

| Option | Default | Description |
| --- | --- | --- |
| `-n`, `--network` | `bitcoin` | Network, e.g. `bitcoin` or `signet` |
| `--build-forest <HINTS>` | | Build the historical forest, then exit |
| `--steady-state <HINTS>` | | Continue from a completed forest and serve proofs |
| `--forest-file` | `$DATA_DIR/forest.dat` | Flat forest file |
| `--leaf-map-path` | `$DATA_DIR/leaf-map` | Outpoint-to-position index |
| `--header-file` | `$DATA_DIR/headers.dat` | Block header file |
| `--header-index-path` | `$DATA_DIR/header-index` | Block-hash-to-height index |
| `--pollard-memory-mib` | `250` | Steady state: in-memory proof cache size |
| `--forest-leaf-workers` | half the CPUs | Bootstrap: block-fetching workers |
| `--forest-chaser-workers` | half the CPUs | Bootstrap: parent-hashing workers |
| `--forest-leaf-capacity` | leaf count | Bootstrap: preallocate more leaf positions |
| `--forest-no-mlock` | | Don't lock forest pages in RAM |

When you build the forest, the output paths must not already exist. Run `bridge --help` or
`bridge-hints --help` to see every option.

### Environment variables

Castor reads these variables from the environment or from a `.env` file. See
[`.env.sample`](.env.sample).

| Variable | Default | Description |
| --- | --- | --- |
| `DATA_DIR` | `~/.bridge` | Where Castor stores its data |
| `P2P_HOST` | `0.0.0.0` | P2P listen address |
| `P2P_PORT` | `8333` | P2P listen port |
| `BITCOIN_CORE_RPC_URL` | `localhost:8332` | Bitcoin Core RPC endpoint |
| `BITCOIN_CORE_COOKIE_FILE` | `~/.bitcoin/.cookie` | RPC cookie authentication |
| `BITCOIN_CORE_RPC_USER` / `BITCOIN_CORE_RPC_PASSWORD` | | RPC user/password authentication |
| `ESPLORA_URL` | | Esplora endpoint (requires the `esplora` feature) |

## P2P interface

In steady state, Castor listens on `P2P_HOST:P2P_PORT` and serves:

- Utreexo block proofs through the BIP183 `getuproof` / `uproof` messages, including Floresta's
  field mask for selecting targets, proof hashes and leaf data
- Block headers through `getheaders`

All connections use encrypted BIP324 (P2PV2). There is no P2PV1 fallback. Castor advertises
`NODE_WITNESS`, `NODE_P2P_V2` and `NODE_UTREEXO`. It **does not serve blocks**, so clients must
fetch blocks from a regular Bitcoin peer.

Inbound connections are capped at 64 peers. Peers that misbehave or send too much traffic are
disconnected.

## Operations

- **Memory locking.** The bootstrap builder tries to keep the forest resident in RAM. Allow
  this with `ulimit -l unlimited`, or with `LimitMEMLOCK=infinity` under systemd. Without this
  permission, the builder logs a warning and falls back to the page cache. Don't raise
  `vm.dirty_ratio` globally.
- **Logs.** The terminal shows progress and lifecycle events. Detailed timings and cache metrics
  go to `$DATA_DIR/debug.log`.
- **Durability.** Castor writes its state to disk in batches of 100 blocks. Graceful shutdown
  flushes all pending work. Recovering from a hard kill or power loss during a database write
  is not guaranteed.
- **Upgrades.** Keep `forest.journal`, `forest.journal.published` and any
  `forest.journal.forest-rows` together, and don't downgrade to an older binary. Leaf maps and
  header indexes from older versions are incompatible and must be rebuilt.

See [docs/design.md](docs/design.md) for details on storage formats, persistence and recovery.

## Roadmap

- [x] Parallel historical forest bootstrap
- [x] Pollard-backed steady-state block proofs
- [x] P2P proof and header serving
- [x] Bitcoin Core and optional Esplora backends
- [x] Online flat-forest growth and journal recovery
- [ ] Trusted UTXO commitment for instant IBD
- [ ] Forest bootstrap transfer between bridge nodes
- [ ] Socks5 and Tor transports

## Development

The fuzz targets require nightly Rust and `cargo-fuzz`:

```bash
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run journal_codec
cargo +nightly fuzz run pollard_behavior
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
