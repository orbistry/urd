# urd

A Cardano full node written in [Odin](https://odin-lang.org). urd aims to
accept and reject exactly what the Haskell `cardano-node` does, quirks
included, while being fast and frugal. Its data is laid out for how it is
processed: flat tables, spans into the original bytes, and no allocation on
the validation path.

urd is early. It decodes every era and validates the Byron era end to end;
the Shelley-and-later ledger, Plutus and the full node are still ahead. The
plan, and the decisions behind it, are in [ARCHITECTURE.md](ARCHITECTURE.md).

## What works today

- **Blocks of every era.** Byron through Conway decode with the same rules
  as the Haskell decoders (Dijkstra: headers only), including body hashes,
  transaction ids and KES, VRF and operational-certificate checks. The rules
  are written down, with citations, in [docs/decoding](docs/decoding).
- **Byron validation.** PBFT, the envelope, and the Byron ledger (UTxO,
  heavyweight delegation, the update system), from the genesis file to the
  Shelley hard fork. The whole preprod Byron chain and the first three
  mainnet epochs replay from genesis. The rules are in
  [docs/rules](docs/rules).
- **Storage.** cardano-node's ImmutableDB format (chunk, primary and
  secondary files), read and written byte for byte the same.
- **Network client.** Mux, handshake, chain-sync, block-fetch and
  keep-alive, enough to pull the chain from a public relay.
- **Crypto.** Ed25519 with both the libsodium (Shelley onwards) and
  ed25519-donna (Byron) semantics, ECVRF, Sum6 KES, and the exact fixed-point
  arithmetic of the leader check.

## Building

You need Odin `dev-2026-10` (the release CI uses), [just](https://just.systems),
and, for formatting, `odinfmt` (`brew install odinfmt`).

```sh
just build        # bin/urd
just test         # every test package
just check        # type-check without building
```

## Using the CLI

```
usage: urd <command> [options]

commands:
  bench-decode DIR [--passes N]
          decoding throughput over an ImmutableDB, and allocations in steady state
  diag    print CBOR (a file, or hex with --hex) in diagnostic notation
  fetch   pull blocks from a peer into an ImmutableDB directory
          --network mainnet|preprod|preview   (default preview)
          --peer HOST:PORT                     (default: the network's public relay)
          --out DIR                            (required)
          --blocks N                           (default 10000)
          --from SLOT.HASH                     (default: genesis)
  replay  DIR --genesis FILE [--requires-magic]
          validate an ImmutableDB's Byron era from its genesis (PBFT, ledger rules)
```

### Fetch blocks from a relay

`fetch` follows the chain from genesis (or from `--from SLOT.HASH`) and
writes the blocks as ImmutableDB chunks, the same files cardano-node keeps
in `db/immutable`. It stops k blocks short of the peer's tip, where blocks
can still roll back.

```sh
bin/urd fetch --network mainnet --out ~/cardano/mainnet --blocks 50000
```

```
connected to backbone.cardano.iog.io:3001 (node-to-node v15)
intersection at origin; peer tip at slot 200630344, block 14077935
500 blocks, slot 498, Byron, 215 blocks/s (headers 1.17s, blocks 1.16s)
1000 blocks, slot 998, Byron, 291 blocks/s (headers 0.93s, blocks 0.17s)
...
```

### Validate the Byron era

`replay` checks a database's Byron blocks against the genesis file:
signatures, the PBFT signing window, the envelope, every transaction, and
the delegation and update rules. It stops at the first block past Byron.
Testnets need `--requires-magic` (their addresses carry the network magic);
mainnet does not.

```sh
bin/urd replay ~/cardano/mainnet --genesis testdata/byron/genesis/mainnet.json
```

```
genesis 5f20df933584822601f9e3f8c024eb5eb252fe8cefb24d1317dc3d432e940ebb, magic 764824073, k 2160
epoch 0: 21587 blocks, 33 txs, utxo 14519 entries / 31112484741541947 lovelace, version 0.0.0, 1.1s
epoch 1: 43177 blocks, 12903 txs, utxo 19328 entries / 31112483708539269 lovelace, version 0.0.0, 2.7s
epoch 2: 50000 blocks, 14515 txs, utxo 20049 entries / 31112483552752530 lovelace, version 0.0.0, 3.2s
```

The counts are cumulative. Once the chain knows when Byron ends, the last
line says so (`Byron ends: Shelley starts at epoch N`).

### Measure decoding throughput

`bench-decode` loads a database into memory and decodes every block several
times, checking each body against its header. It also counts allocations in
the timed passes, which must stay at zero (`just bench` runs it on the
vendored preview chunks).

```sh
bin/urd bench-decode testdata/immutable/preview
```

```
testdata/immutable/preview: 59315 blocks, 21299 txs, 76.3 MiB, 300 chunks
best of 3 passes: 0.135s  438410 blocks/s  563.8 MiB/s  2.28 µs/block
allocations in timed passes: heap 0 (0 bytes), temp 0 (0 bytes)
```

### Inspect CBOR

```sh
bin/urd diag --hex 8200820058204ba839c420b3d2bd439530f891cae9a5d4c4d812044630dac72e8e0962feeecc
bin/urd diag testdata/blocks/consensus/Header_Byron_EBB
```

```
[0, [0, h'4ba839c420b3d2bd439530f891cae9a5d4c4d812044630dac72e8e0962feeecc']]
```

The second prints a chain-sync Byron header: `[0, [[0, 94], 24(h'…')]]`.

## Development

| Command | What it does |
|---|---|
| `just test src/cbor` | one test package |
| `just test src/cbor cbor.test_skip` | one test |
| `just test-debug ...` | tests built with debug info |
| `just bench [DB]` | decoding throughput (default: the vendored preview chunks) |
| `just fmt` / `just fmt-check` | format, or check formatting (CI runs the check) |
| `just refs [name...]` | clone the reference repositories into `refs/` at pinned commits |
| `just testdata` | regenerate `testdata/` from those references |

CI runs the format check, then the build and every test on Linux x86_64 and
macOS arm64.

### Layout

| Path | |
|---|---|
| `src/base` | hashes, slots, points, eras, spans |
| `src/cbor` | zero-copy CBOR reader and writer, with cborg's acceptance rules |
| `src/ccrypto` | Blake2b, Ed25519 (libsodium and donna), VRF, KES |
| `src/consensus` | leader-check arithmetic |
| `src/ledger` | Shelley-to-Conway decoding into block tables |
| `src/ledger/byron` | Byron decoding, genesis, PBFT and the Byron ledger |
| `src/network` | mux, mini-protocol messages, a blocking client |
| `src/storage/immutable` | ImmutableDB chunks |
| `src/cmd/urd` | the `urd` binary |
| `tests/` | integration tests over real chain data |
| `testdata/` | every fixture the tests read, with provenance |
| `docs/` | decoding and ledger rules, written from the Haskell sources |

### Tests and fixtures

Every fixture lives in `testdata/`, copied unmodified from other open-source
Cardano projects at pinned commits ([testdata/README.md](testdata/README.md)
lists each source), so the suite needs nothing outside the repository. It
includes:

- 300 preview ImmutableDB chunks;
- per-era blocks and goldens from ouroboros-consensus, cardano-ledger and
  pallas;
- Amaru's labelled decoding corpus;
- the VRF, KES and leader-check vectors;
- the Plutus conformance suite;
- the whole preprod Byron chain.

`refs/` (gitignored) holds the reference repositories for reading; the tests
never touch it.

## License

[Apache-2.0](LICENSE).
