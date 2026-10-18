# urd architecture

urd is a Cardano full node written in Odin. It syncs and fully validates the
chain from the Byron genesis, keeps its ledger state on disk, and speaks the
Ouroboros node-to-node and node-to-client protocols.

This document records the decisions that shape the code. When a decision
changes, update this file in the same change.

## Ground rules

1. **Conformance first.** The Haskell `cardano-node` is the reference
   behaviour, including its quirks. Every consensus-relevant piece is tested
   against vectors produced by the Haskell implementation (see "Verification").
   Where specs and the reference disagree, we follow the reference and
   document it in a comment that points at the Haskell source.
2. **Worst case is the only case.** Following the blueprint's principles, we
   do not rely on caches or average-case behaviour that an adversary can
   defeat. Every lookup on the validation path has a bounded cost.
3. **Data-oriented.** Data is laid out by how it is processed:
   struct-of-arrays tables, flat arrays indexed by `u32` instead of pointer
   graphs, spans into original bytes instead of copies, per-block arenas
   instead of per-object allocation. Hot loops touch contiguous memory.
4. **Original bytes are sacred.** Cardano hashes the bytes as they were
   serialised (headers, tx bodies, aux data, scripts, datums, redeemers).
   We never re-encode in order to hash. Decoders return spans into the
   source buffer.
5. **No hidden allocation.** Hot-path procedures take explicit allocators or
   write into caller-provided tables. The context allocator is only used at
   the edges (startup, CLI, tests).
6. **Vendor C only where correctness demands it.** BLS12-381 (`blst`) and
   secp256k1 (`libsecp256k1`) are what Plutus uses, so we link exactly those.
   Everything else is Odin.

## Source layout

Odin packages live under `src/` and are imported through the `urd`
collection (`import "urd:cbor"`).

| Package            | Purpose |
|--------------------|---------|
| `base`             | Fixed-size hashes, slots/epochs, points, eras, span utilities, arenas. |
| `cbor`             | Zero-copy CBOR reader (spans, skip, strictness checks) and writer. |
| `ccrypto`          | blake2b wrappers, libsodium-compatible Ed25519, Byron (donna) Ed25519, VRF draft-03/draft-13, Sum6 KES, RIPEMD-160, bindings for blst and libsecp256k1. |
| `ledger/*`         | Per-era decoding into SoA block tables, ledger rules, epoch boundary, governance. |
| `consensus/*`      | Hard-fork combinator (era history), PBFT, TPraos, Praos, nonces, chain selection. |
| `plutus/*`         | Flat decoding, untyped Plutus core CEK machine, builtins, cost models, script context. |
| `storage/*`        | ImmutableDB (cardano-node chunk format), VolatileDB, disk-backed ledger tables. |
| `network/*`        | Multiplexer and the mini-protocol state machines (N2N and N2C). |
| `mempool`          | Transaction validation queue and tx-submission serving. |
| `node`             | Wiring: threads, event loop, configuration, tracing. |
| `cmd/urd`          | The node binary. Other tools live in `cmd/<tool>`. |

Tests sit next to the code as `*_test.odin`; integration tests live in
`tests/`. Every fixture is vendored in `testdata/`, copied from the reference
repositories at pinned commits by `scripts/vendor-testdata.sh` (provenance in
testdata/README.md), so the suite depends on nothing outside the repository.
`refs/` (gitignored) holds those repositories for reading.

## Key designs

### CBOR and decoding

The reader works on a `[]u8` with a cursor. Every read returns a value plus an
error that callers propagate with `or_return`. Besides typed reads it offers
`skip` (structural skip without allocation) and `span` (the raw bytes of the
next item), which is how we capture original bytes for hashing.

Strictness differs by era and protocol version (duplicate map keys, set tags
258, canonical integer widths, and so on). These are parameters of the
ledger decoders, which mirror `cardano-ledger-binary`'s version-gated
decoders, not global modes of the reader.

### Blocks as tables

A decoded block is a set of flat tables (`ledger.Block_Tables`), not a tree
of objects:

- `txs`: one row per transaction, holding the body span, the witness-set span,
  the validity flag, fee, TTL, and so on, plus ranges into the tables below.
- `inputs`, `outputs`, `assets`, `mint`, `certs`, `withdrawals`,
  `vkey_witnesses`, `scripts`, `datums`, `redeemers`, `votes`, `proposals`:
  flattened across the whole block.

Whole-block passes become linear scans. Examples are "verify every vkey
witness", "collect every UTxO key to prefetch", and "hash every script".
These scans parallelise trivially.

The tables are reused from block to block (`tables_reset` keeps their
capacity), and everything temporary that decoding needs, such as duplicate
checks and explicit stacks, comes from a per-block scratch arena owned by the
tables. Steady-state decoding allocates nothing; `just bench` measures
throughput and counts allocations to keep it that way.

The rows are still structs (AoS). They will be split hot/cold or moved to
`#soa` once the ledger rule passes exist, because the right columns depend on
those passes' access patterns, and the change should be measured with the
benchmark rather than guessed.

### Byron blocks

Byron blocks decode into their own tables (`byron.Tables`): transactions,
inputs, outputs, witnesses, delegation certificates, update proposals and
votes. Every Byron decoding check is structural or order-based (fixed shapes,
strictly increasing attribute keys), so Byron needs no scratch arena. Two
Byron hashing rules shape the decoder:

- A transaction id is the hash of the transaction re-encoded at version 1,
  not of the bytes received. The decoder accepts only the shapes the encoder
  produces, so the two differ only through non-minimal CBOR heads (including
  inside the CBOR-in-CBOR payloads of inputs and addresses). `heads_minimal`
  detects that case, and only then is the transaction re-encoded
  (`reencode_tx`). Every transaction in mainnet epochs 0 to 2 and in the
  fixtures is canonical.
- The body proof (Merkle root over the transactions as received, witnesses
  hash, delegation and update payload hashes) is computed while decoding.
  Comparing it with the header is a rule (`proof_matches`).

### Byron chain validation

`byron.Chain` follows the path cardano-node takes, not the ledger's own
CHAIN rule (docs/rules/byron-chain.md, byron-utxo.md,
byron-delegation-update.md, byron-genesis.md):

1. **Tick** to the block's slot: the update system's epoch transition (when
   the slot opens a later epoch), then delegation activation.
2. **Envelope**: block number (an EBB repeats its predecessor's), slot,
   previous hash.
3. **Ledger**: header and block size, body proofs, delegation certificates,
   the update payload and the header's endorsement, then the transactions.
4. **PBFT**: the block signature (donna Ed25519 under the delegate's key,
   with the configured magic), the delegate's genesis key, and the
   signature window (at most floor(0.22 k) of the last k blocks per key).

Nothing changes unless the whole block is valid. The delegation and update
states are small (every change needs a genesis delegate's signature), so each
block works on scratch copies that are swapped in on success. The UTxO
rules run against an overlay (what the block has consumed and produced so
far) over the store and commit it last. Bignum protocol parameters live in an
append-only pool the states refer to by span, so copying a state never copies
them.

The UTxO is held in memory (a hash index to 16-byte entries, addresses in a
compacting arena) until the on-disk table engine exists. It stores each
output's re-encoded address, which is what the Shelley translation inherits.

### Ledger state on disk

The ledger state follows the UTxO-HD shape:

- **Anchor.** The ledger state at the immutable tip (k blocks back) lives on
  disk.
- **Changelog.** In memory, one diff per volatile block (at most k), stored
  as SoA. A rollback drops diffs. As blocks become immutable, their diffs are
  flushed into the anchor in batches.
- **Block application is three phases.** (1) *Prepare*: scan the block tables
  and collect every key the block touches (inputs, reference inputs,
  collateral, credentials, pools, DReps, proposals). (2) *Fetch*: resolve the
  keys in one batch, first from the changelog and then from disk, using
  parallel I/O into a block-local working set. (3) *Validate*: run the rules
  purely in memory against the working set and emit a diff. No rule ever
  touches the disk directly.
- **Table engine.** Large tables (UTxO and accounts) live in our own on-disk
  engine. Keys are cryptographic hashes, so they are uniformly distributed.
  The engine targets a bounded number of page reads per lookup, atomic
  batched apply, and cheap snapshots (for epoch stake snapshots and
  restarts). Its design is settled in its own milestone.
- **Incremental stake.** Stake is aggregated per credential as the UTxO
  changes, so epoch-boundary snapshots never rescan the UTxO.

### Block storage

The ImmutableDB uses cardano-node's on-disk format: `.chunk`, `.primary` and
`.secondary` files. That buys three things:

- Mithril snapshots and existing cardano-node databases are directly usable.
- Test corpora built from real chunk files work as-is.
- Byte-for-byte compatibility is easy to check.

The VolatileDB, which holds the last k blocks and forks, uses our own simple
format.

### Consensus

- **Hard-fork combinator.** The era history is derived from the genesis
  files and the protocol-version transitions, and maps slots to epochs and
  times.
- **Byron** uses PBFT, with signatures from genesis delegates and the
  signing-window threshold.
- **Shelley to Alonzo** use TPraos (two VRF outputs, 512-bit leader values).
  **Babbage onwards** uses Praos (a single VRF with range extension, 256-bit
  leader values).
- **Leader check** uses the exact fixed-point `ln`/`exp` arithmetic of
  `cardano-ledger`'s non-integral library, tested against its 100k golden
  lines.
- **Chain selection** prefers the longest chain within the k-deep rollback
  bound, with the reference tie-breakers (opcert issue number, then VRF).
  Ouroboros Genesis comes later.

### Crypto

- **Ed25519** comes in two flavours, both built on `core:crypto/_edwards25519`:
  - *libsodium-exact* (Shelley onwards): S canonical, R and A not small
    order, A canonical, cofactorless equation. Odin's `core:crypto/ed25519`
    is deliberately stricter and cofactored, so it is *not* used for
    consensus.
  - *ed25519-donna* (Byron-era witnesses): permissive.
- **VRF** follows IETF draft-03 (Praos) and draft-13 (batch-compatible), with
  libsodium's Elligator2 quirks.
- **KES** is Sum6 over Ed25519 and Blake2b-256 (verification only on the
  validation path).
- **blst** and **libsecp256k1** are vendored and built into static libraries
  by the build script.

### Plutus

Flat-encoded programs are decoded into an SoA term arena (tags plus payload
indices). The CEK machine runs over that arena with a per-evaluation bump
allocator that is reset between scripts. Builtins and costing follow the
plutus repository's cost-model JSON files, one per semantics variant.
Phase-2 scripts within a block are independent once inputs are resolved, so
they evaluate in parallel.

### Concurrency

- One I/O thread runs the `core:nbio` event loop, which drives the
  multiplexer and the mini-protocols.
- A worker pool runs decoding, header crypto (VRF and KES), witness
  verification and script evaluation.
- Ledger application is sequential per block and parallel within a block.

## Verification

| Area | Source of truth |
|------|-----------------|
| Byron ledger | dingo's preprod Byron chain (full replay: proposals, votes, adoption, the Shelley transition epoch); mainnet epochs 0 to 2 (redemptions, 15,706 witnesses); signed synthetic certificates, proposals and votes for every rule. |
| CBOR, blocks | ouroboros-consensus goldens (`ouroboros-consensus-cardano/golden`), pallas `test_data`, the dingo preview ImmutableDB corpus (300 chunks), dingo's preprod Byron chain, cardano-ledger's Byron CBOR goldens, ledger CDDLs. |
| Crypto | cardano-base VRF, KES and BLS vectors; plutus builtin conformance cases; hash-parity goldens. |
| Leader math | `cardano-ledger/libs/non-integral/reference` golden tests; pallas `node-vectors.tsv`. |
| Headers | amaru `header-test-cases.json` (Haskell-generated mutations). |
| Ledger rules | cardano-blueprint conformance vectors (2574, Conway ImpSpec); amaru tx scenarios. |
| Plutus | `plutus-conformance` (UPLC, flat, budgets). |
| End to end | Replay preview, preprod and mainnet from genesis, comparing epoch stake distributions, nonces and ledger-state hashes against cardano-node. |

## Roadmap

Each milestone ends with its verification suite passing. Status: 1, 2
(Byron through Conway; Dijkstra headers only), 3 and 5 are done. 4 has both
Ed25519 flavours, VRF and KES; RIPEMD-160, blst and libsecp256k1 remain. 6
validates the whole preprod Byron chain and mainnet epochs 0 to 2 from
genesis (`urd replay`); a full mainnet Byron replay, checkpoints and
header-only validation for chain-sync (the delegation forecast) remain.

1. **Foundation.** Build script, base types, CBOR reader and writer, blake2b.
2. **Blocks.** Decode every era (Byron EBB/main through Conway, Dijkstra
   later) into block tables. Decode the full preview corpus and all goldens.
3. **ImmutableDB.** Read and write chunk files; iterate a whole database.
4. **Crypto.** Ed25519 (both flavours), VRF, KES, RIPEMD-160; vendor blst and
   libsecp256k1.
5. **Network client.** Mux, handshake, chain-sync, block-fetch and keep-alive.
   Sync preview from a public relay into our ImmutableDB.
6. **Byron.** PBFT and the Byron ledger (UTxO, delegation, update system).
   Replay the Byron era.
7. **Ledger store.** On-disk table engine and changelog.
8. **Shelley to Conway.** Ledger rules, epoch boundary (snapshots, rewards,
   pool reap), governance, TPraos and Praos header validation. Replay preview
   and preprod.
9. **Plutus.** Phase-2 validation (V1 to V3), script context construction.
10. **Full node.** Chain selection with rollbacks, VolatileDB, mempool,
    tx-submission, N2N responders, N2C protocols, peer selection.
11. **Beyond.** Block forging, Mithril bootstrap, Ouroboros Genesis,
    Dijkstra, Leios.
