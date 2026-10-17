# urd

Cardano full node in Odin. Read ARCHITECTURE.md first: it holds the design
decisions and the roadmap.

## Commands

- `make test`: all test packages (optimized). Tests read fixtures from `refs/`.
- `make test-pkg PKG=src/cbor [NAME=cbor.test_x] [FAST=1]`: one package.
- `make build` / `make check`.
- `scripts/fetch-refs.sh`: clone the reference repos into `refs/` (gitignored)
  at pinned commits.

The shell is zsh-like: quote globs (`--include='*.hs'`), and don't start an
`echo` argument with `=`.

## Conventions

- Imports use the `urd` collection: `import "urd:cbor"`. Package names must be
  globally unique (hence `ccrypto`, not `crypto`).
- Procedures that use `or_return` with several results must name them.
- Hot paths take explicit allocators or caller-owned buffers. No hidden
  allocation, and nothing on the validation path whose cost an adversary can
  inflate.
- Decoders follow the Haskell decoders exactly, not the CDDL. Cite the
  Haskell source (file and function) in a comment when a rule is subtle.
  Blocks of era E decode at `eraProtVerLow E`: Shelley 2, Allegra 3, Mary 4,
  Alonzo 5, Babbage 7, Conway 9, Dijkstra 12.
- Keep original bytes (as slices or `base.Span`) for anything that is hashed.
- Consensus crypto lives in `ccrypto` and matches libsodium/cardano-base
  semantics. Never use `core:crypto/ed25519` for consensus.
- Docs written from Haskell sources live in `docs/decoding/`.
