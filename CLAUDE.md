# urd

Cardano full node in Odin. Read ARCHITECTURE.md first: it holds the design
decisions and the roadmap.

## Commands

- `just test`: all test packages (optimized). Fixtures live in `testdata/`.
- `just test src/cbor [cbor.test_x]`: one package, optionally one test.
  `just test-debug ...` builds the tests with debug info.
- `just build` / `just debug` / `just check`.
- `just fmt` / `just fmt-check`: odinfmt (Homebrew) with `odinfmt.json`. Run
  `just fmt` before committing.
- `just refs [name...]`: clone the reference repos into `refs/` (gitignored)
  at pinned commits, for reading their sources. Tests never read `refs/`.
- `just testdata`: regenerate `testdata/` (every fixture the tests use,
  vendored with provenance in testdata/README.md) from the pinned refs. New
  fixtures go through scripts/vendor-testdata.sh.
- CI (.github/workflows/ci.yml) runs `fmt-check`, then `check`, `build` and
  `test` on Linux x86_64 and macOS arm64, pinned to the same Odin release as
  local development.

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
