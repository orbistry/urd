# Test data

Every fixture the tests read lives here, so the suite needs nothing outside
this repository. Each set was copied unmodified from another open-source
project at the commit pinned in `scripts/fetch-refs.sh`, and
`scripts/vendor-testdata.sh` (`just testdata`) regenerates the directory from
those commits. All sources are Apache-2.0, like this repository.

| Path | What | Source (repository, path) | Used by |
|------|------|---------------------------|---------|
| `immutable/preview/` | cardano-node ImmutableDB chunks 00000 to 00299 of the **preview** network: 59,315 Alonzo and Babbage blocks | [blinklabs-io/dingo](https://github.com/blinklabs-io/dingo) `database/immutable/testdata/` | `tests/chain` |
| `immutable/pallas/` | Two complete ImmutableDB chunks (01285, 01836): 1,777 Babbage blocks | [txpipe/pallas](https://github.com/txpipe/pallas) `test_data/` | `tests/chain` |
| `blocks/pallas/` | Single real blocks of every era as hex (Byron to Dijkstra), with `dijkstra-fixtures.md` describing the Dijkstra ones | [txpipe/pallas](https://github.com/txpipe/pallas) `test_data/*.block` | `tests/decode` |
| `blocks/consensus/` | Node-to-node goldens per era: blocks, headers, transactions, tx ids | [IntersectMBO/ouroboros-consensus](https://github.com/IntersectMBO/ouroboros-consensus) `ouroboros-consensus-cardano/golden/cardano/CardanoNodeToNodeVersion2/` | `tests/decode` |
| `cbor-decode/amaru/` | Conway blocks, transactions and transaction bodies labelled well-formed or not (`meta.json` beside each `sample.cbor`) | [pragma-org/amaru](https://github.com/pragma-org/amaru) `crates/amaru-kernel/tests/data/cbor.decode/` | `tests/decode` |
| `crypto/vrf/` | ECVRF vectors, IETF draft-03 and draft-13 (batch-compatible) | [IntersectMBO/cardano-base](https://github.com/IntersectMBO/cardano-base) `cardano-crypto-praos/test_vectors/` | `src/ccrypto` |
| `crypto/kes/` | Sum6 / CompactSum6 KES keys and signatures produced by the Haskell implementation | [txpipe/pallas](https://github.com/txpipe/pallas) `pallas-crypto/src/kes/data/` | `src/ccrypto` |
| `nonintegral/golden_tests*.txt` | 100,000 exp / ln / pow / Taylor-comparison cases at E34 precision | [IntersectMBO/cardano-ledger](https://github.com/IntersectMBO/cardano-ledger) `libs/non-integral/reference/` | `src/consensus` |
| `nonintegral/node-*.tsv` | Fixed-point primitives, comparisons and 648 leader checks taken from the node | [txpipe/pallas](https://github.com/txpipe/pallas) `pallas-math/tests/data/` | `src/consensus` |
| `plutus/conformance/` | The Plutus conformance suite: UPLC programs (`.uplc`, `.flat`) with expected results and budgets | [IntersectMBO/plutus](https://github.com/IntersectMBO/plutus) `plutus-conformance/test-cases/uplc/evaluation/` | `src/ccrypto` (Ed25519 builtin cases); the CEK machine later |

Notes:

- The first preview chunks are byte-identical to what `urd fetch --network
  preview` writes from a public relay.
- pallas's third sample chunk (02019) is truncated on purpose and is not
  vendored.
- Some fixtures are expected to fail to decode (with the reason recorded next
  to the test), because the Haskell ledger rejects them: three pallas Conway
  blocks and a class of Amaru tx-body cases whose labels follow the CDDL
  rather than the ledger.
