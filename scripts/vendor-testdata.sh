#!/bin/sh
# Regenerate testdata/ from the reference repositories at their pinned
# commits (scripts/fetch-refs.sh). Tests only ever read testdata/; this script
# documents, and can reproduce, where every fixture came from.
# Provenance and licenses: testdata/README.md.
set -eu

cd "$(dirname "$0")/.."
scripts/fetch-refs.sh amaru cardano-base cardano-ledger dingo ouroboros-consensus pallas plutus

T=testdata

# copy SRC DST: replace DST with a copy of SRC (a file or a directory's contents).
copy() {
	rm -rf "$2"
	mkdir -p "$2"
	if [ -d "$1" ]; then
		cp -R "$1"/. "$2"/
	else
		cp "$1" "$2"/
	fi
}

# ImmutableDB chunks: 300 preview chunks (dingo) and two complete Babbage
# chunks (pallas; its third sample chunk is truncated on purpose).
copy refs/dingo/database/immutable/testdata "$T/immutable/preview"
rm -f "$T/immutable/preview/README.md"
rm -rf "$T/immutable/pallas"
mkdir -p "$T/immutable/pallas"
for n in 01285 01836; do
	cp refs/pallas/test_data/$n.chunk refs/pallas/test_data/$n.primary refs/pallas/test_data/$n.secondary "$T/immutable/pallas/"
done

# Single blocks: pallas's per-era real blocks (hex) and the ouroboros-consensus
# node-to-node goldens (blocks, headers, transactions per era).
rm -rf "$T/blocks/pallas"
mkdir -p "$T/blocks/pallas"
cp refs/pallas/test_data/*.block "$T/blocks/pallas/"
cp refs/pallas/test_data/dijkstra-fixtures.md "$T/blocks/pallas/"
copy refs/ouroboros-consensus/ouroboros-consensus-cardano/golden/cardano/CardanoNodeToNodeVersion2 "$T/blocks/consensus"

# Byron: dingo's complete preprod Byron chain (genesis EBB and 45 main
# blocks, as [type, block] pairs) and single mainnet blocks, plus
# cardano-ledger's Byron CBOR goldens (hex dumps of encoded values).
rm -rf "$T/byron"
mkdir -p "$T/byron/dingo"
for f in preprod-byron-chain.cbor preprod-byron-last-84242.cbor mainnet-byron-4471207.cbor mainnet-byron-last-4492799.cbor; do
	cp refs/dingo/ledger/testdata/$f "$T/byron/dingo/"
done
copy refs/cardano-ledger/eras/byron/ledger/impl/golden/cbor "$T/byron/golden"

# Amaru's labelled Conway decoding corpus.
copy refs/amaru/crates/amaru-kernel/tests/data/cbor.decode "$T/cbor-decode/amaru"
find "$T/cbor-decode/amaru" -name '*.js' -delete

# Crypto vectors: VRF (cardano-base) and Haskell-generated Sum6 KES keys and
# signatures (pallas).
copy refs/cardano-base/cardano-crypto-praos/test_vectors "$T/crypto/vrf"
copy refs/pallas/pallas-crypto/src/kes/data "$T/crypto/kes"

# Non-integral arithmetic: cardano-ledger's 100k golden lines and the node
# vectors collected by pallas.
rm -rf "$T/nonintegral"
mkdir -p "$T/nonintegral"
cp refs/cardano-ledger/libs/non-integral/reference/golden_tests.txt \
	refs/cardano-ledger/libs/non-integral/reference/golden_tests_result.txt "$T/nonintegral/"
for f in node-primitives.tsv node-comparisons.tsv node-extra-arithmetic.tsv node-vectors.tsv; do
	cp refs/pallas/pallas-math/tests/data/$f "$T/nonintegral/"
done

# The Plutus conformance suite (UPLC evaluation: programs, results, budgets).
copy refs/plutus/plutus-conformance/test-cases/uplc/evaluation "$T/plutus/conformance"

echo "testdata/ regenerated"
