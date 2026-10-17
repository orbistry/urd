#!/bin/sh
# Clone the reference repositories used by tests into refs/ at pinned commits.
# Usage: scripts/fetch-refs.sh [name...]   (no args = all)
set -eu

cd "$(dirname "$0")/.."
mkdir -p refs

REFS="
CIPs cardano-foundation/CIPs befcdb75289cb6571ffba6dbece3249ad2bfd491
amaru pragma-org/amaru 03acfc01807e5e2a8a5466541ad22c856f3de99c
cardano-base IntersectMBO/cardano-base 5813d21182c91fa00f8e799a787ef1759d469b26
cardano-blueprint cardano-scaling/cardano-blueprint 0460c5a6152ae094bcfdad64a54b1a6561d7e38a
cardano-formal-specifications IntersectMBO/cardano-formal-specifications 95b5073151508530360c05c6024922dceed353d7
cardano-ledger IntersectMBO/cardano-ledger 178bd36839dcb57f257efc0e96615284d1632088
cardano-node IntersectMBO/cardano-node 4d3ad24938188e2c42db1dd9927f52903f0538a4
dingo blinklabs-io/dingo 20328a802711417c220a60b8cfa9cf878beddac4
formal-ledger-specifications IntersectMBO/formal-ledger-specifications 07baac524022021489e7501c9adf8a8cc6da2e58
gouroboros blinklabs-io/gouroboros 80e9a8069d0334ce41b02bf1cc99ea66c8a4da07
ouroboros-consensus IntersectMBO/ouroboros-consensus 9b918f8a14a9564d0f95b7080a30dad30203a16b
ouroboros-network IntersectMBO/ouroboros-network 2fb69829a19b5c04e4fb212bdd78fb63f9d2d776
pallas txpipe/pallas e6c38ac567ee907db6a3cfdbbcaae1b47908d839
plutus IntersectMBO/plutus 7ab93b9ddb3ec11c2d89b9dc9c6d6e6af4544917
uplc pragma-org/uplc 39c82af9b23e2d611f1eac4a905b5e421c755631
"

echo "$REFS" | while read -r name repo sha; do
	[ -n "$name" ] || continue
	if [ $# -gt 0 ]; then
		case " $* " in *" $name "*) ;; *) continue ;; esac
	fi
	dir="refs/$name"
	if [ -d "$dir/.git" ] && [ "$(git -C "$dir" rev-parse HEAD)" = "$sha" ]; then
		echo "$name: up to date"
		continue
	fi
	mkdir -p "$dir"
	git -C "$dir" init -q
	git -C "$dir" remote remove origin 2>/dev/null || true
	git -C "$dir" remote add origin "https://github.com/$repo.git"
	git -C "$dir" fetch -q --depth 1 origin "$sha"
	git -C "$dir" checkout -q FETCH_HEAD
	echo "$name: $sha"
done
