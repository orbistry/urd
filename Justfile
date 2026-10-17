odin := env("ODIN", "odin")
collection := "-collection:urd=src"
checks := "-vet -strict-style -vet-cast -warnings-as-errors"
bin := "bin"

# List the recipes.
default:
    @just --list

# Build the node binary (optimised).
build:
    @mkdir -p {{bin}}
    {{odin}} build src/cmd/urd {{collection}} {{checks}} -o:speed -out:{{bin}}/urd

# Build the node binary with debug info.
debug:
    @mkdir -p {{bin}}
    {{odin}} build src/cmd/urd {{collection}} {{checks}} -debug -out:{{bin}}/urd-debug

# Type-check the node without building it.
check:
    {{odin}} check src/cmd/urd {{collection}} {{checks}}

# Fixtures are read from refs/ (see `just refs`).
[doc("Run tests (optimised): all, a package (just test src/cbor), or one test (just test src/cbor cbor.test_skip)")]
test pkg="" name="":
    @just _test speed "{{pkg}}" "{{name}}"

# Like `test`, but built with debug info for stepping through failures.
test-debug pkg="" name="":
    @just _test debug "{{pkg}}" "{{name}}"

[private]
_test mode pkg name:
    #!/bin/sh
    set -e
    mkdir -p {{bin}}
    if [ "{{mode}}" = debug ]; then opt=-debug; else opt=-o:speed; fi
    if [ -n "{{pkg}}" ]; then
        pkgs="{{pkg}}"
    else
        pkgs=$(find src tests -name '*_test.odin' -exec dirname {} \; | sort -u)
    fi
    names=""
    if [ -n "{{name}}" ]; then names="-define:ODIN_TEST_NAMES={{name}}"; fi
    for p in $pkgs; do
        echo "== $p"
        {{odin}} test "$p" {{collection}} {{checks}} $opt -define:ODIN_TEST_FANCY=false \
            -out:{{bin}}/test-$(echo "$p" | tr / -) $names
    done

# Clone the reference repositories into refs/ at their pinned commits.
refs *names:
    scripts/fetch-refs.sh {{names}}

# Remove build outputs.
clean:
    rm -rf {{bin}}
