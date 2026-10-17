ODIN       ?= odin
COLLECTION := -collection:urd=src
CHECKS     := -vet -strict-style -vet-cast -warnings-as-errors
OPT        ?= -o:speed

BIN_DIR    := bin

# Every package directory under src/ and tests/ that contains tests.
TEST_PKGS  := $(sort $(patsubst %/,%,$(dir $(shell find src tests -name '*_test.odin'))))

.PHONY: all build debug check test test-pkg clean refs

all: build

build:
	@mkdir -p $(BIN_DIR)
	$(ODIN) build src/cmd/urd $(COLLECTION) $(CHECKS) $(OPT) -out:$(BIN_DIR)/urd

debug:
	@mkdir -p $(BIN_DIR)
	$(ODIN) build src/cmd/urd $(COLLECTION) $(CHECKS) -debug -out:$(BIN_DIR)/urd-debug

check:
	$(ODIN) check src/cmd/urd $(COLLECTION) $(CHECKS)

# Run all test packages. Tests read fixtures from refs/ (see scripts/fetch-refs.sh).
test:
	@mkdir -p $(BIN_DIR)
	@set -e; for p in $(TEST_PKGS); do \
		echo "== $$p"; \
		$(ODIN) test $$p $(COLLECTION) $(CHECKS) -o:speed -define:ODIN_TEST_FANCY=false \
			-out:$(BIN_DIR)/test-$$(echo $$p | tr / -); \
	done

# Run one package's tests: make test-pkg PKG=src/cbor [NAME=cbor.test_name] [FAST=1]
test-pkg:
	@mkdir -p $(BIN_DIR)
	$(ODIN) test $(PKG) $(COLLECTION) $(CHECKS) $(if $(FAST),-o:speed,-debug) -define:ODIN_TEST_FANCY=false \
		-out:$(BIN_DIR)/test-$(subst /,-,$(PKG)) $(if $(NAME),-define:ODIN_TEST_NAMES=$(NAME))

refs:
	scripts/fetch-refs.sh

clean:
	rm -rf $(BIN_DIR)
