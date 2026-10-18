# Rules reference: the Byron genesis

This is an implementer's reference for how cardano-node turns the Byron genesis file into the
initial Byron chain state: what the JSON parser accepts, what is hashed to get the genesis hash,
how the genesis UTxO, the genesis delegation and the initial update state are built, and which
constants are derived from the file. Every rule cites the Haskell source it comes from. Hashes and
byte strings marked **computed** were reproduced with Python from the real genesis files while
writing this document. Where a computation was also checked against real chain data, the text
says so.

Sources (pinned clones under `refs/`):

| repo | commit |
|---|---|
| cardano-ledger | `178bd36` |
| ouroboros-consensus | `9b918f8` |
| cardano-node | `4d3ad24` |
| cardano-crypto | `ac2e12a` |
| crypton | `d5fb2cb` |
| dingo (genesis and config files only) | `20328a8` |

Two libraries that matter here are **not** vendored: `canonical-json` (the JSON parser and the
canonical renderer, module `Text.JSON.Canonical`) and `cardano-prelude` (the canonical-JSON
instances for `Word16`, `Word32`, `Word64`, `Integer`, `Natural` and `UTCTime`). Statements that
depend on them are marked **(verify)**. Section 9 lists them.

Path abbreviations used in citations:

| abbreviation | path under `refs/` |
|---|---|
| `byron/` | `cardano-ledger/eras/byron/ledger/impl/src/Cardano/Chain/` |
| `byron-crypto/` | `cardano-ledger/eras/byron/crypto/src/Cardano/Crypto/` |
| `bin/` | `cardano-ledger/libs/cardano-ledger-binary/src/Cardano/Ledger/Binary/` |
| `oc-byron/` | `ouroboros-consensus/ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/` |
| `oc-core/` | `ouroboros-consensus/ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/` |
| `oc-diffusion/` | `ouroboros-consensus/ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/` |
| `node/` | `cardano-node/cardano-node/src/Cardano/Node/` |
| `cfg/` | `cardano-node/configuration/cardano/` |
| `dingo-cfg/` | `dingo/config/cardano/` |
| `cardano-crypto/` | `cardano-crypto/src/Cardano/Crypto/` |
| `crypton/` | `crypton/Crypto/` |

Terminology:

- **Fatal** means cardano-node refuses to start: a config parse error, a hash mismatch, or an
  `error` while the initial ledger state is built. None of the rules in this document can reject a
  block. They decide what state blocks are validated against.
- **KeyHash** is the Byron key hash: `blake2b-224(sha3-256(CBOR(vk)))`, where `vk` is the 64-byte
  extended verification key (5.2).
- **pm** is the protocol magic, a `Word32` (`byron-crypto/ProtocolMagic.hs:58-60`).
- CBOR shown as hex is minimal unless stated otherwise. `‖` is concatenation.

---

## 0. Summary

1. Read the file named by `ByronGenesisFile` and parse it with the canonical-JSON parser (2.1).
2. The genesis hash is `blake2b-256` of the **canonical re-rendering of the whole parsed JSON
   value**: keys sorted, no whitespace, every field kept, including the ones the schema ignores.
   It is **not** a hash of the file bytes (3.1). If `ByronGenesisHash` is set in the node config, a
   mismatch is fatal. If it is absent, nothing is checked (3.4).
3. Decode the fields in 2.2 to 2.8. `vssCerts`, `ftsSeed`, `protocolConsts.vssMaxTTL` and
   `protocolConsts.vssMinTTL` are ignored but still hashed (2.9).
4. `RequiresNetworkMagic` comes from the **node config**, not the genesis file. It decides whether
   AVVM redeem addresses carry the network-magic attribute (4.2) and what network magic tx outputs
   must have (6).
5. Genesis UTxO: one output per AVVM key (redeem address) and per non-AVVM address. The TxIn is
   `(blake2b-256(CBOR(address)), 0)` (4.4).
6. Genesis delegation certificates get the full ledger check at start-up: issuer in
   `bootStakeholders`, epoch 0 or 1, and a valid signature over
   `0x0a ‖ CBOR(pm) ‖ CBOR_bytes("00" ‖ delegate_xpub ‖ CBOR(epoch))`. Any failure is fatal (5.3).
7. The initial delegation map starts as the identity on genesis keys, and each genesis
   certificate then overrides its issuer (5.4).
8. Initial `ChainValidationState`: last slot 0, previous hash `Left genesisHash`, the genesis UTxO,
   the update state with protocol version 0.0.0 and the genesis `blockVersionData` as adopted
   parameters, and the delegation state from step 7 (7).

---

## 1. Loading pipeline

### 1.1 Node configuration keys (`parseByronProtocol`, `node/Configuration/POM.hs:583-611`)

| key | required | default | effect | cite |
|---|---|---|---|---|
| `ByronGenesisFile` (or legacy `GenesisFile`) | exactly one of the two | none | path of the genesis JSON. Both present, or neither, is a config error | `POM.hs:584-593` |
| `ByronGenesisHash` | no | none | expected genesis hash (hex of 32 bytes). Checked only if present | `POM.hs:594`; `node/Types.hs:205`, `256` |
| `RequiresNetworkMagic` | no | `RequiresNoMagic` | `"RequiresNoMagic"` or `"RequiresMagic"` (the Aeson instance also accepts the legacy spellings `"NMMustBeNothing"` and `"NMMustBeJust"`) | `POM.hs:596-597`; `byron-crypto/ProtocolMagic.hs:136-150` |
| `PBftSignatureThreshold` | no | 0.22 (`defaultPBftSignatureThreshold`) | PBFT per-key signing threshold, a `Double` | `POM.hs:598`; `oc-byron/Node.hs:178-179`, `268-274` |
| `LastKnownBlockVersion-Major`, `-Minor` | yes | none | protocol version written into **forged** blocks only | `POM.hs:599-600` |
| `LastKnownBlockVersion-Alt` | no | 0 | as above | `POM.hs:601` |

Values in the shipped configs: mainnet `RequiresNoMagic` (`cfg/mainnet-config.json:26`); preprod and
preview `RequiresMagic` (`dingo-cfg/preprod/config.json:23`, `dingo-cfg/preview/config.json:27`).
None of the three sets `PBftSignatureThreshold`, so all use 0.22.

### 1.2 Reading and checking the file (`readGenesis`, `node/Protocol/Byron.hs:87-125`)

1. `Genesis.readGenesisData file` returns `(GenesisData, GenesisHash)` (`Byron.hs:93-94`). Any read,
   parse or schema error is fatal (`GenesisReadError`).
2. If `ByronGenesisHash` was given and differs from the computed hash, the node fails with
   `GenesisHashMismatch actual expected` (`Byron.hs:104-113`). With no expected hash the check is
   skipped (`Byron.hs:113`).
3. The node builds `Genesis.Config { configGenesisData, configGenesisHash, configReqNetMagic =
   RequiresNetworkMagic from the node config, configUTxOConfiguration =
   UTxO.defaultUTxOConfiguration }` (`Byron.hs:96-102`). The Cardano protocol path passes this
   config to consensus unchanged (`node/Protocol/Cardano.hs:163-185`).

`mkConfigFromFile` in the ledger does the same, except that the hash check is mandatory
(`byron/Genesis/Config.hs:137-159`). cardano-node does not use it.

### 1.3 Consensus (`protocolInfoByron`, `oc-byron/Node.hs:216-257`)

- PBFT params: security parameter `k`, number of core nodes = `|bootStakeholders|`, signature
  threshold (`byronPBftParams`, `Node.hs:268-274`).
- The block, codec and ledger configs use the **compacted** genesis config, with `avvmDistr`
  emptied to save memory (`oc-byron/Ledger/Config.hs:105-112`; `Node.hs:255`, `257`).
- The initial ledger state is built from the **full** config (`Node.hs:241-244`) by
  `initByronLedgerState`, which calls `initialChainValidationState` and turns any `Left` into an
  `error` (`oc-byron/Ledger/Ledger.hs:132-156`). **A bad genesis delegation certificate is fatal**
  (5.3).
- The initial header state is `genesisHeaderState S.empty`: tip at Origin and an empty PBFT signer
  window (`Node.hs:245`).

---

## 2. JSON schema (`FromJSON GenesisData`)

`readGenesisData` (`byron/Genesis/Data.hs:165-181`):

```
bytes  <- readFile fp                                   -- raw file bytes
json   <- parseCanonicalJSON bytes                      -- GenesisDataParseError
gd     <- fromJSON json                                 -- GenesisDataSchemaError
hash    = hashRaw (renderCanonicalJSON json)            -- GenesisHash (section 3)
```

### 2.1 The parser (canonical-json, **verify**: not vendored)

`parseCanonicalJSON` accepts the "canonical JSON" **format**, not necessarily canonical **form**.
The real files are pretty-printed, and mainnet and preprod use different layouts (4-space indent
versus leading-comma style). Both parse and hash correctly. As understood (verify):

- Whitespace between tokens is skipped.
- Numbers are integers only (`Int54`, magnitude at most 2^53-1): optional `-`, then `0` or a
  non-zero digit followed by more digits. No fraction, exponent or leading `+`.
- Strings are raw bytes between `"`. The only escapes are `\"` and `\\`. The input is treated as
  Latin-1 (`Data.ByteString.Lazy.Char8`), so UTF-8 passes through byte for byte.
- An object is an association list. Order and duplicate keys are preserved in the parsed value.

**Implementer rule:** accept exactly what the three real files need, which is integers, ASCII
strings without escapes, objects and whitespace, and **reject** everything else (floats, escapes,
`null`, booleans, non-ASCII bytes, duplicate keys). Every value in the real files is either an
object, a string or a small integer.

### 2.2 Top level

`fromJSON` (`Data.hs:85-102`). `fromJSField` fails if a field is missing. Fields not listed below
are ignored, but they are still hashed (2.9).

| JSON field | type in JSON | Haskell field / type | validation | used for | cite |
|---|---|---|---|---|---|
| `bootStakeholders` | object `{KeyHashHex: int}` | `gdGenesisKeyHashes :: Set KeyHash` | key: hex of exactly 28 bytes. Value: a JSON number parsed as `Word16` (verify) and **discarded** | genesis keys (5.6) | `Data.hs:93`; `byron/Genesis/KeyHashes.hs:27-29`, `40-42` |
| `heavyDelegation` | object `{KeyHashHex: cert}` | `gdHeavyDelegation :: Map KeyHash Certificate` | 2.8 and 5.1 | initial delegation (5) | `Data.hs:94`; `byron/Genesis/Delegation.hs:42-58` |
| `startTime` | number (seconds since the Unix epoch) | `gdStartTime :: UTCTime` | `Int54` → `posixSecondsToUTCTime` (verify) | `SystemStart` (6) | `Data.hs:95` |
| `nonAvvmBalances` | object `{base58Address: "lovelace"}` | `gdNonAvvmBalances :: Map Address Lovelace` | 2.6 | genesis UTxO (4.3) | `Data.hs:96`; `byron/Genesis/NonAvvmBalances.hs:45-47`, `61-62` |
| `blockVersionData` | object | `gdProtocolParameters :: ProtocolParameters` | 2.4 | adopted params at genesis (7) | `Data.hs:97` |
| `protocolConsts.k` | number | `gdK :: BlockCount` (`Word64`) | parsed as `Int54`, then `fromIntegral` to `Word64` (a negative value would wrap). Consensus rejects 0 with `error` (`oc-byron/Ledger/Conversions.hs:44-45`) | k (6) | `Data.hs:100`; `byron/Common/BlockCount.hs:20-22` |
| `protocolConsts.protocolMagic` | number | `gdProtocolMagicId :: ProtocolMagicId` (`Word32`) | canonical `FromJSON Word32` (verify: believed to be an unchecked `fromIntegral`) | signing context, network magic | `Data.hs:101`; `byron-crypto/ProtocolMagic.hs:58-60`, `95-96` |
| `avvmDistr` | object `{base64urlKey: "lovelace"}` | `gdAvvmDistr :: Map CompactRedeemVerificationKey Lovelace` | 2.5 | genesis UTxO (4.2) | `Data.hs:102`; `byron/Genesis/AvvmBalances.hs:33-42` |

`protocolConsts` is looked up with `Data.List.lookup`, so a duplicate key resolves to the first
occurrence (`Data.hs:88-90`). A missing `protocolConsts` is a schema error.

### 2.3 Integer encodings in JSON

There are two conventions, depending on the Haskell type (verify; these are the cardano-prelude and
canonical-json instances):

- **JSON number** (`Int54`): `k`, `protocolMagic`, `startTime`, `scriptVersion` (`Word16`),
  `omega` (`Int54`), and the `bootStakeholders` weights (`Word16`).
- **JSON string of decimal digits** (`Word64`, `Natural` and `Integer` are parsed with
  `readEither`): every lovelace amount, every `LovelacePortion`, the sizes, `slotDuration`,
  `updateImplicit`, `unlockStakeEpoch`, and both `txFeePolicy` fields. The genesis files rely on
  this because `canonical-json` numbers stop at 2^53 (`byron/Common/LovelacePortion.hs:85-87`).

Haskell's `read` is more lenient than plain decimal (whitespace, and possibly signs or `0x`
literals, with `Word64` wrapping), so its exact edge cases are an open question (9). **Implementer
rule:** accept `^[0-9]+$` and range-check for the target type.

### 2.4 `blockVersionData` (`ProtocolParameters`, `byron/Update/ProtocolParameters.hs:41-69`, `144-160`)

All 14 fields are required. The name `blockVersionData` survives from cardano-sl (`Data.hs:97-99`).

| JSON field | JSON form | Haskell type | unit and meaning | mainnet = preprod = preview | used? | cite |
|---|---|---|---|---|---|---|
| `scriptVersion` | number | `Word16` | none | 0 | only by update-proposal checks (`byron/Update/Validation/Registration.hs:540-541`) | `ProtocolParameters.hs:42` |
| `slotDuration` | string | `Natural` | **milliseconds** | "20000" (20 s) | consensus era slot length, always the **genesis** value (6) | `:43-44`; `oc-byron/Ledger/Conversions.hs:89-92` |
| `maxBlockSize` | string | `Natural` | bytes | "2000000" | block size limit (adopted value) | `:45`; `byron/Block/Validation.hs:410-411` |
| `maxHeaderSize` | string | `Natural` | bytes | "2000000" | header size limit | `:46`; `Block/Validation.hs:468` |
| `maxTxSize` | string | `Natural` | bytes | "4096" | tx size limit | `:47`; `byron/UTxO/Validation.hs:221` |
| `maxProposalSize` | string | `Natural` | bytes | "700" | update proposal size limit | `:48`; `Registration.hs:533` |
| `mpcThd` | string | `LovelacePortion` | numerator over 10^15 | "20000000000000" | unused | `:49` |
| `heavyDelThd` | string | `LovelacePortion` | numerator over 10^15 | "300000000000" | unused | `:50` |
| `updateVoteThd` | string | `LovelacePortion` | numerator over 10^15 | "1000000000000" | unused | `:51` |
| `updateProposalThd` | string | `LovelacePortion` | numerator over 10^15 | "100000000000000" | unused | `:52` |
| `updateImplicit` | string | `SlotNumber` (`Word64`) | slots: proposal TTL | "10000" | update proposals | `:53-65`; `byron/Update/Validation/Interface.hs:480` |
| `softforkRule.initThd` | string | `LovelacePortion` | numerator over 10^15 | "900000000000000" | unused | `byron/Update/SoftforkRule.hs:41-48`, `90-95` |
| `softforkRule.minThd` | string | `LovelacePortion` | numerator over 10^15 | "600000000000000" (0.6) | **used**: `upAdptThd` (6) | `ProtocolParameters.hs:217-221` |
| `softforkRule.thdDecrement` | string | `LovelacePortion` | numerator over 10^15 | "50000000000000" | unused | `SoftforkRule.hs:46` |
| `txFeePolicy.summand` | string | `Word64`, then **`div` 10^9** (truncating), then `mkLovelace` (≤ 45·10^15) | nano-lovelace in JSON | "155381000000000" → 155381 lovelace | min fee | `byron/Common/TxFeePolicy.hs:109-124` |
| `txFeePolicy.multiplier` | string | `Integer`, then `% 10^9`, an exact `Rational` | nano-lovelace per byte in JSON | "43946000000" → 21973/500 = 43.946 | min fee | `TxFeePolicy.hs:119-124`; `byron/Common/TxSizeLinear.hs:46-47` |
| `unlockStakeEpoch` | string | `EpochNumber` (`Word64`) | epoch | "18446744073709551615" (`maxBound`) | effectively unused (`isBootstrapEraPP` has no caller) | `:68`; `ProtocolParameters.hs:207-208` |

Validation applied while parsing:

- **`LovelacePortion`**: the numerator must be ≤ 10^15, otherwise a schema error
  (`byron/Common/LovelacePortion.hs:91-104`).
- **`txFeePolicy.summand`**: after the division by 10^9, `mkLovelace` requires ≤ 45·10^15
  (`TxFeePolicy.hs:112-118`; `byron/Common/Lovelace.hs:179-187`).
- Nothing else is range-checked. A `Natural` field must parse as a non-negative integer (verify).

### 2.5 `avvmDistr`

Key decoding (`FromObjectKey CompactRedeemVerificationKey`,
`byron-crypto/Signing/Redeem/Compact.hs:141-145` → `fromAvvmVK`,
`byron-crypto/Signing/Redeem/VerificationKey.hs:120-129`):

1. Replace `-` with `+` and `_` with `/`. This turns base64url into the standard alphabet.
2. Decode with `Data.ByteString.Base64.decode`, which is strict and requires padding (verify). All
   14,505 mainnet keys are 44 characters ending in `=`.
3. The result must be exactly 32 bytes (`ApeAddressLength`), otherwise a schema error.
4. `redeemVKBuild` → `Ed25519.publicKey`, which checks only the length. It does **not** validate
   the curve point (`VerificationKey.hs:101-115`; `crypton/PubKey/Ed25519.hs:64-69`).
5. The key is stored compactly as four little-endian `Word64`s and converted back to the same 32
   bytes when used (`Compact.hs:57-63`, `108-127`).

Value: `Lovelace` via `fromJSON @Word64` (a decimal string) (`byron/Common/Lovelace.hs:117-118`).
**There is no `maxLovelaceVal` check on genesis amounts.** The `≤ 45·10^15` bound is enforced only
by the CBOR decoder (`Lovelace.hs:107-112`) and by `mkLovelace`.

Container: a `Map`. Duplicate JSON keys collapse, probably last-wins (`Map.fromList`) (verify:
canonical-json's `Map` instance). Map order is the byte order of the 32-byte keys
(`Compact.hs:129-130`; `VerificationKey.hs:79-81`).

### 2.6 `nonAvvmBalances`

Key decoding: `FromObjectKey Address` → `decodeAddressBase58` (`byron/Common/Address.hs:188-189`,
`233-243`):

1. Base58 with the **Bitcoin alphabet** (`Address.hs:219-220`). Each leading `1` becomes a `0x00`
   byte.
2. `decodeFull' byronProtVer`: the full Byron address decoder, which requires all input to be
   consumed. See `docs/decoding/witnesses-auxdata-byron.md` B.3.5 for the decoder: CRC check,
   tag 24, canonical attributes, address type 0 or 2.
3. No network-magic check. A testnet genesis may list any address.

Value: `Lovelace` (a decimal string, no upper bound), as in 2.5. **Zero is allowed.** Preprod and
preview each list seven addresses with `"0"`, and each still gets a zero-value UTxO entry (4.5).

(`convertNonAvvmDataToBalances`, which sums duplicates with `addLovelace`, is used only by genesis
generation, not by `readGenesisData`: `byron/Genesis/NonAvvmBalances.hs:97-123`.)

### 2.7 `bootStakeholders`

`FromJSON GenesisKeyHashes = GenesisKeyHashes . M.keysSet <$> fromJSON @(Map KeyHash Word16)`
(`byron/Genesis/KeyHashes.hs:40-42`).

- Key: `decodeAbstractHash`, which is base16, then exactly 28 bytes (`byron/Common/KeyHash.hs:49-53`;
  `byron-crypto/Hashing.hs:196-205`).
- Value: must be a JSON number (`Word16`, verify), and is thrown away. All the real files use 1.
- There must be at most 255 genesis keys. More panics in `toNumGenKeys` the first time the update
  rules run (`byron/Byron/API/Mempool.hs:176-182`; `byron/Block/Validation.hs:440`, `503`).

### 2.8 `heavyDelegation`

Shape: `{ KeyHashHex: { "omega": int, "issuerPk": b64, "delegatePk": b64, "cert": hex } }`.

| field | decode | cite |
|---|---|---|
| map key | `KeyHash` (hex, 28 bytes) | `KeyHash.hs:49-53` |
| `omega` | `Int54`, `fromIntegral` → `EpochNumber` (`Word64`; a negative value wraps) | `byron/Delegation/Certificate.hs:257-263` |
| `issuerPk`, `delegatePk` | **standard** base64 (`+`, `/`, padding), exactly 64 bytes → `CC.xpub`: 32-byte Ed25519 public key ‖ 32-byte chain code | `byron-crypto/Signing/VerificationKey.hs:75-76`, `137-140`; `cardano-crypto/Wallet.hs:144-149` |
| `cert` | base16, exactly 64 bytes (`CC.xsignature`) | `byron-crypto/Signing/Signature.hs:93-94`, `120-124` |

Parse-time invariants (`recreateGenesisDelegation`, `byron/Genesis/Delegation.hs:114-127`). Each is
a schema error, so fatal:

1. Every map key must equal `hashKey issuerPk` (`GenesisDelegationInvalidKey`, `:120-121`).
2. No delegate may also be an issuer in the map: `hashKey delegatePk ∉ keys`
   (`GenesisDelegationMultiLayerDelegation`, `:123-125`). This also rules out self-delegation,
   because the delegate's hash would equal the issuer's key.

**No signature check, no `bootStakeholders` membership check and no epoch check happen at parse
time.** They happen when the ledger state is initialised (5.3). (`mkGenesisDelegation`'s
duplicate-issuer check, `Delegation.hs:105-111`, is not on the JSON path. In JSON, a duplicate
issuer is a duplicate map key, handled as in 2.5.)

### 2.9 Fields that are parsed but ignored, or not parsed at all

| field | in mainnet | in preprod and preview | effect |
|---|---|---|---|
| `vssCerts` | yes (7 entries, keyed by **delegate** key hash) | absent | none, but **hashed** |
| `ftsSeed` | yes | absent | none, but **hashed** |
| `protocolConsts.vssMaxTTL`, `protocolConsts.vssMinTTL` | 6 and 2 | absent | none, but **hashed** |
| `bootStakeholders` weights | all 1 | all 1 | none, but **hashed** |
| any other field | none | none | none, but **hashed** |

The preprod and preview files leave out all four ignored fields and still load
(`dingo-cfg/preprod/byron-genesis.json`). That confirms they are optional.

### 2.10 Values in the real files

| | mainnet | preprod | preview |
|---|---|---|---|
| `protocolMagic` | 764824073 (`mainnetProtocolMagicId`, `Data.hs:183-184`) | 1 | 2 |
| `k` | 2160 | 2160 | 432 |
| `startTime` | 1506203091 = 2017-09-23T21:44:51Z | 1654041600 = 2022-06-01T00:00:00Z | 1666656000 = 2022-10-25T00:00:00Z |
| `bootStakeholders` | 7 | 7 | 7 |
| `heavyDelegation` | 7 (every genesis key) | 7 | 7 |
| `avvmDistr` | 14,505 entries, total 31,112,484,745,000,000 | empty | empty |
| `nonAvvmBalances` | empty | 8 entries: one with 30,000,000,000,000,000, seven with 0 | same shape |
| `blockVersionData` | identical in all three (2.4) | | |
| `RequiresNetworkMagic` (node config) | `RequiresNoMagic` | `RequiresMagic` | `RequiresMagic` |

---

## 3. Genesis hash

### 3.1 What is hashed

```
GenesisHash = blake2b-256( renderCanonicalJSON( parseCanonicalJSON( file_bytes ) ) )
```

(`byron/Genesis/Data.hs:179`; `hashRaw = unsafeAbstractHash` = blake2b-256 over the bytes,
`byron-crypto/Hashing.hs:260-261`, `272-273`; `newtype GenesisHash = GenesisHash (Hash Raw)`,
`byron/Genesis/Hash.hs:17-20`).

- **Not the raw file bytes.** The real files are pretty-printed, so hashing them gives the wrong
  answer (3.3).
- **Not a re-rendering of the decoded `GenesisData`.** The parsed `JSValue` of the whole file is
  rendered, so ignored fields (2.9) and the original string spellings of every value are part of
  the hash. Dropping `vssCerts` and `ftsSeed` from mainnet changes the hash to
  `9f01363f34f12a1152a580313bc6e2df5b8686e963abe0b3239340b4aa3e9b5b` (computed).

### 3.2 Canonical rendering (`renderCanonicalJSON`, verify: canonical-json)

- No whitespace anywhere.
- Object members are sorted by key with a **stable** sort on the key's bytes. Duplicate keys are
  kept, in their original relative order.
- Integers in decimal, with `-` for negatives.
- Strings: `"`, then the raw bytes with only `"` and `\` escaped as `\"` and `\\`, then `"`.
  Control characters and non-ASCII bytes are written as they are.
- Arrays `[a,b]`, objects `{"k":v,...}`, and the literals `null`, `true` and `false`.

For files with no escapes and only ASCII, as all three real ones are, Python's
`json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)` produces the same
bytes. That makes it a convenient test oracle. Start of the preprod rendering:

```
{"avvmDistr":{},"blockVersionData":{"heavyDelThd":"300000000000","maxBlockSize":"2000000",...
...,"protocolConsts":{"k":2160,"protocolMagic":1},"startTime":1654041600}
```

### 3.3 Computed values

| network | canonical blake2b-256 (= `ByronGenesisHash` in the node config) | canonical size | raw-file blake2b-256 (**wrong**) | raw size |
|---|---|---|---|---|
| mainnet | `5f20df933584822601f9e3f8c024eb5eb252fe8cefb24d1317dc3d432e940ebb` | 910,756 | `dbbdaeab0ea4ea58225892d8b1294f178b417f4a9d1ed3bbf629c40d8f74e86b` | 1,056,360 |
| preprod | `d4b8de7a11d929a323373cbab6c1a9bdc931beffff11db111cf9d57356ee1937` | 4,577 | `559db4dedff91ea6291019d55ac0708595b3820a5aad8cddc4b4863e7947cc8f` | 5,607 |
| preview | `83de1d7302569ad56cf9139a41e2e11346d4cb4a31c00142557b6ab3fa550761` | 4,576 | `81cf23542e33d64c541699926c2b5e6e9c286583f0c8a3fb5f22ea7b352dd174` | 5,607 |

All three canonical hashes match the configs (`cfg/mainnet-config.json:5`;
`dingo-cfg/preprod/config.json:5`; `dingo-cfg/preview/config.json:5`).

### 3.4 Where the genesis hash is used

1. **Start-up check** against `ByronGenesisHash`, if that key is present (1.2).
2. **Previous hash of the epoch-0 EBB.**
   - `initialChainValidationState` sets `cvsPreviousHash = Left genesisHash`
     (`byron/Block/Validation.hs:189`).
   - The EBB header decoder makes the prev hash `Left (GenesisHash bytes)` when the EBB's epoch is
     0, or when its extra data carries the genesis tag `{255: "Genesis"}`. Otherwise it is
     `Right HeaderHash` (`byron/Block/Header.hs:613-626`, `572-574`).
   - `updateChainBoundary` (the consensus path calls it through `validateBoundary`,
     `byron/Byron/API/Validation.hs:184-200`) compares the two values:

     | ledger `cvsPreviousHash` | EBB prev hash | result |
     |---|---|---|
     | `Left g` | `Left g'` | `g == g'`, else `ChainValidationGenesisHashMismatch` |
     | `Right h` | `Right h'` | `h == h'`, else `ChainValidationInvalidHash` |
     | `Left` | `Right` | `ChainValidationExpectedGenesisHash` |
     | `Right` | `Left` | `ChainValidationExpectedHeaderHash` |

     (`Block/Validation.hs:271-297`.) After the EBB, `cvsPreviousHash` becomes
     `Right(blake2b-256(0x82 0x00 ‖ ebb_header_bytes))` (`:293-305`;
     `Header.hs:633-634`).
3. **Consensus chain view.** A boundary header whose prev hash is `Left _` maps to `GenesisHash`
   (Origin) (`byron/Block/Block.hs:620-624`; `oc-byron/Ledger/Block.hs:240-246`). So consensus
   never compares the genesis hash bytes itself. Only the ledger rule in point 2 does.
4. **`configGenesisHeaderHash`** coerces the genesis hash to a `HeaderHash` with the same bytes
   (`byron/Genesis/Config.hs:88-89`; `Header.hs:479-480`). The EBB encoder writes it as the prev
   hash (`Header.hs:550-553`).
5. **Genesis EBB forged at start-up.** `nodeInitChainDB` runs on **every** node
   (`oc-diffusion/NodeKernel.hs:269`). If the ChainDB tip is Origin, it adds
   `forgeEBB cfg (SlotNo 0) (BlockNo 0) GenesisHash` (`oc-byron/Node.hs:324-331`;
   `oc-byron/Ledger/Forge.hs:51-92`). The forged EBB has protocol magic `pm`, prev hash = genesis
   hash, body proof = `blake2b-256(0x9f 0xff)` (an empty indefinite list), consensus data
   `[0, [0]]`, extra data `[{}]` and an empty body (`Header.hs:546-574`).

Nothing else in Byron validation uses the genesis hash. The Praos initial nonce comes from the
**Shelley** genesis hash, not the Byron one (`node/Protocol/Cardano.hs:188-189`).

### 3.5 The forged EBB versus the real epoch-0 EBB (computed)

- **Preprod: identical.** The forged EBB hash is
  `9ad7ff320c9cf74e0f5ee78d22a85ce42bb0a487d0506bf60cfb5a91ea4497d2`. That equals the hash of the
  real EBB in `testdata/byron/dingo/preprod-byron-chain.cbor`, and block 1's prev hash. The real
  EBB bytes are
  `8385015820d4b8de7a…1937 5820afc0da64183bf2664f3d4eec7238d524ba607faeeab24fc100eb861dba69971b 8200810081a0 9fff 81a0`.
  Its prev hash is the preprod genesis hash, as expected.
- **Mainnet: different.** The forged EBB hash is
  `d2d90d10993b3eb309f5485a5413cb9c9fe4f088e79b7b4e815dbbe8fcb8e4b7`, while the real mainnet
  epoch-0 EBB is `89d9b5a5b8ddc8d7e5a6795e9774d97faf1efea59b2caf7eaf9f8c5b32059df4`
  (`oc-byron/EBBs.hs:11`). The node's locally forged EBB is therefore an orphan, and the real chain
  replaces it once peers serve it. **urd should not forge a genesis EBB. It should start from
  Origin and validate the EBB it receives.** (Why the real body differs is open question 9.6.)

---

## 4. Genesis UTxO (`genesisUtxo`, `byron/UTxO/GenesisUTxO.hs:16-32`)

```
balances = [(makeRedeemAddress nm (fromCompact k), v) | (k, v) <- Map.toList avvmDistr]
        ++ Map.toList nonAvvmBalances
nm       = makeNetworkMagic (configProtocolMagic config)     -- uses configReqNetMagic
utxo     = fromBalances balances
```

`fromBalances` (`byron/UTxO/UTxO.hs:121-131`, `151-158`): each `(addr, v)` becomes a singleton UTxO
`{TxInUtxo (serializeCborHash addr) 0 ↦ TxOut addr v}`. These are folded with `union`. If two
entries produce the same TxIn (the same address), `union` fails and `fromBalances` **panics**
("duplicate Address in initial balances"), which is fatal. This can only happen if a
`nonAvvmBalances` address equals the redeem address of an AVVM key. Two AVVM keys always give
different addresses. Order does not matter, because the UTxO is a map keyed by TxIn.

### 4.1 Network magic for AVVM addresses

`makeNetworkMagic pm = case requiresNetworkMagic of RequiresNoMagic → NetworkMainOrStage;
RequiresMagic → NetworkTestnet (pm :: Word32)` (`byron/Common/NetworkMagic.hs:80-83`). The flag is
`configReqNetMagic`, which comes from the **node config**, not the genesis file
(`byron/Genesis/Config.hs:81`, `106-110`). Non-AVVM addresses are used exactly as decoded. Their
network magic attribute is never compared with anything.

### 4.2 AVVM key → redeem address (`makeRedeemAddress`, `byron/Common/Address.hs:255-265`, `291-299`)

Byte layout. `K` is the 32-byte redeem key. The attributes `A` are either `a0` (`{}`, for
`NetworkMainOrStage`) or `a1 02 4N <CBOR(pm)>` (`{2: bytes(CBOR uint pm)}`, for
`NetworkTestnet pm`). There is never a derivation path (key 1).

```
Address'  = 83                     ; array(3)   (AddrType, AddrSpendingData, Attributes)
              02                   ; AddrType  ATRedeem = 2
              82 02 58 20 K        ; AddrSpendingData RedeemASD = [2, bytes(32)]
              A                    ; Attributes AddrAttributes
root      = blake2b-224( sha3-256( Address' ) )                       ; 28 bytes
payload   = 83 58 1c root  A  02   ; (root, attributes, AddrType=2)
address   = 82 d8 18 <bytes header> payload  <CBOR uint crc32(payload)>
```

Citations:

- `Address'` is the 3-tuple, encoded as a definite array (`Address.hs:119-123`).
- `AddrType` encodes as a `Word8` (0 for VerKey, 2 for Redeem) (`byron/Common/AddrSpendingData.hs:102-106`).
- `RedeemASD` encodes as `[2, redeemVK]` (`AddrSpendingData.hs:67-71`). The redeem key is
  `encodeBytes` of the 32 raw bytes (`byron-crypto/Orphans.hs:86-87`).
- Attributes are a definite map `Word8 → bytes`, in ascending key order. The value for key 2 is
  the CBOR-serialised `Word32` magic (`byron/Common/AddrAttributes.hs:89-119`;
  `byron/Common/Attributes.hs:192-196`).
- The root is `abstractHashFromDigest . blake2b_224 . sha3_256 . serialize byronProtVer`
  (`byron/Common/AddressHash.hs:14-25`).
- The address is `encodeCrcProtected (root, attributes, type)`: `[#6.24(bytes(payload)),
  crc32(payload)]`, where the CRC is the standard CRC-32 (zlib/IEEE) of the payload bytes, written
  as a minimal CBOR `Word32` (`Address.hs:157-159`; `byron/Common/CBOR.hs:106-110`).

For the inverse direction (decoding addresses) see `docs/decoding/witnesses-auxdata-byron.md`
B.3.5.

### 4.3 Non-AVVM address

The decoded `Address` (2.6) is used as is. Its TxIn hashes the **re-encoding** (4.4), not the
base58-decoded bytes. The two differ only if the base58 bytes were non-minimal somewhere the
decoder tolerates. For all 16 preprod and preview addresses, re-encoding gives the same bytes as
the base58 payload (computed).

### 4.4 Genesis TxIn

```
TxIn = TxInUtxo (blake2b-256( serialize byronProtVer address )) 0
```

(`byron/UTxO/UTxO.hs:130-131`; `serializeCborHash = blake2b-256 ∘ serialize`,
`byron-crypto/Hashing.hs:212-213`, `264-265`.) The address `EncCBOR` is its `ToCBOR`
(`bin/Encoding/EncCBOR.hs:115-116`), so the bytes hashed are exactly the `address` bytes from 4.2:
`82 d8 18 …crc`. The index is always 0. A later transaction spends it with the usual Byron input
encoding `[0, #6.24(bytes([txid, 0]))]`.

### 4.5 Test vectors (computed)

**Mainnet AVVM, `RequiresNoMagic`.** This is the first key in the file:
`-0BJDi-gauylk4LptQTgjMeo7kY9lTCbZv12vwOSTZk=`, worth 9,999,300,000,000 lovelace.

```
K          fb40490e2fa06aeca59382e9b504e08cc7a8ee463d95309b66fd76bf03924d99
Address'   830282025820fb40490e2fa06aeca59382e9b504e08cc7a8ee463d95309b66fd76bf03924d99a0
root       ccdf735b7d5cafe44e65e75a82fd4305fe7712924a8e1196fefdbddf
payload    83581cccdf735b7d5cafe44e65e75a82fd4305fe7712924a8e1196fefdbddfa002
address    82d818582183581cccdf735b7d5cafe44e65e75a82fd4305fe7712924a8e1196fefdbddfa0021a9cbc2ffe
base58     Ae2tdPwUPEZHFQnrr2dYB4GEQ8WVKspEyrg29pJ3f7qdjzaxjeShEEokF5f
TxIn       8ee33c9906974706223d7d500d63bbee2369d7150f972757a9fdded2f706b938 #0
```

The same key under `RequiresMagic` with pm 764824073. This combination never occurs on a real
network, but it exercises the attribute path:

```
Address'   830282025820fb40…4d99a102451a2d964a09
root       f24e7b6a0bfaacdd51f9e219a0ac3c95e432ff3b9d44692a9db456d8
address    82d818582883581cf24e7b6a0bfaacdd51f9e219a0ac3c95e432ff3b9d44692a9db456d8a102451a2d964a09021ad2337b75
TxIn       85616512f3c8b3619f46c18643e1b63ac3c26b10aa12b2ebc4bfdfc66a4d47cc #0
```

All 14,505 mainnet keys decode to 32 bytes and give 14,505 distinct TxIns. The values sum to
31,112,484,745,000,000, and the smallest is 1,000,000.

The AVVM vector is **not** chain-verified: no vendored block contains a redemption. Its pieces are
checked separately. The sha3/blake2b-224 root, the attribute encoding and the CRC envelope are
confirmed by the non-AVVM vectors below, and the redeem-specific bytes (`02`, `[2, bytes(32)]`)
come from the code cited in 4.2.

**Preprod non-AVVM** (`RequiresMagic`, pm 1, attributes `a1 02 41 01`):

| address | lovelace | address CBOR | genesis TxIn (#0) |
|---|---|---|---|
| `FHnt4NL7yPXuYUxBF33VX5dZMBDAab2kvSNLRzCskvuKNCSDknzrQvKeQhGUw5a` | 30000000000000000 | `82d818582483581c58d2114184c5ed784cc419eb680a7d33c698d0ec963e2e805e83e260a1024101001a74c02a09` | `5526b1373acfc774794a62122f95583ff17febb2ca8a0fe948d097e29cf99099` |
| `FHnt4NL7yPXhCzCHVywZLqVsvwuG3HvwmjKXQJBrXh3h2aigv6uxkePbpzRNV8q` | 0 | `82d818582483581c056d8907b4530dabec0ab77456a2b5c7e695150d7534380a8093091ea1024101001ae0af87de` | `8e0280beebc3d12626e87b182f4205d75e49981042f54081cd35f3a4a85630b0` |

**Preview non-AVVM. This one is chain-verified.** Address
`FHnt4NL7yPXvDWHa8bVs73UEUdJd64VxWXSFNqetECtYfTd9TtJguJ14Lu3feth` (30,000,000,000,000,000 lovelace)
has address CBOR
`82d818582483581c5d5e698eba3dd9452add99a1af9461beb0ba61b8bece26e7399878dda1024102001a36d41aba`
and genesis TxIn `4843cf2e582b2f9ce37600e5ab4cc678991f988f8780fed05407f9537f7712bd #0`. That input
is spent in `testdata/immutable/preview/00000.chunk`, where a one-element input set
`81 82 5820 4843cf2e…12bd 00` starts at byte offset 3973. This confirms the whole construction:
base58 → address bytes → blake2b-256 → index 0.

---

## 5. Genesis delegation

### 5.1 What `heavyDelegation` produces

A `Map KeyHash Certificate`, keyed by the issuer's key hash, with the parse-time invariants from
2.8. A `Certificate` is `UnsafeACertificate { aEpoch = omega, issuerVK, delegateVK, signature }`
(`byron/Delegation/Certificate.hs:93-103`, `139-147`).

### 5.2 `KeyHash`

`hashKey vk = KeyHash (addressHash vk)` (`byron/Common/KeyHash.hs:29-31`, `55-56`). That is

```
KeyHash(vk) = blake2b-224( sha3-256( 58 40 ‖ pub32 ‖ chaincode32 ) )
```

The CBOR byte string holds the full 64-byte extended key (`byron-crypto/Signing/VerificationKey.hs:91-92`;
`byron/Common/AddressHash.hs:16-22`). For all 14 mainnet and preprod certificates,
`hashKey(issuerPk)` equals the map key (computed).

### 5.3 Validation at ledger initialisation (fatal on failure)

`initialChainValidationState` calls `DI.initialState delegationEnv genesisDelegation`
(`byron/Block/Validation.hs:181-206`). The environment is:

- `protocolMagic = Annotated pm (serialize' pm)`: the annotation is the CBOR `Word32` (`:197`).
- `allowedDelegators = bootStakeholders` (`:198`).
- `k = configK`. `initialState` then **overrides it to 0**, so that genesis certificates activate
  immediately (`byron/Delegation/Validation/Interface.hs:105`).
- `currentEpoch = 0`, `currentSlot = 0` (`Validation.hs:200-201`).

The certificates are taken in `Map.elems` order, which is ascending issuer `KeyHash` bytes. Each is
re-annotated: `aEpoch` gets the annotation `serialize' epoch` (`Interface.hs:126-137`). Then
`updateDelegation` runs `scheduleCertificate` on each (`Interface.hs:148-178`;
`byron/Delegation/Validation/Scheduling.hs:177-234`). Its checks are:

| # | check | error | cite |
|---|---|---|---|
| 1 | `hashKey issuerVK ∈ bootStakeholders` | `NonGenesisDelegator` | `Scheduling.hs:185-187` |
| 2 | `0 ≤ omega ≤ 1`, that is currentEpoch ≤ e ≤ currentEpoch + 1 | `WrongEpoch` | `:190-195` |
| 3 | `(omega, issuer) ∉ keyEpochDelegations` | `MultipleDelegationsForEpoch` | `:198-200` |
| 4 | no scheduled delegation from this issuer at slot 0 + 2·0 | `MultipleDelegationsForSlot` | `:203-204`, `229-232` |
| 5 | signature valid (below) | `InvalidCertificate` | `:207`; `Certificate.hs:164-177` |

Checks 3 and 4 cannot fail at genesis, because issuers are distinct map keys. Any failure makes
`initByronLedgerState` call `error` (`oc-byron/Ledger/Ledger.hs:145-149`).

**Signed message** (`Certificate.isValid` → `verifySignatureDecoded`,
`byron-crypto/Signing/Signature.hs:216-233`; tag from `byron-crypto/Signing/Tag.hs:63-87`):

```
msg = 0x0a                          ; SignCertificate tag byte
    ‖ CBOR(pm :: Word32)             ; e.g. 1a 2d 96 4a 09 (mainnet), 01 (preprod)
    ‖ CBOR_bytes( "00"               ; the ASCII bytes 0x30 0x30, NOT 0x00
                ‖ delegate_xpub64    ; pub32 ‖ chaincode32 of delegatePk
                ‖ CBOR(omega) )      ; e.g. 00
verify: Ed25519.verify(pub = issuerPk[0..32], msg, cert)    ; chain code ignored
```

Two details are surprising:

1. **`"00"` is a two-character `ByteString` literal** (`OverloadedStrings`), so it is
   `0x30 0x30` (`Certificate.hs:133`, `174`).
2. **The payload is wrapped in a CBOR byte-string header.** `isValid` maps the annotation through
   `serialize' byronProtVer . mappend ("00" <> xpub)` (`Certificate.hs:173-176`). `Annotated`'s
   `Functor` maps the **annotation** (`bin/Decoding/Annotated.hs:91-92`), so the result is
   `serialize'` of a `ByteString`: header `58 43` (67 = 2 + 64 + 1) followed by the bytes. The
   signer does the same (`safeSign … = signRaw … . serialize'`,
   `byron-crypto/Signing/Signature.hs:181-183`; `Certificate.hs:121-136`).

Verification is plain Ed25519 on the first 32 bytes of the issuer's xpub
(`cardano-crypto/Wallet.hs:197-201`). All 7 mainnet and all 7 preprod certificates verify with this
message, and **none** verifies without the `58 43` header (computed with an RFC 8032 reference
verifier). Example, mainnet issuer `af2800c1…f2d1`:

```
0a 1a2d964a09 5843 3030
61261a95b7613ee6bf2067dad77b70349729b0c50d57bc1cf30de0db4a1e73a8
85d0054af7c23fc6c37919dba41c602a57e2d0f9329a7954b867338d6fb2c945
00
```

### 5.4 Resulting delegation state

`initialState` starts from (`Interface.hs:107-124`):

- `delegationMap = Bimap.fromList [(g, g) | g ∈ bootStakeholders]`. **Every genesis key first
  delegates to itself.**
- `delegationSlots = {g ↦ 0 | g ∈ bootStakeholders}`.
- The scheduling state is empty.

After scheduling, `tickDelegation 0 0` runs (`Interface.hs:162-166`, `181-198`):

- `activateDelegations 0` activates every scheduled delegation with slot ≤ 0, which with k = 0 is
  all of them. `activateDelegation` (`byron/Delegation/Validation/Activation.hs:65-79`) inserts
  `issuer ↦ delegate` into the **Bimap** only if `delegate ∉ range(map)` and
  (`prevSlot < 0` or `slot == 0`). The second condition always holds here. `Bimap.insert` removes
  any old pair with the same key or value (`byron/Delegation/Map.hs:37-39`, `85-86`).
- `pruneScheduledDelegations 0 0` keeps scheduled delegations with slot ≥ 1 (none) and
  `keyEpochDelegations` with epoch ≥ 0 (all) (`Interface.hs:201-217`).

The final state:

| component | value |
|---|---|
| `activationState.delegationMap` | `issuer ↦ delegate` for every genesis certificate; `g ↦ g` for genesis keys without a certificate |
| `activationState.delegationSlots` | `{g ↦ 0}` for every genesis key |
| `schedulingState.scheduledDelegations` | empty |
| `schedulingState.keyEpochDelegations` | `{(omega, issuerHash)}` for every genesis certificate |

Two consequences matter later:

1. Because of `keyEpochDelegations`, a genesis key that delegated with `omega = 0` cannot publish
   another certificate for epoch 0 (`MultipleDelegationsForEpoch`).
2. **A genesis certificate whose delegate is already in the map's range is silently dropped.**
   That happens when the delegate is another genesis key that keeps its identity mapping, or a
   delegate already taken by an earlier certificate in issuer-hash order. The parse-time
   multi-layer check (2.8) only looks at keys of `heavyDelegation`, not at all of
   `bootStakeholders`. No real file triggers this.

Computed delegation maps (genesis key → delegate key hash):

| mainnet genesis key | delegate |
|---|---|
| `1deb82908402c7ee3efeb16f369d97fba316ee621d09b32b8969e54b` | `6bef444609d6e336cb1fe1daba278918dbc5768e6754c2945dd8d25c` |
| `43011479a595b300e0726910d0b602ffcdd20466a3b8ceeacd3fbc26` | `0efd6f3b2849d5baf25b3e2bf2d46f88427b4e455fc3dc43f57819c5` |
| `5071d8802ddd05c59f4db907bd1749e82e6242caf6512b20a8368fcf` | `1040655f58d5bf2be1c06f983abf66c7f01d28c239f27648a0c73e5d` |
| `5411c7bf87c252609831a337a713e4859668cba7bba70a9c3ef7c398` | `5ffca3a329599727e39a7472c5270e54cf59a27b74306cc9f7fd0f5e` |
| `65904a89e6d0e5f881513d1736945e051b76f095eca138ee869d543d` | `eb649333a196ecb024a4a5919d3ce86084014136fd3e884e52ecd057` |
| `6c9e14978b9d6629b8703f4f25e9df6ed4814b930b8403b0d45350ea` | `ce1e50f578d3043dc78d8777f5723cc7b6ca512d8cdbe8a09aafc9c3` |
| `af2800c124e599d6dec188a75f8bfde397ebb778163a18240371f2d1` | `1fa56ba63cff50d124b6af42f33b245a30fcd1b0170d7704b0b201c7` |

(The mainnet delegate hashes are exactly the keys of `vssCerts`.)

| preprod genesis key | delegate |
|---|---|
| `05d1c10e4bf3cdd4de54712531c53be75a1609b25f396ffbbe5becf1` | `2c4dc0543eb5b4ee3e2518cceeddae46f8b7829632bddbcd33d88bcd` |
| `3bf1193b19be416283b8c0516d2f8b80939ffccb1c9b05946f54c83a` | `0b4c7039617cac8ba13a775ec26bd6aec3666cbb5be8dff74eb059ba` |
| `7bdd769bd872e8e6336c23f1e566c19a96e72137174b891fad9f4b99` | `ddc5ff45358a2ea1d6e700e49deac7aa25a1d199a3ee791390b522fe` |
| `9ddc1e29c59df0ddd9347fe8b8a736d247f286414684eddc02885348` | `967d20cf2e39540cc44a42634e3f2f5165730143e2a18688c04cfd05` |
| `a118c0d2737c8a77c0d982a0d299bc42614cea4e0c23614ba24a05ca` | `f685d78015491acb6b6f1a1430572a64d69c206039cbec1e98bc2cb1` |
| `b0b2df3c9cf4dfe2ae04409913b3c3125509acbbfa0722449570aaeb` | `08afaf1477bec844aecadcfd0fe2edad29054223d223b8a31499bbeb` |
| `e0a65f21229e44c2bf6eec5b14e2775003b674ae53de18d22814346a` | `f1d34eb6677d90778e65e7b0b734b119c3a3e6d9fc986c5bbf329ff3` |

### 5.5 How the genesis keys are used

`bootStakeholders` (`gdGenesisKeyHashes`) is the fixed set of Byron "core nodes":

- **Delegation:** the only keys allowed to issue delegation certificates (`allowedDelegators`;
  `Scheduling.hs:185-187`). This applies on chain too (`byron/Block/Validation.hs:573-574`;
  `byron/Byron/API/Validation.hs:79`).
- **PBFT block validation** (`oc-core/Protocol/PBFT.hs:342-377`). The PBFT ledger view is the
  delegation `Bimap` (`PBFT.hs:206-209`). For a regular block:
  1. The block signature must verify.
  2. `slot ≥ lastSignedSlot`. This is non-strict because an EBB shares its slot.
  3. `Bimap.lookupR (hashKey issuer)` must find a genesis key, else `PBftNotGenesisDelegate`.
  4. After appending `(slot, genesisKey)` to the window of the last **k** signers, the number of
     blocks signed by that genesis key must be ≤ `floor(threshold · k)`, else
     `PBftExceededSignThreshold` (`PBFT.hs:417-449`). The window starts empty (1.3). EBBs skip
     all of this (`:348-349`).
- **Update system:** `numGenKeys = |bootStakeholders|`, which must fit in `Word8`. The vote
  confirmation threshold and the endorsement (adoption) threshold are both
  `upAdptThd = floor(minThd/10^15 · numGenKeys)` (`byron/Update/ProtocolParameters.hs:217-221`;
  `byron/Update/Validation/Interface.hs:396`, `452`). For mainnet that is floor(0.6 · 7) = 4.
- **Forging only:** the `CoreNodeId` of a key is its index in the sorted `Set KeyHash`
  (`oc-byron/Protocol.hs:44-60`). The leader is the node with `slot mod numCoreNodes == id`
  (`oc-core/Protocol/PBFT.hs:327`). `numCoreNodes` is the set size
  (`oc-byron/Ledger/Conversions.hs:80-87`).

---

## 6. Parameters and constants derived from genesis

| quantity | formula | mainnet | preprod | preview | cite |
|---|---|---|---|---|---|
| k (`BlockCount`, `Word64`) | `protocolConsts.k` | 2160 | 2160 | 432 | `byron/Genesis/Config.hs:91-92` |
| epoch length (slots) | `10·k` | 21600 | 21600 | 4320 | `byron/ProtocolConstants.hs:44-45`; `Config.hs:100-101` |
| slot security param | `2·k` | 4320 | 4320 | 864 | `ProtocolConstants.hs:18-19`. Delegation activation delay (`Scheduling.hs:229`), update confirmation stability (`byron/Update/Validation/Endorsement.hs:198`) |
| update stability param | `4·k` | 8640 | 8640 | 1728 | `ProtocolConstants.hs:33-34`; `byron/Update/Validation/Interface/ProtocolVersionBump.hs:62` |
| chain quality threshold | `k / 2k` | 0.5 | 0.5 | 0.5 | `ProtocolConstants.hs:38-41` |
| slot length | `slotDuration` ms, **genesis value** (not the adopted parameter) | 20 s | 20 s | 20 s | `oc-byron/Ledger/Ledger.hs:327-337`; `Conversions.hs:50-53`, `89-92` |
| HFC era params | epoch size 10k, slot length as above, `StandardSafeZone (2k)`, genesis window 2k | | | | `oc-byron/Ledger/Ledger.hs:327-337` |
| ImmutableDB chunk | epoch size (10k slots) | 21600 | | | `oc-byron/Node.hs:314-320` |
| `SystemStart` | `startTime` | 2017-09-23T21:44:51Z | 2022-06-01T00:00:00Z | 2022-10-25T00:00:00Z | `oc-byron/Node.hs:292-296` |
| network magic (handshake) | `protocolMagic` | 764824073 | 1 | 2 | `oc-byron/Node.hs:298-302` |
| PBFT window | k blocks | 2160 | 2160 | 432 | `oc-core/Protocol/PBFT.hs:432-433` |
| PBFT max signed per key | `floor(threshold · k)` in `Double`, threshold 0.22 | 475 | 475 | 95 | `PBFT.hs:417-427`; `oc-byron/Node.hs:178-179` |
| core nodes | `|bootStakeholders|` | 7 | 7 | 7 | `Conversions.hs:80-87` |
| update vote and adoption threshold | `floor(minThd/10^15 · |genesis keys|)` | 4 | 4 | 4 | `ProtocolParameters.hs:217-221` |
| min fee | `155381 + 43.946 · size` lovelace (from `txFeePolicy`) | | | | 2.4 |
| initial adopted protocol version | `0.0.0`, **constant, not from genesis** | | | | `byron/Update/Validation/Interface.hs:229` |
| initial adopted protocol parameters | `blockVersionData` | | | | `Interface.hs:230` |
| initial application versions | **empty map**: a software update for an unknown application must have version 0 or 1 | | | | `Interface.hs:232`; `byron/Update/Validation/Registration.hs:591-595` |
| `UTxOConfiguration.tcAssetLockedSrcAddrs` | **always empty**: `defaultUTxOConfiguration`. The node has no setting for it, on mainnet or anywhere else | ∅ | ∅ | ∅ | `node/Protocol/Byron.hs:100-101`; `byron/UTxO/UTxOConfiguration.hs:52-56` |
| required tx-output network magic | `makeNetworkMagic` from `RequiresNetworkMagic` and pm. Every tx output's address network-magic attribute must equal it | MainOrStage (no attribute) | Testnet 1 | Testnet 2 | `byron/UTxO/Validation.hs:253-255`, `281-295`; `byron/Byron/API/Validation.hs:76` |
| signing context | configured pm (not the header field) for tx witnesses, certificates, votes and block signatures | | | | `byron/Byron/API/Validation.hs:43-45`, `76`; `oc-byron/Ledger/PBFT.hs:39` |
| forged-block protocol and software version | `LastKnownBlockVersion-*`; `cardano-sl` version 1. **Forging only**, never validated against | | | | `node/Protocol/Byron.hs:77-82`; `oc-byron/Node.hs:191-205` |

Notes:

- `getSystemStart` and `getNetworkMagic` of the Cardano hard-fork block assert that all eras agree,
  but only when assertions are compiled in. Otherwise they return the **first (Byron)** era's
  value (`oc-core/HardFork/Combinator/Node.hs:38-59`; `oc-core/Util/Assert.hs:9-13`). In practice,
  `SystemStart` and the network magic come from the **Byron** genesis. The shipped Shelley
  genesis files agree (`cfg/mainnet-shelley-genesis.json:61`, `63`).
- The block header carries its own protocol-magic field, which is unsigned. On the consensus
  apply path (`validateBlock`) it is **not** compared with the config. Only the test-oriented
  `updateBlock` CHAIN rule does that (`byron/Block/Validation.hs:519-525`), and
  `verifyHeaderIntegrity` checks it for storage integrity (`oc-byron/Ledger/Integrity.hs:45-56`).
  The EBB decoder drops the EBB's magic without checking it (`byron/Block/Header.hs:617`).

---

## 7. The initial `ChainValidationState`

`initialChainValidationState config` (`byron/Block/Validation.hs:138-146`, `177-206`):

| field | initial value | detail |
|---|---|---|
| `cvsLastSlot :: SlotNumber` | `0` | `:185`. Also 0 after the epoch-0 EBB (`byron/Byron/API/Validation.hs:194-197`) |
| `cvsPreviousHash :: Either GenesisHash HeaderHash` | `Left configGenesisHash` | `:189`; 3.4 |
| `cvsUtxo :: UTxO` | `genesisUtxo config` | section 4. Built from the **full** config, AVVM included (`oc-byron/Node.hs:241-244`) |
| `cvsUpdateState :: UPI.State` | `UPI.initialState config` | below |
| `cvsDelegationState :: DI.State` | `DI.initialState env heavyDelegation` | section 5.4 |

`UPI.initialState` (`byron/Update/Validation/Interface.hs:109-131`, `225-239`):

| field | value |
|---|---|
| `currentEpoch` | 0 |
| `adoptedProtocolVersion` | `ProtocolVersion 0 0 0` |
| `adoptedProtocolParameters` | genesis `blockVersionData` |
| `candidateProtocolUpdates` | `[]` |
| `appVersions` | `{}` |
| `registeredProtocolUpdateProposals` | `{}` |
| `registeredSoftwareUpdateProposals` | `{}` |
| `confirmedProposals` | `{}` |
| `proposalVotes` | `{}` |
| `registeredEndorsements` | `{}` |
| `proposalRegistrationSlot` | `{}` |

Consensus wraps the result (`oc-byron/Ledger/Ledger.hs:137-142`; `oc-byron/Node.hs:239-252`):

- `byronLedgerTipBlockNo = Origin`.
- `byronLedgerTransition = ByronTransitionInfo {}`.
- The header state is `genesisHeaderState S.empty`: tip at Origin, an empty PBFT signer window,
  and `lastSignedSlot = Origin` (`oc-core/Protocol/PBFT/State.hs:189-202`).

---

## 8. Implementation checklist

1. Parse the strict JSON subset (2.1, 2.3). Reject floats, escapes and duplicate keys rather than
   guess.
2. Keep the parsed tree, render it canonically (3.2), and hash the rendering with blake2b-256.
   Compare with `ByronGenesisHash` if it is configured. Test against the three values in 3.3.
3. Decode every field in 2.2 and 2.4 with the listed checks:
   - LovelacePortion ≤ 10^15;
   - summand `div` 10^9 ≤ 45·10^15;
   - AVVM key 32 bytes after the base64url → base64 mapping;
   - xpubs 64 bytes;
   - signatures 64 bytes;
   - KeyHashes 28 bytes;
   - non-AVVM addresses through the full Byron address decoder.
4. Check `heavyDelegation` keys against `hashKey(issuerPk)`, and that delegates are not issuers
   (2.8).
5. At ledger initialisation, check every genesis certificate: issuer ∈ `bootStakeholders`,
   `omega ∈ {0, 1}`, and the signature over the exact message in 5.3. Treat failure as fatal.
6. Build the delegation Bimap: identity, then overrides in issuer-hash order, skipping any delegate
   already in the range. Set `keyEpochDelegations` and all activation slots to 0 (5.4).
7. Build the genesis UTxO. Use the AVVM network magic from the node's `RequiresNetworkMagic`.
   Hash the re-encoded address for each TxIn, index 0. Fail on a duplicate TxIn (4).
8. Set the update state to 0.0.0, the genesis parameters as adopted, and empty everything else (7).
9. Do not forge a genesis EBB. Validate the received epoch-0 EBB's prev hash against the genesis
   hash (3.4, 3.5).
10. `UTxOConfiguration` is the empty set. The PBFT threshold is 0.22 unless configured.

---

## 9. Open questions

1. **canonical-json parser details (not vendored).** Things to confirm in `Text.JSON.Canonical`
   (package `canonical-json`):
   - whether trailing bytes after the top-level value are rejected;
   - which characters count as whitespace (Parsec `spaces` uses `isSpace`, which on Latin-1 input
     includes `0xA0`);
   - whether the opening-quote token skips whitespace inside strings;
   - behaviour of 18-digit numbers above 2^53;
   - whether `"01"` is rejected.

   None of this affects the real files. urd should reject these inputs.
2. **cardano-prelude canonical instances (not vendored).**
   - Are the `Word16` and `Word32` `FromJSON` instances unchecked `fromIntegral` from `Int54`? If
     so, an out-of-range `protocolMagic` or weight would wrap.
   - What exactly does `readEither` accept for `Word64`, `Natural` and `Integer` strings
     (whitespace, `-`, `0x`, `Word64` wrap-around)?
   - Is `startTime` read through `Int54`?
3. **Duplicate JSON keys.** Is `Map` decoding in canonical-json last-wins (`Map.fromList`) or an
   error? `fromJSField` and `lookup` are first-wins. Both duplicates are hashed either way.
4. **base64 and base16 strictness.** Do `Data.ByteString.Base64.decode` (used for keys) and
   base16-bytestring `decode` (used for hashes and signatures) accept missing padding, non-zero
   trailing bits or uppercase hex? Real files use canonical padding and lowercase hex.
5. **AVVM vector on chain.** The mainnet redeem-address vector (4.5) is computed from the code,
   but no vendored block contains an AVVM redemption to confirm it end to end. A mainnet Byron
   redemption tx, whose witness is `[2, #6.24([redeemVK, sig])]`, would close this: its input
   should be `blake2b-256(redeem address of redeemVK) #0`.
6. **Mainnet epoch-0 EBB body.** The forged EBB (empty body) hashes to `d2d90d10…`, while the real
   EBB is `89d9b5a5…` (3.5). The likely cause is that the real body carries cardano-sl's epoch-0
   slot-leader list, which changes the body proof. This was not checked against the real block.
   It does not affect validation, since EBB body proofs are not checked
   (`docs/decoding/witnesses-auxdata-byron.md` B.4 item 5). It only means urd must not substitute
   a forged EBB.
7. **Where `Byron.softwareVersion` comes from.** cardano-node's Cardano path uses it
   (`node/Protocol/Cardano.hs:182`). It is imported from `Cardano.Api.Byron`, which is not
   vendored. The consensus default is `cardano-sl` version 1 (`oc-byron/Node.hs:203-205`). It only
   affects forged blocks.
