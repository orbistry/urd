# Transaction body decoding: Shelley through Conway

This is an implementer's reference for decoding transaction bodies (and everything nested
inside them) exactly as cardano-node's Haskell decoders do. Every rule cites the Haskell
source. The CDDL files are not used as an authority. Where they disagree with the code, the
code wins.

Sources (all paths relative to `refs/`):

| Repo | Commit |
|---|---|
| cardano-ledger | `178bd36839dcb57f257efc0e96615284d1632088` |
| plutus | `7ab93b9ddb3ec11c2d89b9dc9c6d6e6af4544917` |
| cardano-base | `5813d21182c91fa00f8e799a787ef1759d469b26` |

Path abbreviations used in citations:

| Abbrev | Path |
|---|---|
| `BIN` | `cardano-ledger/libs/cardano-ledger-binary/src/Cardano/Ledger/Binary` |
| `CORE` | `cardano-ledger/libs/cardano-ledger-core/src/Cardano/Ledger` |
| `CORE-INT` | `cardano-ledger/libs/cardano-ledger-core/internal/Cardano/Ledger/Internal` |
| `DATA` | `cardano-ledger/libs/cardano-data/src` |
| `SH`, `AL`, `MA`, `AZ`, `BA`, `CO` | `cardano-ledger/eras/{shelley,allegra,mary,alonzo,babbage,conway}/impl/src/Cardano/Ledger/{Shelley,Allegra,Mary,Alonzo,Babbage,Conway}` |
| `BYRON` | `cardano-ledger/eras/byron/ledger/impl/src/Cardano/Chain/Common` |
| `BYRON-CRYPTO` | `cardano-ledger/eras/byron/crypto/src/Cardano/Crypto` |
| `PLC` | `plutus/plutus-core/plutus-core/src/PlutusCore` |
| `PLA` | `plutus/plutus-ledger-api/src/PlutusLedgerApi` |
| `CB` | `cardano-base/cardano-crypto-class/src/Cardano/Crypto` |

## 0. Decoder versions

Blocks of an era are decoded at that era's `ProtVerLow`. `ProtVerHigh` only matters for
`decodeProtVer` (§8.4).

| Era | Decode version (`ProtVerLow`) | `ProtVerHigh` | Source |
|---|---|---|---|
| Shelley | 2 | 2 (defaults to Low) | `CORE-INT/Definition/Era.hs:64,95` |
| Allegra | 3 | 3 | `CORE-INT/Definition/Era.hs:102` |
| Mary | 4 | 4 | `CORE-INT/Definition/Era.hs:109` |
| Alonzo | 5 | 6 | `CORE-INT/Definition/Era.hs:116-117` |
| Babbage | 7 | 8 | `CORE-INT/Definition/Era.hs:124-125` |
| Conway | 9 | 11 | `CORE-INT/Definition/Era.hs:132-133` |

Because the version is fixed per era, the gates that matter in practice are:

- **v≥2**: every era from Shelley on. Pre-v2 branches are Byron only.
- **v≥7**: Babbage and Conway. This affects addresses (§4).
- **v≥9**: Conway only. This affects sets, maps, MultiAsset, addresses, URLs, cost models and
  pointers.
- **v≥12**: Dijkstra only. These branches are mentioned only so you know to ignore them. In
  particular, every "indefinite-length bytes/text accepted" and "RecD replaced by
  `decodeRecordNamed`" branch is v12 only.

v6 and v8 are never used to decode a block.

---

## 1. Generic decoding machinery

Everything below is used repeatedly in later sections. Later sections refer to the notation
defined here.

### 1.1 Primitive decoders

These follow cborg. Non-minimal ("non-canonical") integer, length and tag encodings are
accepted everywhere unless a `*Canonical` decoder is named.

| Notation | Haskell | Accepts | Source |
|---|---|---|---|
| `uint` | `decodeWord` | major type 0 only, 0..2^64-1 | `BIN/Decoding/Decoder.hs:1669-1670` |
| `u8`/`u16`/`u32`/`u64` | `decodeWord8/16/32/64` | major type 0, value ≤ type max (else fail) | `BIN/Decoding/Decoder.hs:1673-1701` |
| `int`, `i64` | `decodeInt`, `decodeInt64` | major type 0 or 1 within [-2^63, 2^63-1]. No bignum tags. | `BIN/Decoding/Decoder.hs:1428-1429,1448-1449` |
| `integer` | `decodeInteger` | major type 0 or 1, or tag 2/3 bignum | `BIN/Decoding/Decoder.hs:1468-1469` |
| `bytes` | `decodeBytes` | **definite-length byte string only** below v12 | `BIN/Decoding/Decoder.hs:359-364` |
| `sbytes` | `ShortByteString`/`ByteArray` via `decodeByteArray` | definite-length only below v12 | `BIN/Decoding/Decoder.hs:1388-1393`, `BIN/Decoding/DecCBOR.hs:428-440` |
| `text` | `decodeString` | definite-length text only below v12 | `BIN/Decoding/Decoder.hs:1564-1569` |
| `null` | `decodeNull` (`DecCBOR ()`) | simple value 22 (`0xf6`) only | `BIN/Decoding/DecCBOR.hs:142-144` |
| `enum(a..b)` | `decodeEnumBounded` | `int`, then range check | `BIN/Decoding/Decoder.hs:702-710` |

Ledger newtypes and the primitive each one reduces to:

| Type | Wire | Source |
|---|---|---|
| `Coin` | `u64` | `CORE/Coin.hs:108-113` |
| `CompactForm Coin`, `CoinPerByte` | `u64` | `CORE/Coin.hs:193-194,220-222` |
| `CoinPerWord` (Alonzo) | `Coin` = `u64` | `AZ/PParams.hs:401-403` |
| `DeltaCoin` (MIR) | `integer` (unbounded, may be negative) | `CORE/Coin.hs:115-119` |
| positive coin (`decodePositiveCoin`) | `u64`, 0 rejected | `CORE/Coin.hs:226-231` |
| `SlotNo` | `u64` (cborg `Serialise Word64`) | `BIN/Decoding/DecCBOR.hs:659-661`; `cardano-base/cardano-slotting/src/Cardano/Slotting/Slot.hs:44-47` |
| `EpochNo` | `u64` | `BIN/Decoding/DecCBOR.hs:669`; `Slot.hs:135-138` |
| `EpochInterval` | `u32` | `BIN/Decoding/DecCBOR.hs:679`; `Slot.hs:145-150` |
| `TxIx`, `CertIx` | `u16` | `CORE/BaseTypes.hs:924-927,954` |
| `GovActionIx` | `u16` | `CO/Governance/Procedures.hs:160-172` |
| `Port` | `u16` | `CORE/BaseTypes.hs:700-702` |
| `Network` | `u8`, then 0 → Testnet, 1 → Mainnet, anything else fails | `CORE/BaseTypes.hs:885-914` |
| `Hash28` (`KeyHash r`, `ScriptHash`, `PolicyID`, Byron `AddressHash`) | `bytes` of exactly 28 bytes | `BIN/Decoding/DecCBOR.hs:555-561`, `CB/PackedBytes/Internal.hs:379-380`, `CORE/Keys/Internal.hs:132-136`, `CORE/Hashes.hs:181-182` |
| `Hash32` (`TxId`, `SafeHash _`: `DataHash`, `TxAuxDataHash`, `ScriptIntegrityHash`, anchor data hash; `VRFVerKeyHash`; `Nonce`) | `bytes` of exactly 32 bytes | `CORE/Hashes.hs:125,156,208-209,254-257,335-348`, `CORE/TxIn.hs:65-67`, `AZ/TxBody.hs:129` |

"Exact size" means the byte string is decoded first (definite only) and then
`packByteString` fails unless the length is exactly N (`CB/PackedBytes/Internal.hs:379-393`).

### 1.2 Containers

| Notation | Haskell | Rule | Source |
|---|---|---|---|
| `List(x)` | `StrictSeq`/`[]` (`decodeStrictSeq`, `decodeList`) | Definite or indefinite array. Any length, including 0. Duplicates kept. Order kept. | `BIN/Decoding/Decoder.hs:538-544,1147-1149` |
| `SetV(x)` | `Set` (`decodeSet`) | **v2–v8**: definite or indefinite array. **No tag allowed** (a tag 258 is not an array header, so it fails). Duplicates are **silently merged**. **v≥9**: optional tag 258 (any other tag fails), then definite or indefinite array. **Duplicates fail**: the element count is compared with the resulting set size. | `BIN/Decoding/Decoder.hs:943-953,955-967,1034-1054,1058-1077`, `BIN/Decoding/Decoder.hs:1347-1353` (`allowTag`) |
| `MapV(k,v)` | `Map` (`decodeMap`/`decodeMapByKey`) | **v2–v8**: definite or indefinite map. Duplicate keys are silently accepted and the **last value wins** (`Map.fromList`). **v≥9**: definite or indefinite map. Duplicate keys fail. Key order is never checked. | `BIN/Decoding/Decoder.hs:792-821,825-847` |
| `OSet(x)` | `OSet` (`decodeOSet`) | Version-independent: optional tag 258, definite or indefinite array, insertion order kept, duplicates fail. Only Conway uses it. | `DATA/Data/OSet/Strict.hs:109-116` |
| `Nullable(x)` | `decodeNullStrictMaybe` | peek: `null` gives absent, anything else is decoded as `x` | `BIN/Decoding/Decoder.hs:626-633` |

"Duplicate" always means equal decoded Haskell values (`Ord`/`Eq`), not equal bytes. Two
encodings of the same value, for example with a non-minimal integer width, are duplicates.

### 1.3 Records and sums

There are four record and sum shapes. They differ in how they handle indefinite-length
arrays.

1. **`Rec(n)`**: `decodeRecordNamed`. Reads an array header. If it is definite, the length
   must equal `n` (`matchSize`). If it is indefinite, the `n` fields are read and the next
   token must be a break, otherwise "Excess terms in array".
   Source: `BIN/Decoding/Decoder.hs:645-659,682-700,1367-1374`.
   `CBORGroup` types such as `ProtVer` use this shape too (`BIN/Group.hs:27-35`).

2. **`RecD(n)`**: Coders `RecD C <! f1 <! ... <! fn`. **Quirk:** the array header is read and
   checked **before** any field is decoded, because `decodeCount (RecD cn) n =
   decodeRecordNamed "RecD" (const n) (pure (n, cn))` (`BIN/Decoding/Coders.hs:482`). The
   "decoder" passed to `decodeListLikeT` is `pure`. So:
   - For a definite header, the length must equal `n`. The fields then follow normally.
   - For an indefinite header (`0x9f`), `decodeBreakOr` runs immediately
     (`BIN/Decoding/Decoder.hs:695-698`). A normal `9f f1 .. fn ff` therefore fails with
     "Excess terms in array". The only accepted indefinite form is the degenerate
     `9f ff f1 .. fn`, where the fields follow *after* the break. cborg does not track
     container nesting, so this decodes. The surrounding structure is then no longer
     well-formed CBOR from a generic parser's point of view, but the Haskell decoder
     consumes it consistently.

   This is derived from reading the code; no test in the tree covers it. It applies to every
   `RecD` type below v12: `MaryValue` pairs, `Update`, `Prices`, `ExUnits`, `Anchor`,
   `GovActionId`, `VotingProcedure`, `ProposalProcedure`, and `Constitution`. At v12 these
   switch to `decodeRecordNamed`.

3. **`Sum`**: `Summands name f` or `decodeRecordSum`. Reads a definite or indefinite array
   header, then the tag (`uint`, via `decodeWord`), then the tag's fields. For a definite
   header, the length must equal `1 + number of fields` for that tag. For an indefinite
   header, a break must follow the fields. An unknown tag fails with `invalidKey`.
   Source: `BIN/Decoding/Decoder.hs:661-666`, `BIN/Decoding/Coders.hs:479-480,486`,
   `BIN/Plain.hs:95-98`.

4. **`Tuple(n)`**: the `DecCBOR (a,b,...)` instances. Below v12 the array must be definite
   with exactly `n` elements (`decodeListLenOf`).
   Source: `BIN/Decoding/DecCBOR.hs:297-303`.

### 1.4 Sparse keyed maps (`SparseKeyed`)

This is used for the TxBody, the Babbage/Conway map-form TxOut, and `PParamsUpdate` below v12.
Source: `BIN/Decoding/Coders.hs:375-385,545-592,630-654`.

- The container is a definite or indefinite CBOR map (`decodeMapLenOrIndef`).
- Each key is read with `decodeWord`. It must be major type 0. A negative, text, or other
  non-uint key fails.
- If the key was already seen, decoding fails with "Duplicate key". This check happens before
  the value is read (`Coders.hs:565-572`).
- An unknown key maps to `invalidField k`, which runs `Invalid k`. That fails with
  `invalidKey` before the value is read (`Coders.hs:159-160,486`).
- `field`: the value is decoded with the given decoder.
- `ofield`: the same, but the result is wrapped in `SJust`.
- `fieldGuarded msg p`: the value is decoded, then decoding fails with `msg` if `p value`
  holds (`Coders.hs:138-152`).
- After the map ends, every required key must have been seen, otherwise "not decoded"
  (`Coders.hs:557-559,642-654`).
- There is no ordering requirement and no upper bound on entry count.

### 1.5 Bounded rationals (`UnitInterval`, `NonNegativeInterval`, `PositiveInterval`, `PositiveUnitInterval`)

Below v12, `decCBOR = fromPlainDecoder fromCBOR` (`CORE/BaseTypes.hs:407-428`), which works
as follows:

1. **Tag 30 is mandatory** (`assertTag 30`, `BIN/Plain.hs:159-161,180-189`). A missing tag or a
   different tag fails.
2. Then a definite or indefinite array whose elements are **all** decoded as `integer`
   (bignums allowed). Exactly 2 elements are required, and the count is checked after
   decoding (`BIN/Plain.hs:162-167`).
3. A zero denominator fails. The value is then `n % d`, which is Haskell `Rational`
   normalisation: reduced to lowest terms with the sign moved to the numerator. For example,
   `[2,4]` becomes 1/2 and `[-1,-2]` becomes 1/2.
4. `boundRational`: the *reduced* numerator and denominator must each lie in
   `[0, 2^64-1]` (Word64). The value must also lie within the type's bounds
   (`CORE/BaseTypes.hs:349-379`).

| Type | Bounds | Source |
|---|---|---|
| `UnitInterval` | [0, 1] | `CORE/BaseTypes.hs:544-561` |
| `NonNegativeInterval` | [0, 2^64-1] | `CORE/BaseTypes.hs:469-486` |
| `PositiveInterval` | [10^-19, 2^64-1] | `CORE/BaseTypes.hs:489-510` |
| `PositiveUnitInterval` | [10^-19, 1] | `CORE/BaseTypes.hs:513-532` |

The unbounded `Rational` decoder `decodeRational` (`BIN/Decoding/Decoder.hs:465-484`, which
has the v9 "optional tag 30" change) is **not used by any field reachable from a transaction
body**. All rational fields in tx bodies are the bounded types above.

### 1.6 Nested CBOR (tag 24)

`decodeNestedCborBytes` reads tag 24 (via `decodeTag`; any other tag fails), then `bytes`,
which is definite only below v12. Source: `BIN/Decoding.hs:213-240`.

### 1.7 Memoisation and sizes

- A TxBody is memoised: the original byte slice is kept (`CORE/MemoBytes/Internal.hs:302-305`,
  `Mem` deriving in each era). **TxId = Blake2b-256 of the exact on-wire TxBody bytes.**
  Never re-encode before hashing. Because non-canonical encodings are accepted, re-encoding
  changes the hash.
- From Babbage on, outputs are decoded as `Sized TxOut`. The size is the original byte span of
  the output (`BIN/Decoding/Sized.hs:64-72`), and it is the size used by the Babbage/Conway
  min-UTxO rule (`BA/TxOut.hs:678-702`, `BA/Rules/Utxo.hs:326`).

---

## 2. TxBody

### 2.1 Common shape

The TxBody is a `SparseKeyed` map (§1.4) in every era. TxBody bytes are memoised (§1.7).
There is **no** "at least one field" check on the TxBody in any era Shelley–Conway: inputs,
outputs and fee are required keys, and that is all. An empty input set decodes fine and is
rejected only by the UTXO rule `InputSetEmptyUTxO` (`SH/Rules/Utxo.hs:173`).

### 2.2 TxIn and TxId (all eras)

| Item | Rule | Source |
|---|---|---|
| `TxIn` | `Rec(2)` `[txid, ix]` (definite with length 2, or indefinite with 2 items then break) | `CORE/TxIn.hs:130-135` |
| `TxId` | `Hash32` (`SafeHash EraIndependentTxBody`) | `CORE/TxIn.hs:65-67` |
| `TxIx` | **`u16` in every era**. Values > 65535 fail at decode time. No version gate exists. | `CORE/BaseTypes.hs:924-927` |

The `DecShareCBOR TxIn` instance (MemPack bytes) is only used for ledger state and never for
blocks (`CORE/TxIn.hs:137-142`).

Related index widths: `CertIx` is `u16` (`CORE/BaseTypes.hs:954`) and appears only inside
pointer addresses (§4.3). `GovActionIx` is `u16` (§9.3).

### 2.3 Shelley (v2)

Source: `SH/TxBody.hs:107-118` (types), `136-144` (decoder and required keys `[0,1,2,3]`),
`194-203` (fields).

| Key | Field | Req | Wire decoder | Decode-time checks |
|---|---|---|---|---|
| 0 | inputs `Set TxIn` | **R** | `SetV(TxIn)` at v2: no tag 258, duplicates merged | — |
| 1 | outputs `StrictSeq TxOut` | **R** | `List(ShelleyTxOut)` (§3.1). Empty allowed. | — |
| 2 | fee `Coin` | **R** | `u64` | — |
| 3 | ttl `SlotNo` | **R** | `u64` | — |
| 4 | certs `StrictSeq TxCert` | O | `List(ShelleyTxCert)` (§6.1). Empty allowed. | — |
| 5 | withdrawals | O | `MapV(AccountAddress, Coin)` at v2 (§7). Empty allowed. | — |
| 6 | update `Update` | O | §8.1 | — |
| 7 | aux data hash | O | `Hash32` | — |
| other | — | — | `invalidField` | fails |

### 2.4 Allegra (v3)

Source: `AL/TxBody.hs:97-109` (types), `139-156` (required keys `[0,1,2]`), `197-225`
(fields), `257-263` (Allegra instantiates `ma = ()`).

| Key | Field | Req | Wire decoder | Notes |
|---|---|---|---|---|
| 0 | inputs | **R** | `SetV(TxIn)` at v3 | — |
| 1 | outputs | **R** | `List(ShelleyTxOut)` (coin-only value, §3.1) | — |
| 2 | fee | **R** | `u64` | — |
| 3 | invalid-hereafter `SlotNo` | O | `u64` | **TTL is now optional** |
| 4 | certs | O | `List(ShelleyTxCert)` | — |
| 5 | withdrawals | O | `MapV` at v3 | — |
| 6 | update | O | §8.1 (Allegra PParamsUpdate) | — |
| 7 | aux data hash | O | `Hash32` | — |
| 8 | invalid-before `SlotNo` | O | `u64` | new |
| 9 | "mint" of type `()` | O | **`null` only** (`DecCBOR ()` = `decodeNull`) | See below |

**Quirk: key 9 in Allegra.** `bodyFields 9` exists for every `AllegraTxBodyRaw ma`, and
Allegra sets `ma = ()` (`AL/TxBody.hs:224,258`). An Allegra body with `9: null` (`09 f6`)
therefore decodes successfully. The value is discarded, but it still contributes to the TxId
because the bytes are memoised. Any other value under key 9 fails. The encoder never emits it,
because `Omit (== mempty)` is always true for `()` (`AL/TxBody.hs:195`).

### 2.5 Mary (v4)

Mary uses the same raw type as Allegra with `ma = MultiAsset` (`MA/TxBody.hs:93,181`), so the
key set is identical. The differences are:

- **Key 9 is mint**: `MultiAsset` with `i64` quantities (§5.3). An empty map `{}` is allowed.
  Zero quantities and empty inner maps are pruned silently (v<9).
- Outputs are `ShelleyTxOut MaryEra`, whose value is a `MaryValue` (§3.2, §5).

### 2.6 Alonzo (v5)

Source: `AZ/TxBody.hs:162-178` (types), `460-498` (decoder, required keys `[0,1,2]`).

| Key | Field | Req | Wire decoder | Notes |
|---|---|---|---|---|
| 0 | inputs | **R** | `SetV(TxIn)` at v5 | — |
| 1 | outputs | **R** | `List(AlonzoTxOut)` (§3.3) | — |
| 2 | fee | **R** | `u64` | — |
| 3 | invalid-hereafter | O | `u64` | — |
| 4 | certs | O | `List(ShelleyTxCert)` | — |
| 5 | withdrawals | O | `MapV` at v5 | — |
| 6 | update | O | §8.1 (Alonzo PParamsUpdate) | — |
| 7 | aux data hash | O | `Hash32` | — |
| 8 | invalid-before | O | `u64` | — |
| 9 | mint | O | `MultiAsset` (§5.3) | `{}` allowed |
| 11 | script integrity hash | O | `Hash32` | new |
| 13 | collateral inputs `Set TxIn` | O | `SetV(TxIn)` at v5 | empty allowed |
| 14 | required signers `Set (KeyHash Guard)` | O | `SetV(Hash28)` at v5 | empty allowed |
| 15 | network id | O | `Network` (`u8` ∈ {0,1}) | new |
| 10, 12, ≥16 | — | — | `invalidField` | fail |

A key 15 mismatch with the node's network is a rule failure (`validateWrongNetworkInTxBody`,
`AZ/Rules/Utxo.hs:446-449`), not a decode failure.

### 2.7 Babbage (v7)

Source: `BA/TxBody.hs:130-153` (types), `525-565` (decoder, required keys `[0,1,2]`).

| Key | Field | Req | Wire decoder | Notes |
|---|---|---|---|---|
| 0 | inputs | **R** | `SetV(TxIn)` at v7 | — |
| 1 | outputs `StrictSeq (Sized TxOut)` | **R** | `List(Sized BabbageTxOut)` (§3.4) | wire size recorded |
| 2 | fee | **R** | `u64` | — |
| 3 | invalid-hereafter | O | `u64` | — |
| 4 | certs | O | `List(ShelleyTxCert)` | — |
| 5 | withdrawals | O | `MapV` at v7 | — |
| 6 | update | O | §8.1 (Babbage PParamsUpdate) | — |
| 7 | aux data hash | O | `Hash32` | — |
| 8 | invalid-before | O | `u64` | — |
| 9 | mint | O | `MultiAsset` | `{}` allowed |
| 11 | script integrity hash | O | `Hash32` | — |
| 13 | collateral inputs | O | `SetV(TxIn)` | empty allowed |
| 14 | required signers | O | `SetV(Hash28)` | empty allowed |
| 15 | network id | O | `Network` | — |
| 16 | collateral return `Sized TxOut` | O | `Sized BabbageTxOut` | new |
| 17 | total collateral `Coin` | O | `u64` | new |
| 18 | reference inputs `Set TxIn` | O | `SetV(TxIn)` | new; empty allowed |
| 10, 12, ≥19 | — | — | `invalidField` | fail |

### 2.8 Conway (v9)

Source: `CO/TxBody.hs:124-146` (types), `182-269` (decoder, required keys `[0,1,2]`, guards).

| Key | Field | Req | Wire decoder | Decode-time guard |
|---|---|---|---|---|
| 0 | spend inputs | **R** | `SetV(TxIn)` at v9: optional tag 258, duplicates **fail** | **none** (empty allowed at decode) |
| 1 | outputs | **R** | `List(Sized BabbageTxOut)` at v9 (§3.4) | — |
| 2 | fee | **R** | `u64` | — |
| 3 | invalid-hereafter | O | `u64` | — |
| 4 | certs `OSet TxCert` | O | `OSet(ConwayTxCert)` (§6.2). Duplicates fail. | **fails if empty**: "TxBody: 'Certificates' must be non-empty when supplied" (`:199-204`) |
| 5 | withdrawals | O | `MapV` at v9 (duplicates fail) | **fails if empty** (`:205-210`) |
| 6 | (update) | — | `invalidField` | **removed: key 6 fails** |
| 7 | aux data hash | O | `Hash32` | — |
| 8 | invalid-before | O | `u64` | — |
| 9 | mint | O | `MultiAsset` at v9 (§5.3) | **fails if `== mempty`**, i.e. `{}` (`:216-221`) |
| 11 | script integrity hash | O | `Hash32` | — |
| 13 | collateral inputs | O | `SetV(TxIn)` at v9 | **fails if empty** (`:223-228`) |
| 14 | required signers | O | `SetV(Hash28)` at v9 | **fails if empty** (`:229-234`) |
| 15 | network id | O | `Network` | — |
| 16 | collateral return | O | `Sized BabbageTxOut` | — |
| 17 | total collateral | O | `u64` | — |
| 18 | reference inputs | O | `SetV(TxIn)` at v9 | **fails if empty** (`:238-243`) |
| 19 | voting procedures | O | §9.1 | **fails if the outer map is empty** (`:244-249`) |
| 20 | proposal procedures | O | `OSet(ProposalProcedure)` (§9.2) | **fails if empty** (`:250-255`) |
| 21 | current treasury value | O | `Coin` (`u64`, 0 allowed) | — (checked by rule `ConwayTreasuryValueMismatch`, `CO/Rules/Ledger.hs:126`) |
| 22 | treasury donation | O | `decodePositiveCoin` (`u64`, **0 fails**) | "TxBody: 'Treasury Donation' must be non-zero when supplied" (`:256-260`, `CORE/Coin.hs:226-231`) |
| 10, 12, ≥23 | — | — | `invalidField` | fail |

Guards run after the value is fully decoded, so any inner decode error is reported first
(`BIN/Decoding/Coders.hs:147-152`).

### 2.9 Cross-era key matrix

R = required, O = optional, ✗ = `invalidField` (decode failure), `ne` = Conway non-empty
guard.

| Key | Meaning | Shelley | Allegra | Mary | Alonzo | Babbage | Conway |
|---|---|---|---|---|---|---|---|
| 0 | inputs | R | R | R | R | R | R |
| 1 | outputs | R | R | R | R | R | R |
| 2 | fee | R | R | R | R | R | R |
| 3 | ttl / invalid-hereafter | **R** | O | O | O | O | O |
| 4 | certs | O | O | O | O | O | O `ne`, OSet |
| 5 | withdrawals | O | O | O | O | O | O `ne` |
| 6 | update | O | O | O | O | O | ✗ |
| 7 | aux data hash | O | O | O | O | O | O |
| 8 | invalid-before | ✗ | O | O | O | O | O |
| 9 | mint | ✗ | O (`null` only) | O | O | O | O `ne` |
| 10 | — | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| 11 | script integrity hash | ✗ | ✗ | ✗ | O | O | O |
| 12 | — | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| 13 | collateral inputs | ✗ | ✗ | ✗ | O | O | O `ne` |
| 14 | required signers | ✗ | ✗ | ✗ | O | O | O `ne` |
| 15 | network id | ✗ | ✗ | ✗ | O | O | O |
| 16 | collateral return | ✗ | ✗ | ✗ | ✗ | O | O |
| 17 | total collateral | ✗ | ✗ | ✗ | ✗ | O | O |
| 18 | reference inputs | ✗ | ✗ | ✗ | ✗ | O | O `ne` |
| 19 | voting procedures | ✗ | ✗ | ✗ | ✗ | ✗ | O `ne` |
| 20 | proposal procedures | ✗ | ✗ | ✗ | ✗ | ✗ | O `ne` |
| 21 | current treasury | ✗ | ✗ | ✗ | ✗ | ✗ | O |
| 22 | donation | ✗ | ✗ | ✗ | ✗ | ✗ | O (>0) |
| ≥23 | — | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |

---

## 3. TxOut

### 3.1 Shelley and Allegra: `[address, coin]`

- `ShelleyTxOut`: `Rec(2)`. It is `decodeRecordNamed "ShelleyTxOut" (const 2)`, so a definite
  length of 2, or an indefinite array with exactly 2 items then break, is accepted
  (`SH/TxOut.hs:159-163`). Allegra reuses it (`AL/TxOut.hs:18-19`).
- Address: the `CompactAddr` decoder (`CORE/Address.hs:961-963`), which follows the v<7 rules
  in §4.
- Value: `CompactForm Coin` = `u64` (`CORE/Coin.hs:193-194`). An array value (multi-asset)
  fails in these eras.

### 3.2 Mary: `[address, value]`

The same `ShelleyTxOut` shape (`MA/TxOut.hs:20-21`). The value is `CompactForm MaryValue`,
whose decoder is `decodeMaryValue` followed by compaction (`MA/Value.hs:432-448`). See §5.
Compaction cannot fail, because all decoded quantities are already `u64`.

### 3.3 Alonzo: `[address, value]` or `[address, value, datum_hash]`

Source: `AZ/TxOut.hs:390-413`.

- Definite length 2: address and value.
- Definite length 3: address, value, then `DataHash` (`Hash32`).
- Any other definite length fails with "wrong number of terms in txout".
- Indefinite: address and value, then either a break (2 items) or a datum hash followed by a
  break. Anything else fails with "Excess terms in txout".
- Address: `fromCborBothAddr` (§4). At v5 this is the backwards (lenient) path.
- Value: `CompactForm MaryValue` (§5).

### 3.4 Babbage and Conway: array form or map form

Source: `BA/TxOut.hs:521-523` (`decodeBabbageTxOut fromCborBothAddr`), `555-592`, `618-676`.
Conway uses the same type (`CO/TxOut.hs:36-37`).

The decoder first peeks at the token type. `TypeMapLen` or `TypeMapLenIndef` selects the map
form. Anything else selects the array form, which then calls `decodeListLenOrIndef`, so a
non-array also fails here.

**Array form** (`oldTxOut`, `BA/TxOut.hs:568-590`) follows the same rules as Alonzo §3.3:
`[addr, value]` or `[addr, value, datum_hash]`, definite or indefinite. The value is decoded as
`Value era` (`MaryValue`, §5).

**Map form** (`decodeTxOut`, `BA/TxOut.hs:618-676`) is a `SparseKeyed "TxOut"` with required
keys `[0, 1]`:

| Key | Field | Req | Decoder | Notes |
|---|---|---|---|---|
| 0 | address | **R** | `fromCborBothAddr` (§4) | — |
| 1 | value | **R** | `MaryValue` (§5) | — |
| 2 | datum option | O | `Datum` sum (§3.5) | no wire encoding of `NoDatum` |
| 3 | script ref | O | `decodeCIC "Script"` (§3.6) | — |
| other | — | — | `invalidField` | fail |

Duplicate keys and unknown keys fail as described in §1.4. A map that contains only a datum
hash, or that has no datum and no script, is accepted and normalised to the same internal
representation as the array form (`BA/TxOut.hs:436-470`).

### 3.5 Datum option and inline datum

`Datum` is a `Sum` (`CORE/Plutus/Data.hs:301-316`):

| Tag | Shape | Decoder |
|---|---|---|
| 0 | `[0, datum_hash]` | `DataHash` (`Hash32`) |
| 1 | `[1, 24(bytes)]` | `BinaryData` |
| other | — | `invalidKey` |

`BinaryData` decoding (`CORE/Plutus/Data.hs:218-237`) works in two steps:

1. Tag 24, then definite `bytes` (§1.6).
2. **Decode-time validation**: the payload must decode **completely**, with no trailing bytes,
   as Plutus `Data` via `decodeFullAnnotator (eraProtVerLow @era)`. Any failure rejects the
   block. The `Data` decoder is version-independent: `fromPlainDecoder Cborg.decode`
   (`CORE/Plutus/Data.hs:100-101`), which is plutus's `decodeData`.

Plutus `Data` decoder rules (`PLC/Data.hs:209-307`):

| CBOR item | Rule |
|---|---|
| uint or nint (major 0/1, ≤ 64 bits) | `I` |
| bignum (tag 2/3) | Payload must be a byte string. Definite: at most 64 bytes. Indefinite: each chunk at most 64 bytes. Tags other than 2/3 inside a bignum fail. (`:232-266`) |
| definite bytes | at most 64 bytes, else "ByteString exceeds 64 bytes" (`:261-266`) |
| indefinite bytes | each chunk at most 64 bytes, any total (`:248-259`) |
| array (definite or indefinite) | `List` |
| map (definite or indefinite) | `Map`, a list of pairs. **Duplicate keys and any key order are allowed.** (`:277-283`) |
| tag 121–127 | `Constr (t-121)` with a fields array (`:291-292`) |
| tag 1280–1400 | `Constr (t-1280+7)` (`:294-295`) |
| tag 102 | `[u64 constructor, fields array]`. A definite array must have length 2; an indefinite one must break after the 2 items. (`:289,298-307`) |
| any other tag, text string, float, simple, null, or bool | fail (`:230`, `:296`) |

### 3.6 Script reference (key 3)

`decodeCIC` (`BA/TxOut.hs:778-785`) reads tag 24 and definite bytes, then decodes the payload
completely (no trailing bytes) as `Annotator (Script era)` at the **current decoder version**
(7 or 9).

`AlonzoScript` is a `Sum` below v12 (`AZ/Scripts.hs:728-759`):

| Tag | Shape | Babbage (v7) | Conway (v9) |
|---|---|---|---|
| 0 | `[0, native_script]` | Timelock | Timelock |
| 1 | `[1, bytes]` PlutusV1 | ok | ok |
| 2 | `[2, bytes]` PlutusV2 | ok | ok |
| 3 | `[3, bytes]` PlutusV3 | **fail**: "PlutusV3 isn't supported in the Babbage era" | ok |
| 4 | `[4, bytes]` PlutusV4 | fail | **fail** ("PlutusV4 isn't supported in the Conway era") |
| ≥5 | — | `invalidKey` | `invalidKey` |

The language check is `mkPlutusScript`, which fails through `eraUnsupportedLanguage`
(`AZ/Scripts.hs:695-702,775-778`; Babbage `BA/Scripts.hs:63-69`; Conway `CO/Scripts.hs:98-105`).

**Plutus script bytes are NOT checked for well-formedness at decode time.** `PlutusBinary` is
just `sbytes` (`CORE/Plutus/Language.hs:251-256`), and any byte string, including an empty
one, is accepted. Deserialisability against the current protocol version (`isValidPlutus`,
`CORE/Plutus/Language.hs:237-238`) is checked by the UTXOW rule as `MalformedReferenceScripts`
(`BA/Rules/Utxow.hs:269-291`; Conway carries the same failure at
`CO/Rules/Utxow.hs:108-111,296-297`). This is a predicate failure, not a block decode failure.

Native script (Timelock) inside a script ref is a `Sum` (`AL/Scripts.hs:190-197,246-259`):

| Tag | Shape |
|---|---|
| 0 | `[0, Hash28]` signature |
| 1 | `[1, List(native_script)]` all-of |
| 2 | `[2, List(native_script)]` any-of |
| 3 | `[3, int, List(native_script)]` m-of. `int` is the full Int64 range, so negative values are accepted. |
| 4 | `[4, u64]` time start (`SlotNo`) |
| 5 | `[5, u64]` time expire (`SlotNo`) |

### 3.7 Internal compact forms and normalisation (no extra checks)

- `mkTxOutCompact` (`AZ/TxOut.hs:480-490`) and `mkTxOut` (`BA/TxOut.hs:436-470`) choose an
  internal representation. For example, `TxOut_AddrHash28_AdaOnly` is used for a Shelley base
  address with an ada-only value. They add **no** validation. Their
  `fromMaybe (error ...) (toCompact v)` cannot fire, because decoded values always fit
  (§5.1).
- The `DecShareCBOR` instances (`AZ/TxOut.hs:415-422`, `BA/TxOut.hs:525-540`) accept MemPack
  bytes and use `fromCborBackwardsBothAddr` (lenient). **They are only used for ledger-state
  snapshots.** TxBody fields always use `From`, which is `DecCBOR`.
- What the decoded TxOut retains:
  - Pre-Babbage trailing address bytes are cropped.
  - Pointer addresses are re-serialised from the normalised `Ptr` (§4.3).
  - Pre-v9 zero quantities are pruned.

  Rules that re-serialise the decoded value see the normalised form. One example is the
  Alonzo+ `OutputTooBigUTxO`, which uses `serialize` of the decoded `Value`
  (`AZ/Rules/Utxo.hs:425-444`). In Babbage+, the min-UTxO rule uses the original wire size
  instead (§1.7).

---

## 4. Addresses

### 4.1 Entry points and version gates

All address decoding first reads a CBOR byte string as `ShortByteString`, which must be
definite below v12, and then parses the raw bytes.

`fromCborBothAddr` (`CORE/Address.hs:459-476`) is used by every TxOut decoder (§3):

| Decoder version | Path | Pointer handling | Trailing bytes after a Shelley address |
|---|---|---|---|
| v < 7 (Shelley, Allegra, Mary, Alonzo) | `fromCborBackwardsBothAddr` (`:495-503`): `decodeAddrStateLenientT True True` | lenient (`decodePtrLenient`) | **accepted**; dropped from the stored `CompactAddr` |
| 7 ≤ v < 9 (Babbage) | `fromCborRigorousBothAddr True` (`:479-488`): `decodeAddrStateLenientT True False` | lenient | **rejected** ("Left over bytes") |
| v ≥ 9 (Conway) | `fromCborRigorousBothAddr False`: `decodeAddrStateLenientT False False` | **strict** (`decodePtr`) | **rejected** |

At every version, if the decoded address is a pointer address, the stored `CompactAddr` is
re-serialised from the decoded (and possibly normalised) `Ptr` (`CORE/Address.hs:471-474`).

`AccountAddress` (reward account) uses a separate decoder with **no version gate** (§4.6).

### 4.2 Header byte

Source: `CORE/Address.hs:539-577,643-675`.

1. The buffer must contain at least 1 byte (`guardLength`).
2. **Byron detection**: the header byte must be exactly `0x82`. Any other value is treated as
   Shelley. A Byron address whose outer CBOR array header is not the single byte `0x82` (for
   example `0x98 0x02` or `0x9f`) is therefore never recognised as Byron.
3. **Shelley**: `header .&. 0b10001110 == 0` is required, otherwise "Invalid header. Unused
   bits are not suppose to be set". So bit 7 and bits 1–3 must be 0.
   - Consequences: header types 8–15 (high nibble ≥ 8) are rejected unless the byte is exactly
     `0x82`. This includes types 9–13 and the reward-account types 14/15 (`0xE0`/`0xF0`
     family) used as a payment address.
   - **Network id**: only bit 0 is read (1 → Mainnet, 0 → Testnet). Network ids 2–15 are
     rejected because bits 1–3 must be zero.
   - Whether the network matches the node's network is checked by the UTXO rules
     `WrongNetwork`/`WrongNetworkWithdrawal` (`SH/Rules/Utxo.hs:178,181`), not at decode time.
4. Type decoding, using bit 4 = payment credential is a script, bit 5 = stake credential is a
   script or "no stake" for enterprise, bit 6 = not a base address:

| Bits 6,5 | Address kind | Body after header |
|---|---|---|
| 0,x | base (types 0–3) | payment `Hash28`, then stake `Hash28` (bit 5 = script) |
| 1,0 | pointer (types 4–5) | payment `Hash28`, then 3 variable-length ints (§4.3) |
| 1,1 | enterprise (types 6–7) | payment `Hash28` |

Hash reads fail with "Not enough bytes" if the buffer is short (`CORE/Address.hs:747-767`).

### 4.3 Pointer encoding

Each component is a big-endian base-128 varint: the high bit of a byte means "more bytes
follow" (`CORE/Address.hs:808-826`). Running out of buffer mid-varint fails (`guardLength`).

**Lenient (v < 9)**: `decodePtrLenient` (`CORE/Address.hs:780-789,876-883`):

- Each of slot, txIx and certIx is read with `decodeVariableLengthWord64` =
  `fix (decode7BitVarLength ...) 0`. This takes **unbounded** continuation bytes and
  accumulates into a `Word64` with `acc << 7 | b`, so overflow wraps silently. The result is
  the true value mod 2^64.
- Non-minimal encodings (leading `0x80` bytes) are accepted.
- Then `mkPtrNormalized` (`CORE/Credential.hs:279-285`): if slot > 2^32-1, **or** txIx > 65535,
  **or** certIx > 65535, the whole pointer becomes `Ptr 0 0 0`. Otherwise it is kept.
- Nothing fails here except running out of bytes.

**Strict (v ≥ 9)**: `decodePtr` (`CORE/Address.hs:769-778,832-872`):

| Component | Max bytes | Rule |
|---|---|---|
| slot (`Word32`) | 5 | If and only if 5 bytes are used, the first byte must satisfy `b & 0xF0 == 0x80`, otherwise "More than 32bits was supplied". A continuation bit on the 5th byte fails with "too many bytes". |
| txIx (`Word16`) | 3 | If and only if 3 bytes are used, the first byte must satisfy `b & 0xFC == 0x80`, otherwise "More than 16bits was supplied". A continuation bit on the 3rd byte fails. |
| certIx (`Word16`) | 3 | same as txIx |

Non-minimal leading `0x80` bytes are still accepted as long as the byte count limit holds. For
example, `80 80 05` is txIx 5. No normalisation is applied.

### 4.4 Trailing bytes

`ensureBufIsConsumed` (`CORE/Address.hs:672-692`) runs only when `isLenient = False`, that is
for v ≥ 7.

For v < 7, any bytes after a complete Shelley address (base, pointer or enterprise) are
accepted and cropped (`CORE/Address.hs:495-503`). For pointer addresses, "complete" means
after the third varint terminates.

Byron addresses always reject trailing bytes at every version: `decodeBootstrapAddress` runs
`decodeFull'` over the **entire** buffer (`CORE/Address.hs:695-704`, and `decodeFull`
reports leftover at `BIN/Decoding.hs:120-126`).

### 4.5 Byron bootstrap addresses inside Shelley+ outputs

All of the following is decoded at `byronProtVer` = v1, so the v<2 container rules apply:

| Step | Rule | Source |
|---|---|---|
| Outer | Definite array of length 2 (`enforceSize`; the first byte must be `0x82` per §4.2) | `BYRON/CBOR.hs:125-127` |
| Payload | Tag 24 (`decodeTag`, any width), then **definite** `bytes` | `BYRON/CBOR.hs:128`, `BIN/Decoding.hs:213-240` |
| CRC | `u32` (`decodeWord32`, any width) | `BYRON/CBOR.hs:129` |
| CRC check | `crc32(payload bytes)` from `Data.Digest.CRC32` must equal the decoded CRC, else fail | `BYRON/CBOR.hs:63,130-139` |
| Inner | `decodeFull' byronProtVer payload`: must consume all bytes | `BYRON/CBOR.hs:140` |
| Inner shape | `Tuple(3)` at v1: a **definite** array of exactly 3 | `BYRON/Address.hs:172-180`, `BIN/Decoding/DecCBOR.hs:297-303,315-326` |
| root | `AddressHash` = `AbstractHash Blake2b_224`: definite bytes, exactly 28 | `BYRON/AddressHash.hs:14`, `BYRON-CRYPTO/Hashing.hs:155-165` |
| attributes | `Map Word8 LazyByteString` at v1: **definite** map (`decodeMapSkel`), keys `u8` **strictly increasing** (canonical order, no duplicates), values definite bytes | `BYRON/Attributes.hs:213-235`, `BIN/Decoding/Decoder.hs:727-757,813` |
| attr 1 (derivation path) | The value bytes must be, in full, a **canonical** CBOR byte string (`decodeBytesCanonical`) | `BYRON/AddrAttributes.hs:136-138,178-179` |
| attr 2 (network magic) | The value bytes must be, in full, a canonical `u32` (`decodeWord32Canonical`) | `BYRON/AddrAttributes.hs:139-142` |
| other attr keys | Kept as unparsed. **Accepted.** | `BYRON/AddrAttributes.hs:143`, `BYRON/Attributes.hs:223-235` |
| type | `decodeWord8Canonical`: 0 (VerKey) or 2 (Redeem) only. 1 and others fail. | `BYRON/AddrSpendingData.hs:108-113` |

Not checked at decode time:

- The network (derived from attribute 2's presence by `getNetwork`, `CORE/Address.hs:173-178`)
  is checked by the UTXO rule `WrongNetwork`.
- Attribute size (`bootstrapAddressAttrsSize` > 64) is checked by the UTXO rule
  `OutputBootAddrAttrsTooBig` (`CORE/Address.hs:334-340`, `SH/Rules/Utxo.hs:187`).
- Redeem addresses are accepted at decode time.

### 4.6 AccountAddress (reward account)

`fromCborAccountAddress` (`CORE/Address.hs:906-955`) has **no version gate**:

- `sbytes` (definite below v12), then the following byte-level checks:
- At least 1 byte.
- The header must satisfy `header & 0b11101110 == 0b11100000`, so only `0xE0`, `0xE1`, `0xF0`
  and `0xF1` are accepted.
- Bit 4 selects a script hash versus a key hash. Bit 0 is the network.
- Then exactly one `Hash28`, and **no trailing bytes** (`ensureBufIsConsumed`).
- Total length is therefore exactly 29 bytes.

It is used for withdrawals keys (§7), the pool reward account (§6.4), and Conway's proposal
return address and treasury withdrawal keys (§9).

---

## 5. Value and MultiAsset (Mary → Conway)

Source: `MA/Value.hs`.

### 5.1 `MaryValue` (TxOut value)

`decodeMaryValue` (`MA/Value.hs:299-322`) peeks at the token type:

| Token | Result |
|---|---|
| `TypeUInt`, `TypeUInt64` | coin-only: `u64` |
| `TypeListLen`, `TypeListLen64`, `TypeListLenIndef` | pair `[coin, multiasset]` |
| anything else (negative int, bignum tag, map, ...) | fail: "MaryValue: expected array or int" |

- The pair is a `RecD(2)` below v12 (`MA/Value.hs:312-316`). So it must be a definite array of
  length 2. An indefinite array is accepted **only** in the degenerate `9f ff coin ma` form
  (§1.3).
- coin is `Coin` (`u64`). Coin 0 is fine at decode time; the min-UTxO rule handles it.
- Quantities in a TxOut value are decoded with `toInteger <$> decodeWord64` (`:305-307`), so
  they lie in **0..2^64-1**. Negative quantities and bignums fail.

### 5.2 `decodeMultiAsset`

Source: `MA/Value.hs:331-352`. The shape is `{ PolicyID => { AssetName => quantity } }`.

| Rule | v4–v8 (Mary, Alonzo, Babbage) | v9 (Conway) |
|---|---|---|
| outer map | `MapV` at v<9: duplicate policy keys silently accepted, **the last inner map wins entirely** (no merge) | `MapV` at v9: duplicates fail. **Empty `{}` allowed.** |
| inner map | `MapV` at v<9: duplicates last-wins | duplicates fail. **Empty inner map fails** ("Empty Assets are not allowed"). |
| zero quantity | allowed, then **silently pruned** (`pruneZeroMultiAsset`, `:897-912`). An inner map that becomes empty is removed. | **fails** ("MultiAsset cannot contain zeros") |
| size limit | after pruning: `44·(total asset entries) + 28·(number of policies) ≤ 65535`, else "MultiAsset is too big to compact" (`:341,743-745`) | same |

At v12 (Dijkstra, not covered here) the outer map must also be non-empty (`:344`).

Key decoders:

| Key | Rule | Source |
|---|---|---|
| `PolicyID` | `ScriptHash` = `Hash28` | `MA/Value.hs:142-156` |
| `AssetName` | `sbytes`, definite. **Length 0..32**; more than 32 bytes fails ("asset name exceeds 32 bytes"). The limit is the same in every era. | `MA/Value.hs:130-139` |

Consequences:

- Mary to Babbage: `[c, {p: {n: 0}}]` decodes to an ada-only value. A pruned value re-encodes
  as plain `c` (`MA/Value.hs:354-362`).
- Conway: `[c, {}]` is accepted and treated as ada-only. `[c, {p: {}}]` and `[c, {p: {n: 0}}]`
  fail.

### 5.3 Mint (TxBody key 9)

`DecCBOR MultiAsset = decodeMultiAsset decodeIntegerBounded64` (`MA/Value.hs:185-186`).

- Quantity: `decodeIntegerBounded64` (`MA/Value.hs:369-393`). The token must be major type 0
  or 1 (`TypeUInt`/`TypeUInt64`/`TypeNInt`/`TypeNInt64`). Bignum tags are rejected ("expected
  major type 0 or 1 when decoding mint field"). The value must lie in
  [-2^63, 2^63-1], otherwise "overflow when decoding mint field".
- All of the §5.2 rules apply.
- **Mary to Babbage**: zero-quantity mint entries are silently pruned. A mint of
  `{p: {n: 0}}` therefore decodes as **empty mint**. Policy `p` is then not part of the mint
  at all, so its minting script is not required. Duplicate policies follow last-wins.
- **Conway**: zeros and empty inner maps fail at decode time. An empty outer map decodes, but
  the TxBody guard then rejects `== mempty` (§2.8). The net effect is that the mint field, if
  present, has at least one policy and every policy has at least one non-zero asset.
- Negative quantities (burns) are allowed in every era.

---

## 6. Certificates

### 6.1 Shelley-family certificates (Shelley, Allegra, Mary, Alonzo, Babbage)

All five eras use `ShelleyTxCert` (`SH/TxCert.hs:127`, `AL/TxCert.hs:12`, `MA/TxCert.hs:26`,
`AZ/TxCert.hs:12`, `BA/TxCert.hs:12`).

The certificate is a `Sum` decoded by `decodeRecordSum "ShelleyTxCert"` (`SH/TxCert.hs:518-567`).
The "len" column below is the required definite array length. An indefinite array must break
after the fields.

| Tag | Certificate | Fields | len | Source |
|---|---|---|---|---|
| 0 | stake registration | `Credential Staking` | 2 | `SH/TxCert.hs:544-546` |
| 1 | stake deregistration | `Credential Staking` | 2 | `:547-549` |
| 2 | stake delegation | `Credential Staking`, pool `Hash28` | 3 | `:550-553` |
| 3 | pool registration | 9 flat pool-param fields (§6.4) | 10 | `:559-561` |
| 4 | pool retirement | pool `Hash28`, `EpochNo` (`u64`) | 3 | `:562-565` |
| 5 | genesis delegation | genesis `Hash28`, delegate `Hash28`, VRF key hash `Hash32` | 4 | `:528-532`, `:294-299` |
| 6 | MIR | `MIRCert` | 2 | `:533-535` |
| ≥7 | — | — | — | `invalidKey` (`:536`) |

MIR sub-structures:

| Item | Rule | Source |
|---|---|---|
| `MIRCert` | `Rec(2)` `[pot, target]` | `SH/TxCert.hs:396-406` |
| `MIRPot` | `uint`: 0 = reserves, 1 = treasury, else `invalidKey` | `:338-343` |
| `MIRTarget` | Peek. A map token (definite or indefinite) gives `StakeAddressesMIR`, a `MapV(Credential Staking, DeltaCoin)`. Any other token gives `SendToOppositePotMIR`, which is a `Coin` (`u64`). | `:359-372` |
| `DeltaCoin` | `integer`: unbounded, negative allowed | `CORE/Coin.hs:115-119` |

All MIR semantics are rule-time, not decode-time (`SH/Rules/Deleg.hs:392-419`):

- Negative deltas are rejected before Alonzo (`MIRNegativesNotCurrentlyAllowed`).
- From Alonzo on, the deltas combined with existing rewards must stay non-negative.
- Transfers to the other pot are rejected before Alonzo (`MIRTransferNotCurrentlyAllowed`).
- An empty stake-address map decodes fine.
- The MIR map follows the v<9 duplicate rule (last wins).

`Credential` is a `Sum` with no version gate below v12 (`CORE/Credential.hs:327-344`):

| Shape | Meaning |
|---|---|
| `[0, Hash28]` | key hash |
| `[1, Hash28]` | script hash |
| other tag | `invalidKey` |

### 6.2 Conway certificates (v9)

`decodeRecordSum "ConwayTxCert"` (`CO/TxCert.hs:713-778`):

| Tag | Certificate | Fields | len |
|---|---|---|---|
| 0 | reg (no deposit) | `Credential` | 2 |
| 1 | unreg (no deposit) | `Credential` | 2 |
| 2 | stake delegation | `Credential`, pool `Hash28` | 3 |
| 3 | pool registration | pool params (§6.4) | 10 |
| 4 | pool retirement | pool `Hash28`, `EpochNo` | 3 |
| **5** | — | **fails**: "Genesis delegation certificates are no longer supported" (`:724`) | — |
| **6** | — | **fails**: "MIR certificates are no longer supported" (`:725`) | — |
| 7 | reg with deposit | `Credential`, `Coin` | 3 |
| 8 | unreg with deposit | `Credential`, `Coin` | 3 |
| 9 | vote delegation | `Credential`, `DRep` | 3 |
| 10 | stake and vote delegation | `Credential`, pool `Hash28`, `DRep` | 4 |
| 11 | reg + stake delegation | `Credential`, pool `Hash28`, `Coin` | 4 |
| 12 | reg + vote delegation | `Credential`, `DRep`, `Coin` | 4 |
| 13 | reg + stake and vote delegation | `Credential`, pool `Hash28`, `DRep`, `Coin` | 5 |
| 14 | committee hot key auth | cold `Credential`, hot `Credential` | 3 |
| 15 | committee cold resign | cold `Credential`, `Nullable(Anchor)` | 3 |
| 16 | DRep registration | `Credential`, `Coin`, `Nullable(Anchor)` | 4 |
| 17 | DRep deregistration | `Credential`, `Coin` | 3 |
| 18 | DRep update | `Credential`, `Nullable(Anchor)` | 3 |
| ≥19 | — | `invalidKey` (`:765`) | — |

Notes:

- Tags 9–13 inline the delegatee fields; there is no nested `Delegatee` array
  (`CO/TxCert.hs:767-776`). The standalone `Delegatee` sum (`:418-440`) is not used by the
  certificate decoder at v9.
- Deposits are `Coin` (`u64`) and 0 is allowed at decode time. Matching against protocol
  parameters is rule-time (`IncorrectDepositDELEG`, `CO/Rules/Deleg.hs:107`;
  `ConwayDRepIncorrectDeposit`, `CO/Rules/GovCert.hs:111`).
- In the TxBody, Conway certificates sit in an `OSet`. Structurally equal certificates
  therefore **fail at decode time** as duplicates (§1.2). Before Conway, duplicate
  certificates decode fine.

`DRep` is a `Sum` (`CORE/DRep.hs:90-110`):

| Shape | Meaning |
|---|---|
| `[0, Hash28]` | key hash |
| `[1, Hash28]` | script hash |
| `[2]` | always abstain |
| `[3]` | always no confidence |
| other tag | `invalidKey` |

`Anchor` is a `RecD(2)` `[Url, Hash32]` (`CORE/BaseTypes.hs:991-1011`). `Url` is ≤ 128 bytes at
v9 (§6.5).

### 6.3 Credential roles

Roles (Staking, DRepRole, ColdCommitteeRole, HotCommitteeRole, StakePool, Genesis...) do not
affect the wire format. Every credential is the 2-tag `Credential` sum, and every pool or
genesis id is a bare `Hash28`.

### 6.4 Pool parameters

`decodeStakePoolParamsFlat` (`CORE/State/StakePool.hs:755-771`). These are flat fields inside
the certificate array, not a nested array:

| # | Field | Decoder | Notes |
|---|---|---|---|
| 1 | operator | `Hash28` | — |
| 2 | VRF key hash | `Hash32` | — |
| — | BLS key | — | v12 only (`:759-763`) |
| 3 | pledge | `Coin` | — |
| 4 | cost | `Coin` | `>= minPoolCost` is rule-time |
| 5 | margin | `UnitInterval` | §1.5: tag 30 required, reduced, [0,1] |
| 6 | reward account | `AccountAddress` | §4.6. Network match is rule-time (`SH/Rules/Pool.hs:220-232`). |
| 7 | owners | `SetV(Hash28)` | v<9: duplicates merged, no tag 258. v9: optional 258, duplicates fail. |
| 8 | relays | `List(StakePoolRelay)` | any length |
| 9 | metadata | `Nullable(PoolMetadata)` | — |

`StakePoolRelay` is a `Sum` (`CORE/State/StakePool.hs:383-390,461-476`):

| Shape | Meaning |
|---|---|
| `[0, Nullable(Port), Nullable(IPv4), Nullable(IPv6)]` | single host address |
| `[1, Nullable(Port), DnsName]` | single host name |
| `[2, DnsName]` | multi host name |
| other tag | `invalidKey` |

| Item | Rule | Source |
|---|---|---|
| `Port` | `u16` | `CORE/BaseTypes.hs:700-702` |
| `IPv4` | definite `bytes` of **exactly 4** bytes. Fewer fails the `Get`; more fails with "leftover". | `BIN/Decoding/DecCBOR.hs:228-246,263-265` |
| `IPv6` | definite `bytes` of **exactly 16** bytes, read as 4 little-endian `Word32`s | `BIN/Decoding/DecCBOR.hs:249-269` |
| `PoolMetadata` | `Rec(2)` `[Url, sbytes]` | `CORE/State/StakePool.hs:348-352,692-694` |
| metadata hash | `ByteArray`, definite, **any length** at decode time. `PoolMedataHashTooBig` (more than 32 bytes) is a POOL rule check, active for protocol version > 4.0. | `CORE/State/StakePool.hs:350`, `SH/Rules/Pool.hs:234-239`, `SH/SoftForks.hs:11-14` |

### 6.5 URL and DNS name limits

`Url` and `DnsName` are both decoded with `textDecCBOR n`: definite `text`, then the
**UTF-8 byte length** (`lengthWord8`) must be ≤ n (`CORE/BaseTypes.hs:645-698`).

| Version | Url limit | DnsName limit |
|---|---|---|
| v < 9 (Shelley–Babbage) | 64 bytes | 64 bytes |
| v ≥ 9 (Conway) | 128 bytes | 128 bytes |

This applies to pool metadata URLs, relay DNS names, and (Conway) every `Anchor` URL.

---

## 7. Withdrawals

`Withdrawals` is a newtype over `Map AccountAddress Coin` with derived `DecCBOR`
(`CORE/Address.hs:980-982`). It decodes as `MapV(AccountAddress, Coin)`.

| Era | Duplicate account keys | Empty map | Value |
|---|---|---|---|
| Shelley–Babbage (v2–v7) | silently accepted, **last wins** | **allowed** (the encoder omits it, but the decoder accepts `5: {}`) | `u64`, 0 allowed |
| Conway (v9) | **fail** | **fail** (TxBody guard, §2.8) | `u64`, 0 allowed |

Keys use the strict `AccountAddress` format (§4.6) in every era. "Duplicate" means equal
decoded `(network, credential)` pairs. Network mismatch is a rule-time check
(`WrongNetworkWithdrawal`, `SH/Rules/Utxo.hs:181`).

---

## 8. Update proposals (TxBody key 6, Shelley–Babbage) and PParamsUpdate

### 8.1 `Update` and `ProposedPPUpdates`

| Item | Rule | Source |
|---|---|---|
| `Update` | `RecD(2)` `[proposed_updates, EpochNo]` (§1.3 RecD quirk) | `SH/PParams.hs:250-271` |
| `ProposedPPUpdates` | `MapV(Hash28 genesis key, PParamsUpdate era)` at the era's version: v<9, so duplicates are last-wins. Empty `{}` allowed. | `SH/PParams.hs:292-312` |
| `EpochNo` | `u64` | §1.1 |

The proposal's PParamsUpdate is decoded with **the tx era's** parameter set. Allegra and Mary
reuse the Shelley set (`AL/PParams.hs:14,43`, `MA/PParams.hs:21,50`).

### 8.2 Generic `PParamsUpdate` decoder (all eras below v12)

Source: `CORE/Core/PParams.hs:264-300`.

- `SparseKeyed` with **no required keys**. **An empty map `{}` decodes.** Unknown keys fail
  through `invalidField`. Duplicate keys fail.
- Each key decodes with the field type's `DecCBOR` (`decode From`), unless the parameter
  supplies an `EraCodec`. Only `protocolVersion` does, with `decodeProtVer @era`.
- In Conway, an empty update or zero values are rejected by the **GOV rule**
  `MalformedProposal` through `ppuWellFormed`, not at decode time (§8.8).

### 8.3 Key table

`·` means not present in that era (decode fails through `invalidField`).

| Key | Parameter | Wire type | Sh | Al | Ma | Az | Ba | Co |
|---|---|---|---|---|---|---|---|---|
| 0 | txFeePerByte (minfee A) | `CoinPerByte` = `u64` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 1 | txFeeFixed (minfee B) | `CompactForm Coin` = `u64` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 2 | maxBlockBodySize | **`u32`** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 3 | maxTxSize | **`u32`** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 4 | maxBlockHeaderSize | **`u16`** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 5 | stakeAddressDeposit | `u64` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 6 | stakePoolDeposit | `u64` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 7 | poolRetireMaxEpoch (eMax) | `EpochInterval` = **`u32`** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 8 | stakePoolTargetNum (nOpt) | **`u16`** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 9 | poolPledgeInfluence (a0) | `NonNegativeInterval` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 10 | monetaryExpansion (rho) | `UnitInterval` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 11 | treasuryCut (tau) | `UnitInterval` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 12 | decentralization (d) | `UnitInterval` | ✓ | ✓ | ✓ | ✓ | · | · |
| 13 | extraPraosEntropy | `Nonce` | ✓ | ✓ | ✓ | ✓ | · | · |
| 14 | protocolVersion | `ProtVer` via `decodeProtVer @era` (§8.4) | ✓ | ✓ | ✓ | ✓ | ✓ | · |
| 15 | minUTxOValue | `u64` | ✓ | ✓ | ✓ | · | · | · |
| 16 | minPoolCost | `u64` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 17 | coinsPerUTxOWord (Az) / coinsPerUTxOByte (Ba, Co) | `u64` | · | · | · | ✓ | ✓ | ✓ |
| 18 | costModels | `CostModels` (§8.5) | · | · | · | ✓ | ✓ | ✓ |
| 19 | prices | `Prices` = `RecD(2)` of `NonNegativeInterval` (mem, steps) | · | · | · | ✓ | ✓ | ✓ |
| 20 | maxTxExUnits | `ExUnits` (§8.6) | · | · | · | ✓ | ✓ | ✓ |
| 21 | maxBlockExUnits | `ExUnits` | · | · | · | ✓ | ✓ | ✓ |
| 22 | maxValueSize | **`u32`** | · | · | · | ✓ | ✓ | ✓ |
| 23 | collateralPercentage | **`u16`** | · | · | · | ✓ | ✓ | ✓ |
| 24 | maxCollateralInputs | **`u16`** | · | · | · | ✓ | ✓ | ✓ |
| 25 | poolVotingThresholds | `Rec(5)` of `UnitInterval` (§8.7) | · | · | · | · | · | ✓ |
| 26 | dRepVotingThresholds | `Rec(10)` of `UnitInterval` (§8.7) | · | · | · | · | · | ✓ |
| 27 | committeeMinSize | **`u16`** | · | · | · | · | · | ✓ |
| 28 | committeeMaxTermLength | `EpochInterval` = `u32` | · | · | · | · | · | ✓ |
| 29 | govActionLifetime | `EpochInterval` = `u32` | · | · | · | · | · | ✓ |
| 30 | govActionDeposit | `u64` | · | · | · | · | · | ✓ |
| 31 | dRepDeposit | `u64` | · | · | · | · | · | ✓ |
| 32 | dRepActivity | `EpochInterval` = `u32` | · | · | · | · | · | ✓ |
| 33 | minFeeRefScriptCostPerByte | `NonNegativeInterval` | · | · | · | · | · | ✓ |

Sources for the key table:

- Field types: `CORE/Core/PParams.hs:445-508`, `SH/PParams.hs:101-136`, `AZ/PParams.hs:226-283`,
  `BA/PParams.hs:91-135`, `CO/PParams.hs:645-711`.
- Tags: `SH/PParams.hs:371-524`, `AZ/PParams.hs:648-708`, `BA/PParams.hs:406-412`,
  `CO/PParams.hs:1268-1336`.
- Per-era lists: `SH/PParams.hs:526-551`, `AZ/PParams.hs:344-369`, `BA/PParams.hs:204-227`,
  `CO/PParams.hs:863-895`.
- Conway's `protocolVersion` has `ppUpdate = Nothing`, so key 14 is not updatable in Conway
  (`CO/PParams.hs:1339-1345`).

Integer widths are enforced by the decoder. For example, maxBlockHeaderSize 70000 or
nOpt 70000 **fail at decode time**, because they are `u16`.

`Nonce` (key 13) is a `Sum` (`CORE/BaseTypes.hs:580-596`):

| Shape | Meaning |
|---|---|
| `[0]` | neutral |
| `[1, Hash32]` | nonce |
| other tag | `invalidKey` |

### 8.4 `ProtVer` (`decodeProtVer @era`)

Source: `CORE/BaseTypes.hs:212-264`.

- `Rec(2)` (CBORGroup) `[major, minor]`.
- major is `decodeVersion` = `u32` and must lie in [0, `MaxVersion`] = [0, 13]
  (`BIN/Decoding/Decoder.hs:453-454`, `BIN/Version.hs:63,111-127`).
- minor is `u32`.
- Then `major ≤ succ(ProtVerHigh era)`, otherwise "Protocol version ... exceeds the maximum
  expected version".

| Era | Maximum major accepted at decode time |
|---|---|
| Shelley | 3 |
| Allegra | 4 |
| Mary | 5 |
| Alonzo | 7 |
| Babbage | 9 |
| Conway (HardForkInitiation, §9.3) | 12 |

Whether the version can legitimately follow the current one is rule-time
(`pvCanFollow`, `SH/PParams.hs:332-349`). `MaxVersion = 13` is a property of the node build.

### 8.5 Cost models (key 18)

`decodeCostModels` (`CORE/Plutus/CostModels.hs:311-317`) depends on the version.

**v5, v7 (Alonzo, Babbage)**: `decodeCostModelsFailing` = `decodeMapByKey Language
decodeCostModelLegacy` (`:306-309,319-337`).

- Outer: `MapV` at v<9. Duplicate languages are last-wins.
- Key: `Language` = `enum(0..3)` (`CORE/Plutus/Language.hs:273-278,332-334`). Keys outside
  0..3, or negative, fail.
- Key 2 (PlutusV3) or 3 (PlutusV4) fails with "Legacy CostModel decoding is not supported".
  So only 0 (V1) and 1 (V2) are accepted. **A V2 cost model decodes even in the Alonzo era.**
- Value: `List(i64)` (definite or indefinite). The length must be **exactly** 166 for V1 and
  175 for V2 (`costModelInitParamCount`, `:233-241`), otherwise "Expected array with ...
  entries".
- Then `mkCostModel`.

**v9 (Conway)**: `decodeCostModelsLenient` = `Map Word8 [Int64]` then `mkCostModelsLenient`
(`:302-304,426-440`).

- Outer: `MapV` at v9. Duplicates fail.
- Keys: `u8` (0..255).
- Value: `List(i64)` of **any length**, including empty.
- Keys 0..3 (`mkLanguageEnum`, `CORE/Plutus/Language.hs:296-302`) are known languages and are
  passed to `mkCostModel`. PlutusV4 uses V3's evaluation context (`:284-289`).
- Keys 4..255 are stored as "unknown" cost models. **Accepted.**

`mkCostModel` (`:278-291`) calls plutus `mkEvaluationContext`. For a parameter count that
differs from expected, plutus only emits warnings: it truncates extra parameters and pads
missing ones with `maxBound` (`PLA/Common/ParamName.hs:96-112`). The only error constructors
(`CMUnknownParamError`, `CMInternalReadError`, `CMInternalWriteError`) are documented as
internal or "should not happen". In practice `mkCostModel` does not fail on any `[Int64]`.
See §11.

### 8.6 `ExUnits` and `Prices`

| Item | Rule | Source |
|---|---|---|
| `ExUnits` | `RecD(2)` `[mem, steps]`. Each is `u64` and must be ≤ 2^63-1 ("values must not exceed maxBound :: Int64"). | `CORE/Plutus/ExUnits.hs:208-230` |
| `OrdExUnits` | newtype over `ExUnits` with the same decoder | `CORE/Plutus/ExUnits.hs:164` |
| `Prices` | `RecD(2)` `[mem_price, step_price]` of `NonNegativeInterval` (§1.5: tag 30 required) | `CORE/Plutus/ExUnits.hs:172-175,235-244` |

### 8.7 Conway voting threshold records

Both are `Rec`, so definite or indefinite arrays work properly. Every element is a
`UnitInterval`.

`PoolVotingThresholds` is a `Rec(5)` (`CO/PParams.hs:305-311,367-375`), in this order:

1. motion of no confidence
2. committee normal
3. committee no confidence
4. hard fork initiation
5. pp security group

`DRepVotingThresholds` is a `Rec(10)` (`CO/PParams.hs:395-406,520-533`), in this order:

1. motion of no confidence
2. committee normal
3. committee no confidence
4. update to constitution
5. hard fork initiation
6. pp network group
7. pp economic group
8. pp technical group
9. pp gov group
10. treasury withdrawal

### 8.8 Conway rule-time well-formedness (not decode)

`ppuWellFormed` (`CO/PParams.hs:936-955`), used by `actionWellFormed` in GOV
(`CO/Rules/Gov.hs:393-399`), raises `MalformedProposal` when any of the following hold:

- The update is empty (`ppu /= emptyPParamsUpdate`).
- Any of these is 0: maxBlockBodySize, maxTxSize, maxBlockHeaderSize, maxValueSize,
  collateralPercentage, committeeMaxTermLength, govActionLifetime, poolDeposit,
  govActionDeposit, dRepDeposit.
- coinsPerUTxOByte is 0 outside bootstrap.
- nOpt is 0 at protocol version ≥ 11.

These are all ledger predicate failures. The block decodes.

---

## 9. Conway governance in the TxBody

### 9.1 VotingProcedures (key 19)

Source: `CO/Governance/Procedures.hs:431-455`.

- Outer: `decodeMapByKey Voter (Map GovActionId VotingProcedure)` at v9. Definite or
  indefinite. **Duplicate voters fail.**
- Inner map: `MapV` at v9, so duplicate `GovActionId`s fail. **An empty inner map fails at
  decode time**: "VotingProcedures require votes, but Voter: ... didn't have any" (`:449-454`).
- Empty outer map: the type decodes it, but the TxBody guard rejects it (§2.8).

`Voter` is a `decodeRecordSum` (`CO/Governance/Procedures.hs:384-392`):

| Shape | Voter |
|---|---|
| `[0, Hash28]` | committee hot key hash |
| `[1, Hash28]` | committee hot script |
| `[2, Hash28]` | DRep key hash |
| `[3, Hash28]` | DRep script |
| `[4, Hash28]` | stake pool |
| `[5, ...]` | **fails**: "Script objects are not allowed for StakePool votes" |
| other tag | `invalidKey` |

| Item | Rule | Source |
|---|---|---|
| `GovActionId` | `RecD(2)` `[TxId (Hash32), GovActionIx (u16)]` | `CO/Governance/Procedures.hs:174-189` |
| `VotingProcedure` | `RecD(2)` `[Vote, Nullable(Anchor)]` | `CO/Governance/Procedures.hs:485-506` |
| `Vote` | `enum(0..2)`: 0 = No, 1 = Yes, 2 = Abstain | `CO/Governance/Procedures.hs:411-426` |

Whether a voter is allowed, whether an action exists, and whether it has expired are all GOV
rule checks (`CO/Rules/Gov.hs:178-195`).

### 9.2 ProposalProcedures (key 20)

The key is an `OSet(ProposalProcedure)`: optional tag 258, duplicates fail. An empty set is
rejected by the TxBody guard.

`ProposalProcedure` is a `RecD(4)` (`CO/Governance/Procedures.hs:543-580`):

1. deposit: `Coin` (`u64`)
2. return address: `AccountAddress` (§4.6)
3. gov action: `GovAction` (§9.3)
4. anchor: `Anchor` (`RecD(2)` `[Url ≤ 128 bytes, Hash32]`)

Deposit amount and return-address network are rule-time checks (`ProposalDepositIncorrect`,
`ProposalProcedureNetworkIdMismatch`, `CO/Rules/Gov.hs:180-182`).

### 9.3 GovAction (tags 0–6)

`Summands "GovAction"` (`CO/Governance/Procedures.hs:872-985`). The "len" column is the
required definite array length.

| Tag | Action | Fields (in order) | len |
|---|---|---|---|
| 0 | ParameterChange | `Nullable(GovPurposeId)`, `PParamsUpdate` (Conway keys, §8.3), `Nullable(ScriptHash)` (guardrail policy) | 4 |
| 1 | HardForkInitiation | `Nullable(GovPurposeId)`, `ProtVer` via `decodeProtVer @Conway` (major ≤ 12, §8.4) | 3 |
| 2 | TreasuryWithdrawals | `MapV(AccountAddress, Coin)` at v9 (duplicates fail, **empty allowed at decode**, 0 values allowed), `Nullable(ScriptHash)` | 3 |
| 3 | NoConfidence | `Nullable(GovPurposeId)` | 2 |
| 4 | UpdateCommittee | `Nullable(GovPurposeId)`, members to remove `SetV(Credential)` at v9, members to add `MapV(Credential, EpochNo)` at v9, new threshold `UnitInterval` | 5 |
| 5 | NewConstitution | `Nullable(GovPurposeId)`, `Constitution` | 3 |
| 6 | InfoAction | — | 1 |
| ≥7 | — | `invalidKey` | — |

| Item | Rule | Source |
|---|---|---|
| `GovPurposeId` | newtype over `GovActionId` (`RecD(2)`) | `CO/Governance/Procedures.hs:704-714` |
| `Constitution` | `RecD(2)` `[Anchor, Nullable(ScriptHash)]` | `CO/Governance/Procedures.hs:1008-1012,1044-1054` |

Rule-time checks for governance actions include:

- `ZeroTreasuryWithdrawals`
- `TreasuryWithdrawalsNetworkIdMismatch`
- `ConflictingCommitteeUpdate`
- `ExpirationEpochTooSmall`
- `InvalidPrevGovActionId`
- `ProposalCantFollow`
- `MalformedProposal`
- guardrail script hash checks

Sources: `CO/Rules/Gov.hs:178-211,393-399`.

### 9.4 Treasury fields (keys 21, 22)

- Key 21 (current treasury value): `Coin` (`u64`). 0 is allowed at decode time. A mismatch
  with the actual treasury is the LEDGER rule failure `ConwayTreasuryValueMismatch`
  (`CO/Rules/Ledger.hs:126`).
- Key 22 (donation): `decodePositiveCoin`, so `u64` and **0 fails at decode time**
  (`CO/TxBody.hs:256-260`, `CORE/Coin.hs:226-231`).

---

## 10. Decode-time versus rule-time quick reference

| Condition | Decode-time (block rejected as undecodable) | Rule-time (predicate failure) |
|---|---|---|
| Unknown, duplicate, or missing-required TxBody key | ✓ all eras | |
| Empty inputs | | ✓ `InputSetEmptyUTxO` |
| Empty certs, withdrawals, mint, collateral, required signers, reference inputs, votes, or proposals | ✓ Conway only | |
| Duplicate set or map elements | ✓ Conway (v9) only; silently merged before | |
| Duplicate certificates | ✓ Conway (OSet) | |
| Zero-quantity or empty-inner multi-asset | ✓ Conway; silently pruned before | |
| Asset name > 32 bytes; MultiAsset too big to compact | ✓ all eras ≥ Mary | |
| Mint quantity outside Int64 or bignum-encoded | ✓ | |
| Treasury donation = 0 | ✓ | |
| TxIx > 65535 | ✓ (`u16`) | |
| PParamsUpdate integer out of `u16`/`u32` range | ✓ | |
| PParamsUpdate empty or zero-valued | | ✓ Conway `MalformedProposal` |
| ProtVer major > succ(ProtVerHigh) or > 13 | ✓ | |
| Cost model wrong length | ✓ Alonzo/Babbage (exact 166/175) | |
| Cost model for V3+ | ✓ Alonzo/Babbage | |
| Rational without tag 30, out of bounds, or zero denominator | ✓ | |
| Address header bits, short buffer, pointer overflow (v9), trailing bytes (v≥7) | ✓ | |
| Address network mismatch | | ✓ `WrongNetwork`, `WrongNetworkWithdrawal` |
| Byron CRC or structure | ✓ | |
| Byron attributes too big | | ✓ `OutputBootAddrAttrsTooBig` |
| Inline datum not valid Plutus Data | ✓ | |
| Script ref language newer than the era | ✓ | |
| Script ref Plutus bytes not deserialisable | | ✓ `MalformedReferenceScripts` |
| Pool metadata hash > 32 bytes | | ✓ `PoolMedataHashTooBig` (pv > 4.0) |
| URL or DNS > 64 bytes (pre-Conway) or > 128 bytes (Conway) | ✓ | |
| Genesis delegation or MIR certificate in Conway | ✓ | |
| MIR negatives or transfers before Alonzo | | ✓ `SH/Rules/Deleg.hs:392-419` |
| Deposits or treasury value mismatching | | ✓ |
| Network id key 15 mismatch | | ✓ `validateWrongNetworkInTxBody` |
| Value too large (`maxValSize`) | | ✓ `OutputTooBigUTxO` (re-serialised value) |

---

## 11. Ambiguities and things to verify with test vectors

1. **`RecD` and indefinite arrays (§1.3).** From the code, `9f f1 .. fn ff` is rejected and
   `9f ff f1 .. fn` is accepted for every `RecD` type below v12. No test in the tree covers
   this. Before relying on it, confirm against a node, for example by decoding a crafted
   Conway `Anchor` inside a DRep update certificate with `cardano-ledger`'s decoder at v9. The
   affected types are `MaryValue` pair, `Update`, `Prices`, `ExUnits`, `Anchor`,
   `GovActionId`, `VotingProcedure`, `ProposalProcedure`, and `Constitution`.
2. **cborg text decoding.** This document assumes cborg's `decodeString` rejects invalid UTF-8.
   It is the decoder behind `Url` and `DnsName`. The cborg source is not in `refs/`. Confirm
   against cborg's `Codec.CBOR.Read`.
3. **`mkCostModel` failure cases (§8.5).** Plutus exposes `CostModelApplyError` constructors,
   but for every `[Int64]` input the reachable code paths only warn. If you need certainty,
   check `PlutusCore.Evaluation.Machine.CostModelInterface.applyCostModelParams` for
   value-dependent failures (`PLC/Evaluation/Machine/CostModelInterface.hs:244-252`). This
   document treats it as infallible.
4. **Historical type widths.** The current code decodes TxIx as `u16` and several PParams
   (maxBHSize, nOpt, collateralPercentage, maxCollateralInputs, committeeMinSize) as
   `u16`/`u32` in every era, with no version gate. Older ledger releases used wider types. The
   refs are a shallow clone, so the history cannot be checked here. The current behaviour is
   what today's node applies when replaying the chain.
5. **`MaxVersion = 13`** (`BIN/Version.hs:63`) bounds `ProtVer` major at decode time. It is a
   build constant that changes between node releases, so pin it to the node version you match.
6. **Cost model keys at v9 for languages 2/3 (V3/V4).** These go through `mkCostModel` with the
   V3 evaluation context (`CORE/Plutus/CostModels.hs:284-289`). They are "known" in the ledger
   enum even though Conway scripts cannot use V4. This is accepted at decode time; any
   consequence is rule-time.
