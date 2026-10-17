# Decoding reference: witness sets, auxiliary data, Plutus data, and Byron

This is an implementer's reference for the parts of a Cardano block that cardano-node's Haskell
decoders accept or reject. It covers witness sets, redeemers, native and Plutus scripts, Plutus
`Data`, auxiliary data (metadata), bootstrap witnesses, and the whole Byron block format. Every
rule cites the Haskell source it comes from. The CDDL files are approximate. Where a CDDL file and
the code disagree, this document follows the code and points out the disagreement.

Sources (pinned clones under `refs/`):

| repo | commit |
|---|---|
| cardano-ledger | `178bd36` |
| plutus | `7ab93b9` |
| ouroboros-consensus | `9b918f8` |
| cardano-base | `5813d21` |

Path abbreviations used in citations:

| abbreviation | path under `refs/` |
|---|---|
| `bin/` | `cardano-ledger/libs/cardano-ledger-binary/src/Cardano/Ledger/Binary/` |
| `core/` | `cardano-ledger/libs/cardano-ledger-core/src/Cardano/Ledger/` |
| `shelley/` `allegra/` `mary/` `alonzo/` `babbage/` `conway/` | `cardano-ledger/eras/<era>/impl/src/Cardano/Ledger/<Era>/` |
| `byron/` | `cardano-ledger/eras/byron/ledger/impl/src/Cardano/Chain/` |
| `byron-crypto/` | `cardano-ledger/eras/byron/crypto/src/Cardano/Crypto/` |
| `byron.cddl` | `cardano-ledger/eras/byron/ledger/impl/cddl-spec/byron.cddl` |
| `plutus-core/` | `plutus/plutus-core/plutus-core/src/PlutusCore/` |
| `plutus-api/` | `plutus/plutus-ledger-api/src/PlutusLedgerApi/` |
| `oc-byron/` | `ouroboros-consensus/ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/` |
| `oc-cardano/` | `ouroboros-consensus/ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/` |
| `cardano-base/` | `cardano-base/` |

Terminology:

- **v** is the decoder version: `eraProtVerLow` of the block's era (Shelley 2, Allegra 3, Mary 4,
  Alonzo 5, Babbage 7, Conway 9, Dijkstra 12; Byron 1).
- **D** means a definite-length CBOR array or map, **I** means indefinite-length, and **D|I** means
  either is accepted.
- **Decode failure** means the Haskell decoder fails, so the whole block is undecodable. **Rule
  failure** means the block decodes but a ledger or consensus rule rejects it. Both reject the
  block, but at different stages and with different error types. An implementation has to put each
  check at the same stage, or at least produce the same accept/reject result.
- Some checks are deferred inside an `Annotator`, which runs after the CBOR parse once the full
  input bytes are available (`bin/Decoding/Annotated.hs:198`). Before v12 nothing in this document
  fails at that stage. At v12 a few duplicate checks do. Both stages are still part of decoding
  (`bin/Decoding.hs:171-179`).

---

## 0. Shared machinery

### 0.1 Primitive (cborg) assumptions

cborg is not vendored under `refs/`. The behaviour below comes from cborg itself and from how the
ledger code relies on it. Items marked (verify) were not checked against cborg source.

- `decodeWord`, `decodeWord8/16/32/64`: major type 0 only, with the value range-checked for the
  width. Non-minimal argument encodings are accepted.
- `decodeInt`, `decodeInt32`, `decodeInt64`: major type 0 or 1, within the signed range.
- `decodeInteger`: major 0 or 1 (full 64-bit argument), or a bignum. (verify) cborg's token-type
  table classifies only the one-byte headers `0xc2` and `0xc3` as `TypeInteger`. A tag 2 or 3
  written in a longer form (for example `0xd8 0x02`) is classified as `TypeTag`. This matters for
  Plutus `Data` (A.5.2).
- `decodeBytes`, `decodeByteArray`, `decodeString`: definite length only. `decodeBytesIndef` and
  `decodeStringIndef` accept only the indefinite headers `0x5f` and `0x7f`. Chunks inside an
  indefinite string must themselves be definite.
- (verify) `decodeString` UTF-8-decodes the text. Treat invalid UTF-8 as a decode failure.
- `*Canonical` variants (`decodeBytesCanonical`, `decodeWord8Canonical`, `decodeWord32Canonical`,
  `decodeListLenCanonical`, ...) reject non-minimal headers. Byron uses a few of them (B.6).
- `decodeListLen` and `decodeMapLen` accept definite only. `decodeListLenIndef` accepts only
  `0x9f`. `decodeListLenOrIndef` and `decodeMapLenOrIndef` accept both. `decodeListLenOf n` is
  definite with exactly `n` entries (non-minimal length header allowed).
- `decodeTag` and `decodeTag64` accept a tag header of any width.
- (verify) `decodeBool` accepts only `0xf4` and `0xf5`.

### 0.2 Version-gated helpers relied on below

All are in `bin/Decoding/Decoder.hs` unless noted.

| helper | behaviour | cite |
|---|---|---|
| `decodeBytes` | definite only below v12; definite or indefinite (chunks concatenated) at v12+ | 359-364, 1603-1620 |
| `decodeByteArray` (used by `ShortByteString`, `ByteArray`) | same gate as `decodeBytes` | 1388-1394; `bin/Decoding/DecCBOR.hs:428-444` |
| `decodeString` (`Text`) | definite only below v12 | 1564-1570 |
| `decodeList` (`[a]`) | v<2: **I only**; v≥2: D\|I | 538-544, 555-559 |
| `decodeNonEmptyList` (`NonEmpty a`) | `decodeList`, then fails if empty | 546-552; `DecCBOR.hs:455-457` |
| `decodeStrictSeq` / `decodeSeq` | D\|I at every version | 1141-1149 |
| `decodeVector` | D only (`decodeListLen`) | 1131-1137, 1100-1127 |
| `decodeMaybe` | v<2: D array of length 0 or 1; v≥2: D\|I, 0 or 1 element | 566-602 |
| `decodeStrictMaybe` | D\|I at every version | 618-620 |
| `decodeMap` (`Map k v`) | v<2: D only, keys strictly increasing under Haskell `Ord`; v2..8: D\|I, duplicates last-wins (`Map.fromList`); v≥9: D\|I, duplicates rejected | 792-821, 727-757, 825-847 |
| `decodeSet` | v<2: tag 258 required, D, strictly increasing; v2..8: D\|I, no tag, duplicates collapsed; v≥9: optional tag 258, D\|I, duplicates rejected | 943-953 |
| tuples `(a,b)` ... `(a,...,g)` | v<12: D exact length (`decodeListLenOf`); v12+: D\|I | `DecCBOR.hs:297-414` |
| `decodeRecordNamed` | D (length must match) \| I (break required after the fields) | 645-659, 682-700 |
| `decodeRecordSum` | `[word_tag, fields...]`, D (length must match the arm's size) \| I | 661-666 |
| `enforceSize n` | D, exactly n | 1362-1375 |
| `allowTag t` | optional tag, which must equal `t` if present | 1347-1354 |
| `assertTag t` (`TagD`) | mandatory tag equal to `t` | `bin/Plain.hs:180-196`; `bin/Decoding/Coders.hs:489-491` |
| `decodeSparse` (`SparseKeyed`) | map D\|I; keys via `decodeWord`; duplicate key → failure; unknown key → whatever the field function returns (always failure here via `invalidField`) | `Coders.hs:552-592`, 634-640, 159-160 |
| `decodeSparseKeyed` (v12 paths) | same contract | 1228-1287 |
| `decodeNonEmptySetLikeEnforceNoDuplicates` | optional tag 258, D\|I, non-empty, no duplicates | 1058-1098 |
| `decodeMapLikeEnforceNoDuplicates` | D\|I via the supplied length decoder; fails if final size ≠ element count | 825-847, 1034-1054 |
| `decodeNatural` | `decodeInteger`, must be ≥ 0 | 1472-1478 |
| `Hash h a` | `decodeBytes`, then exact digest size (`packByteString`) | `DecCBOR.hs:555-561`; `cardano-base/cardano-crypto-class/src/Cardano/Crypto/PackedBytes/Internal.hs:379-381` |
| DSIGN `VerKeyDSIGN` / `SigDSIGN` / `SignedDSIGN` | `decodeBytes`, then exact size (Ed25519: 32 / 64) | `DecCBOR.hs:535-549`; `Decoder.hs:366-367` |
| `SlotNo` | Serialise `Word64` | `DecCBOR.hs:659-661`; `cardano-base/cardano-slotting/src/Cardano/Slotting/Slot.hs:44-47` |

### 0.3 Memoization ("original bytes")

- `type Mem t = Annotator (MemoBytes t)` (`core/MemoBytes/Internal.hs:205`). The
  `DecCBOR (Annotator (MemoBytes t))` instance runs the inner decoder under `withSlice` and stores
  the exact byte span consumed (`core/MemoBytes/Internal.hs:173-180`;
  `bin/Decoding/Annotated.hs:229-233`). The bytes are copied into a `ShortByteString`
  (`MemoBytes/Internal.hs:234-238`).
- `originalBytes` of a memoized value is that byte span (`MemoBytes/Internal.hs:199-201`).
  Hashes that use `hashAnnotated` / `SafeHash` hash these exact bytes, never a re-encoding.
- `decodeMemoized` is the getOriginalBytes-based variant (`MemoBytes/Internal.hs:302-305`). None
  of the types in this document use it before v12; they all go through `Mem` / `Annotator`.

---

# PART A: Shelley to Conway

## A.1 Transaction witness set

### A.1.1 Shelley, Allegra, Mary: `ShelleyTxWits`

`TxWits` is `ShelleyTxWits era` for all three eras (`shelley/TxWits.hs:166-167`,
`allegra/TxWits.hs:22-23`, `mary/TxWits.hs:23`). It is memoized: `newtype ShelleyTxWits era =
MkShelleyTxWits (MemoBytes (ShelleyTxWitsRaw era))` with `deriving via Mem`
(`shelley/TxWits.hs:106`, `113-119`).

Outer structure (`shelley/TxWits.hs:242-274`): `SparseKeyed "ShelleyTxWitsRaw"` with no required
keys.

- The map may be D or I (`Coders.hs:553-556`), and keys may appear in any order.
- Keys are read with `decodeWord` (`Coders.hs:567`). A negative integer, text or any other key type
  is a decode failure.
- A duplicate key is a decode failure (`Coders.hs:568-569`, `634-640`).
- An unknown key (anything other than 0, 1 or 2) is a decode failure:
  `witField n = fieldAA ... (Invalid n)` → `invalidKey` (`shelley/TxWits.hs:274`;
  `Coders.hs:486`, `524`).
- An empty map `{}` is accepted and means no witnesses.

| key | content | decoder | cite |
|---|---|---|---|
| 0 | vkey witnesses | `Set.fromList <$> decodeList decCBOR` (`WitVKey`). D\|I at v2..4, no tag 258 (a tag fails the list-length read), empty allowed, duplicates collapsed by `Ord` (A.1.4) | `shelley/TxWits.hs:258-261` |
| 1 | native scripts | `mapTraverseableDecoderA (decodeList decCBOR) (Map.fromElems (hashScript @era))`, elements `Annotator (Script era)`: Shelley `MultiSig`, Allegra/Mary `Timelock` (A.3). D\|I, empty allowed, keyed by script hash, last-wins on equal hashes (`Map.fromList`, `cardano-ledger/libs/cardano-data/src/Data/MapExtras.hs:271-274`) | `shelley/TxWits.hs:262-269`, `276-281` |
| 2 | bootstrap witnesses | `Set.fromList <$> decodeList decCBOR` (`BootstrapWitness`, A.7). Same container rules as key 0 | `shelley/TxWits.hs:270-273` |

The `Script era` type: Shelley `MultiSig ShelleyEra` (`shelley/Scripts.hs:146-148`); Allegra and
Mary `Timelock era` (`allegra/Scripts.hs:355-356`, `mary/Scripts.hs:21-22`). So a Shelley-era
witness containing a Timelock tag 4 or 5 is a decode failure (A.3.1).

### A.1.2 Alonzo, Babbage, Conway: `AlonzoTxWits`

All three eras use `AlonzoTxWits era` (`alonzo/TxWits.hs:476-477`, `babbage/TxWits.hs:27`,
`conway/TxWits.hs:25`). It is memoized (`alonzo/TxWits.hs:271`, `723-729`). The decoder is
`alonzo/TxWits.hs:620-721`. Below v12 it uses
`decode $ SparseKeyed "AlonzoTxWits" (pure emptyTxWitsRaw) txWitnessField []` (`624-628`). The
outer-map semantics are the same as A.1.1: D\|I, `decodeWord` keys, duplicates and unknown keys
are decode failures, no required keys, and `{}` is allowed. Keys handled: 0 to 7
(`668-693`). Key 8 and above hit `txWitnessField n = invalidField n` (`693`), a decode failure in
Alonzo, Babbage and Conway. (Key 8, Plutus V4, exists only on the v12 path, `651-666`.)

Per-key decoders. Babbage (v7) behaves exactly like Alonzo (v5), except that the era's Plutus
language support differs (A.4.1).

| key | content | Alonzo v5 / Babbage v7 | Conway v9 | cite |
|---|---|---|---|---|
| 0 | vkey witnesses | `Set.fromList <$> decodeList decCBOR`: D\|I, **no tag**, empty OK, duplicates collapsed | `addrWitsSetDecoder`: `allowTag 258`, then `Set.fromList . NE.toList <$> decodeNonEmptyList decCBOR`: D\|I, **non-empty**, duplicates **silently collapsed** | 669-677, 630-641 |
| 1 | native scripts (`Timelock`) | `mapTraverseableDecoderA (decodeList pairDecoder) Map.fromList`: D\|I, no tag, empty OK, keyed by hash | `allowTag 258`, `decodeNonEmptyList hashedNativeSciptDecoder`, `Map.fromList`: **non-empty**, duplicate hashes **silently collapsed** | 678, 704-720, 696-698 |
| 2 | bootstrap witnesses | as key 0 | as key 0 | 679-687 |
| 3 | Plutus V1 | `scriptDecoder`: `Map.fromList <$> decodeList (hashed script)`: D\|I, no tag, empty OK, equal hashes collapsed | `scriptDecoderV9`: `allowTag 258`, `decodeMapLikeEnforceNoDuplicates decodeListLenOrIndef`: D\|I, **duplicate hash → failure**, **empty → failure** ("Empty list of scripts is not allowed") | 688, 741-779 |
| 4 | datums (`TxDats`) | `mapTraverseableDecoderA (decodeList decCBOR) (TxDatsRaw . Map.fromElems hashData)`: D\|I, no tag, empty OK, equal hashes collapsed | `allowTag 258`, `decodeNonEmptyList decCBOR`, `Map.fromElems hashData`: **non-empty**, duplicates **silently collapsed** | 689, 344-363 |
| 5 | redeemers | list form only (A.2) | list or map form (A.2) | 690, 566-615 |
| 6 | Plutus V2 | as key 3, but each element passes through the era's `mkPlutusScript`. Alonzo: **any element → failure**, an **empty list is accepted**. Babbage: V2 accepted | as key 3 | 691, 695-702 |
| 7 | Plutus V3 | Alonzo and Babbage: **any element → failure**, **empty list accepted** | as key 3 | 692 |

Notes:

- **The tag 258 rule** comes from `allowTag` (`Decoder.hs:1347-1354`). The tag must equal 258 if
  present; any other tag is a decode failure. Any tag-header width encoding 258 is accepted
  (`bin/Plain.hs:190-196`). At v5 and v7 a tag in front of any witness list is a decode failure,
  because `decodeList` reads a list length straight away.
- **Duplicates at v9 differ by field.** Plutus script fields (3, 6, 7) reject duplicates.
  Vkey (0), bootstrap (2), native script (1) and datum (4) fields collapse them silently. Rejection
  for those four only arrives at v12 (`630-641`, `700-702`, `350`).
- **Plutus scripts are hashed as they are decoded.** `asHashedScriptPair` runs
  `hashScript @era` (`781-784`). The hash covers the language tag plus the payload bytes (A.4.3),
  so the same payload under two different language keys gives two different hashes.
- **Multiple script keys are merged** with `addScriptsTxWitsRaw` (left-biased `Map` union,
  `731-739`). Keys never collide across languages (the language tag is part of the hash) or
  between native and Plutus (prefix `0x00` versus `0x01`..`0x04`).
- **Language support** is checked only when an element is present. `mkPlutusScript` runs per
  decoded element (`695-702`). So `{6: []}` decodes in an Alonzo block, and `{7: []}` in Alonzo or
  Babbage. In Conway such an empty list fails because V9 requires non-empty.

### A.1.3 Memoized parts of the witness set and what they are used for

| item | memoized bytes | used for | cite |
|---|---|---|---|
| whole witness-set map | exact map bytes | tx-level `originalBytes`, size; block body hash uses the block-level slice | `alonzo/TxWits.hs:723-729`; `shelley/TxWits.hs:113-119` |
| each top-level native script (key 1; also aux data and reference scripts) | exact script array bytes | script hash = blake2b-224(`0x00` ‖ bytes) | `allegra/Scripts.hs:286-287`; `shelley/Scripts.hs:136-139`; `core/Core.hs:615-620` |
| nested native scripts (inside all/any/n-of) | **not memoized**: `MemoBytes t mempty def` | nothing (never hashed individually) | `shelley/Scripts.hs:287-289`; `allegra/Scripts.hs:289-291` |
| Plutus script | the payload of the CBOR byte string (`PlutusBinary`), not its header | script hash = blake2b-224(lang tag ‖ payload) | `core/Plutus/Language.hs:201-205`, `251-253` |
| each datum (`Data`) | exact data-item bytes | datum hash = blake2b-256(bytes) | `core/Plutus/Data.hs:109-123`, `257-258` |
| `TxDats` (key 4 value) | exact bytes of the whole key-4 value, **including** a tag 258 if present | script integrity hash (only if the datum map is non-empty) | `alonzo/TxWits.hs:369-379`; `alonzo/Tx.hs:444-448` |
| `Redeemers` (key 5 value) | exact bytes of the whole key-5 value | script integrity hash (always, even if empty) | `alonzo/TxWits.hs:183-189`; `alonzo/Tx.hs:444-448` |
| `WitVKey`, `BootstrapWitness` | not memoized | n/a | `core/Keys/WitVKey.hs:106-110`; `core/Keys/Bootstrap.hs:109-113` |

**Script integrity hash** (`alonzo/Tx.hs:430-471`). The hashed bytes are:

- `originalBytes redeemers`;
- then, only if the datum map is non-empty, `originalBytes txDats`;
- then a freshly serialized language-view encoding.

If key 5 is absent, `rdmrsTxWitsL` is `Redeemers mempty` built with `mkMemoizedEra`
(`alonzo/TxWits.hs:231-235`, `216`). That is a re-encoding at `eraProtVerLow`: the empty list
`0x80` below v9, an empty map at v9+ (`162-174`). If key 5 is present with an empty list (allowed
at v5 and v7), the **wire bytes** are used, and they may differ (for example `0x9f 0xff`).

### A.1.4 Set semantics of key 0 and key 2 (and what "duplicate" means)

- `WitVKey` `Ord` compares `(hash of vkey, hash of signature)` (`core/Keys/WitVKey.hs:71-81`).
  Two witnesses are "equal" only if both the key and the signature are identical. The same key
  with two different signatures keeps both entries, and both get verified.
- `BootstrapWitness` `Ord` compares **only** `bootstrapWitKeyHash`, the address root rebuilt from
  key, chain code and attributes (`core/Keys/Bootstrap.hs:115-116`, `158-192`). Two bootstrap
  witnesses with the same key, chain code and attributes but different signatures are collapsed
  into one before v12. `Set.fromList` keeps the **last** occurrence, because `Data.Set.insert`
  replaces an equal element. (containers semantics, not in `refs/`; verify.) Which signature
  survives decides whether the tx validates.
- From v12, duplicates in keys 0 and 2 are a decode failure
  (`decodeNonEmptySetLikeEnforceNoDuplicates`, `alonzo/TxWits.hs:637-640`).

### A.1.5 `WitVKey` (vkeywitness)

`decodeRecordNamed "WitVKey" (const 2) $ WitVKey <$> decCBOR <*> decCBOR`
(`core/Keys/WitVKey.hs:106-110`).

- Array: D(2) \| I with exactly 2 elements and a break.
- `VKey`: newtype-derived `VerKeyDSIGN Ed25519`, bytes of exactly 32
  (`core/Keys/Internal.hs:117-118`).
- Signature: `SignedDSIGN`, bytes of exactly 64 (`DecCBOR.hs:547-549`).
- Bytes are definite only below v12.

---

## A.2 Redeemers

Type: `Redeemers era = MkRedeemers (MemoBytes (RedeemersRaw era))`, where
`RedeemersRaw = Map (PlutusPurpose AsIx era) (Data era, ExUnits)` (`alonzo/TxWits.hs:149-151`,
`183-189`). The decoder is `alonzo/TxWits.hs:566-615`.

### A.2.1 Shape by version

| version | accepted shapes | cite |
|---|---|---|
| v5, v7 (Alonzo, Babbage) | **list only**: `decodeList decodeAnnElement`, D\|I. **Empty allowed.** A map is a decode failure (`decodeList` fails on a map header) | 579-582 |
| v9 (Conway) | `peekTokenType`: a D or I map header selects the map form, anything else the list form. List form is `decodeNonEmptyList` (D\|I, **non-empty**). Map form needs **at least 1 entry** ("Expected redeemers map to be non-empty") | 568-578, 588-597 |
| v12 | map form only; list → failure | 574-577 |

A tag in front of either form is a decode failure. At v9 a tag goes down the list path, and
`decodeListLenOrIndef` rejects it.

### A.2.2 List element `[tag, index, data, ex_units]`

`decodeRecordNamed "Redeemer" redeemerLen` where
`redeemerLen = listLenInt (Just ptr) + 2 = 2 + 2 = 4` (`605-613`). Rules:

- The array is D(4) \| I (4 items then a break).
- The purpose group is `decCBORGroup`, inlined: the tag is read with `decodeWord8` and the index
  with `AsIx Word32`, i.e. `decodeWord32` (`alonzo/Scripts.hs:283-285`, `399-413`).
- Data is `Annotator (Data era)` (A.5), memoized.
- `ExUnits`: see A.2.5.

### A.2.3 Map entry `{ [tag, index] => [data, ex_units] }`

From `588-595`:

- The map is D\|I (`decodeListLikeWithCount decodeMapLenOrIndef`).
- The key is `decCBOR @(PlutusPurpose AsIx era)`, which goes through `CBORGroup` → `groupRecord`
  → `decodeRecordNamed "CBORGroup" (const 2)`. So the key is D(2) \| I
  (`bin/Group.hs:27-35`; Conway deriving `conway/Scripts.hs:236-246`).
- The value is `decCBOR @(Annotator (Data era), ExUnits)`, a **2-tuple**. Below v12 that means
  `decodeListLenOf 2`, **definite only** (`DecCBOR.hs:297-313`). An indefinite `[data, ex_units]`
  value is a decode failure at v9. The list-form element, the map key and `ExUnits` itself may all
  be indefinite.

### A.2.4 Purpose tag ranges

- Alonzo and Babbage use `AlonzoPlutusPurpose`: 0 spend, 1 mint, 2 cert, 3 reward. Any other
  `Word8` → failure "Unexpected tag for AlonzoPlutusPurpose" (`alonzo/Scripts.hs:399-413`;
  Babbage `type PlutusPurpose f BabbageEra = AlonzoPlutusPurpose f BabbageEra`,
  `babbage/Scripts.hs:61`).
- Conway uses `ConwayPlutusPurpose`: 0 spend, 1 mint, 2 cert, 3 reward, 4 vote, 5 propose. Any
  other → failure (`conway/Scripts.hs:284-300`).
- Tag values above 255 fail inside `decodeWord8`. The index is a `Word32`.

Whether an index points at an existing input or certificate is **not** checked at decode time. That
is a rule-level check (missing or extra redeemers).

### A.2.5 `ExUnits`

`core/Plutus/ExUnits.hs:208-230`:

- Below v12: `RecD ExUnits <! D decNat <! D decNat`. `RecD` means
  `decodeRecordNamed "RecD" (const 2)` (`Coders.hs:482`), so D(2) \| I.
- At v12: explicit `decodeRecordNamed`, the same thing.
- Each field is `decCBOR @Word64` (major type 0 only; bignums and negatives fail), then must be
  `≤ maxBound :: Int64` (2^63−1), else failure "values must not exceed maxBound :: Int64"
  (`217-226`).
- The Haskell type is `Natural`.

### A.2.6 Duplicate redeemer keys

- **List form, every version:** `Map.fromList` → **last occurrence wins**, no error
  (`581`, `586-587`).
- **Map form (v9, and v12 too):** entries are collected in order (`decodeListLikeWithCount` with
  `(:)` and then `NE.reverse`), then `Map.fromList` → **last occurrence wins, no error**
  (`588-595`, `584-587`). The map-form decoder is not `decodeMap`, so the v9 no-duplicates rule of
  `decodeMap` does **not** apply.
- In both forms the memoized bytes, and so the script integrity hash, include every entry
  including the duplicates.

---

## A.3 Native scripts

### A.3.1 Shelley `MultiSig` (Shelley era only)

`instance DecCBOR (Annotator (MultiSigRaw era))` (`shelley/Scripts.hs:271-285`) is a
`decodeRecordSum "MultiSig"`. That means an array D\|I whose first element is a `decodeWord` tag,
with the length checked against the arm size when definite (`Decoder.hs:661-666`).

| tag | arm | size | fields |
|---|---|---|---|
| 0 | `MultiSigSignature` | 2 | `KeyHash`: bytes of exactly 28 |
| 1 | `MultiSigAllOf` | 2 | `decodeStrictSeq` (D\|I) of nested scripts |
| 2 | `MultiSigAnyOf` | 2 | same |
| 3 | `MultiSigMOf` | 3 | `decCBOR @Int` (signed 64-bit, **may be negative**: major 0 or 1 within `Int`), then nested seq |
| other | n/a | n/a | `invalidKey` → failure |

Notes:

- The top level is memoized via `Mem (MultiSigRaw era)` (`136-139`).
- Nested scripts are decoded with `decodeNoBytesMultiSig`, which stores **empty** memo bytes and
  hash `def` (`287-289`).
- Empty all/any/n-of lists are allowed.
- `Eq` and `Ord` on `MultiSig` compare the memo hash (`127-131`).

### A.3.2 Allegra+ `Timelock` (Allegra, Mary, Alonzo, Babbage, Conway)

`instance DecCBOR (Annotator (TimelockRaw era))` is `decode (Summands "TimelockRaw" decRaw)`
(`allegra/Scripts.hs:246-259`). `Summands` → `decodeRecordSum` (`Coders.hs:479`, `514`), so the
same D\|I and arm-size rules apply.

| tag | arm | size | fields |
|---|---|---|---|
| 0 | `TimelockSignature` | 2 | `KeyHash` (28 bytes) |
| 1 | `TimelockAllOf` | 2 | `decodeStrictSeq` (D\|I) of `decodeNoBytesTimelock` |
| 2 | `TimelockAnyOf` | 2 | same |
| 3 | `TimelockMOf` | 3 | `Int` (may be negative; the comment at `194-195` says a negative n is always true), then nested seq |
| 4 | `TimelockTimeStart` | 2 | `SlotNo`: `Word64` |
| 5 | `TimelockTimeExpire` | 2 | `SlotNo`: `Word64` |
| other | n/a | n/a | `Invalid n` → failure |

Arm sizes are computed by `hsize`/`decodeCount`: `SumD` contributes 1 for the tag and each field 1
(`Coders.hs:451-509`). Tags 0 to 3 are byte-compatible with `MultiSig` (comment `231-232`).

Memoization:

- The top level is `MkTimelock (MemoBytes ...)` through
  `DecCBOR (Annotator (Timelock era)) = fmap MkTimelock <$> decCBOR` (`286-287`), which uses the
  `Annotator (MemoBytes t)` instance and so records the exact bytes.
- Nested scripts get empty memo bytes and hash `def` (`289-291`).

**No nesting or recursion limit** exists in either decoder. Depth is bounded only by input size.
The script hash is `blake2b-224(0x00 ‖ memo bytes)`: `nativeMultiSigTag = "\00"`
(`shelley/Scripts.hs:143-144`, `159`); Alonzo+ native scripts use the same prefix
(`alonzo/Scripts.hs:574-580`); `hashScript` (`core/Core.hs:615-620`); `ADDRHASH` = Blake2b_224
(`core/Keys/Internal.hs:132`).

---

## A.4 Plutus scripts

### A.4.1 What is checked at decode time

- **Witness set keys 3, 6, 7** (`alonzo/TxWits.hs:688-692`, `741-779`).
  - Each element is `PlutusBinary` = `ShortByteString`, via `decodeByteArray`. Definite only below
    v12. Any length, including 0 (`core/Plutus/Language.hs:251-253`).
  - `decodePlutusScript slang` then calls `mkPlutusScript`, which accepts a language only if the
    **era** supports it (`alonzo/Scripts.hs:695-702`):
    - Alonzo: V1 only (`alonzo/Scripts.hs:608-613`);
    - Babbage: V1 and V2 (`babbage/Scripts.hs:63-69`);
    - Conway: V1 to V3 (`conway/Scripts.hs:98-105`).
  - Unsupported → failure "X isn't supported in the Y era" (`alonzo/Scripts.hs:775-778`).
  - The bytes themselves are **not** validated: no flat decoding, no CBOR-in-CBOR check.
- **Auxiliary data keys 2 to 5** (Alonzo+ tag-259 form, A.6.3).
  - `guardPlutus lang` runs **before** the list is decoded (`alonzo/TxAuxData.hs:283-287`,
    `296-299`). It gates on the **decoder version**: V1 needs v≥5, V2 v≥7, V3 v≥9, V4 v≥12
    (`core/Plutus/Language.hs:643-651`).
  - So at Babbage (v7), key 4 (V3) is a decode failure **even with an empty list**. At Conway,
    key 5 (V4) is a decode failure.
  - Elements are raw `PlutusBinary` (`[PlutusBinary]` via `decodeList`, D\|I, empty allowed and
    ignored by `addPlutusScripts`, `315-321`).
- **Reference scripts** (Babbage+ `script_ref`, A.5.5). The `AlonzoScript` decoder calls
  `decodePlutusScript` and therefore the era `mkPlutusScript` check
  (`alonzo/Scripts.hs:728-759`).

### A.4.2 Well-formedness checks are rules, not decode

- **Babbage and Conway witness scripts and reference scripts.** UTXOW `validateScriptsWellFormed`
  runs on every Plutus script in the witness map and every reference script in the outputs,
  including the collateral return (`babbage/Rules/Utxow.hs:249-290`, invoked at `394`; Conway
  reuses `babbageUtxowTransition`, `conway/Rules/Utxow.hs:209`).
  - Failure → `MalformedScriptWitnesses` or `MalformedReferenceScripts`. These are phase-1 rule
    failures.
  - It uses `isValidScript` (`alonzo/TxAuxData.hs:494-514`) → `isValidPlutusScript (pvMajor pv)`
    (`alonzo/Scripts.hs:278-279`), where `pv` is the **current protocol parameters'** version,
    not the decoder version.
- **Alonzo+ auxiliary-data scripts.** `validateAlonzoTxAuxData` runs `isValidScript` on every aux
  data script (`alonzo/TxAuxData.hs:363-373`), called from `validateMetadata`
  (`shelley/Rules/Utxow.hs:438-453`). Failure → `InvalidMetadata`. Native scripts are just forced
  (`deepseq`, `513-514`).
- **Alonzo witness scripts** have no well-formedness predicate. If a malformed script is
  executed, the decode error becomes a script failure (`core/Plutus/Evaluate.hs:163-172`), i.e. a
  phase-2 failure.
- **What "well-formed" means.** `decodePlutusRunnable` → plutus `deserialiseScript ll pv`
  (`core/Plutus/Language.hs:526-527`; `plutus-api/Common/SerialisedScript.hs:241-262`):
  - the ledger language must have been introduced by `pv`: V1 at Alonzo, V2 at Vasil, V3 at Chang,
    V4 at Dijkstra (`plutus-api/Common/Versions.hs:109-114`);
  - the payload must be a CBOR byte string wrapping flat-encoded UPLC;
  - builtins must be available at `(ll, pv)`;
  - constant type headers must be no larger than `maxHeaderSize`, and constr field counts no larger
    than `maxConstrFields` (`195-236`);
  - for V3 and later, **no trailing bytes** after the CBOR item. V1 and V2 tolerate a remainder
    (`258-260`).
  - The Plutus Core language version (1.0.0 versus 1.1.0) is checked at evaluation time
    (`plutus-api/Common/Eval.hs:128`).
- There is no function called `plutusScriptsDeserialisationCheck` in these sources. The
  equivalent is `validateScriptsWellFormed` above.

### A.4.3 Hashing

`hashScript` for an `AlonzoScript` is
`blake2b-224(scriptPrefixTag ‖ originalBytes)` (`core/Core.hs:615-620`):

- the prefix is `0x01`, `0x02`, `0x03` or `0x04` for V1 to V4 (`core/Plutus/Language.hs:525`,
  `545`, `565`, `586`; `alonzo/Scripts.hs:574-580`);
- `originalBytes` of a Plutus script is the `PlutusBinary` payload, the content of the CBOR byte
  string, not its header (`core/Plutus/Language.hs:261-262`, `201-205`).

At v12, where indefinite byte strings are allowed, the hash covers the concatenated chunk content.

---

## A.5 Plutus `Data`

### A.5.1 The ledger wrapper

- `newtype PlutusData era = PlutusData PV1.Data`. Its
  `DecCBOR (Annotator (PlutusData era)) = pure <$> fromPlainDecoder Cborg.decode`
  (`core/Plutus/Data.hs:94-101`), i.e. plutus-core's `Serialise Data` instance, which is **not
  version-gated**.
- `newtype Data era = MkData (MemoBytes (PlutusData era))` with `deriving via Mem`
  (`109-123`). Every `Data` (datum in key 4, redeemer data) is memoized with its exact bytes.
- `hashData` = `hashAnnotated` → blake2b-256 of the memo bytes (`257-258`, `127`).

### A.5.2 plutus-core `decodeData` (`plutus-core/Data.hs:209-307`)

Dispatch is on `peekTokenType` (`209-230`):

| first token | result | rule |
|---|---|---|
| major 0 or 1 (`TypeUInt`, `TypeUInt64`, `TypeNInt`, `TypeNInt64`) | `I` | `CBOR.decodeInteger`; full 64-bit range on either sign, so −2^64 .. 2^64−1 (`213-216`) |
| `TypeInteger` (bignum; header `0xc2` or `0xc3`, see 0.1) | `I` | `decodeBoundedBigInteger` (`232-245`): `decodeTag` must be 2 (unsigned big-endian) or 3 (`−1 − n`); payload is definite bytes ≤ 64, or indefinite bytes whose chunks are each definite ≤ 64. No limit on total length. Leading zeros and an empty payload (0 or −1) are accepted |
| definite bytes (`TypeBytes`) | `B` | `decodeBoundedBytes`: length must be ≤ 64, else "ByteString exceeds 64 bytes" (`261-266`) |
| indefinite bytes (`0x5f`) | `B` | `decodeBoundedBytesIndef`: every chunk definite and ≤ 64; any number of chunks; `0x5f 0xff` → empty (`248-259`) |
| array D or I | `List` | `decodeListOf` (`268-275`) |
| map D or I | `Map [(k,v)]` | arbitrary `Data` keys; **order and duplicates preserved** (`277-283`) |
| any other tag (`TypeTag`, `TypeTag64`) | `Constr` | `decodeConstr` (`286-307`) |
| text, simple, float, break, ... | n/a | "Unrecognized value of type ..." → failure (`230`) |

`decodeConstr` reads the tag with `decodeTag64`, so any header width is accepted:

- 121..127 → `Constr (t − 121)`, fields via `decodeListOf` (D\|I);
- 1280..1400 → `Constr (t − 1280 + 7)` (alternatives 7..127);
- 102 → an array of exactly two: D(2) \| I with a break after 2 (`298-307`). It holds
  `decodeWord64` (major 0 only) for the alternative, then the fields list (D\|I). Any alternative
  0..2^64−1 is allowed, including small ones that also have a 121.. or 1280.. form (a different
  encoding of the same value);
- any other tag → "Unrecognized tag" → failure. Under the 0.1 assumption, that includes tag 2 or 3
  written with a non-compact header.

There is **no depth limit** and no limit on list or map length beyond input size. The 64-byte limit
applies to every byte string leaf and bignum payload chunk, never to the total
(`plutus-core/Data.hs:88-143`).

### A.5.3 Datums in the witness set (key 4)

See A.1.2. Each element is `Annotator (Data era)` (memoized). Elements are keyed by
`hashData` (blake2b-256 of the element's exact bytes), last-wins on equal hashes (equal hash means
equal bytes).

### A.5.4 Datum option in Babbage+ outputs

`Datum` decoder (`core/Plutus/Data.hs:301-316`). Below v12: `Summands "Datum"`, so `decodeRecordSum`
D(2) \| I.

| tag | meaning | field |
|---|---|---|
| 0 | `DatumHash` | `DataHash`: 32 bytes |
| 1 | `Datum` | `BinaryData` |
| other | n/a | `Invalid k` → failure |

`NoDatum` has no encoding; it means the field is absent.

`BinaryData` (`218-237`):

- `decodeNestedCborBytes` = `decodeTag`, which must equal 24 (any header width), then
  `decodeBytes` (definite below v12) (`bin/Decoding.hs:213-217`, `238-240`).
- `makeBinaryData` then decodes the payload with
  `decodeFullAnnotator (eraProtVerLow @era) "PlutusData"`. Trailing bytes inside the payload are a
  decode failure (`DecoderErrorLeftover`, `bin/Decoding.hs:109-127`, `171-179`). The payload must
  be valid `Data` per A.5.2.
- The stored bytes are the **payload** (inside the tag-24 byte string). The datum hash is
  `blake2b-256(payload)` (`209-213`, `250-253`).

Context, from `babbage/TxOut.hs:555-676`: the map-form output carries the datum at key 2
(`662-665`). The legacy array form `[addr, value]` / `[addr, value, datum_hash]` carries only a hash
(`568-591`).

### A.5.5 Reference scripts (`script_ref`, key 3 of a Babbage+ map-form output)

`decodeCIC "Script"` (`babbage/TxOut.hs:778-785`):

- tag 24 plus bytes, then `decodeFullAnnotator` at the **current decoder version**, so trailing
  bytes are a failure;
- the inner value is `DecCBOR (Annotator (AlonzoScript era))` (`alonzo/Scripts.hs:728-759`): below
  v12 `Summands "AlonzoScript"`:
  - `[0, native_script]`;
  - `[1|2|3|4, bytes]` → `decodePlutusScript` (era language check);
  - other → failure;
  - D(2) \| I.
- A native reference script's memo bytes are the slice of the **inner** payload. Its hash is
  `blake2b-224(0x00 ‖ inner script bytes)`.

---

## A.6 Auxiliary data

### A.6.1 Shelley (v2)

`TxAuxData ShelleyEra = ShelleyTxAuxData`, memoized via `Mem` (`shelley/TxAuxData.hs:75-86`,
`88-89`). Raw `newtype ShelleyTxAuxDataRaw = Map Word64 Metadatum` with newtype-derived `DecCBOR`
(`52-56`, `65-68`), so it is `decodeMap decodeWord64 decodeMetadatum`:

- D\|I;
- labels `decodeWord64` (major 0, 0..2^64−1);
- **duplicate labels: last wins** at v2 (`Decoder.hs:812`);
- any other top-level shape (array, tag) is a decode failure.

`validateTxAuxData _ _ _ = True` (`shelley/TxAuxData.hs:97`). In the Shelley era there is **no**
byte or text size limit at decode time (`core/Metadata.hs:157` only checks when v > 2) and none at rule
time.

### A.6.2 Allegra, Mary (v3, v4)

`AllegraTxAuxData`, memoized (`allegra/TxAuxData.hs:133-145`; Mary reuses it,
`mary/TxAuxData.hs:28`). The decoder (`185-210`) dispatches on `peekTokenType`:

- **map** (D or I) → metadata only, scripts empty (`199-204`);
- **array** (D or I) → `RecD AllegraTxAuxDataRaw <*! metadata <*! scripts`, i.e.
  `decodeRecordNamed "RecD" (const 2)`: exactly two elements, D(2) \| I.
  - `metadata` is `Map Word64 Metadatum` (D\|I; duplicates last-wins at v3/v4).
  - `scripts` is `StrictSeq (Annotator (Timelock era))`: D\|I, any length, each script memoized
    (`205-210`).
- anything else, **including any tag** → failure "Failed to decode AuxiliaryDataRaw" (`197`).

Rule: `validateTxAuxData` only forces the scripts and returns `True` (`104`;
`mary/TxAuxData.hs:34`).

### A.6.3 Alonzo, Babbage, Conway (v5, v7, v9)

`AlonzoTxAuxData`, memoized (`alonzo/TxAuxData.hs:329-340`; Babbage and Conway reuse it:
`babbage/TxAuxData.hs:24`, `conway/TxAuxData.hs:24`). The decoder is `210-300` with
`decodeTxAuxDataByTokenType` (`302-313`). Below v12:

| first token | form | decoder | cite |
|---|---|---|---|
| map (D or I) | Shelley form | metadata only | 238-244 |
| array (D or I) | Allegra form | `RecD`: exactly `[metadata, native_scripts]` (D(2) \| I; scripts via `decodeStrictSeq`) | 245-252 |
| tag (`TypeTag` or `TypeTag64`) | Alonzo form | `TagD 259` (mandatory, must equal 259, any header width), then `SparseKeyed "AlonzoTxAuxData"` | 258-261 |
| anything else | n/a | failure "Failed to decode AlonzoTxAuxData" | 313 |

Alonzo-form keys (`auxDataField`, `290-300`). The map is D\|I, duplicate keys and unknown keys
(≥ 6) are decode failures, no key is required, and `259({})` is valid.

| key | content | decoder |
|---|---|---|
| 0 | metadata | `Map Word64 Metadatum` (`decodeMap`) |
| 1 | native scripts | `decodeStrictSeq` of memoized `Timelock` (D\|I, empty OK; appended) |
| 2 | Plutus V1 | `guardPlutus PlutusV1` (v≥5), then `[PlutusBinary]` (`decodeList`, D\|I, empty OK and ignored) |
| 3 | Plutus V2 | `guardPlutus PlutusV2` (v≥7); so **any key 3 in an Alonzo block fails** |
| 4 | Plutus V3 | `guardPlutus PlutusV3` (v≥9); **fails in Alonzo and Babbage** |
| 5 | Plutus V4 | `guardPlutus PlutusV4` (v≥12); **fails in Alonzo, Babbage and Conway** |

Duplicate metadata labels: last wins at v5 and v7; **decode failure at v9** (`decodeMap` v≥9,
`Decoder.hs:809-811`). This applies to all three forms because they all use `decodeMap`.

Rule: `validateAlonzoTxAuxData` checks every script for well-formedness (A.4.2); failure →
`InvalidMetadata`.

**Aux data hash:** `hashTxAuxData` = blake2b-256 of the memo bytes, i.e. the exact item bytes
(`shelley/TxAuxData.hs:107-108`; `alonzo/TxAuxData.hs:402-403`). The comparison with the body's
`auxiliary_data_hash` is a **rule** (`ConflictingMetadataHash`, `MissingTxMetadata`,
`MissingTxBodyMetadataHash`; `shelley/Rules/Utxow.hs:438-453`).

### A.6.4 `Metadatum` (`core/Metadata.hs:154-257`)

`checkSizes = v > 2` (`157`): size limits apply from Allegra on, never in Shelley.

| token | result | rule |
|---|---|---|
| major 0 or 1 (all widths) | `I` | `decodeInteger`; range −2^64 .. 2^64−1 (`162-165`) |
| bignum (`TypeInteger`) or any tag | n/a | **failure** "Unsupported token type" (`219`). Bignums are rejected even for in-range values |
| definite bytes | `B` | if `checkSizes`, length ≤ 64 else failure (`166-170`) |
| indefinite bytes | `B` | `decodeByteArrayIndefLen` (chunks definite), accepted **at every version**; the ≤ 64 check is on the **concatenated** length (`171-175`) |
| definite text | `S` | UTF-8 byte length ≤ 64 if `checkSizes` (`176-180`) |
| indefinite text | `S` | `decodeStringIndefLen`, accepted at every version; concatenated UTF-8 length ≤ 64 (`181-185`) |
| array D or I | `List` | recursive (`193-204`) |
| map D or I | `Map [(k,v)]` | any `Metadatum` keys, order kept, **duplicates kept** (`207-218`) |
| simple, float, bool, null, ... | n/a | failure (`219`) |

There is **no nesting limit**. All checks above are decode-time.

---

## A.7 Bootstrap witnesses (Shelley+)

`decodeRecordNamed "BootstrapWitness" (const 4)` (`core/Keys/Bootstrap.hs:109-113`): D(4) \| I.

| # | field | decoder |
|---|---|---|
| 1 | `bwKey :: VKey Witness` | 32 bytes exactly |
| 2 | `bwSignature` | 64 bytes exactly |
| 3 | `bwChainCode :: ChainCode` | `ByteArray`: definite bytes, **any length** below v12; exactly 32 only from v12 (`79-85`) |
| 4 | `bwAttributes :: ByteArray` | definite bytes, any length, **not parsed** (opaque; never decoded as Byron attributes) |

`bootstrapWitKeyHash` (`158-192`) is
`blake2b-224(sha3-256("\x83\x00\x82\x00\x58\x40" ‖ key ‖ chain_code ‖ attributes))`. The prefix
hard-codes a 64-byte length for key plus chain code. A wrong-length chain code still decodes below
v12 but produces a root that matches no address, so the result is a missing-witness **rule**
failure, not a decode failure.

Set ordering and duplicates: see A.1.4.

---

## A.8 v12 (Dijkstra) deltas in the same code (for orientation only)

Present in the code but outside Shelley to Conway:

- Witness sets use `decodeSparseKeyed`; key 8 is Plutus V4; keys 0, 2, 1 and 4 reject duplicates;
  `ChainCode` must be 32 bytes (`alonzo/TxWits.hs:627`, `651-666`; `core/Keys/Bootstrap.hs:82-84`).
- Redeemers must use the map form (`alonzo/TxWits.hs:574-577`).
- Aux data has a v12 `AlonzoScript` and Allegra-array decoder
  (`alonzo/TxAuxData.hs:219-232`, `253-257`).
- Byte and text strings may be indefinite everywhere `decodeBytes`/`decodeString` are used
  (`Decoder.hs:359-364`, `1564-1570`).
- Tuples may be indefinite (`DecCBOR.hs:297-303`).
- `decodeAnnSet` rejects duplicates (`Annotated.hs:237-249`).

---

# PART B: Byron (decoder version 1)

Every Byron decoder runs at `byronProtVer` = 1 with **no original bytes supplied**:
`toPlainDecoder Nothing byronProtVer` (`oc-byron/Ledger/Serialisation.hs:190-198`). Original bytes
are recovered from `ByteSpan` annotations (`annotatedDecoder`, `Annotated.hs:114-117`) and sliced
from the block bytes afterwards (`annotationBytes`, `Annotated.hs:125-126`).

## B.0 Container rules at v1 (summary)

| construct | required encoding | cite |
|---|---|---|
| `enforceSize n` (every record below) | definite, exactly n | `Decoder.hs:1362-1375` |
| `[a]` (`decodeList`) | **indefinite only** (`0x9f ... 0xff`) | `Decoder.hs:538-544`, `555-559` |
| `NonEmpty a` | indefinite only, ≥ 1 element | `Decoder.hs:546-552` |
| `Vector a` (per-tx witness list) | **definite only** | `Decoder.hs:1131-1137` |
| `Maybe a` | definite array of length 0 or 1 | `Decoder.hs:574-583` |
| `Map k v` (`decodeMap`; attributes, proposal metadata) | definite; keys **strictly increasing under the key's Haskell `Ord`** (no duplicates). For `Text` keys that is lexicographic, not RFC 7049 length-first | `Decoder.hs:727-757`, `814` |
| tuples (inside tag-24 payloads) | definite, exact length | `DecCBOR.hs:297-313` |
| byte and text strings | definite only | `Decoder.hs:359-364`, `1564-1570` |
| `dropList` | indefinite only | `bin/Decoding/Drop.hs:35-38` |
| `dropMap` | definite; **no** order or duplicate check | `Drop.hs:40-43` |
| `dropSet` | **any** tag value (`decodeTag`, not checked against 258), then a definite list | `Drop.hs:45-49` |
| `dropTriple` | definite, exactly 3 | `Drop.hs:57-62` |
| `dropBytes` | definite bytes, any length | `Drop.hs:28-29` |
| `dropInt32` | major 0 or 1, Int32 range | `Drop.hs:31-32` |

Where each applies:

- **Indefinite:** tx payload, tx inputs, tx outputs, delegation payload, update votes, EBB body,
  SSC inner lists.
- **Definite:** every `enforceSize` record, witness lists, attribute maps, SSC maps.

## B.1 Block envelope, blocks, annotations, header hash

### B.1.1 Envelope

`decCBORABlockOrBoundary` (`byron/Block/Block.hs:413-420`):

- `enforceSize "Block" 2`, then `decCBOR @Word` (`decodeWord`, so a non-minimal 0 or 1 is
  accepted);
- `0` → EBB (`decCBORABoundaryBlock`), `1` → main block (`decCBORABlock`), anything else →
  `DecoderErrorUnknownTag`.

The Cardano hard-fork combinator's on-disk block format uses the **same** two tags for Byron
(`[0, ebb]` / `[1, main]`), with Shelley from tag 2 on (`oc-cardano/Node.hs:181-190`). Consensus
re-encodes by prepending `0x82 0x00` or `0x82 0x01` to the annotation
(`oc-byron/Ledger/Serialisation.hs:172-187`, `303-306`).

### B.1.2 Main block

`decCBORABlock` (`byron/Block/Block.hs:326-335`):

```
[ header, body, extra ]      ; enforceSize 3 (definite)
extra = [ {} ]               ; enforceSize "ExtraBodyData" 1 >> dropEmptyAttributes
```

`dropEmptyAttributes` requires a **definite map of length 0**; anything else →
`DecoderErrorSizeMismatch` (`byron/Common/Attributes.hs:241-244`). The CDDL's `[attributes]` with
arbitrary entries is **rejected** unless empty.

The block annotation (`blockAnnotation`) is the byte span of the 3-array, **not** including the
`[1, ...]` envelope (`Block.hs:174-178`, `328`). `blockLength` is the length of that span
(`308-309`); the size limit is a rule (B.7).

### B.1.3 EBB

`decCBORABoundaryBlock` (`Block.hs:483-498`):

```
[ ebb_header, ebb_body, ebb_extra ]          ; enforceSize 3
ebb_body  = indefinite list of bytes          ; dropBoundaryBody = dropList dropBytes
ebb_extra = [ {* uint8 => bytes} ]            ; enforceSize 1 >> dropAttributes (definite map, any order)
```

- `dropBoundaryBody` and `dropBoundaryExtraBodyData` are at `byron/Block/Boundary.hs:73-83`.
- Body elements (CDDL `stakeholderid`) are **any-length** byte strings; the 28-byte size is not
  checked.
- `ABoundaryBody` keeps only an annotation covering body plus extra (`Block.hs:434-451`).
- `boundaryBlockLength` is the 3-array span length (`Block.hs:494`).

### B.1.4 Annotated (memoized) parts

| span | type and field | used for |
|---|---|---|
| main block 3-array | `blockAnnotation` | block size rule |
| header 5-array | `headerAnnotation` (`Header.hs:167`) | header hash, header size rule |
| each of: protocol magic, prev hash, proof, slot (`EpochAndSlotCount`), difficulty | `Annotated` fields (`Header.hs:150-161`) | signed bytes (B.4.7) |
| header extra-data 4-array | `headerExtraAnnotation` (`Header.hs:169`) | signed bytes |
| `[tx, witnesses]` pair | `ATxAux` annotation (`byron/UTxO/TxAux.hs:108-115`) | tx size rule |
| tx 3-array | `Annotated Tx` | Merkle leaf, signature data |
| witness list | `Annotated TxWitness` | witnesses hash |
| delegation payload (whole list) | `APayload` (`byron/Delegation/Payload.hs:77-80`) | delegation proof |
| each delegation certificate, and its epoch | `ACertificate` (`byron/Delegation/Certificate.hs:209-219`) | certificate id, certificate signature |
| update payload `[proposal?, votes]` | `APayload` (`byron/Update/Payload.hs:93-98`) | update proof |
| proposal, and its body (fields 1 to 5) | `AProposal` (`byron/Update/Proposal.hs:157-172`) | `UpId`, proposal signature |
| each vote, and its proposal id | `AVote` (`byron/Update/Vote.hs:199-209`) | vote id, vote signature |
| EBB header 5-array | `boundaryHeaderAnnotation` | EBB hash |
| EBB body plus extra | `ABoundaryBody` | nothing checked |
| EBB 3-array | `boundaryAnnotation` | EBB size rule |

The SSC payload is **not** annotated and is dropped.

### B.1.5 Header hashes

- **Main header:** `headerHashAnnotated = hashDecoded . fmap wrapHeaderBytes`, where
  `wrapHeaderBytes = ("\x82\x01" <>)`. The hash is
  `blake2b-256(0x82 0x01 ‖ header_5array_bytes)` (`byron/Block/Header.hs:489-500`). This is the
  hash of `[1, header]` as cardano-sl serialized it; `hashHeader` re-serializes the same structure
  (`406-408`, `496-497`), but consensus uses the annotated form: `mkByronHash` →
  `CC.abobHdrHash` (`oc-byron/Ledger/Block.hs:72-73`, `117-125`; `byron/Block/Block.hs:616-618`).
- **EBB header:** `boundaryHeaderHashAnnotated = hashDecoded . fmap wrapBoundaryBytes`, where
  `wrapBoundaryBytes = ("\x82\x00" <>)`. The hash is `blake2b-256(0x82 0x00 ‖ ebb_header_bytes)`
  (`Header.hs:539-540`, `633-634`). The chain's next `prevHash` after an EBB uses the same bytes
  (`byron/Block/Validation.hs:298-305`).
- `blake2b-256` is `Hash = AbstractHash Blake2b_256` (`byron-crypto/Hashing.hs:260-261`), and
  `hashDecoded` hashes the annotation bytes (`268-269`).

## B.2 Header

### B.2.1 Main header (`decCBORAHeader`, `byron/Block/Header.hs:351-390`)

```
[ protocol_magic, prev_hash, body_proof, consensus_data, extra_data ]     ; enforceSize "Header" 5
```

| field | decoder | notes |
|---|---|---|
| `protocol_magic` | `ProtocolMagicId` = newtype `Word32` → `decodeWord32` (`byron-crypto/ProtocolMagic.hs:58-62`), annotated | must equal the configured magic: **rule** (`byron/Block/Validation.hs:520-524`) |
| `prev_hash` | `HeaderHash` = `Hash Header`: definite bytes of exactly 32 (`byron-crypto/Hashing.hs:153-167`), annotated | |
| `body_proof` | `Proof`, annotated (B.2.3) | |
| `consensus_data` | `enforceSize "ConsensusData" 4` | below |
| `extra_data` | `decCBORBlockVersions`, annotated as `headerExtraAnnotation` (`392-395`) | below |

`consensus_data = [slot_id, genesis_key, difficulty, block_signature]`:

- `slot_id`: `EpochAndSlotCount` = `enforceSize 2`, `[Word64 epoch, Word64 slot]`
  (`byron/Slotting/EpochAndSlotCount.hs:65-68`), annotated. It is flattened with
  `toSlotNumber epochSlots`, which computes `epoch * epochSlots + slot` in `Word64`. There is **no
  check** that `slot < epochSlots` and no overflow check (`71-77`; `Header.hs:373`). The slot
  number therefore depends on decode-time configuration (`EpochSlots`); signed bytes use the
  original annotation.
- `genesis_key` (the "issuer pubkey" in the CDDL): `VerificationKey` = `decodeBytesCanonical`, so
  the **byte-string header must be minimal**, then `CC.xpub` requires exactly 64 bytes (32 key
  plus 32 chain code) (`byron-crypto/Signing/VerificationKey.hs:88-97`).
- `difficulty`: `ChainDifficulty` = `enforceSize 1`, `[Word64]` (`byron/Common/ChainDifficulty.hs:47-50`),
  annotated.
- `block_signature` (`Header.hs:691-700`):
  ```
  [ 2, [ delegation_certificate, signature ] ]    ; enforceSize 2, decCBOR @Word8 tag, enforceSize 2
  ```
  - **Only tag 2 is accepted.** Tags 0 (plain signature) and 1 (lightweight delegation) from the
    CDDL `blocksig` → `DecoderErrorUnknownTag`.
  - `delegation_certificate` is `ACertificate` (B.3.9).
  - `signature` is `Signature ToSign` = `decodeBytes` (definite), then `CC.xsignature`, which needs
    exactly 64 bytes (`byron-crypto/Signing/Signature.hs:129-143`).

`extra_data = [block_version, software_version, attributes, extra_proof]` (`Header.hs:392-395`):

- `block_version`: `ProtocolVersion` = `enforceSize 3`, `[Word16 major, Word16 minor, Word8 alt]`
  (`byron/Update/ProtocolVersion.hs:28-32`, `64-67`).
- `software_version`: `SoftwareVersion` = `enforceSize 2`, `[ApplicationName, Word32]`
  (`byron/Update/SoftwareVersion.hs:40`, `73-76`). `ApplicationName` is `Text` (definite, UTF-8)
  with **no length or ASCII check at decode** (`byron/Update/ApplicationName.hs:61-62`). The
  12-character and ASCII limits (`113-123`) are checked only in update-proposal registration
  (`byron/Update/Validation/Registration.hs:572`), never for header software versions.
- `attributes`: `dropEmptyAttributes`, so it **must be an empty definite map**.
- `extra_proof`: `dropBytes`, **any length**, never checked. cardano-sl wrote the hash of the empty
  extra-body-data encoding (`Header.hs:337`).

### B.2.2 EBB header (`decCBORABoundaryHeader`, `Header.hs:613-626`)

```
[ protocol_magic, prev_hash, body_proof, consensus_data, extra_data ]   ; enforceSize "BoundaryHeader" 5
```

| field | decoder |
|---|---|
| `protocol_magic` | `dropInt32`: major 0 or 1 in Int32 range, **value discarded** (not compared to the configuration) |
| `prev_hash` | `HeaderHash`, 32 bytes |
| `body_proof` | `dropBytes`: any length, **never verified** |
| `consensus_data` | `enforceSize 2`, `[Word64 epoch, ChainDifficulty [Word64]]` (`byron/Block/Boundary.hs:33-38`) |
| `extra_data` | `enforceSize 1`, then `decCBORAttributes` (canonical attribute map, B.3.8), looking for the "genesis tag" `255 => "Genesis"` (`Boundary.hs:61-67`) |

`prev_hash` is interpreted as the genesis hash (`Left`) if `epoch == 0` or the genesis tag is
present, otherwise as a header hash (`Header.hs:624`). Matching against the expected previous hash
is a rule (`byron/Block/Validation.hs:276-286`).

### B.2.3 Body proof (`Proof`, `byron/Block/Proof.hs:42-47`, `82-85`)

```
[ tx_proof, ssc_proof, dlg_proof, upd_proof ]       ; enforceSize "Proof" 4
tx_proof  = [ Word32 count, merkle_root(32), witnesses_hash(32) ]   ; enforceSize 3
ssc_proof = dropSscProof (dropped)
dlg_proof = Hash (32 bytes)
upd_proof = Hash (32 bytes)
```

- `tx_proof` is defined at `byron/UTxO/TxProof.hs:45-50` and decoded at `82-85`. `MerkleRoot` is
  `Hash Raw` (`byron/Common/Merkle.hs:65-67`, `88-89`).
- `ssc_proof` (`byron/Ssc.hs:164-188`): `decodeListLen` (definite), then a `Word8` tag:
  - 0, 1, 2 → length must be 3, then two `dropBytes` (any length);
  - 3 → length must be 2, then one `dropBytes`;
  - anything else → `DecoderErrorUnknownTag`.
  - The SSC proof is **never compared** to anything.

Validation of `tx_proof`, `dlg_proof` and `upd_proof` against the body is a **rule**
(`validateHeaderMatchesBody`, `byron/Block/Validation.hs:307-339`, applied in `updateBody`
`370-376`). See B.4 for the computations.

## B.3 Body

`decCBOR @(ABody ByteSpan)` (`byron/Block/Body.hs:81-88`):

```
[ tx_payload, ssc_payload, dlg_payload, upd_payload ]   ; enforceSize "Body" 4
```

### B.3.1 Tx payload

`ATxPayload <$> decCBOR @[ATxAux ByteSpan]` (`byron/UTxO/TxPayload.hs:70-71`): an **indefinite**
list (v1 `decodeList`). An empty `0x9f 0xff` is fine. Each element is (`byron/UTxO/TxAux.hs:108-115`):

```
[ tx, witnesses ]         ; enforceSize "TxAux" 2, both decCBORAnnotated
```

### B.3.2 Tx

`byron/UTxO/Tx.hs:55-60`, `110-113`:

```
[ inputs, outputs, attributes ]     ; enforceSize "Tx" 3
inputs     : NonEmpty TxIn   -> indefinite list, >= 1
outputs    : NonEmpty TxOut  -> indefinite list, >= 1
attributes : Attributes ()   -> canonical attribute map (B.3.8), every entry kept in attrRemain
```

### B.3.3 TxIn

`byron/UTxO/Tx.hs:140-143`, `171-177`:

```
[ 0, #6.24(bytes .cbor [txid, index]) ]     ; enforceSize "TxIn" 2, tag decCBOR @Word8
```

- **Only tag 0.** Any other tag → `DecoderErrorUnknownTag`. The CDDL's
  `[u8 .ne 0, encoded-cbor]` alternative is **rejected**.
- The payload is decoded by `decodeKnownCborDataItem` = `decodeNestedCbor`
  (`byron/Common/CBOR.hs:90-91`): tag 24 (any header width, must be 24), definite bytes, then
  `decodeFull'` at v1, so **all payload bytes must be consumed** (`bin/Decoding.hs:222-227`).
- Inner value: a **definite** 2-tuple `(TxId, Word16)`, where `TxId` is 32 bytes and the index is
  `decodeWord16`. **The index is a `Word16`; the CDDL says `u32`.** Values above 65535 are a
  decode failure.

### B.3.4 TxOut

`byron/UTxO/Tx.hs:216-219`:

```
[ address, lovelace ]       ; enforceSize "TxOut" 2
```

`Lovelace` = `decodeWord64`, then `mkLovelace`, which requires `≤ maxLovelaceVal = 45 * 10^15`,
otherwise **decode failure** (`byron/Common/Lovelace.hs:107-112`, `179-188`).

### B.3.5 Address

`byron/Common/Address.hs:172-180`, via `decodeCrcProtected` (`byron/Common/CBOR.hs:125-140`):

```
[ #6.24(bytes), crc32 ]                     ; enforceSize 2
```

1. The payload is `decodeUnknownCborDataItem` = tag 24 plus definite bytes (`CBOR.hs:97-98`).
2. `crc32` is `decCBOR @Word32`, so a non-minimal encoding is fine.
3. The CRC32 of the **payload bytes** must equal it, otherwise **decode failure** (`130-139`).
4. The payload is decoded with `decodeFull' byronProtVer`, so it must be fully consumed. It is a
   **definite** 3-tuple `(AddressHash Address', Attributes AddrAttributes, AddrType)`:
   - `addrRoot`: `AbstractHash Blake2b_224`, 28 bytes (`byron/Common/AddressHash.hs:14`).
   - `addrAttributes`: canonical attribute map (B.3.8) with known keys (`byron/Common/AddrAttributes.hs:121-145`):
     - key `1` (HD derivation payload): the value must fully decode (`decodeFull`) as
       `HDAddressPayload` = `decodeBytesCanonical`, a byte string with a **minimal header**
       (`178-179`);
     - key `2` (network magic): the value must fully decode as `decodeWord32Canonical`
       (`141-142`);
     - other keys are kept raw in `attrRemain`.
   - `addrType`: `decodeWord8Canonical`, accepting **only 0 (`ATVerKey`) or 2 (`ATRedeem`)**
     with a **minimal encoding** (`byron/Common/AddrSpendingData.hs:108-113`). Tag 1 and anything
     above 2 (allowed by the CDDL `u64 .gt 2`) → decode failure.

`Address'` (`134-138`) uses `decodeListLenCanonical`. It is used only to hash spending data, not to
decode on-chain addresses.

### B.3.6 Witnesses (`TxWitness = Vector TxInWitness`)

`byron/UTxO/TxWitness.hs:60`, `118-127`: a **definite** list (`decodeVector`) of:

```
[ 0, #6.24(bytes .cbor [vk, sig]) ]     ; VKWitness
[ 2, #6.24(bytes .cbor [redeem_vk, redeem_sig]) ]   ; RedeemWitness
```

- `decodeListLen` (definite), then the `Word8` tag; the length must be 2 for both arms.
- Any other tag (including 1, script witnesses, and the CDDL's `u8 .gt 2` "encoded-cbor") →
  `DecoderErrorUnknownTag`.
- The payload uses `decodeKnownCborDataItem`: full consumption, definite 2-tuple.
  - `vk` is `VerificationKey` (canonical header, 64 bytes); `sig` is `Signature` (64 bytes).
  - `redeem_vk` is `Ed25519.PublicKey` = bytes of exactly 32; `redeem_sig` is `Ed25519.Signature`
    = bytes of exactly 64 (`byron-crypto/Orphans.hs:89-92`, `111-114`;
    `byron-crypto/Signing/Redeem/VerificationKey.hs:67-69`;
    `byron-crypto/Signing/Redeem/Signature.hs:40-42`).
- An empty witness list is accepted at decode time.

### B.3.7 SSC payload (structure checked, content dropped)

`dropSscPayload` (`byron/Ssc.hs:76-95`): `decodeListLen` (definite), then a `Word8` tag:

| tag | length | contents |
|---|---|---|
| 0 | 3 | commitments, vss_certs |
| 1 | 3 | openings, vss_certs |
| 2 | 3 | shares, vss_certs |
| 3 | 2 | vss_certs |
| other | n/a | `DecoderErrorUnknownTag` |

Sub-structures, with what the decoder actually requires:

```
commitments = dropSet signed_commitment           ; ANY tag, then definite list   (194-195)
signed_commitment = [bytes, commitment, bytes]    ; definite 3                    (197-198)
commitment = [ {definite map: bytes => (INDEFINITE list of bytes)}, secret_proof ]  ; enforceSize 2 (200-205)
secret_proof = [bytes, bytes, bytes, INDEFINITE list of bytes]   ; enforceSize 4  (207-217)
openings = definite map bytes => bytes                                             (223-224)
shares = definite map bytes => (definite map bytes => INDEFINITE list of bytes)    (230-234)
vss_certs = dropSet vss_cert                                                       (240-241)
vss_cert = [bytes, Word64, bytes, bytes]           ; enforceSize 4                 (243-253)
```

Where the CDDL disagrees with this:

- `vssenc = [bytes]`, "a length 1 array": the decoder needs an **indefinite** list of bytes.
- `sscshares` values `[addressid, [* vssdec]]`: the decoder needs a **definite map**
  `bytes => indefinite list`.
- `ssccert = [vsspubkey, pubkey, epochid, signature]`: the decoder needs
  `[bytes, Word64, bytes, bytes]` (comments in the code: vss key, epoch, signature, verification
  key).
- `#6.258(...)`: any tag value is accepted.

Byte strings here may be any length.

### B.3.8 Attributes (`Attributes h`, `byron/Common/Attributes.hs`)

- `decCBORAttributes` (`213-235`) first decodes `Map Word8 LBS.ByteString`. At v1 that is
  `decodeMapSkel`: a **definite map**, `Word8` keys **strictly increasing**, definite byte-string
  values (`Decoder.hs:727-757`). Out-of-order or duplicate keys → `DecoderErrorCanonicityViolation`.
- Each entry is offered to the type's updater. Known keys are parsed and removed. **Unknown keys
  stay as raw bytes in `attrRemain :: UnparsedFields`** (`60-64`, `80-86`).
- `Attributes ()` (tx attributes) treats every key as unknown (`129-130`).
- `dropAttributes` (EBB extra body data) is a definite map with **no ordering or duplicate check**
  (`237-238`).
- `dropEmptyAttributes` requires length 0 (`241-244`).
- Size limits are **rules**:
  - tx attributes: `unknownAttributesLength < 128` (`byron/UTxO/Validation.hs:249-251`);
  - address attributes: the same limit (`288-290`).
  - Only the **value** lengths are summed (`Attributes.hs:140-142`).

### B.3.9 Delegation payload and certificates

`byron/Delegation/Payload.hs:77-80`: an annotated **indefinite** list of `ACertificate`
(`byron/Delegation/Certificate.hs:93-103`, `209-219`):

```
[ epoch, issuer_vk, delegate_vk, signature ]     ; enforceSize 4
epoch: Word64 (annotated); *_vk: VerificationKey (canonical header, 64 bytes); signature: 64 bytes
```

The same `ACertificate` appears inside the block signature (B.2.1). Certificate signature
verification (`isValid`, `164-177`) is a **rule**. It signs
`serialize("00" ‖ delegate_xpub ‖ epoch_annotation_bytes)`; the "00" is two ASCII `0x30` bytes.

### B.3.10 Update payload

`byron/Update/Payload.hs:93-98`:

```
[ proposal, votes ]                    ; enforceSize "Update.Payload" 2 (annotated)
proposal : Maybe AProposal  -> definite array of length 0 or 1
votes    : [AVote]          -> INDEFINITE list
```

Proposal (`byron/Update/Proposal.hs:157-172`) has 7 fields, with fields 1 to 5 annotated together
as the "body":

```
[ protocol_version, pp_update, software_version, metadata, attributes, from_vk, signature ]  ; enforceSize 7
```

- `protocol_version`: as B.2.1.
- `pp_update` (`byron/Update/ProtocolParametersUpdate.hs:135-151`): `enforceSize 14`, each field a
  `Maybe` (definite `[]` or `[x]`), in order:
  1. `Word16` script version;
  2. `Natural` slot duration;
  3. `Natural` max block size;
  4. `Natural` max header size;
  5. `Natural` max tx size;
  6. `Natural` max proposal size;
  7. to 10. `LovelacePortion` × 4 (`Word64` ≤ 10^15, else **decode failure**;
     `byron/Common/LovelacePortion.hs:78-83`, `103-104`);
  11. `SlotNumber` (`Word64`);
  12. `SoftforkRule` (`enforceSize 3`, three `LovelacePortion`; `byron/Update/SoftforkRule.hs:77-80`);
  13. `TxFeePolicy`;
  14. `EpochNumber` (`Word64`).
  - `Natural` = `decodeInteger ≥ 0`; bignums are allowed.
  - `TxFeePolicy` (`byron/Common/TxFeePolicy.hs:93-98`) is `enforceSize 2`, tag `Word8`, **only
    0** → `#6.24(bytes .cbor TxSizeLinear)` (full consumption). Other tags → failure.
  - `TxSizeLinear` (`byron/Common/TxSizeLinear.hs:70-80`) is `enforceSize 2` with two `Nano`
    values (`Fixed E9` over `Integer`, `DecCBOR.hs:214`). The first is
    `round`-converted to `Word64` (Haskell `fromInteger` wraps modulo 2^64), then `mkLovelace`
    (≤ 45·10^15, else failure). The second becomes a `Rational`.
- `software_version`: as B.2.1; no app-name check at decode.
- `metadata`: `Map SystemTag InstallerHash`, a canonical definite map with `Text` keys strictly
  increasing under Haskell `Text` order. `SystemTag` length (≤ 10) and ASCII are checked only at
  registration (`byron/Update/SystemTag.hs:64-68`, `113-116`;
  `byron/Update/Validation/Registration.hs:561`).
  `InstallerHash` (`byron/Update/InstallerHash.hs:58-64`) is `enforceSize 4` =
  `[dropBytes, Hash(32), dropBytes, dropBytes]`. Only the 2nd element has a size check; the CDDL's
  `[hash, hash, hash, hash]` is stricter than the code.
- `attributes`: must be empty (`dropEmptyAttributes`).
- `from_vk`: `VerificationKey`; `signature`: 64 bytes.

Vote (`byron/Update/Vote.hs:199-209`):

```
[ voter_vk, proposal_id(32, annotated), bool, signature ]   ; enforceSize "Vote" 4
```

The `bool` is decoded and **discarded**, so `false` is accepted. The signed bytes hard-code `True`
(`215-227`).

## B.4 Byron hashes and signed bytes

1. **TxId (as used for UTxO keys).** `txOutputUTxO` uses `txId = serializeCborHash`
   (`byron/UTxO/UTxO.hs:176-188`). That is `blake2b-256` of the **re-serialization** of the decoded
   `Tx` at v1 (`byron-crypto/Hashing.hs:212-213`, `264-265`), **not** of the wire bytes. The
   re-encoding (`byron/UTxO/Tx.hs:102-107`) is:
   - `[inputs, outputs, attributes]` with a definite 3-array header;
   - inputs and outputs as **indefinite** lists (`bin/Encoding/Encoder.hs:499-508`);
   - each `TxIn` as `[0, #6.24(serialize (txid, idx))]`;
   - each `TxOut` as `[address, lovelace]`;
   - the address re-encoded through `encodeCrcProtected` with a **recomputed** CRC and
     re-serialized attributes (`byron/Common/Address.hs:157-163`;
     `byron/Common/AddrAttributes.hs` `EncCBOR`);
   - attributes re-encoded as a definite sorted map;
   - all integers and lengths minimal.

   The wire hash and the UTxO txid agree only when the tx was canonically encoded. An exact
   implementation must compute the UTxO txid by re-encoding. The alternative is to prove that every
   Byron tx on the target chain is canonical.

   urd does both cheaply. The decoder accepts only the shapes this encoder produces, and the
   parsed address attributes must already be canonical. So the re-encoding differs from the wire
   bytes exactly when some head is non-minimal, including inside the tag-24 payloads of inputs and
   addresses. When every head is minimal, urd hashes the wire bytes; otherwise it re-encodes
   (`ledger/byron/tx.odin`).

2. **Tx signature data.** `recoverSigData` = `hashDecoded` of the **annotated (wire) tx bytes**
   (`byron/UTxO/TxWitness.hs:136-140`). The signed payload is `serialize'` of that hash. Witness
   verification is a rule (`byron/UTxO/Validation.hs:298-325`).

3. **Merkle root of txs** (`byron/UTxO/TxProof.hs:99-105`, `byron/Common/Merkle.hs`). Built over
   the **wire** tx bytes:
   - leaf: `blake2b-256(0x00 ‖ tx_bytes)` (`227-233`);
   - inner node: `blake2b-256(0x01 ‖ left ‖ right)` (`94-100`);
   - empty tree: `blake2b-256("")` (`102-103`);
   - split: for n leaves, the left subtree takes the largest power of two **strictly less than** n
     (n/2 when n is a power of two) (`150-162`, `169-...`).

   `txpNumber` = the number of txs as `Word32`.

4. **Witnesses hash:** `blake2b-256(0x9f ‖ concat(each tx's witness-list bytes) ‖ 0xff)`
   (`byron/UTxO/TxPayload.hs:82-92`, `byron/UTxO/TxProof.hs:104`).

5. **Delegation proof:** `blake2b-256(delegation payload bytes)` (the whole indefinite list as
   received) (`byron/Block/Validation.hs:316-318`).
   **Update proof:** `blake2b-256(update payload bytes)` (`326-328`;
   `byron/Update/Proof.hs:17-18`).
   **SSC proof:** not computed, not checked.
   **EBB body proof:** not computed, not checked (B.2.2).

6. **Ids:**
   - `CertificateId` = `hashDecoded` certificate (`byron/Delegation/Certificate.hs:156-157`);
   - `UpId` = `hashDecoded` proposal (`byron/Update/Proposal.hs:125-126`);
   - `VoteId` = `hashDecoded` vote (`byron/Update/Vote.hs:168-169`).

   All are over the wire bytes.

7. **Signed bytes, all reconstructed from annotations:**
   - Block: `0x85 ‖ prev_hash ‖ proof ‖ slot ‖ difficulty ‖ extra_data` (`byron/Block/Header.hs:707-722`),
     verified by consensus PBFT (`oc-byron/Ledger/PBFT.hs:69-72`).
   - Proposal: `0x85 ‖ body_fields_1..5` (`byron/Update/Proposal.hs:257-259`).
   - Vote: `0x82 ‖ proposal_id_bytes ‖ 0xf5` (`byron/Update/Vote.hs:215-227`).

## B.5 Byron decode-time size checks (complete list in the block path)

| item | check |
|---|---|
| every `Hash`/`AbstractHash` | exact digest length: 32, or 28 for `AddressHash` (`byron-crypto/Hashing.hs:153-167`) |
| `VerificationKey` | canonical bytes header, 64 bytes |
| `Signature` | 64 bytes |
| redeem key / signature | 32 / 64 bytes |
| `Lovelace` | ≤ 45·10^15 |
| `LovelacePortion` | ≤ 10^15 |
| `TxIn` index | `Word16` |
| address CRC32 | must match |
| `AddrType` | ∈ {0, 2}, canonical |
| address attribute 1 / 2 | canonical inner encodings, full consumption |
| non-empty inputs and outputs | `NonEmpty` |
| main-block extra, header attributes, proposal attributes | empty |
| attribute maps | strictly ordered `Word8` keys |
| every `enforceSize` / tag dispatch | exact |

No checks: EBB body element sizes, SSC byte strings, `extra_proof`, EBB body proof,
`InstallerHash` fields 1/3/4, `ApplicationName`/`SystemTag` content, the vote bool, slot-in-epoch
bounds.

## B.6 Byron leniencies and CDDL discrepancies (implementer checklist)

1. **Non-minimal encodings are accepted** for integers, lengths, tags and byte-string headers
   (cborg non-canonical decoders), **except** at these canonical points:
   - `VerificationKey` bytes header (`byron-crypto/Signing/VerificationKey.hs:97`);
   - `HDAddressPayload` bytes header (`byron/Common/AddrAttributes.hs:179`);
   - network-magic attribute `Word32` (`142`);
   - `AddrType` `Word8` (`byron/Common/AddrSpendingData.hs:110`).

   Hashes and signatures use the original bytes via annotations, with the TxId exception in B.4.1.
2. **Unknown attributes are kept as raw bytes** (`UnparsedFields`) in tx attributes, address
   attributes and the EBB extra header data, as long as the map is canonically ordered. The
   < 128-byte limit on unknown attributes is a **rule**.
3. **Unknown sum tags are rejected, not preserved.** This holds for `TxIn` (only 0), `TxInWitness`
   (0, 2), `AddrType` (0, 2), `TxFeePolicy` (0), `BlockSignature` (2), SSC (0..3) and the envelope
   (0, 1). The CDDL "encoded-cbor" fallbacks do not exist in the decoder.
4. **Definite versus indefinite is strict.** See B.0. For example, a definite tx-input list, a
   definite tx payload or an indefinite witness list is a decode failure.
5. **The CDDL is wrong about:**
   - the TxIn index (`u32` → `Word16`);
   - `blocksig` variants 0 and 1 (rejected);
   - `addrtype .gt 2` (rejected);
   - `twit` tag 1 (rejected);
   - `[attributes]` in the main block extra (must be `[{}]`);
   - `blockheadex` attributes (must be empty);
   - `upprop.attributes` (must be empty);
   - SSC `vssenc`, `sscshares` and `ssccert` (B.3.7);
   - `updata` (only the 2nd element is size-checked).
6. **`dropSet` accepts any tag value**, not just 258 (`Drop.hs:47`).
7. **The vote decision bit is ignored.**
8. **Rule-level, not decode:**
   - The witness/input pairing uses `zip addresses witnesses`
     (`byron/UTxO/Validation.hs:386-390`), so **extra witnesses are ignored and missing witnesses
     are not detected**. With fewer witnesses than inputs, the unmatched inputs are never checked
     by this function.
   - Protocol magic, header size (`464-466`), block size (`370-372`), EBB size ≤ 2,000,000 bytes
     (`290-291`), proofs, delegation and update validity, tx size and fee
     (`byron/UTxO/Validation.hs:183-235`), and the network magic of output addresses (`281-295`)
     are all rules.
9. **The SSC proof and EBB body proof are never verified.** The header `extra_proof` is never
   verified.

## B.7 Byron rule-time checks that consume decoded fields (for completeness)

| check | cite |
|---|---|
| header size ≤ `ppMaxHeaderSize` | `byron/Block/Validation.hs:464-466` |
| block size ≤ `ppMaxBlockSize` | `byron/Block/Validation.hs:370-372` |
| EBB size ≤ 2·10^6 | `byron/Block/Validation.hs:290-291` |
| protocol magic equal to configuration | `byron/Block/Validation.hs:520-524` |
| body proofs | `byron/Block/Validation.hs:307-339` |
| tx size ≤ `ppMaxTxSize` (size of the `[tx, witnesses]` bytes) | `byron/UTxO/Validation.hs:190-193`, `225` |
| unknown attribute size < 128 | `byron/UTxO/Validation.hs:249-251`, `288-290` |
| witness signature and key/address match | `byron/UTxO/Validation.hs:298-325` |

---

## C. Ambiguities and items to verify outside `refs/`

1. **cborg token typing of bignums.** Whether `TypeInteger` is returned only for the one-byte
   headers `0xc2`/`0xc3` (assumed) or also for wider tag-2/3 headers. This affects Plutus `Data`
   (A.5.2) and metadata (A.6.4: either way, bignums are rejected in metadata).
2. **cborg `decodeString` and invalid UTF-8.** Assumed to be a decode failure.
3. **`Data.Set.fromList` duplicate retention** (last-wins), which matters for bootstrap witnesses
   with equal key hashes (A.1.4). This comes from `containers`, not vendored.
4. **Byron TxId re-serialization** (B.4.1). The code is unambiguous. It is listed here because it
   differs from the "hash of wire bytes" intuition and from the Merkle and signature hashes.
   Whether any mainnet Byron tx is non-canonical, and so would expose the difference, has been
   checked only for epochs 0 to 2: all 14,515 transactions there are canonical.
5. **`TxSizeLinear` `round` to `Word64`** wraps on negative or huge values before the `mkLovelace`
   bound (B.3.10). This is standard Haskell `fromInteger` behaviour; it only matters for update
   proposals.
