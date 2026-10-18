# Rules reference: the Byron UTxO ledger

This is an implementer's reference for the Byron-era UTxO rules that cardano-node applies to the
transactions of a Byron main block: input lookup, witness verification, size and fee limits,
balances, attribute and network-magic checks, and the UTxO state transition. Every rule cites
the Haskell code it comes from. Where the executable or formal spec disagrees, this document
follows the implementation (§8 lists the differences).

Decoding is out of scope. It is covered in `docs/decoding/witnesses-auxdata-byron.md` (cited
below as **[dec]**, for example [dec B.4.1]). This document assumes a fully decoded block that
keeps the original byte spans that [dec B.1.4] lists.

Sources (pinned clones under `refs/`):

| repo | commit |
|---|---|
| cardano-ledger | `178bd36` |
| ouroboros-consensus | `9b918f8` |
| cardano-crypto | `ac2e12a` |
| crypton | `d5fb2cb` (1.1.5) |
| cardano-node | `4d3ad24` |

Path abbreviations used in citations:

| abbreviation | path under `refs/` |
|---|---|
| `byron/` | `cardano-ledger/eras/byron/ledger/impl/src/Cardano/Chain/` |
| `byron-crypto/` | `cardano-ledger/eras/byron/crypto/src/Cardano/Crypto/` |
| `byron-spec/` | `cardano-ledger/eras/byron/ledger/executable-spec/src/Byron/Spec/Ledger/` |
| `byron-fspec/` | `cardano-ledger/eras/byron/ledger/formal-spec/` |
| `bin/` | `cardano-ledger/libs/cardano-ledger-binary/src/Cardano/Ledger/Binary/` |
| `shelley/` | `cardano-ledger/eras/shelley/impl/src/Cardano/Ledger/Shelley/` |
| `oc-byron/` | `ouroboros-consensus/ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/` |
| `cardano-crypto/` | `cardano-crypto/` |
| `crypton/` | `crypton/` |
| `node/` | `cardano-node/` |

Conventions:

- `Lovelace` is a `Word64` newtype whose constructors keep it ≤ `maxLovelaceVal` =
  45·10^15 = `45000000000000000` (`byron/Common/Lovelace.hs:81-83`, `179-188`). That is below
  2^56, so any sum of two Lovelace values fits in a `u64`.
- `H256` is blake2b-256 (`Hash = AbstractHash Blake2b_256`, `byron-crypto/Hashing.hs:260-261`).
  `H224` is blake2b-224 and `SHA3` is sha3-256 (`byron/Common/AddressHash.hs:14-25`). All three
  come from crypton's `Crypto.Hash`.
- `CBOR(x)` means the encoding `serialize' byronProtVer x`: definite arrays and maps, minimal
  heads, lists as **indefinite** arrays (`bin/Encoding/Encoder.hs:397-407`, `499-508`).
- "Wire bytes" means the exact bytes received inside the block, as recovered from annotations.
  "Re-encoded" means `CBOR(decoded value)`. The two differ only when the wire form used a
  non-minimal head, which the decoders accept ([dec B.6 item 1]).

---

## 0. The rules most likely to be implemented wrong

1. **Witnesses are paired with inputs positionally by `zip`, with no count check**
   (`byron/UTxO/Validation.hs:387-390`). Input *i* is checked against witness *i* for
   *i* < min(#inputs, #witnesses). If there are fewer witnesses than inputs, the remaining
   inputs are spent with **no authorization at all**. An empty witness list authorizes every
   input. If there are more witnesses than inputs, the extra witnesses are **never verified**,
   not even their signatures.
2. **The signed message** is `tag ‖ P ‖ 0x58 0x20 ‖ H256(tx wire bytes)`, where tag is `0x01`
   (VK) or `0x02` (redeem). P is the **configured** protocol magic re-encoded as a minimal CBOR
   unsigned integer, not the header's bytes (§5.1).
3. **The address root** is `H224(SHA3(CBOR([t, [t, key], attrs])))`. Here t is 0 (VK) or 2
   (redeem), key is the 64-byte XPub or 32-byte redeem key, and attrs is the **canonical
   re-encoding** of the spent address's attributes (§5.3).
4. **The tx size** is the byte length of the wire `[tx, witnesses]` 2-array, and the comparison
   is `size ≤ ppMaxTxSize` (inclusive).
5. **minFee** = `a + ⌈b·size⌉`, computed with exact rational arithmetic, with the result bounded
   by 45·10^15. It is **0** when every distinct spent output sits at a redeem address. The
   check is `minFee ≤ fee`, with no upper bound on the fee.
6. **Duplicate inputs within one tx are accepted.** The spent value is counted once, but every
   listed position still consumes a witness position.
7. **Zero-value outputs are accepted.** The formal spec forbids them; the implementation does
   not check.
8. **Fees are not tracked anywhere** in the Byron state. They are burned and reappear as
   reserves at the Shelley translation (§6.4).
9. **Each output** must have unknown address-attribute bytes < 128 and a network magic equal to
   `makeNetworkMagic`. The tx's own attribute bytes must also be < 128. Inputs' addresses are
   never network-checked.
10. **The asset-lock set is always empty** in cardano-node, so `validateTxIn` never rejects an
    input that the earlier lookup already found.
11. **VK and redeem witnesses both end in crypton's `crypton_ed25519_sign_open`.** VK
    witnesses pass in the first 32 bytes of the XPub; the chain code is ignored by the
    signature check but bound by the address root.

---

## 1. Call path, validation modes, environment

### 1.1 How a block's transactions reach the UTxO rules

```
oc-byron/Ledger/Ledger.hs:376-401   applyByronBlock (ValidateAll | ValidateSuchThat -> BlockValidation,
                                                     ValidateNone -> NoBlockValidation)
oc-byron/Ledger/Ledger.hs:402-411   applyABlock -> CC.validateBlock
byron/Byron/API/Validation.hs:153-179  validateBlock: validateHeader (header size), then
                                        validateBody -> updateBody with mkBodyEnvironment (69-89)
byron/Block/Validation.hs:362-398   updateBody  -> UTxO.updateUTxO utxoEnv utxo txs   (384-386)
byron/UTxO/Validation.hs:407-413    updateUTxO = foldM updateUTxOTxWitness
```

`updateBlock` (`byron/Block/Validation.hs:513-562`) is **not** on this path. It compares the
header's protocol magic and builds the signing magic from the header's annotation bytes
(`535-538`). Consensus uses `validateBlock`, which takes the magic from the configuration
(§1.3).

### 1.2 Validation modes

`fromBlockValidationMode` maps `BlockValidation` to `TxValidation` and `NoBlockValidation` to
`NoTxValidation` (`byron/Block/ValidationMode.hs:24-26`; `byron/ValidationMode.hs:35-40`).

| caller | block mode | tx mode | what runs in `updateUTxOTxWitness` |
|---|---|---|---|
| new block (`ValidateAll`) | `BlockValidation` | `TxValidation` | everything (§3) |
| block re-application (`ValidateNone`) | `NoBlockValidation` | `NoTxValidation` | nothing but the state update; the overlap check in `union` still runs |
| mempool `applyTx` (`oc-byron/Ledger/Mempool.hs:129-133`) | `BlockValidation` | `TxValidation` | everything |
| mempool `reapplyTx` (`135-138`) | `NoBlockValidation` | `TxValidationNoCrypto` | only `validateTx` (steps D1 to D3) and the update. The input lookup, the witnesses **and `validateTxAux` (size and fee)** are skipped |

`whenTxValidation` runs its action only in `TxValidation`. `unlessNoTxValidation` runs in
`TxValidation` and `TxValidationNoCrypto` (`byron/ValidationMode.hs:79-94`). For block
validation, urd only needs `TxValidation`.

Mempool-only rule: consensus rejects a Byron mempool tx whose bytes are not canonical
(`txInvariant`, `oc-byron/Ledger/Mempool.hs:120-125`, `333-346`). **Blocks have no such
rule.** Non-canonical txs inside blocks are accepted.

### 1.3 The UTxO `Environment`

`Environment {protocolMagic, protocolParameters, utxoConfiguration}`
(`byron/UTxO/Validation.hs:325-329`) is built in `updateBody` (`byron/Block/Validation.hs:428-433`)
from the `BodyEnvironment` that `mkBodyEnvironment` returns (`byron/Byron/API/Validation.hs:69-89`):

| field | value on the consensus path | cite |
|---|---|---|
| `protocolMagic :: AProtocolMagic ByteString` | `reAnnotateMagic (configProtocolMagic cfg)`. The id is the genesis `protocolMagic` (`Word32`), annotated with `serialize' byronProtVer pm`: a **minimal CBOR uint**. `getRequiresNetworkMagic` comes from the node config's `RequiresNetworkMagic` | `byron/Byron/API/Common.hs:78-82`; `bin/Decoding/Annotated.hs:129-130`; `byron/Genesis/Config.hs:106-110` |
| `protocolParameters` | `adoptedProtocolParameters` of the **ticked** update state: after this slot's epoch transition, and **before** this block's own update payload is registered (`updateBody` registers it after the UTxO, `389-391`) | `byron/Block/Validation.hs:431`; `byron/Byron/API/Validation.hs:107-124` |
| `utxoConfiguration` | `defaultUTxOConfiguration`, i.e. `tcAssetLockedSrcAddrs = ∅`. cardano-node never sets anything else | `node/cardano-node/src/Cardano/Node/Protocol/Byron.hs:96-101`; `byron/Genesis/Config.hs:158`; `byron/UTxO/UTxOConfiguration.hs:52-56` |

`RequiresNetworkMagic` defaults to `RequiresNoMagic` when the key is absent
(`node/cardano-node/src/Cardano/Node/Configuration/POM.hs:596-597`). Mainnet sets
`RequiresNoMagic` (`node/configuration/cardano/mainnet-config.yaml:22`). Testnet templates set
`RequiresMagic` (`node/configuration/cardano/testnet-template-config.json:27`).

Mainnet genesis values (`node/configuration/cardano/mainnet-byron-genesis.json`): protocol
magic 764824073, `maxTxSize` 4096, and `txFeePolicy` with summand `155381000000000` and
multiplier `43946000000` (both in units of 10^-9 lovelace). That gives a = 155381 lovelace and
b = 43946/1000 = 21973/500. These are initial values only; always read the adopted parameters.

---

## 2. Block-level application

`updateBody` (`byron/Block/Validation.hs:368-398`) runs these steps in order. Each failure
rejects the block.

1. `blockLength ≤ ppMaxBlockSize` (`370-372`).
2. Body proofs: tx count, Merkle root, witnesses hash, delegation hash, update hash (`375-376`;
   [dec B.4]).
3. Delegation certificates (`379-381`).
4. **UTxO**: `updateUTxO utxoEnv utxo txs` with `txs = aUnTxPayload (blockTxPayload b)`
   (`384-386`, `417`).
5. Update payload (`389-391`).

`updateUTxO env utxo = foldM (updateUTxOTxWitness env) utxo` (`byron/UTxO/Validation.hs:407-413`):

- Transactions are applied **sequentially in payload order**. Tx *k* is validated against the
  state left by txs 0..k-1, so:
  - a tx may spend outputs created by an **earlier** tx of the same block;
  - spending an output of a later tx fails `UTxOMissingInput`;
  - two txs spending the same output: the second fails `UTxOMissingInput` (§3.1). There is no
    other cross-tx double-spend check.
- The first failing tx aborts the block. The error is wrapped as
  `ChainValidationUTxOValidationError` (`386`).
- Nothing else in the UTxO step looks at the payload as a whole: no fee totals, no tx-count
  limit (the count is a `Word32` in the proof), no per-block size budget beyond step 1.
- An empty tx payload is valid and leaves the UTxO unchanged.
- **EBBs carry no transactions.** `validateBoundary` never touches the UTxO
  (`byron/Byron/API/Validation.hs:184-200`).
- The state holds no fee pot: `ChainValidationState` is
  `{cvsLastSlot, cvsPreviousHash, cvsUtxo, cvsUpdateState, cvsDelegationState}`
  (`byron/Block/Validation.hs:138-146`).

---

## 3. Per-transaction pipeline (`TxValidation`)

`updateUTxOTxWitness` (`byron/UTxO/Validation.hs:373-404`), then `updateUTxOTx` (`359-370`).
Everything runs in an `Either`-like monad, so evaluation is in the order below and **stops at
the first failure**. For accept/reject equivalence only the set of checks matters. The order
fixes which error is reported.

Notation: `ins` is the input list in wire order (with duplicates), `outs` is the output list,
`wits` is the witness vector in wire order, and `U` is the UTxO before this tx.

| step | check | failure | cite |
|---|---|---|---|
| A | for each `i` in `ins` (in order): `i ∈ dom U`; collect `addr_i` = address of `U[i]` | `UTxOValidationUTxOError (UTxOMissingInput i)` | `382-384`; `byron/UTxO/UTxO.hs:145-149` |
| B | for each `(addr_j, w_j)` in `zip [addr_i] wits` (in order): B1 signature, then B2 key/address match (§5) | `TxValidationWitnessWrongSignature w pm sigData` / `TxValidationWitnessWrongKey w addr` | `387-390`, `298-323` |
| C1 | `size ≤ ppMaxTxSize` | `TxValidationTxTooLarge size max` | `191-193`, `221`, `224-225` |
| C2 | `minFee` = 0 if redeem exemption (§3.5), else `calculateTxSizeLinear` (§3.4) | `TxValidationLovelaceError "Minimum Fee" e` | `196-199`, `229-234` |
| C3 | `balanceOut = Σ outs` ≤ 45·10^15 | `TxValidationLovelaceError "Output Balance" (LovelaceTooLarge s)` | `202-204` |
| C4 | `balanceIn = Σ U[set(ins)]` ≤ 45·10^15 | `TxValidationLovelaceError "Input Balance" (LovelaceTooLarge s)` | `207-209` |
| C5 | `fee = balanceIn − balanceOut`, requires `balanceIn ≥ balanceOut` | `TxValidationLovelaceError "Fee" (LovelaceUnderflow in out)` | `212-214` |
| C6 | `minFee ≤ fee` | `TxValidationFeeTooSmall tx minFee fee` | `217` |
| D1 | `unknownAttributesLength(txAttributes) < 128` | `TxValidationUnknownAttributes` | `249-251` |
| D2 | for each output (in order): unknown address-attribute bytes `< 128`, then `nm == addrNetworkMagic addr` | `TxValidationUnknownAddressAttributes` / `TxValidationNetworkMagicMismatch nm addrNm` | `254-255`, `281-295` |
| D3 | for each `i` in `ins`: `validateTxIn` (asset lock, §3.9) | `TxValidationMissingInput i` | `258`, `263-278` |
| E | `U' = (U ⋪ set(ins)) ∪ txOutputUTxO tx` with no key overlap | `UTxOValidationUTxOError UTxOOverlappingUnion` | `369-370`; `byron/UTxO/UTxO.hs:151-155` |

Steps A to C are skipped when the tx mode is not `TxValidation` (`380`). Step D is skipped only
in `NoTxValidation` (`366`). Errors from A and E are wrapped as `UTxOValidationUTxOError`;
errors from B, C and D as `UTxOValidationTxValidationError` (`384`, `390`, `394`, `367`, `370`).

### 3.1 Input lookup (A)

- `lookupAddress` is a plain `Map` lookup on `CompactTxIn` = (32-byte TxId, `Word16` index)
  (`byron/UTxO/UTxO.hs:145-149`; `byron/UTxO/Compact.hs:105-107`). Every occurrence of a
  duplicated input is looked up, and all of them succeed if the first does.
- All lookups finish before any witness is checked (`mapM`, then `mapM_`).
- The address returned is the **decoded spent output's address**. It went through the compact
  form: `fromCompactAddress` decodes the re-encoded bytes (`byron/Common/Compact.hs:60-64`).
  Its root, type and attributes are unchanged by the round trip.

### 3.2 Witness pairing (B)

```
addresses = [ address(U[i]) | i <- ins ]          -- length n_in, duplicates kept
pairs     = zip addresses (toList wits)           -- length min(n_in, n_wit)
for (addr, w) in pairs: validateWitness pm sigData addr w
```

`byron/UTxO/Validation.hs:382-390`. Consequences, all accepted by cardano-node:

- `n_wit < n_in`: inputs `n_wit .. n_in-1` have **no** witness check (this includes
  `n_wit = 0`).
- `n_wit > n_in`: witnesses `n_in .. n_wit-1` are decoded but never verified.
- Witness *j* must match input *j*'s address even when input *j* duplicates an earlier input.
- The witness kind (VK or redeem) is not tied to the input's position other than through the
  address check (B2).

No other count check exists, in the ledger or in consensus. The witness vector is used
elsewhere only for the body proof's witnesses hash ([dec B.4.4]).

### 3.3 Transaction size (C1)

- `txSize = BS.length txBytes`, where `txBytes` is the `ATxAux` annotation
  (`byron/UTxO/Validation.hs:189`, `224-225`). That annotation is the **wire** span of the whole
  `[tx, witnesses]` 2-array, including its `0x82` head (`byron/UTxO/TxAux.hs:108-115`).
- `maxTxSize = ppMaxTxSize` (`Natural`, `byron/Update/ProtocolParameters.hs:47`).
- The check is `txSize ≤ maxTxSize` (inclusive). Failing reports
  `TxValidationTxTooLarge txSize maxTxSize`.
- The same `txSize` feeds the minimum fee.
- Update registration enforces `maxTxSize < maxBlockSize` (strict) for proposed parameters
  (`byron/Update/Validation/Registration.hs:521-523`).

### 3.4 Minimum fee (C2): `calculateTxSizeLinear`

`TxFeePolicy` has a single constructor, `TxFeePolicyTxSizeLinear (TxSizeLinear a b)`, with
`a :: Lovelace` and `b :: Rational` (`byron/Common/TxFeePolicy.hs:68-71`;
`byron/Common/TxSizeLinear.hs:46-48`).

```haskell
calculateTxSizeLinear (TxSizeLinear a b) sz =
  addLovelace a =<< flip scaleLovelaceRationalUp b <$> integerToLovelace (fromIntegral sz)
```

`byron/Common/TxSizeLinear.hs:81-86`. Step by step (§4 has the primitives):

1. `s = integerToLovelace sz`. This fails with `LovelaceTooLarge` if `sz > 45·10^15`, which
   cannot happen for real byte lengths.
2. `m = scaleLovelaceRationalUp s b = Lovelace (fromInteger (ceiling (toRational s * b)))`
   (`byron/Common/Lovelace.hs:246-248`). `ceiling` is exact over `Rational`. `fromInteger` to
   `Word64` **wraps modulo 2^64** and is **not bound-checked**.
3. `addLovelace a m`: `res = a + m` with `Word64` wrap-around. It succeeds iff
   `res ≥ a ∧ res ≥ m ∧ res ≤ 45·10^15`; otherwise it fails with `LovelaceOverflow res`
   (`216-222`).

Equivalent closed form. This is exact because `a ≤ 45·10^15` and `m < 2^64`; the three
conditions in step 3 reduce to the integer inequality below.

```
c      = ceiling(sz * b)                 -- exact, Integer (may be negative if b < 0)
m      = c mod 2^64                      -- two's-complement wrap
minFee = a + m        if a + m ≤ 45·10^15 (as an integer)
error  LovelaceError "Minimum Fee" (LovelaceOverflow ((a + m) mod 2^64))   otherwise
```

- For `b = n/d ≥ 0` (reduced fraction, `d > 0`), `c = (sz·n + d − 1) div d`.
- **Mainnet genesis:** `minFee = 155381 + ⌈sz · 21973/500⌉ = 155381 + (21973·sz + 499) div 500`.
- Any negative `c` wraps to a value above 45·10^15 and so always fails.
- `b` comes from `Nano` (`Fixed E9` over `Integer`, bignums allowed): `b = n_nano / 10^9`
  reduced, from CBOR (`byron/Common/TxSizeLinear.hs:73-74`) or from genesis JSON
  (`multiplier % 1e9`, `byron/Common/TxFeePolicy.hs:119-123`).
- `a` is `round` (CBOR, `TxSizeLinear.hs:73`) or `div 1e9` (JSON, `TxFeePolicy.hs:112-118`) of
  the nano value. Nothing in update registration constrains the fee policy, so a negative or
  huge `b` could only arrive through an adopted update proposal.

### 3.5 Redeem fee exemption

```haskell
inputUTxO    = S.fromList (NE.toList (txInputs tx)) <| utxo         -- Validation.hs:227
isRedeemUTxO = all (isRedeemAddress . txOutAddress . fromCompactTxOut) . M.elems . unUTxO
isRedeemAddress addr = addrType addr == ATRedeem                     -- Address.hs:340-343
```

`byron/UTxO/UTxO.hs:190-194`; `byron/UTxO/Validation.hs:196-199`.

- The exemption applies iff **every distinct spent output** has `addrType = ATRedeem` (wire
  value 2). Then `minFee = 0`. With any non-redeem input, the full fee applies.
- Only the spent addresses' **type** matters. The witness kinds, the outputs and the tx size
  are irrelevant, although the size limit (C1) still applies.
- `all` over an empty map is `True`, but `inputUTxO` cannot be empty after step A
  (inputs are `NonEmpty` and all exist).
- With minFee 0, C6 always passes once C5 succeeds, so a redeem tx may have fee 0.

### 3.6 Balances and fee (C3 to C6)

- `balance u = sumLovelace (values of u)`: the sum is taken as an **Integer**, then must be
  ≤ 45·10^15, else `LovelaceTooLarge sum` (`byron/UTxO/UTxO.hs:160-164`;
  `byron/Common/Lovelace.hs:207-209`, `260-266`).
- `balanceOut` is computed over `txOutputUTxO tx` (§6.2). It includes every output, zeros
  included, up to index 65535.
- `balanceIn` is computed over `inputUTxO` (§3.5), so **a duplicated input is counted once**.
- `fee = subLovelace balanceIn balanceOut`. If `balanceIn < balanceOut`, the error is
  `LovelaceUnderflow balanceIn balanceOut`, reported as the `"Fee"` error and **not** as
  `FeeTooSmall` (`byron/Common/Lovelace.hs:225-228`).
- Then `minFee ≤ fee`, compared as `Word64`. The fee has no upper bound.
- Order: output balance first, then input balance (`202-209`).

Implementation note: the values are each ≤ 45·10^15, but a `u64` running sum can wrap after
about 410 maximal outputs. Stop as soon as the partial sum exceeds 45·10^15. This is equivalent
because all values are non-negative.

### 3.7 Transaction attributes (D1)

- `txAttributes :: Attributes ()`. Every key is unknown, so every entry stays in `attrRemain`
  (`byron/Common/Attributes.hs:129-130`).
- `unknownAttributesLength = Σ LBS.length v` over the `attrRemain` values
  (`byron/Common/Attributes.hs:140-142`). That is the byte lengths of the value **contents**:
  no CBOR heads and no keys.
- The rule is `unknownAttributesLength < 128` (strict, so at most 127). Otherwise
  `TxValidationUnknownAttributes` (`byron/UTxO/Validation.hs:249-251`).

### 3.8 Output addresses: unknown attributes and network magic (D2)

For each output in order (`byron/UTxO/Validation.hs:281-295`):

1. `unknownAttributesLength (addrAttributes addr) < 128`, else
   `TxValidationUnknownAddressAttributes`. Address attribute keys 1 (HD payload) and 2
   (network magic) are parsed and removed from `attrRemain`. Every other key, including 0,
   counts (`byron/Common/AddrAttributes.hs:121-143`). **The HD payload is not size-limited**
   by this rule.
2. `nm == addrNetworkMagic addr`, else `TxValidationNetworkMagicMismatch nm addrNm`
   (expected first).
   - `nm = makeNetworkMagic protocolMagic`: `RequiresNoMagic` gives `NetworkMainOrStage`, and
     `RequiresMagic` gives `NetworkTestnet pm` (`byron/Common/NetworkMagic.hs:80-83`).
   - `addrNetworkMagic` is `NetworkTestnet w` if attribute key 2 is present (its value
     contents must decode canonically and fully as a `Word32`, at decode time), and
     `NetworkMainOrStage` otherwise (`byron/Common/AddrAttributes.hs:124-142`;
     `byron/Common/Address.hs:332-333`).
   - Effect: on mainnet (`RequiresNoMagic`) **no output may carry key 2**. On `RequiresMagic`
     networks every output must carry key 2 with the value equal to the protocol magic. For
     example, magic 1 means value contents `01`; magic 1097911063 means `1a 41 70 cb 17`.
   - Equality is structural on `Word32` (`byron/Common/NetworkMagic.hs:42-45`).

Only outputs are checked. **Spent addresses (inputs) are never network-checked**, and neither
are addresses in the genesis UTxO.

### 3.9 `validateTxIn` and asset-locked addresses (D3)

```haskell
validateTxIn UTxOConfiguration{tcAssetLockedSrcAddrs} utxo txIn
  | S.null tcAssetLockedSrcAddrs, txIn `member` utxo                 = ok
  | Just (CompactTxOut a _) <- lookupCompact txIn utxo, a `notMember` tcAssetLockedSrcAddrs = ok
  | otherwise = throwError (TxValidationMissingInput txIn)
```

`byron/UTxO/Validation.hs:263-278`.

- With the empty set (cardano-node, §1.3) this is a membership test that step A already passed.
  It never fails in `TxValidation`.
- With a non-empty set, the comparison is on `CompactAddress` bytes: the **re-encoded** address
  (`byron/Common/Compact.hs:56-58`), matched against `toCompactAddress` of each configured
  address (`byron/UTxO/UTxOConfiguration.hs:58-62`).

### 3.10 State update (E)

```haskell
UTxO.union (S.fromList (NE.toList (txInputs tx)) </| utxo) (txOutputUTxO tx)
```

- `</|` is `Map.withoutKeys` (`byron/UTxO/UTxO.hs:171-174`). Each distinct input is removed
  once.
- `union` is `Map.union`, then a check that `size(result) == size(left) + size(right)`, else
  `UTxOOverlappingUnion` (`151-155`).
- An overlap needs a new `(txId, ix)` that is already unspent, i.e. a TxId collision with a
  live entry. A byte-identical (or canonically identical) earlier tx would fail step A first.
  This is unreachable in practice, but implement it: it is the only check that still runs in
  `NoTxValidation`.

---

## 4. Lovelace arithmetic reference

All in `byron/Common/Lovelace.hs`.

| function | exact semantics | lines |
|---|---|---|
| `mkLovelace w` | `w ≤ 45·10^15` → ok, else `LovelaceTooLarge (toInteger w)` | 184-188 |
| `integerToLovelace n` | `n < 0` → `LovelaceTooSmall n`; `n ≤ 45·10^15` → ok; else `LovelaceTooLarge n` | 260-266 |
| `sumLovelace xs` | `integerToLovelace (Σ toInteger x)` (no intermediate overflow) | 207-209 |
| `addLovelace a b` | `r = a + b mod 2^64`; ok iff `r ≥ a ∧ r ≥ b ∧ r ≤ 45·10^15`, else `LovelaceOverflow r` | 216-222 |
| `subLovelace a b` | `a ≥ b` → `a − b`, else `LovelaceUnderflow a b` | 225-228 |
| `scaleLovelaceRationalUp a q` | `Lovelace (fromInteger (ceiling (toRational a * q)))`: wraps mod 2^64, **no bound check** | 246-248 |
| `mkKnownLovelace @0` | the constant 0 (redeem exemption) | 192-193 |

`LovelaceError` constructors and their CBOR tags: `LovelaceOverflow Word64` (0),
`LovelaceTooLarge Integer` (1), `LovelaceTooSmall Integer` (2),
`LovelaceUnderflow Word64 Word64` (3) (`120-125`, `155-164`).

---

## 5. Witness verification, byte-exact

`validateWitness pmi sigData addr w` (`byron/UTxO/Validation.hs:298-323`):

| witness | B1 (first) | B2 (second) |
|---|---|---|
| `VKWitness vk sig` | `verifySignatureDecoded pmi SignTx vk sigData sig` | `checkVerKeyAddress vk addr` |
| `RedeemWitness rvk sig` | `verifyRedeemSigDecoded pmi SignRedeemTx rvk sigData sig` | `checkRedeemAddress rvk addr` |

### 5.1 The signed message

```
msg = tag ‖ P ‖ 0x58 0x20 ‖ H256(tx_wire)          (length 1 + |P| + 34)
```

| part | bytes | source |
|---|---|---|
| `tag` | `0x01` for `SignTx` (VK), `0x02` for `SignRedeemTx` (redeem) | `signTagRaw`, `byron-crypto/Signing/Tag.hs:71-75` |
| `P` | the annotation of the protocol-magic id (`signTagDecoded = signTagRaw . annotation`, `Tag.hs:63-64`). On the consensus path that is `serialize' byronProtVer (pm :: Word32)`, the minimal CBOR uint (§1.3) | `byron/Byron/API/Common.hs:78-82` |
| `0x58 0x20 ‖ H` | `recoverBytes sigData`, where `sigData = recoverSigData aTx` is annotated with `serialize' byronProtVer txHash`. A `Hash` encodes as a definite 32-byte byte string (`encCBOR (AbstractHash h) = encCBOR h`, a `ShortByteString`) | `byron/UTxO/TxWitness.hs:136-140`; `byron-crypto/Hashing.hs:147-148`; `bin/Encoding/EncCBOR.hs:295-297` |
| `H` | `hashDecoded aTx`: **blake2b-256 of the tx's wire bytes**, the annotated `[inputs, outputs, attributes]` 3-array exactly as received. This is not the re-encoded TxId (§6.2) | `byron-crypto/Hashing.hs:268-269`; `byron/UTxO/Validation.hs:402-404` |

`P` values for known networks:

| network | magic | `P` |
|---|---|---|
| mainnet | 764824073 | `1a 2d 96 4a 09` |
| preprod | 1 | `01` |
| preview | 2 | `02` |
| old cardano-sl testnet (fixture `byron7.block`) | 1097911063 | `1a 41 70 cb 17` |

The `TxSigData` golden `testdata/byron/golden/utxo/TxSigData` is `5820 ‖ 32 bytes`, which
matches. Every one of the 59 VK witnesses in the repository's Byron fixtures (13 txs in
`testdata/byron/dingo/mainnet-byron-4471207.cbor` and `testdata/blocks/pallas/byron{2,4,5,6,7}.block`)
verifies against this message, using an independent RFC 8032 check (§9).

### 5.2 Which bytes go to which C function

**VK witness.** `VerificationKey` wraps `CC.XPub` = 32-byte Ed25519 public key ‖ 32-byte chain
code (decoded from exactly 64 bytes, `cardano-crypto/src/Cardano/Crypto/Wallet.hs:78-81`,
`144-149`). The call path:

```
byron-crypto/Signing/Signature.hs:216-225   verifySignatureDecoded: msg = signTagDecoded pm tag <> recoverBytes x
byron-crypto/Signing/Signature.hs:228-233   verifySignatureRaw (VerificationKey k) x (Signature sig) = CC.verify k x sig
cardano-crypto/src/Cardano/Crypto/Wallet.hs:197-201
    verify (XPub point _) ba (XSignature signature) =
      Ed25519.verify (throwCryptoError (Ed25519.publicKey point)) ba (throwCryptoError (Ed25519.signature signature))
    -- Ed25519 = crypton's Crypto.PubKey.Ed25519 (Wallet.hs:58; cardano-crypto.cabal: crypton ^>= 1.1)
crypton/Crypto/PubKey/Ed25519.hs:64-69      publicKey: length == 32 only (no point validation)
crypton/Crypto/PubKey/Ed25519.hs:88-93      signature: length == 64 only
crypton/Crypto/PubKey/Ed25519.hs:135-143    verify = (crypton_ed25519_sign_open msg msgLen pub sig == 0)
crypton/cbits/ed25519/ed25519.c:88-110      int crypton_ed25519_sign_open(m, mlen, pk, RS)   (ED25519_FN prefix "crypton_", :8)
```

- `pk` = the **first 32 bytes** of the 64-byte XPub. The chain code is dropped.
- `m` = `msg` from §5.1, unhashed. Donna computes `SHA-512(R ‖ pk ‖ m)` itself (`ed25519_hram`,
  `ed25519.c:29-36`).
- `RS` = the 64 signature bytes.
- Result 0 means valid; anything else means `TxValidationWitnessWrongSignature`.
- The `throwCryptoError` calls cannot fire, because decoding already guarantees 32 and 64 bytes
  ([dec B.3.6]).
- Not involved: cardano-crypto's own donna copy (prefix `cardano_crypto_`,
  `cardano-crypto/cbits/ed25519/ed25519.c:8`, used only by `Crypto.ECC.Ed25519Donna`) and
  `cardano-crypto/cbits/encrypted_sign.c` (signing and derivation only, no verify entry
  point).

**Redeem witness.** `RedeemVerificationKey` wraps a crypton `Ed25519.PublicKey` (32 bytes);
`RedeemSignature` wraps a 64-byte `Ed25519.Signature`
(`byron-crypto/Signing/Redeem/VerificationKey.hs:67-68`; `Redeem/Signature.hs:40-42`).

```
byron-crypto/Signing/Redeem/Signature.hs:86-95    verifyRedeemSigDecoded: msg = signTagDecoded pm tag <> recoverBytes x
byron-crypto/Signing/Redeem/Signature.hs:98-104   verifyRedeemSigRaw (RedeemVerificationKey k) x (RedeemSignature s) = Ed25519.verify k x s
crypton/Crypto/PubKey/Ed25519.hs:135-143          -> crypton_ed25519_sign_open   (same C function)
```

`pk` is the 32-byte redeem key as decoded; `m` is `msg` with tag `0x02`.

Both witness kinds therefore have identical acceptance semantics, namely those of
`crypton_ed25519_sign_open` (analysed separately). They differ only in the tag byte and in
where the 32-byte key comes from.

### 5.3 Recomputing the address root (B2)

```haskell
checkAddrSpendingData asd addr =
  addrRoot addr == addressHash (Address' (addrType addr, asd, addrAttributes addr))
    && addrType addr == addrSpendingDataToType asd
```

`byron/Common/Address.hs:306-321`, with `addressHash = abstractHashFromDigest . blake2b_224 .
sha3_256 . serialize byronProtVer` (`byron/Common/AddressHash.hs:16-25`).

`addr` is the **spent output's** address (§3.1). `asd` is `VerKeyASD vk` or `RedeemASD rvk`.

Byte layout of `CBOR(Address')`, a 3-tuple encoded as a definite array
(`byron/Common/Address.hs:119-123`; `bin/Encoding/EncCBOR.hs:231-232`):

```
0x83
  uint(t)                        t = addrType addr: 0x00 (ATVerKey) or 0x02 (ATRedeem)   (AddrSpendingData.hs:102-106)
  0x82 uint(t') bytes(key)       AddrSpendingData: t' = 0 VerKeyASD / 2 RedeemASD        (AddrSpendingData.hs:67-71)
                                   VerKeyASD : 0x58 0x40 ‖ xpub(64) = pk(32) ‖ chaincode(32)
                                   RedeemASD : 0x58 0x20 ‖ key(32)
  ATTRS                          canonical re-encoding of addrAttributes addr (below)
root = H224(SHA3(bytes above))   -- 28 bytes, compared with addrRoot (28 bytes)
```

`ATTRS` comes from `encCBOR (Attributes AddrAttributes)` (`byron/Common/AddrAttributes.hs:89-119`;
`byron/Common/Attributes.hs:192-211`). Build a `Map Word8 ByteString` from:

- the decoded unknown entries (`attrRemain`), whose values are the raw value contents exactly as
  decoded;
- key **1**, if `aaVKDerivationPath = Just p`, with value `CBOR(HDAddressPayload p)` = a
  definite byte string with a minimal head (so the value contents are themselves a CBOR byte
  string);
- key **2**, if `aaNetworkMagic = NetworkTestnet w`, with value `CBOR(w :: Word32)` = a minimal
  uint.

Then encode it at v1 (`bin/Encoding/Encoder.hs:397-407`): a **definite** map head with the
minimal length, then entries in **ascending key order**, each key a minimal uint and each value
a definite byte string with a minimal head. An address without attributes gives `0xa0`.

Consequences:

- **Every attribute enters the hash**: the encrypted HD derivation path, the network magic and
  any unknown attributes, all in canonical form.
- The value **contents** of the re-encoding always equal what was decoded. Decoding requires
  key 1 and key 2 values to be canonical and fully consumed, and unknown values are kept raw
  ([dec B.3.5]). So the re-encoding can differ from the wire bytes only in the outer heads (map
  length, key ints, byte-string lengths). **Hash the canonical form, not the wire attribute
  bytes.** urd's `reencode_attributes` (`src/ledger/byron/tx.odin`) produces this form.
- The `addrType addr == type(asd)` conjunct makes a VK witness against a redeem address (or the
  reverse) fail with `TxValidationWitnessWrongKey`, regardless of the hash.
- The 64-byte XPub, chain code included, is hashed. Two witnesses with the same Ed25519 key but
  different chain codes match different addresses.

Typical mainnet layouts:

```
VK, no attributes (Icarus-style):   83 00 82 00 5840 <xpub 64> a0                         (71 bytes)
VK, HD payload (Daedalus legacy):   83 00 82 00 5840 <xpub 64> a1 01 58 1e 58 1c <28 bytes>
redeem (AVVM):                      83 02 82 02 5820 <key 32> a0                          (39 bytes)
testnet VK, HD payload + magic:     83 00 82 00 5840 <xpub> a2 01 58 1e 58 1c <28> 02 45 1a 41 70 cb 17
```

---

## 6. UTxO representation and transitions

### 6.1 Representation

`newtype UTxO = UTxO (Map CompactTxIn CompactTxOut)` (`byron/UTxO/UTxO.hs:71-73`):

| part | content | cite |
|---|---|---|
| key `CompactTxIn` | `(CompactTxId, Word16)`. `CompactTxId` is the 32-byte TxId read as 4 little-endian `Word64`s. This only affects the in-memory layout and `Ord`; the bytes are recoverable | `byron/UTxO/Compact.hs:60-64`, `122-127`, `177-198` |
| value `CompactTxOut` | `(CompactAddress, Lovelace)`. `CompactAddress = serialize' byronProtVer addr` is the **re-encoded** address: `[#6.24(bytes payload'), crc32(payload')]`, with `payload'` = `CBOR((root, attrs, type))` (canonical attributes as in §5.3) and the CRC **recomputed** | `byron/UTxO/Compact.hs:207-211`, `264-266`; `byron/Common/Compact.hs:39`, `56-58`; `byron/Common/Address.hs:157-159`; `byron/Common/CBOR.hs:106-110` |

Witnesses and tx attributes are not stored.

### 6.2 What a transaction adds and removes

```haskell
txOutputUTxO tx = UTxO $ M.fromList
  [ (toCompactTxIn (TxInUtxo (txId tx) ix), toCompactTxOut txOut)
  | (ix, txOut) <- zip [0 ..] (NE.toList (txOutputs tx)) ]   -- ix :: Word16
  where txId = serializeCborHash                                -- H256(CBOR(tx))
```

`byron/UTxO/UTxO.hs:176-188`.

- **TxId = blake2b-256 of the re-encoded `Tx`**, not of the wire bytes
  (`byron-crypto/Hashing.hs:212-213`, `264-265`). The two agree when the tx was canonical.
  [dec B.4.1] gives the exact re-encoding and urd's shortcut (hash the wire bytes when every head
  is minimal).
- The signature hash (§5.1) uses the wire bytes and the UTxO key uses the re-encoded bytes. A
  non-canonical tx therefore has a TxId different from its signed hash. This is legal in blocks.
- Output `ix` is its 0-based position as `Word16`. `[0 ..] :: [Word16]` stops at 65535, so
  outputs past index 65535 are dropped from both the UTxO and `balanceOut`. This is
  unreachable: an output is at least 41 bytes, so 65537 of them exceed the 2,000,000-byte
  mainnet block limit.
- Removed: each distinct input once (§3.10).
- **Zero-value outputs are stored like any other.** There is no positivity check anywhere in
  `byron/UTxO` or `byron/Common`.
- Output values were bounded at decode (≤ 45·10^15, [dec B.3.4]).

### 6.3 Genesis UTxO (initial state)

`genesisUtxo = fromBalances (avvm <> nonAvvm)` (`byron/UTxO/GenesisUTxO.hs:16-32`):

- AVVM entries become `makeRedeemAddress nm key`, where `nm = makeNetworkMagic` and there is
  no derivation path (`byron/Common/Address.hs:291-299`). Non-AVVM entries keep their
  addresses as parsed from base58.
- Each `(addr, value)` becomes the input `TxInUtxo (H256(CBOR(addr))) 0`, i.e. the hash of the
  **address's** CBOR stands in for a TxId (`byron/UTxO/UTxO.hs:130-131`). A duplicate address
  panics (`121-125`).
- Mainnet genesis has 14505 AVVM entries and 0 non-AVVM entries.

### 6.4 Hand-off to Shelley

At the hard fork, each Byron entry becomes a Shelley entry with the **same TxId bytes and
index**. Its address is the Byron `CompactAddress` bytes reused as a bootstrap address, and its
value stays the same (`shelley/API/ByronTranslation.hs:43-47`, `60-72`). Shelley reserves are
`maxLovelaceSupply − Σ UTxO` (`136-138`), which is where the Byron fees (never tracked) end
up. So urd must store the **re-encoded** address bytes, which equal the wire bytes whenever
those were canonical.

---

## 7. Error constructors (for reporting parity)

`TxValidationError` (`byron/UTxO/Validation.hs:92-103`, CBOR tags `112-154`):

| tag | constructor | raised at |
|---|---|---|
| 0 | `TxValidationLovelaceError Text LovelaceError` (text ∈ "Minimum Fee", "Output Balance", "Input Balance", "Fee") | C2 to C5 |
| 1 | `TxValidationFeeTooSmall Tx Lovelace(min) Lovelace(fee)` | C6 |
| 2 | `TxValidationWitnessWrongSignature TxInWitness ProtocolMagicId TxSigData` | B1 |
| 3 | `TxValidationWitnessWrongKey TxInWitness Address` | B2 |
| 4 | `TxValidationMissingInput TxIn` | D3 |
| 5 | `TxValidationNetworkMagicMismatch NetworkMagic(expected) NetworkMagic(actual)` | D2 |
| 6 | `TxValidationTxTooLarge Natural(size) Natural(max)` | C1 |
| 7 | `TxValidationUnknownAddressAttributes` | D2 |
| 8 | `TxValidationUnknownAttributes` | D1 |

`UTxOError`: 0 `UTxOMissingInput TxIn` (A), 1 `UTxOOverlappingUnion` (E)
(`byron/UTxO/UTxO.hs:84-100`). `UTxOValidationError`: 0 wraps a `TxValidationError`, 1 wraps a
`UTxOError` (`byron/UTxO/Validation.hs:332-348`).

---

## 8. Spec versus implementation (the implementation wins)

Executable spec: `byron-spec/STS/UTXO.hs:86-115`, `byron-spec/STS/UTXOW.hs:77-100`,
`byron-spec/UTxO.hs:143-155`. Formal spec: `byron-fspec/utxo.tex:188-235`, `322-345`.

| topic | spec | implementation |
|---|---|---|
| witness count | `length wits == length ins` (exec); formal: ∀ input ∃ a witness in the set | `zip`, no count check (§3.2) |
| witness ↔ input | exec: positional; formal: any witness in the set may cover any input | positional |
| what is signed | `serialised(txbody)` (formal) / abstract `verify key tx sig` | `tag ‖ P ‖ CBOR(H256(tx wire))` (§5.1) |
| address authorization | `addr_h utxo i = hash vk` (formal), `key == pay` (exec) | address-root recomputation over `[t,[t,key],attrs]` (§5.3) |
| output values | `0 < c` for every output (`NonPositiveOutputs`; `utxo.tex:195`, `233-234` says "consistent with the current implementation") | **0 allowed** |
| empty inputs or outputs | rule failures `EmptyTxInputs` / `EmptyTxOutputs` | decode failures (`NonEmpty`, [dec B.3.2]) |
| min fee | `a + b·txSize`, integers, abstract size (exec counts 1 per TxIn/TxOut/Wit) | `a + ⌈b·bytes⌉`, `b` rational, size = wire `[tx, wits]` bytes |
| redeem fee exemption | absent | present (§3.5) |
| max tx size | formal: `txSize ≤ maxTxSize` (UTXOW); exec UTXO: absent | `bytes ≤ ppMaxTxSize` |
| network magic, attribute sizes, asset lock | absent | D1 to D3 |
| balance arithmetic | unbounded integers | bounded at 45·10^15, with the `LovelaceError` failures |
| fee | `reserves += fee` | not tracked; burned until the Shelley translation (§6.4) |
| union | plain `∪` | overlap check (`UTxOOverlappingUnion`) |
| failure for an unknown input | `InputsNotInUTxO` | `UTxOMissingInput` (A); `TxValidationMissingInput` only via D3 |
| check order | inputs ⊆ dom, fee, non-empty, positive (`STS/UTXO.hs:98-109`); witnesses first in UTXOW | §3 table |

---

## 9. Worked example (mainnet, slot 4471207)

Source: `testdata/byron/dingo/mainnet-byron-4471207.cbor` (epoch 207, slot 7), tx #1 of the
payload. Everything below was computed with python3 `hashlib` and an independent pure-Python
RFC 8032 verifier (which compares the encoding of `[S]B − [k]A` with `R`, as donna does).

**Bytes.** The `[tx, witnesses]` span is 291 bytes = `0x82` (1) + tx (150) + witnesses (140).

```
tx (150 B):
83 9f 82 00 d8 18 58 24 82 58 20 779a319e0d64b80eaff5ed13d08062b8672fc71ac27e7b30574c1c7972764de2 02 ff
   9f 82 82 d8 18 58 21 83 58 1c 2c0dd53d4e6001e006729fc09d74c5a799d5f93c9f4b74748412a823 a0 00 1a 1abd8908
         1a 769cfd80                                    ; output 0: 1990000000
      82 82 d8 18 58 21 83 58 1c 05b073f36ee030589a31148838cd47e8d8c8f82fec9fe091c7d53cd8 a0 00 1a 0c5f26b1
         1b 00000016bc0c4c47                            ; output 1: 97644203079
   ff a0
witnesses (140 B): 81 82 00 d8 18 58 85 82 58 40 <xpub 64> 58 40 <sig 64>
xpub = f129f07bbfd87fd1d3ff5fb32e9a5566e02208f89518e9994048add22074f433
       424e682a392581268c7544e34e9c54378a8820bdcf7dddce30490bbb2d363b4b
sig  = 709a2e70d3803554a15d788235bf56c9567407102be375be5071fa81d4c13704
       7743b5f5abefdbab6b2781822474995dff917213c962ecd111619d75b8534f0a
```

The tx spends one input, `(779a319e…4de2, 2)`.

**Hashes and message.** The tx is canonical, so the wire hash and the TxId agree:

```
H = TxId = blake2b-256(tx) = b7f12a75091ac0c5eac7de455fa46e342ba6dd411f1b2f157dc4142128fff71e
msg (40 B) = 01 1a2d964a09 5820 b7f12a75091ac0c5eac7de455fa46e342ba6dd411f1b2f157dc4142128fff71e
Ed25519.verify(pk = xpub[0:32] = f129f07b…f433, msg, sig) = valid
```

**Address root.** Output 1 returns the change to the witness key's own address
`Ae2tdPwUPEYwNguM7TB3dMnZMfZxn1pjGHyGdjaF4mFqZF9L3bj6cdhiH8t` (attributes `{}`). This lets
the root recomputation be checked against real data:

```
Address' (71 B) = 83 00 82 00 5840 <xpub 64> a0
sha3-256        = 8f71c6b180e25edf658f5735acb1db82c6861806baca7822ce52a59cad76db91
blake2b-224     = 05b073f36ee030589a31148838cd47e8d8c8f82fec9fe091c7d53cd8   == root of output 1
address CRC32   = crc32(83 58 1c <root> a0 00) = 0x0c5f26b1                  == wire CRC
```

(The spent output `779a…#2` is not in the fixtures, so B2 against it cannot be shown directly.
Its address is presumably the same reused address.)

**Size and fee.**
`minFee = 155381 + ⌈291 · 21973/500⌉ = 155381 + ⌈12788.286⌉ = 155381 + 12789 = 168170`
lovelace, assuming the genesis fee policy is still adopted at slot 4471207. The actual fee needs
the spent value, which the fixtures lack.

**Redeem address and genesis TxIn (computed only, not checked against the chain).** Take the
first mainnet AVVM key in sorted base64url order, `-0BJDi-gauylk4LptQTgjMeo7kY9lTCbZv12vwOSTZk=`
= `fb40490e2fa06aeca59382e9b504e08cc7a8ee463d95309b66fd76bf03924d99`, with balance
9999300000000:

```
Address'     = 83 02 82 02 5820 fb40490e…4d99 a0
root         = ccdf735b7d5cafe44e65e75a82fd4305fe7712924a8e1196fefdbddf
address CBOR = 82 d818 5821 83 581c <root> a0 02 1a 9cbc2ffe
genesis TxIn = (blake2b-256(address CBOR) = 8ee33c9906974706223d7d500d63bbee2369d7150f972757a9fdded2f706b938, 0)
base58       = Ae2tdPwUPEZHFQnrr2dYB4GEQ8WVKspEyrg29pJ3f7qdjzaxjeShEEokF5f
```

Reproducing the root in Python:

```python
import hashlib
def root(t, key, attrs=b'\xa0'):           # t: 0 VK (key = 64-byte xpub), 2 redeem (32-byte key)
    hdr = b'\x58' + bytes([len(key)])      # both lengths are in 24..255
    ap = bytes([0x83, t, 0x82, t]) + hdr + key + attrs
    return hashlib.blake2b(hashlib.sha3_256(ap).digest(), digest_size=28).digest()
```

---

## 10. Notes for urd

- **Cost.** Per tx there are ≤ min(n_in, n_wit) Ed25519 verifications and at most as many
  SHA3 + blake2b-224 address hashes, plus one blake2b-256 over the tx wire bytes (shared by all
  witnesses). Distinct-input handling (balance, removal, redeem exemption) needs a set: sort
  the `(txid, ix)` keys (O(n log n)) or use the UTxO's own hash lookups. Do not use an O(n²)
  duplicate scan. Keep the positional input list for witness pairing.
- **Precompute per address at decode:** the canonical attribute bytes (for the root), the
  unknown-attribute byte count (for D2) and the network magic. Precompute per tx: the wire hash
  (for signatures) and the re-encoded TxId (for the UTxO key).
- **UTxO values:** store re-encoded address bytes (or wire bytes plus a "canonical" flag) so
  that §3.9 (if ever configured) and the Shelley hand-off (§6.4) see `serialize' addr`.
- **Fee arithmetic:** with mainnet-scale parameters, `sz · n` fits easily in `u128`. To be exact
  for arbitrary adopted parameters (bignum `Nano` numerators, negative `b`), follow §3.4's
  closed form with arbitrary precision, or reject parameter sets whose `n` does not fit, at the
  point the parameters are adopted rather than per tx.
- **Signature verification** must use the crypton/donna semantics (`crypton_ed25519_sign_open`)
  for both witness kinds, through `ccrypto`, never `core:crypto/ed25519`.

---

## 11. Open questions

1. **Historical exercise of the lenient rules.** I could not check from `refs/` whether any
   mainnet or testnet Byron block contains a tx with `n_wit ≠ n_in`, duplicate inputs,
   zero-value outputs, a VK witness for a redeem input, or non-canonical heads in addresses or
   txs. That needs a full-chain scan. All 13 fixture txs have `n_wit = n_in`, positive outputs
   and canonical encodings.
2. **The adopted-parameter history** (fee policy and `maxTxSize` after Byron update proposals)
   is not in `refs/`. Only the genesis values are cited. Take them from the chain's update
   state.
3. **`RequiresNetworkMagic` for preprod and preview.** Their node configs are not vendored. The
   testnet template uses `RequiresMagic`; confirm against the published configs.
4. **GHC base behaviour assumed but not vendored:** `fromInteger :: Integer -> Word64` wraps
   modulo 2^64 (also for negatives); `[0 ..] :: [Word16]` is finite (`boundedEnumFrom`);
   `round` on `Nano` is round-half-even. Only parameter edge cases and the unreachable
   65536-output case depend on these.
5. **Ed25519 acceptance details** (non-canonical `S`, the `RS[63] & 224` pre-check,
   small-order or non-canonical `A`, the cofactorless equation) live in
   `crypton/cbits/ed25519/ed25519.c:88-110` and its donna headers. They are analysed separately.
   This document fixes only the inputs `(m, mlen, pk, RS)`.
6. **The worked-example witness address check.** The spent output `779a…#2` is not vendored,
   so B2 is shown against the matching change output and not against the spent output itself.
