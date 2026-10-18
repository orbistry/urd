# Rules reference: Byron chain validation and PBFT

This is an implementer's reference for what cardano-node checks when it adopts a Byron block or
epoch boundary block (EBB): the ledger's chain-validation layer, the Permissive BFT (PBFT)
consensus protocol, the consensus header envelope, and the hard fork to Shelley. Every rule cites
the Haskell source it comes from. Decoding is covered by
`docs/decoding/witnesses-auxdata-byron.md` (cited below as "decoding doc B.x"). The UTxO,
delegation and update subsystems are only described here at the point where chain validation calls
them, with the arguments it passes.

Sources (pinned clones under `refs/`):

| repo | commit |
|---|---|
| cardano-ledger | `178bd36` |
| ouroboros-consensus | `9b918f8` |
| cardano-base | `5813d21` |
| cardano-crypto | `ac2e12a` |
| crypton | `d5fb2cb` |
| cardano-node | `4d3ad24` |

Path abbreviations used in citations:

| abbreviation | path under `refs/` |
|---|---|
| `byron/` | `cardano-ledger/eras/byron/ledger/impl/src/Cardano/Chain/` |
| `byron-crypto/` | `cardano-ledger/eras/byron/crypto/src/Cardano/Crypto/` |
| `oc/` | `ouroboros-consensus/ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/` |
| `oc-byron/` | `ouroboros-consensus/ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/` |
| `oc-cardano/` | `ouroboros-consensus/ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/` |
| `cardano-crypto/` | `cardano-crypto/src/` |
| `crypton/` | `crypton/` |
| `node/` | `cardano-node/` |

Terminology:

- **es** is the number of slots per epoch. Byron fixes it to `10k`: `configEpochSlots =
  kEpochSlots . configK` and `kEpochSlots = (*) 10` (`byron/Genesis/Config.hs:100-101`,
  `byron/ProtocolConstants.hs:44-45`). Mainnet: k = 2160, es = 21600.
- **Ticked state** is the ledger state after `applyChainTick` to the block's slot (1.3).
- **Full validation** and **reapply** are the two ways consensus applies a block (1.7).
- Integer types: `SlotNumber`, `EpochNumber`, `ChainDifficulty`, `BlockCount`, `EpochSlots`,
  consensus `SlotNo` and `BlockNo` are all `Word64`. `ProtocolMagicId` is `Word32`
  (`byron-crypto/ProtocolMagic.hs:57-62`). Haskell `Word64` arithmetic wraps modulo 2^64.

---

## 0. Who checks what, and in which order

### 0.1 cardano-node does not call `updateChainBlockOrBoundary`

`byron/Block/Validation.hs` exports `updateChainBlockOrBoundary` / `updateBlock`, the CHAIN rule.
Its own comment says it is "intended more for use in tests than in a real implementation"
(`byron/Block/Validation.hs:507-512`). Consensus instead calls the three functions of
`byron/Byron/API/Validation.hs`:

| consensus step | Byron function | cite |
|---|---|---|
| tick to the block's slot | `applyChainTick` | `oc-byron/Ledger/Ledger.hs:194-201`; `byron/Byron/API/Validation.hs:107-126` |
| apply a main block | `validateBlock` | `oc-byron/Ledger/Ledger.hs:402-411`; `byron/Byron/API/Validation.hs:153-179` |
| apply an EBB | `validateBoundary` (wraps `updateChainBoundary`) | `oc-byron/Ledger/Ledger.hs:447-454`; `byron/Byron/API/Validation.hs:184-200` |

They reuse the pieces of `Validation.hs` (`epochTransition`, `headerIsValid`, `updateBody`,
`updateChainBoundary`) but differ from `updateBlock` in ways that matter. Section 1.6 lists the
differences. **urd must follow the consensus path.**

### 0.2 The three stages in a running node

A block from a peer meets three stages. All of them must pass for the block to be adopted.

1. **ChainSync, header only.** The header is validated with the generic `validateHeader`
   (`oc/MiniProtocol/ChainSync/Client.hs:1872-1928`): envelope, then PBFT. The ledger view comes
   from a forecast (3.4). An era-generic "header in the future" check against the wall clock also
   runs here (`oc/MiniProtocol/ChainSync/Client/InFutureCheck.hs`). It is not Byron-specific and
   not covered further.
2. **BlockFetch.** `blockMatchesHeader` is checked on every fetched block
   (`oc/MiniProtocol/BlockFetch/ClientInterface.hs:161-164`). For Byron that is `abobMatchesBody`
   (`oc-byron/Ledger/Block.hs:180-181`): a main header against a main body runs
   `validateHeaderMatchesBody` (the three body proofs); an EBB header against an EBB body is `True`
   with no check; any mixed pair is `False` (`byron/Byron/API/Common.hs:145-159`).
3. **Block application** (ChainDB chain selection, LedgerDB). For `ExtLedgerState`:
   1. tick ledger and header state to the block's slot (`oc/Ledger/Extended.hs:226-264`);
   2. apply the block to the ledger (`oc/Ledger/Extended.hs:289-295`);
   3. then validate the header again, envelope and PBFT, against the ticked ledger view
      (`oc/Ledger/Extended.hs:296-302`).

   The ledger runs **before** the header checks in this stage. Both must succeed. The order only
   decides which error is reported.

### 0.3 Master check list for a main block (full validation)

Order within each component is the order of the source. "Mode" says whether the check is skipped
on reapply (`NoBlockValidation`, 1.7).

| # | check | component | function | skipped on reapply | cite |
|---|---|---|---|---|---|
| 1 | tick: update-system epoch transition, delegation activation | ledger tick | `applyChainTick` | never skipped | `byron/Byron/API/Validation.hs:107-126` |
| 2 | era of block equals era of the ticked ledger (`HardForkLedgerErrorWrongEra`); the envelope repeats it at step 5 of 4.1 | HFC ledger, HFC envelope | `applyBlockLedgerResultWithValidation` (HFC), `additionalEnvelopeChecks` (HFC) | no (ledger) | `oc/HardFork/Combinator/Ledger.hs:251-263`, `392-404` |
| 3 | header size ≤ adopted `ppMaxHeaderSize` | ledger | `headerIsValid` | yes | `byron/Block/Validation.hs:462-468` |
| 4 | block size ≤ adopted `ppMaxBlockSize` | ledger | `updateBody` | yes | `byron/Block/Validation.hs:370-372` |
| 5 | delegation proof, tx proof, update proof | ledger (and BlockFetch) | `validateHeaderMatchesBody` | yes (ledger) | `byron/Block/Validation.hs:312-328`, `375-376` |
| 6 | delegation certificates in the body | ledger | `DI.updateDelegation` | **no** | `byron/Block/Validation.hs:379-381` |
| 7 | transactions | ledger | `UTxO.updateUTxO` | tx checks yes, UTxO update no | `byron/Block/Validation.hs:384-386` |
| 8 | update proposal, votes, endorsement | ledger | `UPI.registerUpdate` | **no** | `byron/Block/Validation.hs:389-391` |
| 9 | block number = expected | envelope | `validateEnvelope` | assert only | `oc/HeaderValidation.hs:378-380` |
| 10 | slot ≥ minimum next slot | envelope | `validateEnvelope` | assert only | `oc/HeaderValidation.hs:381-383` |
| 11 | prev hash = tip hash | envelope | `validateEnvelope` | assert only | `oc/HeaderValidation.hs:384-386` |
| 12 | checkpoint hash, if one is configured at this block number | envelope | `validateIfCheckpoint` | assert only | `oc/HeaderValidation.hs:387`, `431-441` |
| 13 | (EBB only) slot is a multiple of es | envelope | Byron `additionalEnvelopeChecks` | assert only | `oc-byron/Ledger/HeaderValidation.hs:57-76` |
| 14 | header signature | PBFT | `updateChainDepState` | yes | `oc/Protocol/PBFT.hs:353-359` |
| 15 | slot ≥ last signed slot | PBFT | `updateChainDepState` | yes | `oc/Protocol/PBFT.hs:364-365` |
| 16 | issuer is a current genesis delegate | PBFT | `updateChainDepState` | `error` if it fails | `oc/Protocol/PBFT.hs:367-372`, `389-395` |
| 17 | signature-window threshold | PBFT | `pbftWindowExceedsThreshold` | `error` if it fails | `oc/Protocol/PBFT.hs:373-377`, `396-400` |

For an EBB, rows 3 to 8 and 14 to 17 are replaced by `updateChainBoundary` (prev hash and size,
section 5), and PBFT does nothing.

Not checked anywhere on the validation path: the main header's protocol magic (1.6, open question
1), the header's `genesis_key` field and the header's delegation certificate apart from its
delegate key (2.3), the SSC payload and proof, `extra_proof`, the EBB body and body proof (decoding
doc B.6 item 9).

---

## 1. Ledger: chain validation state and algorithm

### 1.1 `ChainValidationState`

`byron/Block/Validation.hs:138-146`:

| field | type | meaning |
|---|---|---|
| `cvsLastSlot` | `SlotNumber` (Word64) | slot of the last applied block or EBB |
| `cvsPreviousHash` | `Either GenesisHash HeaderHash` | `Left genesis hash` until the first block or EBB is applied, then `Right` hash of the last one |
| `cvsUtxo` | `UTxO` | |
| `cvsUpdateState` | `UPI.State` | update interface state, including the adopted protocol version and parameters |
| `cvsDelegationState` | `DI.State` | scheduling state and activation state (`byron/Delegation/Validation/Interface.hs:64-67`) |

Initial value, `initialChainValidationState` (`byron/Block/Validation.hs:177-206`):

- `cvsLastSlot = 0`.
- `cvsPreviousHash = Left (configGenesisHash config)`. The genesis hash is
  `blake2b-256(canonical JSON of the genesis data)` (`byron/Genesis/Data.hs:179`), and the node
  checks it against the configured hash (`byron/Genesis/Config.hs:137-158`). Mainnet:
  `5f20df933584822601f9e3f8c024eb5eb252fe8cefb24d1317dc3d432e940ebb`
  (`node/configuration/cardano/mainnet-config.json:5`).
- `cvsUtxo = genesisUtxo config`; `cvsUpdateState = UPI.initialState config`.
- Delegation: every genesis key delegates to itself, with activation slot 0. Then the genesis
  file's heavy-delegation certificates are run through `updateDelegation` with `k = 0`,
  `currentEpoch = 0` and `currentSlot = 0`, so they activate at once. Their annotations are
  re-serialized (`byron/Delegation/Validation/Interface.hs:94-137`).

The consensus wrapper adds two fields (`oc-byron/Ledger/Ledger.hs:104-125`):

- `byronLedgerTipBlockNo :: WithOrigin BlockNo`. It is set to the block number of every applied
  block or EBB (`oc-byron/Ledger/Ledger.hs:438`, `457`).
- `byronLedgerTransition = ByronTransitionInfo (Map ProtocolVersion BlockNo)`, which records the
  block number at which each candidate protocol update became a candidate. It is updated after
  every main block (`421-434`): entries for versions that are no longer candidates are dropped, and
  new candidates get the current block number. EBBs leave it unchanged (`459`). It is used only
  for the Shelley transition (4.8).

Initial: tip block number `Origin`, empty transition map (`oc-byron/Ledger/Ledger.hs:132-142`).
The ledger tip point is `GenesisPoint` while `cvsPreviousHash` is `Left`, and otherwise
`BlockPoint cvsLastSlot hash` (`oc-byron/Ledger/Ledger.hs:168-176`).

### 1.2 Slot and epoch arithmetic

- **Main header slot.** The header carries `[epoch, slot_in_epoch]`, two `Word64`s. The decoder
  flattens them with `toSlotNumber es`: `epoch * es + slot_in_epoch` in `Word64`, wrapping. There
  is **no** check that `slot_in_epoch < es` (`byron/Slotting/EpochAndSlotCount.hs:71-81`;
  `byron/Block/Header.hs:373`). Every later rule uses the flattened slot, so a header
  `[e, es + 5]` sits in epoch `e + 1`.
- **EBB slot.** `boundaryBlockSlot es epoch = es * epoch` (`byron/Block/Block.hs:533-539`). This is
  the consensus slot of the EBB (`oc-byron/Ledger/Block.hs:117-123`, `288-294`;
  `byron/Block/Block.hs:604-608`), and also the `cvsLastSlot` stored after it (1.5).
- **Epoch of a slot.** `slotNumberEpoch es s = s div es` (`byron/Slotting/EpochAndSlotCount.hs:84-99`).
  `epochFirstSlot es e = es * e` (`byron/Slotting/EpochSlots.hs:56-57`).
- **Block number.** It is the header's `ChainDifficulty`, for main blocks and EBBs alike
  (`oc-byron/Ledger/Block.hs:232-238`; `byron/Block/Block.hs:610-614`; `oc-byron/Ledger/Conversions.hs:41-42`).

### 1.3 Tick: `applyChainTick` (every block and every EBB)

Consensus ticks the ledger to slot `s`, the slot of the block about to be applied, before applying
it (`oc-byron/Ledger/Ledger.hs:194-201`). `applyChainTick cfg s cvs`
(`byron/Byron/API/Validation.hs:107-126`) changes only two fields:

1. `cvsUpdateState := epochTransition env (cvsUpdateState cvs) s`, where env is
   `mkEpochEnvironment cfg cvs` (`37-59`):
   - `protocolMagic` = the configured magic, re-encoded canonically (`reAnnotateMagicId`,
     `byron/Byron/API/Common.hs:78-79`);
   - `k` = genesis k; `allowedDelegators` = genesis key hashes;
   - `delegationMap` = the delegation map **before** this tick;
   - `currentEpoch = slotNumberEpoch es cvsLastSlot`, the **old** epoch.

   `epochTransition` (`byron/Block/Validation.hs:483-505`) computes
   `nextEpoch = slotNumberEpoch (kEpochSlots k) s`. If `nextEpoch > currentEpoch` it calls
   `UPI.registerEpoch updateEnv st nextEpoch`, with `currentSlot = s`. Otherwise the state is
   unchanged. See section 6.
2. `cvsDelegationState := tickDelegation (slotNumberEpoch es s) s`, which activates scheduled
   delegations and prunes old ones (`byron/Delegation/Validation/Interface.hs:181-217`). See
   section 6.

`cvsLastSlot`, `cvsPreviousHash` and the UTxO are not touched by the tick. PBFT's tick only stores
the ledger view (`oc/Protocol/PBFT.hs:340`).

### 1.4 Main block: `validateBlock`

`validateBlock cfg mode block blkHash cvs`, where `cvs` is the ticked state
(`byron/Byron/API/Validation.hs:153-179`):

1. **Header size** (`validateHeader` → `headerIsValid`, `132-140`;
   `byron/Block/Validation.hs:457-468`):
   - `headerLength h ≤ ppMaxHeaderSize (adoptedProtocolParameters (cvsUpdateState cvs))`;
   - `headerLength` is the byte length of the header 5-array as received, without the `[1, …]`
     envelope (`byron/Block/Header.hs:288-289`);
   - both sides are `Natural`, and the comparison is `≤`;
   - error `ChainValidationHeaderTooLarge`; skipped in `NoBlockValidation`;
   - the parameters are the ticked ones, so an epoch transition at this slot takes effect here.

   This is the **only** header-level ledger check.
2. **Body** (`validateBody` → `updateBody bodyEnv bodyState block`, `142-151`;
   `byron/Block/Validation.hs:362-448`). The environment is `mkBodyEnvironment`
   (`byron/Byron/API/Validation.hs:69-89`):
   - `protocolMagic` = the configured magic with its `RequiresNetworkMagic`, canonically
     re-encoded (`reAnnotateMagic`, `byron/Byron/API/Common.hs:81-82`);
   - `utxoConfiguration`, `k`, `allowedDelegators` from genesis;
   - `protocolParameters` = adopted parameters of the ticked state (stored, but `updateBody` reads
     the parameters from `updateState` instead, `410-411`, `431`);
   - `currentEpoch = slotNumberEpoch es (blockSlot block)`, the block's **own** epoch.

   The state is the ticked UTxO, update state and delegation state (`mkBodyState`, `61-67`). In
   order:

   a. **Block size.** `blockLength b ≤ ppMaxBlockSize` (adopted, ticked). `blockLength` is the
      byte length of the block 3-array `[header, body, extra]` as received, without the `[1, …]`
      envelope (`byron/Block/Block.hs:308-309`). The comparison is `≤`. Error
      `ChainValidationBlockTooLarge`; skipped in `NoBlockValidation` (`370-372`).
   b. **Body proofs** (`validateHeaderMatchesBody`, `312-328`), only in `BlockValidation`
      (`375-376`). The computations are in decoding doc B.4 items 3 to 5:
      1. `proofDelegation == blake2b-256(delegation payload bytes)` → `DelegationProofValidationError`;
      2. `proofUTxO == recoverTxProof txPayload`, where the whole `TxProof` must match: `Word32`
         count, Merkle root, witnesses hash (`byron/UTxO/TxProof.hs:99-105`) →
         `UTxOProofValidationError`;
      3. `proofUpdate == blake2b-256(update payload bytes)` → `UpdateProofValidationError`.

      The SSC proof is never compared.
   c. **Delegation** (`379-381`). `DI.updateDelegation` with
      `{protocolMagic, allowedDelegators, k, currentEpoch = epoch of block, currentSlot = block slot}`
      (`419-426`), over the body's certificates in payload order. It runs in **every** mode (plain
      `wrapError`). Detail: section 6.
   d. **UTxO** (`384-386`). `UTxO.updateUTxO` with
      `{protocolMagic, adopted protocol parameters, utxoConfiguration}` (`428-433`), mode-aware
      (1.7).
   e. **Update** (`389-391`). `UPI.registerUpdate` with
      `{protocolMagic, k, currentSlot = block slot, numGenKeys, delegationMap}` (`435-442`). It
      runs in every mode. `delegationMap` is the delegation state **input** to `updateBody`, i.e.
      the ticked map before this block's certificates. `numGenKeys` is the number of genesis keys
      as `Word8`, and the code panics above 255 (`450-453`). The signal is
      `(proposal, votes, Endorsement blockProtocolVersion (hashKey delegateVK))`. The endorsement
      key is the **delegate** key of the header certificate (`443-448`; `blockIssuer =
      headerIssuer`, `byron/Block/Header.hs:274-276`).
3. **State update** (`byron/Byron/API/Validation.hs:164-171`):
   - `cvsLastSlot := blockSlot block`;
   - `cvsPreviousHash := Right blkHash`, where `blkHash = blake2b-256(0x82 0x01 ‖ header bytes)`
     (decoding doc B.1.5; `oc-byron/Ledger/Block.hs:72-73`);
   - UTxO, update and delegation states from the body.

`validateBlock` does **not** check the protocol magic, the previous hash, the signature, the
issuer or the slot ordering. Those are consensus checks (sections 2 to 4).

### 1.5 EBB: `validateBoundary` / `updateChainBoundary`

`validateBoundary cfg blk cvs` (`byron/Byron/API/Validation.hs:184-200`) runs
`updateChainBoundary cvs blk` (`byron/Block/Validation.hs:271-305`) and then sets
`cvsLastSlot := es * boundaryEpoch`. `updateChainBoundary`:

1. **Previous hash.** It compares `cvsPreviousHash` with the EBB's `boundaryPrevHash`. That value
   is `Left` (genesis) if the EBB epoch is 0 or its extra data carries the attribute
   `255 => "Genesis"`, and `Right` otherwise (`byron/Block/Header.hs:613-626`;
   `byron/Block/Boundary.hs:61-67`).

   | ledger has | EBB has | result | error |
   |---|---|---|---|
   | `Left g` | `Left g'` | `g == g'` required | `ChainValidationGenesisHashMismatch` |
   | `Right h` | `Right h'` | `h == h'` required | `ChainValidationInvalidHash` |
   | `Left` | `Right` | reject | `ChainValidationExpectedGenesisHash` |
   | `Right` | `Left` | reject | `ChainValidationExpectedHeaderHash` |

   (`277-287`.) The genesis case compares the 32-byte value with `configGenesisHash`.
2. **Size.** `boundaryBlockLength ≤ 2e6`, i.e. 2,000,000 bytes. It is an `Int64` comparison with
   `≤` (`290-291`; `NumDecimals`, line 9). `boundaryBlockLength` is the length of the EBB 3-array
   as received, without the `[0, …]` envelope (`byron/Block/Block.hs:494`). Error
   `ChainValidationBoundaryTooLarge`. This is a fixed constant, not a protocol parameter, and it
   is checked in **every** mode: `updateChainBoundary` has no `ValidationMode`.
3. **State.** `cvsPreviousHash := Right (blake2b-256(0x82 0x00 ‖ EBB header bytes))` (`294-305`).
   This is the same value as the consensus hash of the EBB (`byron/Block/Block.hs:616-618`;
   `byron/Block/Header.hs:539-540`).

Nothing else is checked. The EBB's protocol magic and body proof are dropped by the decoder
(decoding doc B.2.2), and its body is never inspected.

### 1.6 How the ledger-only path differs (`updateChainBlockOrBoundary`)

`updateBlock` (`byron/Block/Validation.hs:513-576`) and the bare `updateChainBoundary` differ from
what the node runs:

| aspect | `updateBlock` / `updateChainBoundary` | consensus path (authoritative) |
|---|---|---|
| main header protocol magic | `blockProtocolMagicId b == configProtocolMagicId`, error `ChainValidationProtocolMagicMismatch`, skipped in `NoBlockValidation` (`520-525`) | **not checked** during validation; see open question 1 |
| magic bytes in signed data (certificates, tx witnesses, proposals, votes) | the block's own annotated magic bytes (`535-539`), possibly a non-minimal encoding | canonical CBOR of the configured magic (`reAnnotateMagic`) |
| epoch transition | inside `updateBlock`, before the header check (`528`) | in `applyChainTick`, also for EBBs (at the EBB's slot) |
| delegation activation at the block's slot | only inside `updateDelegation`, so the update interface's `delegationMap` (`441`) is the map **before** activation | `tickDelegation` in the tick, so `registerUpdate` and PBFT see the activated map |
| EBB `cvsLastSlot` | unchanged | `es * epoch` |
| EBB tick | none | full tick at `es * epoch` |

Neither path checks a main block's previous hash in the ledger. Only the consensus envelope does
(4.3).

### 1.7 `ValidationMode`: full validation versus reapply

- `ValidationMode = {blockValidationMode, txValidationMode}` (`byron/ValidationMode.hs:26-29`).
- `BlockValidation` maps to `TxValidation`, and `NoBlockValidation` maps to `NoTxValidation`
  (`byron/Block/ValidationMode.hs:16-26`).
- `TxValidationNoCrypto` exists but consensus never selects it (`byron/UTxO/ValidationMode.hs:12-22`).
- Consensus maps `ValidateAll` and `ValidateSuchThat _` to `BlockValidation`, and `ValidateNone` to
  `NoBlockValidation` (`oc-byron/Ledger/Ledger.hs:396-400`).
- Full application uses `ValidateAll` (`oc/Ledger/Abstract.hs:151-159`). Reapply, used for blocks
  already validated against the same state (for example LedgerDB replay), uses `ValidateNone` and
  turns any error into a crash (`oc/Ledger/Abstract.hs:161-171`;
  `oc-byron/Ledger/Ledger.hs:238`, `366-367`).

What `NoBlockValidation` / `NoTxValidation` skips:

| check | skipped? | mechanism |
|---|---|---|
| header size, block size | yes | `orThrowErrorInBlockValidationMode` (`byron/ValidationMode.hs:42-49`) |
| body proofs | yes | `whenBlockValidation` (`69-75`) |
| tx witnesses, `validateTxAux`, `validateTx` | yes | `whenTxValidation` / `unlessNoTxValidation` (`byron/UTxO/Validation.hs:366`, `380`) |
| removing inputs from and adding outputs to the UTxO (`UTxO.union`) | no | `byron/UTxO/Validation.hs:369-370` |
| delegation scheduling, including certificate signatures | no | `wrapError`, not mode-aware (`byron/Block/Validation.hs:379-381`) |
| update registration | no | `byron/Block/Validation.hs:389-391` |
| EBB prev hash and 2 MB limit | no | `updateChainBoundary` takes no mode |
| envelope | evaluated only as an assertion | `oc/HeaderValidation.hs:552-574` |
| PBFT signature, PBFT slot check | yes | `reupdateChainDepState` (`oc/Protocol/PBFT.hs:381-402`) |
| PBFT delegate lookup and threshold | computed; failure is `error` | `oc/Protocol/PBFT.hs:389-400` |

### 1.8 `ChainValidationError` constructors that are never raised

These are declared (`byron/Block/Validation.hs:212-255`), but no code in `refs/cardano-ledger`
throws them:

- `ChainValidationBlockAttributesTooLarge`, `ChainValidationHeaderAttributesTooLarge`;
- `ChainValidationDelegationPayloadError`, `ChainValidationInvalidDelegation`,
  `ChainValidationInvalidSignature`, `ChainValidationSignatureLight`,
  `ChainValidationTooManyDelegations`;
- `ChainValidationMissingHash`, `ChainValidationUnexpectedGenesisHash`.

Signature, delegate and threshold failures are PBFT errors instead (section 3).

### 1.9 Size limits (complete for the chain layer)

| object | bytes measured | limit | comparison | where | mode |
|---|---|---|---|---|---|
| main header | header 5-array | adopted `ppMaxHeaderSize` (`Natural`) | `≤` | ledger `headerIsValid` | full only |
| main block | block 3-array (includes the header) | adopted `ppMaxBlockSize` (`Natural`) | `≤` | ledger `updateBody` | full only |
| EBB | EBB 3-array | 2,000,000 (constant) | `≤` | ledger `updateChainBoundary` | always |
| tx, proposal | (subsystems) | `ppMaxTxSize`, `ppMaxProposalSize` | | UTxO / update rules | |

Mainnet genesis: `maxHeaderSize = maxBlockSize = 2000000`
(`node/configuration/cardano/mainnet-byron-genesis.json`, `blockVersionData`). Updates can
change the adopted values. Consensus has **no** separate header or block size check for Byron:
the `CommonProtocolParams.maxHeaderSize` instance (`oc-byron/Ledger/Ledger.hs:269-271`) is not
used on the validation path.

---

## 2. Block header signature

### 2.1 Who verifies, with what

PBFT verifies the signature in `updateChainDepState` (`oc/Protocol/PBFT.hs:353-359`), using the
validate view built by `oc-byron/Ledger/PBFT.hs:41-74`:

| PBFT field | source in the header | cite |
|---|---|---|
| `pbftIssuer` (verification key) | `delegateVK` of the block signature's delegation certificate | `oc-byron/Ledger/PBFT.hs:52-57` |
| `pbftGenKey` (goes into the sign tag) | the header's own `genesis_key` field, `consensus_data[1]` (`headerGenesisKey`) | `oc-byron/Ledger/PBFT.hs:58-61`; `byron/Block/Header.hs:163` |
| `pbftSignature` | the 64-byte signature in the block signature | `oc-byron/Ledger/PBFT.hs:62-67` |
| signed value | `recoverSignedBytes es header` | `oc-byron/Ledger/PBFT.hs:71` |
| context | `(configured ProtocolMagicId, pbftGenKey)` | `oc-byron/Ledger/PBFT.hs:35-39`, `72`; `oc-byron/Crypto/DSIGN.hs:78` |

The magic comes from the node's genesis configuration (`byronProtocolMagicId`,
`oc-byron/Ledger/Config.hs:59-63`), never from the block.

### 2.2 The signed message, byte by byte

`verifyDSIGN (magic, genKey) vk a sig` checks
`verifySignatureRaw vk (signTag magic (SignBlock genKey) ‖ recoverBytes a) sig`
(`oc-byron/Crypto/DSIGN.hs:60-61`, `108-111`; `signTagFor` `51-55`):

```
msg =  0x30 0x31                     ; ASCII "01" (OverloadedStrings literal)
     ‖ genesis_key[64]               ; header consensus_data[1]: raw XPub = 32-byte key ‖ 32-byte chain code, no CBOR head
     ‖ 0x09
     ‖ cbor_uint(protocol_magic)     ; configured magic as a Word32, minimal CBOR head, major type 0
     ‖ 0x85                          ; literal "array of 5" head, whatever the header's own encoding
     ‖ prev_hash item                ; header[1] exactly as received (0x58 0x20 ‖ 32 bytes if minimal)
     ‖ body_proof item               ; header[2] as received (the 4-array)
     ‖ slot_id item                  ; consensus_data[0] as received: the [epoch, slot] 2-array
     ‖ difficulty item               ; consensus_data[2] as received: the [Word64] 1-array
     ‖ extra_data item               ; header[4] as received: the 4-array
```

- The tag: `SignBlock (VerificationKey issuerVK) -> "01" <> CC.unXPub issuerVK <> "\x09" <> network`,
  with `network = serialize' byronProtVer (unProtocolMagicId magic)`
  (`byron-crypto/Signing/Tag.hs:68-69`, `85-86`). `unXPub` is key ‖ chain code
  (`cardano-crypto/Cardano/Crypto/Wallet.hs:151-152`).
- Mainnet magic 764824073 encodes as `1a 2d 96 4a 09`.
- The body: `recoverSignedBytes` (`byron/Block/Header.hs:707-722`), from the annotations of the
  decoded header (`351-390`). The slot annotation is the original `[epoch, slot]` bytes, not a
  re-encoding of the flattened slot (`373`). The extra-data annotation covers the whole 4-array
  (`377`).
- The header's own protocol magic (`header[0]`), `genesis_key` (as a CBOR item) and block
  signature are **not** in the signed bytes. The magic enters only through the tag, and only as
  the configured value.
- Other tags, for reference (`byron-crypto/Signing/Tag.hs:71-87`): `SignTx 0x01`,
  `SignRedeemTx 0x02`, `SignVssCert 0x03`, `SignUSProposal 0x04`, `SignCommitment 0x05`,
  `SignUSVote 0x06`, `SignCertificate 0x0a`, each followed by the same magic encoding. `0x07` and
  `0x08` are retired.

### 2.3 What is and is not checked about the header's certificate and genesis key

| item | checked? | by whom |
|---|---|---|
| `cert.delegateVK` | it is the verification key for the signature; `hashKey(delegateVK)` must be in the **range** of the ticked delegation map | PBFT (`oc/Protocol/PBFT.hs:353-359`, `367-372`) |
| `cert.issuerVK` | **no** | nobody. It is not compared with the header's `genesis_key` or with the genesis key the delegation map yields |
| `cert.epoch` | **no** | nobody |
| `cert.signature` (the certificate's own signature) | **no** | nobody. Only body certificates go through `Certificate.isValid` (`byron/Delegation/Validation/Scheduling.hs:207`) |
| header `genesis_key` | only indirectly, as part of the signed message (2.2); it is not compared with anything | PBFT signature |
| genesis key counted for the threshold | `lookupR(hashKey(delegateVK))` in the delegation map, **not** the header field | PBFT |

The only uses of the header certificate in `refs/` are PBFT (`delegateVK`), the update endorsement
(`hashKey delegateVK`, `byron/Block/Validation.hs:447-448`), forging and pretty-printing.
Honestly forged headers set `genesis_key = cert.issuerVK` (`byron/Block/Header.hs:247-249`;
`oc-byron/Ledger/Forge.hs:209-210`), but validation does not require it. The decoder still
enforces the shapes: 64-byte keys with a canonical byte-string head, a 64-byte signature, a
`Word64` epoch (decoding doc B.2.1, B.3.9).

> **urd note.** `verify_block_signature` (`src/ledger/byron/sign.odin`) puts the header's
> `genesis_key` (urd's `Header.issuer`) into the sign tag, as cardano-node does, not the
> certificate's issuer. The two differ only for a header where `genesis_key ≠ cert.issuer`, which
> cardano-node accepts if the signature was made over the header's `genesis_key`.

### 2.4 Ed25519 variant

- `verifySignatureRaw (VerificationKey k) x (Signature sig) = CC.verify k x sig`
  (`byron-crypto/Signing/Signature.hs:228-233`).
- `CC.verify (XPub point _) msg sig` verifies with `Crypto.PubKey.Ed25519` on the **first 32
  bytes** of the XPub. The chain code is ignored (`cardano-crypto/Cardano/Crypto/Wallet.hs:58`,
  `197-201`). The package is crypton (`cardano-crypto/cardano-crypto.cabal:51`). `publicKey` and
  `signature` check length only, so `throwCryptoError` cannot fire for 32 / 64 bytes
  (`crypton/Crypto/PubKey/Ed25519.hs:64-68`, `88-92`).
- crypton's `verify` calls ed25519-donna `ed25519_sign_open` (`crypton/Crypto/PubKey/Ed25519.hs:135-141`;
  `crypton/cbits/ed25519/ed25519.c:88-110`). Its rules:
  1. reject if `S[31] & 0xE0 != 0`, i.e. require S < 2^253. S is then reduced mod L
     (`expand256_modm`), so S in [L, 2^253) verifies like S − L
     (`crypton/cbits/ed25519/ed25519.c:94`, `102`; `crypton/cbits/ed25519/modm-donna-64bit.h:153-178`);
  2. A is decoded with `ge25519_unpack_negative_vartime`. y is reduced mod p, so non-canonical
     encodings are accepted, and small-order keys are accepted. It fails only if no square root
     exists (`crypton/cbits/ed25519/ed25519-donna-impl-base.h:192-239`);
  3. k = SHA-512(R ‖ A ‖ M) over the bytes as given (`crypton/cbits/ed25519/ed25519.c:29-36`);
  4. cofactorless check: `encode([S]B − [k]A)` must equal R byte for byte
     (`crypton/cbits/ed25519/ed25519.c:105-109`). R is not otherwise validated.
- These are **not** cardano-base's libsodium `Ed25519DSIGN` semantics. Every Byron signature
  (header, delegation certificate, vkey witness, proposal, vote) goes through `CC.verify`. urd has
  `ccrypto.ed25519_verify_donna` / `ed25519_verify_donna_parts` for exactly this
  (`src/ccrypto/ed25519_donna.odin`).
- Byron consensus never uses cardano-base's `Ed25519DSIGN`. `ByronDSIGN` is its own
  `DSIGNAlgorithm`: verification key 64 bytes, signature 64 bytes (`oc-byron/Crypto/DSIGN.hs:63-111`).

### 2.5 Key hashes

`hashKey vk = blake2b-224(sha3-256(serialize vk))`, where `serialize vk` is the CBOR byte string
`0x58 0x40 ‖ xpub[64]` (`byron/Common/KeyHash.hs:55-56`; `byron/Common/AddressHash.hs:16-25`;
`byron-crypto/Signing/VerificationKey.hs:85-92`). The delegation map and the PBFT state hold these
28-byte hashes (`oc-byron/Protocol.hs:26-33`).

---

## 3. PBFT

### 3.1 Parameters

`byronPBftParams` (`oc-byron/Node.hs:268-274`):

| parameter | value | cite |
|---|---|---|
| `pbftSecurityParam` | genesis `k` (`gdK`), must be non-zero | `oc-byron/Ledger/Conversions.hs:44-45`, `74-78` |
| `pbftNumNodes` | number of genesis key hashes; used **only** for forging (`checkIsLeader`) | `oc-byron/Ledger/Conversions.hs:80-87`; `oc/Protocol/PBFT.hs:319-338` |
| `pbftSignatureThreshold` | node config `PBftSignatureThreshold` (a `Double`), default **0.22** | `oc-byron/Node.hs:178-179`, `273`; `node/cardano-node/src/Cardano/Node/Configuration/POM.hs:598` |

Mainnet `mainnet-config.json` has no `PBftSignatureThreshold` key, so 0.22 applies. The threshold
is **node configuration**, not a ledger or genesis parameter.

Derived values (`oc/Protocol/PBFT.hs:417-433`):

- `windowSize = k` (`pbftWindowSize`, `Word64`);
- `threshold = floor (t * fromIntegral k) :: Word64`, computed in IEEE `Double`. Mainnet:
  `floor(0.22 * 2160.0) = floor(475.2000…) = 475`.

### 3.2 State: `PBftState`

`oc/Protocol/PBFT/State.hs:81-92`:

- `inWindow :: StrictSeq PBftSigner`: the last ≤ k **signed (main) blocks**, oldest first. Each
  `PBftSigner` is `(SlotNo, genesis KeyHash)` (`145-148`).
- `counts :: Map KeyHash Word64`: a cache of the per-genesis-key counts over `inWindow`.

It starts empty at genesis (`oc-byron/Node.hs:245`; `State.hs:202-207`).

- `lastSignedSlot` is the slot of the newest entry, or `Origin` if the window is empty
  (`189-193`).
- `append n signer st` appends on the right, then drops the oldest entry if the window held
  exactly n entries **before** the append (`212-235`). So after an append the window holds at most
  n entries, and they include the new one.
- EBBs never touch the state (`oc/Protocol/PBFT.hs:348-349`). The window counts blocks, not slots.

### 3.3 `updateChainDepState` (full validation), in order

`oc/Protocol/PBFT.hs:342-379`, with `slot` = the header's slot and `dms` = the ledger view's
delegation map:

1. **EBB**: return the state unchanged (`348-349`). Nothing about an EBB is checked by PBFT.
2. **Signature**: `verifySignedDSIGN (magic, genKey) pbftIssuer signed sig` (2.2, 2.4). Failure:
   `PBftInvalidSignature` (`353-359`).
3. **Slot**: `NotOrigin slot >= lastSignedSlot state`, non-strict, against the last **signed**
   block. Failure: `PBftInvalidSlot` (`364-365`). The envelope already requires strict increase
   between main blocks (4.2), so this check never decides anything after the envelope passes.
4. **Delegate**: `gk = Bimap.lookupR (hashKey pbftIssuer) dms`. The map goes genesis key hash →
   delegate key hash, one to one (`byron/Delegation/Map.hs:37-38`), and `lookupR` finds the genesis
   key whose current delegate is the issuer. Not found: `PBftNotGenesisDelegate` (`367-372`).
5. **Threshold**: `state' = append k (slot, gk) state`, then
   `countSignedBy state' gk > threshold` → `PBftExceededSignThreshold gk n` (`373-377`, `438-449`).
   Otherwise the new state is `state'`.

The count includes the new block: a genesis key may sign at most `threshold` (475 on mainnet) of
the last `k` main blocks, counting the new block. This equals the spec's `nrSignedBks ≤ k · t`
(`cardano-ledger/eras/byron/chain/executable-spec/src/Byron/Spec/Chain/STS/Rule/SigCnt.hs:47-58`),
except that the implementation takes `t` from node config and computes `floor` in `Double`.

Not checked by PBFT:

- **The leader schedule.** Any current delegate may sign any slot. The round-robin
  `slot mod numNodes` exists only in `checkIsLeader`, for forging (`319-338`).
- **Time.** Only the generic ChainSync in-future check looks at time (0.2).

### 3.4 Ledger view and delegation map

- The ledger view is the ticked ledger's delegation map: `protocolLedgerView = toPBftLedgerView .
  getDelegationMap . tickedByronLedgerState` (`oc-byron/Ledger/Ledger.hs:280-284`;
  `oc-byron/Ledger/PBFT.hs:78-79`). It includes every delegation whose activation slot is ≤ the
  block's slot (6.2).
- Header-only validation in ChainSync uses a forecast (`oc-byron/Ledger/Ledger.hs:301-324`):
  - for the ledger tip slot: the current map;
  - for slots `< tipSlot + 1 + 2k`: `previewDelegationMap slot`, i.e. `activateDelegations slot`
    without pruning (`byron/Byron/API/Protocol.hs:13-19`);
  - beyond that: `OutsideForecastRange`, and ChainSync waits.

  Certificates take effect 2k slots after their block (6.2), so the forecast equals the ticked map
  inside the range.

### 3.5 Reapply

`reupdateChainDepState` (`oc/Protocol/PBFT.hs:381-402`) skips the signature and slot checks. It
still does the delegate lookup, the append and the threshold check, and calls `error` on failure.
The resulting state is the same as with full validation.

### 3.6 Chain-selection data

- The select view is `(blockNo, PBftTiebreakerView isEBB)` (`oc/Block/SupportsProtocol.hs:55-62`),
  wrapped with the Peras weight boost (0 in Byron) (`oc/Peras/SelectView.hs:57-68`).
- Longer chains win. At equal block number, a tip that is an EBB scores 1 and a regular block 0,
  so the chain ending in the EBB is preferred (`oc/Protocol/PBFT.hs:150-173`).
- `SimpleChainOrder` switches only on strictly greater (`oc/Protocol/Abstract.hs:309-320`).
- PBFT itself has no density or VRF tiebreak.

---

## 4. Consensus envelope and hard fork

### 4.1 `validateEnvelope`

`oc/HeaderValidation.hs:368-441`, run before PBFT in `validateHeader` (`514-535`). In order:

1. `blockNo hdr == expectedBlockNo`, exact equality → `UnexpectedBlockNo` (`378-380`).
2. `blockSlot hdr >= expectedSlotNo` → `UnexpectedSlotNo` (`381-383`).
3. prev hash check → `UnexpectedPrevHash` (`384-386`, `391-397`).
4. checkpoint: if the configured checkpoints map has an entry for `blockNo hdr`, then
   `headerHash hdr` must equal it → `CheckpointMismatch` (`387`, `431-441`).
5. `additionalEnvelopeChecks`:
   - HFC: the header's era must match the ledger view's era → `HardForkEnvelopeErrWrongEra`
     (`oc/HardFork/Combinator/Ledger.hs:392-404`);
   - then Byron's own check (`oc-byron/Ledger/HeaderValidation.hs:57-76`): an EBB's slot must
     satisfy `slot mod es == 0`, else `UnexpectedEBBInSlot`. For a decoded EBB the slot is
     `es * epoch`, so this can only fail through `Word64` wrap-around.

`expectedBlockNo` and `expectedSlotNo` come from the old tip (`AnnTip`: slot, block number, hash,
IsEBB; `oc-byron/Ledger/HeaderValidation.hs:29-32`) and the new header (`oc/HeaderValidation.hs:407-427`).

### 4.2 Block number and slot rules (`BasicEnvelopeValidation ByronBlock`)

`oc-byron/Ledger/HeaderValidation.hs:38-52`:

| old tip | new header | expected block number | minimum slot |
|---|---|---|---|
| Origin | any | 0 (`expectedFirstBlockNo`) | 0 (`minimumPossibleSlotNo`) |
| main block (b, s) | EBB | **b** (same number) | s + 1 |
| main block (b, s) | main block | b + 1 | s + 1 |
| EBB (b, s) | main block | b + 1 | **s** (may share the EBB's slot) |
| EBB (b, s) | EBB | b + 1 | s + 1 |

- Block numbers come from `ChainDifficulty` (1.2). So an EBB's difficulty must equal its
  predecessor's, and the first block after an EBB has the EBB's difficulty + 1.
- The genesis EBB has difficulty 0, and the first main block has difficulty 1.
- Slots are the flattened values (1.2).
- If the old tip and the new header are in different HFC eras, the expected values are `succ b`
  and `succ s` (`oc/HardFork/Combinator/Block.hs:246-277`).

### 4.3 Previous hash

- Main header: `abobHdrPrevHash = Just headerPrevHash`. A main header's previous hash is **always**
  `BlockHash h`, never genesis (`byron/Block/Block.hs:620-624`; `oc-byron/Ledger/Block.hs:240-246`).
- EBB: `Left` (epoch 0 or the "Genesis" attribute) becomes `GenesisHash`, and `Right h` becomes
  `BlockHash h`.
- The rule (`oc/HeaderValidation.hs:391-397`):
  - Origin tip with `GenesisHash`: OK;
  - a tip with hash h with `BlockHash h'`: OK iff h == h';
  - anything else: reject.

Consequences:

- A chain must start with an EBB whose previous hash is interpreted as genesis. A main block can
  never be first. The value of that genesis hash is checked by the ledger (1.5), not the envelope.
- A "genesis" EBB anywhere but at Origin is rejected (by both layers).
- `nodeInitChainDB` forges such a genesis EBB at slot 0 / block 0 on an empty chain. It is a
  node-local start, not a validation rule (`oc-byron/Node.hs:324-331`).
- For main blocks this envelope check is the **only** previous-hash check (1.6).
- Tip hashes: main `blake2b-256(0x82 0x01 ‖ header)`, EBB `blake2b-256(0x82 0x00 ‖ EBB header)`
  (decoding doc B.1.5).

### 4.4 Checkpoints

- Only the top-level (Cardano) checkpoints map is used. Per-era maps are empty
  (`oc/HardFork/Combinator/Basics.hs:290-294`).
- Standalone Byron uses an empty map (`oc-byron/Node.hs:237`).
- cardano-node loads `CheckpointsFile` (`node/cardano-node/src/Cardano/Node/Protocol/Cardano.hs:150-152`,
  `262`). Mainnet ships `mainnet-checkpoints.json` (`node/configuration/cardano/mainnet-config.json:6`):
  2767 entries, block numbers 2000, 4000, …, 5534000, so they include Byron block numbers.
- A checkpoint is keyed by block number, and an EBB shares its block number with its predecessor,
  so the check applies to **both** headers with that number. See open question 2.

### 4.5 Era parameters

`byronEraParams` (`oc-byron/Ledger/Ledger.hs:327-337`):

| field | value |
|---|---|
| `eraEpochSize` | `configEpochSlots` (10k) |
| `eraSlotLength` | genesis `ppSlotDuration` in milliseconds (mainnet 20000), from the **genesis** parameters, not the adopted ones (`oc-byron/Ledger/Conversions.hs:89-92`) |
| `eraSafeZone` | `StandardSafeZone (2k)` |
| `eraGenesisWin` | `2k` |

These drive HFC slot/epoch/time conversion and the forecast horizon. They do not add accept or
reject rules of their own. The Byron envelope uses the genesis `es` directly
(`oc-byron/Ledger/HeaderValidation.hs:71-76`).

### 4.6 Hard fork to Shelley

- **Trigger.** cardano-node sets `triggerHardForkShelley = CardanoTriggerHardForkAtDefaultVersion`
  unless `TestShelleyHardForkAtEpoch` is configured (`node/cardano-node/src/Cardano/Node/Protocol/Cardano.hs:204-230`).
  That becomes `TriggerHardForkAtVersion (eraProtVerLow @ShelleyEra) = TriggerHardForkAtVersion 2`
  (`oc-cardano/Node.hs:355-365`, `547-549`;
  `cardano-ledger/libs/cardano-ledger-core/internal/Cardano/Ledger/Internal/Definition/Era.hs:95`).
- **Decision function.** `singleEraTransition` → `byronTransition cfg 2 ledgerState`
  (`oc-byron/ByronHFC.hs:244-253`, `161-233`). It looks at `Byron.Inspect.protocolUpdates`
  (`oc-byron/Ledger/Inspect.hs:98-239`) for a **candidate** protocol update (a proposal that has
  enough endorsements: an element of `candidateProtocolUpdates` in the update state) with
  `pvMajor == 2`. The transition epoch is known when either of these holds:
  - `UpdateStableCandidate`: the candidate's slot `cpuSlot` is at least `2k` slots below the
    ledger tip slot (`isStable`, `oc-byron/Ledger/Inspect.hs:119`, `124-133`, `200-208`);
  - `UpdateCandidate` and "really stable": `tipBlockNo − becameCandidateBlockNo ≥ k`, using the
    block number in `ByronTransitionInfo` (`oc-byron/ByronHFC.hs:182-185`, `222-228`).

  Any matching candidate will do (`takeAny`).
- **Transition epoch.** `succ (epoch (cpuSlot + 4k))`, i.e. `floor((cpuSlot + 4k) / es) + 1`
  (`cpuEpoch`, `oc-byron/Ledger/Inspect.hs:120`, `231-239`). The ledger state field is
  `cvsUpdateState.candidateProtocolUpdates[i].{cpuProtocolVersion, cpuSlot}`. The **adopted**
  protocol version is not what triggers the fork.
- **At the boundary.** The first slot of the transition epoch is the first Shelley slot. The HFC
  translates the Byron ledger state to Shelley there (`oc-cardano/CanHardFork.hs:344-370`).
- **PBFT state.** It becomes a TPraos state carrying `lastSignedSlot` (`oc-cardano/CanHardFork.hs:393-424`).
  That code also notes that "On mainnet we stopped producing EBBs a while before the transition".
- From the transition epoch on, a Byron header fails the HFC era match (4.1 step 5).
- Mainnet's transition was at epoch 208. That is a chain fact, not derived from these sources.
- Byron's own adoption of version 2 (`tryBumpVersion`, 6.1) uses a slightly different epoch; see
  open question 3.

---

## 5. EBBs, summarised

| aspect | behaviour | cite |
|---|---|---|
| decode | protocol magic (any Int32) and body proof (any bytes) dropped; body is an indefinite list of any bytes; extra data any attribute map | decoding doc B.1.3, B.2.2 |
| slot | `es * epoch` | `byron/Block/Block.hs:533-539` |
| block number | its difficulty; must equal the predecessor's if that is a main block | 4.2 |
| envelope | block number, slot (≥ prev + 1), prev hash, checkpoint, era, `slot mod es == 0` | 4.1 |
| BlockFetch body match | none (`True` if both are EBB) | `byron/Byron/API/Common.hs:152` |
| ledger tick | full `applyChainTick` at the EBB slot: the epoch transition fires here when the EBB opens a new epoch | 1.3 |
| ledger apply | prev hash (with genesis-hash value check) and size ≤ 2,000,000, in every mode | 1.5 |
| ledger state change | `cvsPreviousHash`, `cvsLastSlot := es * epoch`, plus the tick's update and delegation changes; `byronLedgerTipBlockNo`; transition map unchanged | `byron/Byron/API/Validation.hs:184-200`; `oc-byron/Ledger/Ledger.hs:447-460` |
| PBFT | nothing checked, state unchanged, `lastSignedSlot` unaffected | `oc/Protocol/PBFT.hs:348-349`; `oc/Protocol/PBFT/State.hs:188` |
| header state | tip becomes `(slot, blockNo, hash, IsEBB)` | `oc/HeaderValidation.hs:535` |
| chain selection | at equal block number the EBB tip wins | 3.6 |
| integrity check | `True`: no signature, no magic | `oc-byron/Ledger/Integrity.hs:22-27`, `54` |

`oc-byron/EBBs.hs` lists 176 mainnet EBB hashes with their predecessors. Only db-analyser uses
that table; validation never does (`oc-byron/Ledger/Block.hs:262-269`).

---

## 6. Epoch transitions and delegation inside chain validation

This section says where chain validation calls the update and delegation subsystems and with
which slot and epoch. Their internals are documented separately.

### 6.1 Update system: `UPI.registerEpoch`

- **When.** In `applyChainTick` for block or EBB slot `s`, iff
  `s div es > cvsLastSlot div es` (`byron/Block/Validation.hs:488-496`). It therefore fires once,
  at the first block or EBB whose slot lies in a later epoch than the previous one. With EBBs that
  is the EBB. Without EBBs (late mainnet Byron) it is the first main block of the epoch. Skipped
  epochs need no special handling, because the argument is the new block's epoch.
- **Arguments.** `registerEpoch env st (s div es)` with
  `env = {protocolMagic, k, currentSlot = s, numGenKeys, delegationMap = pre-tick map}`
  (`498-505`). `registerEpoch` reads only `k` and the epoch (`byron/Update/Validation/Interface.hs:488-538`).
- **Effect.** `tryBumpVersion` with `epochFirstSlot = epoch * 10k` adopts the first element of
  `candidateProtocolUpdates` with `cpuSlot + 4k ≤ epochFirstSlot`
  (`byron/Update/Validation/Interface/ProtocolVersionBump.hs:41-63`; `kUpdateStabilityParam = 4k`,
  `byron/ProtocolConstants.hs:33-34`). If the adopted version changes, it replaces the adopted
  version and parameters and clears the candidates, the registered protocol and software
  proposals, the confirmed proposals, the votes, the endorsements and the registration slots
  (`509-519`).
- The new parameters apply to the very block being validated: its header and block size limits,
  UTxO rules and update registration (1.4).

### 6.2 Delegation: `tickDelegation` and `updateDelegation`

- **Every tick** (not just at epoch boundaries): `tickDelegation (s div es) s`
  (`byron/Byron/API/Validation.hs:119-126`; `byron/Delegation/Validation/Interface.hs:181-217`).
  1. Activate, in sequence order, every scheduled delegation with `sdSlot ≤ s`
     (`activateDelegation`, `byron/Delegation/Validation/Activation.hs:65-79`).
  2. Keep only scheduled delegations with `sdSlot ≥ s + 1`, and key/epoch registrations with
     `epoch ≥ s div es`.
- **Every main block body**: `updateDelegation env st certs` with
  `env = {protocolMagic (canonical, configured), allowedDelegators, k, currentEpoch = blockSlot div es, currentSlot = blockSlot}`
  (`byron/Block/Validation.hs:419-426`; `byron/Byron/API/Validation.hs:81-89`). For each
  certificate, `scheduleCertificate` (`byron/Delegation/Validation/Scheduling.hs:177-234`) checks,
  in order:
  1. the issuer is a genesis key;
  2. `currentEpoch ≤ cert.epoch ≤ currentEpoch + 1`;
  3. no earlier delegation by this issuer for that epoch;
  4. no delegation by this issuer already scheduled for the same activation slot;
  5. the certificate signature (`Certificate.isValid`, `byron/Delegation/Certificate.hs:164-177`).

  It then schedules the delegation at `activationSlot = blockSlot + 2k`
  (`kSlotSecurityParam`, `byron/ProtocolConstants.hs:18-19`). Afterwards `tickDelegation` runs
  again at the block slot (`Interface.hs:162-166`). That is a no-op for the new entries, since
  2k > 0.
- Delegation is therefore **slot-based**: a certificate in the block at slot s becomes visible to
  PBFT and to the update system in the first block with slot ≥ s + 2k. The epoch only bounds
  `cert.epoch` and prunes the per-epoch registrations.

### 6.3 What else happens at an epoch's first block

Nothing else in chain validation. SSC is ignored. UTxO has no epoch processing. `registerUpdate`
for the block runs after the tick, so it sees the post-transition update state (1.4, step 2e).

---

## 7. Implementation checklist

For a main block B at slot s (flattened), with ledger state L and header state H:

1. Tick L to s:
   - if `s div es > L.lastSlot div es`, run `registerEpoch(s div es)`;
   - `tickDelegation(s div es, s)`;
   - ledger view := delegation map.
2. Era: B must belong to the era of the ticked ledger. The HFC tick has already crossed into
   Shelley if s is at or past the transition.
3. Ledger, using the ticked L:
   1. `len(header 5-array) ≤ pp.maxHeaderSize`;
   2. `len(block 3-array) ≤ pp.maxBlockSize`;
   3. the dlg / tx / upd proofs match;
   4. the body's delegation certificates, with epoch = s div es and slot = s;
   5. the transactions;
   6. the update payload and the endorsement `(B.protocolVersion, hashKey(cert.delegate))`;
   7. set `lastSlot = s`, `prevHash = H(0x82 0x01 ‖ header)`;
   8. update the transition map;
   9. `tipBlockNo = difficulty`.
4. Envelope against H.tip:
   1. difficulty == expected (4.2);
   2. s ≥ minimum (4.2);
   3. prev hash == tip hash, and is never genesis for a main block;
   4. checkpoint.
5. PBFT:
   1. donna-verify `(cert.delegate[0:32], "01" ‖ genesis_key ‖ 0x09 ‖ cbor(magic) ‖ 0x85 ‖ prev ‖ proof ‖ slot ‖ difficulty ‖ extra, sig)`;
   2. s ≥ lastSignedSlot;
   3. gk = lookupR(hashKey(cert.delegate));
   4. append (s, gk), dropping the oldest entry if the window was full (k);
   5. `count(gk) ≤ floor(t · k)`.

For an EBB E with epoch e:

1. Tick L to `es · e`.
2. Era check.
3. Ledger:
   1. prev-hash rule (1.5), including the genesis value check;
   2. `len(EBB 3-array) ≤ 2,000,000`;
   3. set `prevHash = H(0x82 0x00 ‖ EBB header)`, `lastSlot = es · e`, `tipBlockNo = difficulty`.
4. Envelope (4.2 EBB rows; slot mod es == 0).
5. PBFT: no-op.

Reapply (blocks already validated in the same state): skip 3.1 to 3.3, the tx checks in 3.5, and
5.1 and 5.2. Keep every state transition.

---

## 8. Open questions

1. **Main header protocol magic.** Nothing on the consensus validation path compares
   `header[0]` with the configured magic. The ledger-only `updateBlock` does
   (`byron/Block/Validation.hs:520-525`). The storage integrity check `verifyHeaderIntegrity` does
   too (`oc-byron/Ledger/Integrity.hs:45-56`, via `nodeCheckIntegrity`, `oc-byron/Node.hs:333`).
   That integrity check runs when a block is copied from the VolatileDB to the ImmutableDB
   (`GetVerifiedBlock`, `oc/Storage/ChainDB/Impl/Background.hs:196-199`;
   `oc/Storage/VolatileDB/Impl.hs:308-313`) and throws `CorruptBlockError`, which shuts the node
   down.

   So cardano-node would adopt a correctly signed block with a wrong magic and then fail once that
   block is k deep. Only a genesis delegate could produce such a block, and every historical
   mainnet block carries the right magic. Recommendation: reject in urd. This needs a decision,
   because it is not literally what the validation code does. What the VolatileDB does with such a
   block on restart was not traced.

   **urd rejects it** (`Chain_Error_Kind.Protocol_Magic`, `src/ledger/byron/chain.odin`): such a
   block can never become immutable in cardano-node, so no chain the node finalises contains one.
2. **Checkpoints at EBB block numbers.** `validateIfCheckpoint` is keyed by block number. An EBB
   and the main block before it share a number, so at most one of them can match a checkpoint
   hash. A chain containing both would then be rejected. Whether any mainnet EBB has a block
   number that is a multiple of 2000 (the checkpoint spacing) needs chain data.
3. **Byron adoption versus HFC transition epoch.**
   - The Byron ledger adopts a candidate at the first epoch E′ with `E′ · es ≥ cpuSlot + 4k`
     (`tryBumpVersion`).
   - The HFC ends Byron at `E = floor((cpuSlot + 4k) / es) + 1`.
   - These differ by one when `(cpuSlot + 4k) mod es == 0`. Byron would then adopt version 2.0 and
     clear `candidateProtocolUpdates` one epoch before the HFC switches, after which
     `byronTransition` would return `Nothing`. Whether the HFC keeps a transition once it has been
     known was not traced.
   - Irrelevant unless mainnet's (or a target testnet's) Shelley candidate slot hits that case.
     Needs chain data.
4. **`Word64` wrap-around** in `epoch * es + slot_in_epoch` (header slot) and `es * epoch` (EBB
   slot). The decoder and everything after it use the wrapped value. `succ` on `maxBound :: Word64`
   (expected block number or slot) throws in Haskell rather than wrapping. Neither is reachable on
   a real chain. urd should wrap like the decoder and treat `succ` overflow as a rejection.
5. **Threshold `Double` semantics.** `floor(t * k)` is computed in IEEE double. The configured `t`
   is parsed by Aeson from JSON as a `Double`. urd should do the same (`f64` multiply, then
   floor), not use exact rational arithmetic, if it supports non-default thresholds.
