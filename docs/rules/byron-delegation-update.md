# Rules reference: Byron delegation and the update system

This is an implementer's reference for two Byron ledger subsystems as cardano-node runs them:
heavyweight delegation (which key may sign blocks for which genesis key) and the update system
(software and protocol update proposals, votes, endorsements, adoption). It also covers how
consensus reads the update state to end the Byron era. Every rule cites the Haskell source it
comes from. Decoding is covered by `docs/decoding/witnesses-auxdata-byron.md` ("decoding doc
B.x"). Chain validation, PBFT and the header signature are covered by
`docs/rules/byron-chain.md` ("chain doc"). The minimum fee formula is in `docs/rules/byron-utxo.md`.

Sources (pinned clones under `refs/`):

| repo | commit |
|---|---|
| cardano-ledger | `178bd36` |
| ouroboros-consensus | `9b918f8` |
| cardano-crypto | `ac2e12a` |
| crypton | `d5fb2cb` |
| cardano-node | `4d3ad24` |
| dingo (preprod genesis only) | `20328a8` |

Path abbreviations used in citations:

| abbreviation | path under `refs/` |
|---|---|
| `byron/` | `cardano-ledger/eras/byron/ledger/impl/src/Cardano/Chain/` |
| `byron-crypto/` | `cardano-ledger/eras/byron/crypto/src/Cardano/Crypto/` |
| `shelley/` | `cardano-ledger/eras/shelley/impl/src/Cardano/Ledger/Shelley/` |
| `oc/` | `ouroboros-consensus/ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/` |
| `oc-byron/` | `ouroboros-consensus/ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/` |
| `oc-cardano/` | `ouroboros-consensus/ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/` |
| `cardano-crypto/` | `cardano-crypto/src/` |
| `crypton/` | `crypton/` |
| `node/` | `cardano-node/` |

Terminology and notation:

- **k** is the genesis security parameter `gdK` (`BlockCount`, `Word64`;
  `byron/Genesis/Config.hs:91-92`). **es** = `10k` slots per epoch (`kEpochSlots`,
  `byron/ProtocolConstants.hs:44-45`; `configEpochSlots`, `byron/Genesis/Config.hs:100-101`).
  **2k** = `kSlotSecurityParam` (`byron/ProtocolConstants.hs:18-19`). **4k** =
  `kUpdateStabilityParam` (`33-34`). Mainnet and preprod: k = 2160, 2k = 4320, 4k = 8640,
  es = 21600.
- **s** is the absolute slot of the block being processed. `epoch(x) = x div es`
  (`slotNumberEpoch`, `byron/Slotting/EpochAndSlotCount.hs:83-99`).
- **NG** is the number of genesis keys: the size of `GenesisKeyHashes`, the keys of the genesis
  JSON `bootStakeholders` object (`byron/Genesis/Data.hs:93`; `byron/Genesis/Config.hs:115-116`).
  It is passed to the update rules as `Word8`; more than 255 panics (`byron/Block/Validation.hs:450-453`).
  Mainnet and preprod: NG = 7.
- **D** is the delegation map (genesis key hash ↔ delegate key hash, 1.1).
- `a +ₛ b` is `addSlotCount`: `Word64` addition **saturating** at 2^64−1
  (`byron/Slotting/SlotNumber.hs:70-73`). Every other `Word*` operation below wraps, as Haskell
  does. `Natural` is unbounded.
- **Rejected** means the block is invalid. Every error in this document rejects the whole block.
  Delegation and update errors are raised in every validation mode, including reapply (chain doc
  1.7). Error names are given for parity of reporting only.

Rules most likely to be implemented wrong:

1. A certificate activates at the first block with slot ≥ `s + 2k`, whatever its epoch field
   says. The epoch field only limits reuse (1.3, 1.4).
2. A certificate whose delegate is already a delegate is dropped at activation **without an
   error**. The block stays valid (1.4).
3. The update rules use D as ticked, before the block's own certificates (0.4).
4. Votes and endorsements are counted per genesis key (via D), not per signing key (2.6, 2.7).
5. One threshold, `(srMinThd · NG) div 10^15`, serves both confirmation and adoption. The other
   four thresholds are dead parameters (2.3).
6. An endorsement made before `confirmedSlot + 2k` is dropped for good, not deferred (2.7).
7. The proposal size limit applies only to proposals that change the protocol (2.5).
8. Changing parameters without bumping the protocol version is rejected (`pvCanFollow`, 2.5).
9. Confirmed proposals never expire. Expiry of unconfirmed ones happens at the end of a block,
   after that block's votes (2.8).
10. A software update takes effect at confirmation; a protocol update at an epoch boundary after
    endorsement (2.6, 2.9).
11. Byron never adopts version 2.0.0 on a normal chain. The HFC translates the Byron state first,
    at `floor((c + 4k) / es) + 1`, and the two formulas disagree in one edge case (4.4).

---

## 0. Shared machinery

### 0.1 Key hashes

`KeyHash = blake2b-224(sha3-256(0x58 0x40 ‖ xpub))`, where `xpub` is the 64-byte verification key
(32-byte Ed25519 point, then 32-byte chain code).

- `hashKey = KeyHash . addressHash` (`byron/Common/KeyHash.hs:29-31`, `55-56`);
  `addressHash` = `Blake2b_224 (SHA3_256 (serialize byronProtVer vk))`
  (`byron/Common/AddressHash.hs:14-22`). The CBOR of a `VerificationKey` is a byte string of the 64
  bytes (`byron-crypto/Signing/VerificationKey.hs:85-92`), always with the head `0x58 0x40`.
- The decoder accepts only the canonical head for a verification key
  (`decodeBytesCanonical`, `byron-crypto/Signing/VerificationKey.hs:94-97`), so hashing the wire
  bytes and hashing the re-encoding agree.
- The chain code is part of the hash, but not of signature verification (0.2).
- Ordering (`Ord`) is byte-lexicographic on the 28-byte digest (`AbstractHash` over
  `ShortByteString`, `byron-crypto/Hashing.hs:105-106`).
- Checked against all 7 mainnet genesis keys: `hashKey(issuerPk)` equals the `heavyDelegation`
  map key in `node/configuration/cardano/mainnet-byron-genesis.json`.

### 0.2 Signature verification

`verifySignatureDecoded pm tag vk x sig` verifies `sig` over `signTag(tag, pm) ‖ recoverBytes x`
(`byron-crypto/Signing/Signature.hs:216-233`). The primitive is cardano-crypto `verify`, which
uses only the first 32 bytes of the xpub as the Ed25519 public key and ignores the chain code
(`cardano-crypto/Cardano/Crypto/Wallet.hs:144-152`, `197-201`). That calls crypton
`Ed25519.verify` (ed25519-donna `sign_open`; `crypton/Crypto/PubKey/Ed25519.hs:135-143`).
`Ed25519.publicKey` checks only the length (`64-69`). The Ed25519 variant is discussed in chain
doc 2.4.

Sign tags (`byron-crypto/Signing/Tag.hs:71-87`). `pm` is the protocol magic bytes:

| tag | prefix | used for |
|---|---|---|
| `SignTx` | `0x01 ‖ pm` | tx witnesses |
| `SignRedeemTx` | `0x02 ‖ pm` | redeem witnesses |
| `SignUSProposal` | `0x04 ‖ pm` | update proposals |
| `SignUSVote` | `0x06 ‖ pm` | update votes |
| `SignBlock issuerVK` | `0x30 0x31 ‖ issuer_xpub(64) ‖ 0x09 ‖ pm` | block headers |
| `SignCertificate` | `0x0a ‖ pm` | delegation certificates |

**`pm` on the consensus path** is the configured `ProtocolMagicId` (`Word32`) re-serialized with
the minimal CBOR unsigned-integer head: `reAnnotateMagicId` / `reAnnotateMagic` =
`serialize' byronProtVer` (`byron/Byron/API/Common.hs:78-82`; used at
`byron/Byron/API/Validation.hs:43-45`, `76`; `byron/Block/Validation.hs:421`, `437`). Genesis
certificates use the same encoding (`byron/Block/Validation.hs:197`). The protocol magic bytes in
the block header are not used. Mainnet 764824073 → `1a 2d 96 4a 09`; preprod 1 → `01`.

### 0.3 The three signed messages

All three were verified against real signatures: the 7 mainnet and the 7 preprod genesis
certificates, and the 2 proposals and 14 votes in `testdata/byron/dingo/preprod-byron-chain.cbor`.

1. **Delegation certificate** `[epoch, issuer_vk, delegate_vk, sig]` (`isValid`,
   `byron/Delegation/Certificate.hs:164-177`). Verified with **`issuer_vk`**.

   ```
   0x0a ‖ pm ‖ H ‖ 0x30 0x30 ‖ delegate_xpub(64) ‖ E
   ```

   - `E` is the epoch field's bytes **as received** (the `Annotated` epoch,
     `byron/Delegation/Certificate.hs:209-218`), so a non-minimal epoch encoding is signed as-is.
   - The 66 + |E| bytes `"00" ‖ delegate_xpub ‖ E` are themselves CBOR-wrapped as a byte string
     (`serialize'` of a `ByteString`, `174-175`). `H` is that byte-string head with a minimal
     length: `0x58 L` with L = 66 + |E| (67 ≤ L ≤ 75, since 1 ≤ |E| ≤ 9).
   - Example, mainnet, epoch 0: `0a 1a2d964a09 58 43 3030 <delegate_xpub> 00`, 75 bytes.
   - The signer side is `signCertificate` (`115-136`).
2. **Update proposal** `[pv, ppu, sv, metadata, attributes, from_vk, sig]`
   (`byron/Update/Validation/Registration.hs:343-349`;
   `recoverProposalSignedBytes`, `byron/Update/Proposal.hs:257-259`). Verified with **`from_vk`**.

   ```
   0x04 ‖ pm ‖ 0x85 ‖ fields_1_to_5_as_received
   ```

   The body span is the bytes of the five fields, without the 7-array head
   (`byron/Update/Proposal.hs:157-173`). `0x85` stands in for the 5-array head the signer
   serialized (`235-243`).
3. **Vote** `[voter_vk, proposal_id, bool, sig]` (`byron/Update/Validation/Voting.hs:195-196`;
   `recoverSignedBytes`, `byron/Update/Vote.hs:215-227`). Verified with **`voter_vk`**.

   ```
   0x06 ‖ pm ‖ 0x82 ‖ proposal_id_item_as_received ‖ 0xf5
   ```

   `proposal_id_item` includes its byte-string head (normally `58 20` and 32 bytes). The wire
   `bool` is ignored; `0xf5` (`True`) is always signed (decoding doc B.3.10).

### 0.4 Where the two subsystems run

Consensus calls `applyChainTick`, then `validateBlock` or `validateBoundary` (chain doc 0.1). For
a block or EBB at slot s, with S the state after the previous block:

1. **Tick**, for main blocks and EBBs alike (`byron/Byron/API/Validation.hs:107-126`;
   `oc-byron/Ledger/Ledger.hs:194-201`):
   1. update system: if `epoch(s) > epoch(S.cvsLastSlot)`, `registerEpoch(epoch(s))` (2.9)
      (`byron/Block/Validation.hs:483-505`; the old epoch comes from `cvsLastSlot`,
      `byron/Byron/API/Validation.hs:49-55`);
   2. delegation: `tickDelegation(epoch(s), s)` (1.4).

   The two do not read each other's output.
2. **EBB**: no further delegation or update processing (`byron/Byron/API/Validation.hs:184-200`).
3. **Main block**, against the ticked state:
   1. PBFT looks the header's delegate key up in the **ticked** D (1.6).
   2. `headerIsValid`: header size ≤ adopted `ppMaxHeaderSize` (`byron/Block/Validation.hs:457-468`).
   3. `updateBody` (`byron/Block/Validation.hs:362-448`), with
      `currentEpoch = epoch(s)` (`byron/Byron/API/Validation.hs:81-88`) and the adopted
      parameters of the ticked update state:
      1. block size ≤ `ppMaxBlockSize` (`370-372`, `410-411`);
      2. body proofs (`375-376`);
      3. **delegation**: `updateDelegation` over the certificates in payload order
         (`379-381`, `415`; 1.3);
      4. UTxO (`384-386`);
      5. **update**: `registerUpdate(proposal, votes, endorsement)` (`389-391`; 2.4). Its D is
         the ticked map **before** this block's certificates (`441`, `408`), its slot is s
         (`413`, `439`) and `numGenKeys` = NG (`440`).
   4. `cvsLastSlot := s`.

Genesis initial state: `cvsLastSlot = 0`, the update state of 2.2, the delegation state of 1.2
(`byron/Block/Validation.hs:177-206`).

---

## 1. Heavyweight delegation

### 1.1 State

`DI.State = (schedulingState, activationState)` (`byron/Delegation/Validation/Interface.hs:64-67`).

| field | type | meaning | cite |
|---|---|---|---|
| `scheduledDelegations` | sequence of `(sdSlot: Word64, sdDelegator: KeyHash, sdDelegate: KeyHash)`, insertion order | delegations waiting for their slot | `byron/Delegation/Validation/Scheduling.hs:63-66`, `88-92` |
| `keyEpochDelegations` | set of `(EpochNumber: Word64, KeyHash)` | which genesis key already delegated for which epoch | same |
| `delegationMap` (D) | `Bimap KeyHash KeyHash`, genesis key → delegate | the active delegations | `byron/Delegation/Validation/Activation.hs:36-39`; `byron/Delegation/Map.hs:37-39` |
| `delegationSlots` | `Map KeyHash SlotNumber`, genesis key → slot its active delegation started | anti-reordering guard | same |

D is a bijection between its two columns. The operations used are `memberR d` (is d a delegate?),
`notMemberR d`, `lookupR d` (the genesis key whose delegate is d) and `insert g d`
(`byron/Delegation/Map.hs:67-86`). `Bimap.insert g d` removes any existing pair with left side
`g` and any with right side `d` before adding `(g, d)` (bimap package semantics, not vendored; see
open question 1). Activation only inserts a `d` that is not yet a right side, so only `g`'s old
pair is ever removed. **Invariant:** the left column is always exactly the set of genesis keys,
and every genesis key has exactly one delegate, which serves no other genesis key.

### 1.2 Genesis seeding

`DI.initialState` (`byron/Delegation/Validation/Interface.hs:94-137`), called from
`initialChainValidationState` (`byron/Block/Validation.hs:177-206`):

1. D starts as the identity on the genesis keys (each genesis key is its own delegate);
   `delegationSlots` maps every genesis key to 0; nothing is scheduled (`107-124`).
2. The genesis certificates are the values of the genesis `heavyDelegation` map
   (`configHeavyDelegation`, `byron/Genesis/Config.hs:118-119`), in ascending order of the map
   key (the issuer's `KeyHash`). Each is re-annotated with **canonical** bytes: the epoch and the
   whole certificate are re-serialized (`126-137`).
3. They go through `updateDelegation` with `k = 0`, `currentEpoch = 0`, `currentSlot = 0` and the
   canonical `pm` (`105`; `byron/Block/Validation.hs:195-202`). All five checks of 1.3 apply,
   including the signature and `cert.epoch ∈ {0, 1}`. The activation slot is `0 +ₛ 0 = 0`.
4. The final `tickDelegation(0, 0)` activates them all through the `sdSlot == 0` exemption of 1.4.
   A certificate whose delegate is already a delegate (for example another genesis key that is
   still self-delegated at that point) is silently dropped.
5. Any failure is fatal at node start (`oc-byron/Ledger/Ledger.hs:144-149`).

When the genesis JSON is parsed, each `heavyDelegation` key must equal `hashKey(issuerPk)`, and no
delegate may also be an issuer (`recreateGenesisDelegation`, `byron/Genesis/Delegation.hs:114-127`).

**Leftover state.** The prune keeps `keyEpochDelegations` entries with epoch ≥ 0, so
`(cert.epoch, g)` survives for each genesis certificate. With mainnet's `omega = 0`, a genesis key
cannot issue another certificate for epoch 0. It can for epoch 1. The entries disappear at the
first tick in epoch 1.

Mainnet and preprod: 7 certificates, all with epoch 0 and distinct non-genesis delegates. After
seeding, D maps each genesis key to its delegate, and `delegationSlots` is 0 everywhere.

### 1.3 Scheduling a certificate (`scheduleCertificate`)

`byron/Delegation/Validation/Scheduling.hs:177-234`, folded over the payload's certificates in
order, threading the state (`byron/Delegation/Validation/Interface.hs:154-160`).

Let g = `hashKey(issuer_vk)`, d = `hashKey(delegate_vk)`, e = the certificate's epoch (`Word64`),
E = `epoch(s)`, and a = `s +ₛ 2k` (`229`). Checks, in order:

| # | condition (must hold) | error | cite |
|---|---|---|---|
| D1 | g ∈ genesis keys | `NonGenesisDelegator` | `185-187` |
| D2 | `E ≤ e && e ≤ E + 1` | `WrongEpoch` | `190-195` |
| D3 | `(e, g) ∉ keyEpochDelegations` | `MultipleDelegationsForEpoch` | `198-200` |
| D4 | no scheduled entry with `sdSlot == a && sdDelegator == g` | `MultipleDelegationsForSlot` | `203-204`, `231-232` |
| D5 | signature valid (0.3.1) | `InvalidCertificate` | `207` |

Effect: append `(a, g, d)` to `scheduledDelegations`; insert `(e, g)` into
`keyEpochDelegations` (`210-217`). After the fold, `tickDelegation(E, s)` runs again
(`byron/Delegation/Validation/Interface.hs:162-166`). For k ≥ 1 it activates nothing new, since
a > s.

Consequences:

- **Duplicates in one block.** Every certificate in a block has the same a. A second certificate
  from the same genesis key fails D3 (same epoch) or D4 (different epoch). So there is at most one
  certificate per genesis key per block, and identical certificates repeated in a block are
  rejected.
- **Already scheduled or already used.** D3 rejects a second certificate for the same
  `(epoch, genesis key)` while that epoch is current or next.
- **The epoch is replay protection only.** Activation is purely slot-based: s + 2k, whatever e is.
  A certificate for epoch E + 1 included in epoch E can activate while E is still running.
- **Not checked at scheduling:** self-delegation (d == g), a delegate that is another genesis key,
  a delegate already serving some genesis key, re-delegating to the current delegate. These are
  resolved silently at activation (1.4).

### 1.4 Activation and pruning (`tickDelegation`)

`tickDelegation(E, t)` (`byron/Delegation/Validation/Interface.hs:181-217`), with t the slot and
E = `epoch(t)`:

1. **Activate** (`activateDelegations`, `190-198`). For each scheduled entry with `sdSlot ≤ t`,
   in insertion order, apply `activateDelegation`
   (`byron/Delegation/Validation/Activation.hs:65-79`):

   ```
   prev = delegationSlots[sdDelegator] if present else 0
   if sdDelegate ∉ right column of D  &&  (prev < sdSlot || sdSlot == 0):
       D.insert(sdDelegator, sdDelegate)        -- replaces the delegator's old delegate
       delegationSlots[sdDelegator] = sdSlot
   else:
       drop it, no error
   ```
2. **Prune** (`pruneScheduledDelegations`, `201-217`): keep scheduled entries with
   `t + 1 ≤ sdSlot` (`Word64`); keep `keyEpochDelegations` entries with epoch ≥ E.

It runs at every tick (EBB and main block) and again after scheduling (1.3). Because of the prune,
each scheduled entry is evaluated exactly once: at the first tick with t ≥ `sdSlot`. A delegation
scheduled for slot a therefore takes effect at the first block (or EBB) with slot ≥ a, **before**
that block's header is checked against D.

When an entry is dropped:

- The delegate is already a delegate of any genesis key, the issuer included. So a self-delegation
  by a self-delegated genesis key, or a re-delegation to the current delegate, is a no-op.
  Self-delegation by a genesis key whose current delegate is someone else succeeds and restores
  `g → g`.
- `prev ≥ sdSlot`. On a valid chain entries are scheduled in slot order and D4 forbids two at the
  same slot for one delegator, so this cannot happen outside genesis (hence the `sdSlot == 0`
  exemption). Implement it literally anyway.

`delegationSlots` is never pruned.

The chain-sync forecast `previewDelegationMap` runs step 1 without step 2 on the unticked state
(`byron/Byron/API/Protocol.hs:13-19`) for slots in `[tip, tip + 2k]`
(`oc-byron/Ledger/Ledger.hs:301-324`). That gives the same D.

### 1.5 Size bounds

All delegation mutations need a genesis key's signature, and the sizes are small and bounded:

- D has exactly NG entries (NG ≤ 255).
- `keyEpochDelegations` holds only epochs E and E + 1 after a tick: at most 2·NG entries.
- Pending scheduled entries: those accepted in the last 2k slots. Per genesis key that is at most 3
  (since 2k < es, a window spans at most one epoch boundary: certificates for E and E + 1 in epoch
  E, then one for E + 2 in epoch E + 1). So at most 3·NG.

A flat array indexed by genesis-key position, with linear scans for `lookupR`, is bounded.

### 1.6 Who reads D

- **PBFT**: the header's delegate key (from the block signature's certificate) must satisfy
  `lookupR(hashKey(delegate_vk))`, and the genesis key found is the one whose signing window is
  counted (`oc/Protocol/PBFT.hs:342-379`; `oc-byron/Ledger/PBFT.hs:40-73`;
  `oc-byron/Protocol.hs:26-33`). The ledger view is the ticked D (`oc-byron/Ledger/Ledger.hs:280-284`).
  The certificate embedded in the header is never signature-checked: `isValid`'s only caller is D5
  (`byron/Delegation/Validation/Scheduling.hs:207`). Its issuer key is used only to build the
  `SignBlock` tag. See chain doc 2.3 and 3.3.
- **Update system**: the proposer and every voter must be delegates; endorsements and votes are
  credited to the genesis key `lookupR` returns (2.5 to 2.7).
- **Shelley**: the Byron D is not carried over. Shelley's genesis delegates come from the Shelley
  genesis (`shelley/API/ByronTranslation.hs:120-128`).

---

## 2. The update system

### 2.1 Types

| type | representation | cite |
|---|---|---|
| `ProtocolVersion` | `(major: Word16, minor: Word16, alt: Word8)`; derived `Ord` is lexicographic in that field order | `byron/Update/ProtocolVersion.hs:28-33` |
| `SoftwareVersion` | `(appName: Text, number: Word32)` | `byron/Update/SoftwareVersion.hs:40-47` |
| `UpId` | `blake2b-256` of the whole proposal as received (decoding doc B.4.6) | `byron/Update/Proposal.hs:125-126` |
| `LovelacePortion` | `Word64` numerator over 10^15; decoding enforces ≤ 10^15 | `byron/Common/LovelacePortion.hs:52-54`, `103-104`, `116-118` |
| `SoftforkRule` | `(initThd, minThd, thdDecrement)`, three `LovelacePortion` | `byron/Update/SoftforkRule.hs:41-48` |
| `ProtocolParameters` | 14 fields, below | `byron/Update/ProtocolParameters.hs:41-69` |

`ProtocolParameters`, in field order: `ppScriptVersion: Word16`, `ppSlotDuration: Natural` (ms),
`ppMaxBlockSize: Natural`, `ppMaxHeaderSize: Natural`, `ppMaxTxSize: Natural`,
`ppMaxProposalSize: Natural`, `ppMpcThd`, `ppHeavyDelThd`, `ppUpdateVoteThd`,
`ppUpdateProposalThd` (four `LovelacePortion`), `ppUpdateProposalTTL: SlotNumber` (`Word64`, a
slot **count**), `ppSoftforkRule`, `ppTxFeePolicy` (`TxSizeLinear a b`: `a` is lovelace, `b` a
`Rational`), `ppUnlockStakeEpoch: EpochNumber`. Equality is field-wise and exact.

A proposal's `ProtocolParametersUpdate` has the same 14 fields, each optional. `apply ppu pp`
replaces each field that is present (`byron/Update/ProtocolParametersUpdate.hs:177-203`).

### 2.2 State and initial value

`UPI.State` (`byron/Update/Validation/Interface.hs:109-131`), initial value `initialState`
(`225-239`):

| # | field | type | initial |
|---|---|---|---|
| 1 | `currentEpoch` | `EpochNumber` | 0, and **never written again** |
| 2 | `adoptedProtocolVersion` | `ProtocolVersion` | `0.0.0` |
| 3 | `adoptedProtocolParameters` | `ProtocolParameters` | genesis `blockVersionData` (`configProtocolParameters`, `byron/Genesis/Config.hs:127-128`) |
| 4 | `candidateProtocolUpdates` | list of `(cpuSlot: SlotNumber, cpuProtocolVersion, cpuProtocolParameters)`, strictly descending version from the head | `[]` |
| 5 | `appVersions` | `Map ApplicationName (number: Word32, slot: SlotNumber, metadata)` | `{}` |
| 6 | `registeredProtocolUpdateProposals` (PUPs) | `Map UpId (version, parameters)` | `{}` |
| 7 | `registeredSoftwareUpdateProposals` (SUPs) | `Map UpId (SoftwareVersion, metadata)` | `{}` |
| 8 | `confirmedProposals` | `Map UpId SlotNumber` | `{}` |
| 9 | `proposalVotes` | `Map UpId (Set KeyHash)`, genesis keys | `{}` |
| 10 | `registeredEndorsements` | `Set (ProtocolVersion, KeyHash)`, genesis keys | `{}` |
| 11 | `proposalRegistrationSlot` | `Map UpId SlotNumber` | `{}` |

`metadata` is `Map SystemTag InstallerHash` (`byron/Update/Validation/Registration.hs:125-127`).
The environment is `(pm, k, currentSlot = s, numGenKeys = NG, D)`
(`byron/Update/Validation/Interface.hs:93-106`).

### 2.3 The threshold

```
t = upAdptThd(NG, adoptedPP) = floor(srMinThd / 10^15 · NG) = (srMinThd · NG) div 10^15
```

(`byron/Update/ProtocolParameters.hs:217-221`). This is exact `Rational` arithmetic. Since
srMinThd ≤ 10^15 and NG ≤ 255, the product is below 2^58 and fits a `u64`. The same t is the
**vote confirmation** threshold (`byron/Update/Validation/Interface.hs:396`) and the **endorsement
adoption** threshold (`452`). It is computed from the adopted parameters at the time of each vote
or endorsement. Mainnet and preprod: `(6·10^14 · 7) div 10^15 = 4`.

`ppUpdateVoteThd`, `ppUpdateProposalThd`, `srInitThd` and `srThdDecrement` are never read.
cardano-sl's decaying softfork threshold is not implemented.

### 2.4 Per-block rule (`registerUpdate`)

`byron/Update/Validation/Interface.hs:244-256`. The signal is built from the block
(`byron/Block/Validation.hs:443-448`):

- `proposal`: the payload's optional proposal (at most one per block);
- `votes`: the payload's votes, in order;
- `endorsement = (header protocol version, hashKey(header delegate_vk))`
  (`blockIssuer` = the delegate key of the block signature's certificate,
  `byron/Block/Header.hs:274-276`).

It runs for **every main block**, even with an empty payload, and never for EBBs:

1. the proposal, if any (2.5);
2. the votes, then the application-version update (2.6);
3. the endorsement (2.7), then pruning (2.8).

### 2.5 Proposal registration

`registerProposal` (`byron/Update/Validation/Registration.hs:337-364`) and
`registerProposalComponents` (`376-449`). Inputs: the adopted version `apv` and parameters `app`,
`appVersions`, D, s. Let pv, ppu, sv = (name, n) and metadata come from the proposal body.
Checks, in order:

| # | condition (must hold) | error | cite |
|---|---|---|---|
| R1 | `hashKey(from_vk)` ∈ right column of D (a current delegate) | `InvalidProposer` | `339-340` |
| R2 | signature valid (0.3.2) | `InvalidSignature` | `343-349` |
| R3 | `pvChanged ∨ svChanged ∨ exempt` | `NullUpdateProposal` | `377-378` |

with

```
newPP     = apply(ppu, app)
pvChanged = not (pv == apv && newPP == app)                                    -- 406-407
svChanged = name ∉ appVersions || appVersions[name].number != n                -- 402-404
exempt    = pm == 633343913 && s ∈ {969188, 1915231}                           -- 442-449 (staging only)
```

**R4, if `pvChanged`** (`registerProtocolUpdate`, `460-486`):

| # | condition (must hold) | error | cite |
|---|---|---|---|
| R4a | no PUP has version pv | `DuplicateProtocolVersion` | `469-470` |
| R4b | `pvCanFollow(pv, apv)`, below | `InvalidProtocolVersion` | `473-474`, `489-497` |
| R4c | proposal size: the length of the whole proposal as received (the 7-array) ≤ `app.ppMaxProposalSize` | `ProposalTooLarge` | `511-513`, `531-533` |
| R4d | `newPP.ppMaxBlockSize ≤ 2 · app.ppMaxBlockSize` (`Natural`, no overflow) | `MaxBlockSizeTooLarge` | `516-518` |
| R4e | `newPP.ppMaxTxSize < newPP.ppMaxBlockSize` (strict) | `MaxTxSizeTooLarge` | `521-523` |
| R4f | `(newPP.ppScriptVersion − app.ppScriptVersion) mod 2^16 ≤ 1` (`Word16` subtraction; the `0 ≤` half is vacuous) | `InvalidScriptVersion` | `526-529`, `542` |

Then `PUPs[UpId] := (pv, newPP)` (`478-482`).

```
pvCanFollow(new, adopted) =
    adopted < new                                     -- lexicographic (major, minor, alt)
 && case (new.major − adopted.major) mod 2^16 of     -- Word16
      0 -> new.minor == adopted.minor + 1             -- Word16, wraps
      1 -> new.minor == 0
      _ -> False
```

`alt` is unconstrained. A proposal with pv == apv but different parameters has
`pvChanged = True` and fails R4b: **every parameter change needs a version bump**. From `M.m.a` the
valid successors are `M.(m+1).*` and `(M+1).0.*`.

**R5, if `svChanged`** (`registerSoftwareUpdate`, `559-583`):

| # | condition (must hold) | error | cite |
|---|---|---|---|
| R5a | every metadata key (system tag): `Text.length ≤ 10`, then every char < U+0080 | `SystemTagTooLong`, `SystemTagNotAscii` | `561`; `byron/Update/SystemTag.hs:67-68`, `113-117` |
| R5b | no SUP has the same `appName` (whatever its number) | `DuplicateSoftwareVersion` | `564-569` |
| R5c | `appName`: `Text.length ≤ 12`, then every char < U+0080 | `SoftwareVersionError` (`ApplicationNameTooLong` / `NotAscii`) | `572`; `byron/Update/SoftwareVersion.hs:112-116`; `byron/Update/ApplicationName.hs:113-123` |
| R5d | `svCanFollow`: if name ∉ appVersions then n ∈ {0, 1}, else n == current + 1 (`Word32`, wraps) | `InvalidSoftwareVersion` | `575-576`, `591-597` |

Then `SUPs[UpId] := (sv, metadata)` (`579-583`).

**R6.** `proposalRegistrationSlot[UpId] := s` (`byron/Update/Validation/Interface.hs:275-276`).

Notes:

- `Text.length` counts code points. Both length checks run before the ASCII check, which only
  changes the error reported.
- **The size limit R4c applies only to proposals that change the protocol.** A software-only
  proposal is bounded only by the block size.
- Nothing else about the new parameters is checked: not `ppMaxHeaderSize` (against the block size
  or at all), not `ppMaxProposalSize`, `ppSlotDuration`, the thresholds (beyond decoding),
  `ppUpdateProposalTTL`, the softfork rule, the fee policy (a negative `b` decodes and is accepted)
  or `ppUnlockStakeEpoch`.
- There is no explicit "UpId already registered" check. R4a and R5b reject a resubmission of an
  identical proposal, and the insertions would overwrite anyway.
- `newPP` is computed against the parameters adopted at registration. Adoption clears every
  proposal (2.9), so they are also the parameters in force when the proposal is adopted.

### 2.6 Votes, confirmation, application versions

`registerVotes` (`byron/Update/Validation/Interface.hs:316-356`) folds `registerVote` (`361-399`;
`byron/Update/Validation/Voting.hs:127-209`) over the votes in order. For each vote, with
v = `hashKey(voter_vk)` and u the voted `UpId`:

| # | condition (must hold) | error | cite |
|---|---|---|---|
| V1 | u ∈ keys(`proposalRegistrationSlot`) | `VotingProposalNotRegistered` | `Voting.hs:181-182`; `Interface.hs:391` |
| V2 | g = `lookupR(v)` exists | `VotingVoterNotDelegate` | `Voting.hs:185-187` |
| V3 | g ∉ `proposalVotes[u]` | `VotingVoteAlreadyCast` | `Voting.hs:190-192` |
| V4 | signature valid (0.3.3) | `VotingInvalidSignature` | `Voting.hs:195-196` |

Effect: `proposalVotes[u] ∪= {g}` (`Voting.hs:199`). Then, if `|proposalVotes[u]| ≥ t` and
u ∉ `confirmedProposals`: `confirmedProposals[u] := s` (`139-142`, `154-156`).

- Votes are counted per **genesis key**, not per voting key. A genesis key whose delegate changed
  cannot vote again.
- A proposal can be voted on in the block that registers it (the proposal is processed first).
- Votes for an already confirmed proposal are still validated and recorded. They change nothing
  else.

After all votes (also when there are none; `Interface.hs:334-355`): for every SUP whose UpId is in
`confirmedProposals`, set `appVersions[appName] := (n, s, metadata)`, overwriting, and remove that
SUP. **A software update takes effect when its proposal is confirmed.** It needs no endorsement.
`appVersions` is only read by R3 and R5d; it is never cleared, not even by adoption.

### 2.7 Endorsement and candidates

`registerEndorsement` (`byron/Update/Validation/Interface.hs:409-480`) calls
`Endorsement.register` (`byron/Update/Validation/Endorsement.hs:149-222`). Let pv be the header's
protocol version and i = `hashKey(delegate_vk)`. Look at the PUPs **before** this block's prune:

- **No PUP has version pv:** nothing happens. The endorsement is not recorded (`158`).
- **Two or more:** `MultipleProposalsForProtocolVersion` (`184`). R4a makes this unreachable.
- **Exactly one, (u, pp′)** (`160-182`):
  - If u ∈ `confirmedProposals` and `confirmedProposals[u] +ₛ 2k ≤ s` (`195-198`):
    1. `registeredEndorsements ∪= {(pv, lookupR(i))}` when `lookupR(i)` exists, else unchanged
       (`211-222`);
    2. n = the number of endorsements with version pv (`200-205`);
    3. if n ≥ t: prepend `(s, pv, pp′)` to `candidateProtocolUpdates` when the list is empty or its
       head's version is `< pv`, otherwise leave the list alone (`163-178`;
       `updateCandidateProtocolUpdates`, `230-237`).
  - Otherwise nothing happens. **The endorsement is dropped, not deferred**: it does not count
    later.

So a protocol update becomes a **candidate** in the block where the t-th distinct genesis key
endorses its version, provided the proposal was confirmed at least 2k slots earlier. `cpuSlot` is
that block's slot, and later endorsements do not move it. Every block endorses whatever version
its header carries: nodes signal readiness by producing blocks with the new version.

Nothing on the validation path compares the header's protocol version with the adopted one (chain
doc 4.1). The header version is only an endorsement signal.

### 2.8 Expiry and pruning

Right after the endorsement, in the same call (`byron/Update/Validation/Interface.hs:419-446`,
`480`), with TTL = `adoptedPP.ppUpdateProposalTTL`:

```
keep = { u | s ≤ proposalRegistrationSlot[u] +ₛ TTL } ∪ keys(confirmedProposals)
PUPs, SUPs, proposalVotes, proposalRegistrationSlot  := restricted to keep
registeredEndorsements := { (pv, g) | pv is the version of some remaining PUP }
```

`confirmedProposals`, `appVersions` and the candidates are not touched.

- An **unconfirmed** proposal registered at slot r is removed at the end of the first main block
  with slot > r + TTL. Expiry is block-driven: the votes of that block run before the prune and
  can still confirm it.
- A **confirmed** proposal is never removed by the prune. Its version stays taken (R4a) until an
  adoption clears everything. A confirmed protocol update that never gathers t endorsements blocks
  its version forever.

### 2.9 Epoch transition: adoption

`registerEpoch(E)` (`byron/Update/Validation/Interface.hs:488-538`) and `tryBumpVersion`
(`byron/Update/Validation/Interface/ProtocolVersionBump.hs:41-63`) run at the tick into a new
epoch E (0.4). It runs once even if epochs were skipped, with E the new block's epoch.

```
F      = E · es                                        -- epochFirstSlot (kEpochSlots k), Interface.hs:528
stable = [ c in candidateProtocolUpdates, in list order | c.cpuSlot +ₛ 4k ≤ F ]
if stable != [] && stable[0].version != adoptedProtocolVersion:
    adoptedProtocolVersion    := stable[0].version
    adoptedProtocolParameters := stable[0].parameters      -- all 14 fields at once
    candidates, PUPs, SUPs, confirmedProposals, proposalVotes,
    registeredEndorsements, proposalRegistrationSlot := empty
```

(`495-519`). `appVersions` and `currentEpoch` are left as they are.

- `stable[0]` is the highest stable version, because the list descends. A higher candidate that is
  not stable yet is discarded with the rest of the state.
- Timeline of a protocol update: confirmed at slot c; endorsements count from slot c + 2k; it
  becomes a candidate at slot `c_c` with the t-th endorsement; it is adopted at the first epoch E
  with `E · es ≥ c_c + 4k`, i.e. `E = ceil((c_c + 4k) / es)`. It is in force from the tick into E,
  so for every check of the first block (or EBB) of E, header size included.
- On a Cardano network, a candidate with major version 2 normally never reaches this rule: the
  hard-fork combinator ends Byron first (section 4). See 4.4 for the exception.

### 2.10 Transitions by field

| field | proposal (2.5) | votes (2.6) | endorsement (2.7) | prune (2.8) | adoption (2.9) |
|---|---|---|---|---|---|
| `currentEpoch` | | | | | |
| `adoptedProtocolVersion` | | | | | set |
| `adoptedProtocolParameters` | | | | | set |
| `candidateProtocolUpdates` | | | maybe prepend | | clear |
| `appVersions` | | upsert confirmed SUPs | | | |
| PUPs | insert | | | restrict | clear |
| SUPs | insert | remove confirmed | | restrict | clear |
| `confirmedProposals` | | insert | | | clear |
| `proposalVotes` | | insert | | restrict | clear |
| `registeredEndorsements` | | | insert | filter by version | clear |
| `proposalRegistrationSlot` | insert | | | restrict | clear |

When adoption leaves the version unchanged, nothing changes at all.

### 2.11 Worked example: the preprod Byron chain

`testdata/byron/dingo/preprod-byron-chain.cbor` is preprod's whole Byron chain (an EBB and 45
main blocks). Genesis parameters (`refs/dingo/config/cardano/preprod/byron-genesis.json`):
pm = 1, k = 2160, NG = 7, srMinThd = 6·10^14 (so t = 4), TTL = 10000, `maxProposalSize` = 700.
Replaying the rules above over the fixture gives this. All proposal, vote and genesis-certificate
signatures verify with the layouts of 0.3.

| block | slot | event |
|---|---|---|
| 2 | 2163 | proposal: version 1.0.0, software `cardano-sl` 1, empty ppu, 310 bytes. The name is new to `appVersions`, so it registers both a PUP and a SUP. 7 votes; the 4th confirms it at 2163. `appVersions[cardano-sl] = (1, 2163, {linux})` |
| 4 | 6480 | header version 1.0.0: dropped, since 2163 + 4320 = 6483 > 6480 |
| 5 to 8 | 8641, 10802, 12961, 15122 | four distinct genesis keys endorse 1.0.0; candidate `(15122, 1.0.0)` |
| tick, epoch 1 | 21600 | 15122 + 8640 = 23762 > 21600: not adopted |
| tick, epoch 2 | 43200 | 1.0.0 adopted, state cleared |
| 23 | 43211 | proposal: version 2.0.0, software `cardano-sl` 1 (unchanged, so protocol-only). 7 votes; confirmed at 43211 |
| 24 to 26 | 45359, 45366, 47521 | version 2.0.0 endorsements dropped (< 43211 + 4320 = 47531) |
| 27 to 30 | 49682, 51843, 54002, 56163 | candidate `(56163, 2.0.0)` |
| hard fork | | `(56163 + 8640) div 21600 + 1 = 4`: Shelley starts at epoch 4. The last Byron block is at slot 84242, in epoch 3 (`testdata/byron/dingo/preprod-byron-last-84242.cbor`) |

The fixture has no delegation certificates in blocks.

---

## 3. Protocol parameters that matter after adoption

All checks use the adopted parameters of the **ticked** state of the block being validated. A new
set applies from the tick into the adoption epoch, so already to the first block of that epoch.

| parameter | used for | comparison | cite |
|---|---|---|---|
| `ppMaxHeaderSize` | header size (full validation only) | `headerLength ≤ ppMaxHeaderSize` | `byron/Block/Validation.hs:457-468` |
| `ppMaxBlockSize` | block size (full validation only); R4d | `blockLength ≤ ppMaxBlockSize` | `byron/Block/Validation.hs:370-372`, `410-411` |
| `ppMaxTxSize` | size of each `[tx, witnesses]`; R4e; the mempool | `txSize ≤ ppMaxTxSize` | `byron/UTxO/Validation.hs:190-193`, `221`; `oc-byron/Ledger/Mempool.hs:176` |
| `ppTxFeePolicy` | minimum fee `a + ceil(b · txSize)`; redeem txs exempt | utxo doc 3.4 | `byron/UTxO/Validation.hs:196-235`; `byron/Common/TxSizeLinear.hs:81-86` |
| `ppMaxProposalSize` | R4c | `≤` | 2.5 |
| `ppScriptVersion` | R4f only | | 2.5 |
| `ppUpdateProposalTTL` | proposal expiry | `s ≤ r +ₛ TTL` keeps | 2.8 |
| `ppSoftforkRule.srMinThd` | t | `floor` | 2.3 |
| `ppSlotDuration` | **nothing**. Consensus takes the slot length from the genesis parameters (`oc-byron/Ledger/Conversions.hs:89-92`; `oc-byron/Ledger/Ledger.hs:327-337`). An adopted change has no effect | | |
| `ppMpcThd`, `ppHeavyDelThd`, `ppUpdateVoteThd`, `ppUpdateProposalThd`, `srInitThd`, `srThdDecrement`, `ppUnlockStakeEpoch` | nothing (`isBootstrapEraPP` has no caller) | | `byron/Update/ProtocolParameters.hs:207-208` |

Block producers read `ppMaxBlockSize` through `getMaxBlockSize`, a `fromIntegral` to `Word32`
(`byron/Byron/API/Common.hs:68-72`). Validation compares in `Natural`.

---

## 4. The hard fork to Shelley

The chain doc covers the same ground from the consensus side (chain doc 4.6, open question 3). This
section adds what the update state contributes and resolves that open question.

### 4.1 Trigger

cardano-node configures `TriggerHardForkAtVersion 2` unless `TestShelleyHardForkAtEpoch` is set
(`node/cardano-node/src/Cardano/Node/Protocol/Cardano.hs:202-230`;
`oc-cardano/Node.hs:344-365`, `545-550`). 2 is Shelley's `eraProtVerLow`
(`cardano-ledger/libs/cardano-ledger-core/internal/Cardano/Ledger/Internal/Definition/Era.hs:95`).
The test override `TriggerHardForkAtEpoch e` ignores the ledger (`oc-byron/ByronHFC.hs:244-253`).

### 4.2 What is inspected

After every block, the HFC asks `singleEraTransition` → `byronTransition 2` about the **unticked**
Byron ledger state at the tip (`oc-byron/ByronHFC.hs:161-233`). It builds `protocolUpdates`
(`oc-byron/Ledger/Inspect.hs:98-108`): the candidates in list order, then the PUPs that have no
candidate with the same version, in UpId order. For each entry with **major version exactly 2**:

- **Candidate** with slot c. Its epoch is `e = (c + 4k) div es + 1` (`cpuEpoch`, `231-239`;
  `History.addSlots` is plain `Word64` addition, `oc/HardFork/History/Util.hs:22-23`). The
  transition is known as soon as one of these holds:
  - `tipSlot − c ≥ 2k`, with `tipSlot = cvsLastSlot` (`UpdateStableCandidate`; `isStable`,
    `Inspect.hs:119`, `124-133`, `200-208`);
  - `tipBlockNo − b ≥ k`, where b is the block number recorded for this version in
    `ByronTransitionInfo` ("really stable", `oc-byron/ByronHFC.hs:182-185`, `222-228`).
- **Not a candidate:** ignored (`189-191`).

The first entry that yields an epoch wins (`takeAny = listToMaybe`, `232-233`).

`ByronTransitionInfo` (`oc-byron/Ledger/Ledger.hs:112-126`) maps a version to the block number in
which it first appeared among the candidates. After each main block it keeps the old number for
versions that are still candidates, adds the block's number for new ones, and drops versions that
are no longer candidates (`410-441`). EBBs leave it alone (`447-460`). Block numbers come from the
header's chain difficulty (`oc-byron/Ledger/Block.hs:237`). An EBB has its predecessor's number
(`oc-byron/Ledger/HeaderValidation.hs:43-47`).

### 4.3 What happens at the boundary

When the HFC ticks to a slot ≥ `e · es` while the transition is known to be e, it ends the Byron
era (`extendToSlot`, `oc/HardFork/Combinator/State.hs:219-330`, `266-286`;
`mkUpperBound`, `oc/HardFork/History/Summary.hs:126-150`; Byron starts at slot 0, epoch 0). It
translates the **unticked** Byron state, so Byron's `registerEpoch(e)` never runs. The
translation keeps only the UTxO and the tip (`oc-cardano/CanHardFork.hs:344-371`;
`shelley/API/ByronTranslation.hs:90-96`). The update state and D are dropped. Shelley's parameters
and genesis delegates come from the Shelley genesis. The final Byron update state still shows the
pre-Shelley adopted version (1.0.0 on preprod).

Preprod: e = 4, which matches the fixture (2.11). Mainnet's last Byron block is at slot 4492799,
the last slot of epoch 207 (`testdata/byron/dingo/mainnet-byron-last-4492799.cbor`), consistent
with Shelley starting at epoch 208. The mainnet candidate slot was not recomputed here.

### 4.4 Ledger and HFC disagree when `(c + 4k) mod es == 0`

The Byron ledger adopts at `ceil((c + 4k) / es)` (2.9). The HFC switches at
`floor((c + 4k) / es) + 1`. They are equal unless `c + 4k` is a multiple of es, which on mainnet
parameters means `c mod 21600 == 12960`. In that case, with E = `(c + 4k) / es`:

1. The tip before epoch E knows the transition to be E + 1, so the tick into E stays in Byron.
2. Byron's `registerEpoch(E)` finds `c + 4k ≤ E · es`, adopts 2.0.0 and clears the candidates.
3. The HFC keeps no memory of the transition. `TransitionInfo` is recomputed from the current state
   on every call (`mostRecentTransitionInfo`, `oc/HardFork/Combinator/State.hs:120-142`;
   `whenExtend`, `266-286`). Once the candidates are gone, `byronTransition` returns `Nothing`.
   So after that block **Byron continues indefinitely** with adopted version 2.0.0, until some
   later proposal with major version 2 (2.1.0 can follow 2.0.0) becomes a stable candidate.

urd should implement both rules literally rather than one shared formula. That keeps it identical
to cardano-node even in this case. Whether any real network has hit it is open question 2.

The other conceivable gap, a tick into e before the transition is known, cannot arise on a chain
consensus accepts. It would need the tip to be below `c + 2k` while the next block is at
`e · es ≥ c + 4k`, a gap of more than 2k slots. That exceeds the Byron forecast range
`[tip, tip + 2k]` (`oc-byron/Ledger/Ledger.hs:301-324`). See open question 3.

---

## 5. Notes for urd

1. **Exact `Natural` parameters.** (Done: urd now keeps each `Natural` as a `u64` plus the
   big-endian magnitude of larger values, interned into an append-only pool, and compares exactly;
   `src/ledger/byron/update_rules.odin`.) An earlier version stored parameter sizes above 2^64 as
   `max(u64)`, on the grounds that "sizes are compared against lengths that fit 64 bits". The
   update rules also compare parameters with **each other**:
   - R3 tests `apply(ppu, app) == app`;
   - R4d tests `new ≤ 2 · old`;
   - R4e tests `maxTx < maxBlock`.

   `ppMaxHeaderSize`, `ppMaxProposalSize` and `ppSlotDuration` are unbounded (2.5). Suppose
   `maxHeaderSize = 2^70` is adopted and a later proposal has pv == apv and `maxHeaderSize = 2^71`.
   Haskell sees a change and rejects the block (R4b). Saturation makes the two equal: R3 then sees
   no protocol change, and the block can be accepted when the software version changes. Only
   genesis delegates can submit such proposals, but exactness requires keeping the full value (for
   example `u64` plus a span to the big-endian bytes, compared exactly). Also, `2 · old` overflows
   `u64` once old ≥ 2^63; compute it in `u128`.
2. **Fee-policy equality.** R3 compares `TxSizeLinear` with `a` rounded to lovelace and `b` exact.
   Two proposals whose `a` differ only below the rounding are equal. The current representation
   (`a: u64` rounded, `b: Nano` exact) is right for this.
3. **State sizes.** Every mutation is gated by a genesis delegate's signature:
   - PUPs: at most 512, the version successors `M.(m+1).*` and `(M+1).0.*` with an 8-bit `alt`;
   - SUPs: at most one per block for TTL slots;
   - votes and endorsements: at most NG per proposal and per version;
   - candidates: at most 512.

   Sorted flat arrays with linear or binary search stay within the "no attacker-sized quadratic
   loops" rule. `appVersions` grows with confirmed software updates over history.
4. **Order matters only in a few places.** Activation runs in scheduling order (1.4). The candidate
   list keeps its own order (2.7, 2.9). The HFC takes the first matching entry (4.2). Map order by
   UpId never affects a result.
5. **Epoch of a block.** Delegation's E and the update rules use `epoch(s)` of the absolute slot,
   not the header's epoch field (`byron/Byron/API/Validation.hs:81-88`).
6. **Signed bytes come from the wire.** The certificate epoch, proposal body and vote proposal id
   are used exactly as received (0.3). Genesis certificates are the exception: they are canonical
   re-encodings (1.2).
7. **Ledger-state parity.** To compare with cardano-node's `GetUpdateInterfaceState` query
   (`oc-byron/Ledger/Ledger.hs:243-253`), keep `currentEpoch` at 0 and keep `delegationSlots`
   unpruned.

---

## 6. Open questions

1. **`Data.Bimap` semantics.** The bimap package is not vendored. This document assumes `insert`
   deletes both overlapping pairs and that `fromList` is a left fold of `insert`. Given the
   activation guard, only the left overlap (the delegator's old pair) is reachable, so the result
   does not depend on the right-overlap behaviour.
2. **The 4.4 edge case on real chains.** Was any network's major-2 candidate formed at a slot with
   `(c + 4k) mod es == 0`? Preprod's was not (`(56163 + 8640) mod 21600 = 3`). Mainnet's candidate
   slot is not in the fixtures. The behaviour described in 4.4 is derived from the code, not
   tested.
3. **Forecast horizon for EBB headers.** 4.4's claim that a known-late transition cannot occur
   relies on every header, EBBs included, needing a ledger-view forecast within 2k slots of the
   tip. The chain-sync path for EBB headers was not traced here (see chain doc 0.2).
4. **Ed25519 edge semantics** (non-canonical S, small-order or non-canonical points) of crypton's
   donna `sign_open`. They apply to all four Byron signature kinds. They were not re-derived here;
   see chain doc 2.4.
5. **Mainnet coverage.** The rules here were replayed only on preprod (2 proposals, 14 votes, 14
   genesis certificates). Mainnet had more update traffic, possibly including software-only
   proposals and parameter changes. Suggested test: replay mainnet Byron and compare D and the
   update state with cardano-node's ledger state at each epoch boundary.
6. **Delegation certificates in mainnet blocks.** A comment in the Shelley translation says "no
   Byron genesis delegations have happened yet" (`shelley/API/ByronTranslation.hs:120-128`). If
   that means no certificate was ever included in a mainnet block, 1.3 and 1.4 are exercised only
   by genesis. Not checked against chain data.
