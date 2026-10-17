package ledger

import "urd:base"

// A contiguous run of rows in one of the block tables.
Range :: struct {
	start: u32,
	count: u32,
}

range_end :: #force_inline proc "contextless" (r: Range) -> u32 {
	return r.start + r.count
}

Tx_In :: struct {
	id:    base.Tx_Id,
	index: u16,
}

// Haskell `Ord TxIn`: tx id bytes, then index.
tx_in_less :: proc(a, b: Tx_In) -> bool {
	if a.id != b.id {
		return hash32_less(base.Hash32(a.id), base.Hash32(b.id))
	}
	return a.index < b.index
}

Datum_Kind :: enum u8 {
	None,
	Hash,
	Inline,
}

Tx_Out :: struct {
	// The whole output item: its size is what Babbage's min-UTxO rule uses.
	raw:        base.Span,
	address:    Address,
	coin:       u64,
	assets:     Range,
	datum_kind: Datum_Kind,
	// Given (Hash), or Blake2b-256 of the inline datum's bytes (Inline).
	datum_hash: base.Hash32,
	// Inline datum: the Plutus Data bytes inside the tag-24 wrapper.
	datum:      base.Span,
	// Script reference: the `[language, script]` bytes inside the tag-24
	// wrapper; zero length when absent.
	script_ref: base.Span,
}

Withdrawal :: struct {
	account: Reward_Account,
	coin:    u64,
}

Tx_Flag :: enum u8 {
	Ttl,
	Validity_Start,
	Aux_Data,
	Aux_Data_Hash,
	Script_Data_Hash,
	Network_Id,
	Collateral_Return,
	Total_Collateral,
	Treasury,
	Donation,
	Update,
	Mint,
	// Alonzo onwards: false for a transaction listed as phase-2 invalid.
	Valid,
}

Tx_Flags :: bit_set[Tx_Flag;u16]

// One transaction of a block. Ranges index the block tables; spans index the
// era block's bytes.
Tx :: struct {
	id:                base.Tx_Id,
	body:              base.Span,
	witnesses:         base.Span,
	aux_data:          base.Span,
	// Serialised size as the ledger computes it for fees and limits.
	size:              u32,
	flags:             Tx_Flags,
	fee:               u64,
	ttl:               u64,
	validity_start:    u64,
	aux_data_hash:     base.Hash32,
	script_data_hash:  base.Hash32,
	network_id:        Network,
	total_collateral:  u64,
	treasury:          u64,
	donation:          u64,
	// Index into `outputs` of the collateral return output.
	collateral_return: u32,
	inputs:            Range,
	outputs:           Range,
	collateral:        Range,
	ref_inputs:        Range,
	certs:             Range,
	withdrawals:       Range,
	mint:              Range,
	required_signers:  Range,
	votes:             Range,
	proposals:         Range,
	// Pre-Conway protocol parameter update proposal.
	update:            Update,
	// Witnesses.
	vkey_witnesses:    Range,
	bootstrap_wits:    Range,
	scripts:           Range,
	datums:            Range,
	redeemers:         Range,
	// Raw redeemers and datums values from the witness set, for the script
	// integrity hash (zero length when absent).
	redeemers_raw:     base.Span,
	datums_raw:        base.Span,
	// Auxiliary data scripts (validated by the UTXOW rule, not witnesses).
	aux_scripts:       Range,
}

// Decoded transactions of one block. Rows are flattened across all
// transactions of the block; reset and refill per block to reuse capacity.
Block_Tables :: struct {
	txs:              [dynamic]Tx,
	inputs:           [dynamic]Tx_In,
	collateral:       [dynamic]Tx_In,
	ref_inputs:       [dynamic]Tx_In,
	outputs:          [dynamic]Tx_Out,
	assets:           [dynamic]Asset,
	mint:             [dynamic]Asset,
	withdrawals:      [dynamic]Withdrawal,
	required_signers: [dynamic]base.Key_Hash,
	certs:            [dynamic]Cert,
	pool_params:      [dynamic]Pool_Params,
	key_hashes:       [dynamic]base.Key_Hash,
	genesis_delegs:   [dynamic]Genesis_Delegation,
	mirs:             [dynamic]Mir,
	mir_entries:      [dynamic]Mir_Entry,
	votes:            [dynamic]Vote,
	proposals:        [dynamic]Proposal,
	pparam_updates:   [dynamic]PParams_Update,
	update_proposals: [dynamic]Update_Proposal,
	cost_models:      [dynamic]Cost_Model,
	cost_values:      [dynamic]i64,
	treasury_wdrls:   [dynamic]Withdrawal,
	committee_creds:  [dynamic]Committee_Member,
	vkey_witnesses:   [dynamic]Vkey_Witness,
	bootstrap_wits:   [dynamic]Bootstrap_Witness,
	scripts:          [dynamic]Script,
	datums:           [dynamic]Datum,
	redeemers:        [dynamic]Redeemer,
	aux_scripts:      [dynamic]Script,
}

tables_init :: proc(t: ^Block_Tables, allocator := context.allocator) {
	t.txs = make([dynamic]Tx, allocator)
	t.inputs = make([dynamic]Tx_In, allocator)
	t.collateral = make([dynamic]Tx_In, allocator)
	t.ref_inputs = make([dynamic]Tx_In, allocator)
	t.outputs = make([dynamic]Tx_Out, allocator)
	t.assets = make([dynamic]Asset, allocator)
	t.mint = make([dynamic]Asset, allocator)
	t.withdrawals = make([dynamic]Withdrawal, allocator)
	t.required_signers = make([dynamic]base.Key_Hash, allocator)
	t.certs = make([dynamic]Cert, allocator)
	t.pool_params = make([dynamic]Pool_Params, allocator)
	t.key_hashes = make([dynamic]base.Key_Hash, allocator)
	t.genesis_delegs = make([dynamic]Genesis_Delegation, allocator)
	t.mirs = make([dynamic]Mir, allocator)
	t.mir_entries = make([dynamic]Mir_Entry, allocator)
	t.votes = make([dynamic]Vote, allocator)
	t.proposals = make([dynamic]Proposal, allocator)
	t.pparam_updates = make([dynamic]PParams_Update, allocator)
	t.update_proposals = make([dynamic]Update_Proposal, allocator)
	t.cost_models = make([dynamic]Cost_Model, allocator)
	t.cost_values = make([dynamic]i64, allocator)
	t.treasury_wdrls = make([dynamic]Withdrawal, allocator)
	t.committee_creds = make([dynamic]Committee_Member, allocator)
	t.vkey_witnesses = make([dynamic]Vkey_Witness, allocator)
	t.bootstrap_wits = make([dynamic]Bootstrap_Witness, allocator)
	t.scripts = make([dynamic]Script, allocator)
	t.datums = make([dynamic]Datum, allocator)
	t.redeemers = make([dynamic]Redeemer, allocator)
	t.aux_scripts = make([dynamic]Script, allocator)
}

tables_reset :: proc(t: ^Block_Tables) {
	clear(&t.txs)
	clear(&t.inputs)
	clear(&t.collateral)
	clear(&t.ref_inputs)
	clear(&t.outputs)
	clear(&t.assets)
	clear(&t.mint)
	clear(&t.withdrawals)
	clear(&t.required_signers)
	clear(&t.certs)
	clear(&t.pool_params)
	clear(&t.key_hashes)
	clear(&t.genesis_delegs)
	clear(&t.mirs)
	clear(&t.mir_entries)
	clear(&t.votes)
	clear(&t.proposals)
	clear(&t.pparam_updates)
	clear(&t.update_proposals)
	clear(&t.cost_models)
	clear(&t.cost_values)
	clear(&t.treasury_wdrls)
	clear(&t.committee_creds)
	clear(&t.vkey_witnesses)
	clear(&t.bootstrap_wits)
	clear(&t.scripts)
	clear(&t.datums)
	clear(&t.redeemers)
	clear(&t.aux_scripts)
}

tables_destroy :: proc(t: ^Block_Tables) {
	delete(t.txs)
	delete(t.inputs)
	delete(t.collateral)
	delete(t.ref_inputs)
	delete(t.outputs)
	delete(t.assets)
	delete(t.mint)
	delete(t.withdrawals)
	delete(t.required_signers)
	delete(t.certs)
	delete(t.pool_params)
	delete(t.key_hashes)
	delete(t.genesis_delegs)
	delete(t.mirs)
	delete(t.mir_entries)
	delete(t.votes)
	delete(t.proposals)
	delete(t.pparam_updates)
	delete(t.update_proposals)
	delete(t.cost_models)
	delete(t.cost_values)
	delete(t.treasury_wdrls)
	delete(t.committee_creds)
	delete(t.vkey_witnesses)
	delete(t.bootstrap_wits)
	delete(t.scripts)
	delete(t.datums)
	delete(t.redeemers)
	delete(t.aux_scripts)
}
