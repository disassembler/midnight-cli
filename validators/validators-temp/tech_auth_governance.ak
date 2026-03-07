use aiken/collection/list
use cardano/address.{Script}
use cardano/transaction.{Input, OutputReference, Transaction}
use governance/types.{
  UpdateRedeemer, VersionedMultisig, check_threshold,
  has_governance_nft_input, has_governance_nft_output,
}

/// Technical Authority governance validator
/// Requires 2/3 threshold of current TA members to update
validator tech_auth_governance(
  nft_policy_id: ByteArray,
  initial_utxo_ref: OutputReference,
) {
  spend(
    datum_opt: Option<VersionedMultisig>,
    _redeemer: UpdateRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(datum) = datum_opt

    // Find our own input to get the script hash
    expect Some(own_input) =
      list.find(tx.inputs, fn(input) { input.output_reference == own_ref })

    expect Script(own_script_hash) = own_input.output.address.payment_credential

    // Verify NFT is being spent
    let nft_in_input = has_governance_nft_input(tx, nft_policy_id, own_ref)

    // Verify NFT goes back to same script address
    let nft_in_output =
      has_governance_nft_output(tx, nft_policy_id, own_script_hash)

    // Verify 2/3 of current signers signed this transaction
    let threshold_met = check_threshold(tx, datum.data)

    nft_in_input && nft_in_output && threshold_met
  }

  else(_) {
    fail
  }
}
