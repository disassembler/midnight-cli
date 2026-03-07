use aiken/builtin.{Pair}
use aiken/collection/list
use cardano/address.{Address, Script}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction,
}
use governance/types.{
  UpdateRedeemer, VersionedMultisig, check_threshold,
  has_governance_nft_input, has_governance_nft_output,
}

/// Federated Ops governance validator (validator set management)
/// Requires 2/3 threshold from BOTH council AND tech authority to update
validator federated_ops_governance(
  nft_policy_id: ByteArray,
  council_script_hash: ByteArray,
  tech_auth_script_hash: ByteArray,
  initial_utxo_ref: OutputReference,
) {
  spend(
    datum_opt: Option<VersionedMultisig>,
    _redeemer: UpdateRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(_datum) = datum_opt

    // Find our own input to get the script hash
    expect Some(own_input) =
      list.find(tx.inputs, fn(input) { input.output_reference == own_ref })

    expect Script(own_script_hash) = own_input.output.address.payment_credential

    // Verify NFT is being spent
    let nft_in_input = has_governance_nft_input(tx, nft_policy_id, own_ref)

    // Verify NFT goes back to same script address
    let nft_in_output =
      has_governance_nft_output(tx, nft_policy_id, own_script_hash)

    // Find council and TA datums via reference inputs
    let council_datum =
      find_governance_datum(tx.reference_inputs, council_script_hash)

    let tech_auth_datum =
      find_governance_datum(tx.reference_inputs, tech_auth_script_hash)

    // Check 2/3 threshold from both bodies
    expect Some(council_multisig) = council_datum
    expect Some(tech_auth_multisig) = tech_auth_datum

    let council_approved = check_threshold(tx, council_multisig)
    let tech_auth_approved = check_threshold(tx, tech_auth_multisig)

    nft_in_input && nft_in_output && council_approved && tech_auth_approved
  }

  else(_) {
    fail
  }
}

/// Helper: Find governance datum from reference inputs
fn find_governance_datum(
  inputs: List<Input>,
  script_hash: ByteArray,
) -> Option<VersionedMultisig> {
  let matching_inputs =
    list.filter(
      inputs,
      fn(input) {
        when input.output.address.payment_credential is {
          Script(hash) -> hash == script_hash
          _ -> False
        }
      },
    )

  when matching_inputs is {
    [input, ..] ->
      when input.output.datum is {
        InlineDatum(d) -> {
          expect datum: VersionedMultisig = d
          Some(datum.data)
        }
        _ -> None
      }
    _ -> None
  }
}
