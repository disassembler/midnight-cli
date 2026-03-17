use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Script}
use cardano/assets.{tokens}
use cardano/transaction.{
  InlineDatum, Input, OutputReference, Transaction,
}

// Types
pub type CardanoKeyHash =
  ByteArray

pub type Sr25519Key =
  ByteArray

pub type Multisig {
  total_signers: Int,
  signers: List<(CardanoKeyHash, Sr25519Key)>,
}

pub type VersionedMultisig {
  data: Multisig,
  logic_round: Int,
}

pub type UpdateRedeemer {
  new_multisig: Multisig,
}

// Helpers
fn signed_by(tx: Transaction, key_hash: CardanoKeyHash) -> Bool {
  list.has(tx.extra_signatories, key_hash)
}

fn calculate_threshold(total: Int) -> Int {
  ( 2 * total + 2 ) / 3
}

fn count_signatures(tx: Transaction, multisig: Multisig) -> Int {
  list.foldl(
    multisig.signers,
    0,
    fn(pair, count) {
      let (hash, _sr25519_key) = pair
      if signed_by(tx, hash) {
        count + 1
      } else {
        count
      }
    },
  )
}

fn check_threshold(tx: Transaction, multisig: Multisig) -> Bool {
  let required = calculate_threshold(multisig.total_signers)
  let actual = count_signatures(tx, multisig)
  actual >= required
}

fn has_governance_nft(value, policy_id: ByteArray) -> Bool {
  let token_dict = tokens(value, policy_id)
  dict.size(token_dict) > 0
}

fn has_governance_nft_output(
  tx: Transaction,
  policy_id: ByteArray,
  script_hash: ByteArray,
) -> Bool {
  let outputs_with_nft =
    list.filter(
      tx.outputs,
      fn(output) {
        when output.address.payment_credential is {
          Script(hash) ->
            hash == script_hash && has_governance_nft(output.value, policy_id)
          _ -> False
        }
      },
    )

  list.length(outputs_with_nft) == 1
}

// Find governance input and datum by script hash and policy ID
fn find_governance_input(
  inputs: List<Input>,
  script_hash: ByteArray,
  policy_id: ByteArray,
) -> Option<(VersionedMultisig, OutputReference)> {
  let matching_inputs =
    list.filter(
      inputs,
      fn(input) {
        when input.output.address.payment_credential is {
          Script(hash) ->
            hash == script_hash && has_governance_nft(input.output.value, policy_id)
          _ -> False
        }
      },
    )

  when matching_inputs is {
    [input, ..] ->
      when input.output.datum is {
        InlineDatum(d) -> {
          expect datum: VersionedMultisig = d
          Some((datum, input.output_reference))
        }
        _ -> None
      }
    _ -> None
  }
}

// Verify that the governance contract output increments logic_round by 1
fn verify_logic_round_increment(
  tx: Transaction,
  script_hash: ByteArray,
  policy_id: ByteArray,
  old_logic_round: Int,
) -> Bool {
  let outputs_with_nft =
    list.filter(
      tx.outputs,
      fn(output) {
        when output.address.payment_credential is {
          Script(hash) ->
            hash == script_hash && has_governance_nft(output.value, policy_id)
          _ -> False
        }
      },
    )

  when outputs_with_nft is {
    [output] ->
      when output.datum is {
        InlineDatum(d) -> {
          expect new_datum: VersionedMultisig = d
          new_datum.logic_round == old_logic_round + 1
        }
        _ -> False
      }
    _ -> False
  }
}

// Validator
validator federated_ops_governance(
  nft_policy_id: ByteArray,
  council_script_hash: ByteArray,
  council_nft_policy_id: ByteArray,
  tech_auth_script_hash: ByteArray,
  tech_auth_nft_policy_id: ByteArray,
  _initial_utxo_ref: OutputReference,
) {
  spend(
    datum_opt: Option<VersionedMultisig>,
    _redeemer: UpdateRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(_datum) = datum_opt

    expect Some(own_input) =
      list.find(tx.inputs, fn(input) { input.output_reference == own_ref })

    expect Script(own_script_hash) = own_input.output.address.payment_credential

    // Verify NFT is being spent and returned
    expect has_governance_nft(own_input.output.value, nft_policy_id)
    expect has_governance_nft_output(tx, nft_policy_id, own_script_hash)

    // Find and verify council input is being spent
    expect Some((council_datum, _council_ref)) =
      find_governance_input(tx.inputs, council_script_hash, council_nft_policy_id)

    // Find and verify TA input is being spent
    expect Some((tech_auth_datum, _ta_ref)) =
      find_governance_input(tx.inputs, tech_auth_script_hash, tech_auth_nft_policy_id)

    // Verify both council and TA outputs increment logic_round by 1
    expect verify_logic_round_increment(
      tx,
      council_script_hash,
      council_nft_policy_id,
      council_datum.logic_round,
    )

    expect verify_logic_round_increment(
      tx,
      tech_auth_script_hash,
      tech_auth_nft_policy_id,
      tech_auth_datum.logic_round,
    )

    // Check 2/3 threshold from BOTH bodies
    expect check_threshold(tx, council_datum.data)
    expect check_threshold(tx, tech_auth_datum.data)

    True
  }

  else(_) {
    fail
  }
}
