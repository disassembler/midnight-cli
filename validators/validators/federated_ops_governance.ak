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

fn has_governance_nft_input(
  tx: Transaction,
  policy_id: ByteArray,
  expected_ref: OutputReference,
) -> Bool {
  list.any(
    tx.inputs,
    fn(input: Input) {
      input.output_reference == expected_ref && has_governance_nft(
        input.output.value,
        policy_id,
      )
    },
  )
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

// Find governance datum from reference inputs by script hash
fn find_governance_datum(
  inputs: List<Input>,
  script_hash: ByteArray,
) -> Option<Multisig> {
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

// Validator
validator federated_ops_governance(
  nft_policy_id: ByteArray,
  council_script_hash: ByteArray,
  tech_auth_script_hash: ByteArray,
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
    expect has_governance_nft_input(tx, nft_policy_id, own_ref)
    expect has_governance_nft_output(tx, nft_policy_id, own_script_hash)

    // Find council and TA datums via reference inputs
    expect Some(council_multisig) =
      find_governance_datum(tx.reference_inputs, council_script_hash)

    expect Some(tech_auth_multisig) =
      find_governance_datum(tx.reference_inputs, tech_auth_script_hash)

    // Check 2/3 threshold from BOTH bodies
    expect check_threshold(tx, council_multisig)
    expect check_threshold(tx, tech_auth_multisig)

    True
  }

  else(_) {
    fail
  }
}
