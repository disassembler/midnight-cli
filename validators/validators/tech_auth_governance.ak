use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Script}
use cardano/assets.{tokens}
use cardano/transaction.{InlineDatum, Input, OutputReference, Transaction}

// Types
pub type CardanoKeyHash =
  ByteArray

pub type Sr25519Key =
  ByteArray

pub type Multisig {
  total_signers: Int,
  // List of (CBOR-encoded wrapped key hash, sr25519 key) pairs
  // Wrapped keys are encoded as: [0, bytes(28)] = 8200581c<28 bytes>
  signers: List<(ByteArray, Sr25519Key)>,
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
      let (wrapped_key_cbor, _sr25519_key) = pair
      // wrapped_key_cbor is CBOR-encoded: 8200581c<28 bytes>
      // Skip first 4 bytes (82=array, 00=int(0), 581c=bytes(28)) to get the hash
      let hash = builtin.slice_bytearray(4, 32, wrapped_key_cbor)
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

fn get_output_datum(
  tx: Transaction,
  policy_id: ByteArray,
  script_hash: ByteArray,
) -> VersionedMultisig {
  // Find the output with the NFT going to the script
  expect Some(output) =
    list.find(
      tx.outputs,
      fn(output) {
        when output.address.payment_credential is {
          Script(hash) ->
            hash == script_hash && has_governance_nft(output.value, policy_id)
          _ -> False
        }
      },
    )

  // Extract inline datum
  expect InlineDatum(d) = output.datum
  expect new_datum: VersionedMultisig = d
  new_datum
}

// Validator
validator tech_auth_governance(
  nft_policy_id: ByteArray,
  _initial_utxo_ref: OutputReference,
) {
  spend(
    datum_opt: Option<VersionedMultisig>,
    _redeemer: UpdateRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(datum) = datum_opt

    expect Some(own_input) =
      list.find(tx.inputs, fn(input) { input.output_reference == own_ref })

    expect Script(own_script_hash) = own_input.output.address.payment_credential

    expect has_governance_nft_input(tx, nft_policy_id, own_ref)
    expect has_governance_nft_output(tx, nft_policy_id, own_script_hash)
    expect check_threshold(tx, datum.data)

    // Verify output datum has logic_round incremented by exactly 1
    let new_datum = get_output_datum(tx, nft_policy_id, own_script_hash)
    expect new_datum.logic_round == datum.logic_round + 1

    True
  }

  else(_) {
    fail
  }
}
