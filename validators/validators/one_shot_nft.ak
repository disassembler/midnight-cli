use aiken/collection/dict
use aiken/collection/list
use cardano/assets.{PolicyId, tokens}
use cardano/transaction.{OutputReference, Transaction}

validator one_shot_nft(seed_utxo: OutputReference) {
  mint(_redeemer: Data, policy_id: PolicyId, tx: Transaction) {
    expect list.any(
      tx.inputs,
      fn(input) { input.output_reference == seed_utxo },
    )

    // In stdlib v2, tx.mint is a Value
    // Check that exactly 1 token with empty name is minted under this policy
    let minted_tokens = tokens(tx.mint, policy_id)

    // Check: exactly 1 token, with empty name, quantity 1
    dict.size(minted_tokens) == 1 && dict.foldl(
      minted_tokens,
      True,
      fn(name, quantity, _acc) { name == "" && quantity == 1 },
    )
  }

  else(_) {
    fail
  }
}
