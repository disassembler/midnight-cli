use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}

validator simple_mint {
  mint(_redeemer: Data, _policy_id: PolicyId, _tx: Transaction) {
    True
  }
}
