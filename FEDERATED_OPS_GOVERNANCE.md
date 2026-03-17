# Federated Ops Governance - Fixed Implementation

## Overview

The Federated Ops governance system requires **2/3 approval from BOTH Council AND Tech Auth** to modify the validator set.

## ✅ Fixed Implementation

### Contract Parameters

The `federated_ops_governance` validator now takes **5 policy IDs/script hashes**:

```aiken
validator federated_ops_governance(
  nft_policy_id: ByteArray,                    // FedOps NFT policy
  council_script_hash: ByteArray,              // Council contract hash
  council_nft_policy_id: ByteArray,            // Council NFT policy
  tech_auth_script_hash: ByteArray,            // TA contract hash
  tech_auth_nft_policy_id: ByteArray,          // TA NFT policy
  _initial_utxo_ref: OutputReference,
)
```

### Validation Logic

1. **Spends own NFT** and verifies it's returned
2. **Spends Council NFT** (finds in tx.inputs)
3. **Spends TA NFT** (finds in tx.inputs)
4. **Verifies Council logic_round** increments by exactly 1
5. **Verifies TA logic_round** increments by exactly 1
6. **Checks 2/3 threshold** from Council members
7. **Checks 2/3 threshold** from TA members

### Key Changes from Previous Implementation

#### Before (Using Reference Inputs) ❌
```aiken
// Read council and TA datums via reference inputs
expect Some(council_multisig) =
  find_governance_datum(tx.reference_inputs, council_script_hash)

expect Some(tech_auth_multisig) =
  find_governance_datum(tx.reference_inputs, tech_auth_script_hash)
```

**Problems:**
- Council and TA NFTs not spent
- logic_round not incremented (replay vulnerability!)
- Inconsistent with other governance contracts

#### After (Spending Both NFTs) ✅
```aiken
// Find and verify council input is being spent
expect Some((council_datum, _council_ref)) =
  find_governance_input(tx.inputs, council_script_hash, council_nft_policy_id)

// Find and verify TA input is being spent
expect Some((tech_auth_datum, _ta_ref)) =
  find_governance_input(tx.inputs, tech_auth_script_hash, tech_auth_nft_policy_id)

// Verify both outputs increment logic_round by 1
expect verify_logic_round_increment(
  tx, council_script_hash, council_nft_policy_id,
  council_datum.logic_round,
)

expect verify_logic_round_increment(
  tx, tech_auth_script_hash, tech_auth_nft_policy_id,
  tech_auth_datum.logic_round,
)
```

**Benefits:**
- ✅ Enforces logic_round increment on both governance contracts
- ✅ Prevents replay attacks
- ✅ Consistent with council_governance and tech_auth_governance patterns
- ✅ NFTs are spent and returned (proper state transition)

## Transaction Structure

A valid federated ops change transaction must:

### Inputs
1. FedOps governance NFT UTxO (with VersionedMultisig datum)
2. Council NFT UTxO (with VersionedMultisig datum, logic_round = N)
3. TA NFT UTxO (with VersionedMultisig datum, logic_round = M)
4. Wallet UTxOs for fees

### Outputs
1. FedOps governance NFT returned (datum updated)
2. Council NFT returned (logic_round = N+1)
3. TA NFT returned (logic_round = M+1)
4. Validator list output (FederatedOpsDatum with new members)
5. Change output

### Signatures
- 2/3 of Council members (Cardano signatures)
- 2/3 of TA members (Cardano signatures)

## Datum Structures

### Governance Control (all 3 governance contracts)

```rust
VersionedMultisig {
    data: Multisig {
        total_signers: u32,
        signers: Vec<(CardanoKeyHash, Sr25519Key)>,
    },
    logic_round: u64,
}
```

Used by:
- Council governance contract
- Tech Auth governance contract
- **FedOps governance contract** (controls who can modify fedops)

### Validator List (what FedOps manages)

```rust
FederatedOpsDatum {
    members: Vec<ValidatorKeys>,
    logic_round: u64,
}

ValidatorKeys {
    node_id: [u8; 33],        // secp256k1 compressed pubkey
    aura_key: [u8; 32],       // AURA consensus key
    grandpa_key: [u8; 32],    // GRANDPA finality key
    beefy_key: [u8; 33],      // BEEFY bridge key (secp256k1)
}
```

**This is stored separately** - not in the governance contract itself, but in an output that the governance contract validates/creates.

## Security Properties

### Replay Protection

1. **Council logic_round** must increment (enforced by contract)
2. **TA logic_round** must increment (enforced by contract)
3. **FedOps logic_round** can increment (application logic)

Each spend of Council/TA increments their counters, preventing replays.

### Multi-Body Approval

The contract enforces that **both** governance bodies approve:
- Cannot modify fedops with only Council approval
- Cannot modify fedops with only TA approval
- Requires active participation from both (spending their NFTs)

### NFT Integrity

All three NFTs must be properly returned:
- FedOps NFT stays in FedOps governance contract
- Council NFT stays in Council governance contract
- TA NFT stays in TA governance contract

## Implementation Files

### Aiken Source
- **Contract**: `validators/validators/federated_ops_governance.ak`
- **Size**: 1478 bytes (compiled)
- **Hash**: `9d702bd2820dc67c`

### Rust Types (midnight-cli)
- **Module**: `src/types/federated_ops.rs`
- **Types**: `FederatedOpsDatum`, `ValidatorKeys`
- **CBOR Encoding**: Manual indefinite array encoding

### Tests
- **Unit tests**: `src/types/federated_ops.rs::tests`
- **Integration tests**: `tests/governance_contracts_test.rs`
- **Datum analysis**: `tests/decode_fedops_tx.rs`

## Testing Status

✅ FederatedOpsDatum CBOR encoding
✅ Contract compiles and extracts
✅ Basic governance contract validation
⏳ Dual-signature requirement test (TODO)
⏳ Logic round increment test (TODO)
⏳ Full transaction simulation (TODO)

## Deployment Considerations

When deploying the federated ops governance contract:

1. **Compile with parameters**:
   ```bash
   # Apply NFT policy IDs and script hashes
   midnight-cli genesis apply-params \
     --contract federated_ops_governance.plutus \
     --params fedops_params.json \
     --output federated_ops_parameterized.plutus
   ```

2. **Parameters needed**:
   - `nft_policy_id`: FedOps NFT policy (one-shot mint)
   - `council_script_hash`: Hash of council_governance contract
   - `council_nft_policy_id`: Council NFT policy
   - `tech_auth_script_hash`: Hash of tech_auth_governance contract
   - `tech_auth_nft_policy_id`: TA NFT policy
   - `initial_utxo_ref`: TxHash#Index for one-shot NFT mint

3. **Initial state**:
   - Create genesis transaction that:
     - Mints FedOps NFT
     - Locks it in contract with initial VersionedMultisig datum
     - Sets initial fedops members list (separate output)

## Example Transaction

See `/home/sam/Downloads/change-federated-ops-tx.json` for a real example showing:
- 3 script inputs (Council, TA, FedOps)
- 3 script outputs (all NFTs returned, logic_rounds incremented)
- Validator list with 10 members
- Signatures from both governance bodies

## Next Steps

1. ✅ Fix Aiken contract to spend both NFTs
2. ✅ Add FederatedOpsDatum type to midnight-cli
3. ⏳ Write comprehensive integration test
4. ⏳ Test with hayate simulator
5. ⏳ Document parameter application process
6. ⏳ Create deployment scripts
