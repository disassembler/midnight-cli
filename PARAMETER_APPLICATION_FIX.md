# Parameter Application Fix

## Problem Identified

The Aiken governance validators are **parameterized contracts** that require two parameters to be applied before deployment:

```aiken
validator council_governance(
  nft_policy_id: ByteArray,           // ← Policy ID of the NFT that guards the contract
  _initial_utxo_ref: OutputReference, // ← UTxO reference for one-shot validation
)
```

The previous `deploy-contracts` implementation had a critical issue:
1. ✅ Generated NFT policy IDs dynamically
2. ❌ **Never applied these parameters to the contracts**
3. ❌ Deployed **unparameterized** contracts (would fail validation!)

## Solution Implemented

The `deploy-contracts` command now follows this corrected workflow:

### Before (Broken):
1. Load unparameterized contracts
2. Calculate addresses from unparameterized contracts ❌
3. Generate NFT policies
4. Deploy (would fail because validators expect parameters)

### After (Fixed):
1. Load unparameterized contract templates
2. Query wallet UTxOs
3. Select first UTxO as reference parameter
4. Generate NFT minting policies
5. **Apply policy ID + UTxO ref as parameters** ✅
6. Calculate addresses from **parameterized** contracts ✅
7. Build datums
8. Deploy correctly parameterized contracts ✅

## What Changed

### Code Changes (src/cli/commands/genesis.rs)

**New step 10: Apply parameters to contracts**
```rust
// Select first UTxO to use as reference parameter
let ref_utxo = &wallet_utxos[0];
let mut ref_tx_hash = [0u8; 32];
ref_tx_hash.copy_from_slice(&ref_utxo.tx_hash);
let ref_output_index = ref_utxo.output_index as u64;

// Apply parameters to council contract: (nft_policy_id, initial_utxo_ref)
let council_params = vec![
    crate::contracts::params::bytearray_data(&council_policy_id),
    crate::contracts::params::output_reference_data(ref_tx_hash, ref_output_index),
];
let council_parameterized_hex = crate::contracts::params::apply_params(&council_script_hex, council_params)?;
```

**Updated output:**
```
🔧 Applying parameters to governance contracts...
  Reference UTxO:  abc123...#0
  Council contract:  965 bytes (unparameterized) → 1028 bytes (parameterized)
  TA contract:       965 bytes (unparameterized) → 1028 bytes (parameterized)

📍 Calculating contract addresses...
  Council:  61face...
  TA:       71beef...
```

## Usage (Unchanged)

The command interface remains the same - parameter application happens automatically:

### For midnight-cli repo testing:
```bash
cargo run -- genesis deploy-contracts \
  --council-contract ./contracts/council_governance_council_governance_spend.plutus \
  --council-member ./test-deployment/member-keys/council-1.json \
  --council-member ./test-deployment/member-keys/council-2.json \
  --wallet "test" \
  --mnemonic-file polkadot-vault-gov.mnemonic \
  --utxorpc http://localhost:50051 \
  --output ./test-deployment/deployment-info.json
```

### For midnight-playground deployment:

**Step 1: Build contracts**
```bash
cd validators
aiken build  # Generates plutus.json with unparameterized templates
```

**Step 2: Extract contracts**
```bash
cd ..
midnight-cli genesis extract-contracts \
  --plutus-json ./validators/plutus.json \
  --output-dir ./contracts
```

**Step 3: Generate member keys**
```bash
# Council members
for i in 0 1 2; do
  midnight-cli governance generate \
    --mnemonic-file deployment.mnemonic \
    --derivation "//midnight//governance//$i" \
    --output ./member-keys/council-$i.json
done

# TA members
for i in 10 11; do
  midnight-cli governance generate \
    --mnemonic-file deployment.mnemonic \
    --derivation "//midnight//governance//$i" \
    --output ./member-keys/ta-$i.json
done
```

**Step 4: Deploy contracts**
```bash
midnight-cli genesis deploy-contracts \
  --council-contract ./contracts/council_governance_council_governance_spend.plutus \
  --council-member ./member-keys/council-0.json \
  --council-member ./member-keys/council-1.json \
  --council-member ./member-keys/council-2.json \
  --ta-contract ./contracts/tech_auth_governance_tech_auth_governance_spend.plutus \
  --ta-member ./member-keys/ta-10.json \
  --ta-member ./member-keys/ta-11.json \
  --wallet "playground-deployment" \
  --mnemonic-file deployment.mnemonic \
  --utxorpc http://localhost:50051 \
  --network testnet \
  --output ./deployment-info.json
```

**Parameters are applied automatically!** The command will:
1. Query your wallet UTxOs
2. Use the first UTxO as the reference parameter
3. Apply the NFT policy ID and UTxO reference to both contracts
4. Deploy the correctly parameterized validators

## Technical Details

### Parameter Format

Both parameters use PlutusData encoding via pallas-primitives:

**NFT Policy ID (ByteArray):**
```rust
PlutusData::BoundedBytes(policy_id.to_vec().into())
```

**UTxO Reference (Constructor):**
```rust
PlutusData::Constr(Constr {
    tag: 0,
    any_constructor: None,
    fields: [
        PlutusData::BoundedBytes(tx_hash.to_vec().into()),
        PlutusData::BigInt(BigInt::Int(output_index)),
    ],
})
```

### Why These Parameters?

**nft_policy_id**: The validator checks that each contract UTxO contains an NFT from this policy. This ensures:
- Only one instance of the contract exists (one-shot guarantee)
- The contract can be identified on-chain
- Prevents unauthorized contract duplication

**initial_utxo_ref**: Used as a seed for one-shot NFT policies. By consuming this specific UTxO, the NFT policy becomes un-mintable after the first mint, guaranteeing uniqueness.

## Verification

After deployment, you can verify the contracts were correctly parameterized:

### Check Script Addresses
```bash
# Should show DIFFERENT addresses than unparameterized contracts
jq '.council_contract.address, .ta_contract.address' deployment-info.json
```

### Query On-Chain
```bash
cardano-cli query utxo \
  --address $(jq -r '.council_contract.address' deployment-info.json) \
  --testnet-magic 4

# Should show:
# - UTxO with contract output
# - NFT token attached
# - Inline datum with member configuration
```

### Check NFT Policy
```bash
# The policy ID in deployment-info.json should match the parameter applied
jq '.council_contract.nft_policy_id' deployment-info.json
```

## Build Status

✅ **Build successful** (cargo build --release)
✅ **All tests pass**
✅ **Ready for deployment testing**

## Next Steps

1. **Test on local devnet** (recommended first step)
2. **Test on SanchoNet testnet**
3. **Verify on-chain contract behavior**
4. **Document any issues encountered**

## Commit

```
commit f247948
Author: Claude <noreply@anthropic.com>
Date:   Sat Mar 8 19:40:17 2026

    feat: apply parameters to governance contracts during deployment
```

## Related Files

- `src/cli/commands/genesis.rs` - Main deployment logic
- `src/contracts/params.rs` - Parameter application utilities
- `validators/validators/*.ak` - Aiken contract source
- `DEPLOYMENT_TESTING_GUIDE.md` - Testing instructions
- `TESTING_READY.md` - Quick start guide
