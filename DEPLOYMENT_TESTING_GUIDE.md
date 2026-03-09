# Contract Deployment Testing Guide

## Overview

This guide walks through testing the `deploy-contracts` command in **online mode** (Option B from implementation plan). We'll verify that the existing deployment implementation works correctly before adding air-gap support.

## Prerequisites

### 1. Contracts Extracted ✅

Contracts have been extracted from `validators/plutus.json`:

```bash
ls -lh contracts/
# council_governance_council_governance_spend.plutus (965 bytes)
# tech_auth_governance_tech_auth_governance_spend.plutus (965 bytes)
# federated_ops_governance_federated_ops_governance_spend.plutus (1244 bytes)
# one_shot_nft_one_shot_nft_mint.plutus (380 bytes)
```

### 2. Test Member Keys Generated ✅

Member keys created in `test-deployment/member-keys/`:

```bash
ls test-deployment/member-keys/
# council-1.json, council-2.json, council-3.json
# ta-1.json, ta-2.json
```

Each contains:
- `cardano_key_hash` - For Cardano transaction authorization
- `sr25519_public_key` - For Midnight governance operations
- `ss58_address` - For reference

### 3. Required: Cardano Node Access

You need access to a Cardano testnet with:
- **UTxORPC endpoint** - For querying UTxOs and submitting transactions
- **Funded wallet** - The deployment wallet derived from your mnemonic must have ADA for:
  - Transaction fees (~0.2 ADA per transaction)
  - Contract outputs (default: 5 ADA per contract)
  - NFT minting outputs

### 4. Required: Deployment Wallet Mnemonic

The mnemonic at `polkadot-vault-gov.mnemonic` will be used to derive:
- **Payment address** (Cardano path: `1852H/1815H/0H/0/0`) - Must have funds
- **Signing keys** - To authorize the deployment transactions

## Testing Steps

### Step 1: Check Wallet Balance

First, verify your deployment wallet has sufficient funds:

```bash
# This requires a running Cardano node with UTxORPC
# The deploy-contracts command will show the payment address

cargo run -- genesis deploy-contracts \
  --council-contract ./contracts/council_governance_council_governance_spend.plutus \
  --council-member ./test-deployment/member-keys/council-1.json \
  --council-member ./test-deployment/member-keys/council-2.json \
  --mnemonic-file polkadot-vault-gov.mnemonic \
  --utxorpc http://localhost:50051 \
  --dry-run  # If this flag exists
```

**Expected output:**
- Payment address derived from mnemonic
- Available UTxOs and total balance
- Required amount for deployment

**If this fails:**
- Check UTxORPC endpoint is accessible
- Verify mnemonic file is readable
- Ensure Cardano node is synced

### Step 2: Deploy Council Governance Contract (Minimal Test)

Test deploying just the council contract with 2 members:

```bash
cargo run -- genesis deploy-contracts \
  --council-contract ./contracts/council_governance_council_governance_spend.plutus \
  --council-member ./test-deployment/member-keys/council-1.json \
  --council-member ./test-deployment/member-keys/council-2.json \
  --mnemonic-file polkadot-vault-gov.mnemonic \
  --utxorpc http://localhost:50051 \
  --network testnet \
  --output ./test-deployment/council-deployment.json
```

**What this does:**
1. Derives payment address from mnemonic
2. Queries wallet UTxOs via UTxORPC
3. Builds council multisig datum (2/3 threshold for 2 members)
4. Creates one-shot NFT minting policy
5. Builds Cardano transaction with:
   - NFT mint (CouncilNFT token)
   - Contract output with inline datum
   - Change output back to wallet
6. Signs transaction with mnemonic-derived keys
7. Submits to Cardano network
8. Waits for confirmation
9. Saves deployment info to JSON

**Expected output:**
```
🚀 Deploying governance contracts to Cardano testnet

Payment address: addr_test1...
Available UTxOs: 3 (total: 100.000000 ADA)

📋 Deployment Plan:
  • Council Governance
    - Members: 2
    - Threshold: 2 (2/3 majority)
    - Contract: ./contracts/council_governance_council_governance_spend.plutus (965 bytes)

Building transactions...
✅ Council governance transaction built (hash: abc123...)
  - NFT Policy ID: def456...
  - Script address: addr_test1...xyz789

Signing and submitting...
⏳ Waiting for confirmation...
✅ Transaction confirmed in block 12345

📝 Deployment info saved to: ./test-deployment/council-deployment.json
```

**Verify deployment:**
```bash
cat ./test-deployment/council-deployment.json | jq .

# Should contain:
# {
#   "council_contract": {
#     "script_hash": "...",
#     "address": "addr_test1...",
#     "nft_policy_id": "...",
#     "tx_hash": "...",
#     "members": ["...", "..."],
#     "threshold": 2
#   }
# }
```

### Step 3: Deploy Full Governance System

Deploy both council and TA contracts:

```bash
cargo run -- genesis deploy-contracts \
  --council-contract ./contracts/council_governance_council_governance_spend.plutus \
  --council-member ./test-deployment/member-keys/council-1.json \
  --council-member ./test-deployment/member-keys/council-2.json \
  --council-member ./test-deployment/member-keys/council-3.json \
  --ta-contract ./contracts/tech_auth_governance_tech_auth_governance_spend.plutus \
  --ta-member ./test-deployment/member-keys/ta-1.json \
  --ta-member ./test-deployment/member-keys/ta-2.json \
  --mnemonic-file polkadot-vault-gov.mnemonic \
  --utxorpc http://localhost:50051 \
  --network testnet \
  --output ./test-deployment/full-deployment.json
```

**Expected:**
- Two separate transactions (one for council, one for TA)
- Each with its own NFT policy and script address
- Both confirmed on-chain

### Step 4: Verify On-Chain State

Check that the contracts were deployed correctly:

```bash
# Query the script address to see the contract UTxO
cardano-cli query utxo \
  --address $(jq -r '.council_contract.address' ./test-deployment/full-deployment.json) \
  --testnet-magic 4

# Should show:
# - UTxO with 5 ADA (or your configured amount)
# - Inline datum with multisig configuration
# - NFT token attached
```

## Common Issues

### "No UTxOs found"
**Cause:** Deployment wallet has no funds
**Fix:** Send test ADA to the payment address shown in output

### "Insufficient funds"
**Cause:** Not enough ADA for contract outputs + fees
**Fix:** Ensure wallet has at least:
- 10-15 ADA for two contracts
- 0.5 ADA for transaction fees
- Buffer for change output

### "UTxORPC connection failed"
**Cause:** Cardano node not accessible
**Fix:**
- Check node is running: `curl http://localhost:50051/health`
- Verify correct port in --utxorpc flag
- Check firewall settings

### "Transaction failed to submit"
**Cause:** Various - check error message
**Common fixes:**
- Ensure node is fully synced
- Check transaction is well-formed (inspect .txbody file if available)
- Verify collateral is set up correctly

### "Build failed - parameter mismatch"
**Cause:** Contract expects parameters but none provided
**Fix:** For parameterized contracts, apply params first with:
```bash
cargo run -- genesis apply-params \
  --contract <input> \
  --utxo-ref <tx_hash#index> \
  --output <output>
```

## Success Criteria

✅ The deployment is successful if:

1. **Transactions confirmed on-chain**
   - Both council and TA transactions appear in explorer
   - No rollbacks or failures

2. **deployment-info.json contains valid data**
   - Script hashes are 28 bytes (56 hex chars)
   - Addresses are valid Cardano addresses
   - Policy IDs are 28 bytes
   - Transaction hashes are 32 bytes

3. **Contract UTxOs exist on-chain**
   - Query each script address
   - Verify inline datums match expected member configuration
   - Confirm NFT tokens are present

4. **Datum structure is correct**
   - Can be decoded with pallas/cardano-cli
   - Contains expected member key hashes
   - Threshold calculation is correct: `(2 * total + 2) / 3`

## Next Steps After Successful Testing

Once online deployment works:

1. **Document any issues encountered**
   - Update this guide with solutions
   - Note any unexpected behavior

2. **Implement air-gap support** (as planned in Option B)
   - Add `--air-gap` flag to deploy-contracts
   - Implement unsigned transaction saving
   - Create sign-deployment command implementation
   - Create submit-deployment command implementation

3. **Add integration tests**
   - Test full air-gap workflow
   - Test parameter application
   - Test error handling

4. **Update documentation**
   - CONTRACTS_WORKFLOW.md with actual examples
   - README.md with deployment instructions
   - CLAUDE.md with new command examples

## Test Environment Setup

If you don't have a Cardano testnet node:

### Option A: Use Public UTxORPC Service
```bash
# Some Cardano infrastructure providers offer UTxORPC
# Check demeter.run, blockfrost.io, or others
```

### Option B: Run Local Cardano Node with UTxORPC
```bash
# This requires significant resources and sync time
# See: https://developers.cardano.org/docs/get-started/running-cardano
```

### Option C: Use Cardano Devnet (Fastest for Testing)
```bash
# Set up a local devnet with pre-funded addresses
# See: https://github.com/input-output-hk/cardano-node-tests
```

## Testing Checklist

- [ ] Contracts extracted from plutus.json
- [ ] Member keys generated
- [ ] Mnemonic file available
- [ ] UTxORPC endpoint accessible
- [ ] Wallet has sufficient test ADA
- [ ] Minimal deployment test (council only)
- [ ] Full deployment test (council + TA)
- [ ] On-chain verification
- [ ] deployment-info.json validated
- [ ] Issues documented
- [ ] Ready for air-gap implementation

## Notes

- The `deploy-contracts` command uses hayate's `PlutusTransactionBuilder`
- NFT policies are generated using temporary Ed25519 keypairs
- Contract datums use CBOR encoding with Cardano-style binary format
- Threshold is automatically calculated as 2/3 majority
- Each contract gets its own unique NFT policy (one-shot mint)

## Troubleshooting Commands

```bash
# Check if cargo build is up to date
cargo build --release

# Run with more verbose output (if implemented)
RUST_LOG=debug cargo run -- genesis deploy-contracts ...

# Inspect a contract file
xxd contracts/council_governance_council_governance_spend.plutus | head

# Validate member key format
jq . test-deployment/member-keys/council-1.json

# Check mnemonic file
wc -w polkadot-vault-gov.mnemonic  # Should be 24 words
```
