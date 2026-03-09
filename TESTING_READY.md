# Testing Setup Complete ✅

## Summary

Contract deployment testing is ready following **Option B** (test online mode first, then add air-gap).

## What's Done

### 1. Contracts Extracted ✅
```bash
ls contracts/
```

Extracted from `validators/plutus.json`:
- `council_governance_council_governance_spend.plutus` (965 bytes)
- `tech_auth_governance_tech_auth_governance_spend.plutus` (965 bytes)
- `federated_ops_governance_federated_ops_governance_spend.plutus` (1244 bytes)
- `one_shot_nft_one_shot_nft_mint.plutus` (380 bytes)
- `simple_mint_simple_mint_mint.plutus` (86 bytes)

### 2. Test Member Keys Generated ✅
```bash
ls test-deployment/member-keys/
```

Created from `polkadot-vault-gov.mnemonic`:
- `council-1.json`, `council-2.json`, `council-3.json`  (derivation paths: //midnight//governance//0,1,2)
- `ta-1.json`, `ta-2.json` (derivation paths: //midnight//governance//10,11)

Each contains:
```json
{
  "cardano_key_hash": "...",  // For Cardano tx authorization
  "sr25519_public_key": "...", // For Midnight governance
  "ss58_address": "..."       // For reference
}
```

### 3. Documentation Created ✅
- `DEPLOYMENT_TESTING_GUIDE.md` - Complete testing walkthrough
- `AIR_GAP_DESIGN.md` - Air-gap workflow specification
- `CONTRACTS_WORKFLOW.md` - User-facing workflow guide
- `AIR_GAP_IMPLEMENTATION_STATUS.md` - Implementation tracking

## Ready to Test

### Command Template

```bash
cargo run -- genesis deploy-contracts \
  --council-contract ./contracts/council_governance_council_governance_spend.plutus \
  --council-member ./test-deployment/member-keys/council-1.json \
  --council-member ./test-deployment/member-keys/council-2.json \
  --ta-contract ./contracts/tech_auth_governance_tech_auth_governance_spend.plutus \
  --ta-member ./test-deployment/member-keys/ta-1.json \
  --ta-member ./test-deployment/member-keys/ta-2.json \
  --wallet "deployment-test" \
  --mnemonic-file polkadot-vault-gov.mnemonic \
  --utxorpc http://localhost:50051 \
  --network testnet \
  --output ./test-deployment/deployment-info.json
```

### Required Before Testing

**You need:**
1. ✅ Contracts (done)
2. ✅ Member keys (done)
3. ✅ Mnemonic file (exists: `polkadot-vault-gov.mnemonic`)
4. ❓ **Cardano node with UTxORPC** - Need to verify accessibility
5. ❓ **Funded wallet** - Payment address derived from mnemonic needs test ADA

### Check Prerequisites

```bash
# 1. Verify mnemonic file
wc -w polkadot-vault-gov.mnemonic  # Should show 24 words

# 2. Test UTxORPC connection (if you have a running node)
curl http://localhost:50051/health

# 3. (Optional) Check wallet address and balance
#    The deploy-contracts command will show the payment address
#    You can then fund it via a testnet faucet
```

## What Happens Next

### If you have UTxORPC access now:
1. Run the minimal test (council only):
   ```bash
   cargo run -- genesis deploy-contracts \
     --council-contract ./contracts/council_governance_council_governance_spend.plutus \
     --council-member ./test-deployment/member-keys/council-1.json \
     --council-member ./test-deployment/member-keys/council-2.json \
     --wallet "test" \
     --mnemonic-file polkadot-vault-gov.mnemonic \
     --utxorpc http://localhost:50051 \
     --output ./test-deployment/council-only.json
   ```

2. Check output for payment address
3. Fund the address via testnet faucet
4. Re-run the command to deploy
5. Verify deployment-info.json is created
6. Confirm on-chain with explorer or cardano-cli

### If you don't have UTxORPC access yet:
The testing guide (`DEPLOYMENT_TESTING_GUIDE.md`) documents three options:
- **Option A:** Use public UTxORPC service (if available)
- **Option B:** Run local Cardano node with UTxORPC
- **Option C:** Set up local Cardano devnet (fastest for testing)

## Implementation Status

From `AIR_GAP_IMPLEMENTATION_STATUS.md`:

**Phase 1: Essential Contract Preparation** ✅ DONE
- [x] extract-contract command
- [x] extract-contracts command
- [x] apply-params command

**Phase 2: Online Deployment** ← YOU ARE HERE
- [ ] Test deploy-contracts online mode
- [ ] Verify on testnet
- [ ] Document any issues

**Phase 3: Air-Gap Workflow** (After Phase 2)
- [ ] Add --air-gap mode to deploy-contracts
- [ ] Implement sign-deployment
- [ ] Implement submit-deployment

## Key Files

### Contracts
- `validators/plutus.json` - Source (Aiken build output)
- `contracts/*.plutus` - Extracted binary contracts

### Keys
- `polkadot-vault-gov.mnemonic` - Deployment wallet seed
- `test-deployment/member-keys/*.json` - Governance member public keys

### Documentation
- `DEPLOYMENT_TESTING_GUIDE.md` - Start here for testing
- `AIR_GAP_DESIGN.md` - Future air-gap implementation spec
- `CONTRACTS_WORKFLOW.md` - User workflow guide
- `AIR_GAP_IMPLEMENTATION_STATUS.md` - Technical tracking

## Quick Test (If Everything Is Ready)

```bash
# Minimal smoke test - just check if the command runs
cargo run -- genesis deploy-contracts --help

# Expected: Shows usage information with all flags
```

## Next Steps

1. Verify UTxORPC access OR set up a test environment
2. Fund the deployment wallet address
3. Run minimal test (council only)
4. Run full test (council + TA)
5. Verify on-chain deployment
6. Document results
7. Proceed with air-gap implementation (Phase 3)

See `DEPLOYMENT_TESTING_GUIDE.md` for detailed testing instructions.

---

**Status:** Ready for testing when UTxORPC endpoint is available and wallet is funded.
