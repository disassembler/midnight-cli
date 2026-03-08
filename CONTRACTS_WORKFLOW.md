# Complete Contract Workflow

## Overview

This document describes the complete workflow for building, preparing, and deploying Midnight Network governance contracts.

## Step-by-Step Workflow

### Step 1: Build Aiken Contracts

The Aiken smart contracts are in `validators/validators/`:
- `council_governance.ak` - Council multisig governance
- `tech_auth_governance.ak` - Technical Authority multisig governance
- `federated_ops_governance.ak` - Federated Operators multisig governance
- `one_shot_nft.ak` - NFT minting policy for contract singletons
- `simple_mint.ak` - Simple minting policy (test/utility)

```bash
cd validators
aiken build
```

This generates `validators/plutus.json` containing all compiled validators.

### Step 2: Extract Contracts to Individual Files

Extract the contracts you need from plutus.json:

```bash
# Extract council governance spending validator
midnight-cli genesis extract-contract \
  --plutus-json ./validators/plutus.json \
  --validator "council_governance.council_governance.spend" \
  --output ./contracts/council_governance.plutus

# Extract TA governance spending validator
midnight-cli genesis extract-contract \
  --plutus-json ./validators/plutus.json \
  --validator "tech_auth_governance.tech_auth_governance.spend" \
  --output ./contracts/ta_governance.plutus

# Extract one-shot NFT minting policy (for parameter application)
midnight-cli genesis extract-contract \
  --plutus-json ./validators/plutus.json \
  --validator "one_shot_nft.one_shot_nft.mint" \
  --output ./contracts/one_shot_nft_template.plutus
```

Alternatively, extract all at once:

```bash
midnight-cli genesis extract-contracts \
  --plutus-json ./validators/plutus.json \
  --output-dir ./contracts
```

This creates:
- `contracts/council_governance.plutus`
- `contracts/tech_auth_governance.plutus`
- `contracts/federated_ops_governance.plutus`
- `contracts/one_shot_nft.plutus`
- `contracts/simple_mint.plutus`

### Step 3: Apply Parameters (if needed)

Some contracts are parameterized (like one-shot NFT minting policies):

```bash
# Apply UTxO reference parameter to NFT minting policy
midnight-cli genesis apply-params \
  --contract ./contracts/one_shot_nft_template.plutus \
  --utxo-ref "abcd1234...#0" \
  --output ./contracts/council_nft_policy.plutus
```

For governance contracts, parameters are applied during deployment (the multisig datum).

### Step 4: Deploy Contracts (Online Mode - Development/Testing)

Simple one-command deployment:

```bash
midnight-cli genesis deploy-contracts \
  --council-contract ./contracts/council_governance.plutus \
  --ta-contract ./contracts/ta_governance.plutus \
  --council-member ./keys/council-member-1.json \
  --council-member ./keys/council-member-2.json \
  --council-member ./keys/council-member-3.json \
  --ta-member ./keys/ta-member-1.json \
  --ta-member ./keys/ta-member-2.json \
  --mnemonic-file ~/.cardano/deployment-wallet.mnemonic \
  --network testnet \
  --utxorpc http://localhost:50051 \
  --output deployment-info.json
```

This will:
1. Query wallet UTxOs
2. Build transactions
3. Sign with mnemonic
4. Submit to network
5. Wait for confirmations
6. Output deployment info + Hayate configuration

### Step 5: Deploy Contracts (Air-Gap Mode - Production)

**Phase A: Create Unsigned Transactions (Online Machine)**

```bash
midnight-cli genesis deploy-contracts \
  --council-contract ./contracts/council_governance.plutus \
  --ta-contract ./contracts/ta_governance.plutus \
  --council-member ./keys/council-member-1.json \
  --council-member ./keys/council-member-2.json \
  --ta-member ./keys/ta-member-1.json \
  --network testnet \
  --utxorpc http://localhost:50051 \
  --air-gap \
  --airgap-dir ./deployment-airgap
```

This creates:
- `deployment-airgap/council-deploy.txbody` - Unsigned transaction
- `deployment-airgap/council-deploy.payload` - Signing payload (hash)
- `deployment-airgap/council-deploy.metadata.json` - Human-readable details
- `deployment-airgap/ta-deploy.txbody`
- `deployment-airgap/ta-deploy.payload`
- `deployment-airgap/ta-deploy.metadata.json`
- `deployment-airgap/deployment-plan.json` - Overall plan

**Phase B: Sign Transactions (Air-Gapped Machine)**

Transfer `./deployment-airgap/` to air-gapped machine via USB, then:

```bash
midnight-cli genesis deploy-contracts sign-offline \
  --airgap-dir ./deployment-airgap \
  --mnemonic-file ~/.cardano/deployment-wallet.mnemonic
```

This creates:
- `deployment-airgap/council-deploy.witness` - Signature witness
- `deployment-airgap/council-deploy.txsigned` - Signed transaction
- `deployment-airgap/ta-deploy.witness`
- `deployment-airgap/ta-deploy.txsigned`

**Phase C: Submit Transactions (Online Machine)**

Transfer `./deployment-airgap/` back to online machine, then:

```bash
midnight-cli genesis deploy-contracts submit \
  --airgap-dir ./deployment-airgap \
  --utxorpc http://localhost:50051 \
  --output deployment-info.json
```

This submits transactions and outputs deployment info.

## Contract Types

### Spending Validators (Script Addresses)

These guard UTxOs and require a datum + redeemer to spend:
- **Council Governance**: Multisig approval for council actions
- **TA Governance**: Multisig approval for TA actions
- **Federated Ops**: Multisig approval for operator actions

### Minting Policies

These control creation of native assets:
- **One-Shot NFT**: Parameterized by UTxO reference, can only mint once
- **Simple Mint**: Always succeeds (for testing)

## File Formats

### .plutus Files
- Raw CBOR-encoded Plutus scripts
- Can be hex-encoded or binary
- Used as input to deploy-contracts

### .json Files (Member Keys)
- Contains both Cardano and Midnight public keys
- Generated by `governance generate` command
- Format:
```json
{
  "cardano_hash": "28_byte_hex",
  "sr25519_key": "32_byte_hex",
  "cardano_address": "addr1...",
  "midnight_address": "5..."
}
```

### deployment-info.json
- Output after successful deployment
- Contains contract addresses, policy IDs, transaction hashes
- Used to configure Hayate and genesis.json

## Common Issues

### "No UTxOs found"
- Ensure wallet has funds on the testnet
- Check UTxORPC endpoint is accessible
- Verify correct account index

### "Invalid mnemonic"
- Must be 24-word BIP39 phrase
- Check for GPG encryption (.gpg extension)
- Verify no extra whitespace

### "Transaction too large"
- Split into multiple transactions
- Reduce number of members per transaction
- Optimize datum size

### "Collision detected"
- NFT asset name already exists
- Use different UTxO reference for one-shot policy
- Check existing policy IDs

## Security Notes

1. **Never put mnemonics on online machines** for production deployments
2. **Always use --air-gap mode** for mainnet deployments
3. **Verify payload hashes manually** before signing
4. **Store deployment info securely** (contains sensitive addresses)
5. **Test on testnet first** before mainnet deployment

## Next Steps

After deployment:
1. Save deployment-info.json securely
2. Configure Hayate with script addresses
3. Add deployment info to midnight-node genesis configuration
4. Test contract interactions before launching network
