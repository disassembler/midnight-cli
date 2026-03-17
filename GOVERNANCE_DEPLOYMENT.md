# Governance Deployment Guide

This guide walks through deploying and managing Midnight governance contracts with air-gapped M-of-N signing.

## Prerequisites

1. **Running Hayate endpoint** connected to Cardano testnet:
   ```bash
   hayate-server --port 50051
   ```

2. **Wallet with funds** for transaction fees (5+ ADA for collateral)

3. **Governance member keys** - JSON files with:
   ```json
   {
     "cardano_key_hash": "f48558b0...",
     "sr25519_public_key": "0x7c7b89f7...",
     "ss58_address": "5EsvVahbW..."
   }
   ```

4. **Initial UTxO** for one-shot NFT minting (must exist in your wallet)

## Step 1: Deploy Council Governance Contract

### 1.1 Run Deploy Command

```bash
midnight-cli deploy council-governance \
  --member-files council-1.json,council-2.json,council-3.json \
  --initial-utxo-ref <tx_hash>#<output_index> \
  --hayate-endpoint http://localhost:50051 \
  --mnemonic-file wallet.mnemonic \
  --output-dir ./deployment
```

**Parameters:**
- `--member-files`: Comma-separated list of governance member JSON files
- `--initial-utxo-ref`: UTxO to consume for one-shot NFT (format: `tx_hash#index`)
- `--hayate-endpoint`: Hayate gRPC endpoint (default: http://localhost:50051)
- `--mnemonic-file`: Wallet mnemonic for transaction fees
- `--output-dir`: Directory for deployment state file

### 1.2 Deploy Output

The command outputs:
```
✓ Contract address: addr_test1wrqqpktnzf94z0qyvc0usnmduwrm82gjcmj736wyt5prkmssmyhhz
✓ NFT Policy ID: 48abfaa20f6985853527358013c6aa0467cea71c01194202fa002f2b
✓ State file created: ./deployment/council-governance.state.json
```

### 1.3 Manual Deployment Steps

**The deploy command provides the contract details. You need to:**

1. **Build the minting transaction** using cardano-cli:
   - Spend the initial UTxO (enables one-shot minting)
   - Mint 1 NFT with the policy ID shown
   - Send the NFT to the contract address
   - Attach the initial datum (VersionedMultisig with logic_round=0)

2. **Example with cardano-cli:**
   ```bash
   # Build the transaction
   cardano-cli transaction build \
     --tx-in <initial_utxo> \
     --tx-out "<contract_address>+2000000+1 <policy_id>.<asset_name>" \
     --tx-out-inline-datum-file initial-datum.json \
     --mint "1 <policy_id>.<asset_name>" \
     --mint-script-file oneshot-policy.script \
     --change-address <your_address> \
     --testnet-magic 4 \
     --out-file deployment.tx

   # Sign and submit
   cardano-cli transaction sign \
     --tx-body-file deployment.tx \
     --signing-key-file payment.skey \
     --out-file deployment.signed

   cardano-cli transaction submit \
     --tx-file deployment.signed \
     --testnet-magic 4
   ```

3. **Update the state file** with actual deployment tx hash:
   ```bash
   # Edit council-governance.state.json
   # Change "deployment_tx_hash": "UPDATE_AFTER_DEPLOYMENT"
   # To:     "deployment_tx_hash": "<actual_tx_hash>"
   ```

### 1.4 State File

The state file (`council-governance.state.json`) contains:
```json
{
  "contract_type": "council",
  "contract_address": "addr_test1...",
  "nft_policy_id": "48abfaa2...",
  "nft_asset_name": "council",
  "logic_round": 0,
  "members": [
    {
      "cardano_hash": "f48558b0...",
      "sr25519_key": "7c7b89f7..."
    }
  ],
  "deployment_tx_hash": "UPDATE_AFTER_DEPLOYMENT",
  "deployed_at": "2026-03-17T14:49:15Z"
}
```

**This state file is required for all rotation operations.**

## Step 2: Rotate Governance Members (Air-Gap Workflow)

### 2.1 Create Unsigned Rotation Transaction

On the **online machine** with access to hayate:

```bash
midnight-cli rotate council \
  --state-file council-governance.state.json \
  --new-member-files new-council-1.json,new-council-2.json,new-council-3.json \
  --hayate-endpoint http://localhost:50051 \
  --mnemonic-file wallet.mnemonic \
  --output-dir ./rotation \
  --air-gap
```

**Output:**
```
✓ Created: ./rotation/council-rotation.txbody
✓ Created: ./rotation/council-rotation.metadata

━━━ Air-Gap Workflow ━━━
1. Transfer files to air-gap machine(s)
2. Sign with M-of-N members (need 2/3)
3. Assemble and submit
```

### 2.2 Sign on Air-Gap Machines

Transfer these files to air-gap machines via USB/QR:
- `council-rotation.txbody`
- `council-rotation.metadata`

On each **air-gap machine** (need threshold signatures, e.g., 2 of 3):

```bash
midnight-cli witness create-cardano \
  --tx-body-file council-rotation.txbody \
  --metadata-file council-rotation.metadata \
  --mnemonic-file member-1.mnemonic \
  --output member-1.witness
```

**Output:**
```
✓ Signing as: council_member_1
  Cardano key hash: 1587931a...
  Sr25519 address: 5EsvVahbW...
✓ Witness created: member-1.witness
```

Repeat for member 2:
```bash
midnight-cli witness create-cardano \
  --tx-body-file council-rotation.txbody \
  --metadata-file council-rotation.metadata \
  --mnemonic-file member-2.mnemonic \
  --output member-2.witness
```

**Alternative: Use cardano-cli for signing:**
```bash
cardano-cli transaction witness \
  --tx-body-file council-rotation.txbody \
  --signing-key-file member-1.skey \
  --out-file member-1.witness
```

### 2.3 Assemble Witnesses

Transfer witness files back to **online machine**.

Assemble the signed transaction:
```bash
midnight-cli witness assemble \
  --tx-body-file council-rotation.txbody \
  --metadata-file council-rotation.metadata \
  --witness-files member-1.witness,member-2.witness \
  --output council-rotation.tx \
  --validate-threshold
```

**Output:**
```
✓ Witness 1 verified: council_member_1 (1587931a...)
✓ Witness 2 verified: council_member_2 (dc5d4b32...)
✓ Threshold met: 2/3 signatures
✓ Signed transaction assembled: council-rotation.tx
```

**Alternative: Use cardano-cli for assembly:**
```bash
cardano-cli transaction assemble \
  --tx-body-file council-rotation.txbody \
  --witness-file member-1.witness \
  --witness-file member-2.witness \
  --out-file council-rotation.tx
```

### 2.4 Submit Transaction

Submit to the Cardano network:
```bash
# Using cardano-cli
cardano-cli transaction submit \
  --tx-file council-rotation.tx \
  --testnet-magic 4

# Or using midnight-cli (if implemented)
midnight-cli tx submit \
  --tx-file council-rotation.tx
```

### 2.5 Verify Transaction

Inspect the transaction before submission:
```bash
cardano-cli debug transaction view \
  --tx-file council-rotation.tx
```

## Step 3: Deploy TA and FedOps Governance (Future)

### TA Governance
```bash
midnight-cli deploy ta-governance \
  --member-files ta-1.json,ta-2.json,ta-3.json \
  --initial-utxo-ref <tx_hash>#<index> \
  --hayate-endpoint http://localhost:50051 \
  --mnemonic-file wallet.mnemonic \
  --output-dir ./deployment
```

### FedOps Governance
```bash
midnight-cli deploy fedops-governance \
  --member-files fedops-1.json,fedops-2.json,fedops-3.json \
  --initial-utxo-ref <tx_hash>#<index> \
  --hayate-endpoint http://localhost:50051 \
  --mnemonic-file wallet.mnemonic \
  --output-dir ./deployment
```

**Note:** FedOps rotation requires BOTH Council AND TA approval (2/3 from each).

## Threshold Calculation

The governance contracts enforce a **2/3 majority** threshold:

Formula: `(2 * total_signers + 2) / 3`

Examples:
- 3 members → need 2 signatures
- 5 members → need 4 signatures
- 7 members → need 5 signatures

## File Formats

All transaction files use **Cardano-CLI compatible TextEnvelope format**:

### Transaction Body (.txbody)
```json
{
  "type": "Unwitnessed Tx BabbageEra",
  "description": "Council rotation transaction",
  "cborHex": "84a400..."
}
```

### Witness (.witness)
```json
{
  "type": "TxWitness BabbageEra",
  "description": "Governance witness - council_member_1",
  "cborHex": "825820..."
}
```

### Signed Transaction (.tx)
```json
{
  "type": "Tx BabbageEra",
  "description": "council_rotation - signed by 2/3 members",
  "cborHex": "84a600..."
}
```

### Metadata (.metadata)
```json
{
  "transactionType": "council_rotation",
  "txHash": "0x7b81e566...",
  "requiredSigners": [...],
  "signaturesNeeded": {
    "totalSigners": 3,
    "calculatedThreshold": 2
  },
  "proposalDetails": {
    "currentLogicRound": 0,
    "newLogicRound": 1
  }
}
```

## Security Features

1. **Transaction Hash Validation** - Blake2b-256 hash verified before signing
2. **Signer Authorization** - Only authorized members can sign
3. **Signature Verification** - Ed25519 signatures validated
4. **Threshold Enforcement** - M-of-N requirement checked
5. **Replay Protection** - Logic round increments with each rotation
6. **Air-Gap Friendly** - No network access needed for signing

## Troubleshooting

### "Initial UTxO not found"
- Ensure the UTxO exists in your wallet
- Query UTxOs: `cardano-cli query utxo --address <addr>`

### "No suitable collateral UTxO"
- Need a pure 5+ ADA UTxO (no tokens)
- Create one: send 5 ADA to your address

### "Key hash not found in required signers"
- The mnemonic doesn't match any authorized member
- Verify you're using the correct member's mnemonic

### "Insufficient witnesses"
- Need threshold signatures (e.g., 2 of 3)
- Collect more witness files

### "Signature verification failed"
- Witness file may be corrupted
- Transaction hash may have changed
- Re-create the witness

## Advanced: Cardano-CLI Interoperability

All midnight-cli files are compatible with cardano-cli:

```bash
# View transaction body
cardano-cli debug transaction view --tx-body-file rotation.txbody

# Sign with cardano-cli
cardano-cli transaction witness \
  --tx-body-file rotation.txbody \
  --signing-key-file payment.skey \
  --out-file witness.witness

# Assemble with cardano-cli
cardano-cli transaction assemble \
  --tx-body-file rotation.txbody \
  --witness-file witness1.witness \
  --witness-file witness2.witness \
  --out-file rotation.tx

# Submit with cardano-cli
cardano-cli transaction submit \
  --tx-file rotation.tx \
  --testnet-magic 4
```

## Next Steps

1. Deploy contracts on testnet
2. Test rotation workflow
3. Set up air-gap machines for signing
4. Document your specific deployment process
5. Create runbooks for operations team

For more information, see:
- `midnight-cli deploy --help`
- `midnight-cli rotate --help`
- `midnight-cli witness --help`
