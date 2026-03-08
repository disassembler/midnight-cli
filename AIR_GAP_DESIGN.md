# Air-Gap Workflow Design for Contract Deployment

## Problem Statement

The current `deploy-contracts` command requires mnemonic on the online machine to sign transactions. This is insecure for production deployments. We need an air-gap workflow that allows:

1. Creating unsigned transactions on an online machine (with UTxO queries)
2. Signing transactions on an air-gapped machine (with mnemonic)
3. Submitting signed transactions from the online machine

## Proposed Solution

### Three-Phase Workflow

#### Phase 1: Create Unsigned Transactions (Online Machine)
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

**What it does:**
- Queries wallet UTxOs from UTxORPC
- Builds unsigned Cardano transactions for:
  1. Council governance contract deployment (with datum + NFT mint)
  2. TA governance contract deployment (with datum + NFT mint)
- Saves to `./deployment-airgap/`:
  - `council-deploy.txbody` - Unsigned transaction CBOR
  - `council-deploy.payload` - Signing payload (tx body hash)
  - `council-deploy.metadata.json` - Human-readable transaction details
  - `ta-deploy.txbody` - Unsigned transaction CBOR
  - `ta-deploy.payload` - Signing payload (tx body hash)
  - `ta-deploy.metadata.json` - Human-readable transaction details
  - `deployment-plan.json` - Overall deployment metadata
- **Does NOT**:
  - Require mnemonic
  - Sign anything
  - Submit to network

#### Phase 2: Sign Transactions (Air-Gapped Machine)
```bash
# Transfer ./deployment-airgap/ to air-gapped machine via USB/QR

midnight-cli genesis deploy-contracts sign-offline \
  --airgap-dir ./deployment-airgap \
  --mnemonic-file ~/.cardano/deployment-wallet.mnemonic
```

**What it does:**
- Loads unsigned transaction payloads
- Loads mnemonic from file (supports GPG encryption)
- Creates wallet and derives signing keys
- Signs each transaction payload
- Saves to `./deployment-airgap/`:
  - `council-deploy.witness` - Signature witness CBOR
  - `ta-deploy.witness` - Signature witness CBOR
  - `council-deploy.txsigned` - Assembled signed transaction
  - `ta-deploy.txsigned` - Assembled signed transaction
- **Does NOT**:
  - Query network
  - Submit transactions

#### Phase 3: Submit Transactions (Online Machine)
```bash
# Transfer ./deployment-airgap/ back to online machine

midnight-cli genesis deploy-contracts submit \
  --airgap-dir ./deployment-airgap \
  --utxorpc http://localhost:50051 \
  --output deployment-info.json
```

**What it does:**
- Loads signed transactions
- Submits to Cardano network via UTxORPC
- Waits for confirmations
- Saves deployment info (addresses, policy IDs, tx hashes)
- Outputs Hayate configuration instructions

### Online Mode (Current Default)

For development/testing, keep the simple one-command flow:

```bash
midnight-cli genesis deploy-contracts \
  --council-contract ./contracts/council_governance.plutus \
  --ta-contract ./contracts/ta_governance.plutus \
  --council-member ./keys/council-member-1.json \
  --ta-member ./keys/ta-member-1.json \
  --mnemonic-file ~/.cardano/deployment-wallet.mnemonic \
  --utxorpc http://localhost:50051
```

This builds, signs, and submits in one step (no `--air-gap` flag).

## File Format Specifications

### Transaction Body (`*.txbody`)
- Raw CBOR of unsigned Cardano transaction body
- Binary format matching Cardano ledger specification

### Signing Payload (`*.payload`)
- BLAKE2b-256 hash of transaction body (32 bytes)
- Used for signature creation
- Text file with hex encoding for easy verification

### Metadata (`*.metadata.json`)
```json
{
  "contract_type": "council_governance",
  "network": "testnet",
  "script_hash": "...",
  "address": "...",
  "nft_policy_id": "...",
  "datum_cbor": "...",
  "inputs": [
    {"tx_hash": "...", "index": 0, "amount": 100000000}
  ],
  "outputs": [
    {"address": "...", "amount": 50000000, "datum": "..."}
  ],
  "fee": 200000,
  "payload_hash": "..."
}
```

### Witness (`*.witness`)
- CBOR-encoded witness set containing signature
- Binary format matching Cardano witness structure

### Signed Transaction (`*.txsigned`)
- Complete signed transaction ready for submission
- CBOR-encoded: transaction body + witness set

## Implementation Notes

### Hayate Transaction Builder Integration

Use hayate's `PlutusTransactionBuilder` with modifications:
1. Expose `build_unsigned()` method that returns transaction body only
2. Expose `add_witness()` method to add signatures from air-gap
3. Current `build()` method continues to work for online mode

### Signature Witness Format

Cardano transaction witnesses contain:
- Vkey (verification key - 32 bytes)
- Signature (Ed25519 signature - 64 bytes)

### UTxO Selection

For deterministic results, use the same UTxO selection algorithm:
1. Query all available UTxOs for payment address
2. Sort by (tx_hash, output_index)
3. Select UTxOs totaling required amount + fees
4. Use deterministic change calculation

## Comparison with Governance Workflow

| Feature | Governance Transactions | Contract Deployment |
|---------|------------------------|---------------------|
| Create unsigned | `tx propose` | `deploy-contracts --air-gap` |
| Sign offline | `witness create-extrinsic` | `deploy-contracts sign-offline` |
| Submit | `tx submit` | `deploy-contracts submit` |
| Payload format | Substrate SCALE | Cardano CBOR |
| Signature type | SR25519 | Ed25519 |

## Security Benefits

1. **Mnemonic never touches online machine**
2. **Signing happens on air-gapped machine**
3. **Transaction details visible before signing** (metadata.json)
4. **Payload hash can be manually verified** (*.payload file)
5. **Compatible with hardware wallets** (future enhancement)

## Testing Strategy

1. **Unit tests**: Transaction building, signing, assembling
2. **Integration tests**: Full air-gap workflow on local testnet
3. **Manual testing**: With actual SanchoNet deployment
4. **Audit points**: All file I/O, all cryptographic operations

## Future Enhancements

1. **QR code support** for payload transfer (like Polkadot Vault)
2. **Hardware wallet support** (Ledger, Trezor)
3. **Multi-sig support** for deployment transactions
4. **Automatic UTxO management** (coin selection optimization)
