# Midnight Network Setup Guide

Complete UX walkthrough for setting up a new Midnight chain from scratch.

## Prerequisites

- **Cardano Node**: Access to a Cardano testnet/mainnet node with UTxORPC endpoint
- **Midnight Node**: Compiled `midnight-node` binary in PATH or specified location
- **Funding**: Testnet/mainnet ADA to fund governance contract deployment
- **Participants**:
  - 3+ validator operators (each needs their own mnemonic)
  - 3+ Technical Advisory (TA) members (each needs their own mnemonic)
  - 3+ Council members (each needs their own mnemonic)

## Phase 1: Generate All Keys (Air-Gapped)

### Step 1.1: Generate Validator Keys

Each validator operator generates their keys from a 24-word BIP39 mnemonic:

```bash
# Validator 1 (on air-gapped machine)
midnight-cli mnemonic generate > validator1.mnemonic
chmod 600 validator1.mnemonic

midnight-cli validator generate \
  --mnemonic-file validator1.mnemonic \
  --hostname validator1.midnight.network \
  --port 30333 \
  --output validator1-keys.json \
  --write-key-files \
  --key-files-dir ./validator1-keys
```

**Output**:
- `validator1-keys.json` - Public keys (safe to share)
- `validator1-keys/*.skey` - Secret keys (KEEP SECURE, needed by midnight-node)
- `validator1.mnemonic` - Seed phrase (BACKUP SECURELY)

**Repeat for validator2, validator3, etc.**

### Step 1.2: Generate Governance Keys (Technical Advisory)

Each TA member generates governance keys from their mnemonic:

```bash
# TA Member 1 (on air-gapped machine)
midnight-cli mnemonic generate > ta1.mnemonic
chmod 600 ta1.mnemonic

midnight-cli governance generate \
  --mnemonic-file ta1.mnemonic \
  --output ta1-governance.json \
  --write-key-files \
  --key-files-dir ./ta1-keys
```

**Output**:
- `ta1-governance.json` - Contains both Cardano key hash and SR25519 public key (safe to share)
- `ta1-keys/*.skey` - Secret keys (KEEP SECURE, needed for governance signing)
- `ta1.mnemonic` - Seed phrase (BACKUP SECURELY)

**Note**: Cardano key is auto-derived at `1852H/1815H/0H/0/0` from the same mnemonic!

**Repeat for ta2, ta3, etc.**

### Step 1.3: Generate Governance Keys (Council)

Each Council member generates governance keys:

```bash
# Council Member 1 (on air-gapped machine)
midnight-cli mnemonic generate > council1.mnemonic
chmod 600 council1.mnemonic

midnight-cli governance generate \
  --mnemonic-file council1.mnemonic \
  --output council1-governance.json \
  --write-key-files \
  --key-files-dir ./council1-keys
```

**Repeat for council2, council3, etc.**

### Step 1.4: Aggregate Public Keys

Collect all public key JSON files (safe to share):
```
keys/
  validators/
    validator1-keys.json
    validator2-keys.json
    validator3-keys.json
  ta/
    ta1-governance.json
    ta2-governance.json
    ta3-governance.json
  council/
    council1-governance.json
    council2-governance.json
    council3-governance.json
```

## Phase 2: Deploy Governance Contracts to Cardano (Online)

**Status**: ✅ Parameter application fully implemented

```bash
# On online machine with UTxORPC access

# Generate wallet mnemonic for contract deployment
midnight-cli mnemonic generate > deployment-wallet.mnemonic

# Fund the wallet address (get address from command output)
midnight-cli genesis deploy-contracts \
  --council-contract council-governance.cbor \
  --ta-contract ta-governance.cbor \
  --council-member keys/council/council1-governance.json \
  --council-member keys/council/council2-governance.json \
  --council-member keys/council/council3-governance.json \
  --ta-member keys/ta/ta1-governance.json \
  --ta-member keys/ta/ta2-governance.json \
  --ta-member keys/ta/ta3-governance.json \
  --network testnet \
  --utxorpc http://localhost:50051 \
  --mnemonic-file deployment-wallet.mnemonic \
  --output deployment-info.json
```

**Note**: The 2/3 threshold is automatically calculated based on the number of members. With 3 members, threshold = 2.

**Output** (`deployment-info.json`):
```json
{
  "network": "testnet",
  "council_contract": {
    "script_hash": "abc123...",
    "address": "addr_test1...",
    "nft_policy_id": "def456...",
    "nft_asset_name": "436f756e63696c4e4654",
    "datum_cbor": "d8799f...",
    "tx_hash": "789abc...",
    "members": 3,
    "threshold": 2
  },
  "ta_contract": {
    "script_hash": "ghi789...",
    "address": "addr_test1...",
    "nft_policy_id": "jkl012...",
    "nft_asset_name": "5441676f764e4654",
    "datum_cbor": "d8799f...",
    "tx_hash": "345def...",
    "members": 3,
    "threshold": 2
  }
}
```

The command will also output helpful Hayate configuration instructions to guide you to the next steps.

## Phase 2.5: Configure Hayate for Wallet Indexing (Online)

After deploying contracts, configure Hayate to index the governance contracts and wallet:

### Step 2.5.1: Export Wallet Account Public Key

```bash
# Export the account-level public key for Hayate indexing
midnight-cli key export-account-key \
  --mnemonic-file deployment-wallet.mnemonic \
  --account 0 \
  --format hex
```

**Output**: Hex-encoded public key + Hayate configuration snippet

### Step 2.5.2: Update Hayate Configuration

Add the following to your `hayate.yaml` or Hayate configuration:

```yaml
# Governance script addresses
scripts:
  - name: "council-governance"
    address: "<council_contract_address_from_deployment_info>"
    nft_policy_id: "<council_nft_policy_id>"

  - name: "ta-governance"
    address: "<ta_contract_address_from_deployment_info>"
    nft_policy_id: "<ta_nft_policy_id>"

# Wallet account for indexing
accounts:
  - name: "governance-wallet"
    account_index: 0
    public_key: "<hex_output_from_export_account_key>"

# NIGHT token policy
tokens:
  - policy_id: "<NIGHT_POLICY_ID>"
    asset_name: "NIGHT"
    decimals: 18
```

### Step 2.5.3: Restart Hayate

```bash
# Systemd
systemctl restart hayate

# Or Docker Compose
docker-compose restart hayate

# Or manual process restart
pkill -TERM hayate && hayate --config hayate.yaml
```

**Verify indexing**:
- Check Hayate logs for successful script address indexing
- Query Hayate API to verify governance contract UTxOs are being tracked
- Confirm wallet addresses are being derived and indexed

## Phase 3: Generate Genesis Configuration

With all keys collected and governance contracts deployed:

```bash
# On machine with midnight-node binary in PATH
midnight-cli genesis init \
  --validator keys/validators/validator1-keys.json \
  --validator keys/validators/validator2-keys.json \
  --validator keys/validators/validator3-keys.json \
  --ta keys/ta/ta1-governance.json \
  --ta keys/ta/ta2-governance.json \
  --ta keys/ta/ta3-governance.json \
  --council keys/council/council1-governance.json \
  --council keys/council/council2-governance.json \
  --council keys/council/council3-governance.json \
  --night-policy-id <NIGHT_TOKEN_POLICY_ID> \
  --chain-id mychain \
  --chainspec-dir ./chainspec \
  --midnight-node-res ~/midnight-node/res \
  --output genesis.json
```

**This command**:
1. ✅ Creates `genesis.json` with all validator and governance keys
2. ✅ Generates 8 chainspec config files in `./chainspec/`:
   - `permissioned-candidates-config.json`
   - `federated-authority-config.json` (with SS58→hex conversion)
   - `cnight-config.json`
   - `ics-config.json`
   - `reserve-config.json`
   - `pc-chain-config.json`
   - `system-parameters-config.json`
   - `registered-candidates-addresses.json`
3. ✅ Executes `midnight-node build-spec --disable-default-bootnode`
4. ✅ Outputs final `chainspec/chain-spec.json` (ready for validators!)

## Phase 4: Export Network Specs (Optional)

Generate QR codes for Polkadot Vault (mobile governance signing):

```bash
# Unsigned QR (for testing)
midnight-cli genesis export-network \
  --chainspec ./chainspec/chain-spec.json \
  --name "My Midnight Network" \
  --unit NIGHT \
  --decimals 18 \
  --ss58-format 42

# Signed QR (production - requires network signer mnemonic)
midnight-cli mnemonic generate > network-signer.mnemonic

midnight-cli genesis export-network \
  --chainspec ./chainspec/chain-spec.json \
  --signer-mnemonic-file network-signer.mnemonic \
  --name "My Midnight Network" \
  --color "#6f42c1" \
  --out-file network-qr.png
```

**Output**: ASCII QR code printed to terminal, or PNG file for import into Polkadot Vault.

## Phase 5: Distribute to Validators

Each validator operator receives:
1. **Secret Keys**: Their `validator-keys/*.skey` files (from Phase 1.1)
2. **Chain Spec**: The `chain-spec.json` file (from Phase 3)
3. **Genesis**: The `genesis.json` file (from Phase 3)

### Validator Setup

```bash
# Each validator operator (on their node machine)
mkdir -p ~/.midnight/chains/mychain

# Copy files received from chain coordinator
cp validator-keys/*.skey ~/.midnight/chains/mychain/
cp chain-spec.json ~/.midnight/chains/mychain/
cp genesis.json ~/.midnight/chains/mychain/

# Start midnight-node
midnight-node \
  --chain ./chain-spec.json \
  --base-path ~/.midnight/chains/mychain \
  --validator \
  --name "Validator 1" \
  --rpc-port 9944 \
  --port 30333
```

## Phase 6: Governance Operations (Ongoing)

### Update Council Members (Example)

**Step 1: Create Proposal (Online Machine)**
```bash
midnight-cli tx propose membership council add-member 5NewMember... \
  --endpoint ws://localhost:9944 \
  --output-dir ./governance-payloads
```

**Output**: `./governance-payloads/council-add-member.payload`

**Step 2: Transfer to Air-Gap Machine** (via USB/QR)

**Step 3: Sign (Air-Gapped - Each Council Member)**
```bash
# Council Member 1
midnight-cli witness create-extrinsic \
  --payload ./governance-payloads/council-add-member.payload \
  --metadata ./governance-payloads/council-add-member.json \
  --mnemonic-file council1.mnemonic \
  --output council1-signature.extrinsic \
  --yes
```

**Step 4: Transfer Back to Online Machine**

**Step 5: Submit (Online)**
```bash
midnight-cli tx submit \
  --extrinsic council1-signature.extrinsic \
  --endpoint ws://localhost:9944
```

**Step 6: Query Status**
```bash
midnight-cli query proposals --verbose --endpoint ws://localhost:9944
```

**Repeat Steps 3-5 for council2, council3 until threshold (2/3) reached**

**Step 7: Close Proposal (After Threshold)**
```bash
midnight-cli tx close council \
  --proposal-index 0 \
  --state-file ./governance-payloads/state.json \
  --endpoint ws://localhost:9944
```

## Summary of Air-Gap vs Online Operations

### Air-Gapped (Cold Storage)
- ✅ Generate mnemonics
- ✅ Generate validator keys
- ✅ Generate governance keys
- ✅ Sign governance transactions
- ✅ Create witnesses

### Online (Hot)
- ✅ Deploy governance contracts to Cardano
- ✅ Query chain state
- ✅ Create governance proposals
- ✅ Submit signed transactions
- ✅ Monitor proposal status

## File Security Summary

| File Type | Contains Secrets? | Storage |
|-----------|------------------|---------|
| `*.mnemonic` | ✅ YES | Encrypted backup, air-gap only |
| `*.skey` | ✅ YES | Secure storage, needed for signing |
| `*.vkey` | ❌ No | Safe to share |
| `*-keys.json` | ❌ No (public keys only) | Safe to share |
| `*-governance.json` | ❌ No (public keys only) | Safe to share |
| `genesis.json` | ❌ No | Safe to distribute |
| `chain-spec.json` | ❌ No | Safe to distribute |
| `deployment-info.json` | ❌ No | Safe to share |
| `*.payload` | ❌ No | Safe to transfer |
| `*.extrinsic` | ❌ No (signed, but not secret) | Safe to transfer |

## Known Limitations / TODO

1. **Deploy Contracts**: Currently uses native scripts, needs refactoring to use new `apply_params()` utilities for proper one-shot NFT Plutus validators

2. **Federated Ops**: Not yet exposed in CLI (would be a third governance body that requires approval from both Council and TA)

3. **Key Rotation**: Commands exist (`rotate-council-keys`, `rotate-ta-keys`) but need testing

4. **Extended Key Testing**: Need to empirically verify BIP32 extended keys work with Cardano signature verification in governance contracts

## Architecture Notes

The system uses a **dual-key governance model**:
- **Cardano Keys** (Ed25519): For signing Cardano transactions (governance contract updates)
- **Midnight Keys** (SR25519): For Midnight network consensus and finality

Both keys are derived from the **same mnemonic** for each participant, ensuring a single backup recovery path while maintaining separation between the two chains.
