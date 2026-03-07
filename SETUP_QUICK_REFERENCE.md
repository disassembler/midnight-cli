# Midnight Chain Setup - Quick Reference

## 🔐 Phase 1: Generate Keys (Air-Gapped)

```bash
# Generate mnemonics (24 words each)
midnight-cli mnemonic generate > validator1.mnemonic
midnight-cli mnemonic generate > ta1.mnemonic
midnight-cli mnemonic generate > council1.mnemonic

# Generate validator keys (repeat for each validator)
midnight-cli validator generate \
  --mnemonic-file validator1.mnemonic \
  --hostname validator1.network \
  --port 30333 \
  --output validator1-keys.json

# Generate TA governance keys (repeat for each TA member)
midnight-cli governance generate \
  --mnemonic-file ta1.mnemonic \
  --output ta1-governance.json

# Generate Council governance keys (repeat for each council member)
midnight-cli governance generate \
  --mnemonic-file council1.mnemonic \
  --output council1-governance.json
```

**Outputs**: `*-keys.json` files (safe to share with chain coordinator)

---

## 🌐 Phase 2: Deploy Governance Contracts (Online, Cardano)

✅ **Status**: Parameter application fully implemented. Threshold auto-calculated.

```bash
# Generate deployment wallet
midnight-cli mnemonic generate > deployment-wallet.mnemonic

# Fund the wallet with testnet/mainnet ADA
# (get address from command, send ADA via Daedalus/Yoroi)

# Deploy contracts (threshold auto-calculated based on member count)
midnight-cli genesis deploy-contracts \
  --council-member council1-governance.json \
  --council-member council2-governance.json \
  --council-member council3-governance.json \
  --ta-member ta1-governance.json \
  --ta-member ta2-governance.json \
  --ta-member ta3-governance.json \
  --network testnet \
  --utxorpc http://localhost:50051 \
  --mnemonic-file deployment-wallet.mnemonic \
  --output deployment-info.json
```

**Output**: `deployment-info.json` + Hayate configuration instructions

---

## 🔧 Phase 2.5: Configure Hayate (Online)

```bash
# Export wallet account public key
midnight-cli key export-account-key \
  --mnemonic-file deployment-wallet.mnemonic \
  --account 0 \
  --format hex

# Follow the output instructions to:
# 1. Add script addresses to hayate.yaml
# 2. Add account public key to hayate.yaml
# 3. Add NIGHT token policy to hayate.yaml
# 4. Restart Hayate
```

**Purpose**: Enables Hayate to index governance contracts and wallet addresses

---

## ⚙️ Phase 3: Build Chain Spec (Online, with midnight-node)

```bash
midnight-cli genesis init \
  --validator validator1-keys.json \
  --validator validator2-keys.json \
  --validator validator3-keys.json \
  --ta ta1-governance.json \
  --ta ta2-governance.json \
  --ta ta3-governance.json \
  --council council1-governance.json \
  --council council2-governance.json \
  --council council3-governance.json \
  --night-policy-id <NIGHT_TOKEN_POLICY_ID> \
  --chain-id mychain \
  --chainspec-dir ./chainspec \
  --midnight-node-res ~/midnight-node/res \
  --output genesis.json
```

**Outputs**:
- `genesis.json`
- `chainspec/chain-spec.json` (ready for validators!)
- 8 chainspec config files

---

## 📱 Phase 4: Export for Mobile (Optional)

```bash
# Generate QR code for Polkadot Vault
midnight-cli genesis export-network \
  --chainspec ./chainspec/chain-spec.json \
  --name "My Midnight Network" \
  --out-file network-qr.png
```

---

## 🚀 Phase 5: Start Validators

Each validator receives:
- Their `*.skey` files (secret)
- `chain-spec.json` (public)
- `genesis.json` (public)

```bash
midnight-node \
  --chain ./chain-spec.json \
  --base-path ~/.midnight/chains/mychain \
  --validator \
  --name "Validator 1"
```

---

## 🗳️ Phase 6: Governance (Ongoing)

### Propose Change (Online)
```bash
midnight-cli tx propose membership council add-member 5NewAddr... \
  --endpoint ws://localhost:9944 \
  --output-dir ./proposals
```

### Sign (Air-Gapped, Each Member)
```bash
midnight-cli witness create-extrinsic \
  --payload ./proposals/proposal.payload \
  --mnemonic-file council1.mnemonic \
  --output signature.extrinsic
```

### Submit (Online)
```bash
midnight-cli tx submit --extrinsic signature.extrinsic
```

### Check Status
```bash
midnight-cli query proposals
```

---

## 📊 Timeline Estimate

| Phase | Time | Parallelizable? |
|-------|------|-----------------|
| 1. Generate Keys | ~5 min per participant | ✅ Yes |
| 2. Deploy Contracts | ~10-15 min | ❌ No (needs funding) |
| 3. Build Chain Spec | ~5 min | ❌ No (needs all keys) |
| 4. Export QR | ~1 min | ✅ Yes (optional) |
| 5. Start Validators | ~2 min per validator | ✅ Yes |

**Total**: ~30-45 minutes for a 3-validator, 3-TA, 3-council setup

---

## 🔑 Key Insights

1. **One Mnemonic Per Participant**: Each person generates ONE mnemonic that derives both Cardano and Midnight keys
2. **Air-Gap Critical Operations**: Key generation and signing happen offline
3. **Public Keys Safe to Share**: Only `*.skey` and `*.mnemonic` are secrets
4. **Deterministic**: Same inputs = same chain spec (reproducible builds)
5. **Cardano Integration**: Governance contracts live on Cardano, enforcing on-chain governance

---

## 🎯 UX Status & Remaining Improvements

### Recently Completed ✅:
1. ~~**Threshold Not Auto-Calculated**~~: ✅ Now automatically calculates 2/3 majority from member count
2. ~~**No Hayate Integration Guide**~~: ✅ Commands now output Hayate config snippets and next steps
3. ~~**No Account Key Export**~~: ✅ Added `key export-account-key` command for Hayate indexing

### Remaining Issues:
1. **Manual Contract CBOR Files**: Phase 2 requires pre-generated `.cbor` files (parameter application is implemented but not fully integrated)
2. **No Validation**: Commands don't validate that you have 3+ members before building
3. **No Dry-Run**: Can't preview chain spec before deployment
4. **File Juggling**: Many JSON files to manage (could use directory conventions)

### Proposed Improvements:
```bash
# Future ideal UX - single command setup:
midnight-cli genesis create-chain \
  --name "My Chain" \
  --keys-dir ./keys \
  --output-dir ./chain-setup \
  --dry-run  # Preview before deploying

# Would automatically:
# - Count participants and set thresholds
# - Apply validator parameters
# - Deploy contracts
# - Build chain spec
# - Export QR codes
# - Validate configuration
```
