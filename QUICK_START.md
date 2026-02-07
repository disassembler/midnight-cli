# Midnight CLI - Quick Start Guide

## Installation

```bash
cargo build --release
# Binary at: ./target/release/midnight-cli
```

## Simplified Cold Signing Workflow

### 1. Prepare Your Mnemonic File

Create a simple text file with your 24-word phrase:

```bash
echo "your 24 word mnemonic phrase here..." > midnight.mnemonic
```

**For production, encrypt with GPG:**
```bash
echo "your mnemonic..." | gpg --symmetric --armor > midnight.mnemonic.gpg
```

### 2. Sign a Payload (Simplified Syntax)

The tool automatically:
- Constructs the derivation path
- Selects the correct key type (sr25519 or ed25519)
- Derives the key on-demand
- Never saves the key to disk

**Governance signature (sr25519):**
```bash
midnight-cli witness create \
  --payload proposal.txt \
  --mnemonic-file midnight.mnemonic \
  --purpose governance \
  --output witness.json \
  --yes
```

**Payment signature (sr25519):**
```bash
midnight-cli witness create \
  --payload transaction.bin \
  --mnemonic-file midnight.mnemonic \
  --purpose payment \
  --index 5 \
  --output witness-payment.json \
  --yes
```

**Finality signature (ed25519):**
```bash
midnight-cli witness create \
  --payload block.bin \
  --mnemonic-file midnight.mnemonic \
  --purpose finality \
  --output witness-finality.json \
  --yes
```

### 3. Verify the Witness

```bash
midnight-cli witness verify \
  --witness witness.json \
  --payload proposal.txt
```

## Before vs After Comparison

### OLD Syntax (Complex)
```bash
# User had to remember:
# - Full derivation path syntax
# - Key type for each purpose
# - Payload hash vs payload file

midnight-cli witness create \
  --payload-hash "0x688ce9ce936cf4555e3054a9b8308fe63ff68350b940d1db1236353e97926e1d" \
  --mnemonic "24 words here..." \
  --derivation-path "//midnight//payment//0" \
  --key-type sr25519 \
  --output witness.json
```

### NEW Syntax (Simple)
```bash
# Tool auto-constructs everything:
midnight-cli witness create \
  --payload proposal.txt \
  --mnemonic-file midnight.mnemonic \
  --purpose governance \
  --output witness.json \
  --yes
```

**What changed:**
- ✅ Use `--purpose` (and `--index` for payment keys only) instead of full `--derivation-path`
- ✅ No need to specify `--key-type` (auto-selected from purpose)
- ✅ Use `--payload <file>` instead of manually computing `--payload-hash`
- ✅ Use `--mnemonic-file` for cleaner, more secure mnemonic handling
- ✅ Governance and finality keys have no index (one per wallet), only payment keys use `--index`

## Key Generation Workflow

### Generate Keys Locally (for pre-signing)

```bash
# Generate from new mnemonic (will be displayed - save securely!)
midnight-cli key generate \
  --purpose governance \
  --output ./keys

# Generate from existing mnemonic file
midnight-cli key generate \
  --purpose governance \
  --mnemonic-file midnight.mnemonic \
  --output ./keys

# Batch generate payment keys (multiple per wallet)
midnight-cli key batch \
  --mnemonic-file midnight.mnemonic \
  --purposes payment \
  --indices 0,1,2,3,4,5,6,7,8,9 \
  --output ./keys
```

This creates paired files:
- `governance.skey` (private key - keep secure!)
- `governance.vkey` (public key - safe to share)

**Note:** Governance and finality keys have no index suffix because each wallet should have exactly one of each. Only payment keys use numbered files (`payment-0.skey`, `payment-1.skey`, etc.)

### Sign with Pre-generated Key

```bash
midnight-cli witness create \
  --payload proposal.txt \
  --key-file ./keys/governance.skey \
  --output witness.json \
  --yes
```

## File Formats

### Mnemonic Files

**Plain text** (`.mnemonic`, `.txt`):
```
legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title
```

**GPG encrypted** (`.mnemonic.gpg`, `.asc`):
```bash
# Auto-detected and decrypted transparently
midnight-cli witness create \
  --mnemonic-file midnight.mnemonic.gpg \
  --purpose governance \
  ...
```

### Key Files (Cardano Format)

**Signing key** (`governance.skey`):
```json
{
  "type": "GovernanceSigningKeyMidnight_sr25519",
  "description": "Midnight governance key",
  "cborHex": "5840..."
}
```

**Verification key** (`governance.vkey`):
```json
{
  "type": "GovernanceVerificationKeyMidnight_sr25519",
  "description": "Midnight governance key (public)",
  "cborHex": "5820..."
}
```

### Witness Files

```json
{
  "version": "1.0",
  "payload": {
    "hash": "0x...",
    "hashAlgorithm": "blake2b-256",
    "size": 123
  },
  "signature": {
    "type": "sr25519",
    "value": "0x...",
    "signer": {
      "publicKey": "0x...",
      "ss58Address": "5...",
      "derivationPath": "//midnight//governance"
    }
  },
  "metadata": {
    "timestamp": "2026-02-03T04:06:19.353116368+00:00",
    "purpose": "governance",
    "description": "Runtime upgrade proposal #42"
  }
}
```

## Key Purposes and Types

| Purpose | Key Type | Derivation Path | Index | Use Case |
|---------|----------|-----------------|-------|----------|
| `governance` | sr25519 | `//midnight//governance` | None (one per wallet) | Governance proposals, runtime upgrades |
| `payment` | sr25519 | `//midnight//payment//{index}` | Required (multiple per wallet) | Payment transactions |
| `finality` | ed25519 | `//midnight//finality` | None (one per wallet) | Consensus finality signatures |

**Security Policy:**
- Each wallet holds exactly **one** governance key and **one** finality key (no index)
- Each wallet can hold **multiple** payment keys (index required)

The tool automatically selects the correct key type based on the purpose you specify.

## Air-Gap Security Model

### Recommended Setup

**Cold Machine (Air-gapped):**
- midnight-cli installed
- `midnight.mnemonic.gpg` stored securely
- No network connection

**Hot Machine (Online):**
- Fetch governance proposals
- Build payload files
- Submit witnesses

### Workflow

1. **Hot machine**: Download proposal, create `proposal.txt`
2. **Transfer**: USB drive or QR code → `proposal.txt` to cold machine
3. **Cold machine**:
   ```bash
   midnight-cli witness create \
     --payload proposal.txt \
     --mnemonic-file midnight.mnemonic.gpg \
     --purpose governance \
     --output witness.json
   # Review payload hash on screen!
   ```
4. **Transfer**: USB drive → `witness.json` back to hot machine
5. **Hot machine**: Submit witness to Midnight Network

### Security Features

- ✅ All operations work completely offline
- ✅ Interactive confirmation shows payload hash for verification
- ✅ Secrets never logged or exposed except when explicitly requested
- ✅ GPG encryption support for mnemonic storage
- ✅ Cardano-compatible key format for dual-key air-gap setups
- ✅ Memory zeroization on secret key drop

## Advanced Usage

### Custom Derivation Paths

For non-standard paths, use explicit syntax:
```bash
midnight-cli witness create \
  --payload proposal.txt \
  --mnemonic-file midnight.mnemonic \
  --derivation-path "//custom//path//42" \
  --purpose governance \
  --output witness.json \
  --yes
```

### On-Demand Key Inspection

View derived key without saving to disk:
```bash
# Governance key (no index)
midnight-cli key derive \
  --mnemonic-file midnight.mnemonic \
  --derivation "//midnight//governance" \
  --key-type sr25519 \
  --purpose governance \
  --format json

# Payment key (with index)
midnight-cli key derive \
  --mnemonic-file midnight.mnemonic \
  --derivation "//midnight//payment//5" \
  --key-type sr25519 \
  --purpose payment \
  --format json
```

Output:
```json
{
  "keyType": "Sr25519",
  "keyPurpose": "Governance",
  "publicKey": "0x...",
  "ss58Address": "5...",
  "derivationPath": "//midnight//governance"
}
```

### Key File Inspection

```bash
midnight-cli key inspect governance.skey
```

Output:
```
Key Type:        GovernanceSigningKeyMidnight_sr25519
Description:     Midnight governance key
Public Key:      0x...
CBOR Hex:        5840...
```

## Troubleshooting

### "Invalid mnemonic"
- Ensure 24 words from BIP39 wordlist
- Check for typos or extra whitespace
- Verify file encoding (UTF-8)

### "GPG decryption failed"
- Ensure GPG key is available in keyring
- Check passphrase is correct
- Verify file is actually GPG-encrypted: `file midnight.mnemonic.gpg`

### "Witness verification failed"
- Payload file must be byte-identical to original
- Check for line ending changes (CRLF vs LF)
- Verify with: `sha256sum proposal.txt`

### "Unsupported derivation for ed25519"
- Ed25519 (finality) only supports hard derivation (`//`)
- Don't use soft paths (`/`) with finality keys

## Documentation

- **TEST_PLAN.md**: Comprehensive test scenarios
- **CLAUDE.md**: Architecture and developer documentation
- **README.md**: Project overview

## Support

Report issues at: [repository URL]
