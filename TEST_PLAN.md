# Midnight CLI - Test Plan and User Guide

## Overview

The Midnight CLI is a comprehensive key management and witness generation tool for the Midnight Network. It supports hierarchical key derivation using Substrate SURI format, multiple key types (governance, payment, finality) with different cryptographic schemes (sr25519, ed25519), and produces Cardano-style typed JSON key files.

**Key Capabilities:**
- Generate BIP39 24-word mnemonics
- Derive keys using Substrate SURI paths (`//midnight//governance`, `//midnight//payment//{index}`)
- Support sr25519 (governance, payment) and ed25519 (finality) keys
- Generate Cardano-style `.skey` and `.vkey` JSON files with CBOR encoding
- Create and verify cryptographic witnesses for governance proposals
- Two workflows: pre-derive (save key files) and on-demand (derive dynamically)
- Optional GPG encryption for mnemonic files
- Security policy: One governance key and one finality key per wallet (no index), multiple payment keys (index required)

## Architecture

The tool follows clean architecture with 5 layers:
1. **Domain Layer**: Core types (KeyPurpose, KeyTypeId, SURI, KeyMaterial)
2. **Crypto Layer**: Sr25519/Ed25519 operations, SURI parsing
3. **Storage Layer**: Cardano JSON format, GPG support, file I/O
4. **Application Layer**: Use cases (KeyGeneration, WitnessCreation)
5. **CLI Layer**: Command interface and argument parsing

## Prerequisites

- Rust 1.75 or higher
- GPG (optional, for encrypted mnemonic files)
- Git (for cloning the repository)

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd midnight-cli

# Build release version
cargo build --release

# The binary will be at: ./target/release/midnight-cli
```

## Test Scenarios

### Scenario 1: Generate a New Mnemonic

**Purpose**: Create a new BIP39 24-word mnemonic for cold storage

**Command**:
```bash
midnight-cli key generate --purpose governance --output-dir ./keys/
```

**Expected Output**:
- New 24-word mnemonic phrase displayed
- Warning: "Store this mnemonic in a secure location!"
- Files created: `governance.skey` and `governance.vkey`

**Validation**:
```bash
# Check file structure
cat ./keys/governance.vkey
```

**Expected JSON Structure**:
```json
{
  "type": "GovernanceVerificationKeyMidnight_sr25519",
  "description": "Midnight governance key (public)",
  "cborHex": "5820..."
}
```

### Scenario 2: Batch Key Generation

**Purpose**: Generate multiple payment keys from a single mnemonic (cold storage setup)

**Test Mnemonic**:
```
legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title
```

**Command**:
```bash
mkdir -p ./scratch/keys-batch

midnight-cli key batch \
  --mnemonic "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title" \
  --purposes payment \
  --indices 0,1,2,3,4 \
  --output ./scratch/keys-batch/
```

**Expected Output**:
- 10 files created (5 .skey + 5 .vkey pairs)
- Files: `payment-0.skey`, `payment-0.vkey`, ..., `payment-4.skey`, `payment-4.vkey`
- Console output: "Generated 5 key pairs"

**Validation**:
```bash
ls -1 ./scratch/keys-batch/
# Should show:
# payment-0.skey
# payment-0.vkey
# payment-1.skey
# payment-1.vkey
# ... (up to 4)
```

**Note**: Batch generation is only used for payment keys since governance and finality keys have no index (one per wallet).

### Scenario 3: On-Demand Key Derivation

**Purpose**: Derive keys dynamically without saving files (air-gap signing scenario)

**Command (Governance - no index)**:
```bash
midnight-cli key derive \
  --mnemonic "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title" \
  --derivation "//midnight//governance" \
  --key-type sr25519 \
  --purpose governance \
  --format json
```

**Expected Output** (JSON format):
```json
{
  "keyType": "Sr25519",
  "keyPurpose": "Governance",
  "publicKey": "0x...",
  "secretKey": "0x...",
  "ss58Address": "5...",
  "derivationPath": "//midnight//governance"
}
```

**Command (Payment - with index)**:
```bash
midnight-cli key derive \
  --mnemonic "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title" \
  --derivation "//midnight//payment//2" \
  --key-type sr25519 \
  --purpose payment \
  --format json
```

**Expected Output** (JSON format):
```json
{
  "keyType": "Sr25519",
  "keyPurpose": "Payment",
  "publicKey": "0x...",
  "secretKey": "0x...",
  "ss58Address": "5...",
  "derivationPath": "//midnight//payment//2"
}
```

**Alternative Text Format**:
```bash
midnight-cli key derive \
  --mnemonic "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title" \
  --derivation "//midnight//payment//2" \
  --key-type sr25519 \
  --purpose payment \
  --format text
```

**Expected Output** (Text format):
```
Key Type:        Sr25519
Purpose:         Payment
Public Key:      0x...
Secret Key:      0x...
SS58 Address:    5...
Derivation Path: //midnight//payment//2
```

### Scenario 4: Key Inspection

**Purpose**: View key file contents in human-readable format

**Command**:
```bash
midnight-cli key inspect ./scratch/keys-batch/payment-0.vkey
```

**Expected Output**:
```
Key Type:        PaymentVerificationKeyMidnight_sr25519
Description:     Midnight payment key (public)
Public Key:      0x...
CBOR Hex:        5820...
```

### Scenario 5: Multiple Key Types

**Purpose**: Verify support for all key types with their correct cryptographic schemes

**Commands**:
```bash
# Governance (sr25519) - no index, one per wallet
midnight-cli key generate \
  --mnemonic "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title" \
  --purpose governance \
  --output ./scratch/keys/

# Payment (sr25519) - index required, multiple per wallet
midnight-cli key generate \
  --mnemonic "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title" \
  --purpose payment \
  --index 0 \
  --output ./scratch/keys/

# Finality (ed25519) - no index, one per wallet
midnight-cli key generate \
  --mnemonic "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title" \
  --purpose finality \
  --output ./scratch/keys/
```

**Expected Files**:
- `governance.skey` / `governance.vkey` (type: `GovernanceSigningKeyMidnight_sr25519` / `GovernanceVerificationKeyMidnight_sr25519`)
- `payment-0.skey` / `payment-0.vkey` (type: `PaymentSigningKeyMidnight_sr25519` / `PaymentVerificationKeyMidnight_sr25519`)
- `finality.skey` / `finality.vkey` (type: `FinalitySigningKeyMidnight_ed25519` / `FinalityVerificationKeyMidnight_ed25519`)

**Validation**:
```bash
# Check each key type
jq '.type' ./scratch/keys/governance.skey
jq '.type' ./scratch/keys/payment-0.skey
jq '.type' ./scratch/keys/finality.skey
```

### Scenario 6: Witness Creation from Key File

**Purpose**: Sign a payload hash using a pre-derived key file

**Setup**:
```bash
# Create test payload
echo "This is a runtime upgrade proposal for Midnight Network" > ./scratch/payload.txt

# Generate hash
PAYLOAD_HASH=$(b2sum -l 256 ./scratch/payload.txt | cut -d' ' -f1)
echo "Payload hash: $PAYLOAD_HASH"
```

**Command**:
```bash
midnight-cli witness create \
  --payload-hash "0x${PAYLOAD_HASH}" \
  --key-file ./scratch/keys/governance-0.skey \
  --output ./scratch/witness.json \
  --description "Runtime upgrade proposal #42"
```

**Expected Output**:
- File created: `witness.json`
- Console: "Witness created successfully: ./scratch/witness.json"

**Validation**:
```bash
cat ./scratch/witness.json
```

**Expected Structure**:
```json
{
  "version": "1.0",
  "payload": {
    "hash": "0x688ce9ce936cf4555e3054a9b8308fe63ff68350b940d1db1236353e97926e1d",
    "hashAlgorithm": "blake2b-256",
    "size": 45
  },
  "signature": {
    "type": "sr25519",
    "value": "0x...",
    "signer": {
      "publicKey": "0x0a776062785aa50cf7b25b84758d36ea54a619b64535a087e6115740d4465f00",
      "ss58Address": "5CJRoFX52KcWfgJQwTwLxwn7fDMWRVn722gCoXBJRNYeVkR6",
      "derivationPath": null
    }
  },
  "metadata": {
    "timestamp": "2026-02-03T03:55:00.471714402+00:00",
    "purpose": "governance",
    "description": null
  }
}
```

### Scenario 7: On-Demand Witness Creation (Simplified)

**Purpose**: Sign a payload using on-demand key derivation with simplified syntax

**Test Setup**:
```bash
# Create a plain text mnemonic file
echo "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title" > mnemonic.txt
```

**Command** (Simplified - Recommended):
```bash
midnight-cli witness create \
  --payload ./payload.txt \
  --mnemonic-file mnemonic.txt \
  --purpose governance \
  --output ./witness-simple.json \
  --description "Runtime upgrade proposal #42" \
  --yes
```

**Expected Output**:
- File created: `witness-simple.json`
- Derivation path auto-constructed: `//midnight//governance` (no index - one per wallet)
- Key type auto-selected: `sr25519` (for governance)

**Command** (Explicit Path - For Advanced Use):
```bash
midnight-cli witness create \
  --payload ./payload.txt \
  --mnemonic-file mnemonic.txt \
  --derivation-path "//midnight//payment//42" \
  --purpose payment \
  --output ./witness-explicit.json \
  --description "Custom derivation path" \
  --yes
```

**Expected Output**:
- Uses the explicit derivation path provided
- Still requires `--purpose` for metadata
- Note: Only payment keys support custom index values

**Key Features**:
- Auto-constructs standard derivation paths from purpose and index
- Auto-selects key type based on purpose:
  - governance → sr25519
  - payment → sr25519
  - finality → ed25519
- Supports both `.mnemonic`, `.mnemonic.gpg`, or any text file
- Backward compatible with explicit `--derivation-path`

**Test Different Key Types**:
```bash
# Payment key (sr25519)
midnight-cli witness create \
  --payload ./payload.txt \
  --mnemonic-file mnemonic.txt \
  --purpose payment \
  --index 5 \
  --output ./witness-payment.json \
  --yes

# Finality key (ed25519)
midnight-cli witness create \
  --payload ./payload.txt \
  --mnemonic-file mnemonic.txt \
  --purpose finality \
  --output ./witness-finality.json \
  --yes
```

**Validation**:
```bash
# Check auto-constructed derivation paths
jq '.signature.signer.derivationPath' witness-simple.json
# Output: "//midnight//governance"

jq '.signature.signer.derivationPath' witness-payment.json
# Output: "//midnight//payment//5"

jq '.signature.signer.derivationPath' witness-finality.json
# Output: "//midnight//finality"

# Verify key types
jq '.signature.type' witness-simple.json    # "sr25519"
jq '.signature.type' witness-payment.json   # "sr25519"
jq '.signature.type' witness-finality.json  # "ed25519"
```

### Scenario 8: Witness Verification

**Purpose**: Verify a witness signature is valid for a given payload

**Command**:
```bash
midnight-cli witness verify \
  --witness ./scratch/witness.json \
  --payload ./scratch/payload.txt
```

**Expected Output**:
```
Witness verification: VALID

Witness details:
  Version:         1.0
  Payload Hash:    0x688ce9ce936cf4555e3054a9b8308fe63ff68350b940d1db1236353e97926e1d
  Signature Type:  sr25519
  Signer Address:  5CJRoFX52KcWfgJQwTwLxwn7fDMWRVn722gCoXBJRNYeVkR6
  Purpose:         governance
  Timestamp:       2026-02-03T03:55:00.471714402+00:00
  Description:     Runtime upgrade proposal #42
```

**Negative Test** (tampered payload):
```bash
echo "Tampered payload" > ./scratch/payload-bad.txt

midnight-cli witness verify \
  --witness ./scratch/witness.json \
  --payload ./scratch/payload-bad.txt
```

**Expected Output**:
```
Witness verification: INVALID
Error: Signature verification failed
```

### Scenario 9: GPG-Encrypted Mnemonic

**Purpose**: Support secure storage of mnemonic using GPG encryption

**Setup**:
```bash
# Create encrypted mnemonic file
echo "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title" | \
  gpg --encrypt --armor --recipient your-key@example.com > ./scratch/mnemonic.txt.asc
```

**Command**:
```bash
midnight-cli key generate \
  --mnemonic-file ./scratch/mnemonic.txt.asc \
  --purpose governance \
  --output ./scratch/keys/
```

**Expected Behavior**:
- Tool auto-detects GPG encryption
- Prompts for GPG passphrase
- Decrypts mnemonic
- Generates keys normally

### Scenario 10: Deterministic Key Generation

**Purpose**: Verify same mnemonic + derivation path produces identical keys

**Commands**:
```bash
# Generate key first time
midnight-cli key generate \
  --mnemonic "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title" \
  --purpose governance \
  --output-dir ./scratch/test1/

# Generate same key second time
midnight-cli key generate \
  --mnemonic "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title" \
  --purpose governance \
  --output-dir ./scratch/test2/
```

**Validation**:
```bash
diff ./scratch/test1/governance.vkey ./scratch/test2/governance.vkey
# Should show no differences (exit code 0)

# Verify public keys match
jq -r '.cborHex' ./scratch/test1/governance.vkey
jq -r '.cborHex' ./scratch/test2/governance.vkey
# Should output identical CBOR hex strings
```

## Test Results Summary

Run all test scenarios and record results:

| Scenario | Test | Status | Notes |
|----------|------|--------|-------|
| 1 | Generate new mnemonic | ☐ Pass / ☐ Fail | |
| 2 | Batch key generation | ☐ Pass / ☐ Fail | |
| 3 | On-demand derivation (JSON) | ☐ Pass / ☐ Fail | |
| 3 | On-demand derivation (Text) | ☐ Pass / ☐ Fail | |
| 4 | Key inspection | ☐ Pass / ☐ Fail | |
| 5 | Governance keys (sr25519) | ☐ Pass / ☐ Fail | |
| 5 | Payment keys (sr25519) | ☐ Pass / ☐ Fail | |
| 5 | Finality keys (ed25519) | ☐ Pass / ☐ Fail | |
| 6 | Witness from key file | ☐ Pass / ☐ Fail | |
| 7 | Witness on-demand | ☐ Pass / ☐ Fail | |
| 8 | Witness verification (valid) | ☐ Pass / ☐ Fail | |
| 8 | Witness verification (invalid) | ☐ Pass / ☐ Fail | |
| 9 | GPG-encrypted mnemonic | ☐ Pass / ☐ Fail | |
| 10 | Deterministic generation | ☐ Pass / ☐ Fail | |

## Command Reference

### Key Management

```bash
# Generate governance or finality key (no index - one per wallet)
midnight-cli key generate --purpose <governance|finality> --output-dir <dir>

# Generate payment key (index required - multiple per wallet)
midnight-cli key generate --purpose payment --index <N> --output-dir <dir>

# Generate keys from existing mnemonic (CLI)
midnight-cli key generate --mnemonic "<24-word phrase>" --purpose <type> [--index <N>] --output-dir <dir>

# Generate keys from mnemonic file
midnight-cli key generate --mnemonic-file <path> --purpose <type> [--index <N>] --output-dir <dir>

# Batch generate multiple payment keys
midnight-cli key batch --mnemonic "<phrase>" --purposes payment --indices 0,1,2 --output-dir <dir>

# Derive key on-demand (no file output)
midnight-cli key derive --mnemonic "<phrase>" --derivation <path> --key-type <sr25519|ed25519> --purpose <type> --format <json|text>

# Inspect key file
midnight-cli key inspect <path-to-key-file>
```

### Witness Operations

```bash
# Create witness from key file
midnight-cli witness create \
  --payload <file> \
  --key-file <path-to-skey> \
  --output <path> \
  [--description <text>] \
  [--yes]

# Create witness from mnemonic - governance/finality (no index)
midnight-cli witness create \
  --payload <file> \
  --mnemonic-file <path-to-mnemonic> \
  --purpose <governance|finality> \
  --output <path> \
  [--description <text>] \
  [--yes]

# Create witness from mnemonic - payment (index required)
midnight-cli witness create \
  --payload <file> \
  --mnemonic-file <path-to-mnemonic> \
  --purpose payment \
  --index <N> \
  --output <path> \
  [--description <text>] \
  [--yes]

# Create witness from mnemonic (explicit derivation path)
midnight-cli witness create \
  --payload <file> \
  --mnemonic-file <path-to-mnemonic> \
  --derivation-path <//midnight//purpose//index> \
  --purpose <governance|payment|finality> \
  --output <path> \
  [--description <text>] \
  [--yes]

# Create witness from CLI mnemonic (not recommended for production)
midnight-cli witness create \
  --payload <file> \
  --mnemonic "<24-word phrase>" \
  --purpose <type> \
  --index <N> \
  --output <path> \
  [--yes]

# Verify witness
midnight-cli witness verify \
  --witness <witness.json> \
  --payload <payload-file>
```

## Workflows

### Pre-Derive Workflow (Cold Storage)

**Use Case**: Generate keys offline, store files securely, use files later for signing

```bash
# Step 1: Generate mnemonic and governance key (offline, air-gapped machine)
midnight-cli key generate --purpose governance --output-dir /secure/keys/
# Save the mnemonic phrase in secure cold storage

# Step 2: Generate batch of payment keys for future use
midnight-cli key batch --mnemonic-file /secure/mnemonic.txt.asc \
  --purposes payment --indices 0,1,2,3,4,5,6,7,8,9 --output-dir /secure/keys/

# Step 3: Later, when signing is needed (air-gapped machine)
# Transfer payload to air-gapped machine
midnight-cli witness create \
  --payload proposal.txt \
  --key-file /secure/keys/governance.skey \
  --output /secure/witness.json \
  --description "Governance action #42"

# Step 4: Transfer witness.json back to online machine for submission
```

### On-Demand Workflow (Dynamic Derivation) - SIMPLIFIED

**Use Case**: Keep only mnemonic, derive keys dynamically when needed

```bash
# Step 1: Store mnemonic securely (plain text or GPG-encrypted)
echo "<mnemonic>" > midnight.mnemonic
# OR encrypt with GPG:
echo "<mnemonic>" | gpg --encrypt --armor -r key@example.com > midnight.mnemonic.gpg

# Step 2: When signing is needed, use simplified syntax
# No need to remember derivation paths or key types!
midnight-cli witness create \
  --payload ./proposal.txt \
  --mnemonic-file midnight.mnemonic \
  --purpose governance \
  --output witness.json \
  --description "Governance action #42" \
  --yes

# The tool automatically:
# - Constructs derivation path: //midnight//governance (no index - one per wallet)
# - Selects key type: sr25519 (for governance)
# - Derives the key on-demand
# - Signs the payload
# - Never saves the key to disk
```

**For different key types**:
```bash
# Payment transaction (sr25519)
midnight-cli witness create \
  --payload ./tx.bin \
  --mnemonic-file midnight.mnemonic \
  --purpose payment \
  --index 3 \
  --output witness-payment.json \
  --yes

# Finality consensus (ed25519)
midnight-cli witness create \
  --payload ./block.bin \
  --mnemonic-file midnight.mnemonic \
  --purpose finality \
  --output witness-finality.json \
  --yes
```

## Security Considerations

1. **Mnemonic Storage**:
   - Store mnemonics offline in secure cold storage
   - Use GPG encryption for any digital mnemonic files
   - Never commit mnemonics to version control

2. **Key File Security**:
   - `.skey` files contain secret keys - treat as highly sensitive
   - Store in encrypted volumes or hardware security modules
   - `.vkey` files are public and safe to share

3. **Air-Gap Procedures**:
   - Generate keys on air-gapped machines
   - Transfer only payload hashes to signing machine
   - Transfer only witnesses back to online systems

4. **Memory Safety**:
   - Tool uses `secrecy::SecretString` to prevent accidental logging
   - Secrets are zeroized on drop

5. **Derivation Path Validation**:
   - Tool validates derivation paths match Midnight standards
   - Ed25519 only supports hard derivation (no soft paths)

## Mnemonic File Format

Mnemonic files are simple text files containing the 24-word BIP39 phrase. The tool supports multiple formats:

### Plain Text Mnemonic

**Format**: `.mnemonic`, `.txt`, or any extension

**Content**:
```
legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title
```

The tool automatically:
- Trims whitespace
- Normalizes word separators
- Validates the mnemonic against BIP39 wordlist

### GPG-Encrypted Mnemonic

**Format**: `.mnemonic.gpg`, `.txt.asc`, or any GPG-encrypted file

**Creation**:
```bash
# Encrypt with passphrase
echo "<mnemonic>" | gpg --symmetric --armor > midnight.mnemonic.gpg

# Encrypt with public key
echo "<mnemonic>" | gpg --encrypt --armor -r your-key@example.com > midnight.mnemonic.gpg
```

The tool automatically detects GPG encryption by:
- File extension (`.gpg`, `.asc`)
- Magic bytes in file header

When using GPG-encrypted files, the tool will:
- Automatically invoke `gpg --decrypt`
- Prompt for passphrase if needed
- Process the decrypted mnemonic

## File Format Specifications

### Cardano-Style Key Files

**Signing Key (.skey)**:
```json
{
  "type": "GovernanceSigningKeyMidnight_sr25519",
  "description": "Midnight governance key",
  "cborHex": "5840..."  // CBOR-encoded secret key bytes in hex
}
```

**Verification Key (.vkey)**:
```json
{
  "type": "GovernanceVerificationKeyMidnight_sr25519",
  "description": "Midnight governance key (public)",
  "cborHex": "5820..."  // CBOR-encoded public key bytes in hex
}
```

### Witness Format

```json
{
  "version": "1.0",
  "payload": {
    "hash": "0x...",           // Blake2b-256 hash
    "hashAlgorithm": "blake2b-256",
    "size": 123                 // Original payload size in bytes
  },
  "signature": {
    "type": "sr25519",         // or "ed25519"
    "value": "0x...",          // Signature bytes in hex
    "signer": {
      "publicKey": "0x...",
      "ss58Address": "5...",
      "derivationPath": "//midnight//governance"  // null for file-based keys
    }
  },
  "metadata": {
    "timestamp": "2026-02-03T03:55:00.471714402+00:00",
    "purpose": "governance",   // or "payment", "finality"
    "description": "Runtime upgrade proposal #42"  // optional
  }
}
```

## Troubleshooting

### Issue: "Invalid SURI format"
**Cause**: Derivation path doesn't match expected format
**Solution**: Use standard paths: `//midnight//governance`, `//midnight//payment//{index}`, or `//midnight//finality`

### Issue: "Unsupported derivation for key type ed25519"
**Cause**: Trying to use soft derivation (`/`) with ed25519 keys
**Solution**: Ed25519 only supports hard derivation (`//`). Use finality keys only with hard paths.

### Issue: GPG decryption fails
**Cause**: GPG key not available or wrong passphrase
**Solution**: Ensure GPG is installed and you have the correct decryption key in your keyring

### Issue: "CBOR decoding error"
**Cause**: Corrupted or invalid key file
**Solution**: Regenerate key file from mnemonic

### Issue: Witness verification fails on valid payload
**Cause**: Payload file has been modified (line endings, encoding)
**Solution**: Ensure payload file is byte-identical to original. Use `sha256sum` to verify.

## Unit Test Coverage

The tool includes 60+ unit tests covering:

- SURI parsing (hard, soft, password derivations)
- Sr25519 key generation and derivation
- Ed25519 key generation
- Cardano format serialization/deserialization
- Witness creation and verification
- Key material conversion
- Mnemonic generation
- GPG detection

Run tests:
```bash
cargo test
```

Run tests with output:
```bash
cargo test -- --nocapture
```

## Integration with Midnight Network

This tool produces compatible key files and witnesses for:
- Midnight Network governance proposals
- Payment transaction signing
- Finality consensus participation

The witness format can be submitted to Midnight Network nodes via their RPC interface.

## Version History

- **v1.0.0**: Complete refactoring
  - Multi-key type support (governance, payment, finality)
  - Substrate SURI derivation paths
  - Cardano-style JSON format
  - On-demand and pre-derive workflows
  - Clean architecture implementation
  - Comprehensive test coverage

## Support and Documentation

- Architecture details: `CLAUDE.md`
- Code documentation: `cargo doc --open`
- Issue reporting: [repository issues]

---

**Test Plan Version**: 1.0
**Last Updated**: 2026-02-02
**Tested With**: midnight-cli v1.0.0, Rust 1.75
