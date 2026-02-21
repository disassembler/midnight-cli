# Midnight CLI

Comprehensive key management and witness creation tooling for Midnight Network governance participants and validators.

## Overview

The Midnight CLI provides secure, offline (air-gapped) cryptographic operations for the Midnight Network. It supports multiple key types (governance, payment, finality) with hierarchical derivation, Cardano-compatible key file formats, and simplified witness creation for governance proposals and block production.

**Key Features:**
- 🔑 **Multi-Key Type Support**: Governance (sr25519), Payment (sr25519), Finality (ed25519)
- 🌳 **Hierarchical Derivation**: Substrate SURI paths (`//midnight//purpose//index`)
- 🔐 **Air-Gap Ready**: All operations work completely offline
- 📁 **Cardano Compatible**: JSON key files with CBOR encoding (`.skey`/`.vkey`)
- 🔒 **GPG Support**: Encrypted mnemonic files
- ⚡ **Simplified Workflow**: Auto-derivation from purpose and index
- 📝 **Comprehensive Witnesses**: Full metadata and signature verification

## Installation

### Using Cargo

```bash
cargo build --release
# Binary at: ./target/release/midnight-cli
```

### Using Nix

```bash
nix build .#midnight-cli
# Binary at: ./result/bin/midnight-cli
```

## Quick Start

### 1. Generate Keys from a Mnemonic File

```bash
# Create or use existing mnemonic file
echo "your 24-word phrase here..." > midnight.mnemonic

# Generate governance key
midnight-cli key generate \
  --mnemonic-file midnight.mnemonic \
  --purpose governance \
  --output ./keys/

# Files created:
# - governance.skey (private key - keep secure!)
# - governance.vkey (public key - safe to share)
```

### 2. Sign a Governance Proposal (Simplified)

```bash
# Auto-derives key from purpose (no index for governance)
midnight-cli witness create \
  --payload proposal.txt \
  --mnemonic-file midnight.mnemonic \
  --purpose governance \
  --output witness.json \
  --yes
```

### 3. Verify a Witness

```bash
midnight-cli witness verify \
  --witness witness.json \
  --payload proposal.txt
```

## Key Types and Purposes

| Purpose | Key Type | Derivation Path | Index | Use Case |
|---------|----------|-----------------|-------|----------|
| `governance` | sr25519 | `//midnight//governance` | None (one per wallet) | Governance proposals, runtime upgrades |
| `payment` | sr25519 | `//midnight//payment//{index}` | Required (multiple per wallet) | Payment transactions |
| `finality` | ed25519 | `//midnight//finality` | None (one per wallet) | Block production, consensus finality |

**Security Policy:**
- Each wallet holds exactly **one** governance key and **one** finality key (no index allowed)
- Each wallet can hold **multiple** payment keys (index required, enables multiple addresses)

## Commands

### Key Management

```bash
# Generate governance or finality key (no index - one per wallet)
midnight-cli key generate \
  --purpose <governance|finality> \
  [--mnemonic-file <path>] \
  --output <dir>

# Generate payment key (index required - multiple per wallet)
midnight-cli key generate \
  --purpose payment \
  --index <N> \
  [--mnemonic-file <path>] \
  --output <dir>

# Batch generate multiple payment keys
midnight-cli key batch \
  --mnemonic-file <path> \
  --purposes payment \
  --indices 0,1,2,3,4 \
  --output <dir>

# Derive key on-demand (no file output)
midnight-cli key derive \
  --mnemonic-file <path> \
  --derivation <path> \
  --key-type <sr25519|ed25519> \
  --purpose <type> \
  --format <json|text>

# Inspect key file
midnight-cli key inspect <key-file>
```

### Witness Operations

```bash
# Create witness from mnemonic - governance/finality (no index)
midnight-cli witness create \
  --payload <file> \
  --mnemonic-file <path> \
  --purpose <governance|finality> \
  --output <path> \
  [--yes]

# Create witness from mnemonic - payment (index required)
midnight-cli witness create \
  --payload <file> \
  --mnemonic-file <path> \
  --purpose payment \
  --index <N> \
  --output <path> \
  [--yes]

# Create witness from key file
midnight-cli witness create \
  --payload <file> \
  --key-file <path-to-skey> \
  --output <path> \
  [--yes]

# Verify witness
midnight-cli witness verify \
  --witness <witness.json> \
  --payload <payload-file>
```

### Network Setup (SanchoNight / Federated Networks)

```bash
# Generate validator keys for node operator
midnight-cli validator generate \
  [--mnemonic-file <path>] \
  --output validator-keys.json \
  [--write-key-files] \
  [--key-files-dir <dir>]

# Outputs: node key (ed25519), aura key (sr25519), grandpa key (ed25519)

# Generate governance keys for TA/Council member
midnight-cli governance generate \
  [--mnemonic-file <path>] \
  --output governance-key.json \
  [--write-key-files] \
  [--key-files-dir <dir>]

# Create genesis configuration from individual key files
midnight-cli genesis init \
  --validator <validator1.json> \
  --validator <validator2.json> \
  --ta <ta1.json> \
  --ta <ta2.json> \
  --council <council1.json> \
  --council <council2.json> \
  [--night-policy-id <hex>] \
  [--chain-id <name>] \
  --output genesis.json
```

## Workflows

### Pre-Derive Workflow (Cold Storage)

**Use Case**: Generate keys offline, store files securely, use files later for signing

```bash
# Step 1: Generate governance key (offline, air-gapped machine)
midnight-cli key generate \
  --purpose governance \
  --output /secure/keys/
# Save the displayed mnemonic phrase in secure cold storage!

# Step 2: Generate batch of payment keys for future use
midnight-cli key batch \
  --mnemonic-file /secure/mnemonic.txt \
  --purposes payment \
  --indices 0,1,2,3,4,5,6,7,8,9 \
  --output /secure/keys/

# Step 3: Later, when signing is needed (air-gapped machine)
midnight-cli witness create \
  --payload proposal.txt \
  --key-file /secure/keys/governance.skey \
  --output witness.json \
  --yes

# Step 4: Transfer witness.json to online machine for submission
```

### Federated Network Setup (SanchoNight)

**Use Case**: Bootstrap a federated Midnight network with multiple operators

```bash
# Operator 1: Generate validator keys independently
midnight-cli validator generate --output operator1-validator.json

# Operator 2: Generate validator keys independently
midnight-cli validator generate --output operator2-validator.json

# TA Member 1: Generate governance key
midnight-cli governance generate --output ta1-governance.json

# TA Member 2: Generate governance key
midnight-cli governance generate --output ta2-governance.json

# Coordinator: Create genesis from individual key files
# (After receiving JSON files from all operators, TA, and Council members)
midnight-cli genesis init \
  --validator operator1-validator.json \
  --validator operator2-validator.json \
  --ta ta1-governance.json \
  --ta ta2-governance.json \
  --council council1-governance.json \
  --council council2-governance.json \
  --council council3-governance.json \
  --night-policy-id <policy-id-from-cardano> \
  --chain-id sanchonight \
  --output genesis.json

# Use genesis.json to configure midnight-node for network launch
```

### On-Demand Workflow (Dynamic Derivation)

**Use Case**: Keep only mnemonic, derive keys dynamically when needed

```bash
# Step 1: Store encrypted mnemonic securely
echo "<mnemonic>" | gpg --encrypt --armor -r key@example.com > midnight.mnemonic.gpg

# Step 2: When signing is needed, use simplified syntax
midnight-cli witness create \
  --payload proposal.txt \
  --mnemonic-file midnight.mnemonic.gpg \
  --purpose governance \
  --output witness.json \
  --yes

# Tool automatically:
# - Decrypts GPG file (prompts for passphrase)
# - Constructs derivation path: //midnight//governance (no index - one per wallet)
# - Selects key type: sr25519
# - Derives key on-demand
# - Signs payload
# - Never saves key to disk
```

## Air-Gap Security Workflow

**On online machine:**
1. Fetch governance proposal from Midnight network
2. Create payload file (`proposal.txt`)
3. Transfer via USB/QR code to air-gapped machine

**On air-gapped machine:**
4. Run `midnight-cli witness create` with mnemonic file
5. Review displayed payload hash - verify it matches published proposal
6. Confirm signature creation
7. Transfer `witness.json` back to online machine

**On online machine:**
8. Submit witness to Midnight Network via RPC/API

## File Formats

### Mnemonic Files

**Plain text** (`.mnemonic`, `.txt`):
```
legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title
```

**GPG encrypted** (`.mnemonic.gpg`, `.asc`):
- Auto-detected by extension or magic bytes
- Tool invokes `gpg --decrypt` automatically

### Key Files (Cardano Format)

**Signing Key** (`governance.skey`):
```json
{
  "type": "GovernanceSigningKeyMidnight_sr25519",
  "description": "Midnight governance key",
  "cborHex": "5840..."
}
```

**Verification Key** (`governance.vkey`):
```json
{
  "type": "GovernanceVerificationKeyMidnight_sr25519",
  "description": "Midnight governance key (public)",
  "cborHex": "5820..."
}
```

### Witness Format

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

## Governance Action Examples

### Runtime Upgrade

```javascript
// Prepare the action call
const actionCall = api.tx.federatedAuthority.motionApprove(
  api.tx.system.authorizeUpgrade(wasmHash).method
);

// Encode to file
fs.writeFileSync('proposal.txt', actionCall.method.toHex());
```

### D-Parameter Update

```javascript
const dParamCall = api.tx.systemParameters.updateDParameter(
  numPermissionedCandidates,
  numRegisteredCandidates
);
```

### Terms & Conditions Update

```javascript
const tncCall = api.tx.systemParameters.updateTermsAndConditions(
  termsHash,      // 0x... SHA-256 hash
  termsUrl        // string (UTF-8)
);
```

## Integration with Cardano Air-Gap Infrastructure

This tool is designed to work alongside existing Cardano air-gap tooling:

**Dual-Key Model:**
- **Cardano keys**: Prove validator membership on Cardano mainchain
- **Midnight keys**: Authorize operations on Midnight Network

**Same Hardware:**
- Runs on the same air-gapped devices as Cardano signing tools
- Uses similar workflows (offline → sign → broadcast)
- Compatible with Cardano's security model

**Validator Architecture:**
```
┌─────────────────────────────────────────────┐
│     Cardano Mainnet / Preview Testnet      │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │  SPO Registration (Ed25519)          │  │
│  │  - Controls MBP membership           │  │
│  │  - Publishes finality public key     │  │
│  └──────────────────────────────────────┘  │
└─────────────────┬───────────────────────────┘
                  │
                  │ Synchronized
                  ↓
┌─────────────────────────────────────────────┐
│         Midnight Network                    │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │  Finality Keys (Ed25519)             │  │
│  │  - Sign blocks                       │  │
│  │  - GRANDPA finality consensus        │  │
│  │  - Committee participation           │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │  Governance Keys (Sr25519)           │  │
│  │  - Vote on upgrades                  │  │
│  │  - System parameter changes          │  │
│  └──────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

## Security Features

- 🔒 **Offline Operations**: All signing works without network access
- 🔒 **Interactive Confirmation**: Payload hash displayed for manual verification
- 🔒 **Secret Protection**: Secrets wrapped in `SecretString` (no logging)
- 🔒 **Memory Zeroization**: Key material zeroed on drop
- 🔒 **GPG Encryption**: Support for encrypted mnemonic files
- 🔒 **Restrictive Permissions**: Key files created with 0o600 (Unix)
- 🔒 **Payload Verification**: Blake2b-256 hash verification before signing

## Testing

```bash
# Run all tests (60+ unit tests)
cargo test

# Run with output
cargo test -- --nocapture

# Test specific module
cargo test --lib key_generation
```

## Documentation

- **[QUICK_START.md](QUICK_START.md)**: Fast onboarding with practical examples
- **[TEST_PLAN.md](TEST_PLAN.md)**: Comprehensive test scenarios for validation
- **[CLAUDE.md](CLAUDE.md)**: Architecture details and developer reference

## Dependencies

- **sp-core v34**: Substrate primitives (sr25519/ed25519, SS58 encoding)
- **schnorrkel 0.11**: Sr25519 signature scheme
- **bip39 v2.0**: BIP39 mnemonic generation (24-word phrases)
- **clap v4.5**: CLI argument parsing
- **serde_cbor 0.11**: CBOR encoding for Cardano-style keys
- **secrecy 0.8**: Secure secret handling
- **zeroize 1.7**: Memory zeroization

## Architecture

The codebase follows **clean architecture** with 5 layers:

1. **Domain Layer** (`src/domain/`): Core types (KeyPurpose, KeyTypeId, SURI, KeyMaterial)
2. **Crypto Layer** (`src/crypto/`): Sr25519/Ed25519 operations, SURI parser
3. **Storage Layer** (`src/storage/`): Cardano format, GPG support, file I/O
4. **Application Layer** (`src/application/`): Use cases (key generation, witness creation)
5. **CLI Layer** (`src/cli/`): Commands and argument parsing

## License

Copyright 2026 Midnight Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See [LICENSE](LICENSE) and [NOTICE](NOTICE) for more information.

## Support

For issues, questions, or contributions:
- GitHub Issues: [repository URL]
- Documentation: https://docs.midnight.network/
- Forum: https://forum.midnight.network/

---

**For Midnight Network Validators**: See [Become a Midnight Block Producer](https://docs.midnight.network/validate/run-a-validator) for validator setup and key management requirements.
