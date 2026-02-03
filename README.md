# Midnight CLI - Governance Tooling

Secure, offline (air-gapped) tooling for participating in Midnight Network's Federated Authority Governance System.

## Overview

This CLI tool enables air-gapped participation in Midnight governance by providing cryptographic operations for sr25519 keypairs (Substrate/Midnight's signing scheme). It's designed to work alongside existing Cardano air-gap infrastructure.

## Features

- ✅ **Key Generation**: Create new sr25519 keypairs with BIP39 mnemonics
- ✅ **Key Inspection**: Examine existing keys and verify addresses
- ✅ **Offline Signing**: Create governance witnesses (signatures) without network access
- ✅ **Compatible**: Matches `subkey` output format for easy integration

## Installation

```bash
cargo build --release
```

The binary will be available at `target/release/midnight-cli`.

## Usage

### 1. Generate a New Keypair

Generate a random keypair:

```bash
./midnight-cli gov key-gen --output-type json
```

Or use a specific seed phrase:

```bash
./midnight-cli gov key-gen \
  --seed "bottom drive obey lake curtain smoke basket hold race lonely fit walk" \
  --output-type json \
  --output my-key.json
```

**Output:**
```json
{
  "accountId": "0x46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a",
  "networkId": "substrate",
  "publicKey": "0x46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a",
  "secretPhrase": "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
  "secretSeed": "***",
  "ss58Address": "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV",
  "ss58PublicKey": "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV"
}
```

### 2. Inspect an Existing Key

```bash
./midnight-cli gov inspect \
  "bottom drive obey lake curtain smoke basket hold race lonely fit walk" \
  --output-type json
```

Add `--show-secret` to reveal the secret seed (use carefully!):

```bash
./midnight-cli gov inspect \
  "your seed phrase here" \
  --output-type json \
  --show-secret
```

### 3. Create a Governance Witness (Sign a Proposal)

This is the core air-gap operation. On your **offline machine**:

```bash
./midnight-cli gov witness \
  --payload proposal-payload.bin \
  --secret "your seed phrase here" \
  --output witness.json
```

The tool will:
1. Load the payload from the file
2. Display the Blake2-256 hash for verification
3. Prompt for confirmation (unless `--yes` is used)
4. Create and save the signature

**Example witness output:**
```json
{
  "payload_hash": "0x1234567890abcdef...",
  "signature": "0xabcdef1234567890...",
  "signer": "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV",
  "timestamp": "2024-01-25T12:34:56Z"
}
```

#### Workflow for Air-Gap Signing

**On online machine:**
1. Fetch the governance proposal from Midnight network
2. Prepare the call payload (e.g., using polkadot-js)
3. Save the encoded call to `proposal-payload.bin`
4. Transfer file to air-gap machine via USB/QR

**On air-gap machine:**
5. Run `midnight-cli gov witness` to create signature
6. Verify the payload hash matches the published proposal
7. Transfer `witness.json` back to online machine

**On online machine:**
8. Submit the signature to complete the governance action

## Security Features

- 🔒 **No Network Access Required**: All signing operations work offline
- 🔒 **Interactive Confirmation**: User must explicitly approve each signature
- 🔒 **Payload Verification**: Displays hash for cross-checking against published proposals
- 🔒 **Secret Protection**: Seeds are never logged or written to disk unless explicitly requested

## Governance Action Examples

### Runtime Upgrade

```javascript
// Prepare the action call
const actionCall = api.tx.federatedAuthority.motionApprove(
  api.tx.system.authorizeUpgrade(wasmHash).method
);

// Encode for offline signing
const encodedCall = actionCall.method.toHex();
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
  termsHash,   // 0x... SHA-256 hash (H256)
  termsUrl     // string (UTF-8)
);
```

## Testing

Run the test suite:

```bash
cargo test
```

Verify compatibility with known test vectors:

```bash
cargo test test_known_seed_derivation -- --nocapture
```

This will validate that the tool produces identical output to `subkey` for the test seed phrase.

## Integration with Cardano Air-Gap Infrastructure

This tool is designed to work alongside existing `cardano-airgap` tooling:

1. **Dual-Key Model**: Cardano keys prove governance membership; Midnight sr25519 keys authorize actions
2. **Same Air-Gap Device**: Can run on the same secure hardware as Cardano signing tools
3. **Similar Workflow**: Follows the same offline signing pattern (prepare → sign → broadcast)

## Architecture

```
┌─────────────────────────────────────────────┐
│         Governance Membership               │
│            (Cardano Chain)                  │
│  ┌─────────────────────────────────────┐   │
│  │  Root Identity (Ed25519)            │   │
│  │  - Controls membership              │   │
│  │  - Rotates Midnight keys            │   │
│  └─────────────────────────────────────┘   │
└─────────────────┬───────────────────────────┘
                  │
                  │ Synchronized
                  ↓
┌─────────────────────────────────────────────┐
│      Governance Actions                     │
│       (Midnight Sidechain)                  │
│  ┌─────────────────────────────────────┐   │
│  │  Operational Keys (Sr25519)         │   │
│  │  - Sign proposals                   │   │
│  │  - Sign votes                       │   │
│  │  - midnight-cli creates witnesses   │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

## Dependencies

- `schnorrkel`: Sr25519 signature scheme
- `sp-core`/`sp-runtime`: Substrate primitives
- `bip39`: Mnemonic generation
- `clap`: CLI interface

## License

[Your License Here]

## Support

For issues or questions, please file an issue on the project repository or contact the development team.
