# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Midnight CLI is a comprehensive key management and governance tooling for the Midnight Network. It provides secure, offline cryptographic operations for multiple key types (Sr25519, Ed25519) with support for Substrate SURI derivation paths and Cardano-style key file formats. The tool enables air-gapped participation in Midnight Network governance while supporting both pre-derived key files and on-demand key derivation workflows.

## Common Commands

### Building
```bash
# Development build
cargo build

# Release build (optimized, stripped)
cargo build --release

# Nix build (using flakes)
nix build
```

### Testing
```bash
# Run all tests
cargo test

# Run specific test
cargo test test_known_seed_derivation

# Run tests with output
cargo test -- --nocapture

# Run tests for specific module
cargo test --lib key_gen
```

### Development
```bash
# Format code
cargo fmt

# Lint with clippy
cargo clippy

# Enter dev shell with all dependencies (Nix)
nix develop

# Check without building
cargo check
```

### Running

```bash
# Generate keys from a new mnemonic
cargo run -- key generate --purpose governance --index 0 --output ./keys

# Generate keys from existing mnemonic
cargo run -- key generate --purpose governance --index 0 --mnemonic "seed phrase..." --output ./keys

# Generate keys from mnemonic file (plain or GPG-encrypted)
cargo run -- key generate --purpose payment --index 0 --mnemonic-file mnemonic.txt --output ./keys

# Batch generate multiple keys
cargo run -- key batch --mnemonic-file mnemonic.txt --purpose governance --start 0 --count 5 --output ./keys

# Derive a key on-demand (no file output)
cargo run -- key derive --mnemonic-file mnemonic.txt --purpose governance --index 0 --format json

# Inspect a key file
cargo run -- key inspect governance-0.skey

# Create a witness from key file
cargo run -- witness create --payload proposal.bin --key-file governance-0.skey --output witness.json --yes

# Create a witness from mnemonic file (SIMPLIFIED - recommended)
cargo run -- witness create \
  --payload proposal.bin \
  --mnemonic-file mnemonic.txt \
  --purpose governance \
  --index 0 \
  --output witness.json \
  --yes

# Create a witness with explicit derivation path (advanced)
cargo run -- witness create \
  --payload proposal.bin \
  --mnemonic-file mnemonic.txt \
  --derivation-path "//midnight//governance//42" \
  --purpose governance \
  --output witness.json \
  --yes

# Verify a witness
cargo run -- witness verify --witness witness.json --payload proposal.bin
```

## Architecture

The codebase follows a **layered clean architecture** with clear separation of concerns:

### Layer 1: Domain (`src/domain/`)
Core business logic with no external dependencies:
- **key_type.rs**: `KeyTypeId` enum (Sr25519, Ed25519), `KeyPurpose` enum (Governance, Payment, Finality)
- **derivation.rs**: SURI types, `MidnightKeyPath` for standard derivation paths
- **key_material.rs**: `KeyMaterial` value object with metadata
- **error.rs**: Domain-specific error types

### Layer 2: Crypto (`src/crypto/`)
Cryptographic implementations:
- **sr25519.rs**: Sr25519 operations (key generation, signing, verification)
- **ed25519.rs**: Ed25519 operations (same as sr25519 but for Ed25519)
- **suri_parser.rs**: Substrate SURI format parser (`SEED[//hard][/soft][///password]`)
- **mnemonic.rs**: BIP39 mnemonic generation and validation

### Layer 3: Storage (`src/storage/`)
Persistence and I/O operations:
- **cardano_format.rs**: Cardano-style JSON text envelope with CBOR encoding
- **key_reader.rs**: Read keys from files, CLI args, or GPG-encrypted files
- **key_writer.rs**: Write .skey/.vkey file pairs
- **gpg.rs**: GPG encryption support for mnemonics

### Layer 4: Application (`src/application/`)
Use case orchestration:
- **key_generation.rs**: Generate and save keys to files
- **key_derivation.rs**: On-demand key derivation without file output
- **witness_creation.rs**: Sign payloads and create witness files

### Layer 5: CLI (`src/cli/`)
User interface:
- **commands/key.rs**: Key management commands (generate, derive, inspect, batch)
- **commands/witness.rs**: Witness commands (create, verify)
- **output.rs**: Output formatting (JSON, text)

### Key Flow Examples

1. **Generate Key**: BIP39 mnemonic → SURI parser → Sr25519/Ed25519 derivation → Cardano format → .skey/.vkey files
2. **Create Witness**: Payload file → Blake2-256 hash → Load key → Sign → JSON witness output

### Security Model

This tool is designed for air-gapped operations:
- All signing operations work offline without network access
- Interactive confirmation required before signing (unless `--yes` flag)
- Payload hash displayed for manual verification against published proposals
- Secrets never logged or written to disk unless explicitly requested
- Compatible with existing Cardano air-gap infrastructure (dual-key model)

### Key Dependencies

- **sp-core v34**: Substrate primitives for sr25519/ed25519 cryptography and SS58 encoding
- **schnorrkel 0.11**: Sr25519 signature scheme implementation
- **bip39 v2.0**: BIP39 mnemonic generation and validation (24-word phrases)
- **clap v4.5**: CLI argument parsing with derive macros
- **serde_cbor 0.11**: CBOR encoding for Cardano-style key files
- **secrecy 0.8**: Secure secret handling (prevents accidental logging)
- **zeroize 1.7**: Zero memory on drop for security

### Output Format Compatibility

The tool matches `subkey` output format for easy integration with existing Substrate tooling. The test vector in `utils.rs:test_known_seed_derivation` validates that the seed phrase "bottom drive obey lake curtain smoke basket hold race lonely fit walk" produces:
- Public key: `0x46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a`
- SS58 address: `5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV`

### Governance Workflow

The intended air-gap workflow:
1. **Online machine**: Fetch governance proposal from Midnight network, encode call payload
2. **Transfer**: Move payload file to air-gap machine via USB/QR
3. **Air-gap machine**: Run `witness` command to create signature after verifying payload hash
4. **Transfer**: Move witness JSON back to online machine
5. **Online machine**: Submit signature to complete governance action

### Nix Integration

The project uses Nix flakes for reproducible builds:
- `flake.nix`: Flake configuration with naersk for Rust builds
- `perSystem/packages.nix`: Package definition using naersk
- `perSystem/devShells.nix`: Development shell with Rust toolchain and dependencies
- `.envrc`: direnv integration for automatic shell activation

## Important Implementation Details

### Sr25519 Derivation

- Uses Substrate's mini-secret-key derivation via `sr25519::Pair::from_phrase()`
- No additional derivation path (None) for governance keys
- Must match `subkey` output for interoperability

### Signature Creation

The `sign_substrate_payload()` function uses raw message signing with `pair.sign()`. Substrate handles context internally for sr25519 signatures. The signature is 64 bytes and returned as hex-encoded with 0x prefix.

### Error Handling

Custom error types in `types.rs` use `thiserror` for ergonomic error handling. All errors propagate using `anyhow::Result` for CLI operations.

### Secret Handling

Multiple input methods supported:
- Direct BIP39 mnemonic phrase via CLI args
- Mnemonic from plain text file
- Mnemonic from GPG-encrypted file (auto-detected by .gpg extension)
- Pre-derived .skey files (Cardano format)

Secrets use `secrecy::SecretString` to prevent accidental logging and are never written to disk unless explicitly requested.

## New Features (Post-Refactoring)

### Multiple Key Types
- **Sr25519**: For governance and payment operations
- **Ed25519**: For finality operations
- Each key type has proper validation (e.g., Ed25519 doesn't support soft derivation)

### Substrate SURI Derivation
- Full support for `SEED[//hard][/soft][///password]` format
- Standard Midnight paths: `//midnight//governance//INDEX`, `//midnight//payment//INDEX`, `//midnight//finality//INDEX`
- Custom derivation paths supported

### Cardano-Style Key Files
- Separate .skey (signing) and .vkey (verification) files
- JSON text envelope format with CBOR-encoded key material
- Type descriptors: `GovernanceSigningKeyMidnight_sr25519`, `PaymentSigningKeyMidnight_sr25519`, etc.
- Restrictive file permissions on .skey files (Unix: 0o600)

### Dual Workflow Support
1. **Pre-derive workflow**: Generate keys from mnemonic → save as .skey/.vkey files → use files for signing
2. **On-demand workflow**: Keep mnemonic file → derive keys dynamically when needed → no key files stored

### GPG Integration
- Automatic detection of GPG-encrypted files (.gpg extension or magic bytes)
- Transparent decryption via `gpg --decrypt`
- Mnemonic never written to disk in plaintext

### Batch Operations
- Generate multiple keys at once from a single mnemonic
- Specify multiple purposes and indices
- All keys written to output directory with standardized naming
