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

### Git Commit Guidelines

IMPORTANT: When using Claude Code to create commits in this repository:
- **NEVER include AI attribution** in commit messages
- Do NOT add lines like "🤖 Generated with Claude Code" or "Co-Authored-By: Claude"
- Commit messages should be clean, professional, and focused on the technical changes
- Follow conventional commit format when applicable (feat:, fix:, docs:, etc.)

### Running

```bash
# Generate governance key from new mnemonic (no index - one per wallet)
cargo run -- key generate --purpose governance --output ./keys

# Generate governance key from existing mnemonic
cargo run -- key generate --purpose governance --mnemonic "seed phrase..." --output ./keys

# Generate payment key from mnemonic file (index required - multiple per wallet)
cargo run -- key generate --purpose payment --index 0 --mnemonic-file mnemonic.txt --output ./keys

# Batch generate multiple payment keys
cargo run -- key batch --mnemonic-file mnemonic.txt --purposes payment --indices 0,1,2,3,4 --output ./keys

# Derive a key on-demand (no file output) - default path //midnight//governance
cargo run -- key derive --mnemonic-file mnemonic.txt --derivation "//midnight//governance" --purpose governance --key-type sr25519 --format json

# Inspect a key file
cargo run -- key inspect governance-0.skey

# Create a witness from key file
cargo run -- witness create --payload proposal.bin --key-file governance-0.skey --output witness.json --yes

# Create a witness from mnemonic file (SIMPLIFIED - recommended)
# Uses default path: //midnight//governance (matches Polkadot Vault)
cargo run -- witness create \
  --payload proposal.bin \
  --mnemonic-file mnemonic.txt \
  --purpose governance \
  --output witness.json \
  --yes

# Create a witness with numbered key (optional)
cargo run -- witness create \
  --payload proposal.bin \
  --mnemonic-file mnemonic.txt \
  --purpose governance \
  --index 0 \
  --output witness.json \
  --yes

# Create a witness with explicit derivation path (advanced - for payment keys)
cargo run -- witness create \
  --payload transaction.bin \
  --mnemonic-file mnemonic.txt \
  --derivation-path "//midnight//payment//42" \
  --purpose payment \
  --output witness.json \
  --yes

# Verify a witness
cargo run -- witness verify --witness witness.json --payload proposal.bin

# Query chain state
# Query recent extrinsics
cargo run -- query extrinsics --blocks 10 --endpoint ws://localhost:9944

# Query pending governance proposals
cargo run -- query proposals --verbose --endpoint ws://localhost:9944

# Query events from recent blocks
cargo run -- query events --blocks 5 --endpoint ws://localhost:9944

# Query events from specific block
cargo run -- query events --block 1234 --endpoint ws://localhost:9944

# Query events from block range
cargo run -- query events --from 1000 --to 1010 --endpoint ws://localhost:9944

# Filter events by section and method
cargo run -- query events --section Council --method Proposed

# Show all events (not just governance)
cargo run -- query events --all

# Query governance members (council and TA)
cargo run -- query members --endpoint ws://localhost:9944

# Query members with verbose output (include hex account IDs)
cargo run -- query members --verbose

# Create governance transactions (online machine)
# Propose adding a council member
cargo run -- tx propose membership council add-member 5GrwvaEF... \
  --endpoint ws://localhost:9944 \
  --output-dir ./governance-payloads

# Propose removing a TA member
cargo run -- tx propose membership ta remove-member 5DfhGyQd... \
  --endpoint ws://localhost:9944

# Propose a system remark (council)
cargo run -- tx propose system council remark "Governance test message" \
  --signer 5CD3C2Aa6QjxTLSF3R1av6Dwy8GKSB8kHfZkWbcJ7gb3t6Cx

# Propose runtime upgrade authorization (TA)
cargo run -- tx propose runtime ta authorize-upgrade 0xabcd1234... \
  --signer 5GrwvaEF...

# Vote on a proposal (council member approves)
cargo run -- tx vote council \
  --proposal-index 0 \
  --approve \
  --signer 5DfhGyQd...

# Vote on a proposal (TA member rejects - note: no --approve flag means reject)
cargo run -- tx vote ta \
  --proposal-index 1 \
  --signer 5GrwvaEF...

# With optional parameters
cargo run -- tx vote council \
  --proposal-index 0 \
  --proposal-hash 0x7d33c202... \
  --approve \
  --signer 5CD3C2Aa... \
  --endpoint ws://localhost:9944 \
  --output-dir ./governance-payloads

# Close a proposal after voting (council)
cargo run -- tx close council \
  --proposal-index 0 \
  --proposal-hash 0xabcd... \
  --proposal-length 42 \
  --endpoint ws://localhost:9944

# Close a proposal (TA) - hash/length from state file
cargo run -- tx close ta \
  --proposal-index 1 \
  --state-file ./governance-payloads/state.json

# Submit a signed extrinsic to the network
cargo run -- tx submit \
  --extrinsic ./governance-payloads/council-propose-membership.extrinsic \
  --endpoint ws://localhost:9944

# Generate genesis and build chain spec (requires midnight-node in PATH)
cargo run -- genesis init \
  --validator validator1.json \
  --validator validator2.json \
  --ta ta1.json \
  --ta ta2.json \
  --council council1.json \
  --council council2.json \
  --night-policy-id <hex> \
  --chain-id sanchonight \
  --chainspec-dir ./chainspec \
  --midnight-node-res ~/work/iohk/midnight-node/res

# This will:
# 1. Check midnight-node is in PATH
# 2. Create genesis.json
# 3. Generate all chainspec config files (8 files total):
#    - permissioned-candidates-config.json
#    - federated-authority-config.json (with SS58→hex conversion)
#    - cnight-config.json
#    - ics-config.json
#    - reserve-config.json
#    - pc-chain-config.json
#    - system-parameters-config.json
#    - registered-candidates-addresses.json
# 4. Execute: midnight-node build-spec --disable-default-bootnode
# 5. Output: chainspec/chain-spec.json (ready to use)
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
- **commands/query.rs**: Chain state query commands (extrinsics, proposals, events)
- **commands/tx.rs**: Transaction creation and submission (propose, close, submit)
- **commands/tx_builder.rs**: Metadata-driven transaction encoding with subxt
- **commands/genesis.rs**: Genesis and chainspec generation (init, cnight)
- **output.rs**: Output formatting (JSON, text)

### Key Flow Examples

1. **Generate Key**: BIP39 mnemonic → SURI parser → Sr25519/Ed25519 derivation → Cardano format → .skey/.vkey files
2. **Create Witness**: Payload file → Blake2-256 hash → Load key → Sign → JSON witness output
3. **Query Chain State**: WebSocket RPC → Subxt client → Decode storage/events → Formatted output
4. **Create Transaction**: Proposal spec → Subxt metadata → SCALE encoding → Signing payload → Air-gap transfer → Sign → Submit to network
5. **Build Chain Spec**: Validator/governance keys → Genesis JSON → 8 chainspec configs → midnight-node build-spec → chain-spec.json

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
- **subxt 0.37**: Substrate client library for metadata-driven transaction encoding
- **jsonrpsee 0.24**: WebSocket RPC client for chain state queries
- **parity-scale-codec 3.6**: SCALE encoding/decoding for Substrate types

### Output Format Compatibility

The tool matches `subkey` output format for easy integration with existing Substrate tooling. The test vector in `utils.rs:test_known_seed_derivation` validates that the seed phrase "bottom drive obey lake curtain smoke basket hold race lonely fit walk" produces:
- Public key: `0x46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a`
- SS58 address: `5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV`

### Governance Workflow

The intended air-gap workflow for governance transactions:

#### Modern Workflow (using `tx` commands - recommended):
1. **Online machine**: Create governance proposal using `tx propose` command
   - Connects to Midnight node to fetch metadata and current state
   - Encodes proposal call using subxt with runtime metadata
   - Calculates proper threshold (2/3 majority by default)
   - Generates signing payload with proper era, nonce, and chain context
   - Saves `.payload` and `.json` metadata files
2. **Transfer**: Move payload and metadata files to air-gap machine via USB/QR
3. **Air-gap machine**: Sign the payload using `witness create-extrinsic`
   - Verifies payload hash matches metadata
   - Signs with governance key from mnemonic
   - Creates signed extrinsic file
4. **Transfer**: Move signed `.extrinsic` file back to online machine
5. **Online machine**: Submit using `tx submit --extrinsic <file>`
6. **Query**: Use `query proposals` to see proposal status (pending votes)
7. **Vote**: Each governance member votes using `tx vote` command
   - Repeat steps 2-5 for each member who needs to vote
   - Monitor votes with `query proposals` and `query events`
8. **Close**: When threshold reached, use `tx close` to execute the proposal
   - Repeat steps 2-5 to sign and submit the close transaction

#### Legacy Workflow (manual payload encoding):
1. **Online machine**: Manually fetch and encode governance proposal
2. **Transfer**: Move payload file to air-gap machine via USB/QR
3. **Air-gap machine**: Run `witness create` to create signature after verifying payload hash
4. **Transfer**: Move witness JSON back to online machine
5. **Online machine**: Manually construct and submit signed transaction

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
- Standard Midnight paths:
  - `//midnight//governance` (default, matches Polkadot Vault)
  - `//midnight//governance//INDEX` (numbered keys)
  - `//midnight//payment//INDEX`
  - `//midnight//finality//INDEX`
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
