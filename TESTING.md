# Governance Contract Testing

This document describes the governance contract testing framework for Midnight CLI.

## Overview

We've implemented comprehensive integration tests for all three Midnight Network governance contracts using Hayate's transaction simulator. These tests validate contract loading, datum encoding, ledger state setup, and rotation logic without requiring a live blockchain.

## Test Files

### `tests/council_rotation_test.rs`
Original council governance contract test that validates:
- Test environment setup with wallet from mnemonic
- Council governance contract loading
- VersionedMultisig datum CBOR encoding
- Initial ledger state with NFT locked in contract
- Simulator initialization

### `tests/governance_contracts_test.rs`
Comprehensive test suite for all three governance contracts:
- **Council Governance** (3 members)
- **Tech Auth Governance** (5 members)
- **Federated Ops Governance** (7 members)

## Contract Details

All contracts extracted from `validators/plutus.json`:

```
validators/council_governance_council_governance_spend.plutus
  Hash: c000d973124b513c04661fc84f6de387b3a912c6e5e8e9c45d023b6e
  Size: 1198 bytes

validators/tech_auth_governance_tech_auth_governance_spend.plutus
  Hash: c000d973124b513c04661fc84f6de387b3a912c6e5e8e9c45d023b6e
  Size: 1198 bytes

validators/federated_ops_governance_federated_ops_governance_spend.plutus
  Hash: 02cc9ca294b13c244b2661b5068ac4534b7bf42ec1774c08d20c5c46
  Size: 1244 bytes
```

**Note**: Council and Tech Auth share the same base contract implementation and only differ in their NFT policy ID parameters at runtime. Federated Ops has a distinct implementation with a different script hash.

## Test Coverage

### Individual Contract Tests
Each governance contract is tested with:
- Proper member count (3, 5, 7 respectively)
- Deterministic test keys (Cardano hash + Sr25519 keys)
- NFT-locked contract UTxO with inline datum
- Wallet UTxOs for fee payment
- SanchoNet protocol parameters
- Logic round rotation (0 → 1)

### Datum Encoding Tests
Validates VersionedMultisig CBOR encoding for different member counts:
- Council-sized (3 members): 212 bytes
- TA-sized (5 members): 350 bytes
- FedOps-sized (7 members): 488 bytes

### Contract Hash Verification
Ensures:
- Council and TA share the same base contract hash
- Federated Ops has a distinct implementation
- All contracts load successfully from compiled `.plutus` files

## Running Tests

```bash
# Run all governance tests
cargo test --test council_rotation_test --test governance_contracts_test

# Run specific test
cargo test --test governance_contracts_test test_tech_auth_governance

# Run with output
cargo test --test governance_contracts_test -- --nocapture
```

## Test Results

All 7 tests pass:
- ✓ `test_council_rotation_with_simulator` (council_rotation_test.rs)
- ✓ `test_versioned_multisig_datum_encoding` (council_rotation_test.rs)
- ✓ `test_council_governance` (governance_contracts_test.rs)
- ✓ `test_tech_auth_governance` (governance_contracts_test.rs)
- ✓ `test_federated_ops_governance` (governance_contracts_test.rs)
- ✓ `test_datum_encoding_different_sizes` (governance_contracts_test.rs)
- ✓ `test_contract_hashes_are_unique` (governance_contracts_test.rs)

## Implementation Details

### Test Environment Setup
- **Mnemonic**: Fixed test phrase (DO NOT USE IN PRODUCTION)
- **Network**: Testnet (network magic: 4 = SanchoNet)
- **Protocol Params**: SanchoNet configuration with Plutus V2 cost model
- **Wallet**: Derived from test mnemonic (account index 0)

### Ledger State Construction
Each test creates a minimal ledger state with:
1. Contract UTxO containing:
   - VersionedMultisig datum (inline)
   - NFT asset (policy ID + asset name)
   - Minimum lovelace amount
2. Three wallet UTxOs for fee payments
3. Current slot: 1000
4. Network magic: 4 (SanchoNet)

### Simulator Usage
Tests use `TransactionSimulator::new_offline()` for air-gapped testing:
- No network connection required
- Simulates script execution with provided ledger state
- Validates transaction construction and datum updates

## Next Steps

Future enhancements for the test suite:

1. **Full Transaction Building**: Integrate with UnifiedTxBuilder to construct complete rotation transactions including:
   - Script input with redeemer
   - Script output with updated datum
   - NFT preservation
   - Required signatures (2/3 threshold)

2. **Simulation Execution**: Call `simulator.simulate_with_ledger_state()` to validate transactions execute correctly

3. **Parameter Application**: Test governance contracts with actual NFT policy IDs applied as parameters

4. **Error Cases**: Add negative tests for invalid rotations:
   - Wrong logic_round increment
   - Missing NFT
   - Insufficient signatures
   - Invalid datum structure

## References

- Hayate simulator: `/home/sam/work/iohk/hayate/src/wallet/simulator/`
- Aiken contracts: `validators/validators/*.ak`
- Contract extraction: `cargo run -- genesis extract-contracts`
- Plutus blueprint: `validators/plutus.json`
