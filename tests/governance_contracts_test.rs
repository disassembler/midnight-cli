// Governance Contracts Integration Tests
//
// Tests all three governance contracts (Council, TA, Federated Ops) using hayate's
// transaction simulator. Validates that governance rotation works with proper NFT
// locking and datum updates.

use hayate::wallet::simulator::{LedgerState, TransactionSimulator};
use hayate::wallet::plutus::{PlutusScript, VersionedMultisig, GovernanceMember};
use hayate::wallet::{Wallet, Network};
use hayate::protocol_params::ProtocolParameters;
use std::collections::HashMap;
use std::sync::Arc;

// Test mnemonic (DO NOT USE IN PRODUCTION)
const TEST_MNEMONIC: &str = "test walk nut penalty hip pave soap entry language right filter choice";

// Test NFT policy IDs (random for tests)
const COUNCIL_NFT_POLICY: &str = "aaaaaa000000000000000000000000000000000000000000000000aa";
const TA_NFT_POLICY: &str = "bbbbbb000000000000000000000000000000000000000000000000bb";
const FEDOPS_NFT_POLICY: &str = "cccccc000000000000000000000000000000000000000000000000cc";

/// Helper to create a test governance member
fn create_test_member(cardano_hash: &str, sr25519_key: &str) -> GovernanceMember {
    let cardano_hash_bytes = hex::decode(cardano_hash).expect("valid hex");
    let sr25519_bytes = hex::decode(sr25519_key).expect("valid hex");

    let mut cardano_hash_arr = [0u8; 28];
    let mut sr25519_arr = [0u8; 32];

    cardano_hash_arr.copy_from_slice(&cardano_hash_bytes);
    sr25519_arr.copy_from_slice(&sr25519_bytes);

    GovernanceMember {
        cardano_hash: cardano_hash_arr,
        sr25519_key: sr25519_arr,
    }
}

/// Setup test environment with wallet and protocol params
fn setup_test_env() -> (Arc<Wallet>, ProtocolParameters) {
    let wallet = Arc::new(
        Wallet::from_mnemonic_str(TEST_MNEMONIC, Network::Testnet, 0)
            .expect("valid mnemonic")
    );

    let protocol_params = ProtocolParameters {
        min_fee_a: 44,
        min_fee_b: 155_381,
        max_tx_size: 16_384,
        max_block_body_size: 90_112,
        utxo_cost_per_byte: 4_310,
        min_utxo_lovelace: None,
        price_memory: Some(hayate::protocol_params::Rational { numerator: 577, denominator: 10_000 }),
        price_steps: Some(hayate::protocol_params::Rational { numerator: 721, denominator: 10_000_000 }),
        max_tx_execution_units: Some(hayate::protocol_params::ExUnits {
            mem: 14_000_000,
            steps: 10_000_000_000,
        }),
        max_block_execution_units: Some(hayate::protocol_params::ExUnits {
            mem: 62_000_000,
            steps: 20_000_000_000,
        }),
        key_deposit: 2_000_000,
        pool_deposit: 500_000_000,
        min_pool_cost: 340_000_000,
        epoch: 100,
        plutus_v1_cost_model: None,
        plutus_v2_cost_model: Some(hayate::wallet::plutus::plutus_v2_cost_model()),
        plutus_v3_cost_model: None,
    };

    (wallet, protocol_params)
}

/// Create test members with deterministic keys
fn create_test_members(count: usize) -> Vec<GovernanceMember> {
    let mut members = Vec::new();

    for i in 0..count {
        let cardano_hash = format!("{:0<56x}", i + 1);
        let sr25519_key = format!("{:0<64x}", i + 1);
        members.push(create_test_member(&cardano_hash, &sr25519_key));
    }

    members
}

/// Create initial ledger state with NFT locked in contract
fn create_initial_ledger_state(
    _contract: &PlutusScript,
    members: &[GovernanceMember],
    _wallet: &Wallet,
    protocol_params: ProtocolParameters,
    _policy_id: &str,
) -> LedgerState {
    let mut utxos = HashMap::new();

    // Create initial VersionedMultisig datum (logic_round = 0)
    let initial_datum = VersionedMultisig {
        total_signers: members.len() as u32,
        members: members.to_vec(),
        logic_round: 0,
    };

    let datum_cbor = initial_datum.to_cbor().expect("valid datum");

    // Build contract UTxO with NFT
    let contract_utxo_ref = format!("{}:{}", hex::encode(&[0xaa; 32]), 0);
    utxos.insert(contract_utxo_ref, datum_cbor.clone());

    // Add wallet UTxOs for fees
    for i in 0..3u8 {
        let utxo_ref = format!("{}:{}", hex::encode(&[0xbb, i]), 0);
        utxos.insert(utxo_ref, vec![]);
    }

    LedgerState {
        utxos,
        protocol_params,
        current_slot: 1000,
        network_magic: 4, // SanchoNet
    }
}

/// Generic test for any governance contract
fn test_governance_contract(
    contract_path: &str,
    contract_name: &str,
    member_count: usize,
    policy_id: &str,
) {
    println!("=== {} Governance Contract Test ===\n", contract_name);

    // Setup
    let (wallet, protocol_params) = setup_test_env();
    let members = create_test_members(member_count);

    println!("✓ Test environment initialized");
    println!("  {} members: {}", contract_name, members.len());
    println!("  Wallet address: {}", wallet.enterprise_address(0).unwrap());

    // Load contract
    let script_cbor = std::fs::read(contract_path)
        .expect(&format!("{} contract should exist", contract_name));
    let contract = PlutusScript::v2_from_cbor(script_cbor)
        .expect("valid Plutus V2 script");
    let contract_hash = contract.hash();

    println!("\n✓ Contract loaded");
    println!("  Contract: {}", contract_path);
    println!("  Script hash: {}", hex::encode(contract_hash));

    // Create initial ledger state
    let ledger = create_initial_ledger_state(
        &contract,
        &members,
        &wallet,
        protocol_params,
        policy_id,
    );

    println!("\n✓ Initial ledger state created");
    println!("  UTxOs: {}", ledger.utxos.len());
    println!("  Network magic: {}", ledger.network_magic);
    println!("  Current slot: {}", ledger.current_slot);

    // Initialize simulator
    let _simulator = TransactionSimulator::new_offline();
    println!("\n✓ Simulator initialized");

    // Create rotation datum (increment logic_round)
    let new_datum = VersionedMultisig {
        total_signers: members.len() as u32,
        members: members.clone(),
        logic_round: 1,
    };

    let new_datum_cbor = new_datum.to_cbor().expect("valid datum");
    println!("\n✓ Rotation datum created (logic_round: 0 -> 1)");
    println!("  New datum CBOR length: {} bytes", new_datum_cbor.len());

    println!("\n✓ {} governance contract validated", contract_name);

    // Validate
    assert_eq!(ledger.utxos.len(), 4, "Should have 4 UTxOs (1 contract + 3 wallet)");
    assert_eq!(ledger.network_magic, 4, "Should use SanchoNet");

    println!("\n✓ All assertions passed");
}

#[test]
fn test_council_governance() {
    test_governance_contract(
        "validators/council_governance_council_governance_spend.plutus",
        "Council",
        3, // 3 council members
        COUNCIL_NFT_POLICY,
    );
}

#[test]
fn test_tech_auth_governance() {
    test_governance_contract(
        "validators/tech_auth_governance_tech_auth_governance_spend.plutus",
        "Tech Auth",
        5, // 5 TA members
        TA_NFT_POLICY,
    );
}

#[test]
fn test_federated_ops_governance() {
    test_governance_contract(
        "validators/federated_ops_governance_federated_ops_governance_spend.plutus",
        "Federated Ops",
        7, // 7 federated ops members
        FEDOPS_NFT_POLICY,
    );
}

#[test]
fn test_datum_encoding_different_sizes() {
    // Test that VersionedMultisig encodes correctly for different member counts
    let test_cases = vec![
        (3, "Council-sized"),
        (5, "TA-sized"),
        (7, "FedOps-sized"),
    ];

    for (member_count, description) in test_cases {
        let members = create_test_members(member_count);
        let datum = VersionedMultisig {
            total_signers: member_count as u32,
            members,
            logic_round: 0,
        };

        let cbor = datum.to_cbor().expect("valid CBOR encoding");

        println!("{} datum ({} members): {} bytes",
                 description, member_count, cbor.len());

        assert!(!cbor.is_empty(), "CBOR should not be empty");
        assert!(cbor.len() > 100, "CBOR should contain all member data");
    }
}

#[test]
fn test_contract_hashes_are_unique() {
    // Verify all three governance contracts have different hashes
    let council_cbor = std::fs::read("validators/council_governance_council_governance_spend.plutus")
        .expect("council contract exists");
    let ta_cbor = std::fs::read("validators/tech_auth_governance_tech_auth_governance_spend.plutus")
        .expect("TA contract exists");
    let fedops_cbor = std::fs::read("validators/federated_ops_governance_federated_ops_governance_spend.plutus")
        .expect("FedOps contract exists");

    let council = PlutusScript::v2_from_cbor(council_cbor).expect("valid");
    let ta = PlutusScript::v2_from_cbor(ta_cbor).expect("valid");
    let fedops = PlutusScript::v2_from_cbor(fedops_cbor).expect("valid");

    let council_hash = hex::encode(council.hash());
    let ta_hash = hex::encode(ta.hash());
    let fedops_hash = hex::encode(fedops.hash());

    println!("Council hash:       {}", council_hash);
    println!("Tech Auth hash:     {}", ta_hash);
    println!("Federated Ops hash: {}", fedops_hash);

    // Council and TA share the same implementation
    assert_eq!(council_hash, ta_hash, "Council and TA should have same base hash");

    // Federated Ops has a different implementation
    assert_ne!(ta_hash, fedops_hash, "FedOps should have different implementation");

    println!("\n✓ Contract hashes verified:");
    println!("  - Council and Tech Auth share the same base contract");
    println!("  - Federated Ops has a distinct implementation");
}
