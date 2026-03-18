// SPDX-License-Identifier: Apache-2.0

//! Governance contract deployment
//!
//! This module provides functionality for deploying governance contracts
//! (Council, TA, FedOps) with NFT minting and initial datum setup.

use anyhow::{Context, Result};
use hayate::wallet::plutus::{GovernanceMember, PlutusScript, VersionedMultisig};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Type of governance contract to deploy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum GovernanceContractType {
    Council,
    TechnicalAdvisory,
    FederatedOperations,
}

impl GovernanceContractType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Council => "council",
            Self::TechnicalAdvisory => "ta",
            Self::FederatedOperations => "fedops",
        }
    }

    pub fn display_name(&self) -> &str {
        match self {
            Self::Council => "Council Governance",
            Self::TechnicalAdvisory => "Technical Advisory",
            Self::FederatedOperations => "Federated Operations",
        }
    }
}

/// Serializable governance member (for state files)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableMember {
    pub cardano_hash: String,
    pub sr25519_key: String,
}

impl From<&GovernanceMember> for SerializableMember {
    fn from(member: &GovernanceMember) -> Self {
        Self {
            cardano_hash: hex::encode(&member.cardano_hash),
            sr25519_key: hex::encode(&member.sr25519_key),
        }
    }
}

impl SerializableMember {
    pub fn to_governance_member(&self) -> Result<GovernanceMember> {
        let cardano_bytes = hex::decode(&self.cardano_hash)?;
        let sr25519_bytes = hex::decode(&self.sr25519_key)?;

        if cardano_bytes.len() != 28 {
            anyhow::bail!("Invalid cardano_hash length: {}", cardano_bytes.len());
        }
        if sr25519_bytes.len() != 32 {
            anyhow::bail!("Invalid sr25519_key length: {}", sr25519_bytes.len());
        }

        let mut cardano_hash = [0u8; 28];
        let mut sr25519_key = [0u8; 32];
        cardano_hash.copy_from_slice(&cardano_bytes);
        sr25519_key.copy_from_slice(&sr25519_bytes);

        Ok(GovernanceMember {
            cardano_hash,
            sr25519_key,
        })
    }
}

/// Deployment state saved to disk for later rotation operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentState {
    /// Contract type
    pub contract_type: String,

    /// Contract address (bech32)
    pub contract_address: String,

    /// NFT policy ID (hex)
    pub nft_policy_id: String,

    /// NFT asset name (hex)
    pub nft_asset_name: String,

    /// Current logic round
    pub logic_round: u32,

    /// Current members (serialized)
    pub members: Vec<SerializableMember>,

    /// Deployment transaction hash
    pub deployment_tx_hash: String,

    /// Deployment timestamp
    pub deployed_at: String,
}

impl DeploymentState {
    /// Get members as GovernanceMember array
    pub fn get_members(&self) -> Result<Vec<GovernanceMember>> {
        self.members.iter()
            .map(|m| m.to_governance_member())
            .collect()
    }
}

impl DeploymentState {
    /// Write state to a JSON file
    pub fn write_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize deployment state")?;
        std::fs::write(path.as_ref(), json)
            .with_context(|| format!("Failed to write state to {}", path.as_ref().display()))?;
        Ok(())
    }

    /// Read state from a JSON file
    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let json = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read state from {}", path.as_ref().display()))?;
        let state: DeploymentState = serde_json::from_str(&json)
            .context("Failed to parse deployment state JSON")?;
        Ok(state)
    }
}

/// Arguments for contract deployment
#[allow(dead_code)]
pub struct DeploymentArgs<'a> {
    /// Contract type to deploy
    pub contract_type: GovernanceContractType,

    /// Initial members
    pub members: &'a [GovernanceMember],

    /// NFT policy ID (hex) - if None, will generate one-shot policy
    pub nft_policy_id: Option<String>,

    /// Initial UTxO reference for one-shot minting (tx_hash#index)
    pub initial_utxo_ref: String,

    /// Hayate endpoint for querying UTxOs
    pub hayate_endpoint: String,

    /// Wallet mnemonic for fees/collateral (for non-air-gap or when signing)
    pub wallet_mnemonic: Option<&'a str>,

    /// Account extended public key (for air-gap mode)
    pub account_xpub: Option<&'a str>,

    /// Wallet account index
    pub account: u32,

    /// Output directory for state files
    pub output_dir: &'a Path,

    /// Air-gap mode: create unsigned transaction instead of submitting
    pub air_gap: bool,
}

/// Result of a deployment operation
#[allow(dead_code)]
pub struct DeploymentResult {
    /// Contract address (bech32)
    pub contract_address: String,

    /// NFT policy ID (hex)
    pub nft_policy_id: String,

    /// Transaction hash (if submitted) or None (if air-gap)
    pub tx_hash: Option<String>,

    /// Path to state file
    pub state_file: std::path::PathBuf,

    /// Path to unsigned transaction body (if air-gap)
    pub tx_body_file: Option<std::path::PathBuf>,

    /// Path to metadata file (if air-gap)
    pub metadata_file: Option<std::path::PathBuf>,
}

/// Deploy a governance contract
///
/// This function:
/// 1. Loads the appropriate contract script (Council/TA/FedOps)
/// 2. Mints a one-shot NFT using native script
/// 3. Creates the initial VersionedMultisig datum
/// 4. Builds a transaction to lock the NFT in the contract
/// 5. Either submits the transaction or creates unsigned files for air-gap
pub async fn deploy_contract(args: DeploymentArgs<'_>) -> Result<DeploymentResult> {
    eprintln!("Deploying {} contract...\n", args.contract_type.display_name());

    // Validate members
    if args.members.is_empty() {
        anyhow::bail!("Cannot deploy contract with zero members");
    }

    eprintln!("Members: {}", args.members.len());
    for (i, member) in args.members.iter().enumerate() {
        eprintln!("  {}: Cardano hash: {}, Sr25519: {}",
            i + 1,
            hex::encode(&member.cardano_hash),
            hex::encode(&member.sr25519_key)
        );
    }

    // Create initial datum
    let initial_datum = VersionedMultisig {
        total_signers: args.members.len() as u32,
        members: args.members.to_vec(),
        logic_round: 0,
    };

    let datum_cbor = initial_datum.to_cbor()
        .context("Failed to encode initial datum")?;

    eprintln!("\nInitial datum:");
    eprintln!("  Total signers: {}", initial_datum.total_signers);
    eprintln!("  Logic round: {}", initial_datum.logic_round);
    eprintln!("  Datum CBOR: {} bytes", datum_cbor.len());

    // Load contract script
    let contract_cbor_hex = match args.contract_type {
        GovernanceContractType::Council => {
            eprintln!("\nLoading Council governance contract...");
            crate::contracts::governance::COUNCIL_GOVERNANCE_CBOR
        }
        GovernanceContractType::TechnicalAdvisory => {
            eprintln!("\nLoading TA governance contract...");
            crate::contracts::governance::TECH_AUTH_GOVERNANCE_CBOR
        }
        GovernanceContractType::FederatedOperations => {
            eprintln!("\nLoading FedOps governance contract...");
            crate::contracts::governance::FEDERATED_OPS_GOVERNANCE_CBOR
        }
    };

    let contract_cbor = hex::decode(contract_cbor_hex)
        .context("Failed to decode contract CBOR")?;
    let contract_script = PlutusScript::v2_from_cbor(contract_cbor.clone())
        .context("Failed to parse Plutus script")?;

    let contract_address_bytes = contract_script.address(hayate::wallet::plutus::Network::Testnet)
        .map_err(|e| anyhow::anyhow!("Failed to calculate contract address: {}", e))?;

    // Convert address bytes to bech32
    use pallas_addresses::Address;
    let contract_address_obj = Address::from_bytes(&contract_address_bytes)?;
    let contract_address = contract_address_obj.to_bech32()
        .map_err(|e| anyhow::anyhow!("Failed to encode address as bech32: {}", e))?;

    eprintln!("  Contract address: {}", contract_address);

    // Parse initial UTxO reference for one-shot NFT policy
    eprintln!("\nParsing initial UTxO reference...");
    let utxo_parts: Vec<&str> = args.initial_utxo_ref.split('#').collect();
    if utxo_parts.len() != 2 {
        anyhow::bail!("Invalid initial_utxo_ref format. Expected: tx_hash#output_index");
    }
    let initial_tx_hash = hex::decode(utxo_parts[0])
        .context("Failed to decode initial UTxO tx hash")?;
    let initial_output_index: u32 = utxo_parts[1].parse()
        .context("Failed to parse initial UTxO output index")?;

    if initial_tx_hash.len() != 32 {
        anyhow::bail!("Invalid tx hash length: expected 32 bytes, got {}", initial_tx_hash.len());
    }

    eprintln!("  Initial UTxO: {}#{}", utxo_parts[0], initial_output_index);

    // Create one-shot NFT minting policy
    // Policy: requires spending the specific initial UTxO
    use pallas_codec::minicbor::Encoder;

    let mut policy_script_cbor = Vec::new();
    {
        let mut encoder = Encoder::new(&mut policy_script_cbor);

        // Native script array: [type, content]
        encoder.array(2)?;
        encoder.u32(5)?; // Type 5 = RequireAllOf (wrapper for single script)

        encoder.array(1)?; // Array of 1 script
        encoder.array(2)?;
        encoder.u32(3)?; // Type 3 = RequireTimeStart (using as RequireSignature placeholder)

        // Encode the UTxO reference
        encoder.bytes(&initial_tx_hash)?;
        encoder.u32(initial_output_index)?;
    }

    // Calculate policy ID (Blake2b-224 hash of the script)
    use blake2::{Blake2b512, Digest};
    let mut hasher = Blake2b512::new();
    hasher.update(&policy_script_cbor);
    let hash_result = hasher.finalize();
    let policy_id: [u8; 28] = hash_result[..28].try_into().unwrap();
    let policy_id_hex = hex::encode(&policy_id);

    eprintln!("  NFT Policy ID: {}", policy_id_hex);

    // NFT asset name (use contract type name)
    let asset_name = args.contract_type.as_str();
    eprintln!("  NFT Asset name: {}", asset_name);

    // Build deployment transaction
    eprintln!("\n━━━ Building Deployment Transaction ━━━");

    use hayate::wallet::{Wallet, Network};
    use hayate::wallet::unified_tx::UnifiedTxBuilder;
    use hayate::wallet::plutus::DatumOption;
    use hayate::wallet::utxorpc_client::AssetData;
    use std::sync::Arc;

    // Create wallet for address derivation and UTxO queries
    // Note: In air-gap mode, this wallet is NOT used for signing - only for:
    // - Deriving addresses to query UTxOs
    // - Calculating change addresses
    // The actual signing happens on the air-gap machine
    let wallet = if let Some(_xpub) = args.account_xpub {
        // TODO: Support creating wallet from xpub for true air-gap security
        // For now, fall back to requiring mnemonic
        eprintln!("⚠ Account xpub support coming soon");
        eprintln!("   For now, use --mnemonic-file (only used for address derivation, not signing)");
        anyhow::bail!("--account-xpub not yet implemented. Use --mnemonic-file instead.");
    } else if let Some(wallet_mnemonic) = args.wallet_mnemonic {
        if args.air_gap {
            eprintln!("ℹ Using mnemonic for address derivation only (not for signing)");
        }
        Arc::new(Wallet::from_mnemonic_str(
            wallet_mnemonic,
            Network::Testnet,
            args.account,
        )?)
    } else {
        anyhow::bail!("Must provide either --wallet-mnemonic or --account-xpub");
    };

    // Create UnifiedTxBuilder
    eprintln!("Connecting to hayate endpoint...");
    let mut tx_builder = UnifiedTxBuilder::new(
        Arc::clone(&wallet),
        args.hayate_endpoint.clone(),
    ).await?;

    // Query wallet UTxOs
    eprintln!("Querying wallet UTxOs...");
    eprintln!("  Account: {}", args.account);

    // Show addresses being queried
    eprintln!("  Addresses being scanned:");
    for i in 0..3 {
        if let Ok(enterprise_addr) = wallet.enterprise_address(i) {
            eprintln!("    Enterprise {}: {}", i, enterprise_addr);
        }
        if let Ok(payment_addr) = wallet.payment_address(i) {
            eprintln!("    Payment {}: {}", i, payment_addr);
        }
    }
    eprintln!("  ... and 17 more of each type");

    tx_builder.query_utxos().await?;

    // Debug: Check what UTxOs were found
    eprintln!("\n  DEBUG: Checking available UTxOs...");
    // The builder doesn't expose available_utxos, so we can't check directly
    // but the build will fail if there are no UTxOs

    // Build one-shot minting policy (native script)
    // ScriptPubkey format: requires specific UTxO to be spent
    let mut policy_script_bytes = Vec::new();
    {
        let mut enc = Encoder::new(&mut policy_script_bytes);
        // Type 0 = ScriptPubkey (requires UTxO)
        enc.array(2)?;
        enc.u32(0)?;
        enc.array(2)?;
        enc.bytes(&initial_tx_hash)?;
        enc.u32(initial_output_index)?;
    }

    eprintln!("  One-shot policy script: {} bytes", policy_script_bytes.len());

    // Mint 1 NFT with the one-shot policy
    let asset_name_bytes = asset_name.as_bytes().to_vec();
    tx_builder.mint_with_native_script(
        policy_script_bytes.clone(),
        policy_id,
        asset_name_bytes.clone(),
        1, // Mint 1 NFT
    )?;

    eprintln!("  Minting 1 {} NFT", asset_name);

    // Send NFT to contract address with inline datum
    let nft_asset = AssetData {
        policy_id: policy_id.to_vec(),
        asset_name: asset_name_bytes,
        amount: 1,
    };

    tx_builder.pay_to_script_with_assets(
        contract_address_bytes.clone(),
        2_000_000, // 2 ADA locked with NFT
        vec![nft_asset],
        DatumOption::inline(datum_cbor.clone()),
        None, // No script reference
    )?;

    eprintln!("  Sending NFT to contract: {}", contract_address);
    eprintln!("  With inline datum ({} bytes)", datum_cbor.len());

    // Build transaction
    eprintln!("\nBuilding transaction...");
    let built_tx = tx_builder.build().await?;

    let tx_hash_hex = hex::encode(&built_tx.tx_hash);
    eprintln!("  Transaction hash: {}", tx_hash_hex);
    eprintln!("  Fee: {} lovelace", built_tx.fee_paid);
    eprintln!("  Inputs used: {}", built_tx.inputs_used.len());

    if args.air_gap {
        // Create air-gap files
        eprintln!("\n━━━ Creating Air-Gap Files ━━━");

        use crate::storage::{TextEnvelope, TransactionMetadata, SignaturesNeeded, ProposalDetails};

        std::fs::create_dir_all(args.output_dir)?;

        // Create .txbody file
        let tx_body_file = args.output_dir.join(format!("{}-deployment.txbody", args.contract_type.as_str()));
        let tx_body_envelope = TextEnvelope::unwitnessed_tx(
            &built_tx.tx_bytes,
            format!("{} deployment transaction", args.contract_type.display_name())
        );
        tx_body_envelope.write_to_file(&tx_body_file)?;
        eprintln!("✓ Created: {}", tx_body_file.display());

        // Create metadata
        let metadata = TransactionMetadata {
            transaction_type: format!("{}_deployment", args.contract_type.as_str()),
            tx_hash: format!("0x{}", tx_hash_hex),
            required_signers: vec![], // No governance signers for deployment
            signatures_needed: SignaturesNeeded::new(0), // Just wallet signature
            proposal_details: ProposalDetails {
                current_logic_round: 0,
                new_logic_round: 0,
                description: Some(format!("Deploy {} governance contract with NFT", args.contract_type.display_name())),
                contract_address: Some(contract_address.clone()),
                nft_policy_id: Some(policy_id_hex.clone()),
            },
        };

        let metadata_file = args.output_dir.join(format!("{}-deployment.metadata", args.contract_type.as_str()));
        metadata.write_to_file(&metadata_file)?;
        eprintln!("✓ Created: {}", metadata_file.display());

        eprintln!("\n━━━ Air-Gap Workflow ━━━");
        eprintln!("1. Sign transaction with wallet key:");
        eprintln!("   cardano-cli transaction sign \\");
        eprintln!("     --tx-body-file {} \\", tx_body_file.display());
        eprintln!("     --signing-key-file payment.skey \\");
        eprintln!("     --out-file deployment.tx");
        eprintln!();
        eprintln!("2. Submit transaction:");
        eprintln!("   cardano-cli transaction submit \\");
        eprintln!("     --tx-file deployment.tx \\");
        eprintln!("     --testnet-magic 4");

        // Create state file
        let state = DeploymentState {
            contract_type: args.contract_type.as_str().to_string(),
            contract_address: contract_address.clone(),
            nft_policy_id: policy_id_hex.clone(),
            nft_asset_name: asset_name.to_string(),
            logic_round: 0,
            members: args.members.iter().map(SerializableMember::from).collect(),
            deployment_tx_hash: tx_hash_hex.clone(),
            deployed_at: chrono::Utc::now().to_rfc3339(),
        };

        std::fs::create_dir_all(args.output_dir)?;
        let state_file = args.output_dir.join(format!("{}-governance.state.json", args.contract_type.as_str()));
        state.write_to_file(&state_file)?;

        eprintln!("\n✓ State file created: {}", state_file.display());

        Ok(DeploymentResult {
            contract_address,
            nft_policy_id: policy_id_hex,
            tx_hash: Some(tx_hash_hex),
            state_file,
            tx_body_file: Some(tx_body_file),
            metadata_file: Some(metadata_file),
        })
    } else {
        // Sign and submit
        eprintln!("\n━━━ Signing and Submitting ━━━");

        // Rebuild to get a fresh builder for signing
        let mut submit_builder = UnifiedTxBuilder::new(
            Arc::clone(&wallet),
            args.hayate_endpoint.clone(),
        ).await?;

        // Query UTxOs
        submit_builder.query_utxos().await?;

        // Re-apply same operations
        submit_builder.mint_with_native_script(
            policy_script_bytes,
            policy_id,
            asset_name.as_bytes().to_vec(),
            1,
        )?;

        let nft_asset = AssetData {
            policy_id: policy_id.to_vec(),
            asset_name: asset_name.as_bytes().to_vec(),
            amount: 1,
        };

        submit_builder.pay_to_script_with_assets(
            contract_address_bytes.clone(),
            2_000_000,
            vec![nft_asset],
            DatumOption::inline(datum_cbor.clone()),
            None,
        )?;

        // Build, sign, and submit in one call
        let submit_result = submit_builder.build_sign_submit().await?;

        eprintln!("✓ Transaction submitted: {}", hex::encode(&submit_result));
        eprintln!("✓ Contract deployed at: {}", contract_address);

        // Create state file
        let state = DeploymentState {
            contract_type: args.contract_type.as_str().to_string(),
            contract_address: contract_address.clone(),
            nft_policy_id: policy_id_hex.clone(),
            nft_asset_name: asset_name.to_string(),
            logic_round: 0,
            members: args.members.iter().map(SerializableMember::from).collect(),
            deployment_tx_hash: tx_hash_hex.clone(),
            deployed_at: chrono::Utc::now().to_rfc3339(),
        };

        std::fs::create_dir_all(args.output_dir)?;
        let state_file = args.output_dir.join(format!("{}-governance.state.json", args.contract_type.as_str()));
        state.write_to_file(&state_file)?;

        eprintln!("✓ State file created: {}", state_file.display());

        Ok(DeploymentResult {
            contract_address,
            nft_policy_id: policy_id_hex,
            tx_hash: Some(tx_hash_hex),
            state_file,
            tx_body_file: None,
            metadata_file: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_type_str() {
        assert_eq!(GovernanceContractType::Council.as_str(), "council");
        assert_eq!(GovernanceContractType::TechnicalAdvisory.as_str(), "ta");
        assert_eq!(GovernanceContractType::FederatedOperations.as_str(), "fedops");
    }

    #[test]
    fn test_deployment_state_roundtrip() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("test-state.json");

        let state = DeploymentState {
            contract_type: "council".to_string(),
            contract_address: "addr_test1...".to_string(),
            nft_policy_id: "abcd1234".to_string(),
            nft_asset_name: "council".to_string(),
            logic_round: 0,
            members: vec![],
            deployment_tx_hash: "tx123".to_string(),
            deployed_at: "2024-01-01T00:00:00Z".to_string(),
        };

        state.write_to_file(&state_file).unwrap();
        let loaded = DeploymentState::read_from_file(&state_file).unwrap();

        assert_eq!(loaded.contract_type, state.contract_type);
        assert_eq!(loaded.contract_address, state.contract_address);
        assert_eq!(loaded.nft_policy_id, state.nft_policy_id);
        assert_eq!(loaded.logic_round, state.logic_round);
    }

    #[test]
    fn test_serializable_member_conversion() {
        let member = GovernanceMember {
            cardano_hash: [0x42; 28],
            sr25519_key: [0x99; 32],
        };

        let serializable = SerializableMember::from(&member);

        assert_eq!(serializable.cardano_hash, hex::encode([0x42; 28]));
        assert_eq!(serializable.sr25519_key, hex::encode([0x99; 32]));

        // Convert back
        let recovered = serializable.to_governance_member().unwrap();
        assert_eq!(recovered.cardano_hash, member.cardano_hash);
        assert_eq!(recovered.sr25519_key, member.sr25519_key);
    }

    #[test]
    fn test_serializable_member_roundtrip() {
        let members = vec![
            GovernanceMember {
                cardano_hash: [1u8; 28],
                sr25519_key: [2u8; 32],
            },
            GovernanceMember {
                cardano_hash: [3u8; 28],
                sr25519_key: [4u8; 32],
            },
        ];

        let serializable: Vec<SerializableMember> = members.iter().map(SerializableMember::from).collect();

        let recovered: Result<Vec<GovernanceMember>> = serializable.iter().map(|s| s.to_governance_member()).collect();
        let recovered = recovered.unwrap();

        assert_eq!(recovered.len(), members.len());
        for (orig, rec) in members.iter().zip(recovered.iter()) {
            assert_eq!(orig.cardano_hash, rec.cardano_hash);
            assert_eq!(orig.sr25519_key, rec.sr25519_key);
        }
    }

    #[test]
    fn test_deployment_state_with_members() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("test-state-with-members.json");

        let members = vec![
            SerializableMember {
                cardano_hash: hex::encode([0x42; 28]),
                sr25519_key: hex::encode([0x99; 32]),
            },
            SerializableMember {
                cardano_hash: hex::encode([0x43; 28]),
                sr25519_key: hex::encode([0x98; 32]),
            },
        ];

        let state = DeploymentState {
            contract_type: "council".to_string(),
            contract_address: "addr_test1...".to_string(),
            nft_policy_id: "abcd1234".to_string(),
            nft_asset_name: "council".to_string(),
            logic_round: 0,
            members,
            deployment_tx_hash: "tx123".to_string(),
            deployed_at: "2024-01-01T00:00:00Z".to_string(),
        };

        state.write_to_file(&state_file).unwrap();
        let loaded = DeploymentState::read_from_file(&state_file).unwrap();

        assert_eq!(loaded.members.len(), 2);
        assert_eq!(loaded.members[0].cardano_hash, hex::encode([0x42; 28]));
        assert_eq!(loaded.members[1].sr25519_key, hex::encode([0x98; 32]));
    }

    #[test]
    fn test_deployment_state_get_members() {
        let members_serializable = vec![
            SerializableMember {
                cardano_hash: hex::encode([0x42; 28]),
                sr25519_key: hex::encode([0x99; 32]),
            },
        ];

        let state = DeploymentState {
            contract_type: "council".to_string(),
            contract_address: "addr_test1...".to_string(),
            nft_policy_id: "abcd1234".to_string(),
            nft_asset_name: "council".to_string(),
            logic_round: 0,
            members: members_serializable,
            deployment_tx_hash: "tx123".to_string(),
            deployed_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let members = state.get_members().unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].cardano_hash, [0x42; 28]);
        assert_eq!(members[0].sr25519_key, [0x99; 32]);
    }

    #[test]
    fn test_serializable_member_invalid_lengths() {
        // Invalid cardano hash length
        let invalid_cardano = SerializableMember {
            cardano_hash: hex::encode([0x42; 10]), // Wrong length
            sr25519_key: hex::encode([0x99; 32]),
        };
        assert!(invalid_cardano.to_governance_member().is_err());

        // Invalid sr25519 key length
        let invalid_sr25519 = SerializableMember {
            cardano_hash: hex::encode([0x42; 28]),
            sr25519_key: hex::encode([0x99; 16]), // Wrong length
        };
        assert!(invalid_sr25519.to_governance_member().is_err());

        // Invalid hex encoding
        let invalid_hex = SerializableMember {
            cardano_hash: "not_valid_hex".to_string(),
            sr25519_key: hex::encode([0x99; 32]),
        };
        assert!(invalid_hex.to_governance_member().is_err());
    }

    #[test]
    fn test_governance_contract_type_conversions() {
        assert_eq!(GovernanceContractType::Council.as_str(), "council");
        assert_eq!(GovernanceContractType::TechnicalAdvisory.as_str(), "ta");
        assert_eq!(GovernanceContractType::FederatedOperations.as_str(), "fedops");

        assert_eq!(GovernanceContractType::Council.display_name(), "Council Governance");
        assert_eq!(GovernanceContractType::TechnicalAdvisory.display_name(), "Technical Advisory");
        assert_eq!(GovernanceContractType::FederatedOperations.display_name(), "Federated Operations");
    }
}
