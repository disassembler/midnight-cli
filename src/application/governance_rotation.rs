// SPDX-License-Identifier: Apache-2.0

//! Governance rotation transaction building
//!
//! This module provides functions for building governance rotation transactions
//! for Council, TA, and FedOps contracts.

use anyhow::Result;
use hayate::wallet::plutus::{GovernanceMember, VersionedMultisig, Redeemer};
use crate::storage::{SignaturesNeeded, SignerInfo, ProposalDetails, TransactionMetadata, TextEnvelope};
use std::path::Path;

/// Arguments for building a Council rotation transaction
pub struct CouncilRotationArgs<'a> {
    /// Contract address (bech32)
    pub contract_address: String,

    /// NFT policy ID (hex)
    pub nft_policy_id: String,

    /// New members
    pub new_members: &'a [GovernanceMember],

    /// Hayate endpoint for querying UTxOs
    pub hayate_endpoint: String,

    /// Wallet mnemonic for fees/collateral
    pub wallet_mnemonic: &'a str,

    /// Wallet account index
    pub account: u32,

    /// Output directory for transaction files
    pub output_dir: &'a Path,

    /// Air-gap mode: create unsigned transaction instead of submitting
    pub air_gap: bool,
}

/// Arguments for building a TA rotation transaction
#[allow(dead_code)]
pub struct TaRotationArgs<'a> {
    /// Current contract state
    pub current_state: &'a crate::application::governance_deployment::DeploymentState,

    /// New members
    pub new_members: &'a [GovernanceMember],

    /// Hayate endpoint for querying UTxOs
    pub hayate_endpoint: String,

    /// Wallet mnemonic for fees/collateral
    pub wallet_mnemonic: &'a str,

    /// Wallet account index
    pub account: u32,

    /// Output directory for transaction files
    pub output_dir: &'a Path,

    /// Air-gap mode: create unsigned transaction instead of submitting
    pub air_gap: bool,
}

/// Arguments for building a FedOps rotation transaction
#[allow(dead_code)]
pub struct FedopsRotationArgs<'a> {
    /// Current FedOps contract state
    pub fedops_state: &'a crate::application::governance_deployment::DeploymentState,

    /// Current Council contract state
    pub council_state: &'a crate::application::governance_deployment::DeploymentState,

    /// Current TA contract state
    pub ta_state: &'a crate::application::governance_deployment::DeploymentState,

    /// New validator keys (for FedOps)
    pub new_validator_keys: &'a [Vec<u8>],

    /// Hayate endpoint for querying UTxOs
    pub hayate_endpoint: String,

    /// Wallet mnemonic for fees/collateral
    pub wallet_mnemonic: &'a str,

    /// Wallet account index
    pub account: u32,

    /// Output directory for transaction files
    pub output_dir: &'a Path,

    /// Air-gap mode: create unsigned transaction instead of submitting
    pub air_gap: bool,
}

/// Result of a rotation transaction building operation
#[allow(dead_code)]
pub struct RotationResult {
    /// Transaction hash (if submitted) or None (if air-gap)
    pub tx_hash: Option<String>,

    /// Path to updated state file
    pub state_file: std::path::PathBuf,

    /// Path to unsigned transaction body (if air-gap)
    pub tx_body_file: Option<std::path::PathBuf>,

    /// Path to metadata file (if air-gap)
    pub metadata_file: Option<std::path::PathBuf>,
}

/// Build a Council rotation transaction
///
/// This function:
/// 1. Queries the Council contract UTxO
/// 2. Decodes the current VersionedMultisig datum
/// 3. Increments logic_round
/// 4. Builds UpdateRedeemer with new members
/// 5. Extracts required signers (2/3 from current Council members)
/// 6. Either submits or creates unsigned transaction + metadata
pub async fn build_council_rotation_tx(args: CouncilRotationArgs<'_>) -> Result<RotationResult> {
    use hayate::wallet::{Wallet, Network};
    use hayate::wallet::plutus::{PlutusScript, Network as PlutusNetwork, DatumOption};
    use hayate::wallet::tx_builder::{PlutusTransactionBuilder, PlutusOutput};
    use hayate::wallet::utxorpc_client::WalletUtxorpcClient;
    use pallas_addresses::Address;
    use std::sync::Arc;

    eprintln!("Building Council rotation transaction...\n");

    // Validate new members
    if args.new_members.is_empty() {
        anyhow::bail!("Cannot rotate to zero members");
    }

    // Create wallet for fees
    let wallet = Arc::new(Wallet::from_mnemonic_str(
        args.wallet_mnemonic,
        Network::Testnet,
        args.account,
    )?);

    // Connect to hayate
    let mut client = WalletUtxorpcClient::connect(args.hayate_endpoint.clone()).await?;

    // Query contract UTxO
    eprintln!("Querying contract UTxO...");
    let contract_addr_bytes = Address::from_bech32(&args.contract_address)?.to_vec();
    let contract_utxos = client.query_utxos(vec![contract_addr_bytes.clone()]).await?;

    if contract_utxos.is_empty() {
        anyhow::bail!("No UTxO found at contract address: {}", args.contract_address);
    }

    // Find UTxO with the governance NFT
    let nft_policy = hex::decode(&args.nft_policy_id)?;
    let contract_utxo = contract_utxos.iter()
        .find(|u| {
            u.assets.iter().any(|asset| {
                asset.policy_id == nft_policy
            })
        })
        .ok_or_else(|| anyhow::anyhow!("No UTxO with governance NFT found"))?
        .clone();

    eprintln!("  Found contract UTxO: {}#{}", hex::encode(&contract_utxo.tx_hash), contract_utxo.output_index);
    eprintln!("  Value: {} lovelace", contract_utxo.coin);

    // Decode on-chain datum to get current state
    eprintln!("\nDecoding on-chain datum...");
    let datum_bytes = contract_utxo.datum.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Contract UTxO has no datum"))?;
    let current_datum = VersionedMultisig::from_cbor(datum_bytes)?;

    eprintln!("  Current logic round: {}", current_datum.logic_round);
    eprintln!("  Current members: {}", current_datum.members.len());
    eprintln!("  New members: {}", args.new_members.len());

    // Calculate threshold from CURRENT members (on-chain)
    let current_total = current_datum.total_signers;
    let threshold = SignaturesNeeded::calculate_threshold(current_total);

    eprintln!("\nSignature requirements (from on-chain state):");
    eprintln!("  Total signers: {}", current_total);
    eprintln!("  Threshold: {}", threshold);

    // Query wallet UTxOs for collateral
    eprintln!("\nQuerying wallet UTxOs...");
    let mut wallet_addrs = Vec::new();
    for i in 0..20 {
        if let Ok(addr_bech32) = wallet.enterprise_address(i) {
            if let Ok(addr) = Address::from_bech32(&addr_bech32) {
                wallet_addrs.push(addr.to_vec());
            }
        }
    }
    let wallet_utxos = client.query_utxos(wallet_addrs).await?;
    eprintln!("  Found {} wallet UTxOs", wallet_utxos.len());

    // Find collateral
    let collateral_utxo = wallet_utxos.iter()
        .find(|u| u.assets.is_empty() && u.coin >= 5_000_000)
        .ok_or_else(|| anyhow::anyhow!("No suitable collateral UTxO (need 5 ADA pure UTxO)"))?
        .clone();

    // Create new datum (increment logic_round for anti-replay)
    let new_logic_round = current_datum.logic_round + 1;
    let new_datum = VersionedMultisig {
        total_signers: args.new_members.len() as u32,
        members: args.new_members.to_vec(),
        logic_round: new_logic_round,
    };
    let new_datum_cbor = new_datum.to_cbor()?;

    eprintln!("\nNew datum:");
    eprintln!("  Logic round: {} → {}", current_datum.logic_round, new_logic_round);
    eprintln!("  Datum CBOR: {} bytes", new_datum_cbor.len());

    // Build redeemer
    let redeemer = build_update_redeemer(args.new_members)?;
    eprintln!("\nRedeemer: {} bytes", redeemer.data_bytes().len());

    // Load contract script
    let script_cbor = hex::decode(crate::contracts::governance::COUNCIL_GOVERNANCE_CBOR)?;
    let script = PlutusScript::v2_from_cbor(script_cbor)?;

    // Build transaction
    eprintln!("\nBuilding transaction...");
    let change_addr = wallet.enterprise_address(0)?;
    let change_addr_bytes = Address::from_bech32(&change_addr)?.to_vec();
    let mut tx_builder = PlutusTransactionBuilder::new(PlutusNetwork::Testnet, change_addr_bytes);

    // Add script input
    tx_builder.add_script_input(&contract_utxo, script.clone(), redeemer, None)?;

    // Add contract output (with new datum)
    let contract_output = PlutusOutput::with_assets(
        contract_addr_bytes,
        contract_utxo.coin.saturating_sub(2_000_000), // Subtract fee estimate
        contract_utxo.assets.clone(),
    ).with_datum(DatumOption::inline(new_datum_cbor.clone()));
    tx_builder.add_output(&contract_output)?;

    // Add collateral
    tx_builder.add_collateral(&collateral_utxo)?;

    // Add script
    tx_builder.add_plutus_script(script)?;

    // Query protocol parameters
    eprintln!("Querying protocol parameters...");
    let protocol_params = client.query_protocol_params().await?
        .ok_or_else(|| anyhow::anyhow!("Failed to query protocol parameters"))?;

    // Set parameters
    tx_builder.set_fee(2_000_000);
    tx_builder.set_ttl(999999999);

    if let Some(cost_model) = protocol_params.plutus_v2_cost_model {
        tx_builder.set_language_view(hayate::wallet::plutus::PlutusVersion::V2, cost_model);
    }

    // Build unsigned transaction
    let (tx_body_cbor, _witnesses_cbor) = tx_builder.build()?;

    if args.air_gap {
        // Create air-gap files
        eprintln!("\n━━━ Creating Air-Gap Files ━━━");

        std::fs::create_dir_all(args.output_dir)?;

        // Create .txbody file
        let tx_body_file = args.output_dir.join("council-rotation.txbody");
        let tx_body_envelope = TextEnvelope::unwitnessed_tx(&tx_body_cbor, "Council rotation transaction");
        tx_body_envelope.write_to_file(&tx_body_file)?;
        eprintln!("✓ Created: {}", tx_body_file.display());

        // Compute tx hash
        use blake2::{Blake2b512, Digest};
        let mut hasher = Blake2b512::new();
        hasher.update(&tx_body_cbor);
        let hash_result = hasher.finalize();
        let tx_hash = &hash_result[..32];

        // Extract required signers from on-chain datum
        let required_signers: Vec<SignerInfo> = current_datum.members.iter()
            .enumerate()
            .map(|(i, member)| SignerInfo {
                cardano_key_hash: hex::encode(&member.cardano_hash),
                sr25519_public_key: format!("0x{}", hex::encode(&member.sr25519_key)),
                ss58_address: format!("council_{}", i + 1),
                role: format!("council_member_{}", i + 1),
            })
            .collect();

        // Create metadata
        let metadata = TransactionMetadata {
            transaction_type: "council_rotation".to_string(),
            tx_hash: format!("0x{}", hex::encode(tx_hash)),
            required_signers,
            signatures_needed: SignaturesNeeded::new(current_total),
            proposal_details: ProposalDetails {
                current_logic_round: current_datum.logic_round,
                new_logic_round,
                description: Some("Council member rotation".to_string()),
                contract_address: Some(args.contract_address.clone()),
                nft_policy_id: Some(args.nft_policy_id.clone()),
            },
        };

        let metadata_file = args.output_dir.join("council-rotation.metadata");
        metadata.write_to_file(&metadata_file)?;
        eprintln!("✓ Created: {}", metadata_file.display());

        eprintln!("\n━━━ Air-Gap Workflow ━━━");
        eprintln!("1. Transfer files to air-gap machine(s):");
        eprintln!("   - {}", tx_body_file.display());
        eprintln!("   - {}", metadata_file.display());
        eprintln!();
        eprintln!("2. On each air-gap machine, create witness:");
        eprintln!("   midnight-cli witness create-cardano \\");
        eprintln!("     --tx-body-file {} \\", tx_body_file.display());
        eprintln!("     --metadata-file {} \\", metadata_file.display());
        eprintln!("     --mnemonic-file member.mnemonic \\");
        eprintln!("     --output member.witness");
        eprintln!();
        eprintln!("3. Collect {} of {} signatures (threshold)", threshold, current_total);
        eprintln!();
        eprintln!("4. Assemble and submit:");
        eprintln!("   midnight-cli witness assemble \\");
        eprintln!("     --tx-body-file {} \\", tx_body_file.display());
        eprintln!("     --metadata-file {} \\", metadata_file.display());
        eprintln!("     --witness-files member1.witness,member2.witness \\");
        eprintln!("     --output council-rotation.tx");
        eprintln!();
        eprintln!("   cardano-cli transaction submit --tx-file council-rotation.tx");

        Ok(RotationResult {
            tx_hash: None,
            state_file: args.output_dir.join(format!("{}-governance.state.json", "council")),
            tx_body_file: Some(tx_body_file),
            metadata_file: Some(metadata_file),
        })
    } else {
        eprintln!("\n⚠ Online submission mode not yet implemented");
        eprintln!("Use --air-gap flag for air-gapped signing workflow");
        anyhow::bail!("Online mode requires multi-signature support - use --air-gap instead")
    }
}

/// Build a TA rotation transaction
///
/// This is identical to Council rotation but uses the TA contract.
#[allow(dead_code)]
pub async fn build_ta_rotation_tx(args: TaRotationArgs<'_>) -> Result<RotationResult> {
    use hayate::wallet::{Wallet, Network};
    use hayate::wallet::plutus::{PlutusScript, Network as PlutusNetwork, DatumOption};
    use hayate::wallet::tx_builder::{PlutusTransactionBuilder, PlutusOutput};
    use hayate::wallet::utxorpc_client::WalletUtxorpcClient;
    use pallas_addresses::Address;
    use std::sync::Arc;
    use blake2::{Blake2b512, Digest};

    eprintln!("Building TA rotation transaction...\n");

    if args.new_members.is_empty() {
        anyhow::bail!("Cannot rotate to zero members");
    }

    eprintln!("Current members: {}", args.current_state.members.len());
    eprintln!("New members: {}", args.new_members.len());

    let current_members = args.current_state.get_members()?;
    let current_total = current_members.len() as u32;
    let threshold = SignaturesNeeded::calculate_threshold(current_total);

    eprintln!("\nSignature requirements (from CURRENT members):");
    eprintln!("  Total signers: {}", current_total);
    eprintln!("  Threshold: {}", threshold);

    // Create wallet and connect
    let wallet = Arc::new(Wallet::from_mnemonic_str(args.wallet_mnemonic, Network::Testnet, args.account)?);
    let mut client = WalletUtxorpcClient::connect(args.hayate_endpoint.clone()).await?;

    // Query contract UTxO
    eprintln!("\nQuerying contract UTxO...");
    let contract_addr_bytes = Address::from_bech32(&args.current_state.contract_address)?.to_vec();
    let contract_utxos = client.query_utxos(vec![contract_addr_bytes.clone()]).await?;

    if contract_utxos.is_empty() {
        anyhow::bail!("No UTxO found at contract address");
    }

    let nft_policy = hex::decode(&args.current_state.nft_policy_id)?;
    let contract_utxo = contract_utxos.iter()
        .find(|u| u.assets.iter().any(|asset| asset.policy_id == nft_policy))
        .ok_or_else(|| anyhow::anyhow!("No UTxO with governance NFT found"))?
        .clone();

    eprintln!("  Found contract UTxO: {}#{}", hex::encode(&contract_utxo.tx_hash), contract_utxo.output_index);

    // Query wallet UTxOs
    let mut wallet_addrs = Vec::new();
    for i in 0..20 {
        if let Ok(addr_bech32) = wallet.enterprise_address(i) {
            if let Ok(addr) = Address::from_bech32(&addr_bech32) {
                wallet_addrs.push(addr.to_vec());
            }
        }
    }
    let wallet_utxos = client.query_utxos(wallet_addrs).await?;

    let collateral_utxo = wallet_utxos.iter()
        .find(|u| u.assets.is_empty() && u.coin >= 5_000_000)
        .ok_or_else(|| anyhow::anyhow!("No suitable collateral UTxO"))?
        .clone();

    // Create new datum
    let new_logic_round = args.current_state.logic_round + 1;
    let new_datum = VersionedMultisig {
        total_signers: args.new_members.len() as u32,
        members: args.new_members.to_vec(),
        logic_round: new_logic_round,
    };
    let new_datum_cbor = new_datum.to_cbor()?;

    let redeemer = build_update_redeemer(args.new_members)?;

    // Load TA contract (different from Council)
    let script_cbor = hex::decode(crate::contracts::governance::TECH_AUTH_GOVERNANCE_CBOR)?;
    let script = PlutusScript::v2_from_cbor(script_cbor)?;

    // Build transaction
    let change_addr = wallet.enterprise_address(0)?;
    let change_addr_bytes = Address::from_bech32(&change_addr)?.to_vec();
    let mut tx_builder = PlutusTransactionBuilder::new(PlutusNetwork::Testnet, change_addr_bytes);

    tx_builder.add_script_input(&contract_utxo, script.clone(), redeemer, None)?;

    let contract_output = PlutusOutput::with_assets(
        contract_addr_bytes,
        contract_utxo.coin.saturating_sub(2_000_000),
        contract_utxo.assets.clone(),
    ).with_datum(DatumOption::inline(new_datum_cbor));
    tx_builder.add_output(&contract_output)?;

    tx_builder.add_collateral(&collateral_utxo)?;
    tx_builder.add_plutus_script(script)?;

    let protocol_params = client.query_protocol_params().await?
        .ok_or_else(|| anyhow::anyhow!("Failed to query protocol parameters"))?;

    tx_builder.set_fee(2_000_000);
    tx_builder.set_ttl(999999999);

    if let Some(cost_model) = protocol_params.plutus_v2_cost_model {
        tx_builder.set_language_view(hayate::wallet::plutus::PlutusVersion::V2, cost_model);
    }

    let (tx_body_cbor, _witnesses_cbor) = tx_builder.build()?;

    if args.air_gap {
        std::fs::create_dir_all(args.output_dir)?;

        let tx_body_file = args.output_dir.join("ta-rotation.txbody");
        let tx_body_envelope = TextEnvelope::unwitnessed_tx(&tx_body_cbor, "TA rotation transaction");
        tx_body_envelope.write_to_file(&tx_body_file)?;

        let mut hasher = Blake2b512::new();
        hasher.update(&tx_body_cbor);
        let hash_result = hasher.finalize();
        let tx_hash = &hash_result[..32];

        let required_signers: Vec<SignerInfo> = current_members.iter()
            .enumerate()
            .map(|(i, member)| SignerInfo {
                cardano_key_hash: hex::encode(&member.cardano_hash),
                sr25519_public_key: format!("0x{}", hex::encode(&member.sr25519_key)),
                ss58_address: format!("ta_{}", i + 1),
                role: format!("ta_member_{}", i + 1),
            })
            .collect();

        let metadata = TransactionMetadata {
            transaction_type: "ta_rotation".to_string(),
            tx_hash: format!("0x{}", hex::encode(tx_hash)),
            required_signers,
            signatures_needed: SignaturesNeeded::new(current_total),
            proposal_details: ProposalDetails {
                current_logic_round: args.current_state.logic_round,
                new_logic_round,
                description: Some("TA member rotation".to_string()),
                contract_address: Some(args.current_state.contract_address.clone()),
                nft_policy_id: Some(args.current_state.nft_policy_id.clone()),
            },
        };

        let metadata_file = args.output_dir.join("ta-rotation.metadata");
        metadata.write_to_file(&metadata_file)?;

        eprintln!("\n✓ TA rotation files created");
        eprintln!("  TX body: {}", tx_body_file.display());
        eprintln!("  Metadata: {}", metadata_file.display());

        Ok(RotationResult {
            tx_hash: None,
            state_file: args.output_dir.join("ta-governance.state.json"),
            tx_body_file: Some(tx_body_file),
            metadata_file: Some(metadata_file),
        })
    } else {
        anyhow::bail!("Online mode not supported - use --air-gap")
    }
}

/// Build a FedOps rotation transaction (COMPLEX - requires both Council and TA approval)
///
/// FedOps rotation is special:
/// - Spends 3 NFTs: FedOps + Council + TA
/// - Returns 3 NFTs: FedOps (new datum) + Council (same datum) + TA (same datum)
/// - Increments logic_round on ALL 3 contracts
/// - Requires 2/3 threshold from BOTH Council AND TA
#[allow(dead_code)]
pub async fn build_fedops_rotation_tx(args: FedopsRotationArgs<'_>) -> Result<RotationResult> {
    eprintln!("Building FedOps rotation transaction (requires Council + TA approval)...\n");

    // Calculate thresholds from BOTH governance bodies
    let council_total = args.council_state.members.len() as u32;
    let council_threshold = SignaturesNeeded::calculate_threshold(council_total);

    let ta_total = args.ta_state.members.len() as u32;
    let ta_threshold = SignaturesNeeded::calculate_threshold(ta_total);

    eprintln!("━━━ Council Approval ━━━");
    eprintln!("  Total signers: {}", council_total);
    eprintln!("  Threshold: {}", council_threshold);

    eprintln!("\n━━━ TA Approval ━━━");
    eprintln!("  Total signers: {}", ta_total);
    eprintln!("  Threshold: {}", ta_threshold);

    eprintln!("\n━━━ Total Required Signatures ━━━");
    eprintln!("  Council: {} of {}", council_threshold, council_total);
    eprintln!("  TA: {} of {}", ta_threshold, ta_total);
    eprintln!("  Note: Signers may overlap if someone is in both bodies");

    // Extract required signers from BOTH bodies
    let mut required_signers: Vec<SignerInfo> = Vec::new();

    for (i, member) in args.council_state.members.iter().enumerate() {
        required_signers.push(SignerInfo {
            cardano_key_hash: hex::encode(&member.cardano_hash),
            sr25519_public_key: format!("0x{}", hex::encode(&member.sr25519_key)),
            ss58_address: format!("council_{}", i + 1),
            role: format!("council_member_{}", i + 1),
        });
    }

    for (i, member) in args.ta_state.members.iter().enumerate() {
        required_signers.push(SignerInfo {
            cardano_key_hash: hex::encode(&member.cardano_hash),
            sr25519_public_key: format!("0x{}", hex::encode(&member.sr25519_key)),
            ss58_address: format!("ta_{}", i + 1),
            role: format!("ta_member_{}", i + 1),
        });
    }

    eprintln!("\nTotal required signer entries: {}", required_signers.len());

    // TODO: Implement FedOps rotation
    // Complex transaction structure:
    // INPUTS: FedOps UTxO + Council UTxO + TA UTxO
    // OUTPUTS: FedOps (new datum, logic_round++) + Council (same datum, logic_round++) + TA (same datum, logic_round++)
    // REQUIRED SIGNERS: 2/3 from Council + 2/3 from TA

    eprintln!("\n⚠ FedOps rotation not yet fully implemented");
    eprintln!("This requires:");
    eprintln!("1. Query 3 contract UTxOs (FedOps, Council, TA)");
    eprintln!("2. Build transaction with 3 inputs, 3 outputs");
    eprintln!("3. Increment logic_round on ALL 3 datums");
    eprintln!("4. Collect signatures from BOTH governance bodies");

    anyhow::bail!("FedOps rotation implementation in progress")
}

/// Build UpdateRedeemer CBOR for governance rotation
///
/// UpdateRedeemer structure (from Aiken contract):
/// ```aiken
/// UpdateRedeemer { new_multisig: Multisig }
/// ```
///
/// CBOR encoding:
/// - Constructor 0 with one field (the Multisig)
/// - Multisig: (Int, List<(ByteArray, ByteArray)>)
fn build_update_redeemer(members: &[GovernanceMember]) -> Result<Redeemer> {
    use pallas_codec::minicbor::{Encoder, data::Tag};

    // UpdateRedeemer = Constructor 0 [Multisig]
    // Multisig = (total_signers: Int, signers: List<(cardano_hash, sr25519_key)>)

    let mut buf = Vec::new();
    let mut encoder = Encoder::new(&mut buf);

    // Constructor 0 (tag 121, alternative 0)
    encoder.tag(Tag::new(121))
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;
    encoder.array(2)  // [constructor_index, fields]
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

    // Constructor index: 0 (UpdateRedeemer variant)
    encoder.u32(0)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

    // Fields array (just one field: the Multisig)
    encoder.array(1)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

    // Multisig structure: [total_signers, [[cardano_hash, sr25519_key], ...]]
    encoder.array(2)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

    // Field 0: total_signers (Int)
    encoder.u32(members.len() as u32)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

    // Field 1: signers (List of tuples)
    encoder.array(members.len() as u64)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

    for member in members {
        // Each signer is a tuple: (wrapped_cardano_hash, sr25519_key)
        encoder.array(2)
            .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

        // Wrapped Cardano hash (ByteArray wrapped in constructor for Aiken)
        // Constructor tag for ByteArray
        encoder.tag(Tag::new(121))
            .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;
        encoder.array(2)
            .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;
        encoder.u32(0)  // Constructor 0 for ByteArray wrapper
            .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;
        encoder.array(1)
            .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;
        encoder.bytes(&member.cardano_hash)
            .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

        // Sr25519 key (ByteArray)
        encoder.bytes(&member.sr25519_key)
            .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;
    }

    // Create Redeemer with spend tag (index will be set when building transaction)
    Ok(Redeemer::spend(0, buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::DeploymentState;

    #[test]
    fn test_build_update_redeemer() {
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

        let redeemer = build_update_redeemer(&members).unwrap();
        let cbor = redeemer.data_bytes();

        // Should produce valid CBOR
        assert!(!cbor.is_empty());
        eprintln!("Redeemer CBOR: {} bytes", cbor.len());
        eprintln!("Hex: {}", hex::encode(cbor));
    }

    #[test]
    fn test_threshold_calculation() {
        assert_eq!(SignaturesNeeded::calculate_threshold(3), 2);
        assert_eq!(SignaturesNeeded::calculate_threshold(5), 4);
        assert_eq!(SignaturesNeeded::calculate_threshold(7), 5);
    }

    #[test]
    fn test_threshold_calculation_edge_cases() {
        // Single member (threshold = 1)
        assert_eq!(SignaturesNeeded::calculate_threshold(1), 1);

        // Two members (threshold = 2)
        assert_eq!(SignaturesNeeded::calculate_threshold(2), 2);

        // Large number of members
        assert_eq!(SignaturesNeeded::calculate_threshold(10), 7);
        assert_eq!(SignaturesNeeded::calculate_threshold(15), 10);
        assert_eq!(SignaturesNeeded::calculate_threshold(21), 14);
    }

    #[test]
    fn test_build_update_redeemer_single_member() {
        let members = vec![GovernanceMember {
            cardano_hash: [0x42; 28],
            sr25519_key: [0x99; 32],
        }];

        let redeemer = build_update_redeemer(&members).unwrap();
        let cbor = redeemer.data_bytes();

        assert!(!cbor.is_empty());
        eprintln!("Single member redeemer: {} bytes", cbor.len());
    }

    #[test]
    fn test_build_update_redeemer_multiple_members() {
        let members = vec![
            GovernanceMember {
                cardano_hash: [1u8; 28],
                sr25519_key: [2u8; 32],
            },
            GovernanceMember {
                cardano_hash: [3u8; 28],
                sr25519_key: [4u8; 32],
            },
            GovernanceMember {
                cardano_hash: [5u8; 28],
                sr25519_key: [6u8; 32],
            },
        ];

        let redeemer = build_update_redeemer(&members).unwrap();
        let cbor = redeemer.data_bytes();

        assert!(!cbor.is_empty());
        eprintln!("Three members redeemer: {} bytes", cbor.len());

        // Redeemer should grow with more members
        let single_member_redeemer = build_update_redeemer(&members[..1]).unwrap();
        assert!(cbor.len() > single_member_redeemer.data_bytes().len());
    }

    #[test]
    fn test_build_update_redeemer_deterministic() {
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

        let redeemer1 = build_update_redeemer(&members).unwrap();
        let redeemer2 = build_update_redeemer(&members).unwrap();

        assert_eq!(redeemer1.data_bytes(), redeemer2.data_bytes());
    }

    #[test]
    fn test_build_update_redeemer_different_members() {
        let members1 = vec![GovernanceMember {
            cardano_hash: [1u8; 28],
            sr25519_key: [2u8; 32],
        }];

        let members2 = vec![GovernanceMember {
            cardano_hash: [3u8; 28],
            sr25519_key: [4u8; 32],
        }];

        let redeemer1 = build_update_redeemer(&members1).unwrap();
        let redeemer2 = build_update_redeemer(&members2).unwrap();

        // Different members should produce different redeemers
        assert_ne!(redeemer1.data_bytes(), redeemer2.data_bytes());
    }

    #[test]
    fn test_signatures_needed_structure() {
        let sigs = SignaturesNeeded::new(5);

        assert_eq!(sigs.total_signers, 5);
        assert_eq!(sigs.calculated_threshold, 4);
        assert!(sigs.note.contains("2 * total_signers + 2"));
        assert!(sigs.note.contains("/ 3"));
    }

    #[test]
    fn test_rotation_args_lifetimes() {
        // Test that rotation args can be constructed with borrowed data
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

        let members = vec![GovernanceMember {
            cardano_hash: [0x42; 28],
            sr25519_key: [0x99; 32],
        }];

        let output_dir = std::path::Path::new("/tmp/test");

        let _args = CouncilRotationArgs {
            current_state: &state,
            new_members: &members,
            hayate_endpoint: "http://localhost:50051".to_string(),
            wallet_mnemonic: "test mnemonic",
            account: 0,
            output_dir,
            air_gap: true,
        };

        // Just testing compilation and lifetime handling
        assert!(true);
    }
}
