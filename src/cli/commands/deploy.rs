// SPDX-License-Identifier: Apache-2.0

//! Deploy command for governance contracts
//!
//! This module provides CLI commands for deploying Council, TA, and FedOps
//! governance contracts with NFT minting and initial datum setup.

use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum DeployCommands {
    /// Deploy Council governance contract
    CouncilGovernance(DeployGovernanceArgs),
    /// Deploy Technical Advisory governance contract
    TaGovernance(DeployGovernanceArgs),
    /// Deploy Federated Operations governance contract
    FedopsGovernance(DeployGovernanceArgs),
}

#[derive(Args)]
pub struct DeployGovernanceArgs {
    /// Governance member JSON file (can be specified multiple times)
    #[arg(long = "member")]
    pub member_files: Vec<PathBuf>,

    /// Initial UTxO reference for one-shot NFT minting (tx_hash#index)
    #[arg(long)]
    pub initial_utxo_ref: String,

    /// Hayate gRPC endpoint
    #[arg(long, default_value = "http://localhost:50051")]
    pub hayate_endpoint: String,

    /// Wallet mnemonic file for fees/collateral (supports GPG)
    #[arg(long)]
    pub mnemonic_file: PathBuf,

    /// Wallet account index
    #[arg(long, default_value = "0")]
    pub account: u32,

    /// Output directory for state files
    #[arg(long, default_value = "./deployment-state")]
    pub output_dir: PathBuf,

    /// Air-gap mode: create unsigned transaction instead of submitting
    #[arg(long)]
    pub air_gap: bool,
}

pub async fn handle_deploy_command(cmd: DeployCommands) -> Result<()> {
    match cmd {
        DeployCommands::CouncilGovernance(args) => handle_deploy_council(args).await,
        DeployCommands::TaGovernance(args) => handle_deploy_ta(args).await,
        DeployCommands::FedopsGovernance(args) => handle_deploy_fedops(args).await,
    }
}

async fn handle_deploy_council(args: DeployGovernanceArgs) -> Result<()> {
    use crate::application::{deploy_contract, DeploymentArgs, GovernanceContractType};
    use crate::storage::KeyReader;
    use hayate::wallet::plutus::GovernanceMember;
    use serde::{Deserialize, Serialize};

    eprintln!("Deploying Council governance contract...\n");

    // Load member JSON files
    eprintln!("Loading member files...");
    let mut members = Vec::new();

    #[derive(Deserialize, Serialize)]
    struct GovernanceKey {
        cardano_key_hash: String,
        sr25519_public_key: String,
        #[allow(dead_code)]
        ss58_address: String,
    }

    for member_file in &args.member_files {
        let json = std::fs::read_to_string(member_file)?;
        let key: GovernanceKey = serde_json::from_str(&json)?;

        let cardano_bytes = hex::decode(&key.cardano_key_hash)?;
        let sr25519_bytes = hex::decode(key.sr25519_public_key.trim_start_matches("0x"))?;

        if cardano_bytes.len() != 28 {
            anyhow::bail!("Invalid cardano_key_hash length in {}: expected 28 bytes", member_file.display());
        }
        if sr25519_bytes.len() != 32 {
            anyhow::bail!("Invalid sr25519_public_key length in {}: expected 32 bytes", member_file.display());
        }

        let mut cardano_hash = [0u8; 28];
        let mut sr25519_key = [0u8; 32];
        cardano_hash.copy_from_slice(&cardano_bytes);
        sr25519_key.copy_from_slice(&sr25519_bytes);

        members.push(GovernanceMember {
            cardano_hash,
            sr25519_key,
        });

        eprintln!("  ✓ Loaded: {}", member_file.display());
    }

    // Load wallet mnemonic
    let wallet_mnemonic = KeyReader::read_mnemonic_from_file(&args.mnemonic_file)?;
    let wallet_mnemonic_str = secrecy::ExposeSecret::expose_secret(&wallet_mnemonic);

    // Call deploy_contract
    let deploy_args = DeploymentArgs {
        contract_type: GovernanceContractType::Council,
        members: &members,
        nft_policy_id: None,
        initial_utxo_ref: args.initial_utxo_ref.clone(),
        hayate_endpoint: args.hayate_endpoint.clone(),
        wallet_mnemonic: wallet_mnemonic_str,
        account: args.account,
        output_dir: &args.output_dir,
        air_gap: args.air_gap,
    };

    let result = deploy_contract(deploy_args).await?;

    eprintln!("\n✅ Deployment complete!");
    eprintln!("  Contract address: {}", result.contract_address);
    eprintln!("  State file: {}", result.state_file.display());

    Ok(())
}

async fn handle_deploy_ta(_args: DeployGovernanceArgs) -> Result<()> {
    eprintln!("TA governance deployment");
    eprintln!();
    eprintln!("⚠ This feature is under development.");
    eprintln!();
    eprintln!("Implementation will be similar to Council deployment but using");
    eprintln!("TECH_AUTH_GOVERNANCE_CBOR contract instead.");

    anyhow::bail!("TA deployment not yet implemented")
}

async fn handle_deploy_fedops(_args: DeployGovernanceArgs) -> Result<()> {
    eprintln!("FedOps governance deployment");
    eprintln!();
    eprintln!("⚠ This feature is under development.");
    eprintln!();
    eprintln!("Implementation will use FEDERATED_OPS_GOVERNANCE_CBOR contract.");
    eprintln!();
    eprintln!("Note: FedOps deployment is similar to Council/TA but the rotation");
    eprintln!("      logic is more complex (requires both Council AND TA approval).");

    anyhow::bail!("FedOps deployment not yet implemented")
}
