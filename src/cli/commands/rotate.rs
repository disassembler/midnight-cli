// SPDX-License-Identifier: Apache-2.0

//! Rotate command for governance contracts
//!
//! This module provides CLI commands for rotating Council, TA, and FedOps
//! governance members with air-gap M-of-N signing support.

use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum RotateCommands {
    /// Rotate Council governance members
    Council(RotateArgs),
    /// Rotate Technical Advisory members
    Ta(RotateArgs),
    /// Rotate Federated Operations validator keys (requires Council + TA approval)
    Fedops(RotateFedopsArgs),
}

#[derive(Args)]
pub struct RotateArgs {
    /// State file from deployment
    #[arg(long)]
    pub state_file: PathBuf,

    /// New member JSON file (can be specified multiple times)
    #[arg(long = "member")]
    pub new_member_files: Vec<PathBuf>,

    /// Hayate gRPC endpoint
    #[arg(long, default_value = "http://localhost:50051")]
    pub hayate_endpoint: String,

    /// Wallet mnemonic file for fees/collateral (supports GPG)
    #[arg(long)]
    pub mnemonic_file: PathBuf,

    /// Wallet account index
    #[arg(long, default_value = "0")]
    pub account: u32,

    /// Output directory for transaction files
    #[arg(long, default_value = "./rotation")]
    pub output_dir: PathBuf,

    /// Air-gap mode: create unsigned transaction + metadata instead of submitting
    #[arg(long)]
    pub air_gap: bool,
}

#[derive(Args)]
pub struct RotateFedopsArgs {
    /// FedOps state file
    #[arg(long)]
    pub fedops_state_file: PathBuf,

    /// Council state file (required for approval)
    #[arg(long)]
    pub council_state_file: PathBuf,

    /// TA state file (required for approval)
    #[arg(long)]
    pub ta_state_file: PathBuf,

    /// Validator keys JSON file (can be specified multiple times)
    #[arg(long = "validator")]
    pub new_validator_keys: Vec<PathBuf>,

    /// Hayate gRPC endpoint
    #[arg(long, default_value = "http://localhost:50051")]
    pub hayate_endpoint: String,

    /// Wallet mnemonic file for fees/collateral (supports GPG)
    #[arg(long)]
    pub mnemonic_file: PathBuf,

    /// Wallet account index
    #[arg(long, default_value = "0")]
    pub account: u32,

    /// Output directory for transaction files
    #[arg(long, default_value = "./rotation")]
    pub output_dir: PathBuf,

    /// Air-gap mode: create unsigned transaction + metadata instead of submitting
    #[arg(long)]
    pub air_gap: bool,
}

pub async fn handle_rotate_command(cmd: RotateCommands) -> Result<()> {
    match cmd {
        RotateCommands::Council(args) => handle_rotate_council(args).await,
        RotateCommands::Ta(args) => handle_rotate_ta(args).await,
        RotateCommands::Fedops(args) => handle_rotate_fedops(args).await,
    }
}

async fn handle_rotate_council(args: RotateArgs) -> Result<()> {
    use crate::application::{build_council_rotation_tx, CouncilRotationArgs, DeploymentState};
    use crate::storage::KeyReader;
    use hayate::wallet::plutus::GovernanceMember;
    use serde::Deserialize;

    eprintln!("Council governance rotation\n");

    // Load deployment state
    eprintln!("Loading deployment state...");
    let state = DeploymentState::read_from_file(&args.state_file)?;
    eprintln!("  Current logic round: {}", state.logic_round);
    eprintln!("  Current members: {}", state.members.len());

    // Load new member files
    eprintln!("\nLoading new member files...");
    let mut new_members = Vec::new();

    #[derive(Deserialize)]
    struct GovernanceKey {
        cardano_key_hash: String,
        sr25519_public_key: String,
    }

    for member_file in &args.new_member_files {
        let json = std::fs::read_to_string(member_file)?;
        let key: GovernanceKey = serde_json::from_str(&json)?;

        let cardano_bytes = hex::decode(&key.cardano_key_hash)?;
        let sr25519_bytes = hex::decode(key.sr25519_public_key.trim_start_matches("0x"))?;

        if cardano_bytes.len() != 28 || sr25519_bytes.len() != 32 {
            anyhow::bail!("Invalid key lengths in {}", member_file.display());
        }

        let mut cardano_hash = [0u8; 28];
        let mut sr25519_key = [0u8; 32];
        cardano_hash.copy_from_slice(&cardano_bytes);
        sr25519_key.copy_from_slice(&sr25519_bytes);

        new_members.push(GovernanceMember {
            cardano_hash,
            sr25519_key,
        });

        eprintln!("  ✓ Loaded: {}", member_file.display());
    }

    // Load wallet mnemonic
    let wallet_mnemonic = KeyReader::read_mnemonic_from_file(&args.mnemonic_file)?;
    let wallet_mnemonic_str = secrecy::ExposeSecret::expose_secret(&wallet_mnemonic);

    // Build rotation transaction
    let rotation_args = CouncilRotationArgs {
        current_state: &state,
        new_members: &new_members,
        hayate_endpoint: args.hayate_endpoint.clone(),
        wallet_mnemonic: wallet_mnemonic_str,
        account: args.account,
        output_dir: &args.output_dir,
        air_gap: args.air_gap,
    };

    let result = build_council_rotation_tx(rotation_args).await?;

    if let (Some(tx_body), Some(metadata)) = (result.tx_body_file, result.metadata_file) {
        eprintln!("\n✅ Air-gap files created successfully!");
        eprintln!("  TX body: {}", tx_body.display());
        eprintln!("  Metadata: {}", metadata.display());
    }

    Ok(())
}

async fn handle_rotate_ta(_args: RotateArgs) -> Result<()> {
    eprintln!("TA governance rotation");
    eprintln!();
    eprintln!("⚠ This feature is under development.");
    eprintln!();
    eprintln!("Implementation will be similar to Council rotation but using");
    eprintln!("build_ta_rotation_tx() and TA state file.");

    anyhow::bail!("TA rotation not yet implemented")
}

async fn handle_rotate_fedops(_args: RotateFedopsArgs) -> Result<()> {
    eprintln!("FedOps governance rotation");
    eprintln!();
    eprintln!("⚠ This feature is under development.");
    eprintln!();
    eprintln!("FedOps rotation is MORE COMPLEX than Council/TA:");
    eprintln!();
    eprintln!("Transaction structure:");
    eprintln!("  INPUTS:  FedOps UTxO + Council UTxO + TA UTxO (3 NFTs)");
    eprintln!("  OUTPUTS: FedOps UTxO + Council UTxO + TA UTxO (3 NFTs returned)");
    eprintln!("  DATUMS:  FedOps datum CHANGES, Council/TA datums UNCHANGED");
    eprintln!("  LOGIC:   ALL 3 logic_rounds increment (anti-replay)");
    eprintln!();
    eprintln!("Required signatures:");
    eprintln!("  - 2/3 from Council members");
    eprintln!("  - 2/3 from TA members");
    eprintln!("  - Signers may overlap if in both bodies");
    eprintln!();
    eprintln!("Example usage:");
    eprintln!("  midnight-cli rotate fedops \\");
    eprintln!("    --fedops-state-file fedops-governance.state.json \\");
    eprintln!("    --council-state-file council-governance.state.json \\");
    eprintln!("    --ta-state-file ta-governance.state.json \\");
    eprintln!("    --validator fedops-validator-1.json \\");
    eprintln!("    --validator fedops-validator-2.json \\");
    eprintln!("    --validator fedops-validator-3.json \\");
    eprintln!("    --hayate-endpoint http://localhost:50051 \\");
    eprintln!("    --mnemonic-file wallet.mnemonic \\");
    eprintln!("    --output-dir ./rotation \\");
    eprintln!("    --air-gap");

    anyhow::bail!("FedOps rotation not yet implemented - see above for planned implementation")
}
