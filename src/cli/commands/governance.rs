use crate::application::KeyGeneration;
use crate::crypto::Sr25519;
use crate::domain::KeyPurpose;
use crate::storage::KeyReader;
use anyhow::Result;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum GovernanceCommands {
    /// Generate governance key for TA/Council member
    Generate(GovernanceGenerateArgs),
}

#[derive(Args)]
pub struct GovernanceGenerateArgs {
    /// Mnemonic phrase (or file path)
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// Mnemonic file path (supports GPG)
    #[arg(long)]
    pub mnemonic_file: Option<PathBuf>,

    /// Output file for public key JSON
    #[arg(long, default_value = "governance-key.json")]
    pub output: PathBuf,

    /// Also write .skey/.vkey files
    #[arg(long)]
    pub write_key_files: bool,

    /// Output directory for .skey/.vkey files (if --write-key-files)
    #[arg(long, default_value = ".")]
    pub key_files_dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GovernanceKey {
    pub key_type: String,
    pub public_key_hex: String,
    pub ss58_address: String,
}

pub fn handle_governance_command(cmd: GovernanceCommands) -> Result<()> {
    match cmd {
        GovernanceCommands::Generate(args) => handle_governance_generate(args),
    }
}

fn handle_governance_generate(args: GovernanceGenerateArgs) -> Result<()> {
    // Get mnemonic
    let mnemonic = if let Some(ref file) = args.mnemonic_file {
        KeyReader::read_mnemonic_from_file(file)?
    } else if let Some(ref phrase) = args.mnemonic {
        KeyReader::read_mnemonic(phrase)?
    } else {
        // Generate random mnemonic
        let (_, mnemonic) = KeyGeneration::generate_with_random_mnemonic(KeyPurpose::Governance, None)?;
        eprintln!("Generated new mnemonic (keep this safe!):");
        eprintln!("{}", secrecy::ExposeSecret::expose_secret(&mnemonic));
        eprintln!();
        mnemonic
    };

    let mnemonic_str = secrecy::ExposeSecret::expose_secret(&mnemonic);

    // Generate governance key (sr25519)
    let governance_suri = format!("{}//midnight//governance", mnemonic_str);
    let governance_pair = Sr25519::from_suri(&governance_suri)?;
    let governance_public = Sr25519::public_key(&governance_pair);
    let governance_public_bytes: &[u8] = governance_public.as_ref();

    // Create public key JSON
    let governance_key = GovernanceKey {
        key_type: "sr25519".to_string(),
        public_key_hex: hex::encode(governance_public_bytes),
        ss58_address: Sr25519::to_ss58_address(&governance_public),
    };

    // Write JSON file
    let json = serde_json::to_string_pretty(&governance_key)?;
    std::fs::write(&args.output, json)?;

    println!("✓ Governance key generated:");
    println!("  Type:       {}", governance_key.key_type);
    println!("  Public key: {}", governance_key.public_key_hex);
    println!("  SS58:       {}", governance_key.ss58_address);
    println!();
    println!("✓ Public key written to: {}", args.output.display());

    // Optionally write key files
    if args.write_key_files {
        let governance_key_material = Sr25519::to_key_material(
            &governance_pair,
            KeyPurpose::Governance,
            Some("//midnight//governance".to_string()),
        );
        let (skey, vkey) = crate::storage::KeyWriter::write_cardano_key_pair(
            &governance_key_material,
            &args.key_files_dir,
            "governance",
        )?;

        println!();
        println!("✓ Key files written:");
        println!("  Signing key:      {}", skey.display());
        println!("  Verification key: {}", vkey.display());
    }

    Ok(())
}
