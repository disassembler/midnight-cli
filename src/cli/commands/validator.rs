use crate::application::KeyGeneration;
use crate::crypto::{Ed25519, Sr25519};
use crate::domain::KeyPurpose;
use crate::storage::KeyReader;
use anyhow::Result;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum ValidatorCommands {
    /// Generate validator keys for midnight-node operator
    Generate(ValidatorGenerateArgs),
}

#[derive(Args)]
pub struct ValidatorGenerateArgs {
    /// Mnemonic phrase (or file path)
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// Mnemonic file path (supports GPG)
    #[arg(long)]
    pub mnemonic_file: Option<PathBuf>,

    /// Output file for public keys JSON
    #[arg(long, default_value = "validator-keys.json")]
    pub output: PathBuf,

    /// Also write individual .skey/.vkey files
    #[arg(long)]
    pub write_key_files: bool,

    /// Output directory for .skey/.vkey files (if --write-key-files)
    #[arg(long, default_value = ".")]
    pub key_files_dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorKeys {
    /// Node key (ed25519) - LibP2P peer identity
    pub node_key: KeyData,
    /// Aura key (sr25519) - Block production/consensus
    pub aura_key: KeyData,
    /// Grandpa key (ed25519) - Finality gadget
    pub grandpa_key: KeyData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyData {
    pub key_type: String,
    pub public_key_hex: String,
    pub ss58_address: Option<String>,
}

pub fn handle_validator_command(cmd: ValidatorCommands) -> Result<()> {
    match cmd {
        ValidatorCommands::Generate(args) => handle_validator_generate(args),
    }
}

fn handle_validator_generate(args: ValidatorGenerateArgs) -> Result<()> {
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

    // Generate Node key (ed25519) - LibP2P peer identity
    let node_suri = format!("{}//midnight//node", mnemonic_str);
    let node_pair = Ed25519::from_suri(&node_suri)?;
    let node_public = Ed25519::public_key(&node_pair);
    let node_public_bytes: &[u8] = node_public.as_ref();

    // Generate Aura key (sr25519) - Block production
    let aura_suri = format!("{}//midnight//aura", mnemonic_str);
    let aura_pair = Sr25519::from_suri(&aura_suri)?;
    let aura_public = Sr25519::public_key(&aura_pair);
    let aura_public_bytes: &[u8] = aura_public.as_ref();

    // Generate Grandpa key (ed25519) - Finality gadget
    let grandpa_suri = format!("{}//midnight//grandpa", mnemonic_str);
    let grandpa_pair = Ed25519::from_suri(&grandpa_suri)?;
    let grandpa_public = Ed25519::public_key(&grandpa_pair);
    let grandpa_public_bytes: &[u8] = grandpa_public.as_ref();

    // Create public keys JSON
    let validator_keys = ValidatorKeys {
        node_key: KeyData {
            key_type: "ed25519".to_string(),
            public_key_hex: hex::encode(node_public_bytes),
            ss58_address: Some(Ed25519::to_ss58_address(&node_public)),
        },
        aura_key: KeyData {
            key_type: "sr25519".to_string(),
            public_key_hex: hex::encode(aura_public_bytes),
            ss58_address: Some(Sr25519::to_ss58_address(&aura_public)),
        },
        grandpa_key: KeyData {
            key_type: "ed25519".to_string(),
            public_key_hex: hex::encode(grandpa_public_bytes),
            ss58_address: Some(Ed25519::to_ss58_address(&grandpa_public)),
        },
    };

    // Write JSON file
    let json = serde_json::to_string_pretty(&validator_keys)?;
    std::fs::write(&args.output, json)?;

    println!("✓ Validator keys generated:");
    println!("  Node key (ed25519):    {}", validator_keys.node_key.public_key_hex);
    println!("  Aura key (sr25519):    {}", validator_keys.aura_key.public_key_hex);
    println!("  Grandpa key (ed25519): {}", validator_keys.grandpa_key.public_key_hex);
    println!();
    println!("✓ Public keys written to: {}", args.output.display());

    // Optionally write individual key files
    if args.write_key_files {
        // Write node key files
        let node_key_material = Ed25519::to_key_material(
            &node_pair,
            KeyPurpose::Governance,
            Some("//midnight//node".to_string()),
        );
        let (node_skey, node_vkey) = crate::storage::KeyWriter::write_cardano_key_pair(
            &node_key_material,
            &args.key_files_dir,
            "node",
        )?;

        // Write aura key files
        let aura_key_material = Sr25519::to_key_material(
            &aura_pair,
            KeyPurpose::Governance,
            Some("//midnight//aura".to_string()),
        );
        let (aura_skey, aura_vkey) = crate::storage::KeyWriter::write_cardano_key_pair(
            &aura_key_material,
            &args.key_files_dir,
            "aura",
        )?;

        // Write grandpa key files
        let grandpa_key_material = Ed25519::to_key_material(
            &grandpa_pair,
            KeyPurpose::Finality,
            Some("//midnight//grandpa".to_string()),
        );
        let (grandpa_skey, grandpa_vkey) = crate::storage::KeyWriter::write_cardano_key_pair(
            &grandpa_key_material,
            &args.key_files_dir,
            "grandpa",
        )?;

        println!();
        println!("✓ Key files written:");
        println!("  Node:    {}, {}", node_skey.display(), node_vkey.display());
        println!("  Aura:    {}, {}", aura_skey.display(), aura_vkey.display());
        println!("  Grandpa: {}, {}", grandpa_skey.display(), grandpa_vkey.display());
    }

    Ok(())
}
