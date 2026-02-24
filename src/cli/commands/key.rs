use crate::application::{KeyDerivation, KeyGeneration};
use crate::cli::output::{print_key_output, OutputFormat};
use crate::crypto::{Ed25519, Sr25519};
use crate::domain::{KeyPurpose, KeyTypeId};
use crate::storage::{CardanoKeyFile, KeyReader};
use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum KeyCommands {
    /// Generate a new key
    Generate(GenerateArgs),
    /// Derive a key on-demand (no file output)
    Derive(DeriveArgs),
    /// Inspect an existing key file
    Inspect(InspectArgs),
    /// Batch generate multiple keys
    Batch(BatchArgs),
}

#[derive(Args)]
pub struct GenerateArgs {
    /// Key purpose (governance, payment, finality)
    #[arg(long)]
    pub purpose: String,

    /// Key index (optional, defaults to none for governance)
    #[arg(long)]
    pub index: Option<u32>,

    /// Mnemonic phrase (or file path)
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// Mnemonic file path (supports GPG)
    #[arg(long)]
    pub mnemonic_file: Option<PathBuf>,

    /// Custom derivation path (overrides standard path)
    #[arg(long)]
    pub derivation: Option<String>,

    /// Key type (sr25519, ed25519)
    #[arg(long)]
    pub key_type: Option<String>,

    /// Output directory for .skey/.vkey files
    #[arg(long, default_value = ".")]
    pub output_dir: PathBuf,

    /// Base filename (default: purpose-index)
    #[arg(long)]
    pub filename: Option<String>,
}

#[derive(Args)]
pub struct DeriveArgs {
    /// Mnemonic phrase (or file path)
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// Mnemonic file path (supports GPG)
    #[arg(long)]
    pub mnemonic_file: Option<PathBuf>,

    /// Derivation path (e.g., //midnight//governance//0)
    #[arg(long)]
    pub derivation: String,

    /// Key type (sr25519, ed25519)
    #[arg(long)]
    pub key_type: String,

    /// Key purpose
    #[arg(long, default_value = "governance")]
    pub purpose: String,

    /// Output format (json, text)
    #[arg(long, default_value = "json")]
    pub format: String,

    /// Network format for SS58 address (substrate, westend)
    #[arg(long, default_value = "substrate")]
    pub network: String,

    /// Show secret key
    #[arg(long)]
    pub show_secret: bool,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Path to .skey or .vkey file
    #[arg(long)]
    pub key_file: PathBuf,

    /// Output format (json, text)
    #[arg(long, default_value = "json")]
    pub format: String,
}

#[derive(Args)]
pub struct BatchArgs {
    /// Mnemonic phrase (or file path)
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// Mnemonic file path (supports GPG)
    #[arg(long)]
    pub mnemonic_file: Option<PathBuf>,

    /// Purposes (comma-separated: governance,payment,finality)
    #[arg(long)]
    pub purposes: String,

    /// Indices (comma-separated: 0,1,2)
    #[arg(long)]
    pub indices: String,

    /// Output directory
    #[arg(long, default_value = ".")]
    pub output_dir: PathBuf,
}

pub fn handle_key_command(cmd: KeyCommands) -> Result<()> {
    match cmd {
        KeyCommands::Generate(args) => handle_generate(args),
        KeyCommands::Derive(args) => handle_derive(args),
        KeyCommands::Inspect(args) => handle_inspect(args),
        KeyCommands::Batch(args) => handle_batch(args),
    }
}

fn handle_generate(args: GenerateArgs) -> Result<()> {
    let purpose = KeyPurpose::from_str(&args.purpose)?;

    // Get mnemonic
    let mnemonic = if let Some(ref file) = args.mnemonic_file {
        KeyReader::read_mnemonic_from_file(file)?
    } else if let Some(ref phrase) = args.mnemonic {
        KeyReader::read_mnemonic(phrase)?
    } else {
        // Generate random
        let (key, mnemonic) = KeyGeneration::generate_with_random_mnemonic(purpose, args.index)?;
        eprintln!("Generated new mnemonic (keep this safe!):");
        eprintln!("{}", secrecy::ExposeSecret::expose_secret(&mnemonic));
        eprintln!();

        let (skey_path, vkey_path) = crate::storage::KeyWriter::write_cardano_key_pair(
            &key,
            &args.output_dir,
            &args.filename.unwrap_or_else(|| {
                crate::storage::KeyWriter::default_filename(&key, args.index)
            }),
        )?;

        println!("✓ Keys written:");
        println!("  Signing key: {}", skey_path.display());
        println!("  Verification key: {}", vkey_path.display());
        return Ok(());
    };

    let mnemonic_str = secrecy::ExposeSecret::expose_secret(&mnemonic);

    // Generate key
    let key = if let Some(ref custom_path) = args.derivation {
        let key_type = if let Some(ref kt) = args.key_type {
            KeyTypeId::from_str(kt)?
        } else {
            purpose.default_key_type()
        };

        KeyGeneration::generate_with_custom_derivation(
            mnemonic_str,
            key_type,
            purpose,
            custom_path,
        )?
    } else {
        KeyGeneration::generate_from_mnemonic(mnemonic_str, purpose, args.index)?
    };

    // Write to files
    let (skey_path, vkey_path) = crate::storage::KeyWriter::write_cardano_key_pair(
        &key,
        &args.output_dir,
        &args.filename.unwrap_or_else(|| {
            crate::storage::KeyWriter::default_filename(&key, args.index)
        }),
    )?;

    println!("✓ Keys written:");
    println!("  Signing key: {}", skey_path.display());
    println!("  Verification key: {}", vkey_path.display());

    Ok(())
}

fn handle_derive(args: DeriveArgs) -> Result<()> {
    let key_type = KeyTypeId::from_str(&args.key_type)?;
    let purpose = KeyPurpose::from_str(&args.purpose)?;
    let format = OutputFormat::from_str(&args.format)
        .map_err(|e| anyhow::anyhow!(e))?;

    let mut key = if let Some(ref file) = args.mnemonic_file {
        KeyDerivation::derive_from_mnemonic_file(file, &args.derivation, key_type, purpose)?
    } else if let Some(ref phrase) = args.mnemonic {
        let mnemonic = KeyReader::read_mnemonic(phrase)?;
        KeyDerivation::derive_from_mnemonic(
            secrecy::ExposeSecret::expose_secret(&mnemonic),
            &args.derivation,
            key_type,
            purpose,
        )?
    } else {
        return Err(anyhow::anyhow!(
            "Must provide either --mnemonic or --mnemonic-file"
        ));
    };

    // Re-encode SS58 address with custom network if needed
    if args.network != "substrate" {
        let new_address = match key_type {
            KeyTypeId::Sr25519 => {
                use sp_core::sr25519::Public;
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&key.public_key);
                let public = Public::from_raw(bytes);
                Sr25519::to_ss58_address_with_network(&public, &args.network)
                    .map_err(|e| anyhow::anyhow!(e))?
            },
            KeyTypeId::Ed25519 => {
                use sp_core::ed25519::Public;
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&key.public_key);
                let public = Public::from_raw(bytes);
                Ed25519::to_ss58_address_with_network(&public, &args.network)
                    .map_err(|e| anyhow::anyhow!(e))?
            },
            KeyTypeId::Secp256k1 => {
                // Secp256k1 payment keys don't have SS58 addresses
                // Just return the hex-encoded public key
                format!("0x{}", hex::encode(&key.public_key))
            },
        };
        key.metadata.ss58_address = Some(new_address);
    }

    print_key_output(&key, format);

    if args.show_secret && key.has_secret() {
        eprintln!("\n⚠️  Secret key: {}",
            secrecy::ExposeSecret::expose_secret(key.secret_key.as_ref().unwrap()));
    }

    Ok(())
}

fn handle_inspect(args: InspectArgs) -> Result<()> {
    let card_file = CardanoKeyFile::read_from_file(&args.key_file)?;
    let format = OutputFormat::from_str(&args.format)
        .map_err(|e| anyhow::anyhow!(e))?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&card_file)?);
        }
        OutputFormat::Text => {
            println!("Type: {}", card_file.key_type);
            println!("Description: {}", card_file.description);
            println!("Is signing key: {}", card_file.is_signing_key());
        }
    }

    Ok(())
}

fn handle_batch(args: BatchArgs) -> Result<()> {
    // Get mnemonic
    let mnemonic = if let Some(ref file) = args.mnemonic_file {
        KeyReader::read_mnemonic_from_file(file)?
    } else if let Some(ref phrase) = args.mnemonic {
        KeyReader::read_mnemonic(phrase)?
    } else {
        return Err(anyhow::anyhow!(
            "Must provide either --mnemonic or --mnemonic-file"
        ));
    };

    let mnemonic_str = secrecy::ExposeSecret::expose_secret(&mnemonic);

    // Parse purposes
    let purposes: Result<Vec<KeyPurpose>> = args
        .purposes
        .split(',')
        .map(|s| KeyPurpose::from_str(s.trim()).map_err(|e| anyhow::anyhow!(e)))
        .collect();
    let purposes = purposes?;

    // Parse indices
    let indices: Result<Vec<u32>, _> = args
        .indices
        .split(',')
        .map(|s| s.trim().parse::<u32>())
        .collect();
    let indices = indices?;

    // Generate batch
    let results = KeyGeneration::batch_generate(
        mnemonic_str,
        &purposes,
        &indices,
        &args.output_dir,
    )?;

    println!("✓ Generated {} key pairs:", results.len());
    for (purpose, index, skey_path, vkey_path) in results {
        println!(
            "  {} ({}): {}, {}",
            purpose.as_str(),
            index,
            skey_path.display(),
            vkey_path.display()
        );
    }

    Ok(())
}
