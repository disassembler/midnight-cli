use crate::application::WitnessCreation;
use crate::domain::KeyPurpose;
use crate::storage::KeyReader;
use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum WitnessCommands {
    /// Create a witness (signature) for a payload
    Create(CreateArgs),
    /// Verify a witness against a payload
    Verify(VerifyArgs),
}

#[derive(Args)]
pub struct CreateArgs {
    /// Path to payload file to sign
    #[arg(long)]
    pub payload: PathBuf,

    /// Path to .skey file
    #[arg(long)]
    pub key_file: Option<PathBuf>,

    /// Mnemonic phrase (for CLI input)
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// Mnemonic file path (supports .mnemonic, .mnemonic.gpg, or any GPG-encrypted file)
    #[arg(long)]
    pub mnemonic_file: Option<PathBuf>,

    /// Derivation path (optional - if not provided, will auto-construct from purpose and index)
    #[arg(long)]
    pub derivation_path: Option<String>,

    /// Key purpose (governance, payment, finality) - used with mnemonic for auto-derivation
    #[arg(long)]
    pub purpose: Option<String>,

    /// Key index - used with mnemonic for auto-derivation
    #[arg(long)]
    pub index: Option<u32>,

    /// Output file for witness
    #[arg(long)]
    pub output: PathBuf,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,

    /// Optional description for the witness
    #[arg(long)]
    pub description: Option<String>,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to witness file
    #[arg(long)]
    pub witness: PathBuf,

    /// Path to payload file
    #[arg(long)]
    pub payload: PathBuf,
}

pub fn handle_witness_command(cmd: WitnessCommands) -> Result<()> {
    match cmd {
        WitnessCommands::Create(args) => handle_create(args),
        WitnessCommands::Verify(args) => handle_verify(args),
    }
}

fn handle_create(args: CreateArgs) -> Result<()> {
    let witness = if let Some(ref key_file) = args.key_file {
        // Mode 1: Sign with key file
        // Extract purpose from key file type descriptor
        let cardano_file = KeyReader::read_cardano_key_file(key_file)?;
        let purpose = KeyReader::parse_key_purpose_from_descriptor(&cardano_file.key_type)?;

        WitnessCreation::create_from_key_file(
            &args.payload,
            key_file,
            purpose,
            args.yes,
            args.description,
        )?
    } else if args.mnemonic.is_some() || args.mnemonic_file.is_some() {
        // Mode 2: Sign with mnemonic (auto-derive or explicit path)

        // Determine derivation path and key type
        let (derivation_path, key_type, purpose) = if let Some(path) = args.derivation_path {
            // Explicit derivation path provided - need to also provide purpose
            let purpose_str = args.purpose.ok_or_else(|| {
                anyhow::anyhow!("--purpose required when using --derivation-path")
            })?;
            let purpose = KeyPurpose::from_str(&purpose_str)?;
            let key_type = purpose.default_key_type();
            (path, key_type, purpose)
        } else {
            // Auto-construct derivation path from purpose and index
            let purpose_str = args.purpose.ok_or_else(|| {
                anyhow::anyhow!("--purpose required when using mnemonic without --derivation-path")
            })?;
            let index = args.index.ok_or_else(|| {
                anyhow::anyhow!("--index required when using mnemonic without --derivation-path")
            })?;

            let purpose = KeyPurpose::from_str(&purpose_str)?;
            let key_type = purpose.default_key_type();
            let path = format!("//midnight//{}//{}",purpose_str.to_lowercase(), index);

            (path, key_type, purpose)
        };

        // Read mnemonic from file or CLI
        if let Some(ref file) = args.mnemonic_file {
            WitnessCreation::create_from_mnemonic_file(
                &args.payload,
                file,
                &derivation_path,
                key_type,
                purpose,
                args.yes,
                args.description,
            )?
        } else if let Some(ref phrase) = args.mnemonic {
            let mnemonic = KeyReader::read_mnemonic(phrase)?;
            WitnessCreation::create_from_mnemonic(
                &args.payload,
                secrecy::ExposeSecret::expose_secret(&mnemonic),
                &derivation_path,
                key_type,
                purpose,
                args.yes,
                args.description,
            )?
        } else {
            unreachable!()
        }
    } else {
        return Err(anyhow::anyhow!(
            "Must provide either --key-file or mnemonic (--mnemonic/--mnemonic-file)"
        ));
    };

    // Write witness to file
    let witness_json = serde_json::to_string_pretty(&witness)?;
    std::fs::write(&args.output, witness_json)?;

    println!("✓ Witness created: {}", args.output.display());
    println!("  Payload hash: {}", witness.payload.hash);
    println!("  Signer: {}", witness.signature.signer.public_key);

    Ok(())
}

fn handle_verify(args: VerifyArgs) -> Result<()> {
    let valid = WitnessCreation::verify_witness(&args.witness, &args.payload)?;

    if valid {
        println!("✓ Witness is VALID");
        println!("  Signature matches payload");
    } else {
        println!("✗ Witness is INVALID");
        println!("  Signature does not match payload");
        std::process::exit(1);
    }

    Ok(())
}
