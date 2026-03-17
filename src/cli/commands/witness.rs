use crate::application::WitnessCreation;
use crate::domain::KeyPurpose;
use crate::storage::KeyReader;
use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Subcommand)]
pub enum WitnessCommands {
    /// Create a witness (signature) for a payload
    Create(CreateArgs),
    /// Create a signed extrinsic from transaction metadata
    CreateExtrinsic(CreateExtrinsicArgs),
    /// Verify a witness against a payload
    Verify(VerifyArgs),
    /// Create a Cardano witness for an unsigned transaction body (air-gap signing)
    CreateCardano(CreateCardanoArgs),
    /// Assemble multiple Cardano witnesses into a signed transaction
    Assemble(AssembleArgs),
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
pub struct CreateExtrinsicArgs {
    /// Path to payload file to sign
    #[arg(long)]
    pub payload: PathBuf,

    /// Path to transaction metadata JSON file
    #[arg(long)]
    pub tx_metadata: PathBuf,

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

    /// Output file for signed extrinsic hex
    #[arg(long)]
    pub output: PathBuf,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
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

#[derive(Args)]
pub struct CreateCardanoArgs {
    /// Path to unsigned transaction body file (.txbody)
    #[arg(long)]
    pub tx_body_file: PathBuf,

    /// Path to transaction metadata file (.metadata)
    #[arg(long)]
    pub metadata_file: PathBuf,

    /// Mnemonic file path (supports .mnemonic, .mnemonic.gpg, or any GPG-encrypted file)
    #[arg(long)]
    pub mnemonic_file: PathBuf,

    /// Cardano account index
    #[arg(long, default_value = "0")]
    pub account: u32,

    /// Output file for witness (.witness)
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct AssembleArgs {
    /// Path to unsigned transaction body file (.txbody)
    #[arg(long)]
    pub tx_body_file: PathBuf,

    /// Path to transaction metadata file (.metadata)
    #[arg(long)]
    pub metadata_file: PathBuf,

    /// Comma-separated list of witness files
    #[arg(long, value_delimiter = ',')]
    pub witness_files: Vec<PathBuf>,

    /// Output file for signed transaction (.tx)
    #[arg(long)]
    pub output: PathBuf,

    /// Validate that threshold is met (fail if insufficient signatures)
    #[arg(long)]
    pub validate_threshold: bool,
}

pub fn handle_witness_command(cmd: WitnessCommands) -> Result<()> {
    match cmd {
        WitnessCommands::Create(args) => handle_create(args),
        WitnessCommands::CreateExtrinsic(args) => handle_create_extrinsic(args),
        WitnessCommands::Verify(args) => handle_verify(args),
        WitnessCommands::CreateCardano(args) => handle_create_cardano(args),
        WitnessCommands::Assemble(args) => handle_assemble(args),
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
            // Auto-construct derivation path from purpose and optional index
            let purpose_str = args.purpose.ok_or_else(|| {
                anyhow::anyhow!("--purpose required when using mnemonic without --derivation-path")
            })?;

            let purpose = KeyPurpose::from_str(&purpose_str)?;
            let key_type = purpose.default_key_type();

            // Construct path based on purpose:
            // - Governance/Finality: //midnight//{purpose} (no index - one per wallet)
            // - Payment: //midnight//payment//{index} (index required - multiple per wallet)
            let path = match purpose {
                KeyPurpose::Governance | KeyPurpose::Finality => {
                    if args.index.is_some() {
                        return Err(anyhow::anyhow!(
                            "{} keys should not have an index (one per wallet)", purpose.as_str()
                        ));
                    }
                    format!("//midnight//{}", purpose_str.to_lowercase())
                }
                KeyPurpose::Payment => {
                    let index = args.index.ok_or_else(|| {
                        anyhow::anyhow!("Payment keys require --index (multiple per wallet)")
                    })?;
                    format!("//midnight//payment//{}", index)
                }
            };

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

fn handle_create_extrinsic(args: CreateExtrinsicArgs) -> Result<()> {
    // First, create the witness using similar logic to handle_create
    let (signature, public_key) = if let Some(ref key_file) = args.key_file {
        // Mode 1: Sign with key file
        let cardano_file = KeyReader::read_cardano_key_file(key_file)?;
        let purpose = KeyReader::parse_key_purpose_from_descriptor(&cardano_file.key_type)?;

        let witness = WitnessCreation::create_from_key_file(
            &args.payload,
            key_file,
            purpose,
            args.yes,
            None,
        )?;

        // Extract signature and public key from witness
        let sig_hex = witness.signature.value.strip_prefix("0x")
            .unwrap_or(&witness.signature.value);
        let signature = hex::decode(sig_hex)?;

        let pubkey_hex = witness.signature.signer.public_key.strip_prefix("0x")
            .unwrap_or(&witness.signature.signer.public_key);
        let public_key = hex::decode(pubkey_hex)?;

        (signature, public_key)
    } else if args.mnemonic.is_some() || args.mnemonic_file.is_some() {
        // Mode 2: Sign with mnemonic
        let (derivation_path, key_type, purpose) = if let Some(path) = args.derivation_path {
            let purpose_str = args.purpose.ok_or_else(|| {
                anyhow::anyhow!("--purpose required when using --derivation-path")
            })?;
            let purpose = KeyPurpose::from_str(&purpose_str)?;
            let key_type = purpose.default_key_type();
            (path, key_type, purpose)
        } else {
            let purpose_str = args.purpose.ok_or_else(|| {
                anyhow::anyhow!("--purpose required when using mnemonic without --derivation-path")
            })?;

            let purpose = KeyPurpose::from_str(&purpose_str)?;
            let key_type = purpose.default_key_type();

            let path = match purpose {
                KeyPurpose::Governance | KeyPurpose::Finality => {
                    if args.index.is_some() {
                        return Err(anyhow::anyhow!(
                            "{} keys should not have an index (one per wallet)", purpose.as_str()
                        ));
                    }
                    format!("//midnight//{}", purpose_str.to_lowercase())
                }
                KeyPurpose::Payment => {
                    let index = args.index.ok_or_else(|| {
                        anyhow::anyhow!("Payment keys require --index (multiple per wallet)")
                    })?;
                    format!("//midnight//payment//{}", index)
                }
            };

            (path, key_type, purpose)
        };

        let witness = if let Some(ref file) = args.mnemonic_file {
            WitnessCreation::create_from_mnemonic_file(
                &args.payload,
                file,
                &derivation_path,
                key_type,
                purpose,
                args.yes,
                None,
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
                None,
            )?
        } else {
            unreachable!()
        };

        // Extract signature and public key from witness
        let sig_hex = witness.signature.value.strip_prefix("0x")
            .unwrap_or(&witness.signature.value);
        let signature = hex::decode(sig_hex)?;

        let pubkey_hex = witness.signature.signer.public_key.strip_prefix("0x")
            .unwrap_or(&witness.signature.signer.public_key);
        let public_key = hex::decode(pubkey_hex)?;

        (signature, public_key)
    } else {
        return Err(anyhow::anyhow!(
            "Must provide either --key-file or mnemonic (--mnemonic/--mnemonic-file)"
        ));
    };

    // Construct the signed extrinsic
    let signed_extrinsic = WitnessCreation::construct_signed_extrinsic(
        &args.tx_metadata,
        &signature,
        &public_key,
    )?;

    // Write to output file
    std::fs::write(&args.output, &signed_extrinsic)?;

    println!("✓ Signed extrinsic created: {}", args.output.display());
    println!("  Extrinsic: {}...", &signed_extrinsic[..std::cmp::min(66, signed_extrinsic.len())]);

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

fn handle_create_cardano(args: CreateCardanoArgs) -> Result<()> {
    use crate::application::{create_cardano_witness};
    use crate::storage::{TextEnvelope, TransactionMetadata};

    eprintln!("Creating Cardano witness for air-gapped transaction...\n");

    // 1. Load transaction body
    eprintln!("Loading transaction body: {}", args.tx_body_file.display());
    let tx_body_envelope = TextEnvelope::read_from_file(&args.tx_body_file)?;

    if tx_body_envelope.envelope_type != "Unwitnessed Tx BabbageEra" {
        anyhow::bail!(
            "Invalid transaction body type: expected 'Unwitnessed Tx BabbageEra', got '{}'",
            tx_body_envelope.envelope_type
        );
    }

    // 2. Load metadata
    eprintln!("Loading metadata: {}", args.metadata_file.display());
    let metadata = TransactionMetadata::read_from_file(&args.metadata_file)?;

    eprintln!("\n━━━ Transaction Information ━━━");
    eprintln!("Type: {}", metadata.transaction_type);
    eprintln!("TX Hash: {}", metadata.tx_hash);
    eprintln!("\n━━━ Signature Requirements ━━━");
    eprintln!("Required signers: {}", metadata.required_signers.len());
    eprintln!(
        "Threshold: {}/{}",
        metadata.signatures_needed.calculated_threshold,
        metadata.signatures_needed.total_signers
    );
    eprintln!("\n━━━ Creating Witness ━━━");

    // 3. Create witness
    let witness_envelope = create_cardano_witness(
        &tx_body_envelope,
        &metadata,
        &args.mnemonic_file,
        args.account,
    )?;

    // 4. Write witness to file
    witness_envelope.write_to_file(&args.output)?;

    eprintln!("\n✓ Witness created: {}", args.output.display());
    eprintln!("\nNext steps:");
    eprintln!("1. Collect witnesses from other signers (need {}/{})",
        metadata.signatures_needed.calculated_threshold,
        metadata.signatures_needed.total_signers
    );
    eprintln!("2. Use 'witness assemble' to combine witnesses into signed transaction");

    Ok(())
}

fn handle_assemble(args: AssembleArgs) -> Result<()> {
    use crate::application::assemble_witnesses;
    use crate::storage::{TextEnvelope, TransactionMetadata};

    eprintln!("Assembling witnesses into signed transaction...\n");

    // 1. Load transaction body
    eprintln!("Loading transaction body: {}", args.tx_body_file.display());
    let tx_body_envelope = TextEnvelope::read_from_file(&args.tx_body_file)?;

    if tx_body_envelope.envelope_type != "Unwitnessed Tx BabbageEra" {
        anyhow::bail!(
            "Invalid transaction body type: expected 'Unwitnessed Tx BabbageEra', got '{}'",
            tx_body_envelope.envelope_type
        );
    }

    // 2. Load metadata
    eprintln!("Loading metadata: {}", args.metadata_file.display());
    let metadata = TransactionMetadata::read_from_file(&args.metadata_file)?;

    // 3. Load all witnesses
    eprintln!("\nLoading {} witness file(s):", args.witness_files.len());
    let mut witness_envelopes = Vec::new();
    for witness_file in &args.witness_files {
        eprintln!("  - {}", witness_file.display());
        let witness = TextEnvelope::read_from_file(witness_file)?;
        witness_envelopes.push(witness);
    }

    eprintln!("\n━━━ Transaction Information ━━━");
    eprintln!("Type: {}", metadata.transaction_type);
    eprintln!("TX Hash: {}", metadata.tx_hash);
    eprintln!("Threshold: {}/{}",
        metadata.signatures_needed.calculated_threshold,
        metadata.signatures_needed.total_signers
    );
    eprintln!("\n━━━ Assembling Witnesses ━━━");

    // 4. Assemble witnesses (this validates signatures and checks threshold)
    let signed_tx_envelope = assemble_witnesses(
        &tx_body_envelope,
        &metadata,
        &witness_envelopes,
    )?;

    // 5. Write signed transaction to file
    signed_tx_envelope.write_to_file(&args.output)?;

    eprintln!("\n✓ Signed transaction assembled: {}", args.output.display());
    eprintln!("\nNext steps:");
    eprintln!("Submit transaction:");
    eprintln!("  cardano-cli transaction submit --tx-file {} --testnet-magic 4", args.output.display());
    eprintln!("Or:");
    eprintln!("  midnight-cli tx submit --tx-file {}", args.output.display());

    Ok(())
}
