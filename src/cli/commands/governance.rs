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

    /// Cardano Ed25519 verification key file (.vkey)
    /// If not provided, will derive from mnemonic at 1852H/1815H/0H/0/0
    #[arg(long)]
    pub cardano_vkey: Option<PathBuf>,

    /// Derivation path for sr25519 key
    #[arg(long, default_value = "//midnight//governance")]
    pub derivation: String,

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
    /// Ed25519 verification key hash for Cardano operations (28 bytes hex)
    pub cardano_key_hash: String,
    /// Sr25519 public key for Midnight governance (32 bytes hex)
    pub sr25519_public_key: String,
    /// SS58 address of the sr25519 key (for reference)
    pub ss58_address: String,
}

pub fn handle_governance_command(cmd: GovernanceCommands) -> Result<()> {
    match cmd {
        GovernanceCommands::Generate(args) => handle_governance_generate(args),
    }
}

fn handle_governance_generate(args: GovernanceGenerateArgs) -> Result<()> {
    use pallas_crypto::hash::Hasher;

    // 1. Get mnemonic first (needed for both Cardano and Midnight keys if cardano_vkey not provided)
    eprintln!("🔑 Loading mnemonic...");
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

    // 2. Get Cardano Ed25519 public key and calculate key hash
    let (_cardano_pubkey_bytes, cardano_key_hash) = if let Some(ref vkey_path) = args.cardano_vkey {
        // Read from provided .vkey file
        eprintln!("📖 Reading Cardano verification key from file...");
        let cardano_vkey = crate::storage::CardanoKeyFile::read_from_file(vkey_path)?;
        let cardano_pubkey_bytes = cardano_vkey.decode_key_bytes()?;

        if cardano_pubkey_bytes.len() != 32 {
            anyhow::bail!(
                "Invalid Cardano Ed25519 public key length: expected 32 bytes, got {}",
                cardano_pubkey_bytes.len()
            );
        }

        // Calculate key hash: BLAKE2b-224 of public key
        let hash: pallas_crypto::hash::Hash<28> = Hasher::<224>::hash(&cardano_pubkey_bytes);
        let cardano_key_hash = hex::encode(hash.as_ref());

        eprintln!("  Cardano pubkey: {}", hex::encode(&cardano_pubkey_bytes));
        eprintln!("  Key hash:       {}", cardano_key_hash);
        eprintln!();

        (cardano_pubkey_bytes, cardano_key_hash)
    } else {
        // Derive from mnemonic at standard Cardano payment key path: 1852H/1815H/0H/0/0
        eprintln!("📖 Deriving Cardano key from mnemonic at 1852H/1815H/0H/0/0...");

        // Use hayate to derive Cardano payment key
        let wallet = hayate::wallet::Wallet::from_mnemonic_str(
            mnemonic_str,
            hayate::wallet::Network::Testnet,  // Network doesn't matter for key derivation
            0,  // account = 0
        ).map_err(|e| anyhow::anyhow!("Failed to create Cardano wallet: {}", e))?;

        // Get the public key bytes for address index 0 (path: 1852H/1815H/0H/0/0)
        let payment_key = wallet.payment_key(0)
            .map_err(|e| anyhow::anyhow!("Failed to derive Cardano payment key: {}", e))?;
        let cardano_pubkey = payment_key.public();
        let cardano_pubkey_bytes = cardano_pubkey.as_ref();

        // Calculate key hash: BLAKE2b-224 of public key
        let hash: pallas_crypto::hash::Hash<28> = Hasher::<224>::hash(cardano_pubkey_bytes);
        let cardano_key_hash = hex::encode(hash.as_ref());

        eprintln!("  Derivation path: 1852H/1815H/0H/0/0");
        eprintln!("  Cardano pubkey:  {}", hex::encode(&cardano_pubkey_bytes));
        eprintln!("  Key hash:        {}", cardano_key_hash);
        eprintln!();

        (cardano_pubkey_bytes.to_vec(), cardano_key_hash)
    };

    // 3. Generate Midnight governance key (sr25519) with custom derivation
    let governance_suri = format!("{}{}", mnemonic_str, args.derivation);
    let governance_pair = Sr25519::from_suri(&governance_suri)?;
    let governance_public = Sr25519::public_key(&governance_pair);
    let governance_public_bytes: &[u8] = governance_public.as_ref();

    eprintln!("  Derivation:     {}", args.derivation);
    eprintln!("  Sr25519 pubkey: {}", hex::encode(governance_public_bytes));
    eprintln!("  SS58 address:   {}", Sr25519::to_ss58_address(&governance_public));
    eprintln!();

    // 4. Create governance member JSON for contract deployment
    let governance_key = GovernanceKey {
        cardano_key_hash,
        sr25519_public_key: hex::encode(governance_public_bytes),
        ss58_address: Sr25519::to_ss58_address(&governance_public),
    };

    // 5. Write JSON file
    let json = serde_json::to_string_pretty(&governance_key)?;
    std::fs::write(&args.output, json)?;

    println!("✅ Governance member file generated!");
    println!();
    println!("Output: {}", args.output.display());
    println!();
    println!("This file contains:");
    println!("  • Cardano Ed25519 key hash (for Cardano transaction authorization)");
    println!("  • Midnight sr25519 public key (for governance operations)");
    println!("  • SS58 address (for reference)");
    println!();
    println!("Use with: midnight-cli genesis deploy-contracts --council-member {} ...", args.output.display());

    // 6. Optionally write sr25519 key files
    if args.write_key_files {
        eprintln!();
        eprintln!("📝 Writing Midnight key files...");
        let governance_key_material = Sr25519::to_key_material(
            &governance_pair,
            KeyPurpose::Governance,
            Some(args.derivation.clone()),
        );
        let (skey, vkey) = crate::storage::KeyWriter::write_cardano_key_pair(
            &governance_key_material,
            &args.key_files_dir,
            "governance",
        )?;

        println!("  Signing key:      {}", skey.display());
        println!("  Verification key: {}", vkey.display());
    }

    Ok(())
}
