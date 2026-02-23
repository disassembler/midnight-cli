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
    /// Export validator seeds for midnight-node
    ExportSeeds(ExportSeedsArgs),
    /// Export validator keystore files for midnight-node
    ExportKeystore(ExportKeystoreArgs),
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

#[derive(Args)]
pub struct ExportSeedsArgs {
    /// Mnemonic phrase (or file path)
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// Mnemonic file path (supports GPG)
    #[arg(long)]
    pub mnemonic_file: Option<PathBuf>,

    /// Output directory for seed files
    #[arg(long, short = 'o', default_value = ".")]
    pub output_dir: PathBuf,
}

#[derive(Args)]
pub struct ExportKeystoreArgs {
    /// Mnemonic phrase (or file path)
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// Mnemonic file path (supports GPG)
    #[arg(long)]
    pub mnemonic_file: Option<PathBuf>,

    /// Output directory for keystore files
    #[arg(long, short = 'o', default_value = "keystore")]
    pub output_dir: PathBuf,
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
        ValidatorCommands::ExportSeeds(args) => handle_export_seeds(args),
        ValidatorCommands::ExportKeystore(args) => handle_export_keystore(args),
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

fn handle_export_seeds(args: ExportSeedsArgs) -> Result<()> {
    use secrecy::ExposeSecret;
    use sp_core::crypto::Pair as PairTrait;

    // Get mnemonic
    let mnemonic = if let Some(ref file) = args.mnemonic_file {
        KeyReader::read_mnemonic_from_file(file)?
    } else if let Some(ref phrase) = args.mnemonic {
        KeyReader::read_mnemonic(phrase)?
    } else {
        anyhow::bail!("Either --mnemonic or --mnemonic-file must be specified");
    };

    let mnemonic_str = ExposeSecret::expose_secret(&mnemonic);

    // Create output directory if it doesn't exist
    std::fs::create_dir_all(&args.output_dir)?;

    // Derive keys using same paths as validator generate
    let node_suri = format!("{}//midnight//node", mnemonic_str);
    let node_pair = Ed25519::from_suri(&node_suri)?;

    let aura_suri = format!("{}//midnight//aura", mnemonic_str);
    let aura_pair = Sr25519::from_suri(&aura_suri)?;

    let grandpa_suri = format!("{}//midnight//grandpa", mnemonic_str);
    let grandpa_pair = Ed25519::from_suri(&grandpa_suri)?;

    // Extract secret seeds as hex (32 bytes each)
    // For sr25519: to_raw_vec() returns 64 bytes (32-byte mini-secret + 32-byte nonce),
    // we only need the first 32 bytes (mini-secret)
    // For ed25519: to_raw_vec() returns the full keypair, we need just the first 32 bytes (seed)
    let node_raw = node_pair.to_raw_vec();
    let aura_raw = aura_pair.to_raw_vec();
    let grandpa_raw = grandpa_pair.to_raw_vec();

    let node_seed_hex = format!("0x{}", hex::encode(&node_raw[..32]));
    let aura_seed_hex = format!("0x{}", hex::encode(&aura_raw[..32]));
    let grandpa_seed_hex = format!("0x{}", hex::encode(&grandpa_raw[..32]));

    // Write seed files
    let node_seed_path = args.output_dir.join("node-seed.txt");
    let aura_seed_path = args.output_dir.join("aura-seed.txt");
    let grandpa_seed_path = args.output_dir.join("grandpa-seed.txt");

    std::fs::write(&node_seed_path, &node_seed_hex)?;
    std::fs::write(&aura_seed_path, &aura_seed_hex)?;
    std::fs::write(&grandpa_seed_path, &grandpa_seed_hex)?;

    #[cfg(unix)]
    {
        // Set restrictive permissions on Unix (0o600 = owner read/write only)
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&node_seed_path, permissions.clone())?;
        std::fs::set_permissions(&aura_seed_path, permissions.clone())?;
        std::fs::set_permissions(&grandpa_seed_path, permissions)?;
    }

    println!("✓ Validator seed files exported:");
    println!("  Node (ed25519):    {}", node_seed_path.display());
    println!("  Aura (sr25519):    {}", aura_seed_path.display());
    println!("  Grandpa (ed25519): {}", grandpa_seed_path.display());
    println!();
    println!("⚠️  SECURITY WARNING:");
    println!("   - These files contain SECRET KEYS");
    println!("   - Keep them secure and never share them");
    println!("   - Use with midnight-node:");
    println!("     --aura-seed-file {}", aura_seed_path.display());
    println!("     --grandpa-seed-file {}", grandpa_seed_path.display());
    println!("     --cross-chain-seed-file {} (if using cross-chain)", node_seed_path.display());

    Ok(())
}

fn handle_export_keystore(args: ExportKeystoreArgs) -> Result<()> {
    use secrecy::ExposeSecret;
    use sp_core::crypto::Pair as PairTrait;
    use std::io::Write;

    // Get mnemonic
    let mnemonic = if let Some(ref file) = args.mnemonic_file {
        KeyReader::read_mnemonic_from_file(file)?
    } else if let Some(ref phrase) = args.mnemonic {
        KeyReader::read_mnemonic(phrase)?
    } else {
        anyhow::bail!("Either --mnemonic or --mnemonic-file must be specified");
    };

    let mnemonic_str = ExposeSecret::expose_secret(&mnemonic);

    // Create output directory if it doesn't exist
    std::fs::create_dir_all(&args.output_dir)?;

    // Derive keys using same paths as validator generate
    let aura_suri = format!("{}//midnight//aura", mnemonic_str);
    let aura_pair = Sr25519::from_suri(&aura_suri)?;
    let aura_public = Sr25519::public_key(&aura_pair);
    let aura_public_bytes: &[u8] = aura_public.as_ref();

    let grandpa_suri = format!("{}//midnight//grandpa", mnemonic_str);
    let grandpa_pair = Ed25519::from_suri(&grandpa_suri)?;
    let grandpa_public = Ed25519::public_key(&grandpa_pair);
    let grandpa_public_bytes: &[u8] = grandpa_public.as_ref();

    // Extract seeds (32 bytes each)
    let aura_raw = aura_pair.to_raw_vec();
    let grandpa_raw = grandpa_pair.to_raw_vec();

    let aura_seed_hex = format!("0x{}", hex::encode(&aura_raw[..32]));
    let grandpa_seed_hex = format!("0x{}", hex::encode(&grandpa_raw[..32]));

    // Create keystore files
    // Keystore filename format: key_type_hex + public_key_hex
    // "aura" = 61757261, "gran" = 6772616e

    // Aura keystore file
    let aura_pubkey_hex = hex::encode(aura_public_bytes);
    let aura_filename = format!("61757261{}", aura_pubkey_hex);
    let aura_path = args.output_dir.join(&aura_filename);

    let mut aura_file = std::fs::File::create(&aura_path)?;
    aura_file.write_all(format!("\"{}\"", aura_seed_hex).as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&aura_path, permissions)?;
    }

    // Grandpa keystore file
    let grandpa_pubkey_hex = hex::encode(grandpa_public_bytes);
    let grandpa_filename = format!("6772616e{}", grandpa_pubkey_hex);
    let grandpa_path = args.output_dir.join(&grandpa_filename);

    let mut grandpa_file = std::fs::File::create(&grandpa_path)?;
    grandpa_file.write_all(format!("\"{}\"", grandpa_seed_hex).as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&grandpa_path, permissions)?;
    }

    println!("✓ Keystore files created:");
    println!("  Aura (sr25519):");
    println!("    Filename:   {}", aura_filename);
    println!("    Public key: 0x{}", aura_pubkey_hex);
    println!("    Path:       {}", aura_path.display());
    println!();
    println!("  Grandpa (ed25519):");
    println!("    Filename:   {}", grandpa_filename);
    println!("    Public key: 0x{}", grandpa_pubkey_hex);
    println!("    Path:       {}", grandpa_path.display());
    println!();
    println!("✓ Keystore directory: {}", args.output_dir.display());
    println!();
    println!("⚠️  SECURITY WARNING:");
    println!("   - These files contain SECRET KEYS");
    println!("   - Keep them secure and never share them");
    println!("   - Use with midnight-node:");
    println!("     --keystore-path {}", args.output_dir.display());

    Ok(())
}
