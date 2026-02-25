use crate::application::KeyGeneration;
use crate::crypto::{Ecdsa, Ed25519, Sr25519};
use crate::domain::KeyPurpose;
use crate::storage::KeyReader;
use anyhow::Result;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use sp_core::crypto::Pair as PairTrait;
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

    /// Validator hostname or IP address (requires --port)
    #[arg(long, requires = "port")]
    pub hostname: Option<String>,

    /// Validator P2P port (requires --hostname)
    #[arg(long, requires = "hostname")]
    pub port: Option<u16>,
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
    /// BEEFY key (ecdsa) - Bridge finality proofs for Cardano
    pub beefy_key: KeyData,
    /// Bootnode multiaddr (if hostname and port provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootnode: Option<String>,
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

/// Convert Ed25519 public key to libp2p PeerId
fn ed25519_to_peer_id(public_key_bytes: &[u8]) -> Result<String> {
    // Create libp2p Ed25519 public key
    let ed25519_pubkey = libp2p_identity::ed25519::PublicKey::try_from_bytes(public_key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {:?}", e))?;

    // Convert to libp2p PublicKey and then to PeerId
    let public_key = libp2p_identity::PublicKey::from(ed25519_pubkey);
    let peer_id = libp2p_identity::PeerId::from_public_key(&public_key);

    Ok(peer_id.to_string())
}

/// Generate bootnode multiaddr from hostname/IP, port, and peer ID
fn generate_bootnode_multiaddr(hostname: &str, port: u16, peer_id: &str) -> String {
    // Auto-detect if it's an IP address or hostname
    if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(_) => {
                format!("/ip4/{}/tcp/{}/p2p/{}", hostname, port, peer_id)
            }
            std::net::IpAddr::V6(_) => {
                format!("/ip6/{}/tcp/{}/p2p/{}", hostname, port, peer_id)
            }
        }
    } else {
        // Hostname - use /dns/ protocol
        format!("/dns/{}/tcp/{}/p2p/{}", hostname, port, peer_id)
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

    // Generate BEEFY key (ecdsa) - Bridge finality proofs
    let beefy_suri = format!("{}//midnight//beefy", mnemonic_str);
    let beefy_pair = sp_core::ecdsa::Pair::from_string(&beefy_suri, None)
        .map_err(|e| anyhow::anyhow!("ECDSA beefy key derivation failed: {:?}", e))?;
    let beefy_public = beefy_pair.public();
    let beefy_public_bytes: &[u8] = beefy_public.as_ref();

    // Generate bootnode multiaddr if hostname and port provided
    let bootnode = if let (Some(ref hostname), Some(port)) = (&args.hostname, args.port) {
        let peer_id = ed25519_to_peer_id(node_public_bytes)?;
        let multiaddr = generate_bootnode_multiaddr(hostname, port, &peer_id);
        Some(multiaddr)
    } else {
        None
    };

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
        beefy_key: KeyData {
            key_type: "ecdsa".to_string(),
            public_key_hex: hex::encode(beefy_public_bytes),
            ss58_address: None, // ECDSA keys don't use SS58 encoding
        },
        bootnode,
    };

    // Write JSON file
    let json = serde_json::to_string_pretty(&validator_keys)?;
    std::fs::write(&args.output, json)?;

    println!("✓ Validator keys generated:");
    println!("  Node key (ed25519):    {}", validator_keys.node_key.public_key_hex);
    println!("  Aura key (sr25519):    {}", validator_keys.aura_key.public_key_hex);
    println!("  Grandpa key (ed25519): {}", validator_keys.grandpa_key.public_key_hex);
    println!("  BEEFY key (ecdsa):     {}", validator_keys.beefy_key.public_key_hex);
    if let Some(ref bootnode) = validator_keys.bootnode {
        println!();
        println!("✓ Bootnode multiaddr:");
        println!("  {}", bootnode);
    }
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

        // Write beefy key files
        let beefy_key_material = Ecdsa::to_key_material(
            &beefy_pair,
            KeyPurpose::Finality,
            Some("//midnight//beefy".to_string()),
        );
        let (beefy_skey, beefy_vkey) = crate::storage::KeyWriter::write_cardano_key_pair(
            &beefy_key_material,
            &args.key_files_dir,
            "beefy",
        )?;

        println!();
        println!("✓ Key files written:");
        println!("  Node:    {}, {}", node_skey.display(), node_vkey.display());
        println!("  Aura:    {}, {}", aura_skey.display(), aura_vkey.display());
        println!("  Grandpa: {}, {}", grandpa_skey.display(), grandpa_vkey.display());
        println!("  BEEFY:   {}, {}", beefy_skey.display(), beefy_vkey.display());
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
    // Use from_string_with_seed to get the proper derived seed that can reconstruct the keypair
    let node_suri = format!("{}//midnight//node", mnemonic_str);
    let (_node_pair, node_seed_opt) = sp_core::ed25519::Pair::from_string_with_seed(&node_suri, None)
        .map_err(|e| anyhow::anyhow!("Ed25519 node key derivation failed: {:?}", e))?;

    let aura_suri = format!("{}//midnight//aura", mnemonic_str);
    let (_aura_pair, aura_seed_opt) = sp_core::sr25519::Pair::from_string_with_seed(&aura_suri, None)
        .map_err(|e| anyhow::anyhow!("Sr25519 aura key derivation failed: {:?}", e))?;

    let grandpa_suri = format!("{}//midnight//grandpa", mnemonic_str);
    let (_grandpa_pair, grandpa_seed_opt) = sp_core::ed25519::Pair::from_string_with_seed(&grandpa_suri, None)
        .map_err(|e| anyhow::anyhow!("Ed25519 grandpa key derivation failed: {:?}", e))?;

    let beefy_suri = format!("{}//midnight//beefy", mnemonic_str);
    let (_beefy_pair, beefy_seed_opt) = sp_core::ecdsa::Pair::from_string_with_seed(&beefy_suri, None)
        .map_err(|e| anyhow::anyhow!("ECDSA beefy key derivation failed: {:?}", e))?;

    // Extract the derived seeds returned by from_string_with_seed
    // These seeds are the correct values that can reconstruct the derived keypairs
    let node_seed = node_seed_opt
        .ok_or_else(|| anyhow::anyhow!("No seed returned for node key"))?;
    let aura_seed = aura_seed_opt
        .ok_or_else(|| anyhow::anyhow!("No seed returned for aura key"))?;
    let grandpa_seed = grandpa_seed_opt
        .ok_or_else(|| anyhow::anyhow!("No seed returned for grandpa key"))?;
    let beefy_seed = beefy_seed_opt
        .ok_or_else(|| anyhow::anyhow!("No seed returned for beefy key"))?;

    let node_seed_hex = format!("0x{}", hex::encode(&node_seed));
    let aura_seed_hex = format!("0x{}", hex::encode(&aura_seed));
    let grandpa_seed_hex = format!("0x{}", hex::encode(&grandpa_seed));
    let beefy_seed_hex = format!("0x{}", hex::encode(&beefy_seed));

    // Write seed files
    let node_seed_path = args.output_dir.join("node-seed.txt");
    let aura_seed_path = args.output_dir.join("aura-seed.txt");
    let grandpa_seed_path = args.output_dir.join("grandpa-seed.txt");
    let beefy_seed_path = args.output_dir.join("beefy-seed.txt");

    std::fs::write(&node_seed_path, &node_seed_hex)?;
    std::fs::write(&aura_seed_path, &aura_seed_hex)?;
    std::fs::write(&grandpa_seed_path, &grandpa_seed_hex)?;
    std::fs::write(&beefy_seed_path, &beefy_seed_hex)?;

    #[cfg(unix)]
    {
        // Set restrictive permissions on Unix (0o600 = owner read/write only)
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&node_seed_path, permissions.clone())?;
        std::fs::set_permissions(&aura_seed_path, permissions.clone())?;
        std::fs::set_permissions(&grandpa_seed_path, permissions.clone())?;
        std::fs::set_permissions(&beefy_seed_path, permissions)?;
    }

    println!("✓ Validator seed files exported:");
    println!("  Node (ed25519):    {}", node_seed_path.display());
    println!("  Aura (sr25519):    {}", aura_seed_path.display());
    println!("  Grandpa (ed25519): {}", grandpa_seed_path.display());
    println!("  BEEFY (ecdsa):     {}", beefy_seed_path.display());
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
    // Use from_string_with_seed to get the proper derived seed that can reconstruct the keypair
    let node_suri = format!("{}//midnight//node", mnemonic_str);
    let (node_pair, node_seed_opt) = sp_core::ed25519::Pair::from_string_with_seed(&node_suri, None)
        .map_err(|e| anyhow::anyhow!("Ed25519 node key derivation failed: {:?}", e))?;

    let aura_suri = format!("{}//midnight//aura", mnemonic_str);
    let (aura_pair, aura_seed_opt) = sp_core::sr25519::Pair::from_string_with_seed(&aura_suri, None)
        .map_err(|e| anyhow::anyhow!("Sr25519 aura key derivation failed: {:?}", e))?;
    let aura_public = aura_pair.public();
    let aura_public_bytes: &[u8] = aura_public.as_ref();

    let grandpa_suri = format!("{}//midnight//grandpa", mnemonic_str);
    let (grandpa_pair, grandpa_seed_opt) = sp_core::ed25519::Pair::from_string_with_seed(&grandpa_suri, None)
        .map_err(|e| anyhow::anyhow!("Ed25519 grandpa key derivation failed: {:?}", e))?;
    let grandpa_public = grandpa_pair.public();
    let grandpa_public_bytes: &[u8] = grandpa_public.as_ref();

    let beefy_suri = format!("{}//midnight//beefy", mnemonic_str);
    let (beefy_pair, beefy_seed_opt) = sp_core::ecdsa::Pair::from_string_with_seed(&beefy_suri, None)
        .map_err(|e| anyhow::anyhow!("ECDSA beefy key derivation failed: {:?}", e))?;
    let beefy_public = beefy_pair.public();
    let beefy_public_bytes: &[u8] = beefy_public.as_ref();

    // Extract the derived seeds returned by from_string_with_seed
    // These seeds are the correct values that can reconstruct the derived keypairs
    let node_seed = node_seed_opt
        .ok_or_else(|| anyhow::anyhow!("No seed returned for node key"))?;
    let aura_seed = aura_seed_opt
        .ok_or_else(|| anyhow::anyhow!("No seed returned for aura key"))?;
    let grandpa_seed = grandpa_seed_opt
        .ok_or_else(|| anyhow::anyhow!("No seed returned for grandpa key"))?;
    let beefy_seed = beefy_seed_opt
        .ok_or_else(|| anyhow::anyhow!("No seed returned for beefy key"))?;

    let node_seed_hex = format!("0x{}", hex::encode(&node_seed));
    let aura_seed_hex = format!("0x{}", hex::encode(&aura_seed));
    let grandpa_seed_hex = format!("0x{}", hex::encode(&grandpa_seed));
    let beefy_seed_hex = format!("0x{}", hex::encode(&beefy_seed));

    // Create keystore files
    // Keystore filename format: key_type_hex + public_key_hex
    // "aura" = 61757261, "gran" = 6772616e, "beef" = 62656566

    // Node key as network_secret (for libp2p network identity)
    let network_secret_path = args.output_dir.join("network_secret");
    let mut network_secret_file = std::fs::File::create(&network_secret_path)?;
    network_secret_file.write_all(&node_seed)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&network_secret_path, permissions)?;
    }

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

    // BEEFY keystore file
    let beefy_pubkey_hex = hex::encode(beefy_public_bytes);
    let beefy_filename = format!("62656566{}", beefy_pubkey_hex);
    let beefy_path = args.output_dir.join(&beefy_filename);

    let mut beefy_file = std::fs::File::create(&beefy_path)?;
    beefy_file.write_all(format!("\"{}\"", beefy_seed_hex).as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&beefy_path, permissions)?;
    }

    println!("✓ Keystore files created:");
    println!("  Network secret (node/ed25519):");
    println!("    Filename:   network_secret");
    println!("    Path:       {}", network_secret_path.display());
    println!();
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
    println!("  BEEFY (ecdsa):");
    println!("    Filename:   {}", beefy_filename);
    println!("    Public key: 0x{}", beefy_pubkey_hex);
    println!("    Path:       {}", beefy_path.display());
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
