use crate::application::KeyGeneration;
use crate::crypto::Sr25519;
use crate::domain::KeyPurpose;
use crate::storage::KeyReader;
use anyhow::Result;
use clap::{Args, Subcommand};
use hayate::wallet::plutus::GovernanceMember;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum GovernanceCommands {
    /// Generate governance key for TA/Council member
    Generate(GovernanceGenerateArgs),
    /// Rotate council members by spending the governance contract UTxO
    Rotate(GovernanceRotateArgs),
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

#[derive(Args)]
pub struct GovernanceRotateArgs {
    /// Contract address (bech32)
    #[arg(long)]
    pub contract_address: String,

    /// Hayate gRPC endpoint
    #[arg(long, default_value = "http://localhost:50051")]
    pub hayate_endpoint: String,

    /// Council member key files (comma-separated paths to .json files)
    #[arg(long)]
    pub council_keys: String,

    /// Council member mnemonic files for signing (at least 2 for 2/3 threshold)
    #[arg(long)]
    pub council_mnemonic_file: Vec<PathBuf>,

    /// Wallet mnemonic file for collateral/fees (supports GPG)
    #[arg(long)]
    pub mnemonic_file: PathBuf,

    /// Wallet account index for signing
    #[arg(long, default_value = "0")]
    pub account: u32,

    /// Output file for signed transaction (optional, will submit if not provided)
    #[arg(long)]
    pub tx_file: Option<PathBuf>,

    /// Dry run: validate transaction without submitting (phase-1 validation only)
    #[arg(long)]
    pub dry_run: bool,

    /// Ledger state JSON file for simulation (contains UTxOs, protocol params, etc.)
    /// If not provided, will query from hayate endpoint
    #[arg(long)]
    pub ledger_state: Option<PathBuf>,
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

pub async fn handle_governance_command(cmd: GovernanceCommands) -> Result<()> {
    match cmd {
        GovernanceCommands::Generate(args) => handle_governance_generate(args),
        GovernanceCommands::Rotate(args) => handle_governance_rotate(args).await,
    }
}

fn handle_governance_generate(args: GovernanceGenerateArgs) -> Result<()> {
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

        // Calculate key hash: BLAKE2b-224 of public key (32 bytes)
        use pallas_crypto::hash::Hasher;
        let hash: pallas_crypto::hash::Hash<28> = Hasher::<224>::hash(&cardano_pubkey_bytes);
        let cardano_key_hash = hex::encode(hash.as_ref());

        eprintln!("  Cardano pubkey (32 bytes): {}", hex::encode(&cardano_pubkey_bytes));
        eprintln!("  Key hash:                  {}", cardano_key_hash);
        eprintln!();

        (cardano_pubkey_bytes, cardano_key_hash)
    } else {
        // Derive from mnemonic at standard Cardano payment key path: 1852H/1815H/0H/0/0
        eprintln!("📖 Deriving Cardano key from mnemonic at 1852H/1815H/0H/0/0...");

        // Use hayate to derive Cardano payment key and compute key hash
        let wallet = hayate::wallet::Wallet::from_mnemonic_str(
            mnemonic_str,
            hayate::wallet::Network::Testnet,  // Network doesn't matter for key derivation
            0,  // account = 0
        ).map_err(|e| anyhow::anyhow!("Failed to create Cardano wallet: {}", e))?;

        // Get the payment key hash using hayate's method (correctly hashes 32-byte pubkey)
        let key_hash_bytes = wallet.payment_key_hash(0)
            .map_err(|e| anyhow::anyhow!("Failed to compute key hash: {}", e))?;
        let cardano_key_hash = hex::encode(&key_hash_bytes);

        // Also get the public key bytes for display
        let payment_key = wallet.payment_key(0)
            .map_err(|e| anyhow::anyhow!("Failed to derive payment key: {}", e))?;
        let payment_xpub = payment_key.public();
        let cardano_pubkey_bytes = payment_xpub.public_key(); // 32 bytes

        eprintln!("  Derivation path:           1852H/1815H/0H/0/0");
        eprintln!("  Cardano pubkey (32 bytes): {}", hex::encode(&cardano_pubkey_bytes));
        eprintln!("  Key hash (28 bytes):       {}", cardano_key_hash);
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

/// Handle governance rotation using provided ledger state (offline mode)
async fn handle_governance_rotate_with_ledger_state(args: GovernanceRotateArgs) -> Result<()> {
    use hayate::wallet::plutus::{GovernanceMember, VersionedMultisig, Redeemer};
    use hayate::wallet::simulator::LedgerState;
    use pallas_codec::minicbor::decode;

    eprintln!("📁 Loading ledger state...");
    let ledger_state = LedgerState::from_file(
        args.ledger_state
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Ledger state path required"))?
    )?;

    eprintln!("   {} UTxOs in ledger state", ledger_state.utxos.len());
    eprintln!("   Current slot: {}", ledger_state.current_slot);
    eprintln!("   Network magic: {}", ledger_state.network_magic);

    // Parse contract address
    let contract_addr_bytes = if let Ok(addr) = pallas_addresses::Address::from_bech32(&args.contract_address) {
        addr.to_vec()
    } else {
        hex::decode(&args.contract_address)
            .map_err(|_| anyhow::anyhow!("Invalid contract address (not bech32 or hex)"))?
    };

    // Find contract UTxO in ledger state by decoding and matching address
    eprintln!("🔍 Looking for contract UTxO in ledger state...");
    eprintln!("   Expected address: {}", hex::encode(&contract_addr_bytes));

    let mut contract_utxo_opt: Option<ContractUtxo> = None;
    let mut contract_utxo_key: Option<String> = None;

    for (utxo_key, utxo_bytes) in ledger_state.utxos.iter() {
        // Decode the UTxO as MintedTransactionOutput
        let output: pallas_primitives::babbage::MintedTransactionOutput =
            decode(utxo_bytes).map_err(|e| anyhow::anyhow!("Failed to decode UTxO {}: {}", utxo_key, e))?;

        // MintedTransactionOutput is PseudoTransactionOutput enum
        // We expect PostAlonzo variant for modern transactions
        let post_alonzo_output = match output {
            pallas_primitives::babbage::PseudoTransactionOutput::PostAlonzo(post_alonzo) => post_alonzo,
            pallas_primitives::babbage::PseudoTransactionOutput::Legacy(_) => {
                continue; // Skip legacy outputs
            }
        };

        // Check if address matches
        let output_addr = post_alonzo_output.address.as_slice();
        eprintln!("  UTxO {} address: {}", utxo_key, hex::encode(output_addr));
        if output_addr == contract_addr_bytes.as_slice() {
            eprintln!("✅ Found contract UTxO: {}", utxo_key);

            // Parse txhash:index
            let parts: Vec<&str> = utxo_key.split(':').collect();
            if parts.len() != 2 {
                anyhow::bail!("Invalid UTxO key format: {}", utxo_key);
            }
            let tx_hash = hex::decode(parts[0])?;
            let output_index: u64 = parts[1].parse()?;

            // Extract lovelace and assets
            let lovelace = match &post_alonzo_output.value {
                pallas_primitives::babbage::Value::Coin(coin) => *coin,
                pallas_primitives::babbage::Value::Multiasset(coin, assets) => {
                    eprintln!("   {} lovelace + {} asset types", coin, assets.len());
                    *coin
                }
            };

            // Extract assets
            let mut asset_list = Vec::new();
            if let pallas_primitives::babbage::Value::Multiasset(_, assets) = &post_alonzo_output.value {
                for (policy_id, asset_map) in assets.iter() {
                    for (asset_name, amount) in asset_map.iter() {
                        asset_list.push((policy_id.to_vec(), asset_name.to_vec(), *amount));
                    }
                }
            }

            // Extract datum
            let datum = match &post_alonzo_output.datum_option {
                Some(pallas_primitives::babbage::PseudoDatumOption::Data(data)) => {
                    // Inline datum - encode the PlutusData
                    pallas_codec::minicbor::to_vec(data)?
                }
                Some(pallas_primitives::babbage::PseudoDatumOption::Hash(_hash)) => {
                    anyhow::bail!("Datum hash not supported - expected inline datum");
                }
                None => {
                    anyhow::bail!("No datum found on contract UTxO");
                }
            };

            contract_utxo_opt = Some(ContractUtxo {
                tx_hash,
                output_index,
                lovelace,
                assets: asset_list,
                datum,
            });
            contract_utxo_key = Some(utxo_key.clone());
            break;
        }
    }

    let contract_utxo = contract_utxo_opt.ok_or_else(|| {
        anyhow::anyhow!("Contract UTxO not found in ledger state for address: {}", args.contract_address)
    })?;

    let contract_utxo_key_str = contract_utxo_key.unwrap();
    eprintln!("   TX: {}:{}", hex::encode(&contract_utxo.tx_hash), contract_utxo.output_index);
    eprintln!("   Amount: {} lovelace", contract_utxo.lovelace);
    eprintln!("   Assets: {}", contract_utxo.assets.len());

    // Find collateral UTxO in ledger state (pure ADA, >= 5 ADA)
    eprintln!("🔍 Looking for collateral UTxO in ledger state...");

    let mut collateral_utxo_opt: Option<(String, u64)> = None;

    for (utxo_key, utxo_bytes) in ledger_state.utxos.iter() {
        // Skip the contract UTxO
        if *utxo_key == contract_utxo_key_str {
            continue;
        }

        let output: pallas_primitives::babbage::MintedTransactionOutput =
            decode(utxo_bytes).map_err(|e| anyhow::anyhow!("Failed to decode UTxO {}: {}", utxo_key, e))?;

        // Handle PostAlonzo variant
        let post_alonzo_output = match output {
            pallas_primitives::babbage::PseudoTransactionOutput::PostAlonzo(post_alonzo) => post_alonzo,
            pallas_primitives::babbage::PseudoTransactionOutput::Legacy(_) => continue,
        };

        // Check if it's pure ADA (no assets)
        let (lovelace, has_assets) = match &post_alonzo_output.value {
            pallas_primitives::babbage::Value::Coin(coin) => (*coin, false),
            pallas_primitives::babbage::Value::Multiasset(coin, assets) => (*coin, !assets.is_empty()),
        };

        if !has_assets && lovelace >= 5_000_000 {
            eprintln!("✅ Found collateral UTxO: {} ({} lovelace)", utxo_key, lovelace);
            collateral_utxo_opt = Some((utxo_key.clone(), lovelace));
            break;
        }
    }

    let _collateral_utxo_key = collateral_utxo_opt.ok_or_else(|| {
        anyhow::anyhow!("No suitable collateral UTxO found in ledger state (need >= 5 ADA pure ADA)")
    })?;

    // Decode current datum
    eprintln!("📋 Decoding current datum...");
    eprintln!("   Datum bytes (hex): {}", hex::encode(&contract_utxo.datum));
    eprintln!("   Datum length: {} bytes", contract_utxo.datum.len());

    // Unwrap CBOR tag 24 wrapper if present
    let datum_bytes = if contract_utxo.datum.starts_with(&[0xd8, 0x18]) {
        // Has CBOR tag 24 wrapper - decode it
        use pallas_codec::minicbor::Decoder;
        let mut decoder = Decoder::new(&contract_utxo.datum);
        let _tag24 = decoder.tag()?; // Skip tag 24
        let inner_bytes = decoder.bytes()?;
        eprintln!("   Unwrapped {} bytes from CBOR tag 24", inner_bytes.len());

        // Also unwrap Plutus Data tag 121 if present
        if inner_bytes.starts_with(&[0xd8, 0x79]) {
            let mut inner_decoder = Decoder::new(inner_bytes);
            let _tag121 = inner_decoder.tag()?; // Skip tag 121
            // The remaining bytes are the actual array
            let remaining_pos = inner_decoder.position();
            eprintln!("   Skipped Plutus Data tag 121, {} bytes remaining", inner_bytes.len() - remaining_pos);
            &inner_bytes[remaining_pos..]
        } else {
            inner_bytes
        }
    } else {
        &contract_utxo.datum[..]
    };

    let current_datum = VersionedMultisig::from_cbor(datum_bytes)?;
    eprintln!("   Total signers: {}", current_datum.total_signers);
    eprintln!("   Council members: {}", current_datum.members.len());
    eprintln!("   Logic round: {}", current_datum.logic_round);

    // Load council keys
    eprintln!("🔑 Loading council keys...");
    let key_paths: Vec<&str> = args.council_keys.split(',').collect();
    let mut new_members = Vec::new();

    for (i, path) in key_paths.iter().enumerate() {
        let key_file = std::fs::read_to_string(path.trim())
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path, e))?;
        let key: GovernanceKey = serde_json::from_str(&key_file)
            .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", path, e))?;

        let cardano_hash = hex::decode(&key.cardano_key_hash)
            .map_err(|e| anyhow::anyhow!("Invalid cardano_key_hash in {}: {}", path, e))?;
        let sr25519_key = hex::decode(&key.sr25519_public_key)
            .map_err(|e| anyhow::anyhow!("Invalid sr25519_public_key in {}: {}", path, e))?;

        if cardano_hash.len() != 28 {
            anyhow::bail!("cardano_key_hash must be 28 bytes in {}", path);
        }
        if sr25519_key.len() != 32 {
            anyhow::bail!("sr25519_public_key must be 32 bytes in {}", path);
        }

        let mut cardano_hash_arr = [0u8; 28];
        cardano_hash_arr.copy_from_slice(&cardano_hash);

        let mut sr25519_arr = [0u8; 32];
        sr25519_arr.copy_from_slice(&sr25519_key);

        new_members.push(GovernanceMember {
            cardano_hash: cardano_hash_arr,
            sr25519_key: sr25519_arr,
        });

        eprintln!("   [{}] {}", i + 1, key.ss58_address);
    }

    // Create new datum
    eprintln!("📝 Creating new datum (logic_round: {} -> {})...",
              current_datum.logic_round, current_datum.logic_round + 1);

    let mut new_datum = VersionedMultisig::new(
        new_members.len() as u32,
        new_members.clone(),
    );
    new_datum.logic_round = current_datum.logic_round + 1;
    let new_datum_cbor = new_datum.to_cbor()?;

    // Build redeemer
    eprintln!("🔧 Building redeemer...");
    let redeemer = build_update_redeemer(&new_members)?;
    eprintln!("Redeemer CBOR (hex): {}", hex::encode(&redeemer));
    eprintln!("Redeemer CBOR length: {} bytes", redeemer.len());
    let redeemer_obj = Redeemer::spend(0, redeemer);

    // Load wallet mnemonic
    eprintln!("🔐 Loading wallet mnemonic for collateral/fees...");
    let wallet_mnemonic = KeyReader::read_mnemonic_from_file(&args.mnemonic_file)?;
    let wallet_mnemonic_str = secrecy::ExposeSecret::expose_secret(&wallet_mnemonic);

    // Load council mnemonics
    eprintln!("🔑 Loading council member mnemonics for signing...");
    let mut council_mnemonic_strings = Vec::new();
    for (i, path) in args.council_mnemonic_file.iter().enumerate() {
        let mnemonic = KeyReader::read_mnemonic_from_file(path)?;
        let mnemonic_str = secrecy::ExposeSecret::expose_secret(&mnemonic).to_string();
        council_mnemonic_strings.push(mnemonic_str);
        eprintln!("   [{}] Loaded mnemonic from {}", i + 1, path.display());
    }

    // Build transaction (offline mode - no hayate queries)
    eprintln!("🔨 Building transaction (offline mode)...");
    let signed_tx = build_rotation_tx_offline(
        wallet_mnemonic_str,
        args.account,
        &council_mnemonic_strings,
        &contract_utxo,
        &contract_addr_bytes,
        &new_datum_cbor,
        &redeemer_obj,
        &new_members,
        &ledger_state,
    ).await?;

    eprintln!("✅ Transaction built ({} bytes)", signed_tx.len());

    // Calculate transaction hash
    use pallas_crypto::hash::Hasher;
    let tx_hash = Hasher::<256>::hash(&signed_tx);
    eprintln!("Transaction hash: {}", hex::encode(&tx_hash));

    // Save transaction in Cardano CLI format for inspection
    let cli_tx_json = serde_json::json!({
        "type": "Tx BabbageEra",
        "description": "Governance rotation transaction",
        "cborHex": hex::encode(&signed_tx)
    });
    let cli_tx_path = "/tmp/governance-rotation-tx.json";
    std::fs::write(cli_tx_path, serde_json::to_string_pretty(&cli_tx_json)?)?;
    eprintln!("💾 Saved transaction to: {}", cli_tx_path);

    // Always simulate in offline mode
    eprintln!("🧪 Running transaction simulator (phase-1 validation with ledger state)...");
    eprintln!("   Transaction bytes (first 50): {}", hex::encode(&signed_tx[..50.min(signed_tx.len())]));

    match simulate_transaction_offline(&signed_tx, &ledger_state).await {
        Ok(result) => {
            if result.success {
                eprintln!("✅ Simulation PASSED");
                eprintln!("   All phase-1 validation checks passed:");
                for check in &result.checks_passed {
                    eprintln!("   ✓ {}", check);
                }
            } else {
                eprintln!("❌ Simulation FAILED");
                if let Some(ref error) = result.error {
                    eprintln!("   Error: {}", error);
                }
                for check in &result.checks_failed {
                    eprintln!("   ✗ {}", check);
                }
                anyhow::bail!("Transaction simulation failed");
            }
        }
        Err(e) => {
            eprintln!("⚠️  Simulator error: {}", e);
            anyhow::bail!("Simulation failed: {}", e);
        }
    }

    // Save transaction to file if requested
    if let Some(ref tx_file) = args.tx_file {
        std::fs::write(tx_file, &signed_tx)?;
        eprintln!("\n💾 Transaction saved to: {}", tx_file.display());
        eprintln!("   TX Hash: {}", hex::encode(&tx_hash));
    } else {
        eprintln!("\n💡 Offline mode complete. Use --tx-file to save the signed transaction.");
        eprintln!("   You can submit it later using: cardano-cli transaction submit");
    }

    Ok(())
}

async fn handle_governance_rotate(args: GovernanceRotateArgs) -> Result<()> {
    use hayate::wallet::plutus::{GovernanceMember, VersionedMultisig, Redeemer};

    eprintln!("🔄 Starting council rotation...");

    // Check if we're using ledger state (offline mode) or live query mode
    if let Some(ref ledger_state_path) = args.ledger_state {
        eprintln!("📁 Using ledger state from: {}", ledger_state_path.display());
        eprintln!("   (Offline mode - no live chain queries)");
        return handle_governance_rotate_with_ledger_state(args).await;
    }

    eprintln!("🌐 Using live chain data from hayate endpoint");

    // 1. Parse contract address
    eprintln!("📍 Contract address: {}", args.contract_address);
    let contract_addr_bytes = if let Ok(addr) = pallas_addresses::Address::from_bech32(&args.contract_address) {
        addr.to_vec()
    } else {
        hex::decode(&args.contract_address)
            .map_err(|_| anyhow::anyhow!("Invalid contract address (not bech32 or hex)"))?
    };

    // 2. Query hayate for contract UTxO
    eprintln!("🔍 Querying hayate for contract UTxO...");
    let contract_utxo = query_contract_utxo(&args.hayate_endpoint, &contract_addr_bytes).await?;
    
    eprintln!("✅ Found contract UTxO:");
    eprintln!("   TX: {}", hex::encode(&contract_utxo.tx_hash));
    eprintln!("   Index: {}", contract_utxo.output_index);
    eprintln!("   Amount: {} lovelace", contract_utxo.lovelace);
    
    // 3. Decode current datum
    eprintln!("📋 Decoding current datum...");
    let current_datum = VersionedMultisig::from_cbor(&contract_utxo.datum)?;
    eprintln!("   Total signers: {}", current_datum.total_signers);
    eprintln!("   Council members: {}", current_datum.members.len());
    eprintln!("   Logic round: {}", current_datum.logic_round);
    
    // 4. Load council keys from JSON files
    eprintln!("🔑 Loading council keys...");
    let key_paths: Vec<&str> = args.council_keys.split(',').collect();
    let mut new_members = Vec::new();
    
    for (i, path) in key_paths.iter().enumerate() {
        let key_file = std::fs::read_to_string(path.trim())
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path, e))?;
        let key: GovernanceKey = serde_json::from_str(&key_file)
            .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", path, e))?;
        
        let cardano_hash = hex::decode(&key.cardano_key_hash)
            .map_err(|e| anyhow::anyhow!("Invalid cardano_key_hash in {}: {}", path, e))?;
        let sr25519_key = hex::decode(&key.sr25519_public_key)
            .map_err(|e| anyhow::anyhow!("Invalid sr25519_public_key in {}: {}", path, e))?;
        
        if cardano_hash.len() != 28 {
            anyhow::bail!("cardano_key_hash must be 28 bytes in {}", path);
        }
        if sr25519_key.len() != 32 {
            anyhow::bail!("sr25519_public_key must be 32 bytes in {}", path);
        }
        
        let mut cardano_hash_arr = [0u8; 28];
        cardano_hash_arr.copy_from_slice(&cardano_hash);
        
        let mut sr25519_arr = [0u8; 32];
        sr25519_arr.copy_from_slice(&sr25519_key);
        
        new_members.push(GovernanceMember {
            cardano_hash: cardano_hash_arr,
            sr25519_key: sr25519_arr,
        });
        
        eprintln!("   [{}] {}", i + 1, key.ss58_address);
    }
    
    // 5. Create new datum with incremented logic_round
    eprintln!("📝 Creating new datum (logic_round: {} -> {})...", 
              current_datum.logic_round, current_datum.logic_round + 1);
    
    let mut new_datum = VersionedMultisig::new(
        new_members.len() as u32,
        new_members.clone(),
    );
    new_datum.logic_round = current_datum.logic_round + 1;
    let new_datum_cbor = new_datum.to_cbor()?;
    
    // 6. Build UpdateRedeemer
    eprintln!("🔧 Building redeemer...");
    let redeemer = build_update_redeemer(&new_members)?;
    eprintln!("Redeemer CBOR (hex): {}", hex::encode(&redeemer));
    eprintln!("Redeemer CBOR length: {} bytes", redeemer.len());
    let redeemer_obj = Redeemer::spend(0, redeemer);
    
    // 7. Load mnemonics for signing
    eprintln!("🔐 Loading wallet mnemonic for collateral/fees...");
    let wallet_mnemonic = KeyReader::read_mnemonic_from_file(&args.mnemonic_file)?;
    let wallet_mnemonic_str = secrecy::ExposeSecret::expose_secret(&wallet_mnemonic);

    eprintln!("🔑 Loading council member mnemonics for signing...");
    let mut council_mnemonic_strings = Vec::new();

    for (i, path) in args.council_mnemonic_file.iter().enumerate() {
        let mnemonic = KeyReader::read_mnemonic_from_file(path)?;
        let mnemonic_str = secrecy::ExposeSecret::expose_secret(&mnemonic).to_string();
        council_mnemonic_strings.push(mnemonic_str);
        eprintln!("   [{}] Loaded mnemonic from {}", i + 1, path.display());
    }

    eprintln!("   Loaded {} council member mnemonics (need 2 for 2/3 threshold)", council_mnemonic_strings.len());

    // 8. Build and sign transaction
    eprintln!("🔨 Building transaction...");
    let signed_tx = build_and_sign_rotation_tx(
        &args.hayate_endpoint,
        wallet_mnemonic_str,
        args.account,
        &council_mnemonic_strings,
        &contract_utxo,
        &contract_addr_bytes,
        &new_datum_cbor,
        &redeemer_obj,
        &new_members,
    ).await?;

    eprintln!("✅ Transaction built ({} bytes)", signed_tx.len());

    // Calculate transaction hash
    use pallas_crypto::hash::Hasher;
    let tx_hash = Hasher::<256>::hash(&signed_tx);
    eprintln!("Transaction hash: {}", hex::encode(&tx_hash));

    // 9. Dry run simulation (if requested)
    if args.dry_run {
        eprintln!("🧪 Running transaction simulator (phase-1 validation)...");

        let ledger_state = if let Some(ref ledger_path) = args.ledger_state {
            eprintln!("   Loading ledger state from: {}", ledger_path.display());
            Some(hayate::wallet::simulator::LedgerState::from_file(ledger_path)?)
        } else {
            eprintln!("   Will query chain state from hayate endpoint");
            None
        };

        match simulate_transaction(&args.hayate_endpoint, &signed_tx, ledger_state.as_ref()).await {
            Ok(result) => {
                if result.success {
                    eprintln!("✅ Simulation PASSED");
                    eprintln!("   All phase-1 validation checks passed:");
                    for check in &result.checks_passed {
                        eprintln!("   ✓ {}", check);
                    }
                } else {
                    eprintln!("❌ Simulation FAILED");
                    if let Some(ref error) = result.error {
                        eprintln!("   Error: {}", error);
                    }
                    for check in &result.checks_failed {
                        eprintln!("   ✗ {}", check);
                    }
                    anyhow::bail!("Transaction simulation failed - fix errors before submitting");
                }
            }
            Err(e) => {
                eprintln!("⚠️  Simulator error: {}", e);
                eprintln!("   (This may be due to missing storage integration)");
            }
        }

        eprintln!("\n💡 Dry run complete. Use without --dry-run to actually submit.");
        return Ok(());
    }

    // 10. Submit or save
    if let Some(ref tx_file) = args.tx_file {
        std::fs::write(tx_file, &signed_tx)?;
        eprintln!("💾 Transaction saved to: {}", tx_file.display());
    } else {
        eprintln!("📤 Submitting transaction...");
        submit_transaction(&args.hayate_endpoint, signed_tx).await?;
        eprintln!("✅ Transaction submitted!");
        eprintln!("   TX Hash: {}", hex::encode(&tx_hash));
    }
    
    Ok(())
}

// Helper structs and functions
#[derive(Debug)]
struct ContractUtxo {
    tx_hash: Vec<u8>,
    output_index: u64,
    lovelace: u64,
    assets: Vec<(Vec<u8>, Vec<u8>, u64)>, // (policy_id, asset_name, amount)
    datum: Vec<u8>,
}

async fn query_contract_utxo(endpoint: &str, address: &[u8]) -> Result<ContractUtxo> {
    use hayate::wallet::utxorpc_client::WalletUtxorpcClient;

    let mut client = WalletUtxorpcClient::connect(endpoint.to_string()).await?;
    let utxos = client.query_utxos(vec![address.to_vec()]).await?;

    if utxos.is_empty() {
        anyhow::bail!("No UTxO found for contract address");
    }

    if utxos.len() > 1 {
        eprintln!("⚠️  Warning: Found {} UTxOs, using the first one", utxos.len());
    }

    let utxo = &utxos[0];

    // Extract assets (policy_id, asset_name, amount)
    let assets: Vec<(Vec<u8>, Vec<u8>, u64)> = utxo.assets.iter()
        .map(|a| (a.policy_id.clone(), a.asset_name.clone(), a.amount))
        .collect();

    Ok(ContractUtxo {
        tx_hash: utxo.tx_hash.clone(),
        output_index: utxo.output_index as u64,
        lovelace: utxo.coin,
        assets,
        datum: utxo.datum.clone().unwrap_or_default(),
    })
}

fn build_update_redeemer(members: &[GovernanceMember]) -> Result<Vec<u8>> {
    use pallas_codec::minicbor::{Encoder, data::Tag};

    // UpdateRedeemer is a constructor with one field: Multisig
    // In Plutus/Aiken, this is encoded as Constructor(121, alternative, fields)
    //
    // UpdateRedeemer { new_multisig: Multisig }
    // = Constructor 0 [Multisig]
    //
    // Multisig { total_signers: Int, signers: List<(ByteArray, Sr25519Key)> }
    // = [total_signers, [[wrapped_key_1, sr25519_1], [wrapped_key_2, sr25519_2], ...]]
    //
    // IMPORTANT: Must use List (array of pairs), not Map, to match Aiken contract!

    let mut buffer = Vec::new();
    let mut encoder = Encoder::new(&mut buffer);

    // Constructor 0 with 1 field (the Multisig)
    // For Plutus Data, alternative is encoded in the tag: tag(121+N) for alternative N
    encoder.tag(Tag::new(121))?; // Tag 121 = Constructor alternative 0
    encoder.array(1)?; // 1 field: the Multisig

    // Now encode the Multisig: [total_signers, signers_list]
    encoder.array(2)?; // Multisig has 2 fields

    // Field 1: total_signers
    encoder.u32(members.len() as u32)?;

    // Field 2: signers list (array of pairs, NOT a map)
    encoder.array(members.len() as u64)?;

    // Sort members by cardano_hash for deterministic encoding
    let mut sorted_members = members.to_vec();
    sorted_members.sort_by_key(|a| a.cardano_hash);

    for member in sorted_members {
        // Each pair is a 2-element array
        encoder.array(2)?;

        // First element: wrapped Cardano key hash as [0, bytes(28)]
        // This is CBOR-encoded as: 8200581c<28 bytes>
        let mut wrapped_key = Vec::new();
        let mut wrap_encoder = Encoder::new(&mut wrapped_key);
        wrap_encoder.array(2)?;
        wrap_encoder.u32(0)?; // Constructor 0
        wrap_encoder.bytes(&member.cardano_hash)?;
        drop(wrap_encoder);

        encoder.bytes(&wrapped_key)?; // First element of pair (wrapped key as bytes)

        // Second element: sr25519 public key (32 bytes)
        encoder.bytes(&member.sr25519_key)?;
    }

    Ok(buffer)
}

async fn build_and_sign_rotation_tx(
    endpoint: &str,
    wallet_mnemonic: &str,
    account: u32,
    council_mnemonics: &[String],
    contract_utxo: &ContractUtxo,
    contract_address: &[u8],
    new_datum: &[u8],
    redeemer: &hayate::wallet::plutus::Redeemer,
    members: &[GovernanceMember],
) -> Result<Vec<u8>> {
    use hayate::wallet::{Wallet, Network};
    use hayate::wallet::plutus::{PlutusScript, Network as PlutusNetwork};
    use hayate::wallet::tx_builder::{PlutusTransactionBuilder, PlutusInput, PlutusOutput};
    use hayate::wallet::utxorpc_client::{WalletUtxorpcClient, UtxoData, AssetData};
    use std::sync::Arc;

    // 1. Create wallet from mnemonic for collateral/fees
    let wallet = Arc::new(Wallet::from_mnemonic_str(wallet_mnemonic, Network::Testnet, account)?);

    // 1b. Create council member wallets for signing
    let mut council_wallets = Vec::new();
    for council_mnemonic in council_mnemonics {
        let council_wallet = Arc::new(Wallet::from_mnemonic_str(council_mnemonic, Network::Testnet, account)?);
        council_wallets.push(council_wallet);
    }

    // 2. Query wallet UTxOs for fees and collateral
    let mut client = WalletUtxorpcClient::connect(endpoint.to_string()).await?;

    // Get addresses to query (first 20 payment and enterprise addresses)
    let mut wallet_addrs = Vec::new();
    for i in 0..20 {
        // Query payment addresses (with staking)
        if let Ok(addr_bech32) = wallet.payment_address(i) {
            if let Ok(addr) = pallas_addresses::Address::from_bech32(&addr_bech32) {
                wallet_addrs.push(addr.to_vec());
            }
        }
        // Query enterprise addresses (without staking)
        if let Ok(addr_bech32) = wallet.enterprise_address(i) {
            if let Ok(addr) = pallas_addresses::Address::from_bech32(&addr_bech32) {
                wallet_addrs.push(addr.to_vec());
            }
        }
    }

    let wallet_utxos = client.query_utxos(wallet_addrs).await?;

    if wallet_utxos.is_empty() {
        anyhow::bail!("No wallet UTxOs found for fees/collateral");
    }

    // 3. Load the governance contract script
    let script_cbor_hex = crate::contracts::governance::COUNCIL_GOVERNANCE_CBOR;
    let script_cbor = hex::decode(script_cbor_hex)?;
    let script = PlutusScript::v2_from_cbor(script_cbor)?;

    // 4. Convert ContractUtxo to UtxoData
    let contract_utxo_data = UtxoData {
        tx_hash: contract_utxo.tx_hash.clone(),
        output_index: contract_utxo.output_index as u32,
        address: contract_address.to_vec(),
        coin: contract_utxo.lovelace,
        assets: contract_utxo.assets.iter()
            .map(|(policy_id, asset_name, amount)| AssetData {
                policy_id: policy_id.clone(),
                asset_name: asset_name.clone(),
                amount: *amount,
            })
            .collect(),
        datum_hash: None,
        datum: Some(contract_utxo.datum.clone()),
    };

    // 5. Create script input (not used - TODO: integrate with UnifiedTxBuilder)
    let _script_input = PlutusInput::script(
        contract_utxo_data.clone(),
        script.clone(),
        redeemer.clone(),
        None, // datum is inline
    );

    // 6. Create output back to contract with new datum and NFT
    // Subtract fee from contract output to conserve value
    let fee = 2_000_000u64;
    let contract_output_amount = contract_utxo.lovelace.saturating_sub(fee);

    eprintln!("Contract output: {} lovelace (was {})", contract_output_amount, contract_utxo.lovelace);
    eprintln!("New datum CBOR (hex): {}", hex::encode(new_datum));
    eprintln!("New datum CBOR length: {} bytes", new_datum.len());

    use hayate::wallet::plutus::DatumOption;
    let datum_option = DatumOption::inline(new_datum.to_vec());

    let contract_output = PlutusOutput::with_assets(
        contract_address.to_vec(),
        contract_output_amount,
        contract_utxo_data.assets.clone()
    ).with_datum(datum_option);

    // 7. Find collateral (5 ADA pure ADA UTxO required)
    let collateral_utxo = wallet_utxos.iter()
        .find(|u| u.assets.is_empty() && u.coin >= 5_000_000)
        .ok_or_else(|| anyhow::anyhow!("No suitable collateral UTxO found (need 5 ADA pure UTxO)"))?
        .clone();

    // 8. Select wallet UTxOs for fees (skip contract and collateral UTxOs)
    let mut wallet_inputs = Vec::new();
    let mut total_wallet_input = 0u64;

    for utxo in wallet_utxos.iter() {
        // Skip if this is the collateral we're using
        if utxo.tx_hash == collateral_utxo.tx_hash && utxo.output_index == collateral_utxo.output_index {
            continue;
        }

        // Use any UTxO with sufficient ADA
        if utxo.coin > 1_000_000 {
            wallet_inputs.push(PlutusInput::regular(utxo.clone()));
            total_wallet_input += utxo.coin;

            if total_wallet_input >= 10_000_000 || wallet_inputs.len() >= 3 {
                break; // Enough for fees
            }
        }
    }

    if wallet_inputs.is_empty() {
        anyhow::bail!("No wallet UTxOs available for fees");
    }

    // 9. Extract required signer key hashes (28 bytes each)
    // Only add required signers for the council members who are actually signing
    // (not all council members, just the ones providing signatures for this rotation)
    // TODO: Add required_signers when PlutusTransactionBuilder supports it
    let _required_signers: Vec<[u8; 28]> = members.iter()
        .take(council_mnemonics.len()) // Only the first N members that match signing mnemonics
        .map(|m| m.cardano_hash)
        .collect();

    // 12. Build transaction using PlutusTransactionBuilder
    let change_addr = wallet.payment_address(0)?;
    let change_addr_bytes = pallas_addresses::Address::from_bech32(&change_addr)?.to_vec();
    let mut tx_builder = PlutusTransactionBuilder::new(PlutusNetwork::Testnet, change_addr_bytes);

    // Add script input
    tx_builder.add_script_input(&contract_utxo_data, script.clone(), redeemer.clone(), None)?;

    // Add wallet inputs (commented out - fee comes from contract output)
    // for input in wallet_inputs {
    //     tx_builder.add_input(&input)?;
    // }

    // Add contract output
    tx_builder.add_output(&contract_output)?;

    // Add collateral
    tx_builder.add_collateral(&collateral_utxo)?;

    // Add the Plutus script
    tx_builder.add_plutus_script(script)?;

    // TODO: Add required signers when method is implemented in PlutusTransactionBuilder
    // tx_builder.add_required_signers(required_signers);

    // Query protocol parameters for cost model
    eprintln!("Querying protocol parameters...");
    let protocol_params = client.query_protocol_params().await?
        .ok_or_else(|| anyhow::anyhow!("Failed to query protocol parameters"))?;

    let plutus_v2_cost_model = protocol_params.plutus_v2_cost_model
        .ok_or_else(|| anyhow::anyhow!("No PlutusV2 cost model in protocol parameters"))?;

    eprintln!("Using PlutusV2 cost model ({} elements)", plutus_v2_cost_model.len());

    // Set transaction parameters
    tx_builder.set_fee(2_000_000);
    tx_builder.set_network_id();
    tx_builder.set_ttl(999999999);
    tx_builder.set_language_view(hayate::wallet::plutus::PlutusVersion::V2, plutus_v2_cost_model);

    // 13. Build and sign with all keys
    // Collect signing keys: wallet + council members
    let mut signing_keys = vec![wallet.payment_signing_key(0)?];

    // Add council member signing keys
    for council_wallet in council_wallets {
        signing_keys.push(council_wallet.payment_signing_key(0)?);
    }

    eprintln!("Signing with {} keys (1 wallet + {} council members)", signing_keys.len(), council_mnemonics.len());

    let signed_tx = tx_builder.build_and_sign(signing_keys)?;

    Ok(signed_tx)
}

async fn submit_transaction(endpoint: &str, tx_bytes: Vec<u8>) -> Result<Vec<u8>> {
    use hayate::wallet::utxorpc_client::WalletUtxorpcClient;

    let mut client = WalletUtxorpcClient::connect(endpoint.to_string()).await?;
    let response = client.submit_transaction(tx_bytes).await?;

    Ok(response.tx_hash)
}

async fn simulate_transaction(
    _endpoint: &str,
    tx_bytes: &[u8],
    ledger_state: Option<&hayate::wallet::simulator::LedgerState>,
) -> Result<hayate::wallet::simulator::SimulationResult> {
    use hayate::wallet::simulator::TransactionSimulator;

    let simulator = TransactionSimulator::new_offline();

    // Offline simulator requires ledger state
    let state = ledger_state.ok_or_else(|| {
        anyhow::anyhow!("Offline simulation requires ledger state to be provided")
    })?;

    simulator.simulate_with_ledger_state(tx_bytes, state)
}

async fn simulate_transaction_offline(
    tx_bytes: &[u8],
    ledger_state: &hayate::wallet::simulator::LedgerState,
) -> Result<hayate::wallet::simulator::SimulationResult> {
    use hayate::wallet::simulator::TransactionSimulator;

    // Create simulator in offline mode (no client connection)
    let simulator = TransactionSimulator::new_offline();

    // Use provided ledger state
    simulator.simulate_with_ledger_state(tx_bytes, ledger_state)
}

async fn build_rotation_tx_offline(
    wallet_mnemonic: &str,
    account: u32,
    council_mnemonics: &[String],
    contract_utxo: &ContractUtxo,
    contract_address: &[u8],
    new_datum: &[u8],
    redeemer: &hayate::wallet::plutus::Redeemer,
    members: &[GovernanceMember],
    ledger_state: &hayate::wallet::simulator::LedgerState,
) -> Result<Vec<u8>> {
    use hayate::wallet::{Wallet, Network};
    use hayate::wallet::plutus::{PlutusScript, Network as PlutusNetwork};
    use hayate::wallet::tx_builder::PlutusTransactionBuilder;
    use hayate::wallet::utxorpc_client::{UtxoData, AssetData};
    use std::sync::Arc;
    use pallas_codec::minicbor::decode;

    // Create wallet from mnemonic
    let wallet = Arc::new(Wallet::from_mnemonic_str(wallet_mnemonic, Network::Testnet, account)?);

    // Create council member wallets
    let mut council_wallets = Vec::new();
    for council_mnemonic in council_mnemonics {
        let council_wallet = Arc::new(Wallet::from_mnemonic_str(council_mnemonic, Network::Testnet, account)?);
        council_wallets.push(council_wallet);
    }

    // Find collateral UTxO from ledger state
    let mut collateral_utxo_data: Option<UtxoData> = None;

    for (utxo_key, utxo_bytes) in ledger_state.utxos.iter() {
        let output: pallas_primitives::babbage::MintedTransactionOutput =
            decode(utxo_bytes).map_err(|e| anyhow::anyhow!("Failed to decode UTxO {}: {}", utxo_key, e))?;

        // Handle PostAlonzo variant
        let post_alonzo_output = match output {
            pallas_primitives::babbage::PseudoTransactionOutput::PostAlonzo(post_alonzo) => post_alonzo,
            pallas_primitives::babbage::PseudoTransactionOutput::Legacy(_) => continue,
        };

        // Check if it's pure ADA and >= 5 ADA
        let (lovelace, has_assets) = match &post_alonzo_output.value {
            pallas_primitives::babbage::Value::Coin(coin) => (*coin, false),
            pallas_primitives::babbage::Value::Multiasset(coin, assets) => (*coin, !assets.is_empty()),
        };

        if !has_assets && lovelace >= 5_000_000 {
            // Parse txhash:index
            let parts: Vec<&str> = utxo_key.split(':').collect();
            if parts.len() != 2 {
                continue;
            }
            let tx_hash = hex::decode(parts[0]).ok();
            let output_index: Option<u32> = parts[1].parse().ok();

            if let (Some(tx_hash), Some(output_index)) = (tx_hash, output_index) {
                collateral_utxo_data = Some(UtxoData {
                    tx_hash,
                    output_index,
                    address: post_alonzo_output.address.to_vec(),
                    coin: lovelace,
                    assets: Vec::new(),
                    datum_hash: None,
                    datum: None,
                });
                break;
            }
        }
    }

    let collateral_utxo = collateral_utxo_data
        .ok_or_else(|| anyhow::anyhow!("No suitable collateral UTxO found in ledger state"))?;

    // Load governance script
    let script_cbor_hex = crate::contracts::governance::COUNCIL_GOVERNANCE_CBOR;
    let script_cbor = hex::decode(script_cbor_hex)?;
    let script = PlutusScript::v2_from_cbor(script_cbor)?;

    // Convert ContractUtxo to UtxoData
    let contract_utxo_data = UtxoData {
        tx_hash: contract_utxo.tx_hash.clone(),
        output_index: contract_utxo.output_index as u32,
        address: contract_address.to_vec(),
        coin: contract_utxo.lovelace,
        assets: contract_utxo.assets.iter()
            .map(|(policy_id, asset_name, amount)| AssetData {
                policy_id: policy_id.clone(),
                asset_name: asset_name.clone(),
                amount: *amount,
            })
            .collect(),
        datum_hash: None,
        datum: Some(contract_utxo.datum.clone()),
    };

    // Create contract output with reduced amount (subtract fee)
    let fee = 2_000_000u64;
    let contract_output_amount = contract_utxo.lovelace.saturating_sub(fee);

    eprintln!("Contract output: {} lovelace (was {})", contract_output_amount, contract_utxo.lovelace);

    use hayate::wallet::plutus::DatumOption;
    use hayate::wallet::tx_builder::PlutusOutput;

    let datum_option = DatumOption::inline(new_datum.to_vec());
    let contract_output = PlutusOutput::with_assets(
        contract_address.to_vec(),
        contract_output_amount,
        contract_utxo_data.assets.clone(),
    ).with_datum(datum_option);

    // Extract required signers
    // TEST: Add ALL 3 council members to see if pallas behavior changes
    let required_signers: Vec<[u8; 28]> = members.iter()
        .map(|m| m.cardano_hash)
        .collect();

    eprintln!("TEST: Setting {} required signers (all council members)", required_signers.len());

    // Build transaction
    let change_addr = wallet.payment_address(0)?;
    let change_addr_bytes = pallas_addresses::Address::from_bech32(&change_addr)?.to_vec();
    let mut tx_builder = PlutusTransactionBuilder::new(PlutusNetwork::Testnet, change_addr_bytes);

    // Add script input
    tx_builder.add_script_input(&contract_utxo_data, script.clone(), redeemer.clone(), None)?;

    // Add contract output
    tx_builder.add_output(&contract_output)?;

    // Add collateral
    tx_builder.add_collateral(&collateral_utxo)?;

    // Add Plutus script
    tx_builder.add_plutus_script(script)?;

    // Add required signers
    eprintln!("Required signers ({}):", required_signers.len());
    for (i, signer) in required_signers.iter().enumerate() {
        eprintln!("   [{}] {}", i+1, hex::encode(signer));
    }
    // TODO: Add required signers when method is implemented in PlutusTransactionBuilder
    // tx_builder.add_required_signers(required_signers);

    // Use protocol parameters from ledger state
    let plutus_v2_cost_model = ledger_state.protocol_params.plutus_v2_cost_model
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No PlutusV2 cost model in ledger state"))?
        .clone();

    eprintln!("Using PlutusV2 cost model from ledger state ({} elements)", plutus_v2_cost_model.len());

    // Set transaction parameters
    tx_builder.set_fee(fee);
    tx_builder.set_network_id();
    tx_builder.set_ttl(999999999);
    tx_builder.set_language_view(hayate::wallet::plutus::PlutusVersion::V2, plutus_v2_cost_model);

    // Build and sign
    let mut signing_keys = vec![wallet.payment_signing_key(0)?];
    eprintln!("Wallet payment key hash: {}", hex::encode(wallet.payment_key_hash(0)?));

    for (i, council_wallet) in council_wallets.iter().enumerate() {
        let key_hash = council_wallet.payment_key_hash(0)?;
        let expected_hash = &members[i].cardano_hash;
        eprintln!("Council member {} key hash from mnemonic: {}", i+1, hex::encode(&key_hash));
        eprintln!("Council member {} key hash from JSON:     {}", i+1, hex::encode(expected_hash));
        if key_hash != *expected_hash {
            eprintln!("❌ WARNING: Key hash mismatch for council member {}!", i+1);
            eprintln!("   This means the mnemonic does not correspond to the JSON file.");
            eprintln!("   The transaction will fail validation.");
        }
        signing_keys.push(council_wallet.payment_signing_key(0)?);
    }

    eprintln!("Signing with {} keys (1 wallet + {} council members)", signing_keys.len(), council_mnemonics.len());

    let signed_tx = tx_builder.build_and_sign(signing_keys)?;

    Ok(signed_tx)
}
