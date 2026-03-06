use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Subcommand)]
pub enum GenesisCommands {
    /// Initialize genesis configuration from aggregated keys
    Init(GenesisInitArgs),
    /// Generate cNight (Cardano bridge) genesis configuration
    Cnight(CnightGenesisArgs),
    /// Export network specs as QR code for Polkadot Vault
    ExportNetwork(ExportNetworkArgs),
}

#[derive(Args)]
pub struct GenesisInitArgs {
    /// Path to individual validator JSON file (can be specified multiple times)
    #[arg(long = "validator")]
    pub validators: Vec<PathBuf>,

    /// Path to Technical Advisory (TA) governance key JSON file (can be specified multiple times)
    #[arg(long = "ta")]
    pub ta_members: Vec<PathBuf>,

    /// Path to Council governance key JSON file (can be specified multiple times)
    #[arg(long = "council")]
    pub council_members: Vec<PathBuf>,

    /// Chain ID for the network
    #[arg(long, default_value = "sanchonight")]
    pub chain_id: String,

    /// Output file for genesis configuration
    #[arg(long, default_value = "genesis.json")]
    pub output: PathBuf,

    /// Policy ID for the $NIGHT token (hex-encoded)
    #[arg(long)]
    pub night_policy_id: Option<String>,

    /// UTxORPC endpoint (e.g., http://localhost:50051) to query policy ID block info
    #[arg(long)]
    pub utxorpc: Option<String>,

    /// Directory for chainspec config files and final chain-spec.json
    #[arg(long, default_value = "chainspec")]
    pub chainspec_dir: PathBuf,

    /// Path to midnight-node res directory (containing genesis files)
    #[arg(long)]
    pub midnight_node_res: Option<PathBuf>,
}

#[derive(Args)]
pub struct CnightGenesisArgs {
    /// Path to genesis.json file
    #[arg(long)]
    pub genesis: PathBuf,

    /// Mapping validator Cardano address (addr_test1...)
    #[arg(long)]
    pub mapping_validator: Option<String>,

    /// Redemption validator Cardano address (addr_test1...)
    #[arg(long)]
    pub redemption_validator: Option<String>,

    /// Auth token asset name (hex-encoded, empty for script hash only)
    #[arg(long)]
    pub auth_token_asset_name: Option<String>,

    /// cNight asset name (ASCII, e.g., "SNIGHT")
    #[arg(long)]
    pub cnight_asset_name: Option<String>,

    /// Output file for cNight genesis configuration
    #[arg(long, default_value = "cnight-genesis.json")]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ExportNetworkArgs {
    /// Path to chain-spec.json file
    #[arg(long)]
    pub chainspec: PathBuf,

    /// Output PNG file (if not specified, prints to stdout)
    #[arg(long)]
    pub out_file: Option<PathBuf>,

    /// Signing key for network specs (mnemonic or derivation path)
    #[arg(long)]
    pub signer_mnemonic: Option<String>,

    /// Path to mnemonic file for signing
    #[arg(long)]
    pub signer_mnemonic_file: Option<PathBuf>,

    /// Network display name (overrides chainspec name)
    #[arg(long)]
    pub name: Option<String>,

    /// Token decimals (default: 18)
    #[arg(long, default_value = "18")]
    pub decimals: u8,

    /// Token unit/symbol (default: NIGHT)
    #[arg(long, default_value = "NIGHT")]
    pub unit: String,

    /// SS58 address format (default: 42 for generic Substrate)
    #[arg(long, default_value = "42")]
    pub ss58_format: u16,

    /// Network color for UI (hex format like #FF5733)
    #[arg(long, default_value = "#6f42c1")]
    pub color: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorKeysInput {
    pub node_key: KeyData,
    pub aura_key: KeyData,
    pub grandpa_key: KeyData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootnode: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyData {
    pub key_type: String,
    pub public_key_hex: String,
    pub ss58_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GovernanceKeyInput {
    pub key_type: String,
    pub public_key_hex: String,
    pub ss58_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub chain_id: String,
    pub validators: Vec<ValidatorConfig>,
    pub governance: GovernanceConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub night_token: Option<NightTokenConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NightTokenConfig {
    pub policy_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorConfig {
    pub node_id: String,
    pub aura: String,
    pub grandpa: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GovernanceConfig {
    pub council: Vec<String>,
    pub technical_committee: Vec<String>,
}

/// Check if midnight-node is available in PATH
fn check_midnight_node() -> Result<()> {
    let output = Command::new("midnight-node")
        .arg("--version")
        .output();

    match output {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "midnight-node not found in PATH.\n\n\
                Please ensure midnight-node is installed and added to your PATH:\n\
                  export PATH=\"$PATH:/path/to/midnight-node/bin\"\n\n\
                Or install it from: https://github.com/input-output-hk/midnight-node"
            );
        }
        Err(e) => Err(e).context("Failed to execute midnight-node"),
    }
}

/// Convert SS58 address to hex public key
/// Uses sp-core's built-in SS58 decoding
fn ss58_to_hex(ss58: &str) -> Result<String> {
    use sp_core::crypto::Ss58Codec;

    // Try to decode as sr25519 public key
    match sp_core::sr25519::Public::from_ss58check(ss58) {
        Ok(pubkey) => {
            let bytes: &[u8] = pubkey.as_ref();
            let hex = hex::encode(bytes);
            Ok(format!("0x{}", hex))
        }
        Err(e) => {
            anyhow::bail!("Failed to decode SS58 address '{}': {}", ss58, e);
        }
    }
}

pub async fn handle_genesis_command(cmd: GenesisCommands) -> Result<()> {
    match cmd {
        GenesisCommands::Init(args) => handle_genesis_init(args).await,
        GenesisCommands::Cnight(args) => handle_cnight_genesis(args),
        GenesisCommands::ExportNetwork(args) => handle_export_network(args),
    }
}

async fn handle_genesis_init(args: GenesisInitArgs) -> Result<()> {
    // Check midnight-node is available
    eprintln!("🔍 Checking for midnight-node in PATH...");
    check_midnight_node()?;
    eprintln!("✓ Found midnight-node\n");

    // Ensure we have at least one validator
    if args.validators.is_empty() {
        anyhow::bail!("At least one validator must be specified (use --validator <file>)");
    }

    // Ensure we have at least one TA member
    if args.ta_members.is_empty() {
        anyhow::bail!("At least one TA member must be specified (use --ta <file>)");
    }

    // Ensure we have at least one Council member
    if args.council_members.is_empty() {
        anyhow::bail!("At least one Council member must be specified (use --council <file>)");
    }

    // Create chainspec directory
    fs::create_dir_all(&args.chainspec_dir)
        .with_context(|| format!("Failed to create chainspec directory: {}", args.chainspec_dir.display()))?;

    // Read and parse all validator files
    let mut validators: Vec<ValidatorKeysInput> = Vec::new();
    for validator_path in &args.validators {
        let validator_json = fs::read_to_string(validator_path)
            .with_context(|| format!("Failed to read validator file: {}", validator_path.display()))?;

        let validator: ValidatorKeysInput = serde_json::from_str(&validator_json)
            .with_context(|| format!("Failed to parse validator JSON from: {}", validator_path.display()))?;

        validators.push(validator);
    }

    // Read and parse all TA member files
    let mut ta_keys: Vec<GovernanceKeyInput> = Vec::new();
    for ta_path in &args.ta_members {
        let ta_json = fs::read_to_string(ta_path)
            .with_context(|| format!("Failed to read TA governance file: {}", ta_path.display()))?;

        let ta_key: GovernanceKeyInput = serde_json::from_str(&ta_json)
            .with_context(|| format!("Failed to parse TA governance JSON from: {}", ta_path.display()))?;

        ta_keys.push(ta_key);
    }

    // Read and parse all Council member files
    let mut council_keys: Vec<GovernanceKeyInput> = Vec::new();
    for council_path in &args.council_members {
        let council_json = fs::read_to_string(council_path)
            .with_context(|| format!("Failed to read Council governance file: {}", council_path.display()))?;

        let council_key: GovernanceKeyInput = serde_json::from_str(&council_json)
            .with_context(|| format!("Failed to parse Council governance JSON from: {}", council_path.display()))?;

        council_keys.push(council_key);
    }

    // Build genesis config
    let validator_configs: Vec<ValidatorConfig> = validators
        .iter()
        .map(|v| ValidatorConfig {
            node_id: v.node_key.public_key_hex.clone(),
            aura: v.aura_key.public_key_hex.clone(),
            grandpa: v.grandpa_key.public_key_hex.clone(),
        })
        .collect();

    let ta_addresses: Vec<String> = ta_keys
        .iter()
        .map(|g| g.ss58_address.clone())
        .collect();

    let council_addresses: Vec<String> = council_keys
        .iter()
        .map(|g| g.ss58_address.clone())
        .collect();

    let night_token = args.night_policy_id.as_ref().map(|policy_id| NightTokenConfig {
        policy_id: policy_id.clone(),
    });

    let genesis_config = GenesisConfig {
        chain_id: args.chain_id.clone(),
        validators: validator_configs,
        governance: GovernanceConfig {
            council: council_addresses,
            technical_committee: ta_addresses,
        },
        night_token,
    };

    // Write genesis config
    let genesis_json = serde_json::to_string_pretty(&genesis_config)?;
    fs::write(&args.output, genesis_json)?;

    eprintln!("✓ Genesis configuration created:");
    eprintln!("  Chain ID:              {}", args.chain_id);
    eprintln!("  Validators:            {}", genesis_config.validators.len());
    eprintln!("  Technical Committee:   {}", genesis_config.governance.technical_committee.len());
    eprintln!("  Council:               {}", genesis_config.governance.council.len());
    if let Some(ref night) = genesis_config.night_token {
        eprintln!("  $NIGHT:                {}", night.policy_id);
    }
    eprintln!();
    eprintln!("✓ Genesis written to: {}", args.output.display());
    eprintln!();

    // Now generate chainspec config files
    eprintln!("📝 Generating chainspec configuration files...");

    generate_chainspec_configs(&args, &genesis_config, &validators).await?;

    eprintln!("✓ Chainspec configs written to: {}", args.chainspec_dir.display());
    eprintln!();

    // Run midnight-node build-spec
    eprintln!("🔨 Building chain specification with midnight-node...");

    build_chain_spec(&args, &genesis_config)?;

    eprintln!();
    eprintln!("✅ Complete! Chain specification ready:");
    eprintln!("   {}/chain-spec.json", args.chainspec_dir.display());
    eprintln!();
    eprintln!("To run a validator node with this chain spec:");
    eprintln!("  midnight-node \\");
    eprintln!("    --chain {}/chain-spec.json \\", args.chainspec_dir.display());
    eprintln!("    --base-path <data-directory> \\");
    eprintln!("    --validator \\");
    eprintln!("    --keystore-path <keystore-directory> \\");
    eprintln!("    --name \"<node-name>\" \\");
    eprintln!("    --rpc-port 9944");

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CnightGenesisConfig {
    /// Reference to the base genesis configuration
    pub genesis_hash: Option<String>,

    /// Cardano validator addresses for cNight operations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping_validator_address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub redemption_validator_address: Option<String>,

    /// Auth token configuration (policy ID is derived from mapping validator script hash)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token_asset_name: Option<String>,

    /// cNight token asset name (ASCII)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnight_asset_name: Option<String>,
}

/// Generate all chainspec configuration files
async fn generate_chainspec_configs(
    args: &GenesisInitArgs,
    genesis: &GenesisConfig,
    validators_input: &[ValidatorKeysInput],
) -> Result<()> {
    let chainspec_dir = &args.chainspec_dir;

    // Get first validator data
    let validator = genesis.validators.first()
        .ok_or_else(|| anyhow::anyhow!("No validators in genesis config"))?;

    // Collect bootnodes from all validators
    let bootnodes: Vec<String> = validators_input
        .iter()
        .filter_map(|v| v.bootnode.clone())
        .collect();

    // Convert council and TA SS58 addresses to hex
    let council_hex: Vec<String> = genesis.governance.council.iter()
        .map(|addr| ss58_to_hex(addr))
        .collect::<Result<Vec<_>>>()?;

    let ta_hex: Vec<String> = genesis.governance.technical_committee.iter()
        .map(|addr| ss58_to_hex(addr))
        .collect::<Result<Vec<_>>>()?;

    let night_policy_id = genesis.night_token.as_ref()
        .map(|n| {
            let policy = n.policy_id.trim_start_matches("0x");
            // Cardano policy IDs are 28 bytes (56 hex characters), not 32 bytes
            if policy.len() > 56 {
                policy[..56].to_string()
            } else if policy.len() < 56 {
                format!("{:0<56}", policy) // Pad with zeros if too short
            } else {
                policy.to_string()
            }
        })
        .unwrap_or_else(|| "00000000000000000000000000000000000000000000000000000000".to_string());

    // 1. permissioned-candidates-config.json
    let permissioned_candidates = json!({
        "permissioned_candidates_policy_id": "0x00000000000000000000000000000000000000000000000000000000",
        "initial_permissioned_candidates": [{
            "aura_pub_key": format!("0x{}", validator.aura),
            "grandpa_pub_key": format!("0x{}", validator.grandpa),
            "sidechain_pub_key": format!("0x02{}", validator.node_id),
            "beefy_pub_key": format!("0x02{}", validator.node_id)
        }]
    });
    fs::write(
        chainspec_dir.join("permissioned-candidates-config.json"),
        serde_json::to_string_pretty(&permissioned_candidates)?
    )?;

    // 2. federated-authority-config.json
    let federated_authority = json!({
        "council": {
            "address": "addr_test1wq3zc4tj95nd22lgag4nhcjjmapl728wayyml375us60engf2ffwh",
            "policy_id": "222c55722d26d52be8ea2b3be252df43ff28eee909bfc7d4e434fccd",
            "members": council_hex,
            "members_mainchain": []
        },
        "technical_committee": {
            "address": "addr_test1wq5sw7ukk9c0h5vfd9g72pyz6l9vvhz3ly245c3ph6hhwxsgd44za",
            "policy_id": "29077b96b170fbd1896951e50482d7cac65c51f9155a6221beaf771a",
            "members": ta_hex,
            "members_mainchain": []
        }
    });
    fs::write(
        chainspec_dir.join("federated-authority-config.json"),
        serde_json::to_string_pretty(&federated_authority)?
    )?;

    // Query UTxORPC for policy ID block info if endpoint provided
    let (block_hash_hex, block_number, block_timestamp, tx_index) = if let Some(ref utxorpc_endpoint) = args.utxorpc {
        if let Some(policy_id) = genesis.night_token.as_ref().map(|t| &t.policy_id) {
            eprintln!("🔍 Querying UTxORPC endpoint for policy ID block info...");
            match crate::utxorpc::query_policy_id_block(utxorpc_endpoint, policy_id).await {
                Ok((block_hash, slot, timestamp, tx_idx)) => {
                    let block_hash_hex = format!("0x{}", hex::encode(&block_hash));
                    eprintln!("✓ Found policy ID in block:");
                    eprintln!("  Block hash:      {}", block_hash_hex);
                    eprintln!("  Slot:            {}", slot);
                    eprintln!("  Timestamp:       {}", timestamp);
                    eprintln!("  TX index:        {}", tx_idx);
                    eprintln!();
                    (block_hash_hex, slot, timestamp, tx_idx)
                }
                Err(e) => {
                    eprintln!("⚠️  Failed to query UTxORPC endpoint: {}", e);
                    eprintln!("   Using default zero values for cnight-config.json");
                    eprintln!();
                    ("0x0000000000000000000000000000000000000000000000000000000000000000".to_string(), 0, 0, 0)
                }
            }
        } else {
            eprintln!("⚠️  UTxORPC endpoint provided but no policy ID specified");
            eprintln!("   Using default zero values for cnight-config.json");
            eprintln!();
            ("0x0000000000000000000000000000000000000000000000000000000000000000".to_string(), 0, 0, 0)
        }
    } else {
        ("0x0000000000000000000000000000000000000000000000000000000000000000".to_string(), 0, 0, 0)
    };

    // 3. cnight-config.json
    let cnight_config = json!({
        "addresses": {
            "mapping_validator_address": "addr_test1wplxjzranravtp574s2wz00md7vz9rzpucu252je68u9a8qzjheng",
            "auth_token_asset_name": "",
            "cnight_policy_id": night_policy_id,
            "cnight_asset_name": ""
        },
        "observed_utxos": {
            "start": {
                "block_hash": block_hash_hex,
                "block_number": block_number,
                "block_timestamp": block_timestamp,
                "tx_index_in_block": tx_index
            },
            "end": {
                "block_hash": block_hash_hex,
                "block_number": block_number,
                "block_timestamp": block_timestamp,
                "tx_index_in_block": tx_index
            },
            "utxos": []
        },
        "mappings": {},
        "utxo_owners": {},
        "next_cardano_position": {
            "block_hash": block_hash_hex,
            "block_number": block_number,
            "block_timestamp": block_timestamp,
            "tx_index_in_block": tx_index
        },
        "system_tx": null
    });
    fs::write(
        chainspec_dir.join("cnight-config.json"),
        serde_json::to_string_pretty(&cnight_config)?
    )?;

    // 4. ics-config.json
    let ics_config = json!({
        "illiquid_circulation_supply_validator_address": "addr_test1wzeqa6xrntxk4c27xsac4jsajf66q7csxzlpn5hk5682d0g0u73rd",
        "asset": {
            "policy_id": format!("0x{}", night_policy_id),
            "asset_name": ""
        },
        "utxos": [],
        "total_amount": 0
    });
    fs::write(
        chainspec_dir.join("ics-config.json"),
        serde_json::to_string_pretty(&ics_config)?
    )?;

    // 5. reserve-config.json
    let reserve_config = json!({
        "reserve_validator_address": "addr_test1wz6h9v3yqeqgr70kqpaxe9euv2g7uf9sq0tqu8alwqp46usyw3pg6",
        "asset": {
            "policy_id": night_policy_id,
            "asset_name": ""
        },
        "utxos": [],
        "total_amount": 0
    });
    fs::write(
        chainspec_dir.join("reserve-config.json"),
        serde_json::to_string_pretty(&reserve_config)?
    )?;

    // 6. pc-chain-config.json
    let pc_chain_config = json!({
        "bootnodes": bootnodes,
        "chain_parameters": {
            "genesis_utxo": "0000000000000000000000000000000000000000000000000000000000000000#0"
        },
        "cardano": {
            "security_parameter": 432,
            "active_slots_coeff": 0.05,
            "first_epoch_number": 0,
            "first_slot_number": 0,
            "epoch_duration_millis": 86400000_i64,
            "first_epoch_timestamp_millis": 1666656000000_i64,
            "slot_duration_millis": 1000
        },
        "initial_permissioned_candidates": [{
            "aura_pub_key": format!("0x{}", validator.aura),
            "grandpa_pub_key": format!("0x{}", validator.grandpa),
            "sidechain_pub_key": format!("0x02{}", validator.node_id),
            "beefy_pub_key": format!("0x02{}", validator.node_id)
        }]
    });
    fs::write(
        chainspec_dir.join("pc-chain-config.json"),
        serde_json::to_string_pretty(&pc_chain_config)?
    )?;

    // 7. system-parameters-config.json
    let system_parameters = json!({
        "terms_and_conditions": {
            "hash": "0xca85ed77bce68288e55300f006ccd5cce5d4940dc39fc41173a9c2ecd1eb616e",
            "url": "https://www.midnight.gd/global-terms-txt"
        },
        "d_parameter": {
            "num_permissioned_candidates": 1,
            "num_registered_candidates": 0
        }
    });
    fs::write(
        chainspec_dir.join("system-parameters-config.json"),
        serde_json::to_string_pretty(&system_parameters)?
    )?;

    // 8. registered-candidates-addresses.json
    let registered_candidates = json!({
        "committee_candidates_address": "addr_test1wr4zpkfvylru9y3zahezf6vvfz7hlhf2pa4h9vxq70xwqzszre3qk"
    });
    fs::write(
        chainspec_dir.join("registered-candidates-addresses.json"),
        serde_json::to_string_pretty(&registered_candidates)?
    )?;

    Ok(())
}

/// Build chain spec using midnight-node
fn build_chain_spec(args: &GenesisInitArgs, genesis: &GenesisConfig) -> Result<()> {
    let chainspec_dir = &args.chainspec_dir;

    // Determine midnight-node res directory
    let midnight_node_res = if let Some(ref res) = args.midnight_node_res {
        res.clone()
    } else {
        // Try to find it in common locations
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let candidates = vec![
            PathBuf::from(format!("{}/work/iohk/midnight-node/res", home)),
            PathBuf::from("/opt/midnight-node/res"),
            PathBuf::from("./midnight-node/res"),
        ];

        candidates.into_iter()
            .find(|p| p.join("genesis/genesis_state_undeployed.mn").exists())
            .ok_or_else(|| anyhow::anyhow!(
                "Could not find midnight-node res directory.\n\
                Please specify it with --midnight-node-res <path>\n\
                or ensure it exists at ~/work/iohk/midnight-node/res"
            ))?
    };

    // Verify genesis files exist
    let genesis_state = midnight_node_res.join("genesis/genesis_state_undeployed.mn");
    let genesis_block = midnight_node_res.join("genesis/genesis_block_undeployed.mn");

    if !genesis_state.exists() {
        anyhow::bail!("Genesis state file not found: {}", genesis_state.display());
    }
    if !genesis_block.exists() {
        anyhow::bail!("Genesis block file not found: {}", genesis_block.display());
    }

    // Convert chainspec_dir to absolute path for environment variables
    let chainspec_abs = std::fs::canonicalize(chainspec_dir)
        .context("Failed to get absolute path for chainspec-dir")?;

    // midnight-node needs to run from its repository root (where res/ dir exists)
    // Find the midnight-node directory by going up from the res path
    let midnight_node_dir = midnight_node_res.parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid midnight-node-res path"))?;

    // Build the command with environment variables
    let output = Command::new("midnight-node")
        .arg("build-spec")
        .arg("--disable-default-bootnode")
        .current_dir(midnight_node_dir)
        .env("CHAINSPEC_NAME", &genesis.chain_id)
        .env("CHAINSPEC_ID", &genesis.chain_id)
        .env("CHAINSPEC_NETWORK_ID", &genesis.chain_id)
        .env("CHAINSPEC_GENESIS_STATE", genesis_state)
        .env("CHAINSPEC_GENESIS_BLOCK", genesis_block)
        .env("CHAINSPEC_CHAIN_TYPE", "live")
        .env("CHAINSPEC_PC_CHAIN_CONFIG", chainspec_abs.join("pc-chain-config.json"))
        .env("CHAINSPEC_CNIGHT_GENESIS", chainspec_abs.join("cnight-config.json"))
        .env("CHAINSPEC_ICS_CONFIG", chainspec_abs.join("ics-config.json"))
        .env("CHAINSPEC_RESERVE_CONFIG", chainspec_abs.join("reserve-config.json"))
        .env("CHAINSPEC_FEDERATED_AUTHORITY_CONFIG", chainspec_abs.join("federated-authority-config.json"))
        .env("CHAINSPEC_SYSTEM_PARAMETERS_CONFIG", chainspec_abs.join("system-parameters-config.json"))
        .env("CHAINSPEC_PERMISSIONED_CANDIDATES_CONFIG", chainspec_abs.join("permissioned-candidates-config.json"))
        .env("CHAINSPEC_REGISTERED_CANDIDATES_ADDRESSES", chainspec_abs.join("registered-candidates-addresses.json"))
        .env("USE_UTXORPC", "false")
        .output()
        .context("Failed to execute midnight-node build-spec")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("midnight-node build-spec failed:\n{}", stderr);
    }

    // Write the chain spec output
    let chain_spec_path = chainspec_dir.join("chain-spec.json");
    fs::write(&chain_spec_path, &output.stdout)
        .context("Failed to write chain-spec.json")?;

    eprintln!("✓ Chain spec built: {}", chain_spec_path.display());

    Ok(())
}

fn handle_cnight_genesis(args: CnightGenesisArgs) -> Result<()> {
    // Read the base genesis file to validate it exists
    let genesis_json = fs::read_to_string(&args.genesis)
        .with_context(|| format!("Failed to read genesis file: {}", args.genesis.display()))?;

    let _genesis_config: GenesisConfig = serde_json::from_str(&genesis_json)
        .with_context(|| "Failed to parse genesis.json")?;

    // Calculate genesis hash (simple SHA256 of the file content)
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(genesis_json.as_bytes());
    let genesis_hash = format!("{:x}", hasher.finalize());

    // Build cNight genesis config
    let cnight_config = CnightGenesisConfig {
        genesis_hash: Some(genesis_hash.clone()),
        mapping_validator_address: args.mapping_validator,
        redemption_validator_address: args.redemption_validator,
        auth_token_asset_name: args.auth_token_asset_name,
        cnight_asset_name: args.cnight_asset_name,
    };

    // Write cNight genesis config
    let cnight_json = serde_json::to_string_pretty(&cnight_config)?;
    fs::write(&args.output, cnight_json)?;

    println!("✓ cNight genesis configuration created:");
    println!("  Genesis hash:    {}", genesis_hash);
    if let Some(ref addr) = cnight_config.mapping_validator_address {
        println!("  Mapping validator:    {}", addr);
    }
    if let Some(ref addr) = cnight_config.redemption_validator_address {
        println!("  Redemption validator: {}", addr);
    }
    if let Some(ref name) = cnight_config.auth_token_asset_name {
        println!("  Auth token name:      {}", if name.is_empty() { "(script hash only)" } else { name });
    }
    if let Some(ref name) = cnight_config.cnight_asset_name {
        println!("  cNight asset name:    {}", name);
    }
    println!();
    println!("✓ cNight genesis written to: {}", args.output.display());

    Ok(())
}

use parity_scale_codec::{Encode, Decode};

/// Encryption algorithm enum for Polkadot Vault
#[derive(Debug, Clone, Encode, Decode)]
#[repr(u8)]
enum Encryption {
    Ed25519 = 0,
    Sr25519 = 1,
    Ecdsa = 2,
    Ethereum = 3,
}

/// Network specifications for Polkadot Vault (SCALE-encoded)
/// Field order matters for SCALE encoding!
#[derive(Debug, Clone, Encode, Decode)]
struct NetworkSpecs {
    /// Base58 prefix (SS58 format identifier)
    base58prefix: u16,
    /// Network color (hex string like "#6f42c1")
    color: String,
    /// Token decimals
    decimals: u8,
    /// Encryption algorithm
    encryption: Encryption,
    /// Genesis hash (32 bytes)
    genesis_hash: [u8; 32],
    /// Logo asset identifier (empty string if none)
    logo: String,
    /// Network name from metadata
    name: String,
    /// Default derivation path (empty string for default)
    path_id: String,
    /// Secondary UI color (empty string if none)
    secondary_color: String,
    /// User-facing display name
    title: String,
    /// Token symbol
    unit: String,
}

fn handle_export_network(args: ExportNetworkArgs) -> Result<()> {
    use sha2::{Sha256, Digest};
    use sp_core::crypto::Ss58Codec;
    use parity_scale_codec::Encode;
    use crate::storage::KeyReader;
    use secrecy::ExposeSecret;

    eprintln!("📖 Reading chainspec file...");

    // Read chainspec file
    let chainspec_json = fs::read_to_string(&args.chainspec)
        .with_context(|| format!("Failed to read chainspec file: {}", args.chainspec.display()))?;

    let chainspec: serde_json::Value = serde_json::from_str(&chainspec_json)
        .context("Failed to parse chainspec JSON")?;

    // Extract network information
    let network_name = args.name.unwrap_or_else(|| {
        chainspec.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown Network")
            .to_string()
    });

    let chain_id = chainspec.get("id")
        .and_then(|v| v.as_str())
        .unwrap_or(&network_name);

    // Calculate genesis hash from genesis field
    let genesis_hash_bytes = if let Some(genesis) = chainspec.get("genesis") {
        // Hash the genesis object
        let genesis_bytes = serde_json::to_vec(genesis)?;
        let mut hasher = Sha256::new();
        hasher.update(&genesis_bytes);
        let hash_vec = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_vec[..]);
        hash_array
    } else {
        anyhow::bail!("Chainspec does not contain genesis field");
    };

    let genesis_hash_hex = format!("0x{}", hex::encode(genesis_hash_bytes));

    eprintln!("✓ Chainspec loaded:");
    eprintln!("  Name:          {}", network_name);
    eprintln!("  Chain ID:      {}", chain_id);
    eprintln!("  Genesis hash:  {}", genesis_hash_hex);
    eprintln!("  SS58 format:   {}", args.ss58_format);
    eprintln!("  Token:         {} (decimals: {})", args.unit, args.decimals);
    eprintln!();

    // Build network specs using SCALE encoding format
    // Build default values matching Polkadot Vault expectations
    let logo = chain_id.to_string(); // Use chain_id as logo identifier
    let path_id = "//midnight".to_string(); // Default derivation path
    let secondary_color = "#262626".to_string(); // Dark gray as secondary color

    let network_specs = NetworkSpecs {
        base58prefix: args.ss58_format,
        color: args.color.clone(),
        decimals: args.decimals,
        encryption: Encryption::Sr25519,
        genesis_hash: genesis_hash_bytes,
        logo,
        name: chain_id.to_string(),
        path_id,
        secondary_color,
        title: network_name.clone(),
        unit: args.unit.clone(),
    };

    // SCALE-encode the NetworkSpecs
    let encoded_specs = network_specs.encode();

    // Create payload with SCALE compact length prefix
    // This is what Polkadot Vault expects: compact_length + SCALE_encoded_data
    use parity_scale_codec::Compact;
    let payload_len = Compact(encoded_specs.len() as u32);
    let mut payload = payload_len.encode();
    payload.extend_from_slice(&encoded_specs);

    // Construct message envelope with prelude
    let mut message = Vec::new();

    // Handle signing if mnemonic provided
    if args.signer_mnemonic.is_some() || args.signer_mnemonic_file.is_some() {
        eprintln!("🔑 Generating signing key...");

        let mnemonic = if let Some(ref mnemonic_str) = args.signer_mnemonic {
            mnemonic_str.clone()
        } else if let Some(ref mnemonic_file) = args.signer_mnemonic_file {
            // Use KeyReader to support GPG-encrypted files (.asc, .gpg)
            let secret_mnemonic = KeyReader::read_mnemonic_from_file(mnemonic_file)
                .with_context(|| format!("Failed to read mnemonic file: {}", mnemonic_file.display()))?;
            secret_mnemonic.expose_secret().to_string()
        } else {
            unreachable!()
        };

        // Derive signing key from mnemonic
        let (pair, _seed) = sp_core::sr25519::Pair::from_phrase(&mnemonic, None)
            .map_err(|e| anyhow::anyhow!("Failed to parse mnemonic: {:?}", e))?;

        let public_key = pair.public();
        let public_key_bytes: &[u8] = public_key.as_ref();
        let public_key_hex = format!("0x{}", hex::encode(public_key_bytes));

        eprintln!("✓ Signing key generated:");
        eprintln!("  Public key:    {}", public_key_hex);
        eprintln!("  SS58 address:  {}", public_key.to_ss58check());
        eprintln!();

        // Sign the SCALE-encoded NetworkSpecs (without length prefix)
        use sp_core::crypto::Pair as PairTrait;
        let signature = pair.sign(&encoded_specs);
        let signature_bytes: &[u8] = signature.as_ref();

        // Assemble signed message: prelude + pubkey + payload + signature
        // Prelude: 0x53 + 0x01 (sr25519) + 0xc1 (add-specs)
        message.push(0x53);
        message.push(0x01); // Sr25519
        message.push(0xc1); // Add-specs message type
        message.extend_from_slice(public_key_bytes); // 32 bytes
        message.extend_from_slice(&payload); // Compact length + SCALE-encoded NetworkSpecs
        message.extend_from_slice(signature_bytes); // 64 bytes

        eprintln!("✓ Payload signed");
        eprintln!();
    } else {
        // Unsigned message: prelude + payload
        // Prelude: 0x53 + 0xff (unsigned) + 0xc1 (add-specs)
        message.push(0x53);
        message.push(0xff); // Unsigned
        message.push(0xc1); // Add-specs message type
        message.extend_from_slice(&payload); // Compact length + SCALE-encoded NetworkSpecs

        eprintln!("⚠️  No signing key provided (use --signer-mnemonic or --signer-mnemonic-file)");
        eprintln!("   QR code will be unsigned - users will need to manually verify");
        eprintln!();
    }

    // Hex representation for display only
    let payload_hex = format!("0x{}", hex::encode(&message));

    eprintln!("📊 Generating QR code...");
    eprintln!("   Message size:  {} bytes (SCALE-encoded)", message.len());
    eprintln!("   Hex payload:   {}", payload_hex);

    // Output QR code
    // NOTE: Polkadot Vault expects UTF-8 encoded QR data, not raw binary byte mode.
    // The qrcode crate automatically UTF-8 encodes data when using the default API.
    // This matches the format used by Parity's official QR codes.
    if let Some(out_file) = args.out_file {
        use qrcode::{QrCode as QrCodeBin, EcLevel};
        use image::Luma;

        // Create QR code with medium error correction for better scanning reliability
        let qr = QrCodeBin::with_error_correction_level(&message, EcLevel::M)
            .context("Failed to generate QR code from message")?;

        // Render as PNG with 512x512 minimum dimensions
        let img = qr.render::<Luma<u8>>()
            .min_dimensions(512, 512)
            .build();

        img.save(&out_file)
            .with_context(|| format!("Failed to save QR code to: {}", out_file.display()))?;

        eprintln!();
        eprintln!("✅ QR code exported successfully!");
        eprintln!("   Output file:   {}", out_file.display());
        eprintln!();
        eprintln!("To import this network into Polkadot Vault:");
        eprintln!("  1. Open Polkadot Vault app");
        eprintln!("  2. Navigate to Scanner tab");
        eprintln!("  3. Scan the QR code from {}", out_file.display());
        eprintln!("  4. Review and approve the network specs");
    } else {
        // Generate ASCII QR code for terminal display using half-block characters
        use qrcode::{QrCode, EcLevel};

        // Create QR code with medium error correction (UTF-8 encoded by default)
        let qr_code = QrCode::with_error_correction_level(&message, EcLevel::M)
            .context("Failed to generate QR code - payload may be too large")?;

        // Get QR code as matrix
        let colors = qr_code.to_colors();
        let width = qr_code.width();

        // Convert to half-block characters (2 rows per line)
        let mut output_lines = Vec::new();

        // Add quiet zone (2 modules on each side, standard for QR codes)
        let quiet_zone = 2;
        let quiet_line = " ".repeat(width + quiet_zone * 2);

        // Add top quiet zone
        for _ in 0..quiet_zone {
            output_lines.push(quiet_line.clone());
        }

        // Add QR code rows with side quiet zones
        for row in (0..colors.len()).step_by(width * 2) {
            let mut line = " ".repeat(quiet_zone);

            for col in 0..width {
                let top_idx = row + col;
                let bottom_idx = row + width + col;

                let top_dark = top_idx < colors.len() && colors[top_idx] != qrcode::Color::Light;
                let bottom_dark = bottom_idx < colors.len() && colors[bottom_idx] != qrcode::Color::Light;

                let ch = match (top_dark, bottom_dark) {
                    (true, true) => '█',   // both dark
                    (true, false) => '▀',  // top dark
                    (false, true) => '▄',  // bottom dark
                    (false, false) => ' ', // both light
                };
                line.push(ch);
            }
            line.push_str(&" ".repeat(quiet_zone));
            output_lines.push(line);
        }

        // Add bottom quiet zone
        for _ in 0..quiet_zone {
            output_lines.push(quiet_line.clone());
        }

        // Calculate dimensions for border
        let qr_width = width + quiet_zone * 2;
        let border_line = "█".repeat(qr_width + 2);

        eprintln!();
        eprintln!("✅ QR code generated:");
        eprintln!();

        // Print with border
        println!("{}", border_line);
        for line in output_lines {
            println!("█{}█", line);
        }
        println!("{}", border_line);

        eprintln!();
        eprintln!("To import this network into Polkadot Vault:");
        eprintln!("  1. Open Polkadot Vault app");
        eprintln!("  2. Navigate to Scanner tab");
        eprintln!("  3. Scan the QR code from your screen");
        eprintln!("  4. Review and approve the network specs");
    }

    Ok(())
}
