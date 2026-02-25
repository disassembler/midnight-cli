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
        if let Some(ref policy_id) = genesis.night_token.as_ref().and_then(|t| Some(&t.policy_id)) {
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
