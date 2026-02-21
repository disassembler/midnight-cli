use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum GenesisCommands {
    /// Initialize genesis configuration from aggregated keys
    Init(GenesisInitArgs),
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorKeysInput {
    pub node_key: KeyData,
    pub aura_key: KeyData,
    pub grandpa_key: KeyData,
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

pub fn handle_genesis_command(cmd: GenesisCommands) -> Result<()> {
    match cmd {
        GenesisCommands::Init(args) => handle_genesis_init(args),
    }
}

fn handle_genesis_init(args: GenesisInitArgs) -> Result<()> {
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

    println!("✓ Genesis configuration created:");
    println!("  Chain ID:              {}", args.chain_id);
    println!("  Validators:            {}", genesis_config.validators.len());
    println!("  Technical Committee:   {}", genesis_config.governance.technical_committee.len());
    println!("  Council:               {}", genesis_config.governance.council.len());
    if let Some(ref night) = genesis_config.night_token {
        println!("  $NIGHT:                {}", night.policy_id);
    }
    println!();
    println!("✓ Genesis written to: {}", args.output.display());

    Ok(())
}
