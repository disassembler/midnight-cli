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
    /// Path to validators JSON file (from validator generate)
    #[arg(long)]
    pub validators: PathBuf,

    /// Path to governance JSON file (from governance generate)
    #[arg(long)]
    pub governance: PathBuf,

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
    // Read validators file
    let validators_json = fs::read_to_string(&args.validators)
        .with_context(|| format!("Failed to read validators file: {}", args.validators.display()))?;

    // Try to parse as single validator or array
    let validators: Vec<ValidatorKeysInput> = if let Ok(single) = serde_json::from_str::<ValidatorKeysInput>(&validators_json) {
        vec![single]
    } else {
        serde_json::from_str(&validators_json)
            .with_context(|| "Failed to parse validators JSON (expected single validator object or array)")?
    };

    // Read governance file
    let governance_json = fs::read_to_string(&args.governance)
        .with_context(|| format!("Failed to read governance file: {}", args.governance.display()))?;

    // Try to parse as single key or array
    let governance_keys: Vec<GovernanceKeyInput> = if let Ok(single) = serde_json::from_str::<GovernanceKeyInput>(&governance_json) {
        vec![single]
    } else {
        serde_json::from_str(&governance_json)
            .with_context(|| "Failed to parse governance JSON (expected single key object or array)")?
    };

    // Build genesis config
    let validator_configs: Vec<ValidatorConfig> = validators
        .iter()
        .map(|v| ValidatorConfig {
            node_id: v.node_key.public_key_hex.clone(),
            aura: v.aura_key.public_key_hex.clone(),
            grandpa: v.grandpa_key.public_key_hex.clone(),
        })
        .collect();

    let governance_addresses: Vec<String> = governance_keys
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
            council: governance_addresses.clone(),
            technical_committee: governance_addresses,
        },
        night_token,
    };

    // Write genesis config
    let genesis_json = serde_json::to_string_pretty(&genesis_config)?;
    fs::write(&args.output, genesis_json)?;

    println!("✓ Genesis configuration created:");
    println!("  Chain ID:   {}", args.chain_id);
    println!("  Validators: {}", genesis_config.validators.len());
    println!("  Governance: {}", genesis_config.governance.council.len());
    if let Some(ref night) = genesis_config.night_token {
        println!("  $NIGHT:     {}", night.policy_id);
    }
    println!();
    println!("✓ Genesis written to: {}", args.output.display());

    Ok(())
}
