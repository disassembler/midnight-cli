use clap::{Parser, Subcommand};
use anyhow::Result;

mod application;
mod cli;
mod crypto;
mod domain;
mod storage;

use cli::{
    handle_key_command, handle_witness_command, handle_validator_command,
    handle_governance_command, handle_genesis_command, handle_mnemonic_command,
    handle_tx_command, handle_query_command, KeyCommands, WitnessCommands,
    ValidatorCommands, GovernanceCommands, GenesisCommands, MnemonicCommands,
    TxCommands, QueryArgs,
};

#[derive(Parser)]
#[command(name = "midnight-cli")]
#[command(about = "Midnight Network Key Management and Governance Tooling", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Key management operations
    #[command(subcommand)]
    Key(KeyCommands),

    /// Witness (signature) operations
    #[command(subcommand)]
    Witness(WitnessCommands),

    /// Validator key operations
    #[command(subcommand)]
    Validator(ValidatorCommands),

    /// Governance key operations
    #[command(subcommand)]
    Governance(GovernanceCommands),

    /// Genesis configuration operations
    #[command(subcommand)]
    Genesis(GenesisCommands),

    /// Mnemonic operations
    #[command(subcommand)]
    Mnemonic(MnemonicCommands),

    /// Transaction operations
    #[command(subcommand)]
    Tx(TxCommands),

    /// Query chain state
    Query(QueryArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Key(key_cmd) => handle_key_command(key_cmd),
        Commands::Witness(witness_cmd) => handle_witness_command(witness_cmd),
        Commands::Validator(validator_cmd) => handle_validator_command(validator_cmd),
        Commands::Governance(governance_cmd) => handle_governance_command(governance_cmd),
        Commands::Genesis(genesis_cmd) => handle_genesis_command(genesis_cmd),
        Commands::Mnemonic(mnemonic_cmd) => handle_mnemonic_command(mnemonic_cmd),
        Commands::Tx(tx_cmd) => handle_tx_command(tx_cmd).await,
        Commands::Query(query_cmd) => handle_query_command(query_cmd).await,
    }
}
