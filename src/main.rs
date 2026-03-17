use clap::{Parser, Subcommand, CommandFactory};
use clap_complete::{generate, Shell};
use anyhow::Result;
use std::io;

mod application;
mod cli;
mod contracts;
mod crypto;
mod domain;
mod storage;
mod utxorpc;

use cli::{
    handle_debug_command, handle_deploy_command, handle_genesis_command,
    handle_governance_command, handle_key_command, handle_mnemonic_command,
    handle_query_command, handle_rotate_command, handle_tx_command,
    handle_validator_command, handle_witness_command, DebugArgs, DeployCommands,
    GenesisCommands, GovernanceCommands, KeyCommands, MnemonicCommands, QueryArgs,
    RotateCommands, TxCommands, ValidatorCommands, WitnessCommands,
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

    /// Deploy governance contracts
    #[command(subcommand)]
    Deploy(DeployCommands),

    /// Rotate governance members
    #[command(subcommand)]
    Rotate(RotateCommands),

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

    /// Debug utilities for transaction analysis
    Debug(DebugArgs),

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Key(key_cmd) => handle_key_command(key_cmd),
        Commands::Witness(witness_cmd) => handle_witness_command(witness_cmd),
        Commands::Validator(validator_cmd) => handle_validator_command(validator_cmd),
        Commands::Governance(governance_cmd) => handle_governance_command(governance_cmd).await,
        Commands::Deploy(deploy_cmd) => handle_deploy_command(deploy_cmd).await,
        Commands::Rotate(rotate_cmd) => handle_rotate_command(rotate_cmd).await,
        Commands::Genesis(genesis_cmd) => handle_genesis_command(genesis_cmd).await,
        Commands::Mnemonic(mnemonic_cmd) => handle_mnemonic_command(mnemonic_cmd),
        Commands::Tx(tx_cmd) => handle_tx_command(tx_cmd).await,
        Commands::Query(query_cmd) => handle_query_command(query_cmd).await,
        Commands::Debug(debug_cmd) => handle_debug_command(debug_cmd),
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "midnight-cli", &mut io::stdout());
            Ok(())
        }
    }
}
