use clap::{Parser, Subcommand};
use anyhow::Result;

mod application;
mod cli;
mod crypto;
mod domain;
mod storage;

use cli::{handle_key_command, handle_witness_command, KeyCommands, WitnessCommands};

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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Key(key_cmd) => handle_key_command(key_cmd),
        Commands::Witness(witness_cmd) => handle_witness_command(witness_cmd),
    }
}
