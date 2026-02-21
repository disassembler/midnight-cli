use crate::crypto::generate_mnemonic;
use anyhow::Result;
use clap::{Args, Subcommand};
use secrecy::ExposeSecret;
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum MnemonicCommands {
    /// Generate a new BIP39 mnemonic phrase
    Generate(MnemonicGenerateArgs),
}

#[derive(Args)]
pub struct MnemonicGenerateArgs {
    /// Output file for mnemonic (if not specified, prints to stdout)
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
}

pub fn handle_mnemonic_command(cmd: MnemonicCommands) -> Result<()> {
    match cmd {
        MnemonicCommands::Generate(args) => handle_mnemonic_generate(args),
    }
}

fn handle_mnemonic_generate(args: MnemonicGenerateArgs) -> Result<()> {
    // Generate 24-word mnemonic
    let mnemonic = generate_mnemonic()?;
    let mnemonic_str = mnemonic.expose_secret();

    if let Some(ref output_path) = args.output {
        // Write to file
        fs::write(output_path, mnemonic_str)?;

        #[cfg(unix)]
        {
            // Set restrictive permissions on Unix (0o600 = owner read/write only)
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            fs::set_permissions(output_path, permissions)?;
        }

        eprintln!("✓ Mnemonic generated and written to: {}", output_path.display());
        eprintln!();
        eprintln!("⚠️  SECURITY WARNING:");
        eprintln!("   - Keep this mnemonic secure and never share it");
        eprintln!("   - All keys can be derived from this mnemonic");
        eprintln!("   - Consider encrypting with GPG: gpg --encrypt --armor -r <key-id> {}", output_path.display());
    } else {
        // Print to stdout
        println!("{}", mnemonic_str);
        eprintln!();
        eprintln!("⚠️  SECURITY WARNING:");
        eprintln!("   - Keep this mnemonic secure and never share it");
        eprintln!("   - All keys can be derived from this mnemonic");
        eprintln!("   - Store in a secure location (encrypted file, password manager, etc.)");
    }

    Ok(())
}
