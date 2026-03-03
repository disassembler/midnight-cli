// Library exports for testing and external integration

pub mod application;
pub mod cli;
pub mod crypto;
pub mod domain;
pub mod storage;
pub mod utxorpc;

// Re-export commonly used items
pub use application::{KeyDerivation, KeyGeneration, WitnessCreation};
pub use domain::{
    DomainError, DomainResult, KeyMaterial, KeyMetadata, KeyPurpose, KeyTypeId, MidnightKeyPath,
    Suri,
};
pub use storage::{CardanoKeyFile, KeyReader, KeyWriter};

// Re-export CLI types for completion generation
pub use cli::{
    KeyCommands, WitnessCommands, ValidatorCommands, GovernanceCommands,
    GenesisCommands, MnemonicCommands, TxCommands, QueryArgs, DebugArgs,
};
