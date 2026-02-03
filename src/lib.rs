// Library exports for testing and external integration

pub mod application;
pub mod crypto;
pub mod domain;
pub mod storage;

// Re-export commonly used items
pub use application::{KeyDerivation, KeyGeneration, WitnessCreation, WitnessOutput};
pub use domain::{
    DomainError, DomainResult, KeyInfo, KeyMaterial, KeyMetadata, KeyPurpose, KeyTypeId,
    MidnightKeyPath, Suri,
};
pub use storage::{CardanoKeyFile, Gpg, KeyReader, KeyWriter};
