pub mod derivation;
pub mod error;
pub mod key_material;
pub mod key_type;

// Re-export commonly used types
#[allow(unused_imports)]
pub use derivation::{DerivationSegment, MidnightKeyPath, SeedSource, Suri};
pub use error::{DomainError, DomainResult};
pub use key_material::{KeyMaterial, KeyMetadata};
pub use key_type::{KeyPurpose, KeyTypeId};
