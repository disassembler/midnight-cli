use super::error::{DomainError, DomainResult};
use super::key_type::{KeyPurpose, KeyTypeId};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// A single segment in a derivation path
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationSegment {
    pub component: String,
}

impl DerivationSegment {
    pub fn new(component: impl Into<String>) -> Self {
        Self {
            component: component.into(),
        }
    }
}

/// Source of entropy for key generation
#[derive(Debug, Clone)]
pub enum SeedSource {
    Mnemonic(SecretString),
    HexSeed(SecretString),
}

/// A complete SURI (Substrate URI) with all components
/// Format: SEED[//hard][/soft][///password]
#[derive(Debug, Clone)]
pub struct Suri {
    /// The seed phrase or hex seed
    pub seed: SeedSource,
    /// Hard derivation paths (// prefix)
    pub hard_paths: Vec<DerivationSegment>,
    /// Soft derivation paths (/ prefix) - sr25519 only
    pub soft_paths: Vec<DerivationSegment>,
    /// Optional password for key derivation (/// prefix)
    pub password: Option<SecretString>,
}

impl Suri {
    /// Create a new SURI from a mnemonic phrase
    pub fn from_mnemonic(mnemonic: impl Into<SecretString>) -> Self {
        Self {
            seed: SeedSource::Mnemonic(mnemonic.into()),
            hard_paths: Vec::new(),
            soft_paths: Vec::new(),
            password: None,
        }
    }

    /// Add hard derivation paths
    pub fn with_hard_paths(mut self, paths: Vec<DerivationSegment>) -> Self {
        self.hard_paths = paths;
        self
    }

    /// Add soft derivation paths (sr25519 only)
    pub fn with_soft_paths(mut self, paths: Vec<DerivationSegment>) -> Self {
        self.soft_paths = paths;
        self
    }

    /// Add password for key derivation
    pub fn with_password(mut self, password: impl Into<SecretString>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Validate this SURI for a specific key type
    pub fn validate(&self, key_type: KeyTypeId) -> DomainResult<()> {
        // Ed25519 doesn't support soft derivation
        if key_type == KeyTypeId::Ed25519 && !self.soft_paths.is_empty() {
            return Err(DomainError::UnsupportedDerivation {
                key_type: key_type.to_string(),
                path: "soft derivation".to_string(),
            });
        }
        Ok(())
    }
}

/// Standard derivation paths for Midnight keys
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MidnightKeyPath {
    /// SEED//midnight//governance//INDEX
    Governance(u32),
    /// SEED//midnight//payment//INDEX
    Payment(u32),
    /// SEED//midnight//finality//INDEX
    Finality(u32),
}

impl MidnightKeyPath {
    /// Create from purpose and index
    pub fn from_purpose(purpose: KeyPurpose, index: u32) -> Self {
        match purpose {
            KeyPurpose::Governance => Self::Governance(index),
            KeyPurpose::Payment => Self::Payment(index),
            KeyPurpose::Finality => Self::Finality(index),
        }
    }

    /// Convert to derivation path segments
    pub fn to_derivation_path(&self) -> Vec<DerivationSegment> {
        match self {
            Self::Governance(index) => vec![
                DerivationSegment::new("midnight"),
                DerivationSegment::new("governance"),
                DerivationSegment::new(index.to_string()),
            ],
            Self::Payment(index) => vec![
                DerivationSegment::new("midnight"),
                DerivationSegment::new("payment"),
                DerivationSegment::new(index.to_string()),
            ],
            Self::Finality(index) => vec![
                DerivationSegment::new("midnight"),
                DerivationSegment::new("finality"),
                DerivationSegment::new(index.to_string()),
            ],
        }
    }

    /// Get the key type for this path
    pub fn key_type(&self) -> KeyTypeId {
        match self {
            Self::Governance(_) | Self::Payment(_) => KeyTypeId::Sr25519,
            Self::Finality(_) => KeyTypeId::Ed25519,
        }
    }

    /// Get the key purpose for this path
    pub fn purpose(&self) -> KeyPurpose {
        match self {
            Self::Governance(_) => KeyPurpose::Governance,
            Self::Payment(_) => KeyPurpose::Payment,
            Self::Finality(_) => KeyPurpose::Finality,
        }
    }

    /// Get the index for this path
    pub fn index(&self) -> u32 {
        match self {
            Self::Governance(idx) | Self::Payment(idx) | Self::Finality(idx) => *idx,
        }
    }

    /// Format as a string path for display
    pub fn to_string_path(&self) -> String {
        format!("//midnight//{}//{}",
            self.purpose().as_str(),
            self.index())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_midnight_key_path() {
        let gov = MidnightKeyPath::Governance(0);
        assert_eq!(gov.key_type(), KeyTypeId::Sr25519);
        assert_eq!(gov.purpose(), KeyPurpose::Governance);
        assert_eq!(gov.index(), 0);
        assert_eq!(gov.to_string_path(), "//midnight//governance//0");

        let finality = MidnightKeyPath::Finality(5);
        assert_eq!(finality.key_type(), KeyTypeId::Ed25519);
        assert_eq!(finality.to_string_path(), "//midnight//finality//5");
    }

    #[test]
    fn test_derivation_segments() {
        let path = MidnightKeyPath::Payment(3);
        let segments = path.to_derivation_path();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].component, "midnight");
        assert_eq!(segments[1].component, "payment");
        assert_eq!(segments[2].component, "3");
    }

    #[test]
    fn test_suri_validation() {
        let mut suri = Suri::from_mnemonic("test mnemonic".to_string());

        // Sr25519 allows soft derivation
        suri.soft_paths = vec![DerivationSegment::new("soft")];
        assert!(suri.validate(KeyTypeId::Sr25519).is_ok());

        // Ed25519 doesn't allow soft derivation
        assert!(suri.validate(KeyTypeId::Ed25519).is_err());

        // Ed25519 with no soft derivation is OK
        suri.soft_paths.clear();
        assert!(suri.validate(KeyTypeId::Ed25519).is_ok());
    }
}
