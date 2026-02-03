use super::error::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for cryptographic key types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyTypeId {
    Sr25519,
    Ed25519,
}

impl KeyTypeId {
    pub fn from_str(s: &str) -> DomainResult<Self> {
        match s.to_lowercase().as_str() {
            "sr25519" => Ok(Self::Sr25519),
            "ed25519" => Ok(Self::Ed25519),
            _ => Err(DomainError::InvalidKeyType(s.to_string())),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sr25519 => "sr25519",
            Self::Ed25519 => "ed25519",
        }
    }
}

impl fmt::Display for KeyTypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// The purpose/role of a key in the Midnight network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyPurpose {
    Governance,
    Payment,
    Finality,
}

impl KeyPurpose {
    pub fn from_str(s: &str) -> DomainResult<Self> {
        match s.to_lowercase().as_str() {
            "governance" => Ok(Self::Governance),
            "payment" => Ok(Self::Payment),
            "finality" => Ok(Self::Finality),
            _ => Err(DomainError::InvalidKeyPurpose(s.to_string())),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Governance => "governance",
            Self::Payment => "payment",
            Self::Finality => "finality",
        }
    }

    /// Get the default key type for this purpose
    pub fn default_key_type(&self) -> KeyTypeId {
        match self {
            Self::Governance | Self::Payment => KeyTypeId::Sr25519,
            Self::Finality => KeyTypeId::Ed25519,
        }
    }

    /// Get the Cardano-style type descriptor for a signing key
    pub fn signing_key_descriptor(&self, key_type: KeyTypeId) -> String {
        format!("{}SigningKeyMidnight_{}",
            self.capitalized_name(),
            key_type.as_str())
    }

    /// Get the Cardano-style type descriptor for a verification key
    pub fn verification_key_descriptor(&self, key_type: KeyTypeId) -> String {
        format!("{}VerificationKeyMidnight_{}",
            self.capitalized_name(),
            key_type.as_str())
    }

    fn capitalized_name(&self) -> &'static str {
        match self {
            Self::Governance => "Governance",
            Self::Payment => "Payment",
            Self::Finality => "Finality",
        }
    }

    /// Get the default file name (without extension) for this purpose
    pub fn default_filename(&self) -> &'static str {
        match self {
            Self::Governance => "governance",
            Self::Payment => "payment",
            Self::Finality => "finality",
        }
    }
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_type_id_conversions() {
        assert_eq!(KeyTypeId::from_str("sr25519").unwrap(), KeyTypeId::Sr25519);
        assert_eq!(KeyTypeId::from_str("Sr25519").unwrap(), KeyTypeId::Sr25519);
        assert_eq!(KeyTypeId::from_str("SR25519").unwrap(), KeyTypeId::Sr25519);
        assert_eq!(KeyTypeId::from_str("ed25519").unwrap(), KeyTypeId::Ed25519);
        assert!(KeyTypeId::from_str("invalid").is_err());
    }

    #[test]
    fn test_key_purpose_conversions() {
        assert_eq!(KeyPurpose::from_str("governance").unwrap(), KeyPurpose::Governance);
        assert_eq!(KeyPurpose::from_str("PAYMENT").unwrap(), KeyPurpose::Payment);
        assert_eq!(KeyPurpose::from_str("Finality").unwrap(), KeyPurpose::Finality);
        assert!(KeyPurpose::from_str("invalid").is_err());
    }

    #[test]
    fn test_type_descriptors() {
        assert_eq!(
            KeyPurpose::Governance.signing_key_descriptor(KeyTypeId::Sr25519),
            "GovernanceSigningKeyMidnight_sr25519"
        );
        assert_eq!(
            KeyPurpose::Finality.verification_key_descriptor(KeyTypeId::Ed25519),
            "FinalityVerificationKeyMidnight_ed25519"
        );
    }

    #[test]
    fn test_default_key_types() {
        assert_eq!(KeyPurpose::Governance.default_key_type(), KeyTypeId::Sr25519);
        assert_eq!(KeyPurpose::Payment.default_key_type(), KeyTypeId::Sr25519);
        assert_eq!(KeyPurpose::Finality.default_key_type(), KeyTypeId::Ed25519);
    }
}
