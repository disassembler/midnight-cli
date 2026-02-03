use super::key_type::{KeyPurpose, KeyTypeId};
use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Represents cryptographic key material with metadata
#[derive(Clone)]
pub struct KeyMaterial {
    /// Type of key (Sr25519, Ed25519)
    pub key_type: KeyTypeId,
    /// Purpose/role of the key
    pub purpose: KeyPurpose,
    /// Public key bytes
    pub public_key: Vec<u8>,
    /// Secret key bytes (wrapped in SecretString for security)
    pub secret_key: Option<SecretString>,
    /// Derivation path used to generate this key
    pub derivation_path: Option<String>,
    /// Additional metadata
    pub metadata: KeyMetadata,
}

impl KeyMaterial {
    /// Create new key material with required fields
    pub fn new(
        key_type: KeyTypeId,
        purpose: KeyPurpose,
        public_key: Vec<u8>,
        secret_key: Option<SecretString>,
    ) -> Self {
        Self {
            key_type,
            purpose,
            public_key,
            secret_key,
            derivation_path: None,
            metadata: KeyMetadata::default(),
        }
    }

    /// Set the derivation path
    pub fn with_derivation_path(mut self, path: impl Into<String>) -> Self {
        self.derivation_path = Some(path.into());
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: KeyMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Check if this key material includes the secret key
    pub fn has_secret(&self) -> bool {
        self.secret_key.is_some()
    }

    /// Get the Cardano-style type descriptor for the signing key
    pub fn signing_key_descriptor(&self) -> String {
        self.purpose.signing_key_descriptor(self.key_type)
    }

    /// Get the Cardano-style type descriptor for the verification key
    pub fn verification_key_descriptor(&self) -> String {
        self.purpose.verification_key_descriptor(self.key_type)
    }
}

/// Additional metadata about a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Human-readable description
    pub description: String,
    /// Creation timestamp
    pub created_at: Option<DateTime<Utc>>,
    /// SS58 address (Substrate format)
    pub ss58_address: Option<String>,
}

impl Default for KeyMetadata {
    fn default() -> Self {
        Self {
            description: String::new(),
            created_at: Some(Utc::now()),
            ss58_address: None,
        }
    }
}

impl KeyMetadata {
    /// Create new metadata with a description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set the SS58 address
    pub fn with_ss58_address(mut self, address: impl Into<String>) -> Self {
        self.ss58_address = Some(address.into());
        self
    }
}

/// Information about a stored key file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Purpose of the key
    pub purpose: KeyPurpose,
    /// Type of key
    pub key_type: KeyTypeId,
    /// Public key bytes
    pub public_key: Vec<u8>,
    /// SS58 address if available
    pub ss58_address: Option<String>,
    /// Derivation path if available
    pub derivation_path: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_material_creation() {
        let public_key = vec![1, 2, 3, 4];
        let secret = SecretString::new("secret".to_string());

        let key = KeyMaterial::new(
            KeyTypeId::Sr25519,
            KeyPurpose::Governance,
            public_key.clone(),
            Some(secret),
        );

        assert_eq!(key.key_type, KeyTypeId::Sr25519);
        assert_eq!(key.purpose, KeyPurpose::Governance);
        assert_eq!(key.public_key, public_key);
        assert!(key.has_secret());
    }

    #[test]
    fn test_type_descriptors() {
        let key = KeyMaterial::new(
            KeyTypeId::Sr25519,
            KeyPurpose::Governance,
            vec![],
            None,
        );

        assert_eq!(
            key.signing_key_descriptor(),
            "GovernanceSigningKeyMidnight_sr25519"
        );
        assert_eq!(
            key.verification_key_descriptor(),
            "GovernanceVerificationKeyMidnight_sr25519"
        );
    }

    #[test]
    fn test_metadata() {
        let metadata = KeyMetadata::default()
            .with_description("Test key")
            .with_ss58_address("5DfhGyQdFobKM...");

        assert_eq!(metadata.description, "Test key");
        assert!(metadata.ss58_address.is_some());
        assert!(metadata.created_at.is_some());
    }
}
