use crate::domain::{DomainError, DomainResult, KeyMaterial};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Cardano-style JSON text envelope format
/// Matches Cardano's key file format with type, description, and CBOR hex
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardanoKeyFile {
    /// Type descriptor (e.g., "GovernanceSigningKeyMidnight_sr25519")
    #[serde(rename = "type")]
    pub key_type: String,

    /// Human-readable description
    pub description: String,

    /// CBOR-encoded key material as lowercase hex string
    #[serde(rename = "cborHex")]
    pub cbor_hex: String,
}

impl CardanoKeyFile {
    /// Create a signing key file from KeyMaterial
    pub fn signing_key(key: &KeyMaterial) -> DomainResult<Self> {
        let secret_key = key
            .secret_key
            .as_ref()
            .ok_or_else(|| DomainError::CryptoError("No secret key available".to_string()))?;

        let secret_hex = secret_key.expose_secret();
        let secret_hex = secret_hex.strip_prefix("0x").unwrap_or(secret_hex);
        let secret_bytes = hex::decode(secret_hex)
            .map_err(|e| DomainError::CryptoError(format!("Invalid secret key hex: {}", e)))?;

        // CBOR encode the secret key bytes
        let cbor_bytes = serde_cbor::to_vec(&secret_bytes)?;
        let cbor_hex = hex::encode(&cbor_bytes);

        Ok(Self {
            key_type: key.signing_key_descriptor(),
            description: key.metadata.description.clone(),
            cbor_hex,
        })
    }

    /// Create a verification key file from KeyMaterial
    pub fn verification_key(key: &KeyMaterial) -> DomainResult<Self> {
        // CBOR encode the public key bytes
        let cbor_bytes = serde_cbor::to_vec(&key.public_key)?;
        let cbor_hex = hex::encode(&cbor_bytes);

        Ok(Self {
            key_type: key.verification_key_descriptor(),
            description: format!("{} (public)", key.metadata.description),
            cbor_hex,
        })
    }

    /// Parse the CBOR hex field and extract key bytes
    pub fn decode_key_bytes(&self) -> DomainResult<Vec<u8>> {
        let cbor_bytes = hex::decode(&self.cbor_hex)
            .map_err(|e| DomainError::InvalidKeyFile {
                reason: format!("Invalid CBOR hex: {}", e),
            })?;

        let key_bytes: Vec<u8> = serde_cbor::from_slice(&cbor_bytes)
            .map_err(|e| DomainError::InvalidKeyFile {
                reason: format!("Invalid CBOR encoding: {}", e),
            })?;

        Ok(key_bytes)
    }

    /// Read from a JSON file
    pub fn read_from_file(path: &Path) -> DomainResult<Self> {
        let contents = std::fs::read_to_string(path)?;
        let key_file: Self = serde_json::from_str(&contents)?;
        Ok(key_file)
    }

    /// Write to a JSON file
    pub fn write_to_file(&self, path: &Path) -> DomainResult<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Check if this is a signing key (contains "Signing" in type)
    pub fn is_signing_key(&self) -> bool {
        self.key_type.contains("Signing")
    }

    /// Check if this is a verification key (contains "Verification" in type)
    pub fn is_verification_key(&self) -> bool {
        self.key_type.contains("Verification")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{KeyMetadata, KeyPurpose, KeyTypeId};
    use secrecy::SecretString;

    #[test]
    fn test_create_signing_key() {
        let secret_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key_material = KeyMaterial::new(
            KeyTypeId::Sr25519,
            KeyPurpose::Governance,
            vec![1, 2, 3, 4],
            Some(SecretString::new(secret_hex.to_string())),
        )
        .with_metadata(
            KeyMetadata::default().with_description("Test governance key"),
        );

        let card_file = CardanoKeyFile::signing_key(&key_material).unwrap();

        assert_eq!(
            card_file.key_type,
            "GovernanceSigningKeyMidnight_sr25519"
        );
        assert_eq!(card_file.description, "Test governance key");
        assert!(!card_file.cbor_hex.is_empty());
        assert!(card_file.is_signing_key());
    }

    #[test]
    fn test_create_verification_key() {
        let key_material = KeyMaterial::new(
            KeyTypeId::Ed25519,
            KeyPurpose::Finality,
            vec![1, 2, 3, 4, 5],
            None,
        )
        .with_metadata(
            KeyMetadata::default().with_description("Test finality key"),
        );

        let card_file = CardanoKeyFile::verification_key(&key_material).unwrap();

        assert_eq!(
            card_file.key_type,
            "FinalityVerificationKeyMidnight_ed25519"
        );
        assert!(card_file.description.contains("public"));
        assert!(card_file.is_verification_key());
    }

    #[test]
    fn test_round_trip() {
        let original_bytes = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let cbor_bytes = serde_cbor::to_vec(&original_bytes).unwrap();
        let cbor_hex = hex::encode(&cbor_bytes);

        let card_file = CardanoKeyFile {
            key_type: "TestSigningKey".to_string(),
            description: "Test".to_string(),
            cbor_hex,
        };

        let decoded = card_file.decode_key_bytes().unwrap();
        assert_eq!(decoded, original_bytes);
    }

    #[test]
    fn test_json_serialization() {
        let card_file = CardanoKeyFile {
            key_type: "PaymentSigningKeyMidnight_sr25519".to_string(),
            description: "Payment key".to_string(),
            cbor_hex: "5820abcd".to_string(),
        };

        let json = serde_json::to_string_pretty(&card_file).unwrap();
        assert!(json.contains("\"type\""));
        assert!(json.contains("PaymentSigningKeyMidnight_sr25519"));
        assert!(json.contains("\"cborHex\""));

        let deserialized: CardanoKeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key_type, card_file.key_type);
        assert_eq!(deserialized.cbor_hex, card_file.cbor_hex);
    }
}
