use crate::crypto::{normalize_mnemonic, validate_mnemonic, Ed25519, Sr25519};
use crate::domain::{DomainError, DomainResult, KeyTypeId};
use crate::storage::{cardano_format::CardanoKeyFile, gpg::Gpg};
use secrecy::SecretString;
use sp_core::Pair;
use std::path::Path;

/// Read keys from various sources
pub struct KeyReader;

impl KeyReader {
    /// Read a mnemonic from a file or return it as-is if it's not a path
    /// Supports GPG encrypted files automatically
    pub fn read_mnemonic(mnemonic_or_path: &str) -> DomainResult<SecretString> {
        let path = Path::new(mnemonic_or_path);

        // Check if it's a file path
        if path.exists() {
            Self::read_mnemonic_from_file(path)
        } else {
            // Treat as direct mnemonic
            let normalized = normalize_mnemonic(mnemonic_or_path);
            validate_mnemonic(&normalized)?;
            Ok(SecretString::new(normalized))
        }
    }

    /// Read a mnemonic from a file
    /// Automatically handles GPG encryption
    pub fn read_mnemonic_from_file(path: &Path) -> DomainResult<SecretString> {
        let contents = if Gpg::is_encrypted(path) {
            // Decrypt GPG file
            Gpg::decrypt_file(path)?
        } else {
            // Read plain text file
            std::fs::read_to_string(path).map_err(|e| DomainError::KeyFileNotFound {
                path: path.to_path_buf(),
            })?
        };

        // Normalize and validate
        let normalized = normalize_mnemonic(&contents);
        validate_mnemonic(&normalized)?;

        Ok(SecretString::new(normalized))
    }

    /// Read a Cardano-style key file (.skey or .vkey)
    pub fn read_cardano_key_file(path: &Path) -> DomainResult<CardanoKeyFile> {
        if !path.exists() {
            return Err(DomainError::KeyFileNotFound {
                path: path.to_path_buf(),
            });
        }

        CardanoKeyFile::read_from_file(path)
    }

    /// Parse key type from Cardano type descriptor
    /// E.g., "GovernanceSigningKeyMidnight_sr25519" -> Sr25519
    pub fn parse_key_type_from_descriptor(descriptor: &str) -> DomainResult<KeyTypeId> {
        if descriptor.ends_with("_sr25519") {
            Ok(KeyTypeId::Sr25519)
        } else if descriptor.ends_with("_ed25519") {
            Ok(KeyTypeId::Ed25519)
        } else {
            Err(DomainError::InvalidKeyFile {
                reason: format!("Unknown key type in descriptor: {}", descriptor),
            })
        }
    }

    /// Parse key purpose from Cardano type descriptor
    /// E.g., "GovernanceSigningKeyMidnight_sr25519" -> Governance
    pub fn parse_key_purpose_from_descriptor(descriptor: &str) -> DomainResult<crate::domain::KeyPurpose> {
        use crate::domain::KeyPurpose;

        if descriptor.starts_with("Governance") {
            Ok(KeyPurpose::Governance)
        } else if descriptor.starts_with("Payment") {
            Ok(KeyPurpose::Payment)
        } else if descriptor.starts_with("Finality") {
            Ok(KeyPurpose::Finality)
        } else {
            Err(DomainError::InvalidKeyFile {
                reason: format!("Unknown key purpose in descriptor: {}", descriptor),
            })
        }
    }

    /// Load a keypair from a Cardano .skey file
    pub fn load_keypair_from_skey(path: &Path) -> DomainResult<(KeyTypeId, Vec<u8>)> {
        let card_file = Self::read_cardano_key_file(path)?;

        if !card_file.is_signing_key() {
            return Err(DomainError::InvalidKeyFile {
                reason: "File is not a signing key (.skey)".to_string(),
            });
        }

        let key_type = Self::parse_key_type_from_descriptor(&card_file.key_type)?;
        let secret_bytes = card_file.decode_key_bytes()?;

        Ok((key_type, secret_bytes))
    }

    /// Create keypair from secret bytes based on key type
    /// Returns only the requested key type pair
    pub fn create_pair_from_secret(
        key_type: KeyTypeId,
        secret_bytes: &[u8],
    ) -> DomainResult<(KeyTypeId, Vec<u8>)> {
        if secret_bytes.len() != 32 && secret_bytes.len() != 64 {
            return Err(DomainError::CryptoError(format!(
                "Invalid secret key length: {} (expected 32 or 64)",
                secret_bytes.len()
            )));
        }

        // Just return the key type and secret bytes
        // The actual pair creation will be done by the calling code
        Ok((key_type, secret_bytes.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const TEST_MNEMONIC: &str =
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

    #[test]
    fn test_read_direct_mnemonic() {
        let mnemonic = KeyReader::read_mnemonic(TEST_MNEMONIC).unwrap();
        let exposed = secrecy::ExposeSecret::expose_secret(&mnemonic);
        assert!(exposed.contains("bottom"));
    }

    #[test]
    fn test_read_mnemonic_from_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "{}", TEST_MNEMONIC).unwrap();

        let mnemonic = KeyReader::read_mnemonic_from_file(temp_file.path()).unwrap();
        let exposed = secrecy::ExposeSecret::expose_secret(&mnemonic);
        assert!(exposed.contains("bottom"));
    }

    #[test]
    fn test_parse_key_type() {
        assert_eq!(
            KeyReader::parse_key_type_from_descriptor(
                "GovernanceSigningKeyMidnight_sr25519"
            )
            .unwrap(),
            KeyTypeId::Sr25519
        );

        assert_eq!(
            KeyReader::parse_key_type_from_descriptor(
                "FinalityVerificationKeyMidnight_ed25519"
            )
            .unwrap(),
            KeyTypeId::Ed25519
        );

        assert!(KeyReader::parse_key_type_from_descriptor("InvalidKey").is_err());
    }

    #[test]
    fn test_normalize_and_validate() {
        // With extra whitespace
        let messy = format!("  {}  \n", TEST_MNEMONIC);
        let mnemonic = KeyReader::read_mnemonic(&messy).unwrap();
        let exposed = secrecy::ExposeSecret::expose_secret(&mnemonic);
        assert!(!exposed.starts_with(' '));
        assert!(!exposed.ends_with('\n'));
    }

    #[test]
    fn test_invalid_mnemonic() {
        assert!(KeyReader::read_mnemonic("invalid mnemonic phrase").is_err());
    }
}
