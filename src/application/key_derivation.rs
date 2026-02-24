use crate::crypto::{Ed25519, Sr25519, SuriParser};
use crate::domain::{DomainError, DomainResult, KeyMaterial, KeyPurpose, KeyTypeId};
use crate::storage::KeyReader;
use secrecy::ExposeSecret;
use std::path::Path;

/// On-demand key derivation (without saving to files)
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive a key from SURI string
    pub fn derive_from_suri(
        suri_str: &str,
        key_type: KeyTypeId,
        purpose: KeyPurpose,
    ) -> DomainResult<KeyMaterial> {
        let suri = SuriParser::parse(suri_str)?;
        suri.validate(key_type)?;

        // Extract derivation path for metadata
        let derivation_path = if !suri.hard_paths.is_empty() || !suri.soft_paths.is_empty() {
            Some(Self::format_derivation_path(&suri))
        } else {
            None
        };

        match key_type {
            KeyTypeId::Sr25519 => {
                let pair = Sr25519::from_suri(suri_str)?;
                Ok(Sr25519::to_key_material(&pair, purpose, derivation_path))
            }
            KeyTypeId::Ed25519 => {
                let pair = Ed25519::from_suri(suri_str)?;
                Ok(Ed25519::to_key_material(&pair, purpose, derivation_path))
            }
            KeyTypeId::Secp256k1 => {
                Err(DomainError::UnsupportedDerivation {
                    key_type: "secp256k1".to_string(),
                    path: "SURI derivation not supported for payment keys - use BIP-32 paths instead".to_string(),
                })
            }
        }
    }

    /// Derive a key from mnemonic with derivation path
    pub fn derive_from_mnemonic(
        mnemonic: &str,
        derivation_path: &str,
        key_type: KeyTypeId,
        purpose: KeyPurpose,
    ) -> DomainResult<KeyMaterial> {
        let suri_str = format!("{}{}", mnemonic, derivation_path);
        Self::derive_from_suri(&suri_str, key_type, purpose)
    }

    /// Derive a key from mnemonic file with derivation path
    pub fn derive_from_mnemonic_file(
        mnemonic_file: &Path,
        derivation_path: &str,
        key_type: KeyTypeId,
        purpose: KeyPurpose,
    ) -> DomainResult<KeyMaterial> {
        let mnemonic = KeyReader::read_mnemonic_from_file(mnemonic_file)?;
        Self::derive_from_mnemonic(
            mnemonic.expose_secret(),
            derivation_path,
            key_type,
            purpose,
        )
    }

    /// Format derivation path from SURI components
    fn format_derivation_path(suri: &crate::domain::Suri) -> String {
        let mut path = String::new();

        for segment in &suri.hard_paths {
            path.push_str("//");
            path.push_str(&segment.component);
        }

        for segment in &suri.soft_paths {
            path.push('/');
            path.push_str(&segment.component);
        }

        path
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
    fn test_derive_from_suri() {
        let suri = format!("{}//midnight//governance//0", TEST_MNEMONIC);
        let key = KeyDerivation::derive_from_suri(&suri, KeyTypeId::Sr25519, KeyPurpose::Governance)
            .unwrap();

        assert_eq!(key.purpose, KeyPurpose::Governance);
        assert_eq!(key.key_type, KeyTypeId::Sr25519);
        assert!(key.has_secret());
        assert_eq!(
            key.derivation_path,
            Some("//midnight//governance//0".to_string())
        );
    }

    #[test]
    fn test_derive_from_mnemonic() {
        let key = KeyDerivation::derive_from_mnemonic(
            TEST_MNEMONIC,
            "//midnight//payment//3",
            KeyTypeId::Sr25519,
            KeyPurpose::Payment,
        )
        .unwrap();

        assert_eq!(key.purpose, KeyPurpose::Payment);
        assert_eq!(
            key.derivation_path,
            Some("//midnight//payment//3".to_string())
        );
    }

    #[test]
    fn test_derive_from_mnemonic_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "{}", TEST_MNEMONIC).unwrap();

        let key = KeyDerivation::derive_from_mnemonic_file(
            temp_file.path(),
            "//midnight//governance//1",
            KeyTypeId::Sr25519,
            KeyPurpose::Governance,
        )
        .unwrap();

        assert_eq!(key.purpose, KeyPurpose::Governance);
        assert!(key.has_secret());
    }

    #[test]
    fn test_derive_without_path() {
        let key =
            KeyDerivation::derive_from_suri(TEST_MNEMONIC, KeyTypeId::Sr25519, KeyPurpose::Payment)
                .unwrap();

        // No derivation path
        assert_eq!(key.derivation_path, None);
    }

    #[test]
    fn test_validate_derivation_for_key_type() {
        // Ed25519 with soft derivation should fail
        let suri_with_soft = format!("{}//hard/soft", TEST_MNEMONIC);
        let result =
            KeyDerivation::derive_from_suri(&suri_with_soft, KeyTypeId::Ed25519, KeyPurpose::Finality);
        assert!(result.is_err());

        // Ed25519 with only hard derivation should work
        let suri_hard_only = format!("{}//hard//only", TEST_MNEMONIC);
        let result = KeyDerivation::derive_from_suri(
            &suri_hard_only,
            KeyTypeId::Ed25519,
            KeyPurpose::Finality,
        );
        assert!(result.is_ok());
    }
}
