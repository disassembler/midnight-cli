use crate::crypto::{generate_mnemonic, Ed25519, Sr25519, SuriParser};
use crate::domain::{
    DomainResult, KeyMaterial, MidnightKeyPath, KeyPurpose, KeyTypeId,
};
use crate::storage::{KeyReader, KeyWriter};
use secrecy::{ExposeSecret, SecretString};
use std::path::{Path, PathBuf};

/// Key generation use case
pub struct KeyGeneration;

impl KeyGeneration {
    /// Generate a new key with a random mnemonic
    pub fn generate_with_random_mnemonic(
        purpose: KeyPurpose,
        index: u32,
    ) -> DomainResult<(KeyMaterial, SecretString)> {
        let mnemonic = generate_mnemonic()?;
        let key_material = Self::derive_from_mnemonic(
            mnemonic.expose_secret(),
            purpose,
            index,
        )?;

        Ok((key_material, mnemonic))
    }

    /// Generate a key from an existing mnemonic
    pub fn generate_from_mnemonic(
        mnemonic: &str,
        purpose: KeyPurpose,
        index: u32,
    ) -> DomainResult<KeyMaterial> {
        Self::derive_from_mnemonic(mnemonic, purpose, index)
    }

    /// Generate a key from a mnemonic file (supports GPG encryption)
    #[allow(dead_code)]
    pub fn generate_from_mnemonic_file(
        mnemonic_file: &Path,
        purpose: KeyPurpose,
        index: u32,
    ) -> DomainResult<KeyMaterial> {
        let mnemonic = KeyReader::read_mnemonic_from_file(mnemonic_file)?;
        Self::derive_from_mnemonic(mnemonic.expose_secret(), purpose, index)
    }

    /// Generate a key with a custom derivation path
    pub fn generate_with_custom_derivation(
        mnemonic: &str,
        key_type: KeyTypeId,
        purpose: KeyPurpose,
        derivation_path: &str,
    ) -> DomainResult<KeyMaterial> {
        // Build SURI
        let suri_str = format!("{}{}", mnemonic, derivation_path);
        let suri = SuriParser::parse(&suri_str)?;

        // Validate derivation is supported for this key type
        suri.validate(key_type)?;

        // Generate key
        Self::generate_from_suri(&suri_str, key_type, purpose, Some(derivation_path.to_string()))
    }

    /// Internal: Derive key from mnemonic using standard Midnight path
    fn derive_from_mnemonic(
        mnemonic: &str,
        purpose: KeyPurpose,
        index: u32,
    ) -> DomainResult<KeyMaterial> {
        let path = MidnightKeyPath::from_purpose(purpose, index);
        let key_type = path.key_type();
        let derivation_path = path.to_string_path();

        let suri_str = format!("{}{}", mnemonic, derivation_path);

        Self::generate_from_suri(&suri_str, key_type, purpose, Some(derivation_path))
    }

    /// Internal: Generate from SURI string
    fn generate_from_suri(
        suri: &str,
        key_type: KeyTypeId,
        purpose: KeyPurpose,
        derivation_path: Option<String>,
    ) -> DomainResult<KeyMaterial> {
        match key_type {
            KeyTypeId::Sr25519 => {
                let pair = Sr25519::from_suri(suri)?;
                Ok(Sr25519::to_key_material(&pair, purpose, derivation_path))
            }
            KeyTypeId::Ed25519 => {
                let pair = Ed25519::from_suri(suri)?;
                Ok(Ed25519::to_key_material(&pair, purpose, derivation_path))
            }
        }
    }

    /// Generate and save a key as Cardano-style .skey/.vkey files
    #[allow(dead_code)]
    pub fn generate_and_save(
        mnemonic: &str,
        purpose: KeyPurpose,
        index: u32,
        output_dir: &Path,
        filename: Option<String>,
    ) -> DomainResult<(PathBuf, PathBuf)> {
        let key_material = Self::derive_from_mnemonic(mnemonic, purpose, index)?;

        let base_filename = filename.unwrap_or_else(|| {
            KeyWriter::default_filename(&key_material, Some(index))
        });

        KeyWriter::write_cardano_key_pair(&key_material, output_dir, &base_filename)
    }

    /// Batch generate multiple keys
    pub fn batch_generate(
        mnemonic: &str,
        purposes: &[KeyPurpose],
        indices: &[u32],
        output_dir: &Path,
    ) -> DomainResult<Vec<(KeyPurpose, u32, PathBuf, PathBuf)>> {
        let mut results = Vec::new();

        for &purpose in purposes {
            for &index in indices {
                let key_material = Self::derive_from_mnemonic(mnemonic, purpose, index)?;
                let filename = KeyWriter::default_filename(&key_material, Some(index));

                let (skey_path, vkey_path) =
                    KeyWriter::write_cardano_key_pair(&key_material, output_dir, &filename)?;

                results.push((purpose, index, skey_path, vkey_path));
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const TEST_MNEMONIC: &str =
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

    #[test]
    fn test_generate_with_random_mnemonic() {
        let (key, mnemonic) =
            KeyGeneration::generate_with_random_mnemonic(KeyPurpose::Governance, 0).unwrap();

        assert_eq!(key.purpose, KeyPurpose::Governance);
        assert_eq!(key.key_type, KeyTypeId::Sr25519);
        assert!(key.has_secret());

        // Mnemonic should be 24 words
        let phrase = mnemonic.expose_secret();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn test_generate_from_mnemonic() {
        let key =
            KeyGeneration::generate_from_mnemonic(TEST_MNEMONIC, KeyPurpose::Governance, 0)
                .unwrap();

        assert_eq!(key.purpose, KeyPurpose::Governance);
        assert_eq!(key.key_type, KeyTypeId::Sr25519);
        assert_eq!(
            key.derivation_path,
            Some("//midnight//governance//0".to_string())
        );
    }

    #[test]
    fn test_generate_with_custom_derivation() {
        let key = KeyGeneration::generate_with_custom_derivation(
            TEST_MNEMONIC,
            KeyTypeId::Sr25519,
            KeyPurpose::Payment,
            "//custom//path//5",
        )
        .unwrap();

        assert_eq!(key.purpose, KeyPurpose::Payment);
        assert_eq!(key.key_type, KeyTypeId::Sr25519);
        assert_eq!(
            key.derivation_path,
            Some("//custom//path//5".to_string())
        );
    }

    #[test]
    fn test_generate_and_save() {
        let temp_dir = TempDir::new().unwrap();

        let (skey_path, vkey_path) = KeyGeneration::generate_and_save(
            TEST_MNEMONIC,
            KeyPurpose::Governance,
            0,
            temp_dir.path(),
            None,
        )
        .unwrap();

        assert!(skey_path.exists());
        assert!(vkey_path.exists());
        assert_eq!(skey_path.file_name().unwrap(), "governance-0.skey");
        assert_eq!(vkey_path.file_name().unwrap(), "governance-0.vkey");
    }

    #[test]
    fn test_batch_generate() {
        let temp_dir = TempDir::new().unwrap();

        let purposes = vec![KeyPurpose::Governance, KeyPurpose::Payment];
        let indices = vec![0, 1];

        let results =
            KeyGeneration::batch_generate(TEST_MNEMONIC, &purposes, &indices, temp_dir.path())
                .unwrap();

        // Should generate 2 purposes × 2 indices = 4 key pairs
        assert_eq!(results.len(), 4);

        // Check all files exist
        for (_, _, skey_path, vkey_path) in &results {
            assert!(skey_path.exists());
            assert!(vkey_path.exists());
        }

        // Check we have the right combinations
        assert!(results
            .iter()
            .any(|(p, i, _, _)| *p == KeyPurpose::Governance && *i == 0));
        assert!(results
            .iter()
            .any(|(p, i, _, _)| *p == KeyPurpose::Payment && *i == 1));
    }

    #[test]
    fn test_different_key_types() {
        // Governance should be Sr25519
        let gov_key =
            KeyGeneration::generate_from_mnemonic(TEST_MNEMONIC, KeyPurpose::Governance, 0)
                .unwrap();
        assert_eq!(gov_key.key_type, KeyTypeId::Sr25519);

        // Finality should be Ed25519
        let fin_key =
            KeyGeneration::generate_from_mnemonic(TEST_MNEMONIC, KeyPurpose::Finality, 0)
                .unwrap();
        assert_eq!(fin_key.key_type, KeyTypeId::Ed25519);
    }
}
