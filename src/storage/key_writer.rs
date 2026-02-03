//! Key file writing utilities
#![allow(dead_code)]

use crate::domain::{DomainResult, KeyMaterial};
use crate::storage::cardano_format::CardanoKeyFile;
use std::path::{Path, PathBuf};

/// Write keys to files in various formats
pub struct KeyWriter;

impl KeyWriter {
    /// Write a key as Cardano-style .skey and .vkey files
    /// Returns paths to the created files: (skey_path, vkey_path)
    pub fn write_cardano_key_pair(
        key: &KeyMaterial,
        output_dir: &Path,
        base_filename: &str,
    ) -> DomainResult<(PathBuf, PathBuf)> {
        // Ensure output directory exists
        if !output_dir.exists() {
            std::fs::create_dir_all(output_dir)?;
        }

        // Create .skey file
        let skey_path = output_dir.join(format!("{}.skey", base_filename));
        let skey_file = CardanoKeyFile::signing_key(key)?;
        skey_file.write_to_file(&skey_path)?;

        // Set restrictive permissions on .skey file (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&skey_path)?.permissions();
            perms.set_mode(0o600); // rw-------
            std::fs::set_permissions(&skey_path, perms)?;
        }

        // Create .vkey file
        let vkey_path = output_dir.join(format!("{}.vkey", base_filename));
        let vkey_file = CardanoKeyFile::verification_key(key)?;
        vkey_file.write_to_file(&vkey_path)?;

        Ok((skey_path, vkey_path))
    }

    /// Write just the signing key (.skey)
    pub fn write_signing_key(
        key: &KeyMaterial,
        path: &Path,
    ) -> DomainResult<PathBuf> {
        let skey_file = CardanoKeyFile::signing_key(key)?;
        skey_file.write_to_file(path)?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }

        Ok(path.to_path_buf())
    }

    /// Write just the verification key (.vkey)
    pub fn write_verification_key(
        key: &KeyMaterial,
        path: &Path,
    ) -> DomainResult<PathBuf> {
        let vkey_file = CardanoKeyFile::verification_key(key)?;
        vkey_file.write_to_file(path)?;

        Ok(path.to_path_buf())
    }

    /// Get default filename for a key based on its purpose and optional index
    pub fn default_filename(key: &KeyMaterial, index: Option<u32>) -> String {
        let base = key.purpose.default_filename();
        if let Some(idx) = index {
            format!("{}-{}", base, idx)
        } else {
            base.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{KeyMetadata, KeyPurpose, KeyTypeId};
    use secrecy::SecretString;
    use tempfile::TempDir;

    #[test]
    fn test_write_cardano_key_pair() {
        let temp_dir = TempDir::new().unwrap();
        let secret_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let key = KeyMaterial::new(
            KeyTypeId::Sr25519,
            KeyPurpose::Governance,
            vec![1, 2, 3, 4],
            Some(SecretString::new(secret_hex.to_string())),
        )
        .with_metadata(KeyMetadata::default().with_description("Test key"));

        let (skey_path, vkey_path) =
            KeyWriter::write_cardano_key_pair(&key, temp_dir.path(), "governance").unwrap();

        // Check files exist
        assert!(skey_path.exists());
        assert!(vkey_path.exists());

        // Check filenames
        assert_eq!(skey_path.file_name().unwrap(), "governance.skey");
        assert_eq!(vkey_path.file_name().unwrap(), "governance.vkey");

        // Check .skey permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&skey_path).unwrap().permissions();
            let mode = perms.mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // Verify content
        let skey_content = std::fs::read_to_string(&skey_path).unwrap();
        assert!(skey_content.contains("GovernanceSigningKeyMidnight_sr25519"));

        let vkey_content = std::fs::read_to_string(&vkey_path).unwrap();
        assert!(vkey_content.contains("GovernanceVerificationKeyMidnight_sr25519"));
    }

    #[test]
    fn test_default_filename() {
        let key = KeyMaterial::new(
            KeyTypeId::Sr25519,
            KeyPurpose::Governance,
            vec![],
            None,
        );

        assert_eq!(KeyWriter::default_filename(&key, None), "governance");
        assert_eq!(KeyWriter::default_filename(&key, Some(0)), "governance-0");
        assert_eq!(KeyWriter::default_filename(&key, Some(5)), "governance-5");
    }

    #[test]
    fn test_write_creates_directory() {
        let temp_dir = TempDir::new().unwrap();
        let nested_dir = temp_dir.path().join("nested").join("path");

        let key = KeyMaterial::new(
            KeyTypeId::Sr25519,
            KeyPurpose::Payment,
            vec![1, 2, 3],
            Some(SecretString::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string())),
        );

        let (skey_path, _) =
            KeyWriter::write_cardano_key_pair(&key, &nested_dir, "payment").unwrap();

        assert!(nested_dir.exists());
        assert!(skey_path.exists());
    }
}
