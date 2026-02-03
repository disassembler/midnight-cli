use crate::domain::{DomainError, DomainResult};
use std::path::Path;
use std::process::Command;

/// GPG encryption and decryption support
pub struct Gpg;

impl Gpg {
    /// Check if a file is GPG encrypted
    pub fn is_encrypted(path: &Path) -> bool {
        // Check file extension
        if path.extension().and_then(|s| s.to_str()) == Some("gpg") {
            return true;
        }

        // Check GPG magic bytes if file exists
        if let Ok(bytes) = std::fs::read(path) {
            Self::has_gpg_magic_bytes(&bytes)
        } else {
            false
        }
    }

    /// Check for GPG magic bytes
    fn has_gpg_magic_bytes(bytes: &[u8]) -> bool {
        if bytes.len() < 2 {
            return false;
        }

        // PGP/GPG files typically start with specific magic bytes
        // OpenPGP message format: 0x85 (packet tag for compressed data)
        // or 0x8c (packet tag for marker packet)
        // or other packet types in range 0x80-0xBF
        matches!(bytes[0], 0x80..=0xBF) ||
        // ASCII armored format starts with "-----BEGIN PGP"
        bytes.starts_with(b"-----BEGIN PGP")
    }

    /// Decrypt a GPG encrypted file and return the contents
    pub fn decrypt_file(path: &Path) -> DomainResult<String> {
        // Check if gpg is available
        if !Self::is_gpg_available() {
            return Err(DomainError::GpgDecryptionFailed {
                file: path.to_path_buf(),
                gpg_error: "GPG is not available. Please install gnupg.".to_string(),
            });
        }

        // Run gpg --decrypt
        let output = Command::new("gpg")
            .args(&["--decrypt", "--quiet", "--batch"])
            .arg(path)
            .output()
            .map_err(|e| DomainError::GpgDecryptionFailed {
                file: path.to_path_buf(),
                gpg_error: format!("Failed to execute gpg: {}", e),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DomainError::GpgDecryptionFailed {
                file: path.to_path_buf(),
                gpg_error: stderr.to_string(),
            });
        }

        let decrypted = String::from_utf8(output.stdout).map_err(|e| {
            DomainError::GpgDecryptionFailed {
                file: path.to_path_buf(),
                gpg_error: format!("Decrypted content is not valid UTF-8: {}", e),
            }
        })?;

        Ok(decrypted)
    }

    /// Check if gpg command is available
    pub fn is_gpg_available() -> bool {
        Command::new("gpg")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_is_encrypted_by_extension() {
        let path = PathBuf::from("test.txt.gpg");
        assert!(Gpg::is_encrypted(&path));

        let path = PathBuf::from("test.txt");
        assert!(!Gpg::is_encrypted(&path));
    }

    #[test]
    fn test_has_gpg_magic_bytes() {
        // ASCII armored PGP
        let armored = b"-----BEGIN PGP MESSAGE-----\nVersion: GnuPG";
        assert!(Gpg::has_gpg_magic_bytes(armored));

        // Binary PGP (packet tag byte)
        let binary = &[0x85, 0x01, 0x02, 0x03];
        assert!(Gpg::has_gpg_magic_bytes(binary));

        // Not PGP
        let plain = b"just plain text";
        assert!(!Gpg::has_gpg_magic_bytes(plain));

        // Empty
        assert!(!Gpg::has_gpg_magic_bytes(&[]));
    }

    #[test]
    fn test_gpg_availability() {
        // This test will pass/fail depending on whether GPG is installed
        // Just verify the function doesn't panic
        let _available = Gpg::is_gpg_available();
    }
}
