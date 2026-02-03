use std::path::PathBuf;
use thiserror::Error;

/// Domain-level errors for midnight-cli operations
#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Invalid SURI format: {reason}")]
    InvalidSuri {
        suri: String,
        reason: String,
    },

    #[error("Unsupported derivation for key type {key_type}: {path}")]
    UnsupportedDerivation {
        key_type: String,
        path: String,
    },

    #[error("Invalid key purpose: {0}")]
    InvalidKeyPurpose(String),

    #[error("Invalid key type: {0}")]
    InvalidKeyType(String),

    #[error("Key file not found: {}", .path.display())]
    KeyFileNotFound {
        path: PathBuf,
    },

    #[error("Invalid key file format: {reason}")]
    InvalidKeyFile {
        reason: String,
    },

    #[error("GPG decryption failed for {}: {}", .file.display(), .gpg_error)]
    GpgDecryptionFailed {
        file: PathBuf,
        gpg_error: String,
    },

    #[error("Invalid mnemonic phrase: {0}")]
    InvalidMnemonic(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("CBOR error: {0}")]
    Cbor(#[from] serde_cbor::Error),

    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("User cancelled operation")]
    UserCancelled,

    #[error("Invalid payload: {0}")]
    InvalidPayload(String),
}

pub type DomainResult<T> = Result<T, DomainError>;
