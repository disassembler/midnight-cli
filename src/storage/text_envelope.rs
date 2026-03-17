// SPDX-License-Identifier: Apache-2.0

//! Cardano-CLI compatible TextEnvelope format
//!
//! This module provides support for reading and writing files in the TextEnvelope
//! format used by cardano-cli, enabling interoperability between midnight-cli
//! and standard Cardano tooling.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// TextEnvelope wraps CBOR-encoded data with type and description metadata
///
/// This format is used by cardano-cli for transaction bodies, witnesses, and
/// signed transactions. It allows tools to identify the content type before
/// decoding the CBOR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEnvelope {
    /// Type identifier (e.g., "Unwitnessed Tx BabbageEra")
    #[serde(rename = "type")]
    pub envelope_type: String,

    /// Human-readable description
    pub description: String,

    /// Hex-encoded CBOR data
    #[serde(rename = "cborHex")]
    pub cbor_hex: String,
}

impl TextEnvelope {
    /// Create a new TextEnvelope with the given type, description, and CBOR data
    pub fn new(envelope_type: impl Into<String>, description: impl Into<String>, cbor: &[u8]) -> Self {
        Self {
            envelope_type: envelope_type.into(),
            description: description.into(),
            cbor_hex: hex::encode(cbor),
        }
    }

    /// Create an unwitnessed transaction envelope (matches cardano-cli output)
    pub fn unwitnessed_tx(cbor: &[u8], description: impl Into<String>) -> Self {
        Self::new("Unwitnessed Tx BabbageEra", description, cbor)
    }

    /// Create a transaction witness envelope (matches cardano-cli output)
    pub fn tx_witness(cbor: &[u8], description: impl Into<String>) -> Self {
        Self::new("TxWitness BabbageEra", description, cbor)
    }

    /// Create a signed transaction envelope (matches cardano-cli output)
    pub fn tx_signed(cbor: &[u8], description: impl Into<String>) -> Self {
        Self::new("Tx BabbageEra", description, cbor)
    }

    /// Create a payment signing key envelope (matches cardano-cli output)
    pub fn payment_signing_key(cbor: &[u8], description: impl Into<String>) -> Self {
        Self::new("PaymentSigningKeyShelley_ed25519", description, cbor)
    }

    /// Create a payment verification key envelope (matches cardano-cli output)
    pub fn payment_verification_key(cbor: &[u8], description: impl Into<String>) -> Self {
        Self::new("PaymentVerificationKeyShelley_ed25519", description, cbor)
    }

    /// Read a TextEnvelope from a JSON file
    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;

        let envelope: TextEnvelope = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse TextEnvelope from: {}", path.display()))?;

        Ok(envelope)
    }

    /// Write this TextEnvelope to a JSON file
    pub fn write_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize TextEnvelope")?;

        fs::write(path, json)
            .with_context(|| format!("Failed to write file: {}", path.display()))?;

        Ok(())
    }

    /// Decode the CBOR hex data into bytes
    pub fn decode_cbor(&self) -> Result<Vec<u8>> {
        hex::decode(&self.cbor_hex)
            .with_context(|| format!("Failed to decode CBOR hex for type: {}", self.envelope_type))
    }

    /// Get the CBOR data as bytes (same as decode_cbor, for convenience)
    pub fn cbor_bytes(&self) -> Result<Vec<u8>> {
        self.decode_cbor()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_unwitnessed_tx() {
        let cbor = vec![0x84, 0xa4, 0x00, 0x01];
        let envelope = TextEnvelope::unwitnessed_tx(&cbor, "Test transaction");

        assert_eq!(envelope.envelope_type, "Unwitnessed Tx BabbageEra");
        assert_eq!(envelope.description, "Test transaction");
        assert_eq!(envelope.cbor_hex, "84a40001");
    }

    #[test]
    fn test_create_tx_witness() {
        let cbor = vec![0x82, 0x58, 0x20];
        let envelope = TextEnvelope::tx_witness(&cbor, "Test witness");

        assert_eq!(envelope.envelope_type, "TxWitness BabbageEra");
        assert_eq!(envelope.description, "Test witness");
        assert_eq!(envelope.cbor_hex, "825820");
    }

    #[test]
    fn test_create_tx_signed() {
        let cbor = vec![0x84, 0xa6, 0x00];
        let envelope = TextEnvelope::tx_signed(&cbor, "Test signed tx");

        assert_eq!(envelope.envelope_type, "Tx BabbageEra");
        assert_eq!(envelope.description, "Test signed tx");
        assert_eq!(envelope.cbor_hex, "84a600");
    }

    #[test]
    fn test_decode_cbor() {
        let cbor = vec![0x84, 0xa4, 0x00, 0x01];
        let envelope = TextEnvelope::unwitnessed_tx(&cbor, "Test");

        let decoded = envelope.decode_cbor().unwrap();
        assert_eq!(decoded, cbor);
    }

    #[test]
    fn test_read_write_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txbody");

        let cbor = vec![0x84, 0xa4, 0x00, 0x01, 0x02, 0x03];
        let original = TextEnvelope::unwitnessed_tx(&cbor, "Test transaction");

        original.write_to_file(&file_path).unwrap();
        let loaded = TextEnvelope::read_from_file(&file_path).unwrap();

        assert_eq!(loaded.envelope_type, original.envelope_type);
        assert_eq!(loaded.description, original.description);
        assert_eq!(loaded.cbor_hex, original.cbor_hex);
        assert_eq!(loaded.decode_cbor().unwrap(), cbor);
    }

    #[test]
    fn test_payment_key_types() {
        let cbor = vec![0x58, 0x20];

        let skey = TextEnvelope::payment_signing_key(&cbor, "Test skey");
        assert_eq!(skey.envelope_type, "PaymentSigningKeyShelley_ed25519");

        let vkey = TextEnvelope::payment_verification_key(&cbor, "Test vkey");
        assert_eq!(vkey.envelope_type, "PaymentVerificationKeyShelley_ed25519");
    }
}
