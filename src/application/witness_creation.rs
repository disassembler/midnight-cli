use crate::crypto::{Ecdsa, Ed25519, Sr25519};
use crate::domain::{DomainError, DomainResult, KeyPurpose, KeyTypeId};
use crate::storage::KeyReader;
use chrono::Utc;
use parity_scale_codec::{Compact, Encode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sp_core::hashing::blake2_256;
use std::io::{self, Write};
use std::path::Path;
use std::str::FromStr;

/// Witness output format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessOutput {
    pub version: String,
    pub payload: PayloadInfo,
    pub signature: SignatureInfo,
    pub metadata: WitnessMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadInfo {
    pub hash: String,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: String,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    #[serde(rename = "type")]
    pub sig_type: String,
    pub value: String,
    pub signer: SignerInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "ss58Address")]
    pub ss58_address: Option<String>,
    #[serde(rename = "derivationPath")]
    pub derivation_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessMetadata {
    pub timestamp: String,
    pub purpose: String,
    pub description: Option<String>,
}

/// Transaction metadata for extrinsic construction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionMetadata {
    #[serde(rename = "signerAddress")]
    pub signer_address: String,
    pub nonce: u64,
    pub method: String,
    pub era: String,
    pub tip: u64,
    #[serde(rename = "specVersion")]
    pub spec_version: u32,
    #[serde(rename = "transactionVersion")]
    pub transaction_version: u32,
    #[serde(rename = "genesisHash")]
    pub genesis_hash: String,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
}

/// Signer data for witness creation
struct SignerData<'a> {
    signature: &'a [u8],
    public_key: &'a [u8],
    key_type: KeyTypeId,
    ss58_address: Option<String>,
    derivation_path: Option<String>,
}

/// Witness creation use case
pub struct WitnessCreation;

impl WitnessCreation {
    /// Create a witness from a .skey file
    pub fn create_from_key_file(
        payload_path: &Path,
        key_file_path: &Path,
        purpose: KeyPurpose,
        skip_confirmation: bool,
        description: Option<String>,
    ) -> DomainResult<WitnessOutput> {
        // Read payload (handles both hex-encoded and binary formats)
        let payload_bytes = Self::read_payload(payload_path)?;

        // Display and confirm
        if !skip_confirmation {
            Self::display_and_confirm(&payload_bytes)?;
        }

        // Load key from file
        let (key_type, secret_bytes) = KeyReader::load_keypair_from_skey(key_file_path)?;

        // Sign based on key type
        match key_type {
            KeyTypeId::Sr25519 => {
                let pair = Sr25519::from_secret_hex(&hex::encode(&secret_bytes))?;
                let signature = Sr25519::sign(&pair, &payload_bytes);
                let public = Sr25519::public_key(&pair);
                let ss58_address = Sr25519::to_ss58_address(&public);

                Self::create_witness_output(
                    &payload_bytes,
                    SignerData {
                        signature: signature.as_ref(),
                        public_key: public.as_ref(),
                        key_type,
                        ss58_address: Some(ss58_address),
                        derivation_path: None,
                    },
                    purpose,
                    description,
                )
            }
            KeyTypeId::Ed25519 => {
                let pair = Ed25519::from_secret_hex(&hex::encode(&secret_bytes))?;
                let signature = Ed25519::sign(&pair, &payload_bytes);
                let public = Ed25519::public_key(&pair);
                let ss58_address = Ed25519::to_ss58_address(&public);

                Self::create_witness_output(
                    &payload_bytes,
                    SignerData {
                        signature: signature.as_ref(),
                        public_key: public.as_ref(),
                        key_type,
                        ss58_address: Some(ss58_address),
                        derivation_path: None,
                    },
                    purpose,
                    description,
                )
            }
            KeyTypeId::Ecdsa => {
                let pair = Ecdsa::from_secret_hex(&hex::encode(&secret_bytes))?;
                let signature = Ecdsa::sign(&pair, &payload_bytes);
                let public = Ecdsa::public_key(&pair);

                Self::create_witness_output(
                    &payload_bytes,
                    SignerData {
                        signature: signature.as_ref(),
                        public_key: public.as_ref(),
                        key_type,
                        ss58_address: None, // ECDSA doesn't have SS58 address
                        derivation_path: None,
                    },
                    purpose,
                    description,
                )
            }
            KeyTypeId::Secp256k1 => {
                Err(DomainError::UnsupportedDerivation {
                    key_type: "secp256k1".to_string(),
                    path: "Payment key witness creation from .skey files not yet implemented".to_string(),
                })
            }
        }
    }

    /// Create a witness from on-demand mnemonic derivation
    pub fn create_from_mnemonic(
        payload_path: &Path,
        mnemonic: &str,
        derivation_path: &str,
        key_type: KeyTypeId,
        purpose: KeyPurpose,
        skip_confirmation: bool,
        description: Option<String>,
    ) -> DomainResult<WitnessOutput> {
        // Read payload (handles both hex-encoded and binary formats)
        let payload_bytes = Self::read_payload(payload_path)?;

        // Display and confirm
        if !skip_confirmation {
            Self::display_and_confirm(&payload_bytes)?;
        }

        // Build SURI and sign
        let suri_str = format!("{}{}", mnemonic, derivation_path);

        match key_type {
            KeyTypeId::Sr25519 => {
                let pair = Sr25519::from_suri(&suri_str)?;
                let signature = Sr25519::sign(&pair, &payload_bytes);
                let public = Sr25519::public_key(&pair);
                let ss58_address = Sr25519::to_ss58_address(&public);

                Self::create_witness_output(
                    &payload_bytes,
                    SignerData {
                        signature: signature.as_ref(),
                        public_key: public.as_ref(),
                        key_type,
                        ss58_address: Some(ss58_address),
                        derivation_path: Some(derivation_path.to_string()),
                    },
                    purpose,
                    description,
                )
            }
            KeyTypeId::Ed25519 => {
                let pair = Ed25519::from_suri(&suri_str)?;
                let signature = Ed25519::sign(&pair, &payload_bytes);
                let public = Ed25519::public_key(&pair);
                let ss58_address = Ed25519::to_ss58_address(&public);

                Self::create_witness_output(
                    &payload_bytes,
                    SignerData {
                        signature: signature.as_ref(),
                        public_key: public.as_ref(),
                        key_type,
                        ss58_address: Some(ss58_address),
                        derivation_path: Some(derivation_path.to_string()),
                    },
                    purpose,
                    description,
                )
            }
            KeyTypeId::Ecdsa => {
                let pair = Ecdsa::from_suri(&suri_str)?;
                let signature = Ecdsa::sign(&pair, &payload_bytes);
                let public = Ecdsa::public_key(&pair);

                Self::create_witness_output(
                    &payload_bytes,
                    SignerData {
                        signature: signature.as_ref(),
                        public_key: public.as_ref(),
                        key_type,
                        ss58_address: None, // ECDSA doesn't have SS58 address
                        derivation_path: Some(derivation_path.to_string()),
                    },
                    purpose,
                    description,
                )
            }
            KeyTypeId::Secp256k1 => {
                Err(DomainError::UnsupportedDerivation {
                    key_type: "secp256k1".to_string(),
                    path: "Payment key witness creation with SURI not supported - use BIP-32 paths instead".to_string(),
                })
            }
        }
    }

    /// Create a witness from mnemonic file
    pub fn create_from_mnemonic_file(
        payload_path: &Path,
        mnemonic_file: &Path,
        derivation_path: &str,
        key_type: KeyTypeId,
        purpose: KeyPurpose,
        skip_confirmation: bool,
        description: Option<String>,
    ) -> DomainResult<WitnessOutput> {
        let mnemonic = KeyReader::read_mnemonic_from_file(mnemonic_file)?;
        Self::create_from_mnemonic(
            payload_path,
            mnemonic.expose_secret(),
            derivation_path,
            key_type,
            purpose,
            skip_confirmation,
            description,
        )
    }

    /// Read payload from file, detecting and decoding hex-encoded content if present
    ///
    /// Supports two formats:
    /// 1. Hex-encoded: File contains hex string (with or without 0x prefix)
    /// 2. Binary: File contains raw bytes
    ///
    /// Also automatically detects and strips Compact length prefix if present.
    fn read_payload(payload_path: &Path) -> DomainResult<Vec<u8>> {
        let file_contents = std::fs::read(payload_path)?;

        let mut payload_bytes = if let Ok(text) = String::from_utf8(file_contents.clone()) {
            let trimmed = text.trim();

            // Check if it looks like hex (with or without 0x prefix)
            let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);

            // Only try to decode if it's non-empty and all valid hex characters
            if !hex_str.is_empty() && hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
                match hex::decode(hex_str) {
                    Ok(decoded) => {
                        eprintln!("ℹ️  Detected hex-encoded payload, decoded {} chars to {} bytes",
                                  hex_str.len(), decoded.len());
                        decoded
                    }
                    Err(_) => {
                        // If hex decode fails, use raw bytes
                        file_contents
                    }
                }
            } else {
                file_contents
            }
        } else {
            // Not UTF-8, use raw bytes
            file_contents
        };

        // Check for and strip Compact length prefix
        // Substrate Compact encoding for lengths:
        // - Single byte (00): 0b00xxxxxx, value = xxxxxx (0-63)
        // - Two bytes (01): 0bxxxxxxx1, value = xxxxxxx0 | (next_byte << 6)
        // - Four bytes (10): 0bxxxxxx10, value from next 4 bytes
        // We detect this by checking if the first 1-2 bytes encode the length of remaining bytes
        if !payload_bytes.is_empty() {
            let first_byte = payload_bytes[0];
            let mode = first_byte & 0x03; // Last 2 bits indicate mode

            // Decode compact length (handle single and two-byte modes)
            let (prefix_len, decoded_len) = match mode {
                0 => {
                    // Single-byte mode: 0b00xxxxxx
                    let len = (first_byte >> 2) as usize;
                    (1, len)
                }
                1 if payload_bytes.len() >= 2 => {
                    // Two-byte mode: 0bxxxxxxx1
                    let second_byte = payload_bytes[1];
                    let len = (((first_byte as usize) >> 2) | ((second_byte as usize) << 6)) as usize;
                    (2, len)
                }
                _ => {
                    // Other modes (4-byte, big integer) or can't decode - assume no prefix
                    (0, 0)
                }
            };

            // Check if this matches the remaining bytes length
            if prefix_len > 0 && payload_bytes.len() == decoded_len + prefix_len {
                eprintln!("ℹ️  Detected and stripped Compact length prefix ({} bytes, payload now {} bytes)",
                          prefix_len, decoded_len);
                payload_bytes = payload_bytes[prefix_len..].to_vec();
            }
        }

        Ok(payload_bytes)
    }

    /// Display payload info and get user confirmation
    fn display_and_confirm(payload_bytes: &[u8]) -> DomainResult<()> {
        let payload_hash = blake2_256(payload_bytes);
        let payload_hash_hex = format!("0x{}", hex::encode(payload_hash));

        eprintln!("\n⚠️  GOVERNANCE WITNESS CREATION ⚠️");
        eprintln!("═══════════════════════════════════");
        eprintln!("Payload Hash: {}", payload_hash_hex);
        eprintln!("Payload Size: {} bytes", payload_bytes.len());
        eprintln!("═══════════════════════════════════");
        eprintln!("\nThis signature will authorize a governance action on the Midnight network.");
        eprintln!("Verify the payload hash matches the published proposal before proceeding!");

        eprintln!("\nDo you want to sign this payload? (yes/no): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let response = input.trim().to_lowercase();
        if response != "yes" && response != "y" {
            return Err(DomainError::UserCancelled);
        }

        Ok(())
    }

    /// Create witness output structure
    fn create_witness_output(
        payload_bytes: &[u8],
        signer: SignerData,
        purpose: KeyPurpose,
        description: Option<String>,
    ) -> DomainResult<WitnessOutput> {
        let payload_hash = blake2_256(payload_bytes);
        let payload_hash_hex = format!("0x{}", hex::encode(payload_hash));
        let signature_hex = format!("0x{}", hex::encode(signer.signature));
        let public_key_hex = format!("0x{}", hex::encode(signer.public_key));

        Ok(WitnessOutput {
            version: "1.0".to_string(),
            payload: PayloadInfo {
                hash: payload_hash_hex,
                hash_algorithm: "blake2b-256".to_string(),
                size: payload_bytes.len(),
            },
            signature: SignatureInfo {
                sig_type: signer.key_type.as_str().to_string(),
                value: signature_hex,
                signer: SignerInfo {
                    public_key: public_key_hex,
                    ss58_address: signer.ss58_address,
                    derivation_path: signer.derivation_path,
                },
            },
            metadata: WitnessMetadata {
                timestamp: Utc::now().to_rfc3339(),
                purpose: purpose.as_str().to_string(),
                description,
            },
        })
    }

    /// Construct a signed extrinsic from transaction metadata and signature
    pub fn construct_signed_extrinsic(
        tx_metadata_path: &Path,
        signature: &[u8],
        public_key: &[u8],
    ) -> DomainResult<String> {
        // Read and parse transaction metadata JSON
        let tx_json = std::fs::read_to_string(tx_metadata_path)?;
        let tx_metadata: TransactionMetadata = serde_json::from_str(&tx_json)?;

        // Version byte for signed extrinsic (bit 7 = signed, bits 0-6 = version 4)
        let version_byte: u8 = 0x84;

        // Decode address from SS58 to get the public key bytes
        // For Sr25519, the address is AccountId32 which is just the 32-byte public key
        // with SS58 encoding. We'll use the public key directly with AccountId32 format.
        let address_bytes = {
            // For a MultiAddress::Id variant (0x00 prefix + 32 byte AccountId)
            let mut bytes = vec![0x00]; // MultiAddress::Id variant
            bytes.extend_from_slice(public_key);
            bytes
        };

        // Decode signature (already in raw format)
        // For MultiSignature::Sr25519 variant (0x01 prefix + 64 byte signature)
        let signature_bytes = {
            let mut bytes = vec![0x01]; // MultiSignature::Sr25519 variant
            bytes.extend_from_slice(signature);
            bytes
        };

        // Decode era from hex
        let era_hex = tx_metadata.era.strip_prefix("0x").unwrap_or(&tx_metadata.era);
        let era_bytes = hex::decode(era_hex)?;

        // Encode nonce as Compact<u64>
        let nonce_bytes = Compact(tx_metadata.nonce).encode();

        // Encode tip as Compact<u128> (must match what was signed)
        let tip_bytes = Compact(tx_metadata.tip as u128).encode();

        // Decode method from hex
        let method_hex = tx_metadata.method.strip_prefix("0x").unwrap_or(&tx_metadata.method);
        let method_bytes = hex::decode(method_hex)?;

        // Construct the extrinsic without length prefix
        let mut extrinsic = Vec::new();
        extrinsic.push(version_byte);
        extrinsic.extend_from_slice(&address_bytes);
        extrinsic.extend_from_slice(&signature_bytes);
        extrinsic.extend_from_slice(&era_bytes);
        extrinsic.extend_from_slice(&nonce_bytes);
        extrinsic.extend_from_slice(&tip_bytes);
        extrinsic.extend_from_slice(&method_bytes);

        // Add compact length prefix
        let length_bytes = Compact(extrinsic.len() as u32).encode();
        let mut final_extrinsic = Vec::new();
        final_extrinsic.extend_from_slice(&length_bytes);
        final_extrinsic.extend_from_slice(&extrinsic);

        Ok(format!("0x{}", hex::encode(final_extrinsic)))
    }

    /// Verify a witness against a payload
    pub fn verify_witness(
        witness_path: &Path,
        payload_path: &Path,
    ) -> DomainResult<bool> {
        let witness_json = std::fs::read_to_string(witness_path)?;
        let witness: WitnessOutput = serde_json::from_str(&witness_json)?;

        // Read payload (handles both hex-encoded and binary formats)
        let payload_bytes = Self::read_payload(payload_path)?;
        let payload_hash = blake2_256(&payload_bytes);
        let payload_hash_hex = format!("0x{}", hex::encode(payload_hash));

        // Verify hash matches
        if witness.payload.hash != payload_hash_hex {
            return Ok(false);
        }

        // Parse key type
        let key_type = KeyTypeId::from_str(&witness.signature.sig_type)?;

        // Decode public key and signature
        let public_key_hex = witness.signature.signer.public_key.strip_prefix("0x")
            .unwrap_or(&witness.signature.signer.public_key);
        let public_key_bytes = hex::decode(public_key_hex)?;

        let signature_hex = witness.signature.value.strip_prefix("0x")
            .unwrap_or(&witness.signature.value);
        let signature_bytes = hex::decode(signature_hex)?;

        // Verify signature
        match key_type {
            KeyTypeId::Sr25519 => {
                use sp_core::sr25519::{Public, Signature};

                if public_key_bytes.len() != 32 {
                    return Err(DomainError::CryptoError("Invalid public key length".to_string()));
                }
                let mut public_array = [0u8; 32];
                public_array.copy_from_slice(&public_key_bytes);
                let public = Public::from_raw(public_array);

                if signature_bytes.len() != 64 {
                    return Err(DomainError::CryptoError("Invalid signature length".to_string()));
                }
                let mut sig_array = [0u8; 64];
                sig_array.copy_from_slice(&signature_bytes);
                let signature = Signature::from_raw(sig_array);

                Ok(Sr25519::verify(&public, &payload_bytes, &signature))
            }
            KeyTypeId::Ed25519 => {
                use sp_core::ed25519::{Public, Signature};

                if public_key_bytes.len() != 32 {
                    return Err(DomainError::CryptoError("Invalid public key length".to_string()));
                }
                let mut public_array = [0u8; 32];
                public_array.copy_from_slice(&public_key_bytes);
                let public = Public::from_raw(public_array);

                if signature_bytes.len() != 64 {
                    return Err(DomainError::CryptoError("Invalid signature length".to_string()));
                }
                let mut sig_array = [0u8; 64];
                sig_array.copy_from_slice(&signature_bytes);
                let signature = Signature::from_raw(sig_array);

                Ok(Ed25519::verify(&public, &payload_bytes, &signature))
            }
            KeyTypeId::Ecdsa => {
                use sp_core::ecdsa::{Public, Signature};

                if public_key_bytes.len() != 33 {
                    return Err(DomainError::CryptoError("Invalid ECDSA public key length".to_string()));
                }
                let mut public_array = [0u8; 33];
                public_array.copy_from_slice(&public_key_bytes);
                let public = Public::from_raw(public_array);

                if signature_bytes.len() != 65 {
                    return Err(DomainError::CryptoError("Invalid ECDSA signature length".to_string()));
                }
                let mut sig_array = [0u8; 65];
                sig_array.copy_from_slice(&signature_bytes);
                let signature = Signature::from_raw(sig_array);

                Ok(Ecdsa::verify(&public, &payload_bytes, &signature))
            }
            KeyTypeId::Secp256k1 => {
                Err(DomainError::UnsupportedDerivation {
                    key_type: "secp256k1".to_string(),
                    path: "Payment key witness verification not yet implemented".to_string(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::KeyGeneration;
    use crate::storage::KeyWriter;
    use tempfile::{NamedTempFile, TempDir};
    use std::io::Write as IoWrite;

    const TEST_MNEMONIC: &str =
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

    #[test]
    fn test_create_from_key_file() {
        let temp_dir = TempDir::new().unwrap();

        // Generate and save a key
        let key = KeyGeneration::generate_from_mnemonic(TEST_MNEMONIC, KeyPurpose::Governance, None)
            .unwrap();
        let (skey_path, _) =
            KeyWriter::write_cardano_key_pair(&key, temp_dir.path(), "test").unwrap();

        // Create a test payload
        let mut payload_file = NamedTempFile::new().unwrap();
        writeln!(payload_file, "test governance proposal").unwrap();

        // Create witness
        let witness = WitnessCreation::create_from_key_file(
            payload_file.path(),
            &skey_path,
            KeyPurpose::Governance,
            true, // skip confirmation
            Some("Test witness".to_string()),
        )
        .unwrap();

        assert_eq!(witness.version, "1.0");
        assert_eq!(witness.signature.sig_type, "sr25519");
        assert_eq!(witness.metadata.purpose, "governance");
        assert!(witness.signature.signer.ss58_address.is_some());
    }

    #[test]
    fn test_create_from_mnemonic() {
        let mut payload_file = NamedTempFile::new().unwrap();
        writeln!(payload_file, "test proposal").unwrap();

        let witness = WitnessCreation::create_from_mnemonic(
            payload_file.path(),
            TEST_MNEMONIC,
            "//midnight//governance//0",
            KeyTypeId::Sr25519,
            KeyPurpose::Governance,
            true,
            None,
        )
        .unwrap();

        assert!(witness.signature.signer.derivation_path.is_some());
        assert_eq!(
            witness.signature.signer.derivation_path.unwrap(),
            "//midnight//governance//0"
        );
    }

    #[test]
    fn test_verify_witness() {
        let temp_dir = TempDir::new().unwrap();

        // Create payload
        let payload_bytes = b"test governance proposal";
        let mut payload_file = NamedTempFile::new().unwrap();
        payload_file.write_all(payload_bytes).unwrap();

        // Create witness
        let witness = WitnessCreation::create_from_mnemonic(
            payload_file.path(),
            TEST_MNEMONIC,
            "//midnight//governance//0",
            KeyTypeId::Sr25519,
            KeyPurpose::Governance,
            true,
            None,
        )
        .unwrap();

        // Save witness
        let witness_path = temp_dir.path().join("witness.json");
        let witness_json = serde_json::to_string_pretty(&witness).unwrap();
        std::fs::write(&witness_path, witness_json).unwrap();

        // Verify
        let valid = WitnessCreation::verify_witness(&witness_path, payload_file.path()).unwrap();
        assert!(valid);

        // Test with wrong payload
        let mut wrong_payload = NamedTempFile::new().unwrap();
        writeln!(wrong_payload, "wrong payload").unwrap();

        let valid = WitnessCreation::verify_witness(&witness_path, wrong_payload.path()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_hex_encoded_payload() {
        use std::io::Write;

        // Test data: some arbitrary bytes
        let original_bytes = b"test governance proposal";

        // Create hex-encoded payload file (with 0x prefix)
        let mut hex_payload_file = NamedTempFile::new().unwrap();
        let hex_string = format!("0x{}", hex::encode(original_bytes));
        write!(hex_payload_file, "{}", hex_string).unwrap();
        hex_payload_file.flush().unwrap();

        // Create binary payload file
        let mut binary_payload_file = NamedTempFile::new().unwrap();
        binary_payload_file.write_all(original_bytes).unwrap();
        binary_payload_file.flush().unwrap();

        // Read both and verify they produce the same result
        let hex_result = WitnessCreation::read_payload(hex_payload_file.path()).unwrap();
        let binary_result = WitnessCreation::read_payload(binary_payload_file.path()).unwrap();

        assert_eq!(hex_result, binary_result);
        assert_eq!(hex_result, original_bytes);

        // Verify hashes are the same
        let hex_hash = blake2_256(&hex_result);
        let binary_hash = blake2_256(&binary_result);
        assert_eq!(hex_hash, binary_hash);
    }

    #[test]
    fn test_hex_encoded_payload_without_prefix() {
        use std::io::Write;

        let original_bytes = b"test data";

        // Create hex-encoded payload file (without 0x prefix)
        let mut hex_payload_file = NamedTempFile::new().unwrap();
        let hex_string = hex::encode(original_bytes);
        write!(hex_payload_file, "{}", hex_string).unwrap();
        hex_payload_file.flush().unwrap();

        // Read and verify
        let result = WitnessCreation::read_payload(hex_payload_file.path()).unwrap();
        assert_eq!(result, original_bytes);
    }

    #[test]
    fn test_witness_with_hex_payload() {
        // Create hex-encoded payload
        let original_bytes = b"governance action";
        let mut hex_payload_file = NamedTempFile::new().unwrap();
        let hex_string = format!("0x{}", hex::encode(original_bytes));
        write!(hex_payload_file, "{}", hex_string).unwrap();
        hex_payload_file.flush().unwrap();

        // Create witness from hex payload
        let witness = WitnessCreation::create_from_mnemonic(
            hex_payload_file.path(),
            TEST_MNEMONIC,
            "//midnight//governance",
            KeyTypeId::Sr25519,
            KeyPurpose::Governance,
            true,
            Some("Hex payload test".to_string()),
        )
        .unwrap();

        // Verify the hash in witness matches what we expect from the decoded bytes
        let expected_hash = blake2_256(original_bytes);
        let expected_hash_hex = format!("0x{}", hex::encode(expected_hash));
        assert_eq!(witness.payload.hash, expected_hash_hex);

        // Verify payload size is the decoded size, not the hex string length
        assert_eq!(witness.payload.size, original_bytes.len());
    }
}
