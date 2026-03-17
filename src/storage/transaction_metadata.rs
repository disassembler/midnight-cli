// SPDX-License-Identifier: Apache-2.0

//! Transaction metadata for air-gapped signing workflows
//!
//! This module provides metadata structures that accompany unsigned transaction
//! bodies to provide context for air-gapped signing. The metadata includes
//! information about required signers, threshold calculations, and proposal details.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Information about a governance member who can sign the transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    /// Cardano payment key hash (28 bytes, hex-encoded)
    #[serde(rename = "cardanoKeyHash")]
    pub cardano_key_hash: String,

    /// Midnight sr25519 public key (32 bytes, hex-encoded with 0x prefix)
    #[serde(rename = "sr25519PublicKey")]
    pub sr25519_public_key: String,

    /// SS58-encoded Substrate address
    #[serde(rename = "ss58Address")]
    pub ss58_address: String,

    /// Role description (e.g., "council_member", "ta_member")
    pub role: String,
}

/// Information about signature threshold requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturesNeeded {
    /// Note explaining threshold calculation
    pub note: String,

    /// Total number of current members
    #[serde(rename = "totalSigners")]
    pub total_signers: u32,

    /// Calculated threshold using formula: (2 * total + 2) / 3
    #[serde(rename = "calculatedThreshold")]
    pub calculated_threshold: u32,
}

impl SignaturesNeeded {
    /// Create a new SignaturesNeeded with the given total signers
    ///
    /// Calculates threshold using the formula: (2 * total + 2) / 3
    /// This matches the on-chain validator logic.
    pub fn new(total_signers: u32) -> Self {
        let calculated_threshold = Self::calculate_threshold(total_signers);
        Self {
            note: "Threshold calculated by contract: (2 * total_signers + 2) / 3".to_string(),
            total_signers,
            calculated_threshold,
        }
    }

    /// Calculate the threshold for a given number of signers
    ///
    /// Formula: (2 * total + 2) / 3
    ///
    /// Examples:
    /// - 3 signers → (2*3+2)/3 = 8/3 = 2 (need 2 of 3)
    /// - 5 signers → (2*5+2)/3 = 12/3 = 4 (need 4 of 5)
    /// - 7 signers → (2*7+2)/3 = 16/3 = 5 (need 5 of 7)
    pub fn calculate_threshold(total: u32) -> u32 {
        (2 * total + 2) / 3
    }
}

/// Details about the governance proposal being signed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalDetails {
    /// Current logic round (anti-replay counter)
    #[serde(rename = "currentLogicRound")]
    pub current_logic_round: u32,

    /// New logic round after this transaction
    #[serde(rename = "newLogicRound")]
    pub new_logic_round: u32,

    /// Optional: Description of what this proposal does
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Optional: Contract address being updated
    #[serde(skip_serializing_if = "Option::is_none", rename = "contractAddress")]
    pub contract_address: Option<String>,

    /// Optional: NFT policy ID
    #[serde(skip_serializing_if = "Option::is_none", rename = "nftPolicyId")]
    pub nft_policy_id: Option<String>,
}

/// Metadata accompanying an unsigned transaction for air-gapped signing
///
/// This provides all the context needed for signers to verify what they're
/// signing and for the assembly process to validate signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionMetadata {
    /// Type of transaction (e.g., "governance_rotation", "contract_deployment")
    #[serde(rename = "transactionType")]
    pub transaction_type: String,

    /// Hash of the transaction body being signed (hex-encoded with 0x prefix)
    #[serde(rename = "txHash")]
    pub tx_hash: String,

    /// List of members who can sign this transaction
    #[serde(rename = "requiredSigners")]
    pub required_signers: Vec<SignerInfo>,

    /// Information about how many signatures are needed
    #[serde(rename = "signaturesNeeded")]
    pub signatures_needed: SignaturesNeeded,

    /// Details about the proposal
    #[serde(rename = "proposalDetails")]
    pub proposal_details: ProposalDetails,
}

impl TransactionMetadata {
    /// Read metadata from a JSON file
    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read metadata file: {}", path.display()))?;

        let metadata: TransactionMetadata = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse metadata from: {}", path.display()))?;

        Ok(metadata)
    }

    /// Write metadata to a JSON file
    pub fn write_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize metadata")?;

        fs::write(path, json)
            .with_context(|| format!("Failed to write metadata file: {}", path.display()))?;

        Ok(())
    }

    /// Get the transaction hash as bytes
    pub fn tx_hash_bytes(&self) -> Result<Vec<u8>> {
        let hash_hex = self.tx_hash.strip_prefix("0x").unwrap_or(&self.tx_hash);
        hex::decode(hash_hex)
            .context("Failed to decode transaction hash")
    }

    /// Find a signer by their Cardano key hash
    pub fn find_signer_by_cardano_hash(&self, hash: &str) -> Option<&SignerInfo> {
        let normalized_hash = hash.strip_prefix("0x").unwrap_or(hash);
        self.required_signers
            .iter()
            .find(|s| {
                let signer_hash = s.cardano_key_hash.strip_prefix("0x").unwrap_or(&s.cardano_key_hash);
                signer_hash == normalized_hash
            })
    }

    /// Validate that this metadata matches a transaction hash
    pub fn validate_tx_hash(&self, expected_hash: &[u8]) -> Result<()> {
        let actual_hash = self.tx_hash_bytes()?;
        if actual_hash != expected_hash {
            anyhow::bail!(
                "Transaction hash mismatch: expected {}, got {}",
                hex::encode(expected_hash),
                self.tx_hash
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_threshold_calculation() {
        assert_eq!(SignaturesNeeded::calculate_threshold(3), 2);
        assert_eq!(SignaturesNeeded::calculate_threshold(5), 4);
        assert_eq!(SignaturesNeeded::calculate_threshold(7), 5);
        assert_eq!(SignaturesNeeded::calculate_threshold(1), 1);
        assert_eq!(SignaturesNeeded::calculate_threshold(2), 2);
    }

    #[test]
    fn test_signatures_needed_creation() {
        let sigs = SignaturesNeeded::new(3);
        assert_eq!(sigs.total_signers, 3);
        assert_eq!(sigs.calculated_threshold, 2);
        assert!(sigs.note.contains("2 * total_signers + 2"));
    }

    #[test]
    fn test_transaction_metadata_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("metadata.json");

        let metadata = TransactionMetadata {
            transaction_type: "governance_rotation".to_string(),
            tx_hash: "0xabcdef1234567890".to_string(),
            required_signers: vec![
                SignerInfo {
                    cardano_key_hash: "f48558b0c9b049a1c62f7e1e8c1d7e2a3b4c5d6e7f8g9h0i1j2k3l4m5n6".to_string(),
                    sr25519_public_key: "0x7c7b89f71234567890abcdef".to_string(),
                    ss58_address: "5EsvVahbW...".to_string(),
                    role: "council_member".to_string(),
                },
            ],
            signatures_needed: SignaturesNeeded::new(3),
            proposal_details: ProposalDetails {
                current_logic_round: 0,
                new_logic_round: 1,
                description: Some("Test rotation".to_string()),
                contract_address: None,
                nft_policy_id: None,
            },
        };

        metadata.write_to_file(&file_path).unwrap();
        let loaded = TransactionMetadata::read_from_file(&file_path).unwrap();

        assert_eq!(loaded.transaction_type, metadata.transaction_type);
        assert_eq!(loaded.tx_hash, metadata.tx_hash);
        assert_eq!(loaded.required_signers.len(), 1);
        assert_eq!(loaded.signatures_needed.total_signers, 3);
        assert_eq!(loaded.signatures_needed.calculated_threshold, 2);
    }

    #[test]
    fn test_tx_hash_bytes() {
        let metadata = TransactionMetadata {
            transaction_type: "test".to_string(),
            tx_hash: "0xabcd1234".to_string(),
            required_signers: vec![],
            signatures_needed: SignaturesNeeded::new(1),
            proposal_details: ProposalDetails {
                current_logic_round: 0,
                new_logic_round: 1,
                description: None,
                contract_address: None,
                nft_policy_id: None,
            },
        };

        let bytes = metadata.tx_hash_bytes().unwrap();
        assert_eq!(hex::encode(bytes), "abcd1234");
    }

    #[test]
    fn test_find_signer_by_cardano_hash() {
        let metadata = TransactionMetadata {
            transaction_type: "test".to_string(),
            tx_hash: "0x1234".to_string(),
            required_signers: vec![
                SignerInfo {
                    cardano_key_hash: "0xaabbcc".to_string(),
                    sr25519_public_key: "0x1111".to_string(),
                    ss58_address: "5AAA...".to_string(),
                    role: "member1".to_string(),
                },
                SignerInfo {
                    cardano_key_hash: "ddeeff".to_string(),
                    sr25519_public_key: "0x2222".to_string(),
                    ss58_address: "5BBB...".to_string(),
                    role: "member2".to_string(),
                },
            ],
            signatures_needed: SignaturesNeeded::new(2),
            proposal_details: ProposalDetails {
                current_logic_round: 0,
                new_logic_round: 1,
                description: None,
                contract_address: None,
                nft_policy_id: None,
            },
        };

        let found1 = metadata.find_signer_by_cardano_hash("0xaabbcc");
        assert!(found1.is_some());
        assert_eq!(found1.unwrap().role, "member1");

        let found2 = metadata.find_signer_by_cardano_hash("ddeeff");
        assert!(found2.is_some());
        assert_eq!(found2.unwrap().role, "member2");

        let not_found = metadata.find_signer_by_cardano_hash("999999");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_validate_tx_hash() {
        let metadata = TransactionMetadata {
            transaction_type: "test".to_string(),
            tx_hash: "0xabcd1234".to_string(),
            required_signers: vec![],
            signatures_needed: SignaturesNeeded::new(1),
            proposal_details: ProposalDetails {
                current_logic_round: 0,
                new_logic_round: 1,
                description: None,
                contract_address: None,
                nft_policy_id: None,
            },
        };

        let correct_hash = hex::decode("abcd1234").unwrap();
        assert!(metadata.validate_tx_hash(&correct_hash).is_ok());

        let wrong_hash = hex::decode("12345678").unwrap();
        assert!(metadata.validate_tx_hash(&wrong_hash).is_err());
    }
}
