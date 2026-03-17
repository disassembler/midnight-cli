// SPDX-License-Identifier: Apache-2.0

//! Witness assembly for air-gapped governance transactions
//!
//! This module provides functions for creating Cardano Ed25519 witnesses and
//! assembling multiple witnesses into signed transactions.

use crate::storage::{KeyReader, TextEnvelope, TransactionMetadata};
use anyhow::{Context, Result};
use blake2::{Blake2b512, Digest};
use pallas_codec::minicbor::Encoder;
use pallas_crypto::key::ed25519::{PublicKey, Signature};
use secrecy::ExposeSecret as _;
use std::path::Path;

/// Create a Cardano Ed25519 witness for a transaction body
///
/// This function:
/// 1. Loads the mnemonic from file
/// 2. Derives the Cardano Ed25519 key using hayate Wallet (path: 1852H/1815H/0H/0/0)
/// 3. Computes the transaction hash (Blake2b-256 of the tx body CBOR)
/// 4. Signs the hash with the Ed25519 key
/// 5. Creates a witness in cardano-cli compatible format
///
/// # Arguments
/// * `tx_body_envelope` - The unsigned transaction body (TextEnvelope)
/// * `metadata` - Transaction metadata with signer information
/// * `mnemonic_file` - Path to the mnemonic file (supports GPG encryption)
/// * `account` - Cardano account index (default: 0)
///
/// # Returns
/// A TextEnvelope containing the witness in "TxWitness BabbageEra" format
pub fn create_cardano_witness(
    tx_body_envelope: &TextEnvelope,
    metadata: &TransactionMetadata,
    mnemonic_file: &Path,
    account: u32,
) -> Result<TextEnvelope> {
    // 1. Load mnemonic
    let mnemonic = KeyReader::read_mnemonic_from_file(mnemonic_file)
        .context("Failed to read mnemonic")?;

    // 2. Create Cardano wallet and derive payment key
    let mnemonic_str = mnemonic.expose_secret();
    let wallet = hayate::wallet::Wallet::from_mnemonic_str(
        mnemonic_str,
        hayate::wallet::Network::Testnet, // Network doesn't matter for key derivation
        account,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create Cardano wallet: {}", e))?;

    // Get payment signing key (derivation path: 1852H/1815H/0H/0/0)
    let payment_key = wallet
        .payment_signing_key(0)
        .map_err(|e| anyhow::anyhow!("Failed to get payment key: {}", e))?;

    // 3. Compute transaction hash (Blake2b-256 of tx body CBOR)
    let tx_body_cbor = tx_body_envelope.decode_cbor()?;
    let tx_hash = blake2b_256(&tx_body_cbor);

    // 4. Verify against metadata
    metadata
        .validate_tx_hash(&tx_hash)
        .context("Transaction hash mismatch between tx body and metadata")?;

    // 5. Get public key and key hash
    let public_key = payment_key.public_key();
    let public_key_bytes = public_key.as_ref();
    let key_hash = blake2b_224(public_key_bytes);
    let key_hash_hex = hex::encode(&key_hash);

    // 6. Verify this key is in the required signers list
    let signer_info = metadata
        .find_signer_by_cardano_hash(&key_hash_hex)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Key hash {} not found in required signers list. \
                This mnemonic does not correspond to any authorized signer.",
                key_hash_hex
            )
        })?;

    eprintln!("✓ Signing as: {}", signer_info.role);
    eprintln!("  Cardano key hash: {}", key_hash_hex);
    eprintln!("  Sr25519 address: {}", signer_info.ss58_address);

    // 7. Sign the transaction hash
    let signature = payment_key.sign(&tx_hash);
    let signature_bytes = signature.as_ref();

    // 8. Create witness CBOR: [vkey, signature]
    let witness_cbor = encode_witness(public_key_bytes, signature_bytes)?;

    // 9. Wrap in TextEnvelope
    let description = format!("Governance witness - {}", signer_info.role);
    Ok(TextEnvelope::tx_witness(&witness_cbor, description))
}

/// Assemble multiple witnesses into a signed transaction
///
/// This function:
/// 1. Validates that enough witnesses are provided (>= threshold)
/// 2. Verifies each witness signature against the transaction hash
/// 3. Combines the transaction body with witness set
/// 4. Returns a signed transaction ready for submission
///
/// # Arguments
/// * `tx_body_envelope` - The unsigned transaction body
/// * `metadata` - Transaction metadata with threshold information
/// * `witness_envelopes` - List of witness TextEnvelopes
///
/// # Returns
/// A TextEnvelope containing the signed transaction in "Tx BabbageEra" format
pub fn assemble_witnesses(
    tx_body_envelope: &TextEnvelope,
    metadata: &TransactionMetadata,
    witness_envelopes: &[TextEnvelope],
) -> Result<TextEnvelope> {
    // 1. Compute transaction hash
    let tx_body_cbor = tx_body_envelope.decode_cbor()?;
    let tx_hash = blake2b_256(&tx_body_cbor);

    // Verify against metadata
    metadata.validate_tx_hash(&tx_hash)?;

    // 2. Decode all witnesses and verify signatures
    let mut verified_witnesses = Vec::new();

    for (idx, witness_envelope) in witness_envelopes.iter().enumerate() {
        // Verify envelope type
        if witness_envelope.envelope_type != "TxWitness BabbageEra" {
            anyhow::bail!(
                "Invalid witness type at index {}: expected 'TxWitness BabbageEra', got '{}'",
                idx,
                witness_envelope.envelope_type
            );
        }

        // Decode witness CBOR: [vkey, signature]
        let witness_cbor = witness_envelope.decode_cbor()?;
        let (vkey, signature) = decode_witness(&witness_cbor)
            .with_context(|| format!("Failed to decode witness at index {}", idx))?;

        // Verify signature
        verify_signature(&vkey, &tx_hash, &signature)
            .with_context(|| format!("Invalid signature at witness index {}", idx))?;

        // Verify key hash is in required signers
        let key_hash = blake2b_224(&vkey);
        let key_hash_hex = hex::encode(&key_hash);
        let signer_info = metadata.find_signer_by_cardano_hash(&key_hash_hex).ok_or_else(|| {
            anyhow::anyhow!(
                "Witness {} has key hash {} which is not in required signers list",
                idx,
                key_hash_hex
            )
        })?;

        eprintln!(
            "✓ Witness {} verified: {} ({})",
            idx + 1,
            signer_info.role,
            key_hash_hex
        );

        verified_witnesses.push((vkey, signature));
    }

    // 3. Check threshold
    let threshold = metadata.signatures_needed.calculated_threshold as usize;
    if verified_witnesses.len() < threshold {
        anyhow::bail!(
            "Insufficient witnesses: have {}, need {} (threshold: {}/{})",
            verified_witnesses.len(),
            threshold,
            threshold,
            metadata.signatures_needed.total_signers
        );
    }

    eprintln!(
        "\n✓ Threshold met: {}/{} signatures",
        verified_witnesses.len(), metadata.signatures_needed.total_signers
    );

    // 4. Build signed transaction CBOR
    let signed_tx_cbor = encode_signed_transaction(&tx_body_cbor, &verified_witnesses)?;

    // 5. Wrap in TextEnvelope
    Ok(TextEnvelope::tx_signed(
        &signed_tx_cbor,
        format!(
            "{} - signed by {}/{} members",
            metadata.transaction_type, verified_witnesses.len(), metadata.signatures_needed.total_signers
        ),
    ))
}

// === Helper Functions ===

/// Compute Blake2b-256 hash
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..32]);
    hash
}

/// Compute Blake2b-224 hash (for key hashes)
fn blake2b_224(data: &[u8]) -> [u8; 28] {
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 28];
    hash.copy_from_slice(&result[..28]);
    hash
}

/// Encode a witness as CBOR: [vkey, signature]
fn encode_witness(vkey: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    if vkey.len() != 32 {
        anyhow::bail!("Invalid vkey length: {} (expected 32)", vkey.len());
    }
    if signature.len() != 64 {
        anyhow::bail!(
            "Invalid signature length: {} (expected 64)",
            signature.len()
        );
    }

    let mut buf = Vec::new();
    let mut encoder = Encoder::new(&mut buf);

    // Array of 2 elements: [vkey, signature]
    encoder
        .array(2)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;
    encoder
        .bytes(vkey)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;
    encoder
        .bytes(signature)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

    Ok(buf)
}

/// Decode a witness from CBOR: [vkey, signature]
fn decode_witness(cbor: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use pallas_codec::minicbor::Decoder;

    let mut decoder = Decoder::new(cbor);

    // Expect array of 2 elements
    let len = decoder
        .array()
        .map_err(|e| anyhow::anyhow!("Failed to decode witness array: {}", e))?;
    if len != Some(2) {
        anyhow::bail!("Invalid witness format: expected array of length 2, got {:?}", len);
    }

    // Decode vkey (32 bytes)
    let vkey = decoder
        .bytes()
        .map_err(|e| anyhow::anyhow!("Failed to decode vkey: {}", e))?
        .to_vec();
    if vkey.len() != 32 {
        anyhow::bail!("Invalid vkey length: {} (expected 32)", vkey.len());
    }

    // Decode signature (64 bytes)
    let signature = decoder
        .bytes()
        .map_err(|e| anyhow::anyhow!("Failed to decode signature: {}", e))?
        .to_vec();
    if signature.len() != 64 {
        anyhow::bail!(
            "Invalid signature length: {} (expected 64)",
            signature.len()
        );
    }

    Ok((vkey, signature))
}

/// Encode a signed transaction: [tx_body, witness_set, valid, auxiliary_data]
fn encode_signed_transaction(
    tx_body_cbor: &[u8],
    witnesses: &[(Vec<u8>, Vec<u8>)],
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut encoder = Encoder::new(&mut buf);

    // Signed transaction is an array of 4 elements
    encoder
        .array(4)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

    // 1. Transaction body (raw CBOR bytes)
    encoder
        .bytes(tx_body_cbor)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

    // 2. Witness set (map with field 0 = vkeywitness array)
    encoder
        .map(1)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;
    encoder
        .u8(0)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?; // Field 0: vkeywitness

    // Array of witnesses
    encoder
        .array(witnesses.len() as u64)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

    for (vkey, sig) in witnesses {
        encoder
            .array(2)
            .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;
        encoder
            .bytes(vkey)
            .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;
        encoder
            .bytes(sig)
            .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;
    }

    // 3. Valid (true)
    encoder
        .bool(true)
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

    // 4. Auxiliary data (null)
    encoder
        .null()
        .map_err(|e| anyhow::anyhow!("CBOR encode error: {}", e))?;

    Ok(buf)
}

/// Verify an Ed25519 signature
fn verify_signature(vkey: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    if vkey.len() != 32 {
        anyhow::bail!("Invalid public key length: {}", vkey.len());
    }
    if signature.len() != 64 {
        anyhow::bail!("Invalid signature length: {}", signature.len());
    }

    // Create pallas types
    let public_key = PublicKey::try_from(vkey)
        .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;
    let sig = Signature::try_from(signature)
        .map_err(|e| anyhow::anyhow!("Invalid signature: {}", e))?;

    // Verify
    if !public_key.verify(message, &sig) {
        anyhow::bail!("Signature verification failed");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2b_256() {
        let data = b"test data";
        let hash = blake2b_256(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake2b_224() {
        let data = b"test data";
        let hash = blake2b_224(data);
        assert_eq!(hash.len(), 28);
    }

    #[test]
    fn test_encode_decode_witness() {
        let vkey = vec![0x42; 32];
        let signature = vec![0x99; 64];

        let encoded = encode_witness(&vkey, &signature).unwrap();
        let (decoded_vkey, decoded_sig) = decode_witness(&encoded).unwrap();

        assert_eq!(decoded_vkey, vkey);
        assert_eq!(decoded_sig, signature);
    }

    #[test]
    fn test_encode_witness_invalid_lengths() {
        let short_vkey = vec![0x42; 16];
        let signature = vec![0x99; 64];
        assert!(encode_witness(&short_vkey, &signature).is_err());

        let vkey = vec![0x42; 32];
        let short_sig = vec![0x99; 32];
        assert!(encode_witness(&vkey, &short_sig).is_err());
    }

    #[test]
    fn test_encode_signed_transaction() {
        let tx_body = vec![0x84, 0xa4, 0x00, 0x01];
        let witnesses = vec![
            (vec![0x42; 32], vec![0x99; 64]),
            (vec![0x43; 32], vec![0x98; 64]),
        ];

        let signed_tx = encode_signed_transaction(&tx_body, &witnesses).unwrap();

        // Should start with array(4) = 0x84
        assert_eq!(signed_tx[0], 0x84);

        // Should be non-empty
        assert!(signed_tx.len() > 100);
    }

    #[test]
    fn test_encode_signed_transaction_single_witness() {
        let tx_body = vec![0x84, 0xa4, 0x00, 0x01];
        let witnesses = vec![(vec![0x42; 32], vec![0x99; 64])];

        let signed_tx = encode_signed_transaction(&tx_body, &witnesses).unwrap();

        // Should start with array(4) = 0x84
        assert_eq!(signed_tx[0], 0x84);
        assert!(signed_tx.len() > 50);
    }

    #[test]
    fn test_encode_signed_transaction_empty_witnesses() {
        let tx_body = vec![0x84, 0xa4, 0x00, 0x01];
        let witnesses = vec![];

        let signed_tx = encode_signed_transaction(&tx_body, &witnesses).unwrap();

        // Should still produce valid structure
        assert_eq!(signed_tx[0], 0x84);
    }

    #[test]
    fn test_decode_witness_invalid_format() {
        // Invalid CBOR (not an array)
        let invalid = vec![0x01, 0x02, 0x03];
        assert!(decode_witness(&invalid).is_err());

        // Array with wrong length
        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);
        encoder.array(3).unwrap(); // Should be 2
        encoder.bytes(&[0x42; 32]).unwrap();
        encoder.bytes(&[0x99; 64]).unwrap();
        encoder.bytes(&[0x00; 8]).unwrap();
        assert!(decode_witness(&buf).is_err());
    }

    #[test]
    fn test_decode_witness_invalid_lengths() {
        // Valid structure but wrong vkey length
        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);
        encoder.array(2).unwrap();
        encoder.bytes(&[0x42; 16]).unwrap(); // Too short
        encoder.bytes(&[0x99; 64]).unwrap();
        assert!(decode_witness(&buf).is_err());

        // Valid structure but wrong signature length
        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);
        encoder.array(2).unwrap();
        encoder.bytes(&[0x42; 32]).unwrap();
        encoder.bytes(&[0x99; 32]).unwrap(); // Too short
        assert!(decode_witness(&buf).is_err());
    }

    #[test]
    fn test_blake2b_256_deterministic() {
        let data1 = b"test data";
        let data2 = b"test data";
        let hash1 = blake2b_256(data1);
        let hash2 = blake2b_256(data2);
        assert_eq!(hash1, hash2);

        // Different data should produce different hash
        let data3 = b"different data";
        let hash3 = blake2b_256(data3);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_blake2b_224_deterministic() {
        let data1 = b"test data";
        let data2 = b"test data";
        let hash1 = blake2b_224(data1);
        let hash2 = blake2b_224(data2);
        assert_eq!(hash1, hash2);

        // Different data should produce different hash
        let data3 = b"different data";
        let hash3 = blake2b_224(data3);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_blake2b_256_empty_input() {
        let hash = blake2b_256(b"");
        assert_eq!(hash.len(), 32);
        // Blake2b of empty string is deterministic
        let hash2 = blake2b_256(b"");
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_blake2b_224_empty_input() {
        let hash = blake2b_224(b"");
        assert_eq!(hash.len(), 28);
        // Blake2b of empty string is deterministic
        let hash2 = blake2b_224(b"");
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_encode_witness_roundtrip() {
        // Test multiple roundtrips with different data
        let test_cases = vec![
            (vec![0x00; 32], vec![0x00; 64]),
            (vec![0xFF; 32], vec![0xFF; 64]),
            (vec![0x42; 32], vec![0x99; 64]),
            ((0..32).collect(), (0..64).collect()),
        ];

        for (vkey, sig) in test_cases {
            let encoded = encode_witness(&vkey, &sig).unwrap();
            let (decoded_vkey, decoded_sig) = decode_witness(&encoded).unwrap();
            assert_eq!(decoded_vkey, vkey);
            assert_eq!(decoded_sig, sig);
        }
    }
}
