//! secp256k1 crypto operations for Midnight payment keys
//!
//! Implements BIP-32 hierarchical deterministic key derivation and BIP-340 Schnorr signatures
//! for Midnight payment addresses following the path: m/44'/2400'/account'/role/index

use crate::domain::{
    Bip32Path, DomainError, DomainResult, KeyMaterial, KeyMetadata, KeyPurpose, KeyTypeId,
    PaymentRole,
};
use bip32::XPrv;
use secrecy::SecretString;
use secp256k1::{
    schnorr::Signature as SchnorrSignature, Keypair, Secp256k1, SecretKey, XOnlyPublicKey,
};
use sha2::{Digest, Sha256};

/// secp256k1 payment key operations
pub struct Secp256k1Payment;

impl Secp256k1Payment {
    /// Hardening constant for BIP-32
    #[allow(dead_code)]
    const HARDENED: u32 = 0x80000000;

    /// Derive a payment keypair from mnemonic using BIP-32 path
    pub fn derive_from_mnemonic(
        mnemonic: &str,
        path: &Bip32Path,
    ) -> DomainResult<(Keypair, XOnlyPublicKey)> {
        // Convert mnemonic to seed (BIP-39)
        let mnemonic = bip39::Mnemonic::parse(mnemonic)
            .map_err(|e| DomainError::CryptoError(format!("Invalid mnemonic: {}", e)))?;

        let seed = mnemonic.to_seed("");

        // Build derivation path string: m/44'/2400'/account'/role/index
        let path_str = path.to_string_path();

        // Derive child key directly from seed
        let child_xprv = XPrv::derive_from_path(&seed, &path_str.parse()
            .map_err(|e| DomainError::CryptoError(format!("Invalid derivation path: {:?}", e)))?)
            .map_err(|e| DomainError::CryptoError(format!("Derivation failed: {}", e)))?;

        // Extract raw private key bytes
        let private_key = child_xprv.private_key();
        let private_key_bytes = private_key.to_bytes();

        // Create secp256k1 context and keypair
        let secp = Secp256k1::new();

        // Convert to 32-byte array for SecretKey
        if private_key_bytes.len() != 32 {
            return Err(DomainError::CryptoError(format!(
                "Invalid secret key length: {} (expected 32)",
                private_key_bytes.len()
            )));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&private_key_bytes);
        let secret_key = SecretKey::from_byte_array(key_bytes)
            .map_err(|e| DomainError::CryptoError(format!("Invalid secret key: {}", e)))?;

        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (xonly_pubkey, _parity) = XOnlyPublicKey::from_keypair(&keypair);

        Ok((keypair, xonly_pubkey))
    }

    /// Sign a message using BIP-340 Schnorr signature
    pub fn sign_schnorr(keypair: &Keypair, message: &[u8]) -> DomainResult<SchnorrSignature> {
        let secp = Secp256k1::new();

        // Hash the message with SHA-256 (standard for BIP-340)
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();

        // secp256k1 library expects 32-byte message for schnorr signing
        Ok(secp.sign_schnorr(&hash, keypair))
    }

    /// Verify a Schnorr signature
    pub fn verify_schnorr(
        pubkey: &XOnlyPublicKey,
        message: &[u8],
        signature: &SchnorrSignature,
    ) -> bool {
        let secp = Secp256k1::new();

        // Hash the message
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();

        // secp256k1 library expects 32-byte message for schnorr verification
        secp.verify_schnorr(signature, &hash, pubkey).is_ok()
    }

    /// Convert keypair to KeyMaterial
    pub fn to_key_material(
        keypair: &Keypair,
        xonly_pubkey: &XOnlyPublicKey,
        role: PaymentRole,
        path: &Bip32Path,
    ) -> KeyMaterial {
        let public_bytes = xonly_pubkey.serialize().to_vec();
        let secret_bytes = hex::encode(keypair.secret_bytes());

        let metadata = KeyMetadata::default()
            .with_description(format!("Midnight payment key ({})", role.as_str()));

        KeyMaterial::new(
            KeyTypeId::Secp256k1,
            KeyPurpose::Payment,
            public_bytes,
            Some(SecretString::new(secret_bytes)),
        )
        .with_metadata(metadata)
        .with_derivation_path(path.to_string_path())
    }

    /// Get hex-encoded public key
    pub fn public_key_hex(pubkey: &XOnlyPublicKey) -> String {
        format!("0x{}", hex::encode(pubkey.serialize()))
    }

    /// Get hex-encoded signature
    #[allow(dead_code)]
    pub fn signature_hex(signature: &SchnorrSignature) -> String {
        format!("0x{}", hex::encode(signature.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn test_derive_payment_key() {
        let path = Bip32Path::new(0, PaymentRole::UnshieldedExternal, 0);
        let result = Secp256k1Payment::derive_from_mnemonic(TEST_MNEMONIC, &path);
        assert!(result.is_ok());

        let (_keypair, pubkey) = result.unwrap();

        // Verify we can get public key
        let pubkey_hex = Secp256k1Payment::public_key_hex(&pubkey);
        assert!(pubkey_hex.starts_with("0x"));
        assert_eq!(pubkey_hex.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn test_different_paths_produce_different_keys() {
        let path1 = Bip32Path::new(0, PaymentRole::UnshieldedExternal, 0);
        let path2 = Bip32Path::new(0, PaymentRole::UnshieldedExternal, 1);

        let (_, pubkey1) = Secp256k1Payment::derive_from_mnemonic(TEST_MNEMONIC, &path1).unwrap();
        let (_, pubkey2) = Secp256k1Payment::derive_from_mnemonic(TEST_MNEMONIC, &path2).unwrap();

        assert_ne!(pubkey1.serialize(), pubkey2.serialize());
    }

    #[test]
    fn test_different_roles_produce_different_keys() {
        let path1 = Bip32Path::new(0, PaymentRole::UnshieldedExternal, 0);
        let path2 = Bip32Path::new(0, PaymentRole::Dust, 0);

        let (_, pubkey1) = Secp256k1Payment::derive_from_mnemonic(TEST_MNEMONIC, &path1).unwrap();
        let (_, pubkey2) = Secp256k1Payment::derive_from_mnemonic(TEST_MNEMONIC, &path2).unwrap();

        assert_ne!(pubkey1.serialize(), pubkey2.serialize());
    }

    #[test]
    fn test_schnorr_sign_verify() {
        let path = Bip32Path::new(0, PaymentRole::UnshieldedExternal, 0);
        let (keypair, pubkey) = Secp256k1Payment::derive_from_mnemonic(TEST_MNEMONIC, &path).unwrap();

        let message = b"test message";
        let signature = Secp256k1Payment::sign_schnorr(&keypair, message).unwrap();

        // Verify signature
        assert!(Secp256k1Payment::verify_schnorr(&pubkey, message, &signature));

        // Wrong message should fail
        assert!(!Secp256k1Payment::verify_schnorr(&pubkey, b"wrong message", &signature));
    }

    #[test]
    fn test_to_key_material() {
        let path = Bip32Path::new(0, PaymentRole::UnshieldedExternal, 5);
        let (keypair, pubkey) = Secp256k1Payment::derive_from_mnemonic(TEST_MNEMONIC, &path).unwrap();

        let key_material = Secp256k1Payment::to_key_material(
            &keypair,
            &pubkey,
            PaymentRole::UnshieldedExternal,
            &path,
        );

        assert_eq!(key_material.key_type, KeyTypeId::Secp256k1);
        assert_eq!(key_material.purpose, KeyPurpose::Payment);
        assert!(key_material.has_secret());
        assert_eq!(key_material.derivation_path, Some("m/44'/2400'/0'/0/5".to_string()));
    }

    #[test]
    fn test_deterministic_derivation() {
        // Same mnemonic and path should always produce same keys
        let path = Bip32Path::new(0, PaymentRole::UnshieldedExternal, 0);

        let (_, pubkey1) = Secp256k1Payment::derive_from_mnemonic(TEST_MNEMONIC, &path).unwrap();
        let (_, pubkey2) = Secp256k1Payment::derive_from_mnemonic(TEST_MNEMONIC, &path).unwrap();

        assert_eq!(pubkey1.serialize(), pubkey2.serialize());
    }
}
