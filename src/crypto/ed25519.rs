use crate::domain::{DomainError, DomainResult, KeyMaterial, KeyMetadata, KeyPurpose, KeyTypeId};
use secrecy::SecretString;
use sp_core::{
    crypto::{Pair as PairTrait, Ss58Codec},
    ed25519::{Pair, Public, Signature},
};

/// Ed25519 key operations
pub struct Ed25519;

impl Ed25519 {
    /// Generate a keypair from a SURI string
    pub fn from_suri(suri: &str) -> DomainResult<Pair> {
        Pair::from_string(suri, None)
            .map_err(|e| DomainError::CryptoError(format!("Ed25519 from SURI failed: {:?}", e)))
    }

    /// Generate a keypair from a seed
    #[allow(dead_code)]
    pub fn from_seed(seed: &[u8]) -> DomainResult<Pair> {
        if seed.len() != 32 {
            return Err(DomainError::CryptoError(format!(
                "Invalid seed length: {} (expected 32)",
                seed.len()
            )));
        }

        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed);

        Ok(Pair::from_seed(&seed_array))
    }

    /// Sign a message
    pub fn sign(pair: &Pair, message: &[u8]) -> Signature {
        pair.sign(message)
    }

    /// Verify a signature
    pub fn verify(public: &Public, message: &[u8], signature: &Signature) -> bool {
        Pair::verify(signature, message, public)
    }

    /// Get public key from pair
    pub fn public_key(pair: &Pair) -> Public {
        pair.public()
    }

    /// Convert public key to SS58 address (Substrate format, prefix 42)
    pub fn to_ss58_address(public: &Public) -> String {
        public.to_ss58check_with_version(
            sp_core::crypto::Ss58AddressFormatRegistry::SubstrateAccount.into(),
        )
    }

    /// Convert pair to KeyMaterial
    pub fn to_key_material(
        pair: &Pair,
        purpose: KeyPurpose,
        derivation_path: Option<String>,
    ) -> KeyMaterial {
        let public = pair.public();
        let public_ref: &[u8] = public.as_ref();
        let public_bytes = public_ref.to_vec();
        let secret_bytes = hex::encode(pair.to_raw_vec());
        let ss58_address = Self::to_ss58_address(&public);

        let metadata = KeyMetadata::default()
            .with_description(format!("Midnight {} key", purpose.as_str()))
            .with_ss58_address(ss58_address);

        let mut key_material = KeyMaterial::new(
            KeyTypeId::Ed25519,
            purpose,
            public_bytes,
            Some(SecretString::new(secret_bytes)),
        )
        .with_metadata(metadata);

        if let Some(path) = derivation_path {
            key_material = key_material.with_derivation_path(path);
        }

        key_material
    }

    /// Create pair from secret key bytes (hex-encoded)
    pub fn from_secret_hex(secret_hex: &str) -> DomainResult<Pair> {
        let secret_hex = secret_hex.strip_prefix("0x").unwrap_or(secret_hex);
        let secret_bytes = hex::decode(secret_hex)
            .map_err(|e| DomainError::CryptoError(format!("Invalid hex: {}", e)))?;

        if secret_bytes.len() == 32 {
            // Seed
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&secret_bytes);
            Ok(Pair::from_seed(&seed))
        } else if secret_bytes.len() == 64 {
            // Full secret key
            Pair::from_seed_slice(&secret_bytes)
                .map_err(|e| DomainError::CryptoError(format!("Failed to create pair: {:?}", e)))
        } else {
            Err(DomainError::CryptoError(format!(
                "Invalid secret key length: {} (expected 32 or 64)",
                secret_bytes.len()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

    #[test]
    fn test_from_suri() {
        let pair = Ed25519::from_suri(TEST_SEED).unwrap();
        let public = Ed25519::public_key(&pair);

        // Should generate a valid public key
        let public_bytes: &[u8] = public.as_ref();
        assert_eq!(public_bytes.len(), 32);
    }

    #[test]
    fn test_derivation_path_hard_only() {
        // Ed25519 only supports hard derivation
        let suri_with_path = format!("{}//midnight//finality//0", TEST_SEED);
        let pair = Ed25519::from_suri(&suri_with_path).unwrap();
        let public = Ed25519::public_key(&pair);

        // Should be different from root key
        let root_pair = Ed25519::from_suri(TEST_SEED).unwrap();
        let root_public = Ed25519::public_key(&root_pair);

        let public_bytes: &[u8] = public.as_ref();
        let root_public_bytes: &[u8] = root_public.as_ref();
        assert_ne!(public_bytes, root_public_bytes);
    }

    #[test]
    fn test_sign_verify() {
        let pair = Ed25519::from_suri(TEST_SEED).unwrap();
        let message = b"test message";
        let signature = Ed25519::sign(&pair, message);
        let public = Ed25519::public_key(&pair);

        assert!(Ed25519::verify(&public, message, &signature));
        assert!(!Ed25519::verify(&public, b"wrong message", &signature));
    }

    #[test]
    fn test_ss58_address() {
        let pair = Ed25519::from_suri(TEST_SEED).unwrap();
        let public = Ed25519::public_key(&pair);
        let ss58 = Ed25519::to_ss58_address(&public);

        // Should produce a valid SS58 address
        assert!(ss58.starts_with('5'));
        assert!(ss58.len() > 40);
    }

    #[test]
    fn test_to_key_material() {
        let pair = Ed25519::from_suri(TEST_SEED).unwrap();
        let key_material = Ed25519::to_key_material(
            &pair,
            KeyPurpose::Finality,
            Some("//midnight//finality//0".to_string()),
        );

        assert_eq!(key_material.key_type, KeyTypeId::Ed25519);
        assert_eq!(key_material.purpose, KeyPurpose::Finality);
        assert!(key_material.has_secret());
        assert_eq!(
            key_material.derivation_path,
            Some("//midnight//finality//0".to_string())
        );
        assert!(key_material.metadata.ss58_address.is_some());
    }
}
