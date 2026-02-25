use crate::domain::{DomainError, DomainResult, KeyMaterial, KeyMetadata, KeyPurpose, KeyTypeId};
use secrecy::SecretString;
use sp_core::{
    crypto::Pair as PairTrait,
    ecdsa::{Pair, Public, Signature},
};

/// ECDSA key operations (used for BEEFY)
pub struct Ecdsa;

impl Ecdsa {
    /// Generate a keypair from a SURI string
    pub fn from_suri(suri: &str) -> DomainResult<Pair> {
        Pair::from_string(suri, None)
            .map_err(|e| DomainError::CryptoError(format!("ECDSA from SURI failed: {:?}", e)))
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

        let metadata = KeyMetadata::default()
            .with_description(format!("Midnight {} key", purpose.as_str()));

        let mut key_material = KeyMaterial::new(
            KeyTypeId::Ecdsa,
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
        } else {
            Err(DomainError::CryptoError(format!(
                "Invalid secret key length: {} (expected 32)",
                secret_bytes.len()
            )))
        }
    }
}
