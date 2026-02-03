use crate::domain::{DomainError, DomainResult};
use bip39::{Language, Mnemonic};
use secrecy::SecretString;

/// Generate a new random BIP39 mnemonic phrase (24 words)
pub fn generate_mnemonic() -> DomainResult<SecretString> {
    let mnemonic = Mnemonic::generate(24)
        .map_err(|e| DomainError::InvalidMnemonic(format!("Failed to generate mnemonic: {}", e)))?;
    Ok(SecretString::new(mnemonic.to_string()))
}

/// Validate a mnemonic phrase
pub fn validate_mnemonic(phrase: &str) -> DomainResult<()> {
    Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| DomainError::InvalidMnemonic(format!("Invalid mnemonic: {}", e)))?;
    Ok(())
}

/// Normalize a mnemonic phrase (trim whitespace, lowercase, etc.)
pub fn normalize_mnemonic(phrase: &str) -> String {
    phrase
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic = generate_mnemonic().unwrap();
        let phrase = secrecy::ExposeSecret::expose_secret(&mnemonic);

        // Should be 24 words
        assert_eq!(phrase.split_whitespace().count(), 24);

        // Should be valid
        assert!(validate_mnemonic(phrase).is_ok());
    }

    #[test]
    fn test_validate_mnemonic() {
        assert!(validate_mnemonic(TEST_MNEMONIC).is_ok());
        assert!(validate_mnemonic("invalid mnemonic phrase").is_err());
        assert!(validate_mnemonic("").is_err());
    }

    #[test]
    fn test_normalize_mnemonic() {
        let messy = "  bottom   drive  obey\nlake  curtain   smoke  ";
        let normalized = normalize_mnemonic(messy);
        assert_eq!(normalized, "bottom drive obey lake curtain smoke");

        let with_caps = "Bottom DRIVE Obey";
        let normalized = normalize_mnemonic(with_caps);
        assert_eq!(normalized, "bottom drive obey");
    }
}
