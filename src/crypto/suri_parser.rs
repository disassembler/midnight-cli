use crate::domain::{DerivationSegment, DomainError, DomainResult, SeedSource, Suri};
use secrecy::SecretString;

/// Parse a SURI (Substrate URI) string into components
/// Format: SEED[//hard][/soft][///password]
pub struct SuriParser;

impl SuriParser {
    /// Parse a complete SURI string
    pub fn parse(suri: &str) -> DomainResult<Suri> {
        let suri = suri.trim();

        if suri.is_empty() {
            return Err(DomainError::InvalidSuri {
                suri: suri.to_string(),
                reason: "Empty SURI".to_string(),
            });
        }

        // Split by password delimiter (///)
        let (main_part, password) = if let Some(pos) = suri.find("///") {
            let password = suri[pos + 3..].trim();
            let main = &suri[..pos];
            (
                main,
                if password.is_empty() {
                    None
                } else {
                    Some(SecretString::new(password.to_string()))
                },
            )
        } else {
            (suri, None)
        };

        // Find where the seed ends and derivations begin
        let (seed_str, derivation_str) = Self::split_seed_and_derivations(main_part)?;

        // Determine seed type (mnemonic or hex)
        let seed = if seed_str.starts_with("0x") || seed_str.starts_with("0X") {
            SeedSource::HexSeed(SecretString::new(seed_str.to_string()))
        } else {
            SeedSource::Mnemonic(SecretString::new(seed_str.to_string()))
        };

        // Parse derivation paths
        let (hard_paths, soft_paths) = Self::parse_derivations(derivation_str)?;

        Ok(Suri {
            seed,
            hard_paths,
            soft_paths,
            password,
        })
    }

    /// Build a SURI string from components
    pub fn build(suri: &Suri) -> DomainResult<String> {
        use secrecy::ExposeSecret;

        let mut result = match &suri.seed {
            SeedSource::Mnemonic(m) => m.expose_secret().clone(),
            SeedSource::HexSeed(h) => h.expose_secret().clone(),
        };

        // Add hard derivations
        for segment in &suri.hard_paths {
            result.push_str("//");
            result.push_str(&segment.component);
        }

        // Add soft derivations
        for segment in &suri.soft_paths {
            result.push('/');
            result.push_str(&segment.component);
        }

        // Add password
        if let Some(password) = &suri.password {
            result.push_str("///");
            result.push_str(password.expose_secret());
        }

        Ok(result)
    }

    /// Split seed from derivations
    /// The seed is everything before the first // or /
    fn split_seed_and_derivations(s: &str) -> DomainResult<(&str, &str)> {
        // Find the first derivation delimiter
        let hard_pos = s.find("//");
        let soft_pos = s.find('/').filter(|&p| hard_pos.map_or(true, |h| p != h));

        let split_pos = match (hard_pos, soft_pos) {
            (Some(h), Some(s)) => Some(h.min(s)),
            (Some(h), None) => Some(h),
            (None, Some(s)) => Some(s),
            (None, None) => None,
        };

        if let Some(pos) = split_pos {
            let seed = s[..pos].trim();
            let derivations = &s[pos..];

            if seed.is_empty() {
                return Err(DomainError::InvalidSuri {
                    suri: s.to_string(),
                    reason: "Empty seed before derivation path".to_string(),
                });
            }

            Ok((seed, derivations))
        } else {
            // No derivations, entire string is seed
            Ok((s, ""))
        }
    }

    /// Parse derivation paths into hard and soft components
    fn parse_derivations(s: &str) -> DomainResult<(Vec<DerivationSegment>, Vec<DerivationSegment>)> {
        if s.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        let mut hard_paths = Vec::new();
        let mut soft_paths = Vec::new();
        let mut chars = s.chars().peekable();
        let mut current_component = String::new();
        let mut is_hard = false;

        while let Some(ch) = chars.next() {
            if ch == '/' {
                // Check if this is a hard derivation (//)
                if chars.peek() == Some(&'/') {
                    // Hard derivation
                    chars.next(); // consume the second '/'

                    if !current_component.is_empty() {
                        // Save previous component if any
                        if is_hard {
                            hard_paths.push(DerivationSegment::new(current_component.clone()));
                        } else {
                            soft_paths.push(DerivationSegment::new(current_component.clone()));
                        }
                        current_component.clear();
                    }

                    is_hard = true;
                } else {
                    // Soft derivation
                    if !current_component.is_empty() {
                        // Save previous component
                        if is_hard {
                            hard_paths.push(DerivationSegment::new(current_component.clone()));
                        } else {
                            soft_paths.push(DerivationSegment::new(current_component.clone()));
                        }
                        current_component.clear();
                    }

                    is_hard = false;
                }
            } else {
                current_component.push(ch);
            }
        }

        // Save the last component
        if !current_component.is_empty() {
            if is_hard {
                hard_paths.push(DerivationSegment::new(current_component));
            } else {
                soft_paths.push(DerivationSegment::new(current_component));
            }
        }

        Ok((hard_paths, soft_paths))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_parse_simple_mnemonic() {
        let suri_str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        let suri = SuriParser::parse(suri_str).unwrap();

        match &suri.seed {
            SeedSource::Mnemonic(m) => {
                assert_eq!(m.expose_secret(), suri_str);
            }
            _ => panic!("Expected mnemonic"),
        }

        assert!(suri.hard_paths.is_empty());
        assert!(suri.soft_paths.is_empty());
        assert!(suri.password.is_none());
    }

    #[test]
    fn test_parse_with_hard_derivation() {
        let suri_str = "seed phrase//midnight//governance//0";
        let suri = SuriParser::parse(suri_str).unwrap();

        assert_eq!(suri.hard_paths.len(), 3);
        assert_eq!(suri.hard_paths[0].component, "midnight");
        assert_eq!(suri.hard_paths[1].component, "governance");
        assert_eq!(suri.hard_paths[2].component, "0");
        assert!(suri.soft_paths.is_empty());
    }

    #[test]
    fn test_parse_with_soft_derivation() {
        let suri_str = "seed phrase//hard/soft/soft2";
        let suri = SuriParser::parse(suri_str).unwrap();

        assert_eq!(suri.hard_paths.len(), 1);
        assert_eq!(suri.hard_paths[0].component, "hard");
        assert_eq!(suri.soft_paths.len(), 2);
        assert_eq!(suri.soft_paths[0].component, "soft");
        assert_eq!(suri.soft_paths[1].component, "soft2");
    }

    #[test]
    fn test_parse_with_password() {
        let suri_str = "seed phrase//path///mypassword";
        let suri = SuriParser::parse(suri_str).unwrap();

        assert_eq!(suri.hard_paths.len(), 1);
        assert_eq!(suri.hard_paths[0].component, "path");
        assert!(suri.password.is_some());
        assert_eq!(suri.password.unwrap().expose_secret(), "mypassword");
    }

    #[test]
    fn test_parse_hex_seed() {
        let suri_str = "0x1234567890abcdef//path";
        let suri = SuriParser::parse(suri_str).unwrap();

        match &suri.seed {
            SeedSource::HexSeed(h) => {
                assert_eq!(h.expose_secret(), "0x1234567890abcdef");
            }
            _ => panic!("Expected hex seed"),
        }
    }

    #[test]
    fn test_build_suri() {
        let suri = Suri {
            seed: SeedSource::Mnemonic(SecretString::new("test seed".to_string())),
            hard_paths: vec![
                DerivationSegment::new("midnight"),
                DerivationSegment::new("governance"),
                DerivationSegment::new("0"),
            ],
            soft_paths: vec![DerivationSegment::new("soft")],
            password: Some(SecretString::new("pass".to_string())),
        };

        let suri_str = SuriParser::build(&suri).unwrap();
        assert_eq!(suri_str, "test seed//midnight//governance//0/soft///pass");
    }

    #[test]
    fn test_round_trip() {
        let original = "seed phrase//midnight//governance//0/soft///password";
        let parsed = SuriParser::parse(original).unwrap();
        let rebuilt = SuriParser::build(&parsed).unwrap();

        assert_eq!(original, rebuilt);
    }

    #[test]
    fn test_invalid_suri() {
        assert!(SuriParser::parse("").is_err());
        assert!(SuriParser::parse("   ").is_err());
        assert!(SuriParser::parse("//path").is_err()); // No seed
    }
}
