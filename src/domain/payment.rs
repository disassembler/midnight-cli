//! Payment key types and BIP-32 derivation paths for Midnight Network
//!
//! Midnight payment keys follow BIP-32/BIP-44 hierarchical deterministic wallet standard
//! with derivation path: m/44'/2400'/account'/role/index
//!
//! - Purpose: 44' (BIP-44)
//! - Coin type: 2400' (Midnight)
//! - Account: hardened
//! - Role: unhardened (see PaymentRole)
//! - Index: unhardened

use super::error::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// BIP-44 roles for Midnight payment keys
/// These correspond to different types of addresses in the Midnight wallet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum PaymentRole {
    /// Unshielded External (role 0) - Primary chain for unshielded tokens and Night
    UnshieldedExternal,
    /// Unshielded Internal (role 1) - BIP-44 compatibility; change addresses
    UnshieldedInternal,
    /// Dust (role 2) - Fee payment on Midnight
    Dust,
    /// Shielded (role 3) - Privacy-preserving token management
    Shielded,
    /// Metadata (role 4) - Metadata signing operations
    Metadata,
}

#[allow(dead_code)]
impl PaymentRole {
    /// Get the numeric role value for BIP-44 derivation
    pub fn to_u32(self) -> u32 {
        match self {
            Self::UnshieldedExternal => 0,
            Self::UnshieldedInternal => 1,
            Self::Dust => 2,
            Self::Shielded => 3,
            Self::Metadata => 4,
        }
    }

    /// Create from numeric role value
    pub fn from_u32(value: u32) -> DomainResult<Self> {
        match value {
            0 => Ok(Self::UnshieldedExternal),
            1 => Ok(Self::UnshieldedInternal),
            2 => Ok(Self::Dust),
            3 => Ok(Self::Shielded),
            4 => Ok(Self::Metadata),
            _ => Err(DomainError::InvalidKeyPurpose(format!(
                "Invalid payment role: {} (must be 0-4)",
                value
            ))),
        }
    }

    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnshieldedExternal => "unshielded-external",
            Self::UnshieldedInternal => "unshielded-internal",
            Self::Dust => "dust",
            Self::Shielded => "shielded",
            Self::Metadata => "metadata",
        }
    }
}

impl fmt::Display for PaymentRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for PaymentRole {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unshielded-external" | "unshielded_external" | "external" => {
                Ok(Self::UnshieldedExternal)
            }
            "unshielded-internal" | "unshielded_internal" | "internal" | "change" => {
                Ok(Self::UnshieldedInternal)
            }
            "dust" => Ok(Self::Dust),
            "shielded" => Ok(Self::Shielded),
            "metadata" => Ok(Self::Metadata),
            _ => Err(DomainError::InvalidKeyPurpose(format!(
                "Invalid payment role: {}",
                s
            ))),
        }
    }
}

/// BIP-32 derivation path for Midnight payment keys
/// Format: m/44'/2400'/account'/role/index
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct Bip32Path {
    /// BIP-44 purpose (always 44)
    pub purpose: u32,
    /// Midnight coin type (always 2400)
    pub coin_type: u32,
    /// Account index (hardened)
    pub account: u32,
    /// Payment role (unhardened)
    pub role: PaymentRole,
    /// Address index (unhardened)
    pub index: u32,
}

#[allow(dead_code)]
impl Bip32Path {
    /// Midnight's BIP-44 coin type
    pub const MIDNIGHT_COIN_TYPE: u32 = 2400;

    /// BIP-44 purpose constant
    pub const BIP44_PURPOSE: u32 = 44;

    /// Create a new BIP-32 path for Midnight payment keys
    pub fn new(account: u32, role: PaymentRole, index: u32) -> Self {
        Self {
            purpose: Self::BIP44_PURPOSE,
            coin_type: Self::MIDNIGHT_COIN_TYPE,
            account,
            role,
            index,
        }
    }

    /// Create with default account 0
    pub fn new_default(role: PaymentRole, index: u32) -> Self {
        Self::new(0, role, index)
    }

    /// Convert to string path representation
    /// Format: m/44'/2400'/account'/role/index
    pub fn to_string_path(&self) -> String {
        format!(
            "m/{}'/{}'/{}'/{}/{}",
            self.purpose, self.coin_type, self.account, self.role.to_u32(), self.index
        )
    }

    /// Get the derivation path components for bip32 crate
    /// Returns (purpose, coin_type, account, role, index) where first three are hardened
    pub fn to_components(&self) -> (u32, u32, u32, u32, u32) {
        (self.purpose, self.coin_type, self.account, self.role.to_u32(), self.index)
    }
}

impl fmt::Display for Bip32Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_role_conversions() {
        assert_eq!(PaymentRole::UnshieldedExternal.to_u32(), 0);
        assert_eq!(PaymentRole::UnshieldedInternal.to_u32(), 1);
        assert_eq!(PaymentRole::Dust.to_u32(), 2);
        assert_eq!(PaymentRole::Shielded.to_u32(), 3);
        assert_eq!(PaymentRole::Metadata.to_u32(), 4);

        assert_eq!(PaymentRole::from_u32(0).unwrap(), PaymentRole::UnshieldedExternal);
        assert_eq!(PaymentRole::from_u32(4).unwrap(), PaymentRole::Metadata);
        assert!(PaymentRole::from_u32(5).is_err());
    }

    #[test]
    fn test_payment_role_strings() {
        assert_eq!(PaymentRole::UnshieldedExternal.as_str(), "unshielded-external");
        assert_eq!(
            PaymentRole::from_str("unshielded-external").unwrap(),
            PaymentRole::UnshieldedExternal
        );
        assert_eq!(
            PaymentRole::from_str("external").unwrap(),
            PaymentRole::UnshieldedExternal
        );
        assert_eq!(PaymentRole::from_str("change").unwrap(), PaymentRole::UnshieldedInternal);
        assert_eq!(PaymentRole::from_str("dust").unwrap(), PaymentRole::Dust);
    }

    #[test]
    fn test_bip32_path_creation() {
        let path = Bip32Path::new(0, PaymentRole::UnshieldedExternal, 5);
        assert_eq!(path.purpose, 44);
        assert_eq!(path.coin_type, 2400);
        assert_eq!(path.account, 0);
        assert_eq!(path.role, PaymentRole::UnshieldedExternal);
        assert_eq!(path.index, 5);
    }

    #[test]
    fn test_bip32_path_string() {
        let path = Bip32Path::new(0, PaymentRole::UnshieldedExternal, 5);
        assert_eq!(path.to_string_path(), "m/44'/2400'/0'/0/5");

        let path2 = Bip32Path::new(1, PaymentRole::Dust, 10);
        assert_eq!(path2.to_string_path(), "m/44'/2400'/1'/2/10");
    }

    #[test]
    fn test_bip32_path_components() {
        let path = Bip32Path::new(0, PaymentRole::Metadata, 3);
        let (purpose, coin_type, account, role, index) = path.to_components();
        assert_eq!(purpose, 44);
        assert_eq!(coin_type, 2400);
        assert_eq!(account, 0);
        assert_eq!(role, 4);
        assert_eq!(index, 3);
    }
}
