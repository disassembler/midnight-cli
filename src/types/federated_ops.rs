// Federated Ops Datum Types
//
// These types represent the validator set managed by the federated ops governance contract.
// This is different from the VersionedMultisig datum used by the governance control contracts.

use anyhow::Result;

/// A federated ops validator with all their consensus keys
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorKeys {
    /// Secp256k1 compressed public key (33 bytes) - node ID
    pub node_id: [u8; 33],
    /// AURA consensus key (32 bytes)
    pub aura_key: [u8; 32],
    /// GRANDPA finality key (32 bytes)
    pub grandpa_key: [u8; 32],
    /// BEEFY bridge key (33 bytes, secp256k1)
    pub beefy_key: [u8; 33],
}

/// Federated Ops datum - list of validators with rotation tracking
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedOpsDatum {
    /// List of validator key sets
    pub members: Vec<ValidatorKeys>,
    /// Incremented on each update to prevent replay
    pub logic_round: u64,
}

impl FederatedOpsDatum {
    /// Create a new FederatedOps datum
    pub fn new(members: Vec<ValidatorKeys>, logic_round: u64) -> Self {
        Self {
            members,
            logic_round,
        }
    }

    /// Encode to CBOR bytes for Plutus inline datum
    ///
    /// Format (indefinite arrays):
    /// [
    ///   [node_id, [["aura", aura_key], ["gran", grandpa_key], ["beef", beefy_key]]],
    ///   ...(more members)
    ///   logic_round
    /// ]
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Start indefinite array for outer structure (0x9F)
        buf.push(0x9F);

        // Encode each member
        for member in &self.members {
            // Start member array (0x9F = indefinite)
            buf.push(0x9F);

            // Node ID (33 bytes) - 0x58 0x21 = bytes(33)
            buf.push(0x58);
            buf.push(0x21);
            buf.extend_from_slice(&member.node_id);

            // Start keys array (0x9F = indefinite)
            buf.push(0x9F);

            // AURA key - [bytes("aura"), bytes(32)]
            buf.push(0x9F); // indefinite array
            buf.push(0x44); // bytes(4)
            buf.extend_from_slice(b"aura");
            buf.push(0x58); // bytes(32)
            buf.push(0x20);
            buf.extend_from_slice(&member.aura_key);
            buf.push(0xFF); // break

            // GRANDPA key - [bytes("gran"), bytes(32)]
            buf.push(0x9F); // indefinite array
            buf.push(0x44); // bytes(4)
            buf.extend_from_slice(b"gran");
            buf.push(0x58); // bytes(32)
            buf.push(0x20);
            buf.extend_from_slice(&member.grandpa_key);
            buf.push(0xFF); // break

            // BEEFY key - [bytes("beef"), bytes(33)]
            buf.push(0x9F); // indefinite array
            buf.push(0x44); // bytes(4)
            buf.extend_from_slice(b"beef");
            buf.push(0x58); // bytes(33)
            buf.push(0x21);
            buf.extend_from_slice(&member.beefy_key);
            buf.push(0xFF); // break

            // End keys array
            buf.push(0xFF);

            // End member array
            buf.push(0xFF);
        }

        // Logic round (as unsigned integer)
        if self.logic_round <= 23 {
            buf.push(self.logic_round as u8);
        } else if self.logic_round <= 0xFF {
            buf.push(0x18);
            buf.push(self.logic_round as u8);
        } else if self.logic_round <= 0xFFFF {
            buf.push(0x19);
            buf.extend_from_slice(&(self.logic_round as u16).to_be_bytes());
        } else if self.logic_round <= 0xFFFFFFFF {
            buf.push(0x1A);
            buf.extend_from_slice(&(self.logic_round as u32).to_be_bytes());
        } else {
            buf.push(0x1B);
            buf.extend_from_slice(&self.logic_round.to_be_bytes());
        }

        // End outer array
        buf.push(0xFF);

        Ok(buf)
    }

    /// Decode from CBOR bytes
    ///
    /// TODO: Implement CBOR decoding when needed
    pub fn from_cbor(_bytes: &[u8]) -> Result<Self> {
        Err(anyhow::anyhow!("FederatedOpsDatum decoding not yet implemented"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validator(id: u8) -> ValidatorKeys {
        let mut node_id = [0u8; 33];
        node_id[0] = 0x03; // Compressed secp256k1 prefix
        node_id[32] = id;

        let mut aura_key = [0u8; 32];
        aura_key[31] = id;

        let mut grandpa_key = [0u8; 32];
        grandpa_key[31] = id;

        let mut beefy_key = [0u8; 33];
        beefy_key[0] = 0x02;
        beefy_key[32] = id;

        ValidatorKeys {
            node_id,
            aura_key,
            grandpa_key,
            beefy_key,
        }
    }

    #[test]
    fn test_fedops_datum_encoding() {
        let members = vec![
            create_test_validator(1),
            create_test_validator(2),
            create_test_validator(3),
        ];

        let datum = FederatedOpsDatum::new(members, 0);
        let cbor = datum.to_cbor().expect("valid encoding");

        println!("FederatedOps CBOR length: {} bytes", cbor.len());
        assert!(!cbor.is_empty());
        assert!(cbor.len() > 300); // Should be substantial with 3 validators
    }

    #[test]
    fn test_fedops_datum_logic_round_encoding() {
        let members = vec![create_test_validator(1)];

        // Test small logic_round (fits in 1 byte)
        let datum1 = FederatedOpsDatum::new(members.clone(), 5);
        let cbor1 = datum1.to_cbor().expect("valid encoding");
        assert!(!cbor1.is_empty());

        // Test larger logic_round
        let datum2 = FederatedOpsDatum::new(members.clone(), 1000);
        let cbor2 = datum2.to_cbor().expect("valid encoding");
        assert!(cbor2.len() > cbor1.len()); // Should be larger due to multi-byte logic_round

        println!("CBOR with logic_round=5: {} bytes", cbor1.len());
        println!("CBOR with logic_round=1000: {} bytes", cbor2.len());
    }
}
