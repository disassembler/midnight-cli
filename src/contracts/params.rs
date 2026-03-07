// Plutus script parameter application utilities
//
// This module provides functions for applying parameters to compiled Aiken/Plutus validators
//
// Using the `uplc` crate for proper parameter application to Plutus scripts.

use anyhow::{Context, Result};

/// Apply parameters to a Plutus script
///
/// Takes a compiled Plutus script (CBOR hex) and a list of parameters (as PlutusData),
/// and returns a new script with the parameters applied.
///
/// This uses the `uplc` crate to properly parse and manipulate the Plutus Core AST.
///
/// # Arguments
/// * `script_cbor_hex` - The compiled script as hex string (without 0x prefix)
/// * `params` - List of parameters as PlutusData values (from pallas-primitives)
///
/// # Returns
/// New script CBOR as hex string
///
/// # Example
/// ```ignore
/// use pallas_primitives::PlutusData;
/// use midnight_cli::contracts::{apply_params, output_reference_data, bytearray_data};
///
/// // Create OutputReference parameter (tx_hash, index)
/// let output_ref = output_reference_data([0u8; 32], 5);
///
/// let parameterized_script = apply_params(ONE_SHOT_NFT_CBOR, vec![output_ref])?;
/// ```
pub fn apply_params(script_cbor_hex: &str, params: Vec<pallas_primitives::PlutusData>) -> Result<String> {
    use uplc::ast::{FakeNamedDeBruijn, NamedDeBruijn, Program};

    // Decode the script CBOR
    let script_bytes = hex::decode(script_cbor_hex)
        .context("Failed to decode script CBOR hex")?;

    // Parse the Plutus script using uplc
    // We use FakeNamedDeBruijn as the initial representation
    let mut buffer = Vec::new();
    let program: Program<FakeNamedDeBruijn> = Program::from_cbor(&script_bytes, &mut buffer)
        .map_err(|e| anyhow::anyhow!("Failed to parse Plutus script: {}", e))?;

    // Convert to NamedDeBruijn for manipulation
    let mut program: Program<NamedDeBruijn> = program.into();

    // Apply each parameter using apply_data
    for param in params {
        // Convert pallas 0.35 PlutusData to uplc PlutusData (pallas 0.33)
        let uplc_param = convert_plutus_data_to_uplc(param)?;
        program = program.apply_data(uplc_param);
    }

    // Encode back to CBOR
    let applied_cbor = program.to_cbor()
        .map_err(|e| anyhow::anyhow!("Failed to encode applied script: {:?}", e))?;

    Ok(hex::encode(applied_cbor))
}

/// Convert pallas 0.35 PlutusData to uplc PlutusData (which uses pallas 0.33)
///
/// This is needed because uplc uses pallas 0.33 while we use 0.35.
/// We manually reconstruct the data structure instead of using CBOR,
/// since the CBOR encoding changed between pallas versions.
fn convert_plutus_data_to_uplc(data: pallas_primitives::PlutusData) -> Result<uplc::PlutusData> {
    use pallas_primitives::{PlutusData, Constr, BigInt};

    match data {
        PlutusData::Constr(Constr { tag, fields, .. }) => {
            let converted_fields: Result<Vec<_>> = fields
                .iter()
                .map(|f| convert_plutus_data_to_uplc(f.clone()))
                .collect();

            // Use pallas 0.33's MaybeIndefArray for the fields
            use pallas_codec_v033::utils::MaybeIndefArray;

            Ok(uplc::PlutusData::Constr(uplc::Constr {
                tag,
                any_constructor: None,
                fields: MaybeIndefArray::Def(converted_fields?),
            }))
        }
        PlutusData::Map(pairs) => {
            let converted_pairs: Result<Vec<_>> = pairs
                .iter()
                .map(|(k, v)| {
                    Ok((
                        convert_plutus_data_to_uplc(k.clone())?,
                        convert_plutus_data_to_uplc(v.clone())?,
                    ))
                })
                .collect();

            Ok(uplc::PlutusData::Map(uplc::KeyValuePairs::from(converted_pairs?)))
        }
        PlutusData::BigInt(big_int) => {
            match big_int {
                BigInt::Int(i) => {
                    // Convert pallas 0.35 Int to pallas 0.33 Int
                    // Extract the i128 value
                    let val: i128 = i.into();
                    // Create pallas 0.33 Int from i64 (truncate if necessary)
                    let val_i64 = val.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
                    let int_v033 = pallas_codec_v033::utils::Int::from(val_i64);
                    Ok(uplc::PlutusData::BigInt(uplc::BigInt::Int(int_v033)))
                }
                BigInt::BigUInt(bytes) => {
                    // Extract bytes from pallas 0.35 BoundedBytes
                    let slice: &[u8] = bytes.as_ref();
                    let vec_bytes: Vec<u8> = slice.to_vec();
                    Ok(uplc::PlutusData::BigInt(uplc::BigInt::BigUInt(vec_bytes.into())))
                }
                BigInt::BigNInt(bytes) => {
                    let slice: &[u8] = bytes.as_ref();
                    let vec_bytes: Vec<u8> = slice.to_vec();
                    Ok(uplc::PlutusData::BigInt(uplc::BigInt::BigNInt(vec_bytes.into())))
                }
            }
        }
        PlutusData::BoundedBytes(bytes) => {
            // Convert BoundedBytes from pallas 0.35 to pallas 0.33
            let slice: &[u8] = bytes.as_ref();
            let vec_bytes: Vec<u8> = slice.to_vec();
            Ok(uplc::PlutusData::BoundedBytes(vec_bytes.into()))
        }
        PlutusData::Array(items) => {
            let converted_items: Result<Vec<_>> = items
                .iter()
                .map(|item| convert_plutus_data_to_uplc(item.clone()))
                .collect();

            // pallas 0.33 uses MaybeIndefArray (imported through pallas_codec 0.33)
            // We need to create it directly using Vec, which pallas 0.33's MaybeIndefArray supports
            let items_vec = converted_items?;

            // Use pallas_codec 0.33's MaybeIndefArray (not 0.35's!)
            use pallas_codec_v033::utils::MaybeIndefArray;
            Ok(uplc::PlutusData::Array(MaybeIndefArray::Def(items_vec)))
        }
    }
}

/// Create OutputReference as PlutusData (for one-shot NFT parameter)
///
/// This creates the Plutus Data representation of OutputReference:
/// ```
/// data OutputReference {
///   TransactionId { transaction_id: Hash<Blake2b_256, Transaction> },
///   Int
/// }
/// ```
///
/// In Plutus, this is a Constructor with tag 0 and 2 fields: [bytes(32), int]
///
/// # Arguments
/// * `tx_hash` - Transaction hash (32 bytes)
/// * `output_index` - Output index (u64)
///
/// # Returns
/// PlutusData representing OutputReference
pub fn output_reference_data(tx_hash: [u8; 32], output_index: u64) -> pallas_primitives::PlutusData {
    use pallas_codec::utils::{MaybeIndefArray, Int};
    use pallas_primitives::{PlutusData, Constr, BigInt};

    // Constructor 0 with 2 fields: [bytes, int]
    PlutusData::Constr(Constr {
        tag: 0,
        any_constructor: None,
        fields: MaybeIndefArray::Def(vec![
            PlutusData::BoundedBytes(tx_hash.to_vec().into()),
            PlutusData::BigInt(BigInt::Int(Int::from(output_index as i64))),
        ]),
    })
}

/// Create ByteArray as PlutusData (for policy ID / script hash parameters)
///
/// # Arguments
/// * `bytes` - Byte array (typically 28 bytes for policy ID, 32 bytes for script hash)
///
/// # Returns
/// PlutusData representing ByteArray
pub fn bytearray_data(bytes: &[u8]) -> pallas_primitives::PlutusData {
    pallas_primitives::PlutusData::BoundedBytes(bytes.to_vec().into())
}

/// Create OutputReference as CBOR-encoded bytes (legacy method)
///
/// This is kept for compatibility but `output_reference_data` + `apply_params` is preferred.
pub fn output_reference_cbor(tx_hash: [u8; 32], output_index: u64) -> Result<Vec<u8>> {
    let data = output_reference_data(tx_hash, output_index);
    pallas_codec::minicbor::to_vec(&data)
        .map_err(|e| anyhow::anyhow!("Failed to encode OutputReference: {}", e))
}

/// Create ByteArray as CBOR-encoded bytes (legacy method)
///
/// This is kept for compatibility but `bytearray_data` + `apply_params` is preferred.
pub fn bytearray_cbor(bytes: &[u8]) -> Result<Vec<u8>> {
    let data = bytearray_data(bytes);
    pallas_codec::minicbor::to_vec(&data)
        .map_err(|e| anyhow::anyhow!("Failed to encode ByteArray: {}", e))
}

/// Calculate script hash (Blake2b-224) from CBOR bytes
///
/// This is used to calculate:
/// - Policy ID from minting policy CBOR
/// - Script address from validator CBOR
pub fn script_hash(script_cbor_hex: &str) -> Result<[u8; 28]> {
    use pallas_crypto::hash::{Hash, Hasher};

    let script_bytes = hex::decode(script_cbor_hex)
        .context("Failed to decode script CBOR hex")?;

    let hash: Hash<28> = Hasher::<224>::hash(&script_bytes);
    let mut result = [0u8; 28];
    result.copy_from_slice(hash.as_ref());

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_reference_data() {
        let tx_hash = [1u8; 32];
        let output_index = 5;

        let data = output_reference_data(tx_hash, output_index);

        // Should be Constr(0, [bytes(32), int])
        if let pallas_primitives::PlutusData::Constr(constr) = data {
            assert_eq!(constr.tag, 0);
            assert_eq!(constr.fields.len(), 2);
        } else {
            panic!("Expected Constr");
        }
    }

    #[test]
    fn test_bytearray_data() {
        let bytes = vec![1, 2, 3, 4];
        let data = bytearray_data(&bytes);

        if let pallas_primitives::PlutusData::BoundedBytes(b) = data {
            assert_eq!(b.as_ref() as &[u8], bytes.as_slice());
        } else {
            panic!("Expected BoundedBytes");
        }
    }

    #[test]
    fn test_output_reference_cbor() {
        let tx_hash = [1u8; 32];
        let output_index = 5;

        let cbor = output_reference_cbor(tx_hash, output_index);
        assert!(cbor.is_ok());

        let cbor_bytes = cbor.unwrap();
        assert!(!cbor_bytes.is_empty());
    }

    #[test]
    fn test_bytearray_cbor() {
        let bytes = vec![1, 2, 3, 4];
        let cbor = bytearray_cbor(&bytes);
        assert!(cbor.is_ok());

        let cbor_bytes = cbor.unwrap();
        assert!(!cbor_bytes.is_empty());
    }

    #[test]
    fn test_script_hash() {
        // Test with a dummy script CBOR
        let script_cbor = "4e4d01000033222220051200120011";
        let hash = script_hash(script_cbor);
        assert!(hash.is_ok());

        let hash_bytes = hash.unwrap();
        assert_eq!(hash_bytes.len(), 28);
    }

    #[test]
    fn test_apply_params_simple() {
        // This is a simple always-succeed Plutus script: (program 1.0.0 (con unit ()))
        // CBOR encoding: 0x46 01 00 00 20 01 01 (wrapped in CBOR bytes)
        let always_succeed_script = "4746010000200101";

        // Try to apply a parameter (this will create an invalid script, but tests the mechanism)
        let param = output_reference_data([0u8; 32], 0);
        let result = apply_params(always_succeed_script, vec![param]);

        // Should succeed in applying the parameter
        match &result {
            Ok(_) => {},
            Err(e) => eprintln!("Error applying params: {}", e),
        }
        assert!(result.is_ok(), "Failed to apply params: {:?}", result.err());

        let applied_script = result.unwrap();
        // Applied script should be different (longer) than original
        assert_ne!(applied_script, always_succeed_script);
        assert!(applied_script.len() > always_succeed_script.len());
    }

    #[test]
    fn test_apply_params_one_shot_nft() {
        // Use our actual one-shot NFT validator from the contracts module
        use crate::contracts::ONE_SHOT_NFT_CBOR;

        // Create a test seed UTxO reference
        let test_tx_hash = [0x42u8; 32];
        let test_output_index = 5;

        // Create the OutputReference parameter
        let seed_utxo_param = output_reference_data(test_tx_hash, test_output_index);

        // Apply the parameter to the one-shot NFT validator
        let result = apply_params(ONE_SHOT_NFT_CBOR, vec![seed_utxo_param]);

        // Should succeed
        assert!(result.is_ok(), "Failed to apply params to one-shot NFT: {:?}", result.err());

        let parameterized_script = result.unwrap();

        // Parameterized script should be different from original
        assert_ne!(parameterized_script, ONE_SHOT_NFT_CBOR);

        // Parameterized script should be longer (contains the parameter data)
        assert!(parameterized_script.len() > ONE_SHOT_NFT_CBOR.len());

        // Calculate the policy ID of the parameterized script
        let policy_id_result = script_hash(&parameterized_script);
        assert!(policy_id_result.is_ok());

        let policy_id = policy_id_result.unwrap();
        assert_eq!(policy_id.len(), 28); // Policy IDs are 28 bytes

        // The policy ID should be deterministic for the same parameters
        let second_result = apply_params(ONE_SHOT_NFT_CBOR, vec![output_reference_data(test_tx_hash, test_output_index)]);
        assert!(second_result.is_ok());
        let second_script = second_result.unwrap();
        let second_policy_id = script_hash(&second_script).unwrap();
        assert_eq!(policy_id, second_policy_id, "Policy IDs should be deterministic");
    }
}
