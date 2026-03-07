// One-shot NFT minting policy CBOR encoding
//
// This is a Plutus V3 minting policy compiled from Aiken source
// See /validators/README.md for compilation instructions

/// One-Shot NFT Minting Policy
///
/// Parameters (applied at deployment):
/// - seed_utxo: OutputReference - The UTxO that must be consumed to mint the NFT
///
/// Rules:
/// - The seed UTxO must be consumed in the minting transaction
/// - Exactly 1 token with empty name ("") must be minted
/// - Since UTxOs can only be spent once, this ensures uniqueness
///
/// Security Properties:
/// - Each governance contract gets a unique NFT
/// - NFT cannot be re-minted after initial deployment
/// - Provides singleton enforcement for governance UTxOs
///
pub const ONE_SHOT_NFT_CBOR: &str = "590179010100229800aba2aba1aba0aab9faab9eaab9dab9a488888896600264653001300800198041804800cc0200092225980099b8748000c01cdd500144c96600264660020026eb0c034c028dd5001912cc00400629422b30013375e601c60166ea8c0380040462946266004004601e002804900c44c8c9660026004646600200200444b30010018a40011337009001198010011808800a01c8994c0040060054a280088896600200510018994c00401260260075980099b8f375c601c002910100898031bad300f0018a5040348020c04400900f452820123259800980118051baa0018a5eb7bdb18226eacc038c02cdd5000a01232330010013756601c601e601e601e601e60166ea8010896600200314c103d87a8000899192cc004cdc8803000c56600266e3c018006266e95200033010300e0024bd7045300103d87a80004031133004004301200340306eb8c030004c03c00500d1b874800a2c8038dd7180598041baa0028b200c180400098019baa0088a4d1365640041";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nft_cbor_not_placeholder() {
        assert_ne!(ONE_SHOT_NFT_CBOR, "TODO_COMPILE_AIKEN_VALIDATORS");
    }
}
