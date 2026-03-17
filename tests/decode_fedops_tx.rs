// Decode the federated ops change transaction to understand datum format
//
// This transaction shows how to change federated ops members:
// - Spends Council NFT (incrementing logic_round only)
// - Spends TA NFT (incrementing logic_round only)
// - Modifies the FederatedOps member list
//
// This requires 2/3 signatures from BOTH council and TA

#[test]
fn analyze_fedops_change_transaction() {
    println!("=== Federated Ops Change Transaction Analysis ===\n");

    // The inline datum from the transaction output starts at "d818" (CBOR tag 24)
    // Then "5906669fd87980" is the datum bytes
    // Let me extract just the datum payload part

    // Looking at the CBOR, after "028201d818" we have the inline datum
    // "590666" means bytes string of length 0x0666 (1638 bytes)
    // "9fd87980" starts the actual datum structure

    // The datum appears to be:
    // 9f = indefinite array start
    // 9f = indefinite array start (member 1)
    //   582103d55a64... = 33-byte bytestring (secp256k1 public key)
    //   9f = indefinite array start (member details)
    //     44 61757261 = 4-byte bytestring "aura"
    //     5820... = 32-byte bytestring (aura key?)
    //   ff = break (end indefinite array)
    //   9f = indefinite array start
    //     44 6772616e = 4-byte bytestring "gran"
    //     5820... = 32-byte bytestring (grandpa key?)
    //   ff = break
    //   9f = indefinite array start
    //     44 62656566 = 4-byte bytestring "beef"
    //     582103d55a64... = 33-byte bytestring (beef key - same as first)
    //   ff = break
    // ff = break (end member 1)
    // ... (more members)
    // ff = break (end member array)
    // 01 = integer 1 (logic_round?)
    // ff = break (end outer array)

    let datum_cbor_hex = "9fd879809f9f582103d55a64edd5c294265bbe46051b47e8bd0d0299bf18b14345ca53e5bac6f53cbd9f9f446175726158200ab04fd165acd8df55e6695a68bbaa2dcb2f768ee5625420bb012ef11ee5f737ff9f446772616e5820794084b91735c1cbeb2a75e8e09abbb21433d71aa37e966d04702f21949f9ca5ff9f4462656566582103d55a64edd5c294265bbe46051b47e8bd0d0299bf18b14345ca53e5bac6f53cbdffffff9f58210302873e08924b80c6d43314bd69e3a4ff25d645f87e8bded6cfe2f318ec299c379f9f4461757261582078fe1f9d48ff2f3561f62e13b0c8aa41b7570ac046e4e35d9692d5ba87dbf452ff9f446772616e58205c6c16299ac3f0f9063fee4ec0ba6ac677aea36c13dcb7815fd87724b82cb3f6ff9f446265656658210302873e08924b80c6d43314bd69e3a4ff25d645f87e8bded6cfe2f318ec299c37ffffff9f5821021a620667273158c5ce5e030fb2598acc8d11b306abe6105d12defcd4ca9973249f9f44617572615820506135964b135adfdbea434003172d620732731efd4e33f3eca73c785ebd5d0aff9f446772616e5820366a577abd0e3f0d4230cad84cd7669870d2dd531dad81b9231f7ad3f2b75aa8ff9f44626565665821021a620667273158c5ce5e030fb2598acc8d11b306abe6105d12defcd4ca997324ffffff9f582103c11695bf19bcfe043f3539bb61502134293ec325b065cb13f7dad56ffd24b9299f9f4461757261582022004d700d62df213b2edc6d05bca2d1cb5de88c9f12058de94f164a13bb0b2bff9f446772616e582038b6c38be64b7679316e80382fb01fa856c94bf979de233a7aaabfca4489293fff9f4462656566582103c11695bf19bcfe043f3539bb61502134293ec325b065cb13f7dad56ffd24b929ffffff9f582103deafaa8e0286bcc0f637f0bd82486578d97f6e691fee856e1bdc92d8b003cebd9f9f44617572615820faed36e0e8910990c42b865abe3ad33ca91958f589717956654d93a124556d12ff9f446772616e582001e389e9ac23e585a43485029f89112544c76f397683fddbf37e5e1e30cce32fff9f4462656566582103deafaa8e0286bcc0f637f0bd82486578d97f6e691fee856e1bdc92d8b003cebdffffff9f58210263a7c11e3f720b86ff52cfb68de9217259cd2781414526b6291afb097344b7439f9f446175726158208a7abbefa181f46dada06b8e6faea4d2b3bb693c0f3bb0a07e57ba7cb138415bff9f446772616e5820ab44c485474457eb2cec355b60a9352c3ce39fd422deb885f1e5fd92dca04842ff9f446265656658210263a7c11e3f720b86ff52cfb68de9217259cd2781414526b6291afb097344b743ffffff9f58210262527e47b08356aa8314ca6aa38ed18a28ee7d4a87e69446f8d89c0bfc4cd6e99f9f446175726158202a55fc6597761cc9a4869c6a92d50d21bc85f03c4a93bb07279225bad12aac63ff9f446772616e5820c34944dcec3c142b0d91bebdcaa3299a523ffd1a7d3f512ce2784398c9f4a64dff9f446265656658210262527e47b08356aa8314ca6aa38ed18a28ee7d4a87e69446f8d89c0bfc4cd6e9ffffff9f582103882e9305e46b270d0f68314fef20a8df3d16d83338fa12dacb5df43a60e140439f9f44617572615820bc0bcf2d14d13073f5117b4ff63e71d4db2cfb939637b0fb394fa26e369f142cff9f446772616e58201a2548519519879d0185ab5ea3c6a1b3675e9ec7f0f30ea858b7723102579a8dff9f4462656566582103882e9305e46b270d0f68314fef20a8df3d16d83338fa12dacb5df43a60e14043ffffff9f5821039fff087435982cd547adbb9ff8c7ced547dbade96c12d25976f86f3c8fcadeb99f9f44617572615820fcbfa8c3d767d8ccbf41c7ac666c802363545f2f620854744ba86ed89ba87925ff9f446772616e58200f708bf4ff76ccee2ab2ddc6d7f7b9fd481a2aba724b6a37c43adefe321df824ff9f44626565665821039fff087435982cd547adbb9ff8c7ced547dbade96c12d25976f86f3c8fcadeb9ffffff9f5821032e7c919e71a7a9aaffe1d251a647a056ebbd2b53eb84ebba676da4a62c82abc69f9f4461757261582034b084864869ce00e9f31fb0fd0d2dbe17fd98b97d9a91c2508a895cdba5592fff9f446772616e582027c5f1d94ffe4e559915e1ca0eaceb7d0d98954938f8ed438be33d48d7f978b7ff9f44626565665821032e7c919e71a7a9aaffe1d251a647a056ebbd2b53eb84ebba676da4a62c82abc6ffffffff01ff";

    let datum_bytes = hex::decode(datum_cbor_hex).expect("valid hex");

    println!("Datum CBOR length: {} bytes", datum_bytes.len());
    println!("First 100 bytes: {}", hex::encode(&datum_bytes[0..100.min(datum_bytes.len())]));

    // Analyze structure
    println!("\n✓ Datum Structure Analysis:");
    println!("  - Format: Indefinite-length CBOR arrays");
    println!("  - Each member has:");
    println!("    1. 33-byte secp256k1 public key (validator node ID)");
    println!("    2. \"aura\" key (32 bytes) - consensus");
    println!("    3. \"gran\" key (32 bytes) - grandpa finality");
    println!("    4. \"beef\" key (33 bytes) - BeefyECDSA");
    println!("  - Logic round at end: 1");

    // Count members by looking for secp256k1 key pattern (58 21 03...)
    let mut member_count = 0;
    let mut i = 0;
    while i < datum_bytes.len() - 3 {
        // Look for 0x5821 followed by 0x03 or 0x02 (compressed secp256k1 pubkey)
        if datum_bytes[i] == 0x58 && datum_bytes[i+1] == 0x21 &&
           (datum_bytes[i+2] == 0x03 || datum_bytes[i+2] == 0x02) {
            // Check if this is at the start of a member (not inside aura/gran/beef)
            // We can identify this by looking back for 0x9f (array start)
            if i >= 2 && datum_bytes[i-1] == 0x9f && datum_bytes[i-2] == 0x9f {
                member_count += 1;
            }
        }
        i += 1;
    }

    println!("\n✓ Found {} federated ops members", member_count);

    println!("\n✓ This datum format is DIFFERENT from VersionedMultisig!");
    println!("  VersionedMultisig uses:");
    println!("    - total_signers: u32");
    println!("    - members: Vec<GovernanceMember> (Cardano hash + Sr25519 key)");
    println!("    - logic_round: u64");

    println!("\n  FederatedOps datum uses:");
    println!("    - members: Vec<ValidatorKeys> (secp256k1 + aura + grandpa + beefy)");
    println!("    - logic_round: u64");
    println!("    - No total_signers field!");

    println!("\n✓ Contract Logic:");
    println!("  To modify FederatedOps:");
    println!("    1. Spend Council NFT (2/3 council sigs, increment logic_round only)");
    println!("    2. Spend TA NFT (2/3 TA sigs, increment logic_round only)");
    println!("    3. Update FederatedOps member list (new validators)");
    println!("    4. Requires signatures from BOTH governance bodies");
}

#[test]
fn test_fedops_datum_is_different_from_multisig() {
    // This test documents that FederatedOps uses a DIFFERENT datum structure
    // than Council/TA governance contracts

    println!("\n=== Datum Structure Comparison ===\n");

    println!("Council/TA (VersionedMultisig):");
    println!("  Constructor: 122 (0x7A)");
    println!("  Fields:");
    println!("    - total_signers: u32");
    println!("    - members: Vec<GovernanceMember>");
    println!("      - cardano_hash: [u8; 28]");
    println!("      - sr25519_key: [u8; 32]");
    println!("    - logic_round: u64");

    println!("\nFederatedOps:");
    println!("  Format: Indefinite CBOR array");
    println!("  Fields:");
    println!("    - members: Vec<ValidatorKeys>");
    println!("      - node_id: [u8; 33] (secp256k1 compressed pubkey)");
    println!("      - aura_key: [u8; 32]");
    println!("      - grandpa_key: [u8; 32]");
    println!("      - beefy_key: [u8; 33]");
    println!("    - logic_round: u64");

    println!("\n✓ These are INCOMPATIBLE datum formats!");
    println!("  FederatedOps needs its own Rust type in hayate");
}
