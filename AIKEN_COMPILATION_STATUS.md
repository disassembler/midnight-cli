# Aiken Validator Compilation Status

## Summary

✅ **All validators successfully compiled** using Aiken v1.1.21 with stdlib v2. All CBOR hex extracted and integrated into Rust codebase.

## Environment

- **Aiken Version**: v1.1.21+57da530c (built from source at ~/work/iohk/aiken)
- **Stdlib Version**: v2
- **Plutus Version**: v3
- **Compiler**: `/home/sam/work/iohk/aiken/result/bin/aiken`

## Successfully Compiled Validators

### 1. one_shot_nft (NFT Minting Policy)

**Purpose**: Ensures uniqueness by consuming a specific seed UTxO that can only be spent once.

**Compiled CBOR**:
```
590179010100229800aba2aba1aba0aab9faab9eaab9dab9a488888896600264653001300800198041804800cc0200092225980099b8748000c01cdd500144c96600264660020026eb0c034c028dd5001912cc00400629422b30013375e601c60166ea8c0380040462946266004004601e002804900c44c8c9660026004646600200200444b30010018a40011337009001198010011808800a01c8994c0040060054a280088896600200510018994c00401260260075980099b8f375c601c002910100898031bad300f0018a5040348020c04400900f452820123259800980118051baa0018a5eb7bdb18226eacc038c02cdd5000a01232330010013756601c601e601e601e601e60166ea8010896600200314c103d87a8000899192cc004cdc8803000c56600266e3c018006266e95200033010300e0024bd7045300103d87a80004031133004004301200340306eb8c030004c03c00500d1b874800a2c8038dd7180598041baa0028b200c180400098019baa0088a4d1365640041
```

**Key Adaptations for stdlib v2**:
- `tx.mint` is `Value` type, not `List<Pair<PolicyId, List<Pair<AssetName, Int>>>>`
- Use `tokens(tx.mint, policy_id)` to extract tokens for specific policy
- Use `dict.foldl` instead of `dict.to_list` (not available in v2)
- Changed `let seed_consumed = ...` to `expect` to avoid unused variable warning

**Source**: `/home/sam/work/iohk/midnight-cli/validators/validators/one_shot_nft.ak`

### 2. simple_mint (Always-Succeed Minting Policy)

**Purpose**: Simple test validator that always succeeds (for testing only).

**Compiled CBOR**:
```
585401010029800aba2aba1aab9eaab9dab9a4888896600264653001300600198031803800cc0180092225980099b8748000c01cdd500144c9289bae30093008375400516401830060013003375400d149a26cac8009
```

**Source**: `/home/sam/work/iohk/midnight-cli/validators/validators/simple_mint.ak`

## Governance Validators Status

✅ **All three governance validators successfully compiled** (council, tech_auth, federated_ops).

### Adaptations Made for stdlib v2:

1. **Dict API changes** ✅:
   - Changed from `aiken/dict` to `aiken/collection/dict`
   - Used `dict.size()` for counting members
   - Changed `Pair<K,V>` to tuple syntax `(K, V)`

2. **Value/Assets API** ✅:
   - Used `cardano/assets.tokens(value, policy_id)` for NFT checking
   - Properly handled Value type operations

3. **Reference Input Handling** ✅:
   - Verified `tx.reference_inputs` API works correctly
   - InlineDatum extraction uses proper pattern matching

### Governance Validator Compilation:

**Council Governance** (`council_governance.ak`): ✅ Compiled
- Compiled CBOR: 5903c2... (986 bytes)
- Read VersionedMultisig datum (Dict-based)
- Check 2/3 threshold signatures via `tx.extra_signatories`
- Verify NFT is spent and returned to same script address

**Tech Authority Governance** (`tech_auth_governance.ak`): ✅ Compiled
- Compiled CBOR: 5903c2... (986 bytes)
- Identical logic to council, different NFT policy ID

**Federated Ops Governance** (`federated_ops_governance.ak`): ✅ Compiled
- Compiled CBOR: 5904d9... (1245 bytes)
- Read datums from council and TA via reference inputs
- Check 2/3 threshold from BOTH bodies
- Most complex validator

## Next Steps

1. ✅ **Adapt governance validators to stdlib v2** - COMPLETED
   - ✅ Replaced `Pair<K,V>` with tuple syntax `(K, V)`
   - ✅ Updated dict operations to use `dict.size()`
   - ✅ Fixed NFT checking logic with `tokens()` API
   - ✅ Verified reference input datum extraction

2. ✅ **Extract compiled CBOR** - COMPLETED
   - ✅ All validators compiled successfully
   - ✅ CBOR hex extracted from `plutus.json`
   - ✅ Updated Rust constants in `src/contracts/governance.rs`
   - ✅ Updated NFT policy in `src/contracts/nft.rs`

3. ✅ **Implement parameter application utilities** - COMPLETED
   - ✅ Created `src/contracts/params.rs` with full `uplc` integration
   - ✅ Successfully applies parameters to compiled Plutus validators at runtime
   - ✅ Tested with real Aiken-compiled one-shot NFT validator
   - ✅ All 7 tests passing, including deterministic policy ID generation

4. **Test with Extended Keys** - TODO
   - Deploy contracts to testnet
   - Attempt governance update with BIP32-derived keys
   - Verify `tx.extra_signatories` handles extended keys correctly

## Build Commands

```bash
# Build validators
~/work/iohk/aiken/result/bin/aiken build /home/sam/work/iohk/midnight-cli/validators

# Check types only
~/work/iohk/aiken/result/bin/aiken check /home/sam/work/iohk/midnight-cli/validators

# Extract CBOR
jq -r '.validators[] | "\(.title):\n\(.compiledCode)\n"' \
  /home/sam/work/iohk/midnight-cli/validators/plutus.json
```

## Known Issues

### Aiken v1.1.19 from nixpkgs

- Has code generation bug with actual validator logic
- Compiles stdlib but then exits with code 1
- No error message, just silent failure
- Works with `todo` stubs but fails with real logic

**Solution**: Build Aiken v1.1.21 from source via Nix flake

### stdlib v3 Compilation Failure

- Aiken v1.1.21 fails to compile projects using stdlib v3
- Exits with code 1 after compiling stdlib
- No specific error message visible in terminal
- Possibly related to breaking changes in v3 API

**Solution**: Use stdlib v2 which is stable and well-tested

## Project Structure

```
validators/
├── aiken.toml              # Project config (compiler: v1.1.21, stdlib: v2)
├── plutus.json            # Generated blueprint with compiled CBOR
├── validators/            # Validator source files
│   ├── one_shot_nft.ak   # ✅ Compiled (377 bytes)
│   ├── simple_mint.ak    # ✅ Compiled (test validator)
│   ├── council_governance.ak        # ✅ Compiled (986 bytes)
│   ├── tech_auth_governance.ak      # ✅ Compiled (986 bytes)
│   └── federated_ops_governance.ak  # ✅ Compiled (1245 bytes)
└── lib/                   # Shared library
    └── governance/
        └── types.ak       # Type definitions and helpers for governance
```

## References

- [Aiken Documentation](https://aiken-lang.org)
- [Aiken stdlib v2 Source](https://github.com/aiken-lang/stdlib/tree/v2)
- [Midnight Node Contracts](file:///home/sam/work/iohk/midnight-node/primitives/mainchain-follower/)
