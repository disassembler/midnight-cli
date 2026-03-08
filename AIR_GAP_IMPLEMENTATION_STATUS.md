# Air-Gap Workflow Implementation Status

## ✅ Completed

### CLI Commands
1. **`genesis extract-contract`** - Extract single contract from plutus.json
   - Parses Aiken build output
   - Decodes hex CBOR to binary .plutus files
   - Shows validator title, hash, and size

2. **`genesis extract-contracts`** - Extract all contracts at once
   - Batch extraction with filtering options (--spending-only, --minting-only)
   - Generates clean filenames from validator titles
   - Creates organized contracts/ directory

3. **`genesis apply-params`** - Apply parameters to Plutus contracts
   - Supports UTxO reference parameters for one-shot NFT policies
   - Uses existing `src/contracts/params.rs` functionality
   - Wraps uplc parameter application with clean CLI

4. **`genesis sign-deployment`** - Offline signing (STUB)
   - Command structure defined
   - Validation of air-gap directory
   - Helpful error message explaining the feature is coming soon

5. **`genesis submit-deployment`** - Submit signed transactions (STUB)
   - Command structure defined
   - Validation of air-gap directory
   - Helpful error message explaining the feature is coming soon

### Infrastructure
- ✅ All command Args structs defined
- ✅ Handler functions implemented
- ✅ Module imports fixed (added contracts to main.rs)
- ✅ Code compiles successfully
- ✅ Design documents created (AIR_GAP_DESIGN.md, CONTRACTS_WORKFLOW.md)

## 🚧 In Progress / Next Steps

### Core Transaction Building (Priority: HIGH)
The `deploy-contracts` command currently shows a deployment plan but doesn't build actual Cardano transactions. This needs to be implemented for both online and air-gap modes.

**Required work:**
1. **Integrate hayate's `PlutusTransactionBuilder`**
   - Query wallet UTxOs via UTxORPC
   - Build unsigned transaction bodies
   - Calculate proper fees
   - Handle NFT minting policies
   - Add contract outputs with datums

2. **Online mode** (--mnemonic-file, no --air-gap flag):
   - Build transaction
   - Sign with wallet keys
   - Submit via UTxORPC
   - Wait for confirmations
   - Output deployment-info.json

3. **Air-gap mode** (--air-gap flag, no mnemonic):
   - Build unsigned transactions
   - Save transaction bodies (.txbody files)
   - Calculate signing payloads (.payload files)
   - Save metadata (.metadata.json files)
   - Create deployment-plan.json

### Air-Gap Signing (`sign-deployment`)
Convert from stub to full implementation:

**Required work:**
1. Load unsigned transaction bodies from air-gap directory
2. Load signing payloads (transaction hashes)
3. Derive wallet keys from mnemonic
4. Create Ed25519 signatures
5. Build CBOR witness sets
6. Assemble signed transactions
7. Save .witness and .txsigned files

### Air-Gap Submission (`submit-deployment`)
Convert from stub to full implementation:

**Required work:**
1. Load signed transactions from air-gap directory
2. Submit to Cardano network via UTxORPC
3. Wait for confirmations
4. Extract transaction hashes
5. Build deployment-info.json
6. Output Hayate configuration instructions

## 📋 Testing Plan

### Unit Tests Needed
- [ ] plutus.json parsing in extract-contract
- [ ] Parameter application in apply-params
- [ ] Transaction building logic
- [ ] Signature creation and verification
- [ ] File I/O for air-gap workflow

### Integration Tests Needed
- [ ] End-to-end extract → apply-params workflow
- [ ] Full air-gap workflow with local testnet
- [ ] Online deployment to SanchoNet
- [ ] Error handling for invalid inputs

### Manual Testing
- [ ] Extract contracts from actual Aiken build
- [ ] Apply parameters to one-shot NFT policy
- [ ] Deploy contracts on local devnet
- [ ] Complete air-gap workflow on testnet
- [ ] Verify deployment with Hayate indexing

## 🔧 Technical Challenges

### 1. Cardano Transaction Construction
**Challenge:** Building valid Cardano transactions with:
- Plutus script references
- Inline datums
- NFT minting
- Proper fee calculation
- Collateral inputs

**Solution:** Use hayate's `PlutusTransactionBuilder` which handles most of this, but may need modifications to:
- Expose `build_unsigned()` method
- Support external witness addition
- Handle multiple outputs per transaction

### 2. UTxORPC Integration
**Challenge:** Querying UTxOs and submitting transactions via UTxORPC.

**Current status:**
- src/utxorpc/ module exists with basic client
- May need additional methods for:
  - Querying UTxOs by address
  - Submitting transactions
  - Waiting for confirmations

### 3. Ed25519 vs Sr25519
**Challenge:** Cardano uses Ed25519, Midnight uses Sr25519.

**Solution:** The wallet mnemonic derives separate key chains:
- Cardano: Ed25519 at `m/1852H/1815H/accountH`
- Midnight: Sr25519 at `//midnight//governance`

Both are derived from the same mnemonic but use different signature schemes.

### 4. CBOR Encoding
**Challenge:** Proper CBOR encoding of:
- Transaction bodies
- Witness sets
- Datums
- Minting policies

**Solution:** Use pallas_codec for consistent CBOR handling. Already working in params.rs.

## 📚 Documentation Status

✅ **Created:**
- AIR_GAP_DESIGN.md - Complete air-gap workflow design
- CONTRACTS_WORKFLOW.md - Step-by-step user guide
- AIR_GAP_IMPLEMENTATION_STATUS.md (this file)

⏳ **Needs Updates:**
- SETUP_GUIDE.md - Add contract extraction and application steps
- CLAUDE.md - Add new genesis commands examples
- README.md - Update with air-gap workflow instructions

## 🎯 Implementation Priorities

### Phase 1: Essential Contract Preparation (✅ DONE)
- [x] extract-contract command
- [x] extract-contracts command
- [x] apply-params command

### Phase 2: Online Deployment (NEXT)
- [ ] Complete deploy-contracts online mode
- [ ] Integrate hayate transaction building
- [ ] UTxORPC query and submission
- [ ] Test on local devnet

### Phase 3: Air-Gap Workflow (AFTER Phase 2)
- [ ] deploy-contracts --air-gap mode
- [ ] Complete sign-deployment implementation
- [ ] Complete submit-deployment implementation
- [ ] End-to-end air-gap testing

### Phase 4: Polish & Documentation
- [ ] Error handling improvements
- [ ] Help text and examples
- [ ] Updated documentation
- [ ] Tutorial videos/guides

## 💡 Design Decisions

### Why Separate Commands?
We chose `sign-deployment` and `submit-deployment` as separate commands instead of subcommands (like `deploy-contracts sign-offline`) for:
1. **Clarity:** Each phase is a distinct operation
2. **Simplicity:** Easier to understand and document
3. **Flexibility:** Can be used independently if needed
4. **Consistency:** Matches other top-level commands

### Why Stubs Instead of TODOs?
The sign/submit commands are implemented as stubs (not just TODOs) because:
1. **User Experience:** Provides helpful guidance instead of "not found"
2. **Testing:** Can test argument parsing and validation
3. **Documentation:** Generated help text shows the full workflow
4. **Commitment:** Shows the feature is planned, not just an idea

### File Format Choices
- **.txbody:** Raw CBOR transaction body (Cardano standard)
- **.payload:** Hex-encoded hash (human-readable for verification)
- **.metadata.json:** Human-readable transaction details
- **.witness:** CBOR witness set (Cardano standard)
- **.txsigned:** Complete signed transaction (ready to submit)

These match Cardano ecosystem conventions for easy integration with other tools.

## 🔗 Related Work

### Upstream Dependencies
- **hayate:** Cardano transaction building (may need PRs for air-gap support)
- **pallas:** CBOR encoding/decoding
- **uplc:** Plutus script parameter application

### Similar Tools
- **cardano-cli:** Reference for transaction format
- **Polkadot Vault:** Inspiration for air-gap workflow
- **Aiken:** Contract compilation (upstream)

## 📊 Metrics

- **Lines of code added:** ~500
- **New commands:** 5
- **Design documents:** 3
- **Build status:** ✅ Passing
- **Test coverage:** 0% (tests needed)
- **Documentation coverage:** 60% (more needed)

## 🚀 Getting Started (For Next Developer)

To continue this work:

1. **Read the design documents:**
   - AIR_GAP_DESIGN.md
   - CONTRACTS_WORKFLOW.md

2. **Test what's working:**
   ```bash
   # Extract contracts from validators
   cargo run -- genesis extract-contracts --plutus-json ./validators/plutus.json --output-dir ./contracts

   # Apply parameters
   cargo run -- genesis apply-params --contract ./contracts/one_shot_nft.plutus --utxo-ref "abc...#0" --output ./contracts/council_nft_policy.plutus
   ```

3. **Start with online deployment:**
   - Focus on `handle_deploy_contracts()` in genesis.rs
   - Integrate hayate's `PlutusTransactionBuilder`
   - Test on local devnet first

4. **Then add air-gap support:**
   - Implement unsigned transaction saving
   - Implement offline signing
   - Implement transaction submission

5. **Finally, add tests and documentation**

Good luck! 🎉
