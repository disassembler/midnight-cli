# Proposal Implementation Plan

## Current Status (as of this session)

### ✅ WORKING Commands
1. **`tx propose system council/ta remark`** - Creates remark proposals
   - Fixed: Missing tip in signing payload
   - Fixed: Missing tip in extrinsic construction
   - Tested: Successfully created proposal #0 on testnet

2. **`tx vote council/ta`** - Votes on proposals
   - Fixed: Manual encoding with proper `Compact<u32>` for parameters
   - Tested: 2 successful votes, reached 2/2 threshold

### ❌ BROKEN Commands
1. **`tx close council/ta`** - Runtime validation error
   - Error: `wasm unreachable` in `TaggedTransactionQueue_validate_transaction`
   - Tested multiple approaches (different weights, signers, encodings)
   - Appears to be a runtime-level bug, not CLI encoding issue
   - **Action**: Document as known issue, move on

## Current Work (IN PROGRESS)

### Implementing Federated Authority Proposals

**Status**: ✅ Type definitions and encoding complete, ❌ Runtime validation failing (non-deterministic issue)

**Files Modified**:
- `src/cli/commands/tx.rs` - Added `FederatedProposal`, `FederatedBody`, `FederatedArgs`, `FederatedAction` enums with federated wrapping logic
- `src/cli/commands/tx_builder.rs` - Added `build_propose_call_from_bytes()` for manual encoding of federated proposals

**Implementation Details**:
- Created `build_propose_call_from_bytes()` to accept pre-encoded RuntimeCall bytes
- Federated proposals are manually encoded as: `FederatedAuthority.motion_approve(inner_call_bytes)`
- Detection via description prefix "Federated " to route to correct encoding path
- Successfully generates payloads with correct 3-layer nesting: inner call → motion_approve → Council/TA.propose

**Current Issue - Runtime Validation Failure**:
ALL propose transactions (including previously working code) now fail with:
```
wasm trap: wasm `unreachable` instruction executed
WASM backtrace: TaggedTransactionQueue_validate_transaction
```

**Evidence of Non-Deterministic Behavior**:
- Old working extrinsic (Feb 26, nonce=0) gets "bad signature" error (expected, already used)
- New extrinsics (nonce=1) get wasm unreachable error
- Even commit 6b29507 (known working from Feb 26) now fails with wasm unreachable
- Encoding appears correct when compared byte-by-byte with old working payloads
- Error occurs during transaction pool validation, before block inclusion

**Possible Causes**:
1. Runtime was updated/modified on the node
2. Chain state changed (e.g., existing pending proposal blocking new ones)
3. Account state issue (locked, insufficient funds, etc.)
4. Governance configuration changed (threshold, membership)
5. Non-deterministic runtime bug triggered by specific conditions

**Action**: ✅ Documented as runtime issue

**Testing Results**:
- ❌ Council member 1 (5CD3C2Aa..., nonce=1): wasm unreachable
- ❌ Council member 2 (5CtwJC84..., nonce=1): wasm unreachable
- ❌ Same error across ALL transaction types (propose, vote, close)
- ❌ Even old working commit 6b29507 now fails
- ✅ Old extrinsic from Feb 26 (nonce=0) gets "bad signature" not wasm unreachable

**Conclusion**: Runtime or chain state has changed since Feb 26. All governance transactions are currently blocked. Federated implementation is complete but cannot be tested until runtime issue is resolved.

**Recommendation**: Check if runtime needs reset, or if midnight-node was upgraded without corresponding CLI changes.

**Architecture Decision**:
For federated proposals, the structure is:
1. Inner call (e.g., `TxPause.pause`)
2. Wrapped in `FederatedAuthority.motion_approve(inner_call_bytes)`
3. Wrapped in `Council.propose` or `TA.propose`

Implementation in `tx_builder.rs`:
- `build_proposal_call()` returns the inner call
- `handle_propose()` in `tx.rs` detects federated type and wraps in `motion_approve`
- Then proceeds with normal `Council.propose` wrapping

**Federated Actions Implemented**:
- ✅ `PauseTransaction` - TxPause.pause(pallet, call)
- ✅ `UnpauseTransaction` - TxPause.unpause(pallet, call)
- ✅ `UpdateTermsAndConditions` - SystemParameters.update_terms_and_conditions(hash, url)
- ✅ `UpdateDParameter` - SystemParameters.update_d_parameter(num_permissioned, num_registered)
- ✅ `Remark` - System.remark_with_event (for testing federated flow)

## Remaining Work

### Phase 1: Complete Federated Implementation
1. ✅ Fix compilation errors
2. Test federated remark proposal (simplest test case)
3. Test vote on federated proposals
4. Test close on federated proposals (expect it to fail like other close commands)
5. Test actual TxPause.pause/unpause
6. Test SystemParameters updates

### Phase 2: Remove Membership Commands
**Reason**: Membership is controlled by Cardano mainchain, not governable via CLI

**Files to modify**:
- `src/cli/commands/tx.rs`:
  - Remove `MembershipProposal`, `MembershipBody`, `MembershipArgs`, `MembershipAction`
  - Remove `ProposalType::Membership` variant
  - Remove all membership-related pattern matches
- `src/cli/commands/tx_builder.rs`:
  - Remove membership building code
  - Remove `MembershipAction, MembershipBody` from imports

### Phase 3: Add Missing Single-Authority Proposals

**System proposals to add** (Council OR TA with 2/3 vote):
- ✅ `System.remark_with_event` - Already implemented
- `System.apply_authorized_upgrade` - Apply runtime upgrade after authorization
  - Takes: `code: Vec<u8>` (wasm bytes)
  - Used after `authorize_upgrade` is approved

**Runtime proposals already exist**:
- ✅ `System.authorize_upgrade` - Already implemented
- ✅ `System.set_code` - Already implemented (though probably should be removed - too dangerous)

### Phase 4: Add Additional Federated Authority Proposals

**Bridge Operations** (FederatedAuthority → Bridge pallet):
- `update_policy_script(policy_script)` - Update bridge policy script
- `update_committee_certificate_hashes(...)` - Update committee certificates

**Session Management** (FederatedAuthority → SessionCommitteeManagement):
- `set_main_chain_scripts(...)` - Update mainchain scripts

**Scheduler** (FederatedAuthority → Scheduler):
- `schedule(when, maybe_periodic, priority, call)` - Schedule a call
- `cancel(when, index)` - Cancel scheduled call
- `schedule_named(id, when, maybe_periodic, priority, call)` - Schedule named
- `cancel_named(id)` - Cancel named

**Preimage** (FederatedAuthority → Preimage):
- `note_preimage(bytes)` - Store preimage
- `unnote_preimage(hash)` - Remove preimage
- `request_preimage(hash)` - Request preimage
- `unrequest_preimage(hash)` - Unrequest preimage

**MidnightSystem** (FederatedAuthority → MidnightSystem):
- `send_mn_system_transaction(midnight_system_tx)` - Execute governance-allowed ledger system transactions
  - This is complex, needs investigation of what midnight_system_tx structure is

### Phase 5: Add FederatedAuthority.motion_close Support

**New command**: `tx federated-close`
- Similar to regular close, but for federated authority motions
- Anyone can call `FederatedAuthority.motion_close(motion_hash)` after both Council and TA approve
- This executes the wrapped call with Root origin

**Command structure**:
```bash
midnight-cli tx federated-close \
  --motion-hash 0x... \
  --signer <any-address> \
  --endpoint ws://localhost:9944
```

## Testing Strategy

### For Each Proposal Type:
1. **Create proposal** with Council
2. **Vote** with 2/3 Council members → reaches threshold
3. **Attempt close** (expect failure for close command, but proposal should be created and voted on)
4. **For federated only**: Repeat steps 1-2 with TA, then call `motion_close`

### Test Order (Simplest to Complex):
1. ✅ System.remark (already tested)
2. Federated System.remark (test federated flow)
3. TxPause.pause/unpause
4. SystemParameters.update_d_parameter (simple params)
5. SystemParameters.update_terms_and_conditions
6. Runtime.authorize_upgrade
7. More complex proposals

## Key Implementation Notes

### Transaction Encoding (CRITICAL - Don't Break This!)

**Signing Payload Structure** (WORKING - DO NOT CHANGE):
```
call_bytes + era_bytes + Compact(nonce) + Compact(tip) + spec_version + tx_version + genesis_hash + block_hash
```

**Extrinsic Structure** (WORKING - DO NOT CHANGE):
```
version_byte + address + signature + era + nonce + tip + method
```

**Key fix commits**:
- 6b29507: Added tip to signing payload and extrinsic construction
- 9ce0627: Manual encoding for vote/close with proper Compact types

### Manual vs Dynamic Encoding

**Use Manual Encoding** (with metadata introspection):
- `Council/TA.propose` - Uses `build_propose_call()` in tx_builder.rs
- `Council/TA.vote` - Manual encoding in `build_vote_call()`
- `Council/TA.close` - Manual encoding in `build_close_call()` (though close is broken)

**Use Dynamic API**:
- Inner proposal calls (System.remark, TxPause.pause, etc.) - subxt handles encoding
- Works well for straightforward calls, but careful with complex types

### Metadata Query Commands (VERY USEFUL)

```bash
# Inspect pallet calls
midnight-cli query metadata --pallet <PalletName> [--call <CallName>]

# Decode signing payload
midnight-cli debug decode-payload <hex-payload>
```

## Known Issues

1. **Close command fails with runtime panic** - All close operations (Council, TA, and likely Federated) fail with `wasm unreachable`. This appears to be a midnight-node runtime bug, not CLI issue.

2. **Membership commands exist but shouldn't** - Need to remove them (Phase 2)

## File Map

### Core Files
- `src/cli/commands/tx.rs` - All tx command definitions and handling (1400+ lines)
- `src/cli/commands/tx_builder.rs` - Proposal call building logic (280+ lines)
- `src/application/witness_creation.rs` - Extrinsic construction from signatures

### Supporting Files
- `src/cli/commands/query.rs` - Chain state queries, metadata inspection
- `src/cli/commands/debug.rs` - Payload decoder
- `src/domain/` - Core types (keys, derivation paths)
- `src/crypto/` - Sr25519/Ed25519 operations

## Next Immediate Steps

1. Fix remaining compilation error (import FederatedBody, FederatedAction) - DONE
2. Build and test: `cargo build --release`
3. Test federated remark proposal:
   ```bash
   midnight-cli tx propose federated council remark "test federated" \
     --signer <council-member> \
     --endpoint ws://localhost:9944
   ```
4. Sign and submit
5. Vote with Council (2/3)
6. Create same proposal with TA
7. Vote with TA (2/3)
8. Attempt `motion_close` (need to implement this command)
