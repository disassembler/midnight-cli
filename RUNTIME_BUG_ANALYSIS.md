# Midnight Node Runtime Bug Analysis

## Issue Summary

**Symptom:** All governance transactions fail with `wasm unreachable` error after the first transaction (appears to be nonce>0 related, but actually call-type specific)

**Actual Pattern:**
- ✅ `Council.propose` (nonce=0): SUCCESS
- ❌ `Council.vote` (nonce=0): FAIL
- ❌ `Council.close` (any nonce): FAIL (expected based on pattern)
- ❌ All transactions from accounts with nonce>0: FAIL

**Root Cause:** The issue is NOT related to nonce handling. It's related to the **call filter** configuration.

## Investigation Findings

### 1. Call Filter Stack

The runtime has **TWO** call filters:

#### A. `BaseCallFilter = TxPause` (line 361 in runtime/src/lib.rs)
```rust
impl frame_system::Config for Runtime {
    type BaseCallFilter = TxPause;
    // ...
}
```

#### B. `CheckCallFilter` (SignedExtension at line 996)
```rust
pub type SignedExtra = (
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    CheckCallFilter,  // <-- Custom filter
);
```

### 2. TxPause Configuration (line 711-719)

```rust
impl pallet_tx_pause::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type PauseOrigin = EnsureRoot<AccountId>;
    type UnpauseOrigin = EnsureRoot<AccountId>;
    type WhitelistedCalls = Nothing;  // <-- NO CALLS ARE WHITELISTED!
    type MaxNameLen = ConstU32<256>;
    type WeightInfo = pallet_tx_pause::weights::SubstrateWeight<Runtime>;
}
```

**KEY:** `WhitelistedCalls = Nothing` means TxPause checks EVERY call against its paused list.

### 3. CheckCallFilter Implementation (check_call_filter.rs)

```rust
impl Contains<RuntimeCall> for GovernanceAuthorityCallFilter {
    fn contains(call: &RuntimeCall) -> bool {
        matches!(
            call,
            RuntimeCall::Council(_)  // <-- ALL Council calls allowed
                | RuntimeCall::TechnicalCommittee(_)  // <-- ALL TA calls allowed
                | RuntimeCall::FederatedAuthority(
                    pallet_federated_authority::Call::motion_close { .. }
                )
                | RuntimeCall::System(frame_system::Call::apply_authorized_upgrade { .. })
        )
    }
}
```

This filter SHOULD allow all Council and TA calls, including vote and close.

## Hypothesis

The `wasm unreachable` panic is likely occurring in the **TxPause pallet's call checking logic** when:

1. A call comes in (e.g., Council.vote)
2. TxPause.contains() is called to check if it's paused
3. The paused calls storage lookup fails or panics
4. This happens because the genesis state didn't properly initialize the TxPause storage

### Why Propose Works But Vote Doesn't

Possible reasons:
1. TxPause storage is uninitialized, causing a panic on lookup for certain call types
2. There's a specific bug in how TxPause handles Council.vote vs Council.propose
3. The genesis initialization paused vote/close by default

## Evidence

1. **Transaction Extension Migration** (commit eea4bbae, Feb 3 2026):
   - Recent migration to TransactionExtension API
   - Multiple fixup commits suggesting issues
   - This was only 24 days ago - likely related

2. **Pattern Analysis**:
   - First transaction (propose, nonce=0): ✅ Works
   - Second transaction (vote, nonce=0): ❌ Fails
   - Pattern suggests storage initialization issue, not nonce issue

3. **Error Location**:
   - `TaggedTransactionQueue_validate_transaction` - transaction pool validation
   - Panic before dispatch, during validation phase
   - Consistent with call filter panic

## Recommended Fixes

### Option 1: Whitelist Governance Calls in TxPause (RECOMMENDED)

```rust
// In runtime/src/lib.rs
parameter_types! {
    pub WhitelistedGovernanceCalls: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b"Council".to_vec(), b"*".to_vec()),  // All Council calls
        (b"TechnicalCommittee".to_vec(), b"*".to_vec()),  // All TA calls
        (b"FederatedAuthority".to_vec(), b"motion_close".to_vec()),
    ];
}

impl pallet_tx_pause::Config for Runtime {
    // ...
    type WhitelistedCalls = WhitelistedGovernanceCalls;  // <-- CHANGE THIS
    // ...
}
```

### Option 2: Remove TxPause from BaseCallFilter

```rust
impl frame_system::Config for Runtime {
    type BaseCallFilter = frame_support::traits::Everything;  // <-- CHANGE THIS
    // Keep CheckCallFilter extension for governance-only filtering
}
```

### Option 3: Initialize TxPause Storage Properly

Ensure genesis configuration properly initializes the TxPause pallet's storage to not panic on uninitialized access.

## Testing Recommendation

1. Apply Option 1 or 2
2. Rebuild runtime: `cd ~/work/iohk/midnight-node && cargo build --release`
3. Restart node with new runtime
4. Test vote and close transactions

## Files Involved

- `/home/sam/work/iohk/midnight-node/runtime/src/lib.rs` (lines 361, 711-719, 988-997)
- `/home/sam/work/iohk/midnight-node/runtime/src/check_call_filter.rs`
- Potentially: genesis initialization code for TxPause

## Commit History

- `eea4bbae` - feat: migrated to TransactionExtension (Feb 3, 2026)
- `1a68fbda`, `b6cf031b`, `9f5d087f` - fixup commits (suggests issues with migration)

## Next Steps

1. **Immediate:** Apply Option 1 (whitelist governance calls in TxPause)
2. **Test:** Verify vote and close work after fix
3. **Long-term:** Consider if TxPause is needed at all given CheckCallFilter already restricts calls
