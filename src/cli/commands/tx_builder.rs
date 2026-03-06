use anyhow::Result;
use subxt::dynamic::Value;
use subxt::{OnlineClient, SubstrateConfig};
use super::tx::{FederatedAction, FederatedBody, MembershipAction, MembershipBody, ProposalType, RuntimeAction, RuntimeBody, SystemAction, SystemBody};

/// Build a dynamic transaction call and return its encoded bytes and description
pub async fn build_proposal_call(
    proposal_type: &ProposalType,
    api: &OnlineClient<SubstrateConfig>,
) -> Result<(subxt::tx::DynamicPayload, String)> {

    match proposal_type {
        ProposalType::Membership(m) => {
            let (pallet_name, action) = match &m.body {
                MembershipBody::Council(args) => ("CouncilMembership", &args.action),
                MembershipBody::Ta(args) => ("TechnicalCommitteeMembership", &args.action),
            };

            match action {
                MembershipAction::AddMember { address, .. } => {
                    let account_bytes = parse_ss58_address(address)?;
                    let account_id = Value::unnamed_composite(vec![Value::from_bytes(&account_bytes)]);
                    let multi_address = Value::unnamed_variant("Id", vec![account_id]);
                    Ok((
                        subxt::dynamic::tx(pallet_name, "add_member", vec![multi_address]),
                        format!("Add member {}", address),
                    ))
                }
                MembershipAction::RemoveMember { address, .. } => {
                    let account_bytes = parse_ss58_address(address)?;
                    let account_id = Value::unnamed_composite(vec![Value::from_bytes(&account_bytes)]);
                    let multi_address = Value::unnamed_variant("Id", vec![account_id]);
                    Ok((
                        subxt::dynamic::tx(pallet_name, "remove_member", vec![multi_address]),
                        format!("Remove member {}", address),
                    ))
                }
                MembershipAction::SwapMember { old_address, new_address, .. } => {
                    let old_account = parse_ss58_address(old_address)?;
                    let new_account = parse_ss58_address(new_address)?;
                    let old_id = Value::unnamed_composite(vec![Value::from_bytes(&old_account)]);
                    let old_multi = Value::unnamed_variant("Id", vec![old_id]);
                    let new_id = Value::unnamed_composite(vec![Value::from_bytes(&new_account)]);
                    let new_multi = Value::unnamed_variant("Id", vec![new_id]);
                    Ok((
                        subxt::dynamic::tx(
                            pallet_name,
                            "swap_member",
                            vec![old_multi, new_multi],
                        ),
                        format!("Swap member {} → {}", old_address, new_address),
                    ))
                }
                MembershipAction::ResetMembers { addresses, .. } => {
                    let accounts: Result<Vec<_>> = addresses
                        .iter()
                        .map(|addr| parse_ss58_address(addr))
                        .collect();
                    let accounts = accounts?;
                    let values: Vec<Value> = accounts
                        .iter()
                        .map(Value::from_bytes)
                        .collect();
                    Ok((
                        subxt::dynamic::tx(pallet_name, "reset_members", vec![Value::unnamed_composite(values)]),
                        format!("Reset members ({} new members)", addresses.len()),
                    ))
                }
                MembershipAction::ChangeKey { old_address, new_address, .. } => {
                    let old_account = parse_ss58_address(old_address)?;
                    let new_account = parse_ss58_address(new_address)?;
                    let old_id = Value::unnamed_composite(vec![Value::from_bytes(&old_account)]);
                    let old_multi = Value::unnamed_variant("Id", vec![old_id]);
                    let new_id = Value::unnamed_composite(vec![Value::from_bytes(&new_account)]);
                    let new_multi = Value::unnamed_variant("Id", vec![new_id]);
                    Ok((
                        subxt::dynamic::tx(
                            pallet_name,
                            "change_key",
                            vec![old_multi, new_multi],
                        ),
                        format!("Change key {} → {}", old_address, new_address),
                    ))
                }
                MembershipAction::SetPrime { address, .. } => {
                    let account = parse_ss58_address(address)?;
                    let account_id = Value::unnamed_composite(vec![Value::from_bytes(&account)]);
                    let multi_address = Value::unnamed_variant("Id", vec![account_id]);
                    Ok((
                        subxt::dynamic::tx(pallet_name, "set_prime", vec![multi_address]),
                        format!("Set prime member {}", address),
                    ))
                }
                MembershipAction::ClearPrime { .. } => Ok((
                    subxt::dynamic::tx(pallet_name, "clear_prime", Vec::<Value>::new()),
                    "Clear prime member".to_string(),
                )),
            }
        }
        ProposalType::System(s) => {
            let action = match &s.body {
                SystemBody::Council(args) | SystemBody::Ta(args) => &args.action,
            };

            match action {
                SystemAction::Remark { message, .. } => {
                    let message_bytes = message.as_bytes();
                    Ok((
                        subxt::dynamic::tx(
                            "System",
                            "remark_with_event",
                            vec![Value::from_bytes(message_bytes)],
                        ),
                        format!("Remark: {}", message),
                    ))
                }
            }
        }
        ProposalType::Runtime(r) => {
            let action = match &r.body {
                RuntimeBody::Council(args) | RuntimeBody::Ta(args) => &args.action,
            };

            match action {
                RuntimeAction::AuthorizeUpgrade { code_hash, .. } => {
                    let hash_bytes = hex::decode(code_hash.trim_start_matches("0x"))?;
                    if hash_bytes.len() != 32 {
                        anyhow::bail!("Code hash must be 32 bytes");
                    }
                    Ok((
                        subxt::dynamic::tx("System", "authorize_upgrade", vec![Value::from_bytes(&hash_bytes)]),
                        format!("Authorize upgrade {}", code_hash),
                    ))
                }
                RuntimeAction::SetCode { wasm_hex, .. } => {
                    let wasm_bytes = hex::decode(wasm_hex.trim_start_matches("0x"))?;
                    Ok((
                        subxt::dynamic::tx(
                            "System",
                            "set_code_without_checks",
                            vec![Value::from_bytes(&wasm_bytes)],
                        ),
                        format!("Set runtime code ({} bytes)", wasm_bytes.len()),
                    ))
                }
            }
        }
        ProposalType::Federated(f) => {
            let action = match &f.body {
                FederatedBody::Council(args) | FederatedBody::Ta(args) => &args.action,
            };

            // Build the inner call first
            let (inner_call, description) = match action {
                FederatedAction::PauseTransaction { pallet, call, .. } => {
                    // TxPause.pause takes a tuple (pallet_name_bytes, call_name_bytes)
                    let pallet_bytes = pallet.as_bytes();
                    let call_bytes = call.as_bytes();
                    (
                        subxt::dynamic::tx(
                            "TxPause",
                            "pause",
                            vec![Value::unnamed_composite(vec![
                                Value::from_bytes(pallet_bytes),
                                Value::from_bytes(call_bytes),
                            ])],
                        ),
                        format!("Pause transaction: {}::{}", pallet, call),
                    )
                }
                FederatedAction::UnpauseTransaction { pallet, call, .. } => {
                    let pallet_bytes = pallet.as_bytes();
                    let call_bytes = call.as_bytes();
                    (
                        subxt::dynamic::tx(
                            "TxPause",
                            "unpause",
                            vec![Value::unnamed_composite(vec![
                                Value::from_bytes(pallet_bytes),
                                Value::from_bytes(call_bytes),
                            ])],
                        ),
                        format!("Unpause transaction: {}::{}", pallet, call),
                    )
                }
                FederatedAction::UpdateTermsAndConditions { hash, url, .. } => {
                    let hash_bytes = hex::decode(hash.trim_start_matches("0x"))?;
                    if hash_bytes.len() != 32 {
                        anyhow::bail!("T&C hash must be 32 bytes");
                    }
                    let url_bytes = url.as_bytes();
                    (
                        subxt::dynamic::tx(
                            "SystemParameters",
                            "update_terms_and_conditions",
                            vec![Value::from_bytes(&hash_bytes), Value::from_bytes(url_bytes)],
                        ),
                        format!("Update T&C: {} ({})", hash, url),
                    )
                }
                FederatedAction::UpdateDParameter { num_permissioned, num_registered, .. } => {
                    (
                        subxt::dynamic::tx(
                            "SystemParameters",
                            "update_d_parameter",
                            vec![Value::u128(*num_permissioned as u128), Value::u128(*num_registered as u128)],
                        ),
                        format!("Update D-parameter: permissioned={}, registered={}", num_permissioned, num_registered),
                    )
                }
                FederatedAction::Remark { message, .. } => {
                    let message_bytes = message.as_bytes();
                    (
                        subxt::dynamic::tx(
                            "System",
                            "remark_with_event",
                            vec![Value::from_bytes(message_bytes)],
                        ),
                        format!("Federated Remark: {}", message),
                    )
                }
            };

            // For federated proposals, we need to manually build the full call stack:
            // Council.propose(FederatedAuthority.motion_approve(inner_call))
            //
            // The problem is that motion_approve expects RuntimeCall as a variant,
            // but subxt's dynamic API can't nest calls properly.
            //
            // Solution: Manually encode everything
            

            // Step 1: Encode the inner call
            let inner_call_bytes = api.tx().call_data(&inner_call)?;

            // Step 2: Get FederatedAuthority pallet and motion_approve call indices
            let metadata = api.metadata();
            let fa_pallet = metadata
                .pallet_by_name("FederatedAuthority")
                .ok_or_else(|| anyhow::anyhow!("FederatedAuthority pallet not found"))?;
            let fa_pallet_index = fa_pallet.index();

            let motion_approve_call = fa_pallet
                .call_variant_by_name("motion_approve")
                .ok_or_else(|| anyhow::anyhow!("motion_approve call not found"))?;
            let motion_approve_index = motion_approve_call.index;

            // Step 3: Manually encode FederatedAuthority.motion_approve(inner_call)
            let mut motion_approve_bytes = Vec::new();
            motion_approve_bytes.push(fa_pallet_index);
            motion_approve_bytes.push(motion_approve_index);
            motion_approve_bytes.extend_from_slice(&inner_call_bytes);

            // Step 4: Return as a "fake" dynamic payload that we'll handle specially
            // We'll just return the encoded bytes as a Value and handle it in handle_propose
            // Actually, we can't do this cleanly. Let me try a different approach.
            //
            // Better: Return a marker in description, and handle it specially in handle_propose
            Ok((inner_call, format!("[FEDERATED:{}:{}] {}", fa_pallet_index, motion_approve_index, description)))
        }
    }
}

/// Build a Council or TA propose call from pre-encoded bytes
///
/// Use this for federated proposals where the call is already manually encoded
pub async fn build_propose_call_from_bytes(
    api: &OnlineClient<SubstrateConfig>,
    is_council: bool,
    threshold: u32,
    proposal_call_bytes: &[u8],
) -> Result<Vec<u8>> {
    use parity_scale_codec::{Compact, Encode};

    let proposal_length = proposal_call_bytes.len() as u32;

    // Get pallet and call indices from metadata
    let pallet_name = if is_council { "Council" } else { "TechnicalCommittee" };
    let metadata = api.metadata();
    let pallet = metadata
        .pallet_by_name(pallet_name)
        .ok_or_else(|| anyhow::anyhow!("Pallet '{}' not found", pallet_name))?;

    let pallet_index = pallet.index();
    let call_ty_id = pallet
        .call_ty_id()
        .ok_or_else(|| anyhow::anyhow!("Pallet {} has no calls", pallet_name))?;

    let call_type = metadata
        .types()
        .resolve(call_ty_id)
        .ok_or_else(|| anyhow::anyhow!("Call type not found"))?;

    let propose_call_index = if let scale_info::TypeDef::Variant(v) = &call_type.type_def {
        v.variants
            .iter()
            .find(|var| var.name == "propose")
            .ok_or_else(|| anyhow::anyhow!("propose call not found"))?
            .index
    } else {
        anyhow::bail!("Call type is not a variant");
    };

    // Manually encode the propose call
    // Format: pallet_index | call_index | Compact(threshold) | proposal_bytes | Compact(length)
    let mut call_bytes = Vec::new();
    call_bytes.push(pallet_index);
    call_bytes.push(propose_call_index);
    call_bytes.extend_from_slice(&Compact(threshold).encode());
    call_bytes.extend_from_slice(proposal_call_bytes); // Pre-encoded RuntimeCall bytes
    call_bytes.extend_from_slice(&Compact(proposal_length).encode());

    Ok(call_bytes)
}

/// Build a Council or TA propose call that wraps an inner proposal
///
/// From metadata (query metadata --pallet Council --call propose):
/// - threshold: Compact<u32>
/// - proposal: RuntimeCall (pre-encoded call bytes)
/// - length_bound: Compact<u32>
pub async fn build_propose_call(
    api: &OnlineClient<SubstrateConfig>,
    is_council: bool,
    threshold: u32,
    proposal_call: &subxt::tx::DynamicPayload,
) -> Result<Vec<u8>> {
    use parity_scale_codec::{Compact, Encode};

    // Step 1: Encode the inner proposal (this becomes the RuntimeCall bytes)
    let proposal_call_bytes = api.tx().call_data(proposal_call)?;
    let proposal_length = proposal_call_bytes.len() as u32;

    // Step 2: Get pallet and call indices from metadata
    let pallet_name = if is_council { "Council" } else { "TechnicalCommittee" };
    let metadata = api.metadata();
    let pallet = metadata
        .pallet_by_name(pallet_name)
        .ok_or_else(|| anyhow::anyhow!("Pallet '{}' not found", pallet_name))?;

    let pallet_index = pallet.index();
    let call_ty_id = pallet
        .call_ty_id()
        .ok_or_else(|| anyhow::anyhow!("Pallet {} has no calls", pallet_name))?;

    let call_type = metadata
        .types()
        .resolve(call_ty_id)
        .ok_or_else(|| anyhow::anyhow!("Call type not found"))?;

    let propose_call_index = if let scale_info::TypeDef::Variant(v) = &call_type.type_def {
        v.variants
            .iter()
            .find(|var| var.name == "propose")
            .ok_or_else(|| anyhow::anyhow!("propose call not found"))?
            .index
    } else {
        anyhow::bail!("Call type is not a variant");
    };

    // Step 3: Manually encode the propose call
    // Format: pallet_index | call_index | Compact(threshold) | proposal_bytes | Compact(length)
    let mut call_bytes = Vec::new();
    call_bytes.push(pallet_index);
    call_bytes.push(propose_call_index);
    call_bytes.extend_from_slice(&Compact(threshold).encode());
    call_bytes.extend_from_slice(&proposal_call_bytes); // RuntimeCall is already encoded
    call_bytes.extend_from_slice(&Compact(proposal_length).encode());

    Ok(call_bytes)
}

/// Build a Council or TA vote call
pub async fn build_vote_call(
    api: &OnlineClient<SubstrateConfig>,
    is_council: bool,
    proposal_hash: &str,
    proposal_index: u32,
    approve: bool,
) -> Result<Vec<u8>> {
    use parity_scale_codec::{Compact, Encode};

    let pallet_name = if is_council { "Council" } else { "TechnicalCommittee" };

    let hash_bytes = hex::decode(proposal_hash.trim_start_matches("0x"))?;
    if hash_bytes.len() != 32 {
        anyhow::bail!("Proposal hash must be 32 bytes");
    }

    // Get pallet and call indices from metadata
    let metadata = api.metadata();
    let pallet = metadata
        .pallet_by_name(pallet_name)
        .ok_or_else(|| anyhow::anyhow!("Pallet '{}' not found", pallet_name))?;
    let pallet_index = pallet.index();

    let vote_call = pallet
        .call_variant_by_name("vote")
        .ok_or_else(|| anyhow::anyhow!("Call 'vote' not found in {}", pallet_name))?;
    let call_index = vote_call.index;

    // Manually encode: pallet_index | call_index | hash | Compact(index) | bool(approve)
    let mut call_bytes = Vec::new();
    call_bytes.push(pallet_index);
    call_bytes.push(call_index);
    call_bytes.extend_from_slice(&hash_bytes);
    call_bytes.extend_from_slice(&Compact(proposal_index).encode());
    call_bytes.push(if approve { 1 } else { 0 });

    Ok(call_bytes)
}

/// Build a Council or TA close call
pub async fn build_close_call(
    api: &OnlineClient<SubstrateConfig>,
    is_council: bool,
    proposal_hash: &str,
    proposal_index: u32,
    proposal_length: u32,
) -> Result<Vec<u8>> {
    use subxt::dynamic::Value;

    let pallet_name = if is_council { "Council" } else { "TechnicalCommittee" };

    let hash_bytes = hex::decode(proposal_hash.trim_start_matches("0x"))?;
    if hash_bytes.len() != 32 {
        anyhow::bail!("Proposal hash must be 32 bytes");
    }

    // Use subxt's dynamic API for close call
    // Use max Weight values (u64::MAX) to ensure we don't under-bound
    let close_tx = subxt::dynamic::tx(
        pallet_name,
        "close",
        vec![
            Value::from_bytes(&hash_bytes),
            Value::u128(proposal_index as u128),
            Value::unnamed_composite(vec![
                Value::u128(u64::MAX as u128), // ref_time (max)
                Value::u128(u64::MAX as u128), // proof_size (max)
            ]),
            Value::u128(proposal_length as u128),
        ],
    );

    let close_bytes = api.tx().call_data(&close_tx)?;
    Ok(close_bytes)
}

/// Parse an SS58 address to raw account bytes
fn parse_ss58_address(address: &str) -> Result<Vec<u8>> {
    use sp_core::crypto::Ss58Codec;
    let pubkey: sp_core::sr25519::Public = sp_core::sr25519::Public::from_ss58check(address)?;
    Ok(pubkey.0.to_vec())
}
