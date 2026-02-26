use anyhow::Result;
use subxt::dynamic::Value;
use subxt::{OnlineClient, SubstrateConfig};
use super::tx::{MembershipAction, MembershipBody, ProposalType, RuntimeAction, RuntimeBody, SystemAction, SystemBody};

/// Build a dynamic transaction call and return its encoded bytes and description
pub fn build_proposal_call(
    proposal_type: &ProposalType,
) -> Result<(subxt::tx::DynamicPayload, String)> {

    match proposal_type {
        ProposalType::Membership(m) => {
            let (pallet_name, action) = match &m.body {
                MembershipBody::Council(args) => ("CouncilMembership", &args.action),
                MembershipBody::Ta(args) => ("TechnicalCommitteeMembership", &args.action),
            };

            match action {
                MembershipAction::AddMember { address } => {
                    let account_bytes = parse_ss58_address(address)?;
                    let account_id = Value::unnamed_composite(vec![Value::from_bytes(&account_bytes)]);
                    let multi_address = Value::unnamed_variant("Id", vec![account_id]);
                    Ok((
                        subxt::dynamic::tx(pallet_name, "add_member", vec![multi_address]),
                        format!("Add member {}", address),
                    ))
                }
                MembershipAction::RemoveMember { address } => {
                    let account_bytes = parse_ss58_address(address)?;
                    let account_id = Value::unnamed_composite(vec![Value::from_bytes(&account_bytes)]);
                    let multi_address = Value::unnamed_variant("Id", vec![account_id]);
                    Ok((
                        subxt::dynamic::tx(pallet_name, "remove_member", vec![multi_address]),
                        format!("Remove member {}", address),
                    ))
                }
                MembershipAction::SwapMember { old_address, new_address } => {
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
                MembershipAction::ResetMembers { addresses } => {
                    let accounts: Result<Vec<_>> = addresses
                        .iter()
                        .map(|addr| parse_ss58_address(addr))
                        .collect();
                    let accounts = accounts?;
                    let values: Vec<Value> = accounts
                        .iter()
                        .map(|bytes| Value::from_bytes(bytes))
                        .collect();
                    Ok((
                        subxt::dynamic::tx(pallet_name, "reset_members", vec![Value::unnamed_composite(values)]),
                        format!("Reset members ({} new members)", addresses.len()),
                    ))
                }
                MembershipAction::ChangeKey { old_address, new_address } => {
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
                MembershipAction::SetPrime { address } => {
                    let account = parse_ss58_address(address)?;
                    let account_id = Value::unnamed_composite(vec![Value::from_bytes(&account)]);
                    let multi_address = Value::unnamed_variant("Id", vec![account_id]);
                    Ok((
                        subxt::dynamic::tx(pallet_name, "set_prime", vec![multi_address]),
                        format!("Set prime member {}", address),
                    ))
                }
                MembershipAction::ClearPrime => Ok((
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
                SystemAction::Remark { message } => {
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
                RuntimeAction::AuthorizeUpgrade { code_hash } => {
                    let hash_bytes = hex::decode(code_hash.trim_start_matches("0x"))?;
                    if hash_bytes.len() != 32 {
                        anyhow::bail!("Code hash must be 32 bytes");
                    }
                    Ok((
                        subxt::dynamic::tx("System", "authorize_upgrade", vec![Value::from_bytes(&hash_bytes)]),
                        format!("Authorize upgrade {}", code_hash),
                    ))
                }
                RuntimeAction::SetCode { wasm_hex } => {
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
    }
}

/// Build a Council or TA propose call that wraps an inner proposal
pub async fn build_propose_call(
    api: &OnlineClient<SubstrateConfig>,
    is_council: bool,
    threshold: u32,
    proposal_call: &subxt::tx::DynamicPayload,
) -> Result<Vec<u8>> {
    use parity_scale_codec::{Compact, Encode};

    // Get pallet index from metadata
    let metadata = api.metadata();
    let pallet_name = if is_council { "Council" } else { "TechnicalCommittee" };
    let pallet = metadata.pallet_by_name(pallet_name)
        .ok_or_else(|| anyhow::anyhow!("Pallet {} not found", pallet_name))?;
    let pallet_index = pallet.index();

    // Get propose call index from metadata
    let call_ty = pallet.call_ty_id()
        .ok_or_else(|| anyhow::anyhow!("Pallet {} has no calls", pallet_name))?;
    let call_type = metadata.types().resolve(call_ty)
        .ok_or_else(|| anyhow::anyhow!("Call type not found"))?;

    let propose_call_index = if let scale_info::TypeDef::Variant(v) = &call_type.type_def {
        v.variants.iter()
            .find(|var| var.name == "propose")
            .ok_or_else(|| anyhow::anyhow!("propose call not found"))?
            .index
    } else {
        anyhow::bail!("Call type is not a variant");
    };

    // Encode the inner proposal call
    let proposal_call_bytes = api.tx().call_data(proposal_call)?;
    let proposal_length = proposal_call_bytes.len() as u32;

    // Manually construct the propose call bytes
    // propose(threshold: Compact<u32>, proposal: Box<Call>, length_bound: Compact<u32>)
    let mut call_bytes = Vec::new();
    call_bytes.push(pallet_index);
    call_bytes.push(propose_call_index);
    call_bytes.extend_from_slice(&Compact(threshold).encode());
    call_bytes.extend_from_slice(&proposal_call_bytes); // Box<Call> has no length prefix
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
    let pallet_name = if is_council { "Council" } else { "TechnicalCommittee" };

    let hash_bytes = hex::decode(proposal_hash.trim_start_matches("0x"))?;
    if hash_bytes.len() != 32 {
        anyhow::bail!("Proposal hash must be 32 bytes");
    }

    // Build the vote call: vote(proposal_hash, index, approve)
    let vote_tx = subxt::dynamic::tx(
        pallet_name,
        "vote",
        vec![
            Value::from_bytes(&hash_bytes),
            Value::u128(proposal_index as u128),
            Value::bool(approve),
        ],
    );

    let vote_bytes = api.tx().call_data(&vote_tx)?;
    Ok(vote_bytes)
}

/// Build a Council or TA close call
pub async fn build_close_call(
    api: &OnlineClient<SubstrateConfig>,
    is_council: bool,
    proposal_hash: &str,
    proposal_index: u32,
    proposal_length: u32,
) -> Result<Vec<u8>> {
    let pallet_name = if is_council { "Council" } else { "TechnicalCommittee" };

    let hash_bytes = hex::decode(proposal_hash.trim_start_matches("0x"))?;
    if hash_bytes.len() != 32 {
        anyhow::bail!("Proposal hash must be 32 bytes");
    }

    // Build the close call with Weight parameter (refTime, proofSize)
    let close_tx = subxt::dynamic::tx(
        pallet_name,
        "close",
        vec![
            Value::from_bytes(&hash_bytes),
            Value::u128(proposal_index as u128),
            Value::unnamed_composite(vec![
                Value::u128(1000000000), // refTime
                Value::u128(1000000),    // proofSize
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
