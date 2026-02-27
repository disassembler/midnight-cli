use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Common transaction arguments shared across all tx commands
#[derive(Args, Clone)]
pub struct CommonTxArgs {
    /// Signer address (must be a governance member)
    #[arg(long)]
    pub signer: Option<String>,

    /// WebSocket endpoint of the Midnight node
    #[arg(long, default_value = "ws://localhost:9944")]
    pub endpoint: String,

    /// Output directory for payload and metadata files
    #[arg(long, default_value = "./governance-payloads")]
    pub output_dir: PathBuf,

    /// Era period in blocks (default: 64)
    #[arg(long, default_value = "64")]
    pub era_period: u64,

    /// State file for multi-step governance workflows
    #[arg(long)]
    pub state_file: Option<PathBuf>,

    /// Voting threshold (number of yes votes required). If not provided, calculates 2/3 majority.
    #[arg(long)]
    pub threshold: Option<u32>,
}

#[derive(Subcommand)]
pub enum TxCommands {
    /// Propose a governance action
    Propose(ProposeArgs),
    /// Vote on a governance proposal
    Vote(VoteArgs),
    /// Close and execute a proposal
    Close(CloseArgs),
    /// Submit a signed extrinsic to the network
    Submit(SubmitArgs),
}

#[derive(Args)]
pub struct ProposeArgs {
    /// Proposal category
    #[command(subcommand)]
    pub proposal: ProposalType,
}

#[derive(Args)]
pub struct VoteArgs {
    /// Governance body
    #[command(subcommand)]
    pub body: VoteBody,
}

#[derive(Subcommand)]
pub enum VoteBody {
    /// Vote on a Council proposal
    Council {
        /// Proposal index
        #[arg(long)]
        proposal_index: u32,
        /// Proposal hash (optional, can be queried from chain)
        #[arg(long)]
        proposal_hash: Option<String>,
        /// Vote approve (true) or reject (false)
        #[arg(long)]
        approve: bool,
        /// Signer address (must be a Council member)
        #[arg(long)]
        signer: Option<String>,
        /// WebSocket endpoint of the Midnight node
        #[arg(long, default_value = "ws://localhost:9944")]
        endpoint: String,
        /// Output directory for payload and metadata files
        #[arg(long, default_value = "./governance-payloads")]
        output_dir: PathBuf,
        /// Era period in blocks (default: 64)
        #[arg(long, default_value = "64")]
        era_period: u64,
    },
    /// Vote on a Technical Authority proposal
    Ta {
        /// Proposal index
        #[arg(long)]
        proposal_index: u32,
        /// Proposal hash (optional, can be queried from chain)
        #[arg(long)]
        proposal_hash: Option<String>,
        /// Vote approve (true) or reject (false)
        #[arg(long)]
        approve: bool,
        /// Signer address (must be a TA member)
        #[arg(long)]
        signer: Option<String>,
        /// WebSocket endpoint of the Midnight node
        #[arg(long, default_value = "ws://localhost:9944")]
        endpoint: String,
        /// Output directory for payload and metadata files
        #[arg(long, default_value = "./governance-payloads")]
        output_dir: PathBuf,
        /// Era period in blocks (default: 64)
        #[arg(long, default_value = "64")]
        era_period: u64,
    },
}

#[derive(Subcommand)]
pub enum ProposalType {
    /// Membership management proposals
    Membership(MembershipProposal),
    /// System operation proposals
    System(SystemProposal),
    /// Runtime upgrade proposals
    Runtime(RuntimeProposal),
}

#[derive(Args)]
pub struct MembershipProposal {
    #[command(subcommand)]
    pub body: MembershipBody,
}

#[derive(Subcommand)]
pub enum MembershipBody {
    /// Council membership changes
    Council(MembershipArgs),
    /// Technical Authority membership changes
    Ta(MembershipArgs),
}

#[derive(Args)]
pub struct MembershipArgs {
    #[command(subcommand)]
    pub action: MembershipAction,
}

#[derive(Subcommand)]
pub enum MembershipAction {
    /// Add a new member
    AddMember {
        /// Member address (SS58 format)
        address: String,
        #[command(flatten)]
        common: CommonTxArgs,
    },
    /// Remove an existing member
    RemoveMember {
        /// Member address (SS58 format)
        address: String,
        #[command(flatten)]
        common: CommonTxArgs,
    },
    /// Swap one member for another
    SwapMember {
        /// Old member address
        old_address: String,
        /// New member address
        new_address: String,
        #[command(flatten)]
        common: CommonTxArgs,
    },
    /// Reset the entire membership set
    ResetMembers {
        /// New member addresses
        addresses: Vec<String>,
        #[command(flatten)]
        common: CommonTxArgs,
    },
    /// Change a member's key
    ChangeKey {
        /// Old member address
        old_address: String,
        /// New member address
        new_address: String,
        #[command(flatten)]
        common: CommonTxArgs,
    },
    /// Set the prime member (tie-breaker for votes)
    SetPrime {
        /// Prime member address
        address: String,
        #[command(flatten)]
        common: CommonTxArgs,
    },
    /// Clear the prime member
    ClearPrime {
        #[command(flatten)]
        common: CommonTxArgs,
    },
}

#[derive(Args)]
pub struct SystemProposal {
    #[command(subcommand)]
    pub body: SystemBody,
}

#[derive(Subcommand)]
pub enum SystemBody {
    /// Council system proposal
    Council(SystemArgs),
    /// Technical Authority system proposal
    Ta(SystemArgs),
}

#[derive(Args)]
pub struct SystemArgs {
    #[command(subcommand)]
    pub action: SystemAction,
}

#[derive(Subcommand)]
pub enum SystemAction {
    /// Post a remark message on-chain
    Remark {
        /// Message text
        message: String,
        #[command(flatten)]
        common: CommonTxArgs,
    },
}

#[derive(Args)]
pub struct RuntimeProposal {
    #[command(subcommand)]
    pub body: RuntimeBody,
}

#[derive(Subcommand)]
pub enum RuntimeBody {
    /// Council runtime proposal
    Council(RuntimeArgs),
    /// Technical Authority runtime proposal
    Ta(RuntimeArgs),
}

#[derive(Args)]
pub struct RuntimeArgs {
    #[command(subcommand)]
    pub action: RuntimeAction,
}

#[derive(Subcommand)]
pub enum RuntimeAction {
    /// Authorize a runtime upgrade
    AuthorizeUpgrade {
        /// Code hash to authorize
        code_hash: String,
        #[command(flatten)]
        common: CommonTxArgs,
    },
    /// Set new runtime code directly
    SetCode {
        /// WASM runtime code (hex-encoded)
        wasm_hex: String,
        #[command(flatten)]
        common: CommonTxArgs,
    },
}

#[derive(Args)]
pub struct CloseArgs {
    /// Governance body
    #[command(subcommand)]
    pub body: CloseBody,
}

#[derive(Subcommand)]
pub enum CloseBody {
    /// Close a Council proposal
    Council {
        /// Proposal index
        #[arg(long)]
        proposal_index: u32,
        /// Proposal hash (optional, from state file if not provided)
        #[arg(long)]
        proposal_hash: Option<String>,
        /// Proposal length (optional, from state file if not provided)
        #[arg(long)]
        proposal_length: Option<u32>,
        /// Signer address (must be a Council member)
        #[arg(long)]
        signer: Option<String>,
        /// WebSocket endpoint of the Midnight node
        #[arg(long, default_value = "ws://localhost:9944")]
        endpoint: String,
        /// Output directory for payload and metadata files
        #[arg(long, default_value = "./governance-payloads")]
        output_dir: PathBuf,
        /// Era period in blocks (default: 64)
        #[arg(long, default_value = "64")]
        era_period: u64,
        /// State file for multi-step governance workflows
        #[arg(long)]
        state_file: Option<PathBuf>,
    },
    /// Close a Technical Authority proposal
    Ta {
        /// Proposal index
        #[arg(long)]
        proposal_index: u32,
        /// Proposal hash (optional, from state file if not provided)
        #[arg(long)]
        proposal_hash: Option<String>,
        /// Proposal length (optional, from state file if not provided)
        #[arg(long)]
        proposal_length: Option<u32>,
        /// Signer address (must be a TA member)
        #[arg(long)]
        signer: Option<String>,
        /// WebSocket endpoint of the Midnight node
        #[arg(long, default_value = "ws://localhost:9944")]
        endpoint: String,
        /// Output directory for payload and metadata files
        #[arg(long, default_value = "./governance-payloads")]
        output_dir: PathBuf,
        /// Era period in blocks (default: 64)
        #[arg(long, default_value = "64")]
        era_period: u64,
        /// State file for multi-step governance workflows
        #[arg(long)]
        state_file: Option<PathBuf>,
    },
}

#[derive(Args)]
pub struct SubmitArgs {
    /// WebSocket endpoint of the Midnight node
    #[arg(long, default_value = "ws://localhost:9944")]
    pub endpoint: String,

    /// Path to the signed extrinsic file
    #[arg(long)]
    pub extrinsic: PathBuf,
}

pub async fn handle_tx_command(command: TxCommands) -> Result<()> {
    match command {
        TxCommands::Propose(args) => handle_propose(args).await,
        TxCommands::Vote(args) => handle_vote(args).await,
        TxCommands::Close(args) => handle_close(args).await,
        TxCommands::Submit(args) => handle_submit(args).await,
    }
}

/// Extract all governance members from SCALE-encoded storage
fn extract_all_members(data_hex: Option<String>, body_name: &str) -> Result<Vec<String>> {
    let data_hex = data_hex.ok_or_else(|| anyhow::anyhow!("{} membership not found in storage", body_name))?;

    let data = hex::decode(data_hex.trim_start_matches("0x"))?;
    if data.is_empty() {
        anyhow::bail!("No members found in {} storage", body_name);
    }

    // Decode compact-encoded Vec length
    // SCALE compact encoding for small numbers (0-63): (value << 2) | 0b00
    // To decode: if (byte & 0b11) == 0, then value = byte >> 2
    let first_byte = data[0];
    let mode = first_byte & 0b11;

    let (member_count, offset_start) = if mode == 0b00 {
        // Single-byte mode (0-63)
        ((first_byte >> 2) as usize, 1)
    } else if mode == 0b01 {
        // Two-byte mode (64-16383)
        if data.len() < 2 {
            anyhow::bail!("Incomplete compact encoding for {} member count", body_name);
        }
        let value = ((first_byte as u16 >> 2) | ((data[1] as u16) << 6)) as usize;
        (value, 2)
    } else {
        anyhow::bail!("Unsupported compact encoding mode for {} member count: {}", body_name, mode);
    };

    if member_count == 0 {
        anyhow::bail!("No members in {} body", body_name);
    }

    let mut members = Vec::new();
    let mut offset = offset_start;

    // Each member is exactly 32 bytes (AccountId32)
    for i in 0..member_count {
        if offset + 32 > data.len() {
            anyhow::bail!("Incomplete member data at index {} for {}", i, body_name);
        }

        let account_bytes = &data[offset..offset + 32];
        let pubkey = sp_core::sr25519::Public::from_raw(
            account_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("Failed to parse account bytes at offset {}", offset))?
        );

        use sp_core::crypto::Ss58Codec;
        members.push(pubkey.to_ss58check());
        offset += 32;
    }

    Ok(members)
}

/// Extract common args from deeply nested proposal structure
fn extract_propose_common(proposal: &ProposalType) -> &CommonTxArgs {
    match proposal {
        ProposalType::Membership(m) => match &m.body {
            MembershipBody::Council(args) => match &args.action {
                MembershipAction::AddMember { common, .. } => common,
                MembershipAction::RemoveMember { common, .. } => common,
                MembershipAction::SwapMember { common, .. } => common,
                MembershipAction::ResetMembers { common, .. } => common,
                MembershipAction::ChangeKey { common, .. } => common,
                MembershipAction::SetPrime { common, .. } => common,
                MembershipAction::ClearPrime { common } => common,
            },
            MembershipBody::Ta(args) => match &args.action {
                MembershipAction::AddMember { common, .. } => common,
                MembershipAction::RemoveMember { common, .. } => common,
                MembershipAction::SwapMember { common, .. } => common,
                MembershipAction::ResetMembers { common, .. } => common,
                MembershipAction::ChangeKey { common, .. } => common,
                MembershipAction::SetPrime { common, .. } => common,
                MembershipAction::ClearPrime { common } => common,
            },
        },
        ProposalType::System(s) => match &s.body {
            SystemBody::Council(args) => match &args.action {
                SystemAction::Remark { common, .. } => common,
            },
            SystemBody::Ta(args) => match &args.action {
                SystemAction::Remark { common, .. } => common,
            },
        },
        ProposalType::Runtime(r) => match &r.body {
            RuntimeBody::Council(args) => match &args.action {
                RuntimeAction::AuthorizeUpgrade { common, .. } => common,
                RuntimeAction::SetCode { common, .. } => common,
            },
            RuntimeBody::Ta(args) => match &args.action {
                RuntimeAction::AuthorizeUpgrade { common, .. } => common,
                RuntimeAction::SetCode { common, .. } => common,
            },
        },
    }
}

async fn handle_propose(args: ProposeArgs) -> Result<()> {
    use jsonrpsee::ws_client::WsClientBuilder;
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::rpc_params;
    use parity_scale_codec::{Compact, Encode};
    use serde_json::json;
    use std::fs;
    use sp_core::hashing::blake2_256;

    let common = extract_propose_common(&args.proposal);

    eprintln!("🔗 Connecting to {}", common.endpoint);

    // Connect with both RPC client (for queries) and subxt (for tx building)
    let api = subxt::OnlineClient::<subxt::SubstrateConfig>::from_url(&common.endpoint).await?;
    let client = WsClientBuilder::default()
        .build(&common.endpoint)
        .await?;

    let chain: String = client.request("system_chain", rpc_params![]).await?;
    let header: serde_json::Value = client.request("chain_getHeader", rpc_params![]).await?;
    let block_number = header["number"]
        .as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);

    eprintln!("✅ Connected to: {}", chain);
    eprintln!("📊 Current block: {}", block_number);
    eprintln!();

    fs::create_dir_all(&common.output_dir)?;

    let state_path = common.state_file.clone().unwrap_or_else(|| common.output_dir.join("state.json"));
    let mut state: serde_json::Value = if state_path.exists() {
        serde_json::from_str(&fs::read_to_string(&state_path)?)?
    } else {
        json!({})
    };

    // Query governance members
    eprintln!("👥 Querying governance members...");
    let council_storage_key = format!("0x{}{}",
        hex::encode(sp_core::hashing::twox_128(b"CouncilMembership")),
        hex::encode(sp_core::hashing::twox_128(b"Members"))
    );
    let council_data_hex: Option<String> = client
        .request("state_getStorage", rpc_params![council_storage_key])
        .await?;

    let ta_storage_key = format!("0x{}{}",
        hex::encode(sp_core::hashing::twox_128(b"TechnicalCommitteeMembership")),
        hex::encode(sp_core::hashing::twox_128(b"Members"))
    );
    let ta_data_hex: Option<String> = client
        .request("state_getStorage", rpc_params![ta_storage_key])
        .await?;

    // Extract all members
    let council_members = extract_all_members(council_data_hex, "Council")?;
    let ta_members = extract_all_members(ta_data_hex, "Technical Authority")?;

    eprintln!("   Council members: {}", council_members.len());
    eprintln!("   Technical Authority members: {}", ta_members.len());
    eprintln!();

    // Determine which body is proposing (early check for signer validation)
    let is_council = match &args.proposal {
        ProposalType::Membership(m) => match &m.body {
            MembershipBody::Council(_) => true,
            MembershipBody::Ta(_) => false,
        },
        ProposalType::System(s) => match &s.body {
            SystemBody::Council(_) => true,
            SystemBody::Ta(_) => false,
        },
        ProposalType::Runtime(r) => match &r.body {
            RuntimeBody::Council(_) => true,
            RuntimeBody::Ta(_) => false,
        },
    };

    let (available_members, body_name) = if is_council {
        (council_members, "Council")
    } else {
        (ta_members, "Technical Authority")
    };

    // Select or validate signer (BEFORE building any payloads)
    let signer_address = if let Some(provided_signer) = &common.signer {
        // Validate provided signer is a member
        if !available_members.contains(provided_signer) {
            eprintln!("❌ Error: Address {} is not a member of {}", provided_signer, body_name);
            eprintln!();
            eprintln!("Available {} members:", body_name);
            for (idx, member) in available_members.iter().enumerate() {
                eprintln!("  {}. {}", idx + 1, member);
            }
            eprintln!();
            eprintln!("Usage: --signer <ADDRESS>");
            anyhow::bail!("Invalid signer address");
        }
        provided_signer.clone()
    } else {
        // No signer provided - show available members and error
        eprintln!("❌ Error: No signer address specified");
        eprintln!();
        eprintln!("Available {} members:", body_name);
        for (idx, member) in available_members.iter().enumerate() {
            eprintln!("  {}. {}", idx + 1, member);
        }
        eprintln!();
        eprintln!("Please specify which member to sign as:");
        eprintln!("  --signer <ADDRESS>");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  --signer {}", available_members[0]);
        anyhow::bail!("Missing required --signer argument");
    };

    eprintln!("✓ Using signer: {}", signer_address);
    eprintln!();

    // Build the proposal call using subxt
    let (proposal_payload, proposal_description) = super::tx_builder::build_proposal_call(&args.proposal)?;
    let proposal_bytes = api.tx().call_data(&proposal_payload)?;

    let proposal_hash = blake2_256(&proposal_bytes);
    let proposal_hash_hex = format!("0x{}", hex::encode(proposal_hash));
    let proposal_hex = format!("0x{}", hex::encode(&proposal_bytes));
    let proposal_length = proposal_bytes.len() as u32;

    eprintln!("📝 Proposal: {}", proposal_description);
    eprintln!("   Hash: {}", proposal_hash_hex);
    eprintln!("   Length: {} bytes", proposal_length);
    eprintln!();

    // Save proposal to state
    state["proposalCall"] = json!(proposal_hex);
    state["proposalHash"] = json!(proposal_hash_hex);
    state["proposalLength"] = json!(proposal_length);

    // Determine filename for output
    let filename = match &args.proposal {
        ProposalType::Membership(m) => match &m.body {
            MembershipBody::Council(_) => "council-propose-membership",
            MembershipBody::Ta(_) => "ta-propose-membership",
        },
        ProposalType::System(s) => match &s.body {
            SystemBody::Council(_) => "council-propose-system",
            SystemBody::Ta(_) => "ta-propose-system",
        },
        ProposalType::Runtime(r) => match &r.body {
            RuntimeBody::Council(_) => "council-propose-runtime",
            RuntimeBody::Ta(_) => "ta-propose-runtime",
        },
    };

    // Calculate threshold: 2/3 majority (matches runtime config)
    // For Council and Technical Committee, both are configured with AtLeastTwoThirds
    let member_count = available_members.len() as u32;
    let threshold = common.threshold.unwrap_or_else(|| {
        (member_count * 2).div_ceil(3) // Ceiling division: ceil(n * 2/3)
    });

    if threshold > member_count {
        eprintln!("❌ Error: Threshold ({}) cannot exceed member count ({})", threshold, member_count);
        anyhow::bail!("Invalid threshold");
    }

    eprintln!("📊 Governance threshold: {} of {} members{}",
        threshold,
        member_count,
        if common.threshold.is_some() { " (custom)" } else { " (2/3 majority)" }
    );
    eprintln!();

    // Build the propose call using subxt
    let call_bytes = super::tx_builder::build_propose_call(
        &api,
        is_council,
        threshold,
        &proposal_payload,
    ).await?;

    // Get nonce and build signing payload
    let nonce: u64 = client
        .request("system_accountNextIndex", rpc_params![signer_address.clone()])
        .await?;

    let genesis_hash_hex: String = client.request("chain_getBlockHash", rpc_params![0]).await?;
    let block_hash_hex: String = client.request("chain_getBlockHash", rpc_params![]).await?;

    let runtime_version: serde_json::Value = client.request("state_getRuntimeVersion", rpc_params![]).await?;
    let spec_version = runtime_version["specVersion"].as_u64().unwrap_or(0) as u32;
    let transaction_version = runtime_version["transactionVersion"].as_u64().unwrap_or(0) as u32;

    eprintln!("📝 Transaction details:");
    eprintln!("   Signer: {}", signer_address);
    eprintln!("   Nonce: {}", nonce);
    eprintln!();

    // Calculate era
    let period = common.era_period;
    let period_pow2 = period.next_power_of_two().clamp(4, 65536);
    let period_encoded = (period_pow2.trailing_zeros() - 1).clamp(1, 15) as u8;
    let quantize_factor = (period_pow2 >> 12).max(1);
    let phase = (block_number / quantize_factor) % (period_pow2 / quantize_factor);
    let phase_encoded = (phase as u16) << 4 | period_encoded as u16;
    let era_bytes = if phase_encoded < 256 {
        vec![phase_encoded as u8]
    } else {
        vec![(phase_encoded & 0xff) as u8, (phase_encoded >> 8) as u8]
    };
    let era_hex = format!("0x{}", hex::encode(&era_bytes));

    // Construct signing payload
    let mut payload = Vec::new();
    payload.extend_from_slice(&call_bytes);
    payload.extend_from_slice(&era_bytes);
    payload.extend_from_slice(&Compact(nonce).encode());
    payload.extend_from_slice(&Compact(0u128).encode()); // tip
    payload.extend_from_slice(&spec_version.to_le_bytes());
    payload.extend_from_slice(&transaction_version.to_le_bytes());
    let genesis_hash_bytes = hex::decode(genesis_hash_hex.trim_start_matches("0x"))?;
    payload.extend_from_slice(&genesis_hash_bytes);
    let block_hash_bytes = hex::decode(block_hash_hex.trim_start_matches("0x"))?;
    payload.extend_from_slice(&block_hash_bytes);

    let final_payload = if payload.len() > 256 {
        blake2_256(&payload).to_vec()
    } else {
        payload
    };

    let payload_hex = format!("0x{}", hex::encode(&final_payload));
    let method_hex = format!("0x{}", hex::encode(&call_bytes));

    // Save files
    let payload_file = common.output_dir.join(format!("{}.payload", filename));
    let metadata_file = common.output_dir.join(format!("{}.json", filename));

    fs::write(&payload_file, &payload_hex)?;
    eprintln!("✓ Payload: {}", payload_file.display());

    let metadata = json!({
        "step": filename,
        "signerAddress": signer_address,
        "nonce": nonce,
        "payload": payload_hex,
        "method": method_hex,
        "era": era_hex,
        "tip": 0,
        "specVersion": spec_version,
        "transactionVersion": transaction_version,
        "genesisHash": genesis_hash_hex,
        "blockHash": block_hash_hex,
        "createdAt": chrono::Utc::now().to_rfc3339()
    });

    fs::write(&metadata_file, serde_json::to_string_pretty(&metadata)?)?;
    eprintln!("   Data: {}", metadata_file.display());

    fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;

    eprintln!();
    eprintln!("📋 Next steps:");
    eprintln!("   1. Sign on airgapped computer:");
    eprintln!("      midnight-cli witness create-extrinsic \\");
    eprintln!("        --payload {} \\", payload_file.display());
    eprintln!("        --tx-metadata {} \\", metadata_file.display());
    eprintln!("        --mnemonic-file <mnemonic> \\");
    eprintln!("        --purpose governance \\");
    eprintln!("        --output {}/{}.extrinsic", common.output_dir.display(), filename);
    eprintln!("   2. Submit:");
    eprintln!("      midnight-cli tx submit --extrinsic {}/{}.extrinsic", common.output_dir.display(), filename);

    Ok(())
}

async fn handle_vote(args: VoteArgs) -> Result<()> {
    use jsonrpsee::ws_client::WsClientBuilder;
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::rpc_params;
    use parity_scale_codec::{Compact, Encode};
    use serde_json::json;
    use std::fs;
    use sp_core::hashing::blake2_256;

    // Extract fields from VoteBody variant
    let (is_council, proposal_index, proposal_hash_opt, approve, signer, endpoint, output_dir, era_period) = match &args.body {
        VoteBody::Council { proposal_index, proposal_hash, approve, signer, endpoint, output_dir, era_period } => {
            (true, *proposal_index, proposal_hash.clone(), *approve, signer.clone(), endpoint.clone(), output_dir.clone(), *era_period)
        }
        VoteBody::Ta { proposal_index, proposal_hash, approve, signer, endpoint, output_dir, era_period } => {
            (false, *proposal_index, proposal_hash.clone(), *approve, signer.clone(), endpoint.clone(), output_dir.clone(), *era_period)
        }
    };

    eprintln!("🔗 Connecting to {}", endpoint);

    let api = subxt::OnlineClient::<subxt::SubstrateConfig>::from_url(&endpoint).await?;
    let client = WsClientBuilder::default().build(&endpoint).await?;

    let chain: String = client.request("system_chain", rpc_params![]).await?;
    let header: serde_json::Value = client.request("chain_getHeader", rpc_params![]).await?;
    let block_number = header["number"]
        .as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);

    eprintln!("✅ Connected to: {}", chain);
    eprintln!("📊 Current block: {}", block_number);
    eprintln!();

    fs::create_dir_all(&output_dir)?;

    // Query governance members
    eprintln!("👥 Querying governance members...");
    let council_storage_key = format!("0x{}{}",
        hex::encode(sp_core::hashing::twox_128(b"CouncilMembership")),
        hex::encode(sp_core::hashing::twox_128(b"Members"))
    );
    let council_data_hex: Option<String> = client
        .request("state_getStorage", rpc_params![council_storage_key])
        .await?;

    let ta_storage_key = format!("0x{}{}",
        hex::encode(sp_core::hashing::twox_128(b"TechnicalCommitteeMembership")),
        hex::encode(sp_core::hashing::twox_128(b"Members"))
    );
    let ta_data_hex: Option<String> = client
        .request("state_getStorage", rpc_params![ta_storage_key])
        .await?;

    let council_members = extract_all_members(council_data_hex, "Council")?;
    let ta_members = extract_all_members(ta_data_hex, "Technical Authority")?;

    eprintln!("   Council members: {}", council_members.len());
    eprintln!("   Technical Authority members: {}", ta_members.len());
    eprintln!();

    // Query proposal hash if not provided
    let proposal_hash = if let Some(h) = proposal_hash_opt {
        h
    } else {
        query_proposal_hash(&client, is_council, proposal_index).await?
    };

    let (available_members, body_name, filename) = if is_council {
        (council_members, "Council", "council-vote")
    } else {
        (ta_members, "Technical Authority", "ta-vote")
    };

    // Validate signer
    let signer_address = if let Some(provided_signer) = &signer {
        if !available_members.contains(provided_signer) {
            eprintln!("❌ Error: Address {} is not a member of {}", provided_signer, body_name);
            eprintln!();
            eprintln!("Available {} members:", body_name);
            for (idx, member) in available_members.iter().enumerate() {
                eprintln!("  {}. {}", idx + 1, member);
            }
            anyhow::bail!("Invalid signer address");
        }
        provided_signer.clone()
    } else {
        eprintln!("❌ Error: No signer address specified");
        eprintln!();
        eprintln!("Available {} members:", body_name);
        for (idx, member) in available_members.iter().enumerate() {
            eprintln!("  {}. {}", idx + 1, member);
        }
        eprintln!();
        eprintln!("Example: --signer {}", available_members[0]);
        anyhow::bail!("Missing required --signer argument");
    };

    eprintln!("✓ Using signer: {}", signer_address);
    eprintln!();
    eprintln!("🗳️  Vote details:");
    eprintln!("   Proposal index: {}", proposal_index);
    eprintln!("   Proposal hash: {}", proposal_hash);
    eprintln!("   Vote: {}", if approve { "✅ APPROVE" } else { "❌ REJECT" });
    eprintln!();

    // Build the vote call
    let call_bytes = super::tx_builder::build_vote_call(&api, is_council, &proposal_hash, proposal_index, approve).await?;

    // Get nonce and build signing payload
    let nonce: u64 = client.request("system_accountNextIndex", rpc_params![signer_address.clone()]).await?;
    let genesis_hash_hex: String = client.request("chain_getBlockHash", rpc_params![0]).await?;
    let block_hash_hex: String = client.request("chain_getBlockHash", rpc_params![]).await?;
    let runtime_version: serde_json::Value = client.request("state_getRuntimeVersion", rpc_params![]).await?;
    let spec_version = runtime_version["specVersion"].as_u64().unwrap_or(0) as u32;
    let transaction_version = runtime_version["transactionVersion"].as_u64().unwrap_or(0) as u32;

    eprintln!("📝 Transaction details:");
    eprintln!("   Signer: {}", signer_address);
    eprintln!("   Nonce: {}", nonce);
    eprintln!();

    // Calculate era
    let period = era_period;
    let period_pow2 = period.next_power_of_two().clamp(4, 65536);
    let period_encoded = (period_pow2.trailing_zeros() - 1).clamp(1, 15) as u8;
    let quantize_factor = (period_pow2 >> 12).max(1);
    let phase = (block_number / quantize_factor) % (period_pow2 / quantize_factor);
    let phase_encoded = (phase as u16) << 4 | period_encoded as u16;
    let era_bytes = if phase_encoded < 256 {
        vec![phase_encoded as u8]
    } else {
        vec![(phase_encoded & 0xff) as u8, (phase_encoded >> 8) as u8]
    };
    let era_hex = format!("0x{}", hex::encode(&era_bytes));

    // Construct signing payload
    let mut payload = Vec::new();
    payload.extend_from_slice(&call_bytes);
    payload.extend_from_slice(&era_bytes);
    payload.extend_from_slice(&Compact(nonce).encode());
    payload.extend_from_slice(&Compact(0u128).encode()); // tip
    payload.extend_from_slice(&spec_version.to_le_bytes());
    payload.extend_from_slice(&transaction_version.to_le_bytes());
    let genesis_hash_bytes = hex::decode(genesis_hash_hex.trim_start_matches("0x"))?;
    payload.extend_from_slice(&genesis_hash_bytes);
    let block_hash_bytes = hex::decode(block_hash_hex.trim_start_matches("0x"))?;
    payload.extend_from_slice(&block_hash_bytes);

    let final_payload = if payload.len() > 256 {
        blake2_256(&payload).to_vec()
    } else {
        payload
    };

    let payload_hex = format!("0x{}", hex::encode(&final_payload));
    let method_hex = format!("0x{}", hex::encode(&call_bytes));

    // Save files
    let payload_file = output_dir.join(format!("{}.payload", filename));
    let metadata_file = output_dir.join(format!("{}.json", filename));

    fs::write(&payload_file, &payload_hex)?;
    eprintln!("✓ Payload: {}", payload_file.display());

    let metadata = json!({
        "step": filename,
        "signerAddress": signer_address,
        "nonce": nonce,
        "payload": payload_hex,
        "method": method_hex,
        "era": era_hex,
        "tip": 0,
        "specVersion": spec_version,
        "transactionVersion": transaction_version,
        "genesisHash": genesis_hash_hex,
        "blockHash": block_hash_hex,
        "proposalIndex": proposal_index,
        "proposalHash": proposal_hash,
        "approve": approve,
        "createdAt": chrono::Utc::now().to_rfc3339()
    });

    fs::write(&metadata_file, serde_json::to_string_pretty(&metadata)?)?;
    eprintln!("   Data: {}", metadata_file.display());

    eprintln!();
    eprintln!("📋 Next steps:");
    eprintln!("   1. Sign on airgapped computer:");
    eprintln!("      midnight-cli witness create-extrinsic \\");
    eprintln!("        --payload {} \\", payload_file.display());
    eprintln!("        --tx-metadata {} \\", metadata_file.display());
    eprintln!("        --mnemonic-file <mnemonic> \\");
    eprintln!("        --purpose governance \\");
    eprintln!("        --output {}/{}.extrinsic", output_dir.display(), filename);
    eprintln!("   2. Submit:");
    eprintln!("      midnight-cli tx submit --extrinsic {}/{}.extrinsic", output_dir.display(), filename);

    Ok(())
}

/// Query proposal hash from chain state
async fn query_proposal_hash(
    client: &jsonrpsee::ws_client::WsClient,
    is_council: bool,
    proposal_index: u32,
) -> Result<String> {
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::rpc_params;
    use parity_scale_codec::Decode;

    let pallet_name = if is_council { "Council" } else { "TechnicalCommittee" };

    // Query Proposals storage - it's a Vec<Hash>, not a map
    let storage_key = format!("0x{}{}",
        hex::encode(sp_core::hashing::twox_128(pallet_name.as_bytes())),
        hex::encode(sp_core::hashing::twox_128(b"Proposals"))
    );

    let data_hex: Option<String> = client
        .request("state_getStorage", rpc_params![storage_key])
        .await?;

    let data_hex = data_hex.ok_or_else(|| anyhow::anyhow!("No proposals found in {}", pallet_name))?;

    // Decode the Vec<Hash>
    let data = hex::decode(data_hex.trim_start_matches("0x"))?;
    let mut data_slice = &data[..];
    let proposals: Vec<[u8; 32]> = Vec::<[u8; 32]>::decode(&mut data_slice)
        .map_err(|e| anyhow::anyhow!("Failed to decode proposals vec: {}", e))?;

    if (proposal_index as usize) >= proposals.len() {
        anyhow::bail!("Proposal index {} out of range (only {} active proposals)", proposal_index, proposals.len());
    }

    let proposal_hash = proposals[proposal_index as usize];
    Ok(format!("0x{}", hex::encode(proposal_hash)))
}

async fn handle_close(args: CloseArgs) -> Result<()> {
    use jsonrpsee::ws_client::WsClientBuilder;
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::rpc_params;
    use parity_scale_codec::{Compact, Encode};
    use serde_json::json;
    use std::fs;
    use sp_core::hashing::blake2_256;

    // Extract fields from CloseBody variant
    let (is_council, proposal_index, proposal_hash_opt, proposal_length_opt, signer, endpoint, output_dir, era_period, state_file) = match &args.body {
        CloseBody::Council { proposal_index, proposal_hash, proposal_length, signer, endpoint, output_dir, era_period, state_file } => {
            (true, *proposal_index, proposal_hash.clone(), *proposal_length, signer.clone(), endpoint.clone(), output_dir.clone(), *era_period, state_file.clone())
        }
        CloseBody::Ta { proposal_index, proposal_hash, proposal_length, signer, endpoint, output_dir, era_period, state_file } => {
            (false, *proposal_index, proposal_hash.clone(), *proposal_length, signer.clone(), endpoint.clone(), output_dir.clone(), *era_period, state_file.clone())
        }
    };

    eprintln!("🔗 Connecting to {}", endpoint);

    // Connect with both RPC client (for queries) and subxt (for tx building)
    let api = subxt::OnlineClient::<subxt::SubstrateConfig>::from_url(&endpoint).await?;
    let client = WsClientBuilder::default()
        .build(&endpoint)
        .await?;

    let chain: String = client.request("system_chain", rpc_params![]).await?;
    let header: serde_json::Value = client.request("chain_getHeader", rpc_params![]).await?;
    let block_number = header["number"]
        .as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);

    eprintln!("✅ Connected to: {}", chain);
    eprintln!("📊 Current block: {}", block_number);
    eprintln!();

    fs::create_dir_all(&output_dir)?;

    let state_path = state_file.clone().unwrap_or_else(|| output_dir.join("state.json"));
    let mut state: serde_json::Value = if state_path.exists() {
        serde_json::from_str(&fs::read_to_string(&state_path)?)?
    } else {
        json!({})
    };

    // Query governance members
    eprintln!("👥 Querying governance members...");

    let council_storage_key = format!("0x{}{}",
        hex::encode(sp_core::hashing::twox_128(b"CouncilMembership")),
        hex::encode(sp_core::hashing::twox_128(b"Members"))
    );
    let council_data_hex: Option<String> = client
        .request("state_getStorage", rpc_params![council_storage_key])
        .await?;

    let ta_storage_key = format!("0x{}{}",
        hex::encode(sp_core::hashing::twox_128(b"TechnicalCommitteeMembership")),
        hex::encode(sp_core::hashing::twox_128(b"Members"))
    );
    let ta_data_hex: Option<String> = client
        .request("state_getStorage", rpc_params![ta_storage_key])
        .await?;

    // Extract all members
    let council_members = extract_all_members(council_data_hex, "Council")?;
    let ta_members = extract_all_members(ta_data_hex, "Technical Authority")?;

    eprintln!("   Council members: {}", council_members.len());
    eprintln!("   Technical Authority members: {}", ta_members.len());
    eprintln!();

    // Get proposal hash and length from args or state file
    let proposal_hash = proposal_hash_opt
        .or_else(|| state.get("proposalHash").and_then(|v| v.as_str()).map(String::from))
        .ok_or_else(|| anyhow::anyhow!("Missing proposal hash"))?;
    let proposal_length = proposal_length_opt.unwrap_or_else(||
        state.get("proposalLength").and_then(|v| v.as_u64()).unwrap_or(0) as u32
    );

    let (available_members, body_name, filename, state_key) = if is_council {
        (council_members, "Council", "council-close", "councilProposalIndex")
    } else {
        (ta_members, "Technical Authority", "ta-close", "taProposalIndex")
    };

    // Select or validate signer
    let signer_address = if let Some(provided_signer) = &signer {
        // Validate provided signer is a member
        if !available_members.contains(provided_signer) {
            eprintln!("❌ Error: Address {} is not a member of {}", provided_signer, body_name);
            eprintln!();
            eprintln!("Available {} members:", body_name);
            for (idx, member) in available_members.iter().enumerate() {
                eprintln!("  {}. {}", idx + 1, member);
            }
            eprintln!();
            eprintln!("Usage: --signer <ADDRESS>");
            anyhow::bail!("Invalid signer address");
        }
        provided_signer.clone()
    } else {
        // No signer provided - show available members and error
        eprintln!("❌ Error: No signer address specified");
        eprintln!();
        eprintln!("Available {} members:", body_name);
        for (idx, member) in available_members.iter().enumerate() {
            eprintln!("  {}. {}", idx + 1, member);
        }
        eprintln!();
        eprintln!("Please specify which member to sign as:");
        eprintln!("  --signer <ADDRESS>");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  --signer {}", available_members[0]);
        anyhow::bail!("Missing required --signer argument");
    };

    eprintln!("✓ Using signer: {}", signer_address);
    eprintln!();

    // Build the close call using subxt
    let call_bytes = super::tx_builder::build_close_call(
        &api,
        is_council,
        &proposal_hash,
        proposal_index,
        proposal_length,
    ).await?;

    state[state_key] = json!(proposal_index);

    // Get nonce and build signing payload
    let nonce: u64 = client
        .request("system_accountNextIndex", rpc_params![signer_address.clone()])
        .await?;

    let genesis_hash_hex: String = client.request("chain_getBlockHash", rpc_params![0]).await?;
    let block_hash_hex: String = client.request("chain_getBlockHash", rpc_params![]).await?;

    let runtime_version: serde_json::Value = client.request("state_getRuntimeVersion", rpc_params![]).await?;
    let spec_version = runtime_version["specVersion"].as_u64().unwrap_or(0) as u32;
    let transaction_version = runtime_version["transactionVersion"].as_u64().unwrap_or(0) as u32;

    eprintln!("📝 Closing proposal:");
    eprintln!("   Index: {}", proposal_index);
    eprintln!("   Signer: {}", signer_address);
    eprintln!("   Nonce: {}", nonce);
    eprintln!();

    // Calculate era
    let period = era_period;
    let period_pow2 = period.next_power_of_two().clamp(4, 65536);
    let period_encoded = (period_pow2.trailing_zeros() - 1).clamp(1, 15) as u8;
    let quantize_factor = (period_pow2 >> 12).max(1);
    let phase = (block_number / quantize_factor) % (period_pow2 / quantize_factor);
    let phase_encoded = (phase as u16) << 4 | period_encoded as u16;
    let era_bytes = if phase_encoded < 256 {
        vec![phase_encoded as u8]
    } else {
        vec![(phase_encoded & 0xff) as u8, (phase_encoded >> 8) as u8]
    };
    let era_hex = format!("0x{}", hex::encode(&era_bytes));

    // Construct signing payload
    let mut payload = Vec::new();
    payload.extend_from_slice(&call_bytes);
    payload.extend_from_slice(&era_bytes);
    payload.extend_from_slice(&Compact(nonce).encode());
    payload.extend_from_slice(&Compact(0u128).encode()); // tip
    payload.extend_from_slice(&spec_version.to_le_bytes());
    payload.extend_from_slice(&transaction_version.to_le_bytes());
    let genesis_hash_bytes = hex::decode(genesis_hash_hex.trim_start_matches("0x"))?;
    payload.extend_from_slice(&genesis_hash_bytes);
    let block_hash_bytes = hex::decode(block_hash_hex.trim_start_matches("0x"))?;
    payload.extend_from_slice(&block_hash_bytes);

    let final_payload = if payload.len() > 256 {
        blake2_256(&payload).to_vec()
    } else {
        payload
    };

    let payload_hex = format!("0x{}", hex::encode(&final_payload));
    let method_hex = format!("0x{}", hex::encode(&call_bytes));

    // Save files
    let payload_file = output_dir.join(format!("{}.payload", filename));
    let metadata_file = output_dir.join(format!("{}.json", filename));

    fs::write(&payload_file, &payload_hex)?;
    eprintln!("✓ Payload: {}", payload_file.display());

    let metadata = json!({
        "step": filename,
        "signerAddress": signer_address,
        "nonce": nonce,
        "payload": payload_hex,
        "method": method_hex,
        "era": era_hex,
        "tip": 0,
        "specVersion": spec_version,
        "transactionVersion": transaction_version,
        "genesisHash": genesis_hash_hex,
        "blockHash": block_hash_hex,
        "createdAt": chrono::Utc::now().to_rfc3339()
    });

    fs::write(&metadata_file, serde_json::to_string_pretty(&metadata)?)?;
    eprintln!("   Data: {}", metadata_file.display());

    fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;

    eprintln!();
    eprintln!("📋 Next steps:");
    eprintln!("   1. Sign and submit as before");

    Ok(())
}

async fn handle_submit(args: SubmitArgs) -> Result<()> {
    use jsonrpsee::ws_client::WsClientBuilder;
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::rpc_params;
    use std::fs;

    eprintln!("🔗 Connecting to {}", args.endpoint);

    let client = WsClientBuilder::default()
        .build(&args.endpoint)
        .await?;

    let chain: String = client.request("system_chain", rpc_params![]).await?;
    eprintln!("✅ Connected to: {}", chain);
    eprintln!();

    let extrinsic_hex = fs::read_to_string(&args.extrinsic)?.trim().to_string();

    eprintln!("📝 Submitting extrinsic...");
    eprintln!("   Hex: {}...", &extrinsic_hex[..extrinsic_hex.len().min(66)]);
    eprintln!("   Length: {} bytes", (extrinsic_hex.len() - 2) / 2);
    eprintln!();

    let tx_hash: String = client
        .request("author_submitExtrinsic", rpc_params![extrinsic_hex])
        .await?;

    eprintln!("✅ Submitted! Hash: {}", tx_hash);

    Ok(())
}
