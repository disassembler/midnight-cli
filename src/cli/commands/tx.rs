use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum TxCommands {
    /// Propose a governance action
    Propose(ProposeArgs),
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
        address: String
    },
    /// Remove an existing member
    RemoveMember {
        /// Member address (SS58 format)
        address: String
    },
    /// Swap one member for another
    SwapMember {
        /// Old member address
        old_address: String,
        /// New member address
        new_address: String,
    },
    /// Reset the entire membership set
    ResetMembers {
        /// New member addresses
        addresses: Vec<String>
    },
    /// Change a member's key
    ChangeKey {
        /// Old member address
        old_address: String,
        /// New member address
        new_address: String,
    },
    /// Set the prime member (tie-breaker for votes)
    SetPrime {
        /// Prime member address
        address: String
    },
    /// Clear the prime member
    ClearPrime,
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
        message: String
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
    },
    /// Set new runtime code directly
    SetCode {
        /// WASM runtime code (hex-encoded)
        wasm_hex: String,
    },
}

#[derive(Args)]
pub struct CloseArgs {
    /// Governance body
    #[command(subcommand)]
    pub body: CloseBody,

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
        TxCommands::Close(args) => handle_close(args).await,
        TxCommands::Submit(args) => handle_submit(args).await,
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

    eprintln!("🔗 Connecting to {}", args.endpoint);

    // Connect with both RPC client (for queries) and subxt (for tx building)
    let api = subxt::OnlineClient::<subxt::SubstrateConfig>::from_url(&args.endpoint).await?;
    let client = WsClientBuilder::default()
        .build(&args.endpoint)
        .await?;

    let chain: String = client.request("system_chain", rpc_params![]).await?;
    let header: serde_json::Value = client.request("chain_getHeader", rpc_params![]).await?;
    let block_number = header["number"]
        .as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);

    eprintln!("✅ Connected to: {}", chain);
    eprintln!("📊 Current block: {}", block_number);
    eprintln!("");

    fs::create_dir_all(&args.output_dir)?;

    let state_path = args.state_file.clone().unwrap_or_else(|| args.output_dir.join("state.json"));
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

    let council_member = if let Some(data_hex) = council_data_hex {
        let data = hex::decode(data_hex.trim_start_matches("0x"))?;
        if data.len() >= 33 {
            let account_id = &data[1..33];
            let pubkey = sp_core::sr25519::Public::from_raw(account_id.try_into()?);
            use sp_core::crypto::Ss58Codec;
            pubkey.to_ss58check()
        } else {
            anyhow::bail!("No council members found");
        }
    } else {
        anyhow::bail!("Council membership not found in storage");
    };

    let ta_member = if let Some(data_hex) = ta_data_hex {
        let data = hex::decode(data_hex.trim_start_matches("0x"))?;
        if data.len() >= 33 {
            let account_id = &data[1..33];
            let pubkey = sp_core::sr25519::Public::from_raw(account_id.try_into()?);
            use sp_core::crypto::Ss58Codec;
            pubkey.to_ss58check()
        } else {
            anyhow::bail!("No TA members found");
        }
    } else {
        anyhow::bail!("TA membership not found in storage");
    };

    eprintln!("   Council: {}", council_member);
    eprintln!("   Technical Authority: {}", ta_member);
    eprintln!("");

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
    eprintln!("");

    // Save proposal to state
    state["proposalCall"] = json!(proposal_hex);
    state["proposalHash"] = json!(proposal_hash_hex);
    state["proposalLength"] = json!(proposal_length);

    // Determine which body is proposing and build the outer call
    let (is_council, filename) = match &args.proposal {
        ProposalType::Membership(m) => match &m.body {
            MembershipBody::Council(_) => (true, "council-propose-membership"),
            MembershipBody::Ta(_) => (false, "ta-propose-membership"),
        },
        ProposalType::System(s) => match &s.body {
            SystemBody::Council(_) => (true, "council-propose-system"),
            SystemBody::Ta(_) => (false, "ta-propose-system"),
        },
        ProposalType::Runtime(r) => match &r.body {
            RuntimeBody::Council(_) => (true, "council-propose-runtime"),
            RuntimeBody::Ta(_) => (false, "ta-propose-runtime"),
        },
    };

    let signer_address = if is_council {
        council_member
    } else {
        ta_member
    };

    let threshold = 1u32; // TODO: Calculate actual threshold

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
    eprintln!("");

    // Calculate era
    let period = args.era_period;
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
    let payload_file = args.output_dir.join(format!("{}.payload", filename));
    let metadata_file = args.output_dir.join(format!("{}.json", filename));

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

    eprintln!("");
    eprintln!("📋 Next steps:");
    eprintln!("   1. Sign on airgapped computer:");
    eprintln!("      midnight-cli witness create-extrinsic \\");
    eprintln!("        --payload {} \\", payload_file.display());
    eprintln!("        --tx-metadata {} \\", metadata_file.display());
    eprintln!("        --mnemonic-file <mnemonic> \\");
    eprintln!("        --purpose governance \\");
    eprintln!("        --output {}/{}.extrinsic", args.output_dir.display(), filename);
    eprintln!("   2. Submit:");
    eprintln!("      midnight-cli tx submit --extrinsic {}/{}.extrinsic", args.output_dir.display(), filename);

    Ok(())
}

async fn handle_close(args: CloseArgs) -> Result<()> {
    use jsonrpsee::ws_client::WsClientBuilder;
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::rpc_params;
    use parity_scale_codec::{Compact, Encode};
    use serde_json::json;
    use std::fs;
    use sp_core::hashing::blake2_256;

    eprintln!("🔗 Connecting to {}", args.endpoint);

    // Connect with both RPC client (for queries) and subxt (for tx building)
    let api = subxt::OnlineClient::<subxt::SubstrateConfig>::from_url(&args.endpoint).await?;
    let client = WsClientBuilder::default()
        .build(&args.endpoint)
        .await?;

    let chain: String = client.request("system_chain", rpc_params![]).await?;
    let header: serde_json::Value = client.request("chain_getHeader", rpc_params![]).await?;
    let block_number = header["number"]
        .as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);

    eprintln!("✅ Connected to: {}", chain);
    eprintln!("📊 Current block: {}", block_number);
    eprintln!("");

    fs::create_dir_all(&args.output_dir)?;

    let state_path = args.state_file.clone().unwrap_or_else(|| args.output_dir.join("state.json"));
    let mut state: serde_json::Value = if state_path.exists() {
        serde_json::from_str(&fs::read_to_string(&state_path)?)?
    } else {
        json!({})
    };

    // Query governance members
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

    let council_member = if let Some(data_hex) = council_data_hex {
        let data = hex::decode(data_hex.trim_start_matches("0x"))?;
        if data.len() >= 33 {
            let account_id = &data[1..33];
            let pubkey = sp_core::sr25519::Public::from_raw(account_id.try_into()?);
            use sp_core::crypto::Ss58Codec;
            pubkey.to_ss58check()
        } else {
            anyhow::bail!("No council members found");
        }
    } else {
        anyhow::bail!("Council membership not found");
    };

    let ta_member = if let Some(data_hex) = ta_data_hex {
        let data = hex::decode(data_hex.trim_start_matches("0x"))?;
        if data.len() >= 33 {
            let account_id = &data[1..33];
            let pubkey = sp_core::sr25519::Public::from_raw(account_id.try_into()?);
            use sp_core::crypto::Ss58Codec;
            pubkey.to_ss58check()
        } else {
            anyhow::bail!("No TA members found");
        }
    } else {
        anyhow::bail!("TA membership not found");
    };

    let (is_council, proposal_index, proposal_hash, proposal_length, signer_address, filename, state_key) = match &args.body {
        CloseBody::Council { proposal_index, proposal_hash, proposal_length } => {
            let hash = proposal_hash.clone()
                .or_else(|| state.get("proposalHash").and_then(|v| v.as_str()).map(String::from))
                .ok_or_else(|| anyhow::anyhow!("Missing proposal hash"))?;
            let length = proposal_length.unwrap_or_else(||
                state.get("proposalLength").and_then(|v| v.as_u64()).unwrap_or(0) as u32
            );
            (true, *proposal_index, hash, length, council_member, "council-close", "councilProposalIndex")
        }
        CloseBody::Ta { proposal_index, proposal_hash, proposal_length } => {
            let hash = proposal_hash.clone()
                .or_else(|| state.get("proposalHash").and_then(|v| v.as_str()).map(String::from))
                .ok_or_else(|| anyhow::anyhow!("Missing proposal hash"))?;
            let length = proposal_length.unwrap_or_else(||
                state.get("proposalLength").and_then(|v| v.as_u64()).unwrap_or(0) as u32
            );
            (false, *proposal_index, hash, length, ta_member, "ta-close", "taProposalIndex")
        }
    };

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
    eprintln!("");

    // Calculate era
    let period = args.era_period;
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
    let payload_file = args.output_dir.join(format!("{}.payload", filename));
    let metadata_file = args.output_dir.join(format!("{}.json", filename));

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

    eprintln!("");
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
    eprintln!("");

    let extrinsic_hex = fs::read_to_string(&args.extrinsic)?.trim().to_string();

    eprintln!("📝 Submitting extrinsic...");
    eprintln!("   Hex: {}...", &extrinsic_hex[..extrinsic_hex.len().min(66)]);
    eprintln!("   Length: {} bytes", (extrinsic_hex.len() - 2) / 2);
    eprintln!("");

    let tx_hash: String = client
        .request("author_submitExtrinsic", rpc_params![extrinsic_hex])
        .await?;

    eprintln!("✅ Submitted! Hash: {}", tx_hash);

    Ok(())
}
