use anyhow::Result;
use clap::{Args, Subcommand};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::params::ArrayParams;
use jsonrpsee::ws_client::WsClientBuilder;
use serde_json::Value;
use subxt::{OnlineClient, SubstrateConfig};

#[derive(Args)]
pub struct QueryArgs {
    #[command(subcommand)]
    pub command: QueryCommands,

    /// WebSocket endpoint of the Midnight node
    #[arg(long, default_value = "ws://localhost:9944")]
    pub endpoint: String,
}

#[derive(Subcommand)]
pub enum QueryCommands {
    /// Query recent extrinsics from recent blocks
    Extrinsics(ExtrinsicsArgs),
    /// Query pending governance proposals
    Proposals(ProposalsArgs),
    /// Query events from blocks
    Events(EventsArgs),
    /// Query governance members (council and TA)
    Members(MembersArgs),
    /// Inspect runtime metadata for pallet calls
    Metadata(MetadataArgs),
}

#[derive(Args)]
pub struct ExtrinsicsArgs {
    /// Number of recent blocks to check
    #[arg(long, default_value = "5")]
    pub blocks: u32,
}

#[derive(Args)]
pub struct ProposalsArgs {
    /// Show detailed proposal information
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Args)]
pub struct EventsArgs {
    /// Block number to query (default: last 5 blocks)
    #[arg(long)]
    pub block: Option<u32>,

    /// Start of block range (use with --to)
    #[arg(long)]
    pub from: Option<u32>,

    /// End of block range (use with --from)
    #[arg(long)]
    pub to: Option<u32>,

    /// Number of recent blocks to check (ignored if --block, --from, or --to is specified)
    #[arg(long, default_value = "5")]
    pub blocks: u32,

    /// Filter by event section (e.g., "council", "system")
    #[arg(long)]
    pub section: Option<String>,

    /// Filter by event method (e.g., "Proposed", "Executed")
    #[arg(long)]
    pub method: Option<String>,

    /// Show all events (default: governance and system only)
    #[arg(long)]
    pub all: bool,
}

#[derive(Args)]
pub struct MembersArgs {
    /// Show verbose output (include account IDs in hex)
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Args)]
pub struct MetadataArgs {
    /// Pallet name to inspect
    #[arg(long)]
    pub pallet: String,

    /// Call name to inspect (optional, shows all calls if not specified)
    #[arg(long)]
    pub call: Option<String>,
}

pub async fn handle_query_command(args: QueryArgs) -> Result<()> {
    match args.command {
        QueryCommands::Extrinsics(extrinsics_args) => {
            query_extrinsics(&args.endpoint, extrinsics_args).await
        }
        QueryCommands::Proposals(proposals_args) => {
            query_proposals(&args.endpoint, proposals_args).await
        }
        QueryCommands::Events(events_args) => {
            query_events(&args.endpoint, events_args).await
        }
        QueryCommands::Members(members_args) => {
            query_members(&args.endpoint, members_args).await
        }
        QueryCommands::Metadata(metadata_args) => {
            query_metadata(&args.endpoint, metadata_args).await
        }
    }
}

async fn query_extrinsics(endpoint: &str, args: ExtrinsicsArgs) -> Result<()> {
    eprintln!("🔗 Connecting to {}", endpoint);
    let client = WsClientBuilder::default().build(endpoint).await?;

    // Get current block number
    let latest_hash: String = client
        .request("chain_getBlockHash", ArrayParams::new())
        .await?;

    let header: Value = client
        .request("chain_getHeader", [latest_hash.clone()])
        .await?;

    let current_block = header["number"]
        .as_str()
        .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);

    eprintln!("📊 Current block: {}\n", current_block);
    println!("=== Last {} blocks extrinsics ===\n", args.blocks);

    // Query recent blocks
    for i in 0..args.blocks {
        let block_num = current_block.saturating_sub(i);

        let block_hash: String = client
            .request("chain_getBlockHash", [block_num])
            .await?;

        let block: Value = client
            .request("chain_getBlock", [block_hash])
            .await?;

        println!("Block {}:", block_num);

        if let Some(extrinsics) = block["block"]["extrinsics"].as_array() {
            for (idx, ext) in extrinsics.iter().enumerate() {
                if let Some(ext_str) = ext.as_str() {
                    // Decode the extrinsic to get basic info
                    let bytes = hex::decode(ext_str.trim_start_matches("0x"))?;
                    if bytes.len() >= 2 {
                        // First byte is version/signature info, second byte starts call
                        let is_signed = (bytes[0] & 0x80) != 0;
                        println!("  [{}] {} bytes ({})",
                            idx,
                            bytes.len(),
                            if is_signed { "signed" } else { "unsigned" }
                        );
                    }
                }
            }
        }
        println!();
    }

    Ok(())
}

async fn query_proposals(endpoint: &str, args: ProposalsArgs) -> Result<()> {
    eprintln!("🔗 Connecting to {}", endpoint);
    let api = OnlineClient::<SubstrateConfig>::from_url(endpoint).await?;

    println!("=== Council Proposals ===\n");
    query_collective_proposals(&api, "Council", args.verbose).await?;

    println!("\n=== Technical Authority Proposals ===\n");
    query_collective_proposals(&api, "TechnicalCommittee", args.verbose).await?;

    Ok(())
}

async fn query_members(endpoint: &str, args: MembersArgs) -> Result<()> {
    eprintln!("🔗 Connecting to {}", endpoint);
    let api = OnlineClient::<SubstrateConfig>::from_url(endpoint).await?;

    println!("=== Council Members ===\n");
    query_collective_members(&api, "Council", args.verbose).await?;

    println!("\n=== Technical Authority Members ===\n");
    query_collective_members(&api, "TechnicalCommittee", args.verbose).await?;

    Ok(())
}

async fn query_collective_members(
    api: &OnlineClient<SubstrateConfig>,
    pallet: &str,
    verbose: bool,
) -> Result<()> {
    use parity_scale_codec::Decode;
    use subxt::dynamic::Value;
    use sp_core::crypto::Ss58Codec;

    // Query the Members storage (Vec<AccountId32>)
    let members_addr = subxt::dynamic::storage(pallet, "Members", Vec::<Value>::new());
    let members_data = api.storage().at_latest().await?.fetch(&members_addr).await?;

    if let Some(data) = members_data {
        let bytes = data.encoded();

        // Decode Vec<AccountId32>
        let members: Vec<sp_core::crypto::AccountId32> = Vec::<sp_core::crypto::AccountId32>::decode(&mut &bytes[..])?;

        if members.is_empty() {
            println!("No members");
            return Ok(());
        }

        println!("Total members: {}\n", members.len());

        for (idx, member) in members.iter().enumerate() {
            let ss58_address = member.to_ss58check();
            println!("{}. {}", idx + 1, ss58_address);

            if verbose {
                let bytes: &[u8] = member.as_ref();
                println!("   Hex: 0x{}", hex::encode(bytes));
            }
        }
    } else {
        println!("No members (storage not found)");
    }

    Ok(())
}

async fn query_collective_proposals(
    api: &OnlineClient<SubstrateConfig>,
    pallet: &str,
    verbose: bool,
) -> Result<()> {
    use parity_scale_codec::Decode;
    use subxt::dynamic::Value;

    // Query the Proposals storage (Vec<Hash>)
    let proposals_addr = subxt::dynamic::storage(pallet, "Proposals", Vec::<Value>::new());
    let proposals_data = api.storage().at_latest().await?.fetch(&proposals_addr).await?;

    if let Some(data) = proposals_data {
        let bytes = data.encoded();

        // Decode Vec<H256>
        let proposal_hashes: Vec<sp_core::H256> = Vec::<sp_core::H256>::decode(&mut &bytes[..])?;

        if proposal_hashes.is_empty() {
            println!("No active proposals");
            return Ok(());
        }

        println!("Active proposals: {}", proposal_hashes.len());

        for (i, hash) in proposal_hashes.iter().enumerate() {
            let hash_hex = format!("0x{}", hex::encode(hash.as_bytes()));
            println!("\n📋 Proposal #{}", i);
            println!("   Hash: {}", hash_hex);

            // Query voting info (always, not just verbose)
            let voting_addr = subxt::dynamic::storage(
                pallet,
                "Voting",
                vec![Value::from_bytes(hash.as_bytes())]
            );

            if let Some(voting_data) = api.storage().at_latest().await?.fetch(&voting_addr).await? {
                let voting_bytes = voting_data.encoded();

                // Votes struct: { index: u32, threshold: u32, ayes: Vec<AccountId>, nays: Vec<AccountId>, end: BlockNumber }
                if voting_bytes.len() >= 8 {
                    let _index = u32::from_le_bytes([
                        voting_bytes[0],
                        voting_bytes[1],
                        voting_bytes[2],
                        voting_bytes[3],
                    ]);
                    let threshold = u32::from_le_bytes([
                        voting_bytes[4],
                        voting_bytes[5],
                        voting_bytes[6],
                        voting_bytes[7],
                    ]);

                    // Decode ayes/nays accounts
                    if let Ok((ayes_accounts, nays_accounts, end_block)) = decode_vote_details(&voting_bytes[8..]) {
                        let total_votes = ayes_accounts.len();
                        let status = if total_votes >= threshold as usize {
                            "✅ READY"
                        } else {
                            "⏳ PENDING"
                        };

                        println!("   Status: {} ({}/{} votes)", status, total_votes, threshold);
                        println!("   Expires: Block {}", end_block);

                        if !ayes_accounts.is_empty() {
                            println!("   👍 Approved by ({}):", ayes_accounts.len());
                            for (idx, account) in ayes_accounts.iter().enumerate() {
                                println!("      {}. {}", idx + 1, account);
                            }
                        }

                        if !nays_accounts.is_empty() {
                            println!("   👎 Rejected by ({}):", nays_accounts.len());
                            for (idx, account) in nays_accounts.iter().enumerate() {
                                println!("      {}. {}", idx + 1, account);
                            }
                        }
                    }
                }
            }

            if verbose {
                // Query proposal call data in verbose mode
                let proposal_addr = subxt::dynamic::storage(
                    pallet,
                    "ProposalOf",
                    vec![Value::from_bytes(hash.as_bytes())]
                );

                if let Some(proposal_data) = api.storage().at_latest().await?.fetch(&proposal_addr).await? {
                    let proposal_bytes = proposal_data.encoded();
                    println!("   Proposal data: {} bytes", proposal_bytes.len());
                    println!("   Call (hex): 0x{}", hex::encode(&proposal_bytes[..proposal_bytes.len().min(64)]));
                }
            }
        }
    } else {
        println!("No active proposals");
    }

    Ok(())
}

// Helper to decode full voting details including voter addresses
fn decode_vote_details(data: &[u8]) -> Result<(Vec<String>, Vec<String>, u32)> {
    use parity_scale_codec::{Compact, Decode};
    use sp_core::crypto::Ss58Codec;

    let mut cursor = data;

    // Decode ayes Vec<AccountId>
    let ayes_count = <Compact<u32>>::decode(&mut cursor)?.0 as usize;
    let mut ayes_accounts = Vec::new();

    for _ in 0..ayes_count {
        if cursor.len() < 32 {
            anyhow::bail!("Not enough data for ayes account");
        }
        let account_bytes: [u8; 32] = cursor[..32].try_into()?;
        let account = sp_core::sr25519::Public::from_raw(account_bytes);
        ayes_accounts.push(account.to_ss58check());
        cursor = &cursor[32..];
    }

    // Decode nays Vec<AccountId>
    let nays_count = <Compact<u32>>::decode(&mut cursor)?.0 as usize;
    let mut nays_accounts = Vec::new();

    for _ in 0..nays_count {
        if cursor.len() < 32 {
            anyhow::bail!("Not enough data for nays account");
        }
        let account_bytes: [u8; 32] = cursor[..32].try_into()?;
        let account = sp_core::sr25519::Public::from_raw(account_bytes);
        nays_accounts.push(account.to_ss58check());
        cursor = &cursor[32..];
    }

    // Decode end block number (u32)
    let end_block = u32::decode(&mut cursor)?;

    Ok((ayes_accounts, nays_accounts, end_block))
}

async fn query_events(endpoint: &str, args: EventsArgs) -> Result<()> {
    eprintln!("🔗 Connecting to {}", endpoint);

    // Use subxt to connect to the node
    let api = OnlineClient::<SubstrateConfig>::from_url(endpoint).await?;

    // Also keep a jsonrpsee client for block hash lookups
    let rpc_client = WsClientBuilder::default().build(endpoint).await?;
    
    // Determine which blocks to query
    let blocks_to_query = if let Some(block) = args.block {
        vec![block]
    } else if let (Some(from), Some(to)) = (args.from, args.to) {
        if from > to {
            anyhow::bail!("--from ({}) must be less than or equal to --to ({})", from, to);
        }
        (from..=to).collect()
    } else if args.from.is_some() || args.to.is_some() {
        anyhow::bail!("Both --from and --to must be specified together");
    } else {
        // Get current block and go backwards using RPC client
        let latest_hash: String = rpc_client
            .request("chain_getBlockHash", ArrayParams::new())
            .await?;

        let header: Value = rpc_client
            .request("chain_getHeader", [latest_hash])
            .await?;

        let current_block = header["number"]
            .as_str()
            .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);

        eprintln!("📊 Current block: {}\n", current_block);

        (0..args.blocks)
            .map(|i| current_block.saturating_sub(i))
            .collect()
    };

    println!("=== Events ===\n");

    for block_num in blocks_to_query {
        // Get block hash using RPC
        let block_hash_str: String = rpc_client
            .request("chain_getBlockHash", [block_num])
            .await?;

        // Parse hash to the type subxt expects
        let block_hash = sp_core::H256::from_slice(&hex::decode(block_hash_str.trim_start_matches("0x"))?);

        // Get block using subxt
        let block = api.blocks().at(block_hash).await?;

        // Get events for this block using subxt's event API
        let events = block.events().await?;

        let mut block_has_events = false;
        let mut block_events = Vec::new();

        // Iterate through all events
        for event in events.iter() {
            let event = event?;
            let pallet_name = event.pallet_name();
            let variant_name = event.variant_name();

            // Apply filters
            let should_include = if args.all {
                true
            } else {
                // Default: only show governance and system events
                matches!(
                    pallet_name,
                    "Council" | "TechnicalCommittee" | "System" | "Democracy" | "Treasury"
                )
            };

            let should_include = should_include
                && args.section.as_ref().map_or(true, |s| pallet_name.eq_ignore_ascii_case(s))
                && args.method.as_ref().map_or(true, |m| variant_name.eq_ignore_ascii_case(m));

            if should_include {
                block_has_events = true;

                // Get event field values for detailed display
                let field_values = match event.field_values() {
                    Ok(values) => format!("{:?}", values),
                    Err(_) => "Unable to decode fields".to_string(),
                };

                block_events.push((
                    pallet_name.to_string(),
                    variant_name.to_string(),
                    field_values
                ));
            }
        }

        if block_has_events {
            println!("Block {}:", block_num);
            for (pallet, variant, data) in block_events {
                println!("  [{}.{}]", pallet, variant);
                // Only show data if it's not empty or just "()"
                if !data.is_empty() && data != "()" && data != "Composite(())" {
                    println!("    Data: {}", data);
                }
            }
            println!();
        }
    }

    Ok(())
}

async fn query_metadata(endpoint: &str, args: MetadataArgs) -> Result<()> {
    eprintln!("🔗 Connecting to {}", endpoint);
    let api = OnlineClient::<SubstrateConfig>::from_url(endpoint).await?;
    let metadata = api.metadata();

    eprintln!("✅ Connected\n");

    // Find the pallet
    let pallet = metadata
        .pallet_by_name(&args.pallet)
        .ok_or_else(|| anyhow::anyhow!("Pallet '{}' not found", args.pallet))?;

    println!("=== Pallet: {} ===", args.pallet);
    println!("Index: {}", pallet.index());
    println!();

    // Get call type
    let call_ty_id = pallet
        .call_ty_id()
        .ok_or_else(|| anyhow::anyhow!("Pallet {} has no calls", args.pallet))?;

    let call_type = metadata
        .types()
        .resolve(call_ty_id)
        .ok_or_else(|| anyhow::anyhow!("Call type not found"))?;

    if let scale_info::TypeDef::Variant(v) = &call_type.type_def {
        let variants_to_show: Vec<_> = if let Some(call_name) = &args.call {
            v.variants
                .iter()
                .filter(|var| var.name == *call_name)
                .collect()
        } else {
            v.variants.iter().collect()
        };

        if variants_to_show.is_empty() {
            anyhow::bail!("Call '{}' not found in pallet '{}'", args.call.as_ref().unwrap(), args.pallet);
        }

        for variant in variants_to_show {
            println!("Call: {}", variant.name);
            println!("  Index: {}", variant.index);

            if variant.fields.is_empty() {
                println!("  Fields: (none)");
            } else {
                println!("  Fields:");
                for field in &variant.fields {
                    let field_name = field
                        .name
                        .as_ref()
                        .map(|s| s.as_str())
                        .unwrap_or("(unnamed)");

                    println!("    - {}: type_id={}", field_name, field.ty.id);

                    // Resolve the type to show more details
                    if let Some(resolved_type) = metadata.types().resolve(field.ty.id) {
                        if !resolved_type.path.segments.is_empty() {
                            println!("      path: {}", resolved_type.path.segments.join("::"));
                        }

                        match &resolved_type.type_def {
                            scale_info::TypeDef::Composite(c) => {
                                println!("      kind: Composite");
                                if !c.fields.is_empty() {
                                    println!("      composite fields:");
                                    for comp_field in &c.fields {
                                        let comp_name = comp_field
                                            .name
                                            .as_ref()
                                            .map(|s| s.as_str())
                                            .unwrap_or("(unnamed)");
                                        println!("        * {}: type_id={}", comp_name, comp_field.ty.id);
                                    }
                                }
                            }
                            scale_info::TypeDef::Variant(v) => {
                                println!("      kind: Variant ({} variants)", v.variants.len());
                            }
                            scale_info::TypeDef::Sequence(s) => {
                                println!("      kind: Sequence<type_id={}>", s.type_param.id);
                            }
                            scale_info::TypeDef::Array(a) => {
                                println!("      kind: Array<type_id={}, len={}>", a.type_param.id, a.len);
                            }
                            scale_info::TypeDef::Tuple(t) => {
                                println!("      kind: Tuple with {} fields", t.fields.len());
                            }
                            scale_info::TypeDef::Primitive(p) => {
                                println!("      kind: Primitive({:?})", p);
                            }
                            scale_info::TypeDef::Compact(c) => {
                                println!("      kind: Compact<type_id={}>", c.type_param.id);
                            }
                            scale_info::TypeDef::BitSequence(_) => {
                                println!("      kind: BitSequence");
                            }
                        }
                    }
                }
            }
            println!();
        }
    } else {
        anyhow::bail!("Call type is not a variant");
    }

    Ok(())
}
