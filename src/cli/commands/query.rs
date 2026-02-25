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
            println!("\nProposal #{}: {}", i, hash_hex);

            if verbose {
                // Query proposal call data
                let proposal_addr = subxt::dynamic::storage(
                    pallet,
                    "ProposalOf",
                    vec![Value::from_bytes(hash.as_bytes())]
                );

                if let Some(proposal_data) = api.storage().at_latest().await?.fetch(&proposal_addr).await? {
                    let proposal_bytes = proposal_data.encoded();
                    println!("  Proposal data: {} bytes", proposal_bytes.len());
                    println!("  Call: 0x{}", hex::encode(&proposal_bytes[..proposal_bytes.len().min(64)]));
                }

                // Query voting info
                let voting_addr = subxt::dynamic::storage(
                    pallet,
                    "Voting",
                    vec![Value::from_bytes(hash.as_bytes())]
                );

                if let Some(voting_data) = api.storage().at_latest().await?.fetch(&voting_addr).await? {
                    let voting_bytes = voting_data.encoded();

                    // Votes struct: { index: u32, threshold: u32, ayes: Vec<AccountId>, nays: Vec<AccountId>, end: BlockNumber }
                    if voting_bytes.len() >= 8 {
                        let index = u32::from_le_bytes([
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

                        println!("  Index: {}", index);
                        println!("  Threshold: {}", threshold);

                        // Decode ayes/nays vectors from the remaining bytes
                        if let Ok((ayes, nays)) = decode_vote_accounts(&voting_bytes[8..]) {
                            println!("  Ayes: {}", ayes);
                            println!("  Nays: {}", nays);
                        }
                    }
                }
            }
        }
    } else {
        println!("No active proposals");
    }

    Ok(())
}

// Helper to decode ayes and nays counts from voting data
fn decode_vote_accounts(data: &[u8]) -> Result<(usize, usize)> {
    use parity_scale_codec::{Compact, Decode};

    let mut cursor = &data[..];

    // Decode ayes count
    let ayes_count = <Compact<u32>>::decode(&mut cursor)?.0 as usize;

    // Skip ayes accounts (32 bytes each)
    if cursor.len() < ayes_count * 32 {
        anyhow::bail!("Not enough data for ayes accounts");
    }
    cursor = &cursor[ayes_count * 32..];

    // Decode nays count
    let nays_count = <Compact<u32>>::decode(&mut cursor)?.0 as usize;

    Ok((ayes_count, nays_count))
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
