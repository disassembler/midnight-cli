// UTxORPC client for querying Cardano chain data
//
// Compatible with any UTxORPC-compliant indexer (e.g., hayate, dolos, etc.)

use anyhow::{Context, Result};

// Include the generated proto code
pub mod proto {
    tonic::include_proto!("utxorpc.query.v1");
}

use proto::{query_service_client::QueryServiceClient, SearchUtxosRequest};

/// Query UTxORPC endpoint for the first UTxO containing a specific policy ID
/// Returns (block_hash, slot, block_timestamp, tx_index)
pub async fn query_policy_id_block(
    endpoint: &str,
    policy_id: &str,
) -> Result<(Vec<u8>, u64, u64, u32)> {
    // Remove 0x prefix if present
    let policy_id_hex = policy_id.trim_start_matches("0x");

    // Decode policy ID from hex
    let policy_id_bytes = hex::decode(policy_id_hex)
        .context("Failed to decode policy ID hex")?;

    // Connect to UTxORPC gRPC endpoint
    let mut client = QueryServiceClient::connect(endpoint.to_string())
        .await
        .context("Failed to connect to UTxORPC endpoint")?;

    // Search for UTxOs with this policy ID
    let request = tonic::Request::new(SearchUtxosRequest {
        pattern: policy_id_hex.to_string(),
    });

    let response = client
        .search_utxos(request)
        .await
        .context("Failed to query UTxORPC for policy ID")?;

    let utxos = response.into_inner().items;

    // Find the first UTxO with this policy ID
    for utxo in utxos {
        for asset in &utxo.assets {
            if asset.policy_id == policy_id_bytes {
                // Return the block information where this UTxO was created
                return Ok((
                    utxo.created_at_block_hash,
                    utxo.created_at_slot,
                    utxo.created_at_block_timestamp,
                    utxo.created_at_tx_index,
                ));
            }
        }
    }

    anyhow::bail!(
        "No UTxO found with policy ID {}. Policy may not exist on chain yet.",
        policy_id_hex
    );
}
