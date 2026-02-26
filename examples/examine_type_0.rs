use subxt::{OnlineClient, SubstrateConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api = OnlineClient::<SubstrateConfig>::from_url("ws://localhost:9944").await?;

    let metadata = api.metadata();

    // Examine type 0 (AccountId)
    if let Some(ty) = metadata.types().resolve(0) {
        println!("Type 0 (AccountId):");
        println!("{:#?}", ty);
    } else {
        println!("Could not resolve type 0");
    }

    Ok(())
}
