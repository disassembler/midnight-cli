use subxt::{OnlineClient, SubstrateConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api = OnlineClient::<SubstrateConfig>::from_url("ws://localhost:9944").await?;

    let metadata = api.metadata();

    // Examine type 248
    if let Some(ty) = metadata.types().resolve(248) {
        println!("Type 248:");
        println!("{:#?}", ty);
    } else {
        println!("Could not resolve type 248");
    }

    Ok(())
}
