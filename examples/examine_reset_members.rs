use subxt::{OnlineClient, SubstrateConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api = OnlineClient::<SubstrateConfig>::from_url("ws://localhost:9944").await?;

    let metadata = api.metadata();

    // Find CouncilMembership pallet
    if let Some(pallet) = metadata.pallet_by_name("CouncilMembership") {
        println!("CouncilMembership pallet:");

        // Find reset_members call
        if let Some(call) = pallet.call_variant_by_name("reset_members") {
            println!("\nreset_members call:");
            println!("  Index: {}", call.index);
            println!("  Fields:");
            for field in &call.fields {
                println!("    - name: {:?}", field.name);
                println!("      type_id: {:?}", field.ty.id);

                // Resolve the type
                if let Some(ty) = metadata.types().resolve(field.ty.id) {
                    println!("      type: {:#?}", ty);
                }
            }
        }
    }

    Ok(())
}
