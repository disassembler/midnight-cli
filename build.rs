fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use proto files from hayate (linked via Nix flake)
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &["../hayate/proto/utxorpc/query.proto"],
            &["../hayate/proto"],
        )?;

    Ok(())
}
