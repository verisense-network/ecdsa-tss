fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .out_dir("src/proto")
        .compile_protos(&["proto/signer.proto"], &["proto"])?;
    Ok(())
}
