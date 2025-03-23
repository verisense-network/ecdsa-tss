# Rust Wrapper for tss-lib

This project is a Rust wrapper for [tss-lib](https://github.com/bnb-chain/tss-lib), aiming to provide functionalities for Threshold Signature Schemes (TSS). The tss-lib implements {t,n}-threshold ECDSA (Elliptic Curve Digital Signature Algorithm) based on the work by Gennaro and Goldfeder presented at CCS 2018, as well as similar methods for EdDSA (Edwards-curve Digital Signature Algorithm).

## Features

This library includes the following main protocols:

- **Key Generation**: Enables the creation of key shares without the need for a trusted third party.
- **Signing**: Allows the generation of digital signatures using key shares.
- **Dynamic Groups**: Facilitates the modification of participant groups while keeping the key unchanged.

These protocols allow multiple participants to collaboratively generate keys and signatures, enhancing the security and reliability of the system.

## Usage Example

Start ```bash run.sh``` to start grpc server.

### Key Generation

```rust
use ecdsa_tss::EcdsaTssSignerClient;
use ecdsa_tss::signer_rpc::BaseInfo;
use tokio::sync::mpsc;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let base_info = BaseInfo {
        id: 1,
        curve_id: 0,
        threshold: 2,
        ids: vec![1, 2, 3],
    };

    let client = EcdsaTssSignerClient::new(29197).await.unwrap();
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let (out_tx, out_rx) = mpsc::unbounded_channel();

    let key_package = client
        .dkg(base_info, in_rx, out_tx, Duration::from_secs(1000))
        .await
        .unwrap();

    println!("Key generation successful: {:?}", key_package);
}
```

### Signing

```rust
use ecdsa_tss::EcdsaTssSignerClient;
use ecdsa_tss::signer_rpc::{BaseInfo, SigningInfo, KeyPackage};
use tokio::sync::mpsc;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let base_info = BaseInfo {
        id: 1,
        curve_id: 0,
        threshold: 2,
        ids: vec![1, 2],
    };

    let key_package = KeyPackage {
        // Initialize your key package
    };

    let signing_info = SigningInfo {
        base_info: Some(base_info),
        key_package: Some(key_package),
        message: vec![15; 32], // Message to be signed
        derivation_delta: vec![1, 2, 3],
    };

    let client = EcdsaTssSignerClient::new(29197).await.unwrap();
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let (out_tx, out_rx) = mpsc::unbounded_channel();

    let signature = client
        .sign(signing_info, in_rx, out_tx, Duration::from_secs(1000))
        .await
        .unwrap();

    println!("Signing successful: {:?}", signature);
}
```


## License

This project is licensed under the Apache 2.0 License. For more details, please refer to the [LICENSE](./LICENSE) file.
