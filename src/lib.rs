#[path = "proto/signer.rs"]
pub mod signer_rpc;
use std::time;

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::transport::Channel;

use signer_rpc::{DkgRequest, SignRequest, signer_service_client::SignerServiceClient};
pub struct EcdsaTssSignerClient {
    client: SignerServiceClient<Channel>,
}

#[derive(Debug, thiserror::Error)]
pub enum EcdsaTssSignerClientError {
    #[error("Tonic error: {0}")]
    TonicError(#[from] tonic::Status),

    #[error("Transport error: {0}")]
    TransportError(#[from] tonic::transport::Error),

    #[error("Invalid URI: {0}")]
    InvalidUri(#[from] http::uri::InvalidUri),

    #[error("DKG Failed: {0}")]
    DkgFailed(String),

    #[error("Sign Failed: {0}")]
    SignFailed(String),

    #[error("Recv error: {0}")]
    RecvError(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("Send error: {0}")]
    SendError(#[from] tokio::sync::mpsc::error::SendError<signer_rpc::SignerToCoordinatorMsg>),

    #[error("Init error: {0}")]
    InitError(String),
}
impl EcdsaTssSignerClient {
    pub async fn new(port: u16) -> Result<Self, EcdsaTssSignerClientError> {
        let url = format!("http://localhost:{}", port);
        let channel = Channel::from_shared(url)?.connect().await?;
        Ok(Self {
            client: SignerServiceClient::new(channel),
        })
    }
    pub async fn dkg(
        mut self,
        base_info: signer_rpc::BaseInfo,
        mut in_chan: UnboundedReceiver<signer_rpc::CoordinatorToSignerMsg>,
        out_chan: UnboundedSender<signer_rpc::SignerToCoordinatorMsg>,
        timeout: time::Duration,
    ) -> Result<signer_rpc::KeyPackage, EcdsaTssSignerClientError> {
        let request = DkgRequest {
            req_type: "init".into(),
            base_info: Some(base_info),
            coordinator_to_signer_msg: None,
        };
        let (stream_sender, stream_receiver) = tokio::sync::mpsc::unbounded_channel();
        let request_stream = UnboundedReceiverStream::new(stream_receiver);
        let (result_sender, result_receiver) = tokio::sync::oneshot::channel();
        let mut stream = self.client.dkg(request_stream).await?.into_inner();
        stream_sender
            .send(request)
            .map_err(|e| EcdsaTssSignerClientError::InitError(e.to_string()))?;
        let handler = tokio::spawn(async move {
            let sleep = tokio::time::sleep(timeout);
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    _ = &mut sleep => {
                        let _ = result_sender.send(Err(EcdsaTssSignerClientError::DkgFailed("DKG process timeout".into())));
                        return;
                    }
                    Ok(Some(response)) = stream.message() => {
                    match response.resp_type.as_str() {
                        // the first response from coordinator to signer must be empty, since go-grpc will not send header for connection and tonic client will be blocked
                        // see the issue in https://github.com/hyperium/tonic/issues/515
                        "empty" => {
                            continue;
                        }
                        "intermediate" => {
                            if let Some(msg) = response.signer_to_coordinator_msg {
                                if let Err(e) = out_chan.send(msg) {
                                    result_sender
                                        .send(Err(EcdsaTssSignerClientError::SendError(e)))
                                        .unwrap();
                                    return;
                                }
                            } else {
                                result_sender
                                    .send(Err(EcdsaTssSignerClientError::DkgFailed(
                                        "No signer to coordinator message in intermediate response"
                                            .into(),
                                    )))
                                    .unwrap();
                                return;
                            }
                        }
                        "final" => {
                            if let Some(key_package) = response.key_package {
                                result_sender.send(Ok(key_package)).unwrap();
                                return;
                            } else {
                                result_sender
                                    .send(Err(EcdsaTssSignerClientError::DkgFailed(
                                        "No key package in final response".into(),
                                    )))
                                    .unwrap();
                                return;
                            }
                        }
                        "error" => {
                            result_sender
                                .send(Err(EcdsaTssSignerClientError::DkgFailed(response.error)))
                                .unwrap();
                            return;
                        }
                        other => {
                            result_sender
                                .send(Err(EcdsaTssSignerClientError::DkgFailed(format!(
                                    "Unexpected response type: {}",
                                    other
                                ))))
                                .unwrap();
                            return;
                            }
                        }
                    }
                    input = in_chan.recv() => {
                        match input {
                            Some(msg) => {
                                let wrapped_request = DkgRequest {
                                    req_type: "intermediate".into(),
                                    base_info: None,
                                    coordinator_to_signer_msg: Some(msg),
                                };
                                if let Err(e) = stream_sender.send(wrapped_request){
                                    tracing::warn!("Failed to send intermediate request: {}", e);
                                }
                            }
                            None => {
                                continue;
                            }
                        }
                    }

                }
            }
        });
        let result = result_receiver.await?;
        handler.abort();
        result
    }
    // return public key and derived public key
    pub async fn derive_pk_from_pk(
        mut self,
        curve_id: u32,
        public_key: Vec<u8>,
        derivation_delta: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), EcdsaTssSignerClientError> {
        let request = signer_rpc::PkRequest {
            curve_id,
            source: Some(signer_rpc::pk_request::Source::PublicKey(public_key)),
            derivation_delta,
        };
        let response = self.client.pk(request).await?.into_inner();
        Ok((response.public_key, response.public_key_derived))
    }
    pub async fn derive_pk_from_key_package(
        mut self,
        curve_id: u32,
        key_package: signer_rpc::KeyPackage,
        derivation_delta: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), EcdsaTssSignerClientError> {
        let request = signer_rpc::PkRequest {
            curve_id,
            source: Some(signer_rpc::pk_request::Source::KeyPackage(key_package)),
            derivation_delta,
        };
        let response = self.client.pk(request).await?.into_inner();
        Ok((response.public_key, response.public_key_derived))
    }
    pub async fn sign(
        mut self,
        signing_info: signer_rpc::SigningInfo,
        mut in_chan: UnboundedReceiver<signer_rpc::CoordinatorToSignerMsg>,
        out_chan: UnboundedSender<signer_rpc::SignerToCoordinatorMsg>,
        timeout: time::Duration,
    ) -> Result<signer_rpc::Signature, EcdsaTssSignerClientError> {
        let request = SignRequest {
            req_type: "init".into(),
            signing_info: Some(signing_info),
            coordinator_to_signer_msg: None,
        };
        let (stream_sender, stream_receiver) = tokio::sync::mpsc::unbounded_channel();
        let request_stream = UnboundedReceiverStream::new(stream_receiver);
        let (result_sender, result_receiver) = tokio::sync::oneshot::channel();
        let mut stream = self.client.sign(request_stream).await?.into_inner();
        stream_sender
            .send(request)
            .map_err(|e| EcdsaTssSignerClientError::InitError(e.to_string()))?;
        let handler = tokio::spawn(async move {
            let sleep = tokio::time::sleep(timeout);
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    _ = &mut sleep => {
                        let _ = result_sender.send(Err(EcdsaTssSignerClientError::SignFailed("Sign process timeout".into())));
                        return;
                    }
                    Ok(Some(response)) = stream.message() => {
                    match response.resp_type.as_str() {
                        // the first response from coordinator to signer must be empty, since go-grpc will not send header for connection and tonic client will be blocked
                        // see the issue in https://github.com/hyperium/tonic/issues/515
                        "empty" => {
                            continue;
                        }
                        "intermediate" => {
                            if let Some(msg) = response.signer_to_coordinator_msg {
                                if let Err(e) = out_chan.send(msg) {
                                    result_sender
                                        .send(Err(EcdsaTssSignerClientError::SendError(e)))
                                        .unwrap();
                                    return;
                                }
                            } else {
                                result_sender
                                    .send(Err(EcdsaTssSignerClientError::DkgFailed(
                                        "No signer to coordinator message in intermediate response"
                                            .into(),
                                    )))
                                    .unwrap();
                                return;
                            }
                        }
                        "final" => {
                            if let Some(signature) = response.signature {
                                result_sender.send(Ok(signature)).unwrap();
                                return;
                            } else {
                                result_sender
                                    .send(Err(EcdsaTssSignerClientError::DkgFailed(
                                        "No signature in final response".into(),
                                    )))
                                    .unwrap();
                                return;
                            }
                        }
                        "error" => {
                            result_sender
                                .send(Err(EcdsaTssSignerClientError::SignFailed(response.error)))
                                .unwrap();
                            return;
                        }
                        other => {
                            result_sender
                                .send(Err(EcdsaTssSignerClientError::DkgFailed(format!(
                                    "Unexpected response type: {}",
                                    other
                                ))))
                                .unwrap();
                            return;
                            }
                        }
                    }
                    input = in_chan.recv() => {
                        match input {
                            Some(msg) => {
                                let wrapped_request = SignRequest {
                                    req_type: "intermediate".into(),
                                    signing_info: None,
                                    coordinator_to_signer_msg: Some(msg),
                                };
                                if let Err(e) = stream_sender.send(wrapped_request){
                                    tracing::warn!("Failed to send intermediate request: {}", e);
                                }
                            }
                            None => {
                                continue;
                            }
                        }
                    }

                }
            }
        });
        let result = result_receiver.await?;
        handler.abort();
        result
    }
}
#[cfg(test)]
mod test {
    use std::time;

    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

    use crate::{EcdsaTssSignerClient, EcdsaTssSignerClientError, signer_rpc};
    async fn dkg_single_node(
        port: u16,
        id: u32,
        curve_id: u32,
        threshold: u32,
        ids: Vec<u32>,
    ) -> Result<
        (
            UnboundedSender<signer_rpc::CoordinatorToSignerMsg>,
            UnboundedReceiver<signer_rpc::SignerToCoordinatorMsg>,
            tokio::sync::oneshot::Receiver<
                Result<signer_rpc::KeyPackage, EcdsaTssSignerClientError>,
            >,
        ),
        EcdsaTssSignerClientError,
    > {
        let base_info = signer_rpc::BaseInfo {
            id,
            curve_id,
            threshold,
            ids,
        };
        let client = EcdsaTssSignerClient::new(port).await?;
        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
        let (result_sender, result_receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = client
                .dkg(base_info, in_rx, out_tx, time::Duration::from_secs(1000))
                .await;
            result_sender.send(result).unwrap();
        });
        Ok((in_tx, out_rx, result_receiver))
    }
    async fn sign_single_node(
        port: u16,
        id: u32,
        curve_id: u32,
        threshold: u32,
        ids: Vec<u32>,
        message: Vec<u8>,
        key_package: signer_rpc::KeyPackage,
        derivation_delta: Vec<u8>,
    ) -> Result<
        (
            UnboundedSender<signer_rpc::CoordinatorToSignerMsg>,
            UnboundedReceiver<signer_rpc::SignerToCoordinatorMsg>,
            tokio::sync::oneshot::Receiver<
                Result<signer_rpc::Signature, EcdsaTssSignerClientError>,
            >,
        ),
        EcdsaTssSignerClientError,
    > {
        let signing_info = signer_rpc::SigningInfo {
            base_info: Some(signer_rpc::BaseInfo {
                id,
                curve_id,
                threshold,
                ids,
            }),
            key_package: Some(key_package),
            message,
            derivation_delta,
        };
        let client = EcdsaTssSignerClient::new(port).await?;
        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
        let (result_sender, result_receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = client
                .sign(signing_info, in_rx, out_tx, time::Duration::from_secs(1000))
                .await;
            result_sender.send(result).unwrap();
        });
        Ok((in_tx, out_rx, result_receiver))
    }
    async fn test_signer_service_client() {
        let (in1_tx, mut out1_rx, result1_receiver) =
            dkg_single_node(29197, 1, 0, 2, vec![1, 2, 3])
                .await
                .unwrap();
        let (in2_tx, mut out2_rx, result2_receiver) =
            dkg_single_node(29198, 2, 0, 2, vec![1, 2, 3])
                .await
                .unwrap();
        let (in3_tx, mut out3_rx, result3_receiver) =
            dkg_single_node(29199, 3, 0, 2, vec![1, 2, 3])
                .await
                .unwrap();
        // Clone the "in" channels for use in the coordinator task.
        let in1_tx_coord = in1_tx.clone();
        let in2_tx_coord = in2_tx.clone();
        let in3_tx_coord = in3_tx.clone();

        // Coordinator task: continuously listen on the three out channels and forward
        // messages to the corresponding in channels based on their content.
        let coordinator = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Listen for messages from signer 1.
                    Some(msg) = out1_rx.recv() => {
                        let from = 1;
                        let coord_msg = signer_rpc::CoordinatorToSignerMsg {
                            msg: msg.msg,
                            is_broadcast: msg.is_broadcast,
                            from,
                        };
                        if msg.is_broadcast {
                            // For broadcast messages, forward to all other clients.
                            let _ = in2_tx_coord.send(coord_msg.clone());
                            let _ = in3_tx_coord.send(coord_msg);
                        } else {
                            // For direct messages, forward based on msg.to.
                            match msg.to {
                                2 => { let _ = in2_tx_coord.send(coord_msg); },
                                3 => { let _ = in3_tx_coord.send(coord_msg); },
                                _ => {
                                    tracing::warn!("Signer1 sent a non-broadcast message with an unknown target: {}", msg.to);
                                }
                            }
                        }
                    },
                    // Listen for messages from signer 2.
                    Some(msg) = out2_rx.recv() => {
                        let from = 2;
                        let coord_msg = signer_rpc::CoordinatorToSignerMsg {
                            msg: msg.msg,
                            is_broadcast: msg.is_broadcast,
                            from,
                        };
                        if msg.is_broadcast {
                            let _ = in1_tx_coord.send(coord_msg.clone());
                            let _ = in3_tx_coord.send(coord_msg);
                        } else {
                            match msg.to {
                                1 => { let _ = in1_tx_coord.send(coord_msg); },
                                3 => { let _ = in3_tx_coord.send(coord_msg); },
                                _ => {
                                    tracing::warn!("Signer2 sent a non-broadcast message with an unknown target: {}", msg.to);
                                }
                            }
                        }
                    },
                    // Listen for messages from signer 3.
                    Some(msg) = out3_rx.recv() => {
                        let from = 3;
                        let coord_msg = signer_rpc::CoordinatorToSignerMsg {
                            msg: msg.msg,
                            is_broadcast: msg.is_broadcast,
                            from,
                        };
                        if msg.is_broadcast {
                            let _ = in1_tx_coord.send(coord_msg.clone());
                            let _ = in2_tx_coord.send(coord_msg);
                        } else {
                            match msg.to {
                                1 => { let _ = in1_tx_coord.send(coord_msg); },
                                2 => { let _ = in2_tx_coord.send(coord_msg); },
                                _ => {
                                    tracing::warn!("Signer3 sent a non-broadcast message with an unknown target: {}", msg.to);
                                }
                            }
                        }
                    },
                    else => {
                        // Exit the loop if all out channels are closed.
                        break;
                    }
                }
            }
        });

        // Wait for all three DKG tasks to complete their oneshot results.
        let (res1, res2, res3) = tokio::join!(result1_receiver, result2_receiver, result3_receiver);

        // After all results are received, abort the coordinator task.
        coordinator.abort();
        let res1 = res1.unwrap();
        let res2 = res2.unwrap();
        let res3 = res3.unwrap();

        assert!(res1.is_ok(), "Signer1 DKG failed: {:?}", res1);
        assert!(res2.is_ok(), "Signer2 DKG failed: {:?}", res2);
        assert!(res3.is_ok(), "Signer3 DKG failed: {:?}", res3);
        let res1 = res1.unwrap();
        let res2 = res2.unwrap();
        let res3 = res3.unwrap();
        let res1_copy = res1.clone();
        assert!(
            res1.public_key == res2.public_key,
            "Signer1 and Signer2 public key mismatch"
        );
        assert!(
            res1.public_key == res3.public_key,
            "Signer1 and Signer3 public key mismatch"
        );
        println!("completed dkg");
        // generate random message vec<u8> fill bytes
        let message = vec![15; 32];
        let (in1_tx, mut out1_rx, result1_receiver) = sign_single_node(
            29197,
            1,
            0,
            2,
            vec![1, 2],
            message.clone(),
            res1,
            vec![1, 2, 3],
        )
        .await
        .unwrap();
        let (in2_tx, mut out2_rx, result2_receiver) = sign_single_node(
            29198,
            2,
            0,
            2,
            vec![1, 2],
            message.clone(),
            res2,
            vec![1, 2, 3],
        )
        .await
        .unwrap();
        // Clone the "in" channels for use in the coordinator task.
        let in1_tx_coord = in1_tx.clone();
        let in2_tx_coord = in2_tx.clone();

        let coordinator = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Listen for messages from signer 1.
                    Some(msg) = out1_rx.recv() => {
                        let from = 1;
                        let coord_msg = signer_rpc::CoordinatorToSignerMsg {
                            msg: msg.msg,
                            is_broadcast: msg.is_broadcast,
                            from,
                        };
                        if msg.is_broadcast {
                            // For broadcast messages, forward to all other clients.
                            let _ = in2_tx_coord.send(coord_msg.clone());
                        } else {
                            // For direct messages, forward based on msg.to.
                            match msg.to {
                                2 => { let _ = in2_tx_coord.send(coord_msg); },
                                _ => {
                                    tracing::warn!("Signer1 sent a non-broadcast message with an unknown target: {}", msg.to);
                                }
                            }
                        }
                    },
                    // Listen for messages from signer 2.
                    Some(msg) = out2_rx.recv() => {
                        let from = 2;
                        let coord_msg = signer_rpc::CoordinatorToSignerMsg {
                            msg: msg.msg,
                            is_broadcast: msg.is_broadcast,
                            from,
                        };
                        if msg.is_broadcast {
                            let _ = in1_tx_coord.send(coord_msg.clone());
                        } else {
                            match msg.to {
                                1 => { let _ = in1_tx_coord.send(coord_msg); },
                                _ => {
                                    tracing::warn!("Signer2 sent a non-broadcast message with an unknown target: {}", msg.to);
                                }
                            }
                        }
                    },
                    else => {
                        // Exit the loop if all out channels are closed.
                        break;
                    }
                }
            }
        });
        // Wait for all three DKG tasks to complete their oneshot results.
        let (res1, res2) = tokio::join!(result1_receiver, result2_receiver);

        // After all results are received, abort the coordinator task.
        coordinator.abort();
        let res1 = res1.unwrap();
        let res2 = res2.unwrap();

        assert!(res1.is_ok(), "Signer1 Signing failed: {:?}", res1);
        assert!(res2.is_ok(), "Signer2 Signing failed: {:?}", res2);
        let res1 = res1.unwrap();
        let res2 = res2.unwrap();
        assert!(
            res1.signature == res2.signature,
            "Signer1 and Signer2 signature mismatch"
        );
        // ecdsa verify
        let message = message.as_slice();
        let signature = res1.signature.as_slice();
        let public_key = res1.public_key.as_slice();
        let public_key_derived: &[u8] = res1.public_key_derived.as_slice();
        assert!(signature.len() == 64, "Signature must be 64 bytes");
        assert!(message.len() == 32, "Message must be 32 bytes");
        assert!(
            public_key.len() == 33 || public_key.len() == 65,
            "Public key must be 33 bytes or 65 bytes"
        );
        // pubkey must be 33 bytes or 65 bytes
        assert!(
            public_key_derived.len() == 33 || public_key_derived.len() == 65,
            "Public key must be 33 bytes or 65 bytes"
        );
        let signature = secp256k1::ecdsa::Signature::from_compact(&signature).unwrap();
        let message = secp256k1::Message::from_digest(message.try_into().unwrap());
        let secp = secp256k1::Secp256k1::verification_only();
        let pubkey = secp256k1::PublicKey::from_slice(&public_key_derived).unwrap();
        assert!(pubkey.serialize().len() == 33);
        if !secp.verify_ecdsa(&message, &signature, &pubkey).is_ok() {
            panic!("Signature is invalid");
        }
        let recovery_id = (0..=1)
            .find_map(|v| {
                let rec_id = secp256k1::ecdsa::RecoveryId::try_from(v as i32).ok()?;
                let recoverable_sig = secp256k1::ecdsa::RecoverableSignature::from_compact(
                    &signature.serialize_compact(),
                    rec_id,
                )
                .ok()?;
                secp.recover_ecdsa(&message, &recoverable_sig).ok()?;
                Some(v as u8)
            })
            .expect("Failed to recover signature");
        println!("recovery_id: {}", recovery_id);
        println!("completed sign");
        let client = EcdsaTssSignerClient::new(29197).await.unwrap();
        let (public_key, public_key_derived1) = client
            .derive_pk_from_key_package(0, res1_copy, vec![1, 2, 3])
            .await
            .unwrap();
        assert!(public_key_derived1 == public_key_derived);
        let client = EcdsaTssSignerClient::new(29197).await.unwrap();
        let (_, public_key_derived2) = client
            .derive_pk_from_pk(0, public_key, vec![1, 2, 3])
            .await
            .unwrap();
        assert!(public_key_derived2 == public_key_derived);
    }
    use futures::future::join_all;
    #[tokio::test]
    async fn test_signer_service_client_test() {
        let mut handles = vec![];
        for _ in 0..10 {
            handles.push(tokio::spawn(async move {
                test_signer_service_client().await;
            }));
        }
        join_all(handles).await;
    }
}
