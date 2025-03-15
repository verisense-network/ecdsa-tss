#[path = "proto/signer.rs"]
pub mod signer_rpc;
use std::time;

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::transport::Channel;

use signer_rpc::{DkgRequest, signer_service_client::SignerServiceClient};
pub struct BscTssSignerClient {
    client: SignerServiceClient<Channel>,
}

#[derive(Debug, thiserror::Error)]
pub enum BscTssSignerClientError {
    #[error("Tonic error: {0}")]
    TonicError(#[from] tonic::Status),

    #[error("Transport error: {0}")]
    TransportError(#[from] tonic::transport::Error),

    #[error("Invalid URI: {0}")]
    InvalidUri(#[from] http::uri::InvalidUri),

    #[error("DKG Failed: {0}")]
    DkgFailed(String),

    #[error("Recv error: {0}")]
    RecvError(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("Send error: {0}")]
    SendError(#[from] tokio::sync::mpsc::error::SendError<signer_rpc::SignerToCoordinatorMsg>),

    #[error("Init error: {0}")]
    InitError(String),
}
impl BscTssSignerClient {
    pub async fn new(port: u16) -> Result<Self, BscTssSignerClientError> {
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
    ) -> Result<signer_rpc::KeyPackage, BscTssSignerClientError> {
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
            .map_err(|e| BscTssSignerClientError::InitError(e.to_string()))?;
        let handler = tokio::spawn(async move {
            let sleep = tokio::time::sleep(timeout);
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    _ = &mut sleep => {
                        let _ = result_sender.send(Err(BscTssSignerClientError::DkgFailed("DKG process timeout".into())));
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
                                        .send(Err(BscTssSignerClientError::SendError(e)))
                                        .unwrap();
                                    return;
                                }
                            } else {
                                result_sender
                                    .send(Err(BscTssSignerClientError::DkgFailed(
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
                                    .send(Err(BscTssSignerClientError::DkgFailed(
                                        "No key package in final response".into(),
                                    )))
                                    .unwrap();
                                return;
                            }
                        }
                        other => {
                            result_sender
                                .send(Err(BscTssSignerClientError::DkgFailed(format!(
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
}
mod test {
    use std::time;

    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

    use crate::{BscTssSignerClient, BscTssSignerClientError, signer_rpc};
    async fn dkg(
        port: u16,
        id: u32,
        curve_id: u32,
        threshold: u32,
        ids: Vec<u32>,
    ) -> Result<
        (
            UnboundedSender<signer_rpc::CoordinatorToSignerMsg>,
            UnboundedReceiver<signer_rpc::SignerToCoordinatorMsg>,
            tokio::sync::oneshot::Receiver<Result<signer_rpc::KeyPackage, BscTssSignerClientError>>,
        ),
        BscTssSignerClientError,
    > {
        let base_info = signer_rpc::BaseInfo {
            id,
            curve_id,
            threshold,
            ids,
        };
        let client = BscTssSignerClient::new(port).await?;
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
    async fn test_signer_service_client() {
        let (in1_tx, mut out1_rx, result1_receiver) =
            dkg(29197, 1, 0, 2, vec![1, 2, 3]).await.unwrap();
        let (in2_tx, mut out2_rx, result2_receiver) =
            dkg(29198, 2, 0, 2, vec![1, 2, 3]).await.unwrap();
        let (in3_tx, mut out3_rx, result3_receiver) =
            dkg(29199, 3, 0, 2, vec![1, 2, 3]).await.unwrap();
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
        println!("completed");

        // Optionally: Check that all results are successful.
        assert!(res1.is_ok(), "Signer1 DKG failed: {:?}", res1);
        assert!(res2.is_ok(), "Signer2 DKG failed: {:?}", res2);
        assert!(res3.is_ok(), "Signer3 DKG failed: {:?}", res3);
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
