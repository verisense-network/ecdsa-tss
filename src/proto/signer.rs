// This file is @generated by prost-build.
/// curve_id 0 for S256, 1 for P256
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BaseInfo {
    #[prost(uint32, tag = "1")]
    pub curve_id: u32,
    #[prost(uint32, tag = "2")]
    pub id: u32,
    #[prost(uint32, tag = "3")]
    pub threshold: u32,
    #[prost(uint32, repeated, tag = "4")]
    pub ids: ::prost::alloc::vec::Vec<u32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SigningInfo {
    #[prost(message, optional, tag = "1")]
    pub base_info: ::core::option::Option<BaseInfo>,
    #[prost(message, optional, tag = "2")]
    pub key_package: ::core::option::Option<KeyPackage>,
    #[prost(bytes = "vec", tag = "3")]
    pub message: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub derivation_delta: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyPackage {
    #[prost(bytes = "vec", tag = "1")]
    pub key_package: ::prost::alloc::vec::Vec<u8>,
    /// optional in request
    #[prost(bytes = "vec", tag = "2")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Signature {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub public_key_derived: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PkRequest {
    #[prost(uint32, tag = "1")]
    pub curve_id: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub derivation_delta: ::prost::alloc::vec::Vec<u8>,
    #[prost(oneof = "pk_request::Source", tags = "2, 3")]
    pub source: ::core::option::Option<pk_request::Source>,
}
/// Nested message and enum types in `PkRequest`.
pub mod pk_request {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Source {
        #[prost(message, tag = "2")]
        KeyPackage(super::KeyPackage),
        #[prost(bytes, tag = "3")]
        PublicKey(::prost::alloc::vec::Vec<u8>),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PkResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub public_key_derived: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignerToCoordinatorMsg {
    #[prost(bytes = "vec", tag = "1")]
    pub msg: ::prost::alloc::vec::Vec<u8>,
    #[prost(bool, tag = "2")]
    pub is_broadcast: bool,
    #[prost(uint32, tag = "3")]
    pub to: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CoordinatorToSignerMsg {
    #[prost(bytes = "vec", tag = "1")]
    pub msg: ::prost::alloc::vec::Vec<u8>,
    #[prost(bool, tag = "2")]
    pub is_broadcast: bool,
    #[prost(uint32, tag = "3")]
    pub from: u32,
}
/// from rust to go
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DkgRequest {
    /// init / intermediate
    #[prost(string, tag = "1")]
    pub req_type: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub base_info: ::core::option::Option<BaseInfo>,
    /// if is intermediate, coordinator_to_signer_msg is not nil
    #[prost(message, optional, tag = "3")]
    pub coordinator_to_signer_msg: ::core::option::Option<CoordinatorToSignerMsg>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DkgResponse {
    /// intermediate / final / empty / error
    /// the first response from coordinator to signer must be empty, since go-grpc will not send header for connection and tonic client will be blocked
    /// see the issue in <https://github.com/hyperium/tonic/issues/515>
    #[prost(string, tag = "1")]
    pub resp_type: ::prost::alloc::string::String,
    /// if is final, data is key package
    #[prost(message, optional, tag = "2")]
    pub key_package: ::core::option::Option<KeyPackage>,
    /// if is intermediate, signer_to_coordinator_msg is not nil
    #[prost(message, optional, tag = "3")]
    pub signer_to_coordinator_msg: ::core::option::Option<SignerToCoordinatorMsg>,
    /// if is error, error is not nil
    #[prost(string, tag = "4")]
    pub error: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignRequest {
    /// init / intermediate
    #[prost(string, tag = "1")]
    pub req_type: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub signing_info: ::core::option::Option<SigningInfo>,
    /// if is intermediate, coordinator_to_signer_msg is not nil
    #[prost(message, optional, tag = "3")]
    pub coordinator_to_signer_msg: ::core::option::Option<CoordinatorToSignerMsg>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignResponse {
    /// intermediate / final / empty / error
    /// the first response from signer to coordinator must be empty, since go-grpc will not send header for connection and tonic client will be blocked
    /// see the issue in <https://github.com/hyperium/tonic/issues/515>
    #[prost(string, tag = "1")]
    pub resp_type: ::prost::alloc::string::String,
    /// if is final, data is signature
    #[prost(message, optional, tag = "2")]
    pub signature: ::core::option::Option<Signature>,
    /// if is intermediate, signer_to_coordinator_msg is not nil
    #[prost(message, optional, tag = "3")]
    pub signer_to_coordinator_msg: ::core::option::Option<SignerToCoordinatorMsg>,
    /// if is error, error is not nil
    #[prost(string, tag = "4")]
    pub error: ::prost::alloc::string::String,
}
/// Generated client implementations.
pub mod signer_service_client {
    #![allow(
        unused_variables,
        dead_code,
        missing_docs,
        clippy::wildcard_imports,
        clippy::let_unit_value,
    )]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    #[derive(Debug, Clone)]
    pub struct SignerServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl SignerServiceClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> SignerServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> SignerServiceClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + std::marker::Send + std::marker::Sync,
        {
            SignerServiceClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        pub async fn dkg(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = super::DkgRequest>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::DkgResponse>>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::unknown(
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/signer.SignerService/DKG");
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(GrpcMethod::new("signer.SignerService", "DKG"));
            self.inner.streaming(req, path, codec).await
        }
        pub async fn sign(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = super::SignRequest>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::SignResponse>>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::unknown(
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/signer.SignerService/Sign",
            );
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(GrpcMethod::new("signer.SignerService", "Sign"));
            self.inner.streaming(req, path, codec).await
        }
        pub async fn pk(
            &mut self,
            request: impl tonic::IntoRequest<super::PkRequest>,
        ) -> std::result::Result<tonic::Response<super::PkResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::unknown(
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/signer.SignerService/Pk");
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new("signer.SignerService", "Pk"));
            self.inner.unary(req, path, codec).await
        }
    }
}
