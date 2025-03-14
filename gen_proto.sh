#!/usr/bin/env bash

# 1. Set the output parameters for the protoc plugins.
GO_OUT_FLAGS="paths=source_relative"
GO_GRPC_OUT_FLAGS="paths=source_relative"

# 2. Compile the .proto file with protoc.
protoc --go_out=./signer --go_opt="${GO_OUT_FLAGS}" \
       --go-grpc_out=./signer --go-grpc_opt="${GO_GRPC_OUT_FLAGS}" \
       proto/signer.proto

echo "Proto generation done."
