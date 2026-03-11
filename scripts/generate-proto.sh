#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PROTO_DIR="$ROOT_DIR/proto"
GO_OUT="$ROOT_DIR/teamserver/pkg/proto/apexpb"

mkdir -p "$GO_OUT"

echo "[*] Generating Go protobuf + gRPC code..."

protoc \
  --proto_path="$PROTO_DIR" \
  --go_out="$GO_OUT" \
  --go_opt=paths=source_relative \
  --go-grpc_out="$GO_OUT" \
  --go-grpc_opt=paths=source_relative \
  "$PROTO_DIR"/*.proto

echo "[+] Generated Go code in $GO_OUT"
ls -la "$GO_OUT"
