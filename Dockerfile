FROM golang:1.23 as builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Disable CGO and build a static binary
RUN CGO_ENABLED=0 go build -o ecdsa-tss main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/ecdsa-tss .

ENTRYPOINT ["./ecdsa-tss"]