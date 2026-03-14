# Dockerfile for local testing
# Note: Production builds use ko (see .github/workflows/container-release.yaml)

FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install git for go mod download
RUN apk add --no-cache git

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY *.go ./

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-X main.version=local-test" -o cs-unifi-bouncer .

# Final stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/cs-unifi-bouncer .

ENTRYPOINT ["./cs-unifi-bouncer"]
