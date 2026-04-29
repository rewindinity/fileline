FROM golang:1.26.2-trixie AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/fileline .

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/fileline /usr/local/bin/fileline

RUN mkdir -p /app/uploads /app/chunks

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/fileline"]
