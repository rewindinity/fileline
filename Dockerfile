FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/fileline ./cmd/server && \
    mkdir -p /out/app/data /out/app/uploads /out/app/chunks && \
    chmod 0750 /out/app/data /out/app/uploads /out/app/chunks

FROM gcr.io/distroless/static-debian13:nonroot

WORKDIR /app

COPY --from=builder --chown=65532:65532 /out/app /app
COPY --from=builder /out/fileline /usr/local/bin/fileline

USER 65532:65532

EXPOSE 8080 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/fileline", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/fileline"]
