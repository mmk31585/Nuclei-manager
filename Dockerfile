# Build stage
FROM golang:1.27-alpine AS builder

RUN apk add --no-cache gcc musl-dev git make

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /scanner-manager ./cmd/scanner-manager

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata bash curl jq \
    && adduser -D -u 1000 appuser

# Install nuclei
RUN apk add --no-cache wget \
    && wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip \
    && unzip -q nuclei_3.11.1_linux_amd64.zip -d /usr/local/bin/ \
    && rm nuclei_3.11.1_linux_amd64.zip \
    && nuclei -version

# Copy custom templates
COPY custom-templates /app/custom-templates

# Copy binary
COPY --from=builder /scanner-manager /usr/local/bin/scanner-manager

# Create directories and nuclei config (suppresses .nuclei-ignore warnings)
RUN mkdir -p /app/data/runs /app/custom-templates /nuclei-templates /home/appuser/.config/nuclei /home/appuser/.config/uncover \
    && echo "providers: {}" > /home/appuser/.config/uncover/provider-config.yaml \
    && echo "ignore:" > /home/appuser/.config/nuclei/.nuclei-ignore \
    && chown -R appuser:appuser /app /nuclei-templates /home/appuser/.config

USER appuser
WORKDIR /app

ENV SM_HTTP_ADDR=0.0.0.0:8080 \
    SM_GIN_MODE=release \
    SM_DATA_DIR=/app/data \
    SM_NUCLEI_BIN=nuclei \
    SM_NUCLEI_TEMPLATES_DIR=/nuclei-templates \
    SM_MAX_CONCURRENT_RUNS=2 \
    SM_WORKER_POLL=2s

EXPOSE 8080

ENTRYPOINT ["scanner-manager"]