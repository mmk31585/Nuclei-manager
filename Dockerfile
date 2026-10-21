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

# Copy nuclei templates from build context (host)
COPY nuclei-templates /home/appuser/nuclei-templates

# Copy custom templates
COPY custom-templates /app/custom-templates

# Copy binary
COPY --from=builder /scanner-manager /usr/local/bin/scanner-manager

# Create directories
RUN mkdir -p /app/data/runs /app/custom-templates \
    && chown -R appuser:appuser /app /home/appuser/nuclei-templates

USER appuser

ENV SM_HTTP_ADDR=0.0.0.0:8080 \
    SM_GIN_MODE=release \
    SM_DATA_DIR=/app/data \
    SM_NUCLEI_BIN=nuclei \
    SM_CUSTOM_TEMPLATES_DIR=/app/custom-templates \
    SM_NUCLEI_TEMPLATES_DIR=/home/appuser/nuclei-templates \
    SM_MAX_CONCURRENT_RUNS=2 \
    SM_WORKER_POLL=2s

EXPOSE 8080

ENTRYPOINT ["scanner-manager"]