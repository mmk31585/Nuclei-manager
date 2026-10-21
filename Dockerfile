# syntax=docker/dockerfile:1

# ---------- build ----------
FROM golang:1.27.2 AS builder

WORKDIR /src

# Dependencies first so this layer stays cached across source changes
COPY go.mod go.sum ./
RUN go mod download

# Only the packages the compiler needs (docs/ is imported by internal/api for Swagger)
COPY cmd/ cmd/
COPY internal/ internal/
COPY docs/ docs/

# Pure Go build: no C toolchain needed, produces a static binary
ENV CGO_ENABLED=0 GOOS=linux
RUN mkdir -p /out && \
    go build -o /out/scanner-manager ./cmd/scanner-manager

# ---------- tools ----------
FROM alpine:3.20 AS tools

RUN apk add --no-cache curl unzip

RUN set -eux; \
    mkdir -p /out; \
    curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip"; \
    echo "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6  /tmp/nuclei.zip" | sha256sum -c -; \
    unzip -jq -o /tmp/nuclei.zip 'nuclei' -d /out; \
    curl -fsSL -o /tmp/naabu.zip "https://github.com/projectdiscovery/naabu/releases/download/v2.6.1/naabu_2.6.1_linux_amd64.zip"; \
    echo "018c4c9884dea971eda860435ede3021d1150732f34cfd245498c6726d8cab90  /tmp/naabu.zip" | sha256sum -c -; \
    unzip -jq -o /tmp/naabu.zip 'naabu' -d /out; \
    curl -fsSL -o /tmp/httpx.zip "https://github.com/projectdiscovery/httpx/releases/download/v1.12.0/httpx_1.12.0_linux_amd64.zip"; \
    echo "9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76  /tmp/httpx.zip" | sha256sum -c -; \
    unzip -jq -o /tmp/httpx.zip 'httpx' -d /out; \
    chmod 0755 /out/nuclei /out/naabu /out/httpx; \
    rm -f /tmp/nuclei.zip /tmp/naabu.zip /tmp/httpx.zip

# ---------- runtime ----------
FROM alpine:3.20

# ca-certificates: nuclei fetches templates/CVE feeds over HTTPS
# tzdata: task schedules use user-supplied IANA timezones
# gcompat: naabu v2.6.1 is a glibc-dynamic binary (nuclei/httpx are static Go)
RUN apk add --no-cache ca-certificates tzdata gcompat \
    && adduser -D -u 1000 appuser

COPY --from=tools   /out/nuclei         /usr/local/bin/nuclei
COPY --from=tools   /out/naabu          /usr/local/bin/naabu
COPY --from=tools   /out/httpx          /usr/local/bin/httpx
COPY --from=builder /out/scanner-manager /usr/local/bin/scanner-manager

# WORKDIR must stay /app: config resolves ./custom-templates relative to the CWD
WORKDIR /app
# nuclei reads .nuclei-ignore and the uncover provider config from the user's
# home; pre-creating them keeps nuclei from logging errors on every run.
RUN mkdir -p /app/data/runs /app/custom-templates /nuclei-templates \
        /home/appuser/.config/nuclei /home/appuser/.config/uncover \
    && echo "providers: {}" > /home/appuser/.config/uncover/provider-config.yaml \
    && echo "ignore:" > /home/appuser/.config/nuclei/.nuclei-ignore \
    && chown -R appuser:appuser /app /nuclei-templates /home/appuser/.config

USER appuser

EXPOSE 8080

ENTRYPOINT ["scanner-manager"]