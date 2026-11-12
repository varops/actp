# syntax=docker/dockerfile:1
# actp with no agents inside: install them from the dashboard or with ACTP_AGENTS.
# See docs/docker.md.

FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/actp ./cmd/actp

FROM node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git gosu less openssh-client procps ripgrep tini \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/actp /usr/local/bin/actp
# The pinned cloudflared, checked against the SHA-256 built into actp.
RUN HOME=/tmp/cf actp tunnel install \
 && mv /tmp/cf/.actp/bin/cloudflared /usr/local/bin/cloudflared \
 && rm -rf /tmp/cf
COPY packaging/docker/entrypoint.sh /usr/local/bin/actp-entrypoint
ENV HOME=/data \
    PATH=/data/.actp/agents/bin:/data/.local/bin:$PATH
# Login shells (the dashboard terminal) reset PATH in /etc/profile: add the agents back.
RUN echo 'export PATH=/data/.actp/agents/bin:/data/.local/bin:$PATH' > /etc/profile.d/actp.sh
VOLUME /data
EXPOSE 7860 7861
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD curl -fsS http://127.0.0.1:7860/health || exit 1
ENTRYPOINT ["tini", "--", "actp-entrypoint"]
CMD ["actp", "container"]
