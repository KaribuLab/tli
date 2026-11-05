# syntax=docker/dockerfile:1

# ---- Build stage -----------------------------------------------------------
# Runs on the build host's platform and cross-compiles for the target platform.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/tli ./cmd/tli

# ---- Runtime stage ---------------------------------------------------------
# Alpine (not scratch) on purpose: Bitbucket Pipelines needs a shell in the
# base image, and `tli scan` shells out to git.
FROM alpine:3.21

RUN apk add --no-cache bash git ca-certificates

COPY --from=build /out/tli /usr/local/bin/tli

# Config is read from ~/.tli/config.json, or from TLI_USER_ID, TLI_API_KEY
# and TLI_API_ENDPOINT when that file does not exist (CI usage).
WORKDIR /workspace

CMD ["tli", "--help"]
