# syntax=docker/dockerfile:1.4
ARG BASE_IMAGE=alpine

# 1) Cross-compile helper
FROM --platform=$BUILDPLATFORM \
     tonistiigi/xx:1.6.1@sha256:923441d7c25f1e2eb5789f82d987693c47b8ed987c4ab3b075d6ed2b5d6779a3 \
     AS xx

# 2) Builder
FROM --platform=$BUILDPLATFORM \
     golang:1.24.2-alpine3.20@sha256:00f149d5963f415a891943531b9092fde06b596b276281039604292d8b2b9c8 \
     AS builder

COPY --from=xx / /

RUN apk add --no-cache alpine-sdk ca-certificates openssl clang lld

ARG TARGETPLATFORM
RUN xx-apk --update add musl-dev gcc

# lld has issues building static binaries for ppc so prefer ld
RUN [ "$(xx-info arch)" != "ppc64le" ] || \
    XX_CC_PREFER_LINKER=ld xx-clang --setup-target-triple

RUN xx-go --wrap

WORKDIR /usr/local/src/dex

ARG GOPROXY
ENV CGO_ENABLED=1

COPY go.mod go.sum ./
COPY api/v2/go.mod api/v2/go.sum ./api/v2/
RUN go mod download

COPY . .

# build args
ARG VERSION
ARG ORG_PATH=github.com/opengovern
ARG PROJ=dex-idp

# this will pick up your fork (ORG_PATH/PROJ) in the Makefile
RUN make release-binary ORG_PATH=${ORG_PATH} PROJ=${PROJ} VERSION=${VERSION}

# sanity-check
RUN xx-verify /go/bin/dex && xx-verify /go/bin/docker-entrypoint

# 3) Stager for config & data
FROM alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c AS stager

RUN mkdir -p /var/dex /etc/dex
COPY config.docker.yaml /etc/dex/

# 4) Gomplate
FROM alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c AS gomplate

ARG TARGETOS TARGETARCH TARGETVARIANT
ENV GOMPLATE_VERSION=v4.3.0

RUN wget -O /usr/local/bin/gomplate \
      "https://github.com/hairyhenderson/gomplate/releases/download/${GOMPLATE_VERSION}/gomplate_${TARGETOS:-linux}-${TARGETARCH:-amd64}${TARGETVARIANT}" \
    && chmod +x /usr/local/bin/gomplate

# 5) Dummy stages for Dependabot
FROM alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c AS alpine
FROM gcr.io/distroless/static-debian12:nonroot@sha256:c0f429e16b13e583da7e5a6ec20dd656d325d88e6819cafe0adb0828976529dc AS distroless

# 6) Final image
FROM $BASE_IMAGE

# root CAs
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# config & data
COPY --from=stager --chown=1001:1001 /var/dex /var/dex
COPY --from=stager --chown=1001:1001 /etc/dex /etc/dex

# module files (for CVE scanning)
COPY --from=builder /usr/local/src/dex/go.mod   /usr/local/src/dex/go.sum   /usr/local/src/dex/
COPY --from=builder /usr/local/src/dex/api/v2/go.mod /usr/local/src/dex/api/v2/go.sum /usr/local/src/dex/api/v2/

# the two binaries
COPY --from=builder /go/bin/dex               /usr/local/bin/dex
COPY --from=builder /go/bin/docker-entrypoint /usr/local/bin/docker-entrypoint

# web UI
COPY --from=builder /usr/local/src/dex/web /srv/dex/web

# gomplate
COPY --from=gomplate /usr/local/bin/gomplate /usr/local/bin/gomplate

USER 1001:1001

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["dex", "serve", "/etc/dex/config.docker.yaml"]
