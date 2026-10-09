# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/wgproxy .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/wgproxy /wgproxy

USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGTERM

ENTRYPOINT ["/wgproxy"]
