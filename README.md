# wgproxy

An HTTP forward proxy with one isolated userspace WireGuard tunnel per
configuration file. A single Go executable provides WireGuard, TCP/IP stacks,
destination DNS, health checking, HTTP forwarding, and CONNECT relaying.

No TUN device, Linux network namespaces, privileged container, or NET_ADMIN
capability is required. Each profile can use the same private interface and
DNS addresses as every other profile.

## Run with Docker

Place provider configurations under `wireguard/`, with names such as
`japan-1.conf` and `japan-2.conf`. Files must be readable by the container's
UID/GID, `65532:65532`. Keep the configuration directory private to the
accounts that need it. Its contents are ignored by Git.

```sh
docker compose up --build -d
docker compose logs -f
curl --proxy http://127.0.0.1:8080 https://api.ipify.org
```

The example file under `examples/` is a template, not a working profile.

The image contains CA certificates and runs as a non-root user. Compose
publishes the proxy only on host loopback. There is no proxy authentication:
do not expose it publicly or to untrusted Docker-network clients.

The service reads configurations once at startup. Restart it after changing
profiles. Different profiles are not guaranteed to have different public
exit IP addresses. The VPN provider must permit simultaneous use of the
configured client identities.

## Run the executable

```sh
WG_CONFIG_DIR=./wireguard ./bin/wgproxy
```

This listens on all interfaces at port 8080. For a directly executed
local-only proxy:

```sh
WG_CONFIG_DIR=./wireguard PROXY_ADDR=127.0.0.1:8080 ./bin/wgproxy
```

Configure applications with an HTTP proxy URL. HTTPS destinations still use
an `http://` proxy URL because the client establishes an HTTP CONNECT tunnel:

```sh
HTTPS_PROXY=http://127.0.0.1:8080 curl https://api.ipify.org
```

SIGINT and SIGTERM initiate graceful shutdown. New work is rejected during
draining. After the shutdown timeout, remaining requests and CONNECT tunnels
are closed.

## Balancing and failures

Plain HTTP is balanced per request, including requests on a reused
client-to-proxy connection. HTTPS is balanced per new CONNECT tunnel.
Everything within one CONNECT tunnel stays on its selected profile.

Profiles begin unhealthy. Successful health checks make them eligible.
Round robin starts in filename order and skips unhealthy profiles. Selection
is concurrency-safe; round robin does not mean equal bandwidth.

A destination connection failure returns 502, or 504 for a timeout. It does
not mark the whole profile unhealthy and is not retried through another
profile. Standard HTTP connection-pool recovery may retry eligible requests
within the same profile. Once response headers have been sent, a streaming
failure terminates the response rather than changing its status code.

No healthy profiles, the active-operation limit, or shutdown draining
produces 503. Invalid proxy targets produce 400. Ordinary HTTP Upgrade
requests produce 501. Secure WebSockets work through CONNECT; plain `ws://`
Upgrade proxying is not supported.

The active-operation limit counts each ordinary HTTP request until its
response finishes, and each CONNECT tunnel until it closes.

## Configuration format

Each `.conf` file must contain exactly one `[Interface]` and one `[Peer]`.
Comments beginning with `#` and blank lines are ignored. Comma-separated and
repeated Address, DNS, and AllowedIPs directives are supported.

Interface fields are PrivateKey, Address, DNS, optional MTU, and optional
ListenPort. ListenPort must be omitted or zero because local UDP ports are
allocated automatically. MTU defaults to 1420.

Peer fields are PublicKey, optional PresharedKey, AllowedIPs, Endpoint, and
optional PersistentKeepalive.

An IPv4 interface address, `0.0.0.0/0`, and at least one numeric DNS server
are required. This service intentionally does not implement split-tunnel
routing or the complete wg-quick format.

IPv6 is enabled only when the profile has an IPv6 interface address and
`::/0`. A profile containing `::/0` but only an IPv4 interface address stays
IPv4-only. IPv6 DNS servers require IPv6 to be enabled. IPv4-only profiles
do not resolve or dial IPv6 destinations.

Unsupported fields and malformed files fail startup. Scripts such as
PostUp and PostDown are never executed. Configuration errors identify
fields without printing key values.

## Network isolation

Destination TCP connections and destination DNS use the selected profile's
userspace stack. There is no host-network destination dialer or direct
fallback.

The container's ordinary network is used for WireGuard UDP transport, proxy
and administrative listeners, and WireGuard endpoint hostname resolution.
Numeric endpoints need no bootstrap DNS.

Endpoint DNS failures leave the profile unhealthy and are retried by its
health worker. After successful endpoint resolution, the address is retained
for the lifetime of the process. Restart to pick up a changed endpoint DNS
record. Normal authenticated WireGuard endpoint roaming remains supported.

This is application-level egress isolation, not an OS firewall policy. The
container must retain ordinary UDP networking to reach its VPN endpoints.

## Health and administration

Every profile is checked independently through its tunnel. Checks use fresh
connections and do not follow redirects. The response must have status 204.

The default URL is `https://www.gstatic.com/generate_204`. The default
timeout is 10 seconds, with another check 30 seconds after completion.
Initial checks are spread across one interval, with the first profile
checked immediately.

The check endpoint is a real availability dependency. For controlled
deployments, use an equivalent endpoint you own. A failed check removes the
profile from new selections; the next successful check restores it.
Established CONNECT tunnels are not migrated.

The administrative server must bind to a numeric loopback address.
`GET /livez` reports process liveness. `GET /readyz` succeeds when the service
is not draining and at least one profile is healthy. `GET /status` exposes
profile IDs, health, active operations, selection counts, and the latest
check result. It does not expose configuration keys.

```sh
./bin/wgproxy healthcheck
docker compose exec wgproxy /wgproxy healthcheck
```

These commands query the local administrative listener and return a nonzero
exit status when the service is not ready.

## Environment

`WG_CONFIG_DIR` defaults to `/etc/wgproxy/wireguard`.

`PROXY_ADDR` defaults to `0.0.0.0:8080`. `ADMIN_ADDR` defaults to
`127.0.0.1:9090`.

`HEALTHCHECK_URL` defaults to `https://www.gstatic.com/generate_204`.
`HEALTHCHECK_INTERVAL` defaults to `30s`. `HEALTHCHECK_TIMEOUT` defaults to
`10s`.

`DIAL_TIMEOUT` defaults to `15s`. `RESPONSE_HEADER_TIMEOUT` defaults to `30s`.
`SHUTDOWN_TIMEOUT` defaults to `15s`.

`MAX_ACTIVE` defaults to `256`.

Duration values use Go duration syntax. Values must be positive.
Application proxy environment variables are not used by upstream or
health-check transports.

There is no blanket response-body or CONNECT lifetime timeout. Incoming
request headers have a 10-second timeout and a 64 KiB configured limit.
Idle incoming HTTP connections expire after 90 seconds.

## Development

Go tools are recorded in go.mod. No global golangci-lint installation is
needed.

```sh
./scripts/format
./scripts/check
go test -race ./...
```

The format script runs gofumpt and autofixes wsl_v5 issues through
golangci-lint. The lint configuration excludes the `comments` and
`common-false-positives` presets.

The race detector needs a supported platform and a working C compiler.
Normal tests and static production builds do not require CGO.

Integration tests create independent WireGuard servers over loopback, with
overlapping private addresses and tunnel-only DNS servers. They test HTTP
round robin, CONNECT pinning, initially buffered CONNECT data, half-closes,
DNS isolation, absence of direct TCP fallback, IPv4-only behavior, health
selection, header stripping, streaming, trailers, operation limits, and
forced CONNECT shutdown.

The automated Docker check verifies that the static binary starts in the
restricted runtime image. Actual VPN connectivity in Docker must be checked
with working provider configurations.

## Builds and resource measurements

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o dist/wgproxy-linux-amd64 .

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w" -o dist/wgproxy-linux-arm64 .

docker buildx build --platform linux/amd64,linux/arm64 \
  -t your-registry/wgproxy:latest --push .
```

Module versions and checksums are committed. Container base-image tags are
not digest-pinned; pin reviewed digests when reproducible image inputs are
required.

Each profile has its own userspace TCP/IP stack and WireGuard state.
Bodies are streamed rather than buffered in full. Connection pools are
bounded per profile, and active work is bounded globally.

Measure container memory with one, five, and twenty profiles, after health
checks, during concurrent transfers, and after connections close. No fixed
memory-per-profile claim is made.

Before using real profiles for leak-sensitive traffic, capture host egress
while breaking WireGuard connectivity. Verify that destination addresses and
destination DNS are absent from direct egress, while endpoint UDP and any
endpoint bootstrap DNS remain present. The self-contained tests do not
replace packet-capture acceptance testing on the deployment network.
