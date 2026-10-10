# wgproxy

An HTTP forward proxy that routes traffic through WireGuard. Each configuration file gets an isolated userspace tunnel, so profiles can share the same private IP and DNS addresses.

Runs as a single Go executable or an unprivileged container. No TUN device, network namespaces, or `NET_ADMIN` capability is required.

## Quick start

Place your WireGuard profiles in `wireguard/`, for example `japan-1.conf` and `japan-2.conf`. The files must be readable by the container's UID/GID, `65532:65532`. Keep the directory private; its contents are ignored by Git.

The file in [examples/](examples/) is a template, not a working profile.

```sh
docker compose up --build -d
docker compose logs -f
curl --proxy http://127.0.0.1:8080 https://api.ipify.org
```

Profiles become available after their first successful health check. Restart the service after changing configuration files.

Compose publishes the proxy on host loopback only. The image includes CA certificates and runs as a non-root user.

> There is no proxy authentication. Do not expose the proxy publicly or to untrusted Docker-network clients.

### Run without Docker

To listen on loopback only:

```sh
WG_CONFIG_DIR=./wireguard PROXY_ADDR=127.0.0.1:8080 ./bin/wgproxy
```

Without `PROXY_ADDR`, the executable listens on all interfaces at port 8080.

### Configure your application

Use an `http://` proxy URL for both HTTP and HTTPS destinations. HTTPS uses an HTTP CONNECT tunnel:

```sh
HTTPS_PROXY=http://127.0.0.1:8080 curl https://api.ipify.org
```

Secure WebSockets work through CONNECT. Plain `ws://` Upgrade proxying is not supported.

## How traffic is handled

Ordinary HTTP requests are balanced across healthy profiles using round robin, starting in filename order. Each new HTTPS CONNECT tunnel selects one profile and stays on it until it closes. Profiles are not guaranteed to have different public exit IPs, and your VPN provider must allow simultaneous use of the configured client identities.

Destination TCP connections and DNS queries stay inside the selected tunnel. There is no direct destination fallback. The host or container network carries WireGuard UDP traffic, incoming proxy and administrative connections, and DNS lookups for WireGuard endpoint hostnames.

Endpoint DNS failures are retried by health checks. After successful resolution, the endpoint address is retained until restart; authenticated WireGuard endpoint roaming still works. Numeric endpoints need no bootstrap DNS.

A destination connection failure returns 502, or 504 for a timeout. It requests an early health check but does not directly mark the profile unhealthy or retry through another profile. Canceled client requests do not trigger checks. Standard HTTP connection-pool recovery may retry eligible requests within the same profile.

No healthy profiles, the active-operation limit, or shutdown draining produces 503. Invalid targets produce 400; ordinary HTTP Upgrade requests produce 501.

`MAX_ACTIVE` counts each HTTP request until its response finishes and each CONNECT tunnel until it closes. Bodies are streamed, with no blanket response-body or CONNECT lifetime timeout.

SIGINT and SIGTERM stop new work and begin graceful shutdown. Remaining requests and tunnels are closed after `SHUTDOWN_TIMEOUT`.

## WireGuard profiles

Each `.conf` file must contain exactly one `[Interface]` and one `[Peer]`. Blank lines and `#` comments are ignored. `Address`, `DNS`, and `AllowedIPs` support repeated directives and comma-separated values.

| Section | Required fields | Optional fields |
| --- | --- | --- |
| `[Interface]` | `PrivateKey`, `Address`, `DNS` | `MTU`, `ListenPort` |
| `[Peer]` | `PublicKey`, `AllowedIPs`, `Endpoint` | `PresharedKey`, `PersistentKeepalive` |

Every profile needs an IPv4 interface address, `0.0.0.0/0` in `AllowedIPs`, and at least one numeric DNS server. MTU defaults to 1420. `ListenPort` must be omitted or zero; local UDP ports are allocated automatically.

IPv6 requires both an IPv6 interface address and `::/0` in `AllowedIPs`. IPv6 DNS servers require IPv6 to be enabled. IPv4-only profiles never resolve or dial IPv6 destinations.

Split-tunnel routing and the full wg-quick format are not supported. Unsupported fields, including `PostUp` and `PostDown`, fail startup; scripts are never executed. Configuration errors identify fields without printing key values.

## Health and status

Each profile is checked independently through its tunnel. Checks use fresh connections, do not follow redirects, and require an HTTP 204 response.

By default, checks use `https://www.gstatic.com/generate_204`, time out after 10 seconds, and normally repeat 30 seconds after completion. Initial checks are staggered over one interval, with the first profile checked immediately. Set `HEALTHCHECK_URL` to an equivalent endpoint you control when needed.

HTTP transport errors and CONNECT dial failures request an earlier check for a still-healthy profile. These requests are coalesced, and each profile runs only one check at a time. Early checks are rate-limited to one start every 5 seconds per profile, or the configured interval if shorter. Failures reported during a check are covered by that check rather than queuing another. After any check completes, the next periodic check is scheduled one interval later.

A failed check removes the profile from new selections. A successful check restores it. Unhealthy profiles keep their periodic recovery-check schedule. Existing CONNECT tunnels are not migrated, and operations selected before a failed check may still report errors afterward.

Every failed health check is logged, including repeated failures while already unhealthy. Successful checks are logged only on initial success or recovery. Health checks probe the path; they do not restart the tunnel or repair underlying DNS or network problems.

Check whether the proxy is ready:

```sh
./bin/wgproxy healthcheck

# With Docker Compose:
docker compose exec wgproxy /wgproxy healthcheck
```

These commands return a nonzero exit status when the service is not ready.

The administrative listener defaults to `127.0.0.1:9090` and must bind to a numeric loopback address.

| Endpoint | Purpose |
| --- | --- |
| `GET /livez` | Reports process liveness. |
| `GET /readyz` | Succeeds when at least one profile is healthy and the service is not draining. |
| `GET /status` | Shows profile IDs, health, active operations, selection counts, and the latest check result. Never exposes configuration keys. |

## Environment variables

| Variable | Default |
| --- | --- |
| `WG_CONFIG_DIR` | `/etc/wgproxy/wireguard` |
| `PROXY_ADDR` | `0.0.0.0:8080` |
| `ADMIN_ADDR` | `127.0.0.1:9090` |
| `HEALTHCHECK_URL` | `https://www.gstatic.com/generate_204` |
| `HEALTHCHECK_INTERVAL` | `30s` |
| `HEALTHCHECK_TIMEOUT` | `10s` |
| `DIAL_TIMEOUT` | `15s` |
| `RESPONSE_HEADER_TIMEOUT` | `30s` |
| `SHUTDOWN_TIMEOUT` | `15s` |
| `MAX_ACTIVE` | `256` |

Durations use Go syntax, such as `10s` or `1m`, and must be positive. `MAX_ACTIVE` must also be positive.

Incoming request headers have a 10-second timeout and a configured 64 KiB limit. Idle incoming HTTP connections expire after 90 seconds. Upstream and health-check transports ignore application proxy environment variables.

## Published images

CI publishes `linux/amd64` and `linux/arm64` images to `ghcr.io/<owner>/<repository>`, using the lowercase GitHub repository name.

The `master` tag tracks successful builds from `master`. Published releases use their Git tag, normalized to Docker tag syntax. Non-prerelease releases also update `latest`. Both publication paths include a `sha-<short-commit>` tag.

GHCR package visibility is managed separately in GitHub Packages. Anonymous pulls require a public package.

## Development

Go tools are recorded in `go.mod`; no global golangci-lint installation is needed.

```sh
./scripts/format
./scripts/check
go test -race ./...
```

The race detector requires a supported platform and a working C compiler. Normal tests and static production builds do not require CGO.

Build a static Linux binary:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o bin/wgproxy .
```

Integration tests cover tunnel and DNS isolation, balancing, CONNECT behavior, streaming, health selection, operation limits, and shutdown. The Docker smoke test checks startup in the restricted image, not connectivity to a real VPN provider.

## Verify your deployment

This is application-level egress isolation, not an OS firewall policy. Ordinary UDP networking must remain available for WireGuard endpoints.

Before sending leak-sensitive traffic, capture host egress while breaking WireGuard connectivity. Destination traffic and destination DNS must not appear outside the tunnel; endpoint UDP and endpoint bootstrap DNS may remain visible. Automated tests do not replace this deployment check.
