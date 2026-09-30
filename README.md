# SHIEP-Pipeline

SHIEP-Pipeline is a **minimal Rust CLI-only EasyConnect client for SHIEP**.
It exposes a local SOCKS5 TCP proxy and automatically selects VPN or fallback connections using the gateway's route table. No TUN device or system-route changes are needed.

## Quick Start

### 1. Download and Run

Go to the latest release page on GitHub and download the binary for Linux x64, macOS ARM64, or Windows x64. The examples below use `./SHIEP-Pipeline` for the executable.

```bash
chmod +x ./SHIEP-Pipeline
SHIEP_PIPELINE_PASSWORD='<PASSWORD>' ./SHIEP-Pipeline --server '<VPN_SERVER>' --username '<USERNAME>'
```

Or pass the password directly. This is not recommended because process arguments may be visible:

```bash
./SHIEP-Pipeline --server '<VPN_SERVER>' --username '<USERNAME>' --password '<PASSWORD>'
```

### 2. Use With Browser

Use [ZeroOmega](https://github.com/zero-peak/ZeroOmega) to send selected browser traffic into Pipeline without changing the system proxy:

1. Create a **SOCKS5** proxy profile with server **127.0.0.1** and port **1080** (or the address set by `--bind`).
2. Select that profile manually or through ZeroOmega rules. Pipeline then applies its own VPN/fallback routing.

Other SOCKS5-capable clients and automation scripts can use the same listener. Use a client setting that forwards hostnames, such as `socks5h://` in curl, so Pipeline can apply its hostname rules before choosing a route.

## CLI Arguments

- `--server` required, VPN server address
- `--username` required, username
- `SHIEP_PIPELINE_PASSWORD` required unless `--password` is provided
- `--password` optional, VPN password; usable as an alternative to `SHIEP_PIPELINE_PASSWORD`, but not recommended because process arguments may be visible
- `--bind` optional, local bind address, default `127.0.0.1:1080`
- `--fallback` optional, fallback upstream proxy address

Example:

```bash
SHIEP_PIPELINE_PASSWORD='<PASSWORD>' ./SHIEP-Pipeline \
  --server '<VPN_SERVER>' \
  --username '<USERNAME>' \
  --bind 127.0.0.1:1080 \
  --fallback socks5h://127.0.0.1:114514
```

## Highlights

- **Pure Rust TLS:** modern HTTPS and legacy VPN connections need no OpenSSL or AWS-LC; gateway behavior is informed by detailed EasyConnect protocol analysis and reverse engineering.
- **Automatic split routing:** gateway rules, DNS mappings, and CNAME chains select VPN or fallback; inferred DNS scopes limit exploratory queries, and TTL-based caches reuse answers.
- **Controlled TCP forwarding:** an event-driven userspace stack with bounded buffers, backpressure in both directions, half-close handling, and explicit failure detection.
- **Readable logs:** request paths, DNS provenance, and failure reasons with millisecond timestamps and restrained color, balancing information with visual clarity.

## Routing and Fallback

- The app fetches and parses route rules from `/por/rclist.csp`.
- If a route-table rule or trusted route-table DNS resolution chain matches, traffic goes remote.
- If no whitelist rule matches, TCP traffic goes fallback.
- With `--fallback`, TCP traffic goes through the upstream proxy.
- Without `--fallback`, TCP traffic goes direct.
- If the route table cannot be fetched, routing degrades to tunnel mode and requests are marked as `route-table-unavailable`.
- Explicit IPv6 TCP targets always use fallback, even when route-table loading fails; IPv6 tunnel routing is not supported.
- The local SOCKS5 listener accepts TCP CONNECT without authentication. UDP ASSOCIATE is explicitly rejected.

### Route Resolution

Matching starts with the requested hostname or IPv4 address and port. A matched hostname uses its rule's `dns.data` mapping first, then the gateway-provided DNS servers if that mapping is missing. If the hostname itself has no rule, the remaining lookup order is:

`dns.data IPv4 rule -> scoped DNS CNAME rule -> scoped DNS IPv4 rule -> fallback`

DNS resolution alone does not authorize VPN routing: a derived hostname or IPv4 address must still match an active rule for the requested port. Hostname and exact-IP rules use hash indexes, while IPv4 ranges use address buckets; original rule priority is preserved.

DNS servers are tried in the supplied order. Positive answers and CNAME chains are cached with their shortest relevant TTL, capped at five minutes, in bounded caches. Failed lookups are not cached. Queries use the host network directly, independently of `--fallback`, with UDP first and TCP when a response is truncated. This internal DNS transport is separate from the TCP-only SOCKS listener.

### Trusted DNS Scopes

DNS server lookup for otherwise unmatched domains is limited to scopes inferred from the active route table. Domains outside those scopes skip exploratory VPN-DNS queries. No Public Suffix List or hardcoded campus suffix list is required.

The scope inference algorithm:

1. Builds a reverse-label trie from unique active TCP Rc domain rules, excluding IP rules, inactive protocols, and `dns.data`.
2. Treats only terminal nodes without children as leaves.
3. Collapses a subtree when a node has at least two direct leaf children, allowing the resulting synthetic leaf to merge recursively into its parent.
4. Stops before one-label roots and retains only the final synthetic leaves, allowing scopes such as `edu.cn` but never a TLD such as `com`.

For example, `pan.shiep.edu.cn + ids.shiep.edu.cn -> shiep.edu.cn`.

An otherwise unknown domain may query route-table DNS only when it equals or is below an inferred scope. Exact Rc domain matches remain independent of this gate and may still query DNS when their local mapping is missing. Route-table `dns.data` records remain local resolution data and do not authorize broader DNS queries.

Scopes are computed once when the route table is installed. Each lookup checks the hostname and its ancestors against a hash set; it does not rebuild or scan the trie.

### Fallback Proxies

Supported fallback proxy input formats:

| Input format | Interpreted as |
| --- | --- |
| `socks5://host:port` | SOCKS5 proxy |
| `socks5h://host:port` | SOCKS5 proxy with remote DNS |
| `http://host:port` | HTTP CONNECT proxy |
| `host:port` | Plain host/port, interpreted as `socks5h://host:port` |

For fallback proxies, `socks5` and `socks5h` use the same implementation: hostname targets are passed to the upstream proxy for resolution.

## Logs

Logs use `YYYY/MM/DD HH:MM:SS.mmm` timestamps, module tags, distinct route colors, and explicit WARN/ERROR labels. Date fields and separators are subdued; addresses and important values are highlighted. The aim is to make request flow and failures readable without coloring every word.

Example request paths:

```text
[REQ] portal.example.edu:443 -> remote -> Campus Portal(10.0.0.20:443)
[REQ] example.com:443 -> fallback -> direct
```

DNS logs distinguish a `dns.data` mapping, a query to a named DNS server, and a cache hit. Upstream errors retain the requested target, route, and underlying cause.

- `[APP]` shows startup, route-table status, fallback mode, and listener status.
- `[LOGIN]` shows login and session acquisition.
- `[AGENT]` shows agent-token acquisition.
- `[REQ]` shows local proxy requests and the selected route.
- `[UPSTREAM]` shows upstream routing, DNS resolution, and route execution errors.
- `[VPN]` shows tunnel setup, heartbeat policy, and tunnel shutdown reasons.
- `[NETSTACK]` shows local network-stack runtime errors.
- `[CLI]` shows top-level configuration and runtime errors.

## Pure Rust TLS

The application uses two TLS implementations for different gateway connections:

| Connection path | Implementation |
| --- | --- |
| HTTPS login | `rustls` with the `rustls-rustcrypto` provider |
| Agent token, route-table fetch, and VPN command/RX/TX streams | The workspace's [legacy-tls](crates/legacy-tls/README.md) crate, using RustCrypto primitives |

The dedicated legacy client implements TLS 1.1/1.2 with RSA key transport and AES-CBC. Pipeline uses it to preserve the gateway's `L3IP` ClientHello identifier and TLS session identifier handling. The connection flow covers RSA-encrypted login, session and agent-token acquisition, and separate command/RX/TX streams. This integration follows detailed EasyConnect protocol analysis and reverse engineering, with independent interoperability checks and live VPN testing.

The `legacy-tls` crate forbids unsafe code and accepts a blocking transport supplied by the caller. It handles fragmented records, authenticated shutdown, and failed-stream state without adding its own sockets, threads, or timers. A standard Rust toolchain and platform linker are sufficient to build Pipeline; no CMake, libclang, NASM, or separately installed cryptographic library is needed. Neither building nor running the application requires OpenSSL or AWS-LC.

The legacy client and RustCrypto's rustls provider are experimental and have not received an independent security audit for this integration. Pipeline retains its existing gateway policy: server certificate trust and hostname are not verified, and legacy TLS suites do not provide forward secrecy. See [security and validation](crates/legacy-tls/SECURITY.md) for the exact boundaries and dependency review.

## Runtime Design

The runtime uses blocking I/O and worker threads. The userspace TCP stack waits for incoming packets, connection commands, or the next TCP deadline. Fatal tunnel failures wake the CLI through a condition variable, so an already detected failure does not wait for another browser request or a periodic status check.

Upload reads follow available TCP send-buffer capacity, and download delivery waits for the local consumer to accept the previous chunk. This bounds application read-ahead during large transfers and lets TCP acknowledgements and receive windows regulate flow. A TCP half-close ends only that direction; the other direction can finish its remaining data.

### Liveness and Shutdown

The client preserves the gateway's distinct liveness mechanisms:

- An ICMP data heartbeat travels over the TX tunnel every 12 seconds to the heartbeat address supplied by the gateway.
- A command heartbeat exchanges control messages on the persistent command stream every 30 seconds. Transient I/O failures retry after one second and stop after three consecutive failures.
- Native TCP keepalive helps detect broken underlying VPN connections. Stream I/O and control replies also participate in failure detection.

Data heartbeats provide keepalive traffic; they are not an RX echo watchdog. Explicit server shutdown or IP-kick replies are treated as terminal. Recoverable data streams have bounded reconnect attempts within the current session. A fatal tunnel failure reports its cause and exits the process; it does not silently log in again. Normal heartbeat success stays quiet, while startup policy and failures remain visible.

## Development

### Run From Source

1. Install Rust stable and the platform linker/toolchain.
2. Run with Cargo.

```bash
SHIEP_PIPELINE_PASSWORD='<PASSWORD>' cargo run --locked -p ec-cli -- --server '<VPN_SERVER>' --username '<USERNAME>'
```

Cargo uses the checked-in lockfile for reproducible dependency selection. Add `--release` for an optimized build.

### Diagnostics

Debug builds expose an additional `--debug` flag:

```bash
SHIEP_PIPELINE_PASSWORD='<PASSWORD>' cargo run --locked -p ec-cli -- --server '<VPN_SERVER>' --username '<USERNAME>' --debug
```

Without the flag, debug builds use normal logging. With it, they also show TLS summaries, stream reconnect attempts, and raw abnormal protocol replies. The flag changes diagnostic output only. Release builds do not include it or the diagnostic strings.

### Validation

The [manual test workflow](.github/workflows/build-test.yml) runs workspace tests natively on Linux x64, macOS ARM64, and Windows x64. It also builds and starts both debug and release binaries with `--version`, then uploads them for manual testing without creating a Release. All three platforms have passed this workflow; live VPN use has also been tested on Linux and Windows. macOS validation currently covers CI tests and binary startup.

The [release workflow](.github/workflows/build-release.yml) builds and uploads platform binaries when a GitHub Release is published.

Local checks:

```bash
cargo fmt --all --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Tests cover TLS authentication and malformed input, fragmented records and control replies, HTTP response boundaries, and TCP relay shutdown. The separate [interoperability harness](experiments/legacy-tls-interop/README.md) checks the legacy client against OpenSSL and AWS-LC reference servers. Those native libraries are test-only dependencies outside the production workspace.

## Project Structure

- `crates/ec-cli`: CLI entry point and argument parsing
- `crates/ec-core`: Core implementation (login, protocol, tunnel, netstack, route-table parsing, and forwarding)
- `crates/legacy-tls`: Independently packageable Rust TLS 1.1/1.2 client for the legacy gateway
- `experiments/legacy-tls-interop`: Independent TLS reference-server tests, outside the workspace
- `.github/workflows/build-test.yml`: Manual native tests and debug/release builds for three platforms
- `.github/workflows/build-release.yml`: Build and upload release artifacts on `release.published`

## Disclaimer

This project is for learning and research in authorized environments only.
Please follow your institution and network usage policies.

## Acknowledgements

- [NJUConnect](https://github.com/lyc8503/NJUConnect): the original upstream whose connection logic and behavior were referenced during this project's design.
- [EasierConnect](https://github.com/Yan233th/EasierConnect): a strengthened fork with much better logging and critical bug fixes, but with no routing/split-routing support.
