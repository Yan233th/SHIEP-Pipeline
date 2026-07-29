# SHIEP-Pipeline

SHIEP-Pipeline is a **Rust CLI-only** EasyConnect implementation for SHIEP.
The project focuses on minimal scope, clear structure, and maintainability, with no GUI.

## Project Focus

- Minimal CLI-only
- SHIEP-oriented EasyConnect protocol behavior
- Route-table based split routing
- Clear runtime logs and maintainable structure

## Current Capabilities

- Username/password login (RSA-encrypted password flow)
- Session and agent token acquisition
- VPN tunnel setup with RX/TX runtime
- Local SOCKS5 listener (CONNECT only, no auth)
- Automatic route-table fetch and parse (`/por/rclist.csp`) for split-routing decisions
- Route table based target decisions using whitelist rules, DNS records, scoped DNS server lookup, CNAMEs, and IP-range matches
- Configurable TCP fallback routing (non-whitelist -> direct or upstream proxy via `--fallback`)
- IPv6 TCP targets via fallback only; IPv6 traffic never enters the VPN tunnel
- Explicit tunnel degradation when the route table is unavailable
- Structured, colorized logging that balances operational detail and visual clarity

## Quick Start

### 1. Download From Release

1. Go to the latest release page on GitHub.
2. Download the artifact for your platform:
   - Linux: `SHIEP-Pipeline-<tag>-linux-x64`
   - macOS (Apple Silicon): `SHIEP-Pipeline-<tag>-macos-arm64`
   - Windows: `SHIEP-Pipeline-<tag>-windows-x64.exe`
3. Run it with required arguments.

```bash
chmod +x ./SHIEP-Pipeline
SHIEP_PIPELINE_PASSWORD=<PASSWORD> ./SHIEP-Pipeline --server <VPN_SERVER> --username <USERNAME>
```

Or pass the password directly. This is not recommended because process arguments may be visible:

```bash
./SHIEP-Pipeline --server <VPN_SERVER> --username <USERNAME> --password <PASSWORD>
```

### 2. Use With Browser

Recommended browser-side companion: [ZeroOmega](https://github.com/zero-peak/ZeroOmega).

ZeroOmega is a Manifest V3 compatible fork of SwitchyOmega for managing and switching browser proxy profiles. It is useful when you want selected browser traffic to enter SHIEP-Pipeline while keeping the system proxy untouched.

Typical setup:

- Start SHIEP-Pipeline with the default listener, or choose one with `--bind`.
- In ZeroOmega, create a SOCKS5 proxy profile.
- Set the proxy server to `127.0.0.1` and the port to the SHIEP-Pipeline listener port, default `1080`.
- Use ZeroOmega rules or manual switching to decide which browser traffic is sent into SHIEP-Pipeline.

SHIEP-Pipeline still performs its own route-table based split-routing after traffic reaches the local SOCKS5 listener.

## CLI Arguments

- `--server` required, VPN server address
- `--username` required, username
- `SHIEP_PIPELINE_PASSWORD` required unless `--password` is provided
- `--password` optional, VPN password; usable as an alternative to `SHIEP_PIPELINE_PASSWORD`, but not recommended because process arguments may be visible
- `--bind` optional, local bind address, default `127.0.0.1:1080`
- `--fallback` optional, fallback upstream proxy address

Example:

```bash
SHIEP_PIPELINE_PASSWORD=<PASSWORD> ./SHIEP-Pipeline \
  --server <VPN_SERVER> \
  --username <USERNAME> \
  --bind 127.0.0.1:1080 \
  --fallback socks5h://127.0.0.1:114514
```

## Routing and Fallback

- The app fetches and parses route rules from `/por/rclist.csp`.
- If a route-table rule or trusted route-table DNS resolution chain matches, traffic goes remote.
- DNS Server lookup for otherwise unknown domains is limited to scopes inferred from active route-table domain rules, preventing unrelated domains from being disclosed to VPN-provided DNS servers.
- Route-table `dns.data` records remain local resolution data and do not authorize DNS query scopes.
- If no whitelist rule matches, TCP traffic goes fallback.
- With `--fallback`, TCP traffic goes through the upstream proxy.
- Without `--fallback`, TCP traffic goes direct.
- If the route table cannot be fetched, routing degrades to tunnel mode and requests are marked as `route-table-unavailable`.
- Explicit IPv6 TCP targets always use fallback, even when route-table loading fails; IPv6 tunnel routing is not supported.
- UDP ASSOCIATE is explicitly rejected; proxied traffic is TCP-only.

Supported fallback proxy input formats:

| Input format | Interpreted as |
| --- | --- |
| `socks5://host:port` | SOCKS5 proxy |
| `socks5h://host:port` | SOCKS5 proxy with remote DNS |
| `http://host:port` | HTTP CONNECT proxy |
| `host:port` | Plain host/port, interpreted as `socks5h://host:port` |

## Logs

- `[APP]` shows startup, route-table status, fallback mode, and listener status.
- `[LOGIN]` shows login and session acquisition.
- `[AGENT]` shows agent-token acquisition.
- `[REQ]` shows local proxy requests and the selected route.
- `[UPSTREAM]` shows upstream routing, DNS resolution, and route execution errors.
- `[VPN]` shows tunnel setup, heartbeat policy, and tunnel shutdown reasons.
- `[NETSTACK]` shows local network-stack runtime errors.
- `[CLI]` shows top-level configuration and runtime errors.

## Development

### Run From Source

1. Install Rust stable
2. Install OpenSSL development dependencies (your system may already have them)
3. Run with Cargo

```bash
SHIEP_PIPELINE_PASSWORD=<PASSWORD> cargo run -p ec-cli -- --server <VPN_SERVER> --username <USERNAME>
```

### Diagnostics

Debug builds expose an additional `--debug` flag:

```bash
SHIEP_PIPELINE_PASSWORD=<PASSWORD> cargo run -p ec-cli -- --server <VPN_SERVER> --username <USERNAME> --debug
```

This enables verbose protocol diagnostics such as TLS summaries, stream reconnect attempts, and raw abnormal protocol replies. Release builds do not include this flag or the diagnostic strings.

## Project Structure

- `crates/ec-cli`: CLI entry point and argument parsing
- `crates/ec-core`: Core implementation (login, protocol, tunnel, netstack, route-table parsing, and forwarding)
- `.github/workflows/build-release.yml`: Build and upload release artifacts on `release.published`

## Release Artifacts

The workflow triggers on GitHub Release `published` and uploads platform-specific binaries:

- Linux: `SHIEP-Pipeline-<tag>-linux-x64`
- macOS (Apple Silicon): `SHIEP-Pipeline-<tag>-macos-arm64`
- Windows: `SHIEP-Pipeline-<tag>-windows-x64.exe`

## Disclaimer

This project is for learning and research in authorized environments only.
Please follow your institution and network usage policies.

## Acknowledgements

- [NJUConnect](https://github.com/lyc8503/NJUConnect): the original upstream whose connection logic and behavior were referenced during this project's design.
- [EasierConnect](https://github.com/Yan233th/EasierConnect): a strengthened fork with much better logging and critical bug fixes, but with no routing/split-routing support.
