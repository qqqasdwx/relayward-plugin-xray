# Xray Plugin for Relayward

[![CI](https://github.com/qqqasdwx/relayward-plugin-xray/actions/workflows/ci.yml/badge.svg)](https://github.com/qqqasdwx/relayward-plugin-xray/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/qqqasdwx/relayward-plugin-xray)](https://github.com/qqqasdwx/relayward-plugin-xray/releases)
[![License](https://img.shields.io/github/license/qqqasdwx/relayward-plugin-xray)](LICENSE)

`relayward-plugin-xray` is an independently maintained Xray runtime plugin for Relayward, tailored to the maintainer's real deployments. The center artifact participates in Relayward plugin lifecycle management, while the node artifact installs and supervises an official Xray release on each node.

The plugin supports only the combinations documented below. It does not aim to expose every Xray protocol, transport, field, platform, or legacy configuration.

## Current Scope

- Linux AMD64 center and node artifacts
- responsive Simplified Chinese and English administration page
- multiple independent VLESS + REALITY + RAW Vision and Shadowsocks inbounds per node
- official stable `XTLS/Xray-core` release resolution
- bounded download with exact size and SHA-256 verification
- private, immutable Xray version installations
- Xray-native configuration checks with `xray run -test`
- process replacement with restoration of the previous healthy configuration when candidate startup fails
- dynamic authorization enforcement through Xray's local Handler API
- cumulative per-authorization upload and download counters through Xray's local Stats API
- recent accepted activity from Xray's online-user Stats API with a persistent telemetry cursor
- per-authorization dynamic source-IP blocking through Xray's local Routing API
- ordered static domain-suffix, destination-CIDR, and sniffed-protocol routing to direct or blocked outbounds
- ordered system, UDP, TCP, and DNS-over-HTTPS resolvers with global IPv4/IPv6 query strategy and per-server domain selection
- VLESS and Shadowsocks URI, Mihomo, and sing-box subscription contributions
- Relayward generation, digest, and health reporting

The current runtime supports up to 64 independently identified VLESS + REALITY + RAW Vision or Shadowsocks inbounds, 128 static routing rules, and 16 ordered DNS servers per node. Shadowsocks supports the `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, and `xchacha20-ietf-poly1305` methods over TCP, UDP, or both. Additional outbound types, protocols, transports, certificates, and full access-log collection are not implemented.

Recent activity is an online-presence signal rather than a full request log. While an authorization remains online, the plugin emits at most one accepted activity event per authorization, service, and source IP every 30 seconds. The stream ID, sequence cursor, unacknowledged events, and refresh index are stored atomically in a private state file so Agent retries and plugin restarts do not create sequence gaps. Dynamic blocks match authorization email, inbound service, and one source IP together, avoiding collateral blocking of another authorization behind the same NAT. Runtime routing replacement always rebuilds the complete managed rule set in API, dynamic-block, then static-rule order, so a static direct rule cannot bypass a Relayward soft IP block.

## Installation

This plugin requires a running [Relayward](https://github.com/Relayward/relayward) center and an enrolled, online Relayward Agent on each target node. The center and nodes must be Linux AMD64. Nodes require outbound HTTPS access to GitHub Releases and must expose the proxy ports configured below to their intended clients.

In the Relayward administration interface, open **Plugins**, select **Install plugin**, and enter:

```text
GitHub repository: https://github.com/qqqasdwx/relayward-plugin-xray
Version:           an existing release number without the leading v, for example 0.4.1
GitHub token:      leave empty for this public repository
```

Select **Check release**, inspect the manifest and artifacts, approve both requested permissions, and install the plugin:

- `core.node_plugins.configure` reads and publishes Xray configuration for managed nodes.
- `core.services.write` publishes Xray services for Relayward authorization bindings.

After installation, the plugin must report `active` and `healthy` before a node is configured.

## First Inbound

1. Open **Nodes**, view an enrolled, online node, and select its **Xray** tab.
2. Select a stable official Xray version and add a VLESS + RAW + REALITY or Shadowsocks inbound.
3. Review the listener, public host and port, and protocol-specific settings. Configure routing and DNS only when required.
4. Save the node configuration. The Agent installs the node artifact, the plugin downloads and verifies the official Xray release, starts Xray, and publishes the inbound through Relayward's internal service catalog.
5. Wait until **Plugins > Node instances** reports the desired generation as applied and the runtime as running.
6. Open the configured TCP port in the node firewall, provider firewall, and any NAT port mapping. Relayward and this plugin do not modify host firewall rules.
7. In Relayward, create a user and a node authorization, then use **Manage services** to bind the authorization to the published Xray service.
8. Open the authorization's subscription link and select the required URI, Mihomo, or sing-box output.

Verify that the subscription contains the configured public host and port, then connect a real client through the inbound. Relayward should report the authorization as active, update traffic counters, and show recent accepted activity after traffic is generated.

## Configuration

Relayward treats runtime-plugin configuration as opaque JSON. The Xray plugin owns the following structure:

```json
{
  "xray_version": "26.3.27",
  "api_port": 10085,
  "credential_seed": "base64url-encoded-32-byte-secret",
  "services": [
    {
      "type": "vless-reality",
      "enabled": true,
      "service_id": "reality-main",
      "display_name": "Reality Main",
      "listen": "0.0.0.0",
      "port": 443,
      "public_host": "edge.example.com",
      "public_port": 443,
      "tcp": {
        "accept_proxy_protocol": false,
        "header": {
          "type": "none"
        }
      },
      "sniffing": {
        "enabled": true,
        "dest_override": ["http", "tls", "quic", "fakedns"],
        "metadata_only": false,
        "route_only": false,
        "ips_excluded": [],
        "domains_excluded": []
      },
      "vless_reality": {
        "decryption": "none",
        "encryption": "none",
        "test_seed": [],
        "fallbacks": [],
        "show": false,
        "xver": 0,
        "target": "addons.mozilla.org:443",
        "server_names": ["addons.mozilla.org"],
        "private_key": "base64url-encoded-X25519-private-key",
        "short_ids": ["0123456789abcdef"],
        "min_client_version": "1.0.0",
        "max_client_version": "",
        "max_time_diff": 0,
        "mldsa65_seed": "",
        "mldsa65_verify": "",
        "master_key_log": "",
        "flow": "xtls-rprx-vision",
        "fingerprint": "chrome",
        "spider_x": "/"
      }
    },
    {
      "type": "shadowsocks",
      "enabled": true,
      "service_id": "shadowsocks-main",
      "display_name": "Shadowsocks Main",
      "listen": "0.0.0.0",
      "port": 8388,
      "public_host": "edge.example.com",
      "public_port": 8388,
      "sniffing": {
        "enabled": false,
        "dest_override": [],
        "metadata_only": false,
        "route_only": false,
        "ips_excluded": [],
        "domains_excluded": []
      },
      "shadowsocks": {
        "method": "2022-blake3-aes-256-gcm",
        "network": "tcp,udp",
        "server_key": "padded-base64-encoded-32-byte-secret",
        "iv_check": true
      }
    }
  ],
  "routing": {
    "rules": [
      {
        "rule_id": "block-private",
        "display_name": "Block private destinations",
        "enabled": true,
        "domains": [],
        "ip_cidrs": ["192.0.2.0/24"],
        "protocols": [],
        "action": "blocked"
      }
    ]
  },
  "dns": {
    "enabled": true,
    "query_strategy": "use-ipv4",
    "servers": [
      {
        "server_id": "regional",
        "display_name": "Regional DNS",
        "enabled": true,
        "transport": "doh",
        "address": "https://dns.example.com/dns-query",
        "port": 0,
        "domains": ["example.com"]
      },
      {
        "server_id": "system",
        "display_name": "System DNS",
        "enabled": true,
        "transport": "system",
        "address": "",
        "port": 0,
        "domains": []
      }
    ]
  }
}
```

The administration UI consistently calls these entries inbounds. The persisted `services[]` array and `service_id` fields are Relayward's internal cross-plugin contract. Each entry keeps the inbound identity and public endpoint at that contract level, while protocol-specific fields are stored in either `vless_reality` or `shadowsocks`. The inbound protocol cannot be changed after the entry is created.

Each internal service ID is unique within its node configuration and becomes the Xray inbound tag used by authorization control, telemetry, dynamic blocking, and subscription rendering. Entries are stored in service-ID order. The administration page generates a node credential seed, independent REALITY secrets for each new VLESS inbound, and a method-sized server key for each new Shadowsocks 2022 inbound. Editing an inbound preserves its secrets by ID; deleting it removes them.

Every Relayward authorization receives an independent, deterministic Shadowsocks password for each Shadowsocks inbound. Shadowsocks 2022 subscriptions combine the inbound server key and the authorization-specific user key as required by the protocol; traditional AEAD subscriptions contain only the authorization-specific password. The private bootstrap account used to keep a Shadowsocks 2022 inbound in Xray's multi-user mode is derived internally and is never exposed through subscriptions.

Static routing rules retain their configured order and have stable rule IDs. Values within one match category are alternatives, while every populated category on a rule must match. A domain value matches that domain and its subdomains; raw Xray expressions and regular expressions are not accepted. IP matches must use canonical IPv4 or IPv6 CIDR notation. Protocol matches are limited to `http`, `tls`, `quic`, and `bittorrent`; Xray reports HTTP/1 traffic as `http1`, which is covered by its `http` protocol-prefix matcher. Rules may send matching traffic only to the built-in `direct` or `blocked` outbound. Domain or protocol rules enable route-only HTTP, TLS, and QUIC sniffing on enabled inbounds, preserving the original connection target while making the sniffed destination available to routing.

DNS is disabled unless explicitly enabled. Enabling it makes Xray use the configured resolver list for routing fallback and direct outbound domain resolution; disabling it preserves the previous `AsIs` direct-outbound behavior. The global query strategy is `use-ip`, `use-ipv4`, or `use-ipv6`. Servers retain their configured order and may use the system resolver, classic UDP, local TCP, or local DNS-over-HTTPS. UDP and TCP endpoints require a canonical IP address and explicit port. DNS-over-HTTPS endpoints require a credential-free HTTPS URL and are rendered in Xray local mode to avoid recursive bootstrap through the configured resolver chain.

An empty server domain list makes that server a general fallback resolver. A populated list contains lowercase domain suffixes and restricts the server to those domains and their subdomains. When at least one domain-specific server matches, general fallback servers are not queried for that lookup. Disabled servers remain editable in Relayward but are omitted from the generated Xray configuration.

Unknown fields, prerelease Xray versions, duplicate inbound, rule, or DNS server IDs, conflicting listeners, invalid REALITY targets, noncanonical addresses or CIDRs, insecure DNS-over-HTTPS URLs, unsupported routing expressions, malformed keys, and trailing JSON are rejected. Relayward stores the opaque configuration through its encrypted plugin-configuration path.

The target is a starting value, not a universal deployment choice. It must be reachable from the node, support TLS 1.3, and complete a real REALITY handshake with the selected Xray release; a successful TCP or ordinary TLS probe alone is insufficient.

Each VLESS authorization receives a deterministic UUID derived as `HMAC-SHA256(credential_seed, authorization_id + NUL + service_id)`. Traditional Shadowsocks AEAD uses the same stable value as its password. Shadowsocks 2022 derives a method-sized base64 user key from the same node secret and identifiers with a protocol-specific domain separator. These credentials are stable for one node configuration, differ between authorizations, and cannot be derived from public Relayward identifiers without the node secret. Subscription rendering repeats the derivation without creating or mutating state.

## Release Trust

The node plugin queries the fixed official `XTLS/Xray-core` GitHub Release endpoint and selects only `Xray-linux-64.zip`. It requires the release to be published and stable, verifies the asset URL, bounds its size, and checks the SHA-256 digest supplied by GitHub before extraction. Xray is downloaded directly by the node plugin and is not bundled in Relayward plugin releases. Runtime control uses a persistent loopback gRPC connection and does not import or build Xray-core as a Go dependency. Routing API encoding supports both the legacy schema used through Xray `v26.7.10` and the geodata rule schema introduced in `v26.7.11`.

## Development

```sh
go test ./...
go vet ./...
go build ./...

cd ui
npm ci
npm run typecheck
npm run lint
npm test
npm run build
cd ..

./scripts/build-release.sh 0.0.0-dev /tmp/relayward-plugin-xray-release
```

Run `npm run dev` from `ui/` for local UI development. The page is a sandboxed iframe application and communicates with Relayward through the vendored UI SDK; a host simulator is required for standalone browser interaction.

Release builds contain `relayward-plugin.json`, separate center and node Linux AMD64 artifacts, the sandboxed UI archive, and `SHA256SUMS`.

## License

This plugin is licensed under GPL-3.0. Xray-core is an independent project distributed under MPL-2.0 and is downloaded from its official releases.
