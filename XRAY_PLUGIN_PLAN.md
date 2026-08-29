# Xray Plugin for Relayward Plan

## Goal

Provide an independently maintained Xray runtime integration for the maintainer's Relayward deployments without moving proxy-core concepts into the Relayward kernel. The plugin owns Xray installation, node configuration, runtime control, telemetry, dynamic blocking, subscription fragments, and its sandboxed administration page.

All stages target Linux AMD64 and official stable Xray releases. Scope is driven by real deployment requirements rather than complete Xray feature coverage. Existing configurations created for a different plugin ID are not migrated or read by this plugin.

## Design Rules

- A plugin instance manages one Xray process per node and may publish multiple independently identified services.
- Every service has a stable, node-local `service_id`. Authorization state, counters, activity, dynamic blocks, and subscription entries use that ID rather than a protocol-specific constant.
- Relayward keeps quota and authorization aggregation in the kernel. The plugin reports per-authorization, per-service facts.
- Secrets remain in encrypted opaque plugin configuration. The administration UI never receives private keys or the node credential seed.
- New service types must reuse the existing service-control and telemetry contracts. They must not introduce a parallel authorization or traffic model.
- Configuration changes are validated by both the plugin and the selected official Xray binary before replacing the last healthy process.

## Stage 1: Multi-Service VLESS REALITY Foundation

Status: implemented and validated on Debian/systemd and Alpine/OpenRC test nodes.

- Manage zero to 64 independent `vless-reality` services in `services[]`.
- Generate an independent REALITY private key and short ID for every new service.
- Generate deterministic authorization UUIDs from the node credential seed, authorization ID, and service ID.
- Publish every configured service to Relayward and render VLESS URI, Mihomo, and sing-box contributions per binding.
- Apply user enablement, cumulative traffic counters, recent online activity, and source-IP dynamic blocks to the correct inbound.
- Restore users and applicable block rules after configuration replacement or plugin restart.
- Provide responsive Chinese and English service-list CRUD and runtime settings in the sandboxed administration page.
- Validate a two-service lifecycle against an official Xray release.

Acceptance requires two enabled services on one node to start simultaneously, accept independent authorization state, produce two subscription entries, report separate counters for kernel aggregation, apply dynamic blocks to both inbounds, and recover state after restart or a failed configuration replacement.

## Stage 2: Service-Type Contract

Status: implemented and locally validated.

- Define the internal typed configuration boundary required for service types with different fields while preserving the common `service_id`, display name, enabled state, listener, and public endpoint semantics.
- Split shared service validation from type-specific Xray JSON and subscription rendering.
- Add conformance fixtures proving that every service type supports the capabilities it declares.
- Keep the administration page driven by explicit supported types; do not expose arbitrary raw Xray JSON.

No additional protocol or transport is selected by this stage. A service type is added only after its client compatibility, security defaults, certificate requirements, and subscription representations are approved.

## Stage 3: Additional Inbound Types

Status: Shadowsocks implemented and locally validated; further inbound types require separate approval.

- Support Shadowsocks 2022 AES and traditional AEAD methods over TCP, UDP, or both.
- Derive an independent credential for every authorization and service, including the server-key and user-key form required by Shadowsocks 2022 multi-user mode.
- Render Shadowsocks URI, Mihomo, and sing-box subscription contributions.
- Reuse Xray service control, traffic, activity, and dynamic-blocking behavior for Shadowsocks services.
- Validate Shadowsocks configuration startup and dynamic user addition against an official Xray release.
- Add further approved protocol and transport combinations one vertical slice at a time.
- For each slice, implement validation, Xray generation, runtime user control, counters, activity, dynamic blocking, all supported subscription formats, UI, and official-Xray integration coverage together.
- Introduce certificate lifecycle support before any inbound type that requires managed TLS certificates.

Further protocol priority is intentionally not fixed in this plan. It must be chosen from actual deployment and client requirements rather than inherited 3x-ui feature breadth.

## Stage 4: Routing, DNS, and Outbound Policy

Status: static direct/blocked routing and structured DNS implemented and validated with an official Xray release; additional outbound policy pending.

- Model reusable Xray routing, DNS, and outbound policy separately from inbound service identity.
- Implement ordered static rules for controlled domain-suffix, canonical destination-CIDR, and sniffed-protocol matches.
- Limit static actions to the built-in direct and blocked outbounds until additional outbound requirements are approved.
- Preserve Relayward-managed dynamic block rules ahead of static routing policy when either set changes.
- Validate rule ordering, stable IDs, values, actions, and collision behavior before Xray replacement.
- Keep sensitive destinations and activity data out of configuration logs and audit payloads.
- Provide ordered system, UDP, TCP, and DNS-over-HTTPS resolvers with global query strategy and per-server domain selection.
- Apply structured DNS to both routing fallback and direct outbound resolution without changing behavior while DNS is disabled.

The remaining work in this stage is any approved additional outbound type. This stage does not add a raw JSON escape hatch. Any advanced configuration surface must remain structured, reviewable, and compatible with Relayward rollback semantics.

## Stage 5: Production Acceptance

Status: pending earlier stages and an explicit release decision.

- Exercise release artifacts on Debian/systemd and low-resource Alpine/OpenRC nodes.
- Verify center interruption, Agent and plugin restarts, Xray upgrades, failed upgrades, configuration rollback, quota enforcement, subscription rendering, and soft IP recovery.
- Measure idle memory, CPU, telemetry cadence, and configuration replacement time with representative service and authorization counts.
- Complete security review, operator documentation, release notes, and explicit compatibility policy before the first production-supported plugin release.
