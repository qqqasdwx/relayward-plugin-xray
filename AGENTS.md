# Xray Plugin for Relayward AGENTS.md

## Project Role

This repository owns an independently maintained Xray runtime plugin for Relayward. It is tailored to the maintainer's real deployments and adapts Relayward plugin contracts to an independently managed Xray process on a node.

The Relayward control plane, Agent runtime, shared SDK contracts, risk analysis, and protocol-specific product configuration do not belong in this repository.

## Architecture Boundaries

- Implement both the center and node plugin entry points required by the Relayward SDK.
- Keep Xray-specific configuration and lifecycle behavior inside this repository.
- Use official `XTLS/Xray-core` release artifacts by default. Do not build or depend on a maintained Xray fork.
- Support only explicitly documented deployment combinations. Do not pursue complete Xray protocol, transport, field, platform, or legacy-configuration coverage.
- Treat the plugin configuration as opaque to Relayward. Do not introduce protocol, certificate, inbound, or outbound product models until their requirements are explicitly approved.
- Do not add sing-box support here. A different runtime must use a separate plugin repository.

## Security

- Treat configuration, manifests, release metadata, archives, and RPC requests as untrusted input.
- Never log raw Xray configuration, credentials, private keys, subscription data, or access logs.
- Verify the size and SHA-256 digest of downloaded artifacts before installation.
- Reject unsafe archive paths, links, unexpected executable locations, unknown configuration fields, and unsupported platforms.
- Keep installed versions immutable and runtime configuration private to the plugin data directory.
- Start Xray in its own process group and terminate the group when replacing Xray or shutting down the plugin.

## Engineering Conventions

- Target Linux AMD64 only unless the supported platform policy is changed explicitly.
- Use the versioned contracts and helpers from `relayward-sdk`; do not duplicate shared protocol definitions.
- Keep release resolution, installation, configuration validation, and process supervision independently testable.
- Surface failures explicitly. Do not report a healthy generation until the matching Xray process is running.
- Preserve the last healthy process and configuration when candidate validation or startup fails.

## Plugin UI

- Build the administration page as an independent React, Vite, TypeScript, Tailwind CSS, and shadcn/ui iframe application. Do not depend on the control plane's React instance or private component paths.
- Use `shadcnstore/shadcn-dashboard-landing-template` as the approved visual and interaction baseline. Copy only the template components that are actually used, preserve applicable license notices, and keep their structure and original classes unless a build, accessibility, or responsive defect requires a focused correction.
- Prefer the copied shadcn components and Lucide icons over handwritten buttons, dialogs, inputs, selects, tabs, tooltips, badges, switches, or a second component system.
- Use the semantic design tokens supplied by the Relayward UI SDK. Obtain locale, theme, RPC, navigation, and confirmation behavior through the versioned UI SDK; do not access the parent DOM or invent plugin-specific bridge messages.
- Default to Simplified Chinese and support English according to the host context. Support light and dark themes, a minimum width of 320px, keyboard interaction, visible focus states, and layouts without whole-page overflow or overlapping content.
- Package only the Vite production output in the UI release archive. Do not preserve the retired handwritten UI as a parallel implementation.

## Git And Releases

- Keep commits, tags, releases, and release notes within this repository.
- Use `qqqasdwx/relayward-plugin-xray` as `origin`; treat the archived organization repository as read-only upstream history.
- Do not push, tag, or publish a release without explicit confirmation.
- Release artifacts must include the plugin manifest and Linux AMD64 center and node binaries.
- Do not commit downloaded Xray archives, Xray binaries, generated release bundles, local state, or credentials.

## Validation

Full validation runs in GitHub Actions. The local development host is resource constrained, so default local validation to `git diff --check`, formatting or syntax checks, and small tests that directly cover the changed code. Do not routinely run full Go or frontend suites, production builds, or release packaging locally unless they are needed to diagnose a failure or the user explicitly requests them.

GitHub Actions must cover the checks relevant to each change:

- `go test ./...`
- `go vet ./...`
- `go build ./...`
- `npm --prefix ui run typecheck`
- `npm --prefix ui run lint`
- `npm --prefix ui test`
- `npm --prefix ui run build`
- release script and manifest validation when packaging changes

For material UI changes, also exercise the iframe through the real UI SDK message protocol in a browser at desktop and 320px widths, in Simplified Chinese and English, and in light and dark themes.

Prefer deterministic fake-Xray lifecycle tests during development. Use the real official artifact only for focused integration validation.

Pushing still requires explicit user confirmation. After an approved push, monitor every triggered workflow to completion; before that, report the commit as CI pending.
