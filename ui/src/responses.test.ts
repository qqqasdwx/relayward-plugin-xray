import { describe, expect, it } from "vitest"

import { parseDiagnostics, parseStored, parseXrayVersions } from "@/responses"

describe("plugin RPC response parsing", () => {
  it("parses official Xray versions and preserves prerelease state", () => {
    expect(parseXrayVersions({ versions: [
      { version: "26.8.1", prerelease: false },
      { version: "26.8.0", prerelease: true },
    ] })).toEqual([
      { version: "26.8.1", prerelease: false },
      { version: "26.8.0", prerelease: true },
    ])
    expect(() => parseXrayVersions({ versions: [{ version: "26.8.1", prerelease: "false" }] })).toThrow()
  })

  it("accepts only known diagnostic enums", () => {
    const response = {
      diagnostics: [{
        service_id: "vless-reality",
        network: "tcp",
        local_port: 24443,
        listen_address: "0.0.0.0",
        local_state: "listening",
        local_observed_at_unix_nano: Number("1788338799421725340"),
        endpoints: [{
          endpoint_id: "ipv6",
          display_name: "IPv6",
          kind: "direct",
          address: "2001:db8::1",
          port: 24443,
          reachability: "reachable",
          reason: "",
        }],
      }],
    }
    expect(parseDiagnostics(response)[0]?.endpoints[0]?.address).toBe("2001:db8::1")
    expect(parseDiagnostics(response)[0]?.local_observed_at_unix_nano).toBeGreaterThan(Number.MAX_SAFE_INTEGER)
    expect(() => parseDiagnostics({ diagnostics: [{ ...response.diagnostics[0], local_state: "ready" }] })).toThrow()
    expect(() => parseDiagnostics({ diagnostics: [{
      ...response.diagnostics[0],
      endpoints: [{ ...response.diagnostics[0].endpoints[0], reason: "unexpected" }],
    }] })).toThrow()
  })

  it("rejects unknown access-rule protocols in stored configuration", () => {
    const stored = {
      exists: true,
      node_id: "node",
      generation: 1,
      configuration: {
        xray_version: "26.8.1",
        services: [],
        egress_lines: [{
          line_id: "default", display_name: "Default", enabled: true,
          vless_route: 0, type: "direct", direct: { send_through: "" },
        }],
        access_rules: [{
          rule_id: "rule", display_name: "Rule", enabled: true,
          source_ips: [], network: "", protocols: ["unknown"], destination_ips: [],
          domains: [], destination_port: "443", authorization_ids: [], service_ids: [], action: "block",
        }],
      },
    }
    expect(() => parseStored(stored)).toThrow("invalid routing protocol")
  })
})
