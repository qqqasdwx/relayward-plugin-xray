import { describe, expect, it } from "vitest"

import {
  cloneServices,
  configurationChanges,
  configurationForSave,
  configurationFromStored,
  configurationsEqual,
  defaultDNSConfiguration,
  lines,
  moveItem,
  nextDNSServerDefaults,
  nextRoutingRuleDefaults,
  nextServiceDefaults,
} from "@/configuration"
import { compatibilityFor } from "@/inboundCompatibility"

describe("configuration helpers", () => {
  it("creates an empty new-node configuration", () => {
    const value = configurationFromStored({ exists: false, node_id: "node-1" }, "zh-CN")
    expect(value.xray_version).toBe("26.3.27")
    expect(value.services).toEqual([])
    expect(value.dns).toEqual(defaultDNSConfiguration("zh-CN"))
  })

  it("creates an inbound only when requested and preserves list order", () => {
    const service = nextServiceDefaults([], [])
    expect(service.service_id).toBe("vless-reality")
    expect(service.tcp.header.type).toBe("none")
    expect(service.sniffing.dest_override).toEqual(["http", "tls", "quic", "fakedns"])
    expect(nextServiceDefaults([service], []).service_id).toBe("vless-reality-2")
    const rule = nextRoutingRuleDefaults([], "en")
    expect(nextRoutingRuleDefaults([rule], "en").rule_id).toBe("routing-rule-2")
    const server = nextDNSServerDefaults([], "en")
    expect(nextDNSServerDefaults([server], "en").server_id).toBe("dns-server-2")
    expect(moveItem(["first", "second"], 1, -1)).toEqual(["second", "first"])
  })

  it("creates Shadowsocks defaults without VLESS-only settings", () => {
    const service = nextServiceDefaults([], [
      { id: "vless-reality", display_name: "VLESS REALITY" },
      { id: "shadowsocks", display_name: "Shadowsocks" },
    ], "shadowsocks")
    expect(service).toMatchObject({
      type: "shadowsocks",
      service_id: "shadowsocks",
      display_name: "Shadowsocks",
      port: 8388,
      public_port: 8388,
      shadowsocks: {
        method: "2022-blake3-aes-256-gcm",
        network: "tcp,udp",
        server_key: "",
        iv_check: true,
      },
    })
    expect(service.vless_reality).toBeUndefined()
    expect(compatibilityFor(service).every((entry) => entry.supported)).toBe(true)
  })

  it("normalizes lines and sorts services only for publication", () => {
    const first = nextServiceDefaults([], [])
    const second = cloneServices([{ ...first, service_id: "alpha" }])[0]
    const draft = configurationFromStored({ exists: false, node_id: "node-1" }, "en")
    draft.services = [first, second]
    expect(configurationForSave(draft).services.map((service) => service.service_id)).toEqual(["alpha", "vless-reality"])
    expect(draft.services.map((service) => service.service_id)).toEqual(["vless-reality", "alpha"])
    expect(lines(" example.com\n\napi.example.com \r\n")).toEqual(["example.com", "api.example.com"])
  })

  it("returns to a clean state when a value is changed and restored", () => {
    const baseline = configurationFromStored({ exists: false, node_id: "node-1" }, "en")
    const draft = configurationForSave(baseline)
    draft.api_port = 20000
    expect(configurationsEqual(baseline, draft)).toBe(false)
    draft.api_port = baseline.api_port
    expect(configurationsEqual(baseline, draft)).toBe(true)
  })

  it("compares record keys independently of insertion order", () => {
    const baseline = configurationFromStored({ exists: false, node_id: "node-1" }, "en")
    const service = nextServiceDefaults([], [])
    service.tcp.header = {
      type: "http",
      request: { version: "1.1", method: "GET", path: ["/"], headers: { Host: ["example.com"], Accept: ["*/*"] } },
      response: { version: "1.1", status: "200", reason: "OK", headers: {} },
    }
    baseline.services = [service]
    const draft = configurationForSave(baseline)
    const request = draft.services[0]?.tcp.header.request
    if (request == null) throw new Error("expected HTTP request")
    request.headers = { Accept: ["*/*"], Host: ["example.com"] }
    expect(configurationsEqual(baseline, draft)).toBe(true)
  })

  it("summarizes runtime, entity, DNS, and ordering changes", () => {
    const baseline = configurationFromStored({ exists: false, node_id: "node-1" }, "en")
    const firstService = nextServiceDefaults([], [])
    const removedService = { ...nextServiceDefaults([firstService], []), display_name: "Removed inbound" }
    baseline.services = [firstService, removedService]
    const firstRule = nextRoutingRuleDefaults([], "en")
    const secondRule = nextRoutingRuleDefaults([firstRule], "en")
    baseline.routing.rules = [firstRule, secondRule]
    const draft = configurationForSave(baseline)
    draft.xray_version = "26.4.1"
    draft.services = [{ ...draft.services[0]!, display_name: "Updated inbound" }, { ...nextServiceDefaults(draft.services, []), display_name: "Added inbound" }]
    draft.routing.rules = [draft.routing.rules[1]!, draft.routing.rules[0]!]
    draft.dns.enabled = true
    draft.dns.servers[0] = { ...draft.dns.servers[0]!, address: "127.0.0.1" }

    expect(configurationChanges(baseline, draft)).toEqual({
      runtime: ["xray_version"],
      services: { added: ["Added inbound"], updated: ["Updated inbound"], removed: ["Removed inbound"], reordered: false },
      routing: { added: [], updated: [], removed: [], reordered: true },
      dns: ["enabled"],
      dnsServers: { added: [], updated: ["System DNS"], removed: [], reordered: false },
    })
  })
})
