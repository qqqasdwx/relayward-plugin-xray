import { describe, expect, it } from "vitest"

import {
  cloneServices,
  configurationForSave,
  configurationFromStored,
  defaultDNSConfiguration,
  lines,
  moveItem,
  nextDNSServerDefaults,
  nextRoutingRuleDefaults,
  nextServiceDefaults,
} from "@/configuration"

describe("configuration helpers", () => {
  it("creates a complete new-node configuration", () => {
    const value = configurationFromStored({ exists: false, node_id: "node-1" }, [{ id: "vless-reality", display_name: "VLESS Reality" }], "zh-CN")
    expect(value.xray_version).toBe("26.3.27")
    expect(value.services[0]?.service_id).toBe("vless-reality")
    expect(value.services[0]?.tcp.header.type).toBe("none")
    expect(value.services[0]?.sniffing.dest_override).toEqual(["http", "tls", "quic", "fakedns"])
    expect(value.dns).toEqual(defaultDNSConfiguration("zh-CN"))
  })

  it("creates unique defaults and preserves list order", () => {
    const service = nextServiceDefaults([], [])
    expect(nextServiceDefaults([service], []).service_id).toBe("vless-reality-2")
    const rule = nextRoutingRuleDefaults([], "en")
    expect(nextRoutingRuleDefaults([rule], "en").rule_id).toBe("routing-rule-2")
    const server = nextDNSServerDefaults([], "en")
    expect(nextDNSServerDefaults([server], "en").server_id).toBe("dns-server-2")
    expect(moveItem(["first", "second"], 1, -1)).toEqual(["second", "first"])
  })

  it("normalizes lines and sorts services only for publication", () => {
    const first = nextServiceDefaults([], [])
    const second = cloneServices([{ ...first, service_id: "alpha" }])[0]
    const draft = configurationFromStored({ exists: false, node_id: "node-1" }, [], "en")
    draft.services = [first, second]
    expect(configurationForSave(draft).services.map((service) => service.service_id)).toEqual(["alpha", "vless-reality"])
    expect(draft.services.map((service) => service.service_id)).toEqual(["vless-reality", "alpha"])
    expect(lines(" example.com\n\napi.example.com \r\n")).toEqual(["example.com", "api.example.com"])
  })
})
