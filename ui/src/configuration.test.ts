import { describe, expect, it } from "vitest"

import { configurationForSave, configurationFromStored, configurationsEqual, defaultEgressLine, moveItem, nextAccessRuleDefaults, nextEgressLineDefaults, nextServiceDefaults, randomServicePort } from "@/configuration"

describe("personal Xray configuration", () => {
  it("starts with no inbound and one fixed default egress line", () => {
    expect(configurationFromStored({ exists: false, node_id: "node" }, "26.8.1")).toEqual({
      xray_version: "26.8.1", services: [], egress_lines: [defaultEgressLine()], access_rules: [],
    })
  })

  it("creates only approved inbound fields", () => {
    const service = nextServiceDefaults([], [{ id: "vless-reality", display_name: "VLESS" }])
    expect(service).toMatchObject({ type: "vless-reality", accept_proxy_protocol: false, vless_reality: { target: "www.tesla.com:443" } })
    expect(service.port).toBeGreaterThanOrEqual(20000)
    expect(service.port).toBeLessThanOrEqual(29999)
    const shadowsocks = nextServiceDefaults([service], [], "shadowsocks")
    expect(shadowsocks).toMatchObject({ type: "shadowsocks", shadowsocks: { method: "2022-blake3-aes-256-gcm" } })
  })

  it("allocates unique VLESS routes for named egress lines", () => {
    const first = nextEgressLineDefaults([defaultEgressLine()])
    const second = nextEgressLineDefaults([defaultEgressLine(), first], "socks5")
    expect(first.vless_route).toBe(1)
    expect(second.vless_route).toBe(2)
    expect(second.socks5).toBeDefined()
  })

  it("returns to clean when an edit is reverted", () => {
    const baseline = configurationFromStored({ exists: false, node_id: "node" })
    const draft = configurationForSave(baseline)
    draft.xray_version = "26.8.1"
    expect(configurationsEqual(baseline, draft)).toBe(false)
    draft.xray_version = baseline.xray_version
    expect(configurationsEqual(baseline, draft)).toBe(true)
  })

  it("creates ordered access rules and list moves", () => {
    const first = nextAccessRuleDefaults([])
    const second = nextAccessRuleDefaults([first])
    expect(first.rule_id).toBe("access-rule")
    expect(second.rule_id).toBe("access-rule-2")
    expect(moveItem([first, second], 1, -1)).toEqual([second, first])
  })

  it("does not reuse the previous or occupied random port", () => {
    const first = randomServicePort([20000, 20001])
    const second = randomServicePort([20000, 20001, first], first)
    expect(second).not.toBe(first)
    expect([20000, 20001]).not.toContain(first)
    expect([20000, 20001]).not.toContain(second)
  })
})
