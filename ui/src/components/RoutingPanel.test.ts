import { describe, expect, it } from "vitest"

import { routingCriteria, systemRoutingProtections } from "@/routingPresentation"
import type { ProxyService } from "@/types"

describe("systemRoutingProtections", () => {
  it("derives one user-facing protection summary for each enabled REALITY inbound", () => {
    const protections = systemRoutingProtections([
      service("primary", "Primary", true, "www.tesla.com:443"),
      service("disabled", "Disabled", false, "example.com:443"),
      { ...service("shadowsocks", "Shadowsocks", true, "unused.example:443"), type: "shadowsocks", vless_reality: undefined },
    ])

    expect(protections).toEqual([{ serviceID: "primary", serviceName: "Primary", sni: "www.tesla.com" }])
  })
})

describe("routingCriteria", () => {
  it("keeps only populated match categories in their evaluation order", () => {
    expect(routingCriteria({
      rule_id: "rule-1",
      display_name: "Block trackers",
      enabled: true,
      source_ips: ["192.0.2.1"],
      source_port: "",
      vless_route: "",
      network: "tcp",
      protocols: ["bittorrent"],
      attributes: {},
      destination_ips: [],
      domains: ["domain:tracker.example"],
      users: [],
      destination_port: "443",
      inbound_tags: [],
      outbound_tag: "blocked",
    })).toEqual([
      { kind: "source_ips", values: ["192.0.2.1"] },
      { kind: "network", values: ["TCP"] },
      { kind: "protocols", values: ["BitTorrent"] },
      { kind: "domains", values: ["domain:tracker.example"] },
      { kind: "destination_port", values: ["443"] },
    ])
  })
})

function service(serviceID: string, displayName: string, enabled: boolean, target: string): ProxyService {
  return {
    type: "vless-reality",
    enabled,
    service_id: serviceID,
    display_name: displayName,
    listen: "0.0.0.0",
    port: 443,
    tcp: { accept_proxy_protocol: false, header: { type: "none" } },
    sniffing: { enabled: true, dest_override: ["http", "tls", "quic"], metadata_only: false, route_only: true, ips_excluded: [], domains_excluded: [] },
    vless_reality: { target },
  }
}
