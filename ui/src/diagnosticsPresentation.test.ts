import { describe, expect, it } from "vitest"

import { firewallCommand, probeReasonMessage } from "@/diagnosticsPresentation"
import type { EndpointPortDiagnostic, ServicePortDiagnostic } from "@/types"

const diagnostic: ServicePortDiagnostic = {
  service_id: "vless-main",
  network: "tcp",
  local_port: 23456,
  listen_address: "0.0.0.0",
  local_state: "listening",
  local_observed_at_unix_nano: 1,
  endpoints: [],
}

const endpoint: EndpointPortDiagnostic = {
  endpoint_id: "nat",
  display_name: "NAT",
  kind: "nat",
  address: "edge.example.com",
  port: 45142,
  reachability: "unreachable",
  reason: "timeout",
}

describe("port diagnostic presentation", () => {
  it("generates a UFW command for the local listener rather than the public NAT port", () => {
    expect(firewallCommand(diagnostic, endpoint)).toBe("ufw allow 23456/tcp")
  })

  it("does not suggest firewall changes without a matching public connection failure", () => {
    expect(firewallCommand(diagnostic, { ...endpoint, reachability: "reachable", reason: "" })).toBe("")
    expect(firewallCommand({ ...diagnostic, local_state: "not_listening" }, endpoint)).toBe("")
    expect(firewallCommand(diagnostic, { ...endpoint, reason: "dns_failed" })).toBe("")
  })

  it("maps every probe reason to standalone interface copy", () => {
    expect(probeReasonMessage("connection_refused")).toBe("The public endpoint refused the connection.")
    expect(probeReasonMessage("")).toBe("")
  })
})
