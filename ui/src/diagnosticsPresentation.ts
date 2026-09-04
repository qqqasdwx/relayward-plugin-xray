import type { EndpointPortDiagnostic, ServicePortDiagnostic } from "@/types"

const firewallReasons = new Set<EndpointPortDiagnostic["reason"]>([
  "connection_refused",
  "timeout",
  "network_unreachable",
])

export function firewallCommand(diagnostic: ServicePortDiagnostic, endpoint: EndpointPortDiagnostic): string {
  if (diagnostic.local_state !== "listening" || endpoint.reachability !== "unreachable" || !firewallReasons.has(endpoint.reason)) {
    return ""
  }
  return `ufw allow ${diagnostic.local_port}/${diagnostic.network}`
}

export function probeReasonMessage(reason: EndpointPortDiagnostic["reason"]): string {
  return ({
    node_offline: "The node is offline.",
    local_not_listening: "The local port is not listening.",
    endpoint_unavailable: "The public endpoint address is unavailable.",
    proxied_endpoint: "Proxied endpoints cannot be tested directly.",
    unsupported_network: "This network cannot be tested from the center.",
    dns_failed: "The endpoint domain could not be resolved.",
    connection_refused: "The public endpoint refused the connection.",
    timeout: "The public endpoint connection timed out.",
    network_unreachable: "The public endpoint network is unreachable.",
    "": "",
  })[reason]
}
