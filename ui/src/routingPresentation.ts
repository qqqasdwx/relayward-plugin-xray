import type { ProxyService, RoutingRule } from "@/types"

export interface SystemRoutingProtection {
  serviceID: string
  serviceName: string
  sni: string
}

export interface RoutingCriterion {
  kind: string
  values: string[]
}

export function systemRoutingProtections(services: ProxyService[]): SystemRoutingProtection[] {
  return services.flatMap((service) => {
    if (!service.enabled || service.type !== "vless-reality" || service.vless_reality == null) return []
    return [{
      serviceID: service.service_id,
      serviceName: service.display_name,
      sni: realityTargetHost(service.vless_reality.target),
    }]
  })
}

export function routingCriteria(rule: RoutingRule): RoutingCriterion[] {
  return [
    { kind: "source_ips", values: rule.source_ips },
    { kind: "source_port", values: single(rule.source_port) },
    { kind: "vless_route", values: single(rule.vless_route) },
    { kind: "network", values: single(rule.network.toUpperCase()) },
    { kind: "protocols", values: rule.protocols.map((value) => value === "bittorrent" ? "BitTorrent" : value.toUpperCase()) },
    { kind: "attributes", values: Object.entries(rule.attributes).map(([key, value]) => `${key}: ${value}`) },
    { kind: "destination_ips", values: rule.destination_ips },
    { kind: "domains", values: rule.domains },
    { kind: "users", values: rule.users },
    { kind: "destination_port", values: single(rule.destination_port) },
  ].filter((criterion) => criterion.values.length > 0)
}

export function inboundNames(rule: RoutingRule, services: ProxyService[]): string[] {
  if (rule.inbound_tags.length === 0) return []
  const names = new Map(services.map((service) => [service.service_id, service.display_name]))
  return rule.inbound_tags.map((tag) => names.get(tag) ?? tag)
}

function single(value: string): string[] {
  return value === "" ? [] : [value]
}

function realityTargetHost(target: string): string {
  const separator = target.lastIndexOf(":")
  return separator > 0 ? target.slice(0, separator) : target
}
