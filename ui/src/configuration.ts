import type { AccessRule, EditableConfiguration, EgressLine, ProxyService, ServiceType, StoredConfiguration } from "@/types"

export const RANDOM_PORT_MIN = 20000
export const RANDOM_PORT_MAX = 29999

export function randomServicePort(excludedPorts: number[], previousPort?: number): number {
  const excluded = new Set(excludedPorts)
  if (previousPort != null) excluded.add(previousPort)
  const size = RANDOM_PORT_MAX - RANDOM_PORT_MIN + 1
  const random = new Uint32Array(1)
  for (let attempt = 0; attempt < 100; attempt += 1) {
    crypto.getRandomValues(random)
    const candidate = RANDOM_PORT_MIN + random[0]! % size
    if (!excluded.has(candidate)) return candidate
  }
  for (let candidate = RANDOM_PORT_MIN; candidate <= RANDOM_PORT_MAX; candidate += 1) {
    if (!excluded.has(candidate)) return candidate
  }
  throw new Error("No listening port is available")
}

export function defaultEgressLine(): EgressLine {
  return { line_id: "default", display_name: "Default", enabled: true, vless_route: 0, type: "direct", direct: { send_through: "" } }
}

export function nextServiceDefaults(services: ProxyService[], serviceTypes: ServiceType[], preferredType?: string, reservedPorts: number[] = []): ProxyService {
  const requested = preferredType ?? serviceTypes[0]?.id ?? "vless-reality"
  const type = requested === "shadowsocks" ? "shadowsocks" : "vless-reality"
  const prefix = type === "shadowsocks" ? "shadowsocks" : "vless-reality"
  const serviceID = nextID(prefix, services.map((service) => service.service_id))
  const common = {
    type, enabled: true, service_id: serviceID,
    display_name: type === "shadowsocks" ? "Shadowsocks" : "VLESS Reality",
    port: randomServicePort([...services.map((service) => service.port), ...reservedPorts]),
    accept_proxy_protocol: false,
  } satisfies Omit<ProxyService, "vless_reality" | "shadowsocks">
  if (type === "shadowsocks") return { ...common, type, shadowsocks: { method: "2022-blake3-aes-256-gcm" } }
  return { ...common, type, vless_reality: { target: "www.tesla.com:443" } }
}

export function nextEgressLineDefaults(lines: EgressLine[], preferredType: EgressLine["type"] = "direct"): EgressLine {
  const lineID = nextID("line", lines.map((line) => line.line_id))
  const usedRoutes = new Set(lines.map((line) => line.vless_route))
  let route = 1
  while (usedRoutes.has(route)) route += 1
  const common = { line_id: lineID, display_name: `Line ${lines.length}`, enabled: true, vless_route: route, type: preferredType }
  if (preferredType === "socks5") return { ...common, type: preferredType, socks5: { address: "", port: 1080, use_authentication: false, username: "", password: "", password_configured: false } }
  if (preferredType === "shadowsocks") return { ...common, type: preferredType, shadowsocks: { address: "", port: 8388, method: "2022-blake3-aes-256-gcm", password: "", password_configured: false } }
  return { ...common, type: preferredType, direct: { send_through: "" } }
}

export function nextAccessRuleDefaults(rules: AccessRule[]): AccessRule {
  return {
    rule_id: nextID("access-rule", rules.map((rule) => rule.rule_id)), display_name: "", enabled: true,
    source_ips: [], network: "", protocols: [], destination_ips: [], domains: [], destination_port: "",
    authorization_ids: [], service_ids: [], action: "block",
  }
}

export function configurationFromStored(stored: StoredConfiguration, defaultVersion = "26.7.28"): EditableConfiguration {
  if (!stored.exists || stored.configuration == null) {
    return { xray_version: defaultVersion, services: [], egress_lines: [defaultEgressLine()], access_rules: [] }
  }
  return cloneConfiguration(stored.configuration)
}

export function configurationForSave(value: EditableConfiguration): EditableConfiguration {
  const result = cloneConfiguration(value)
  result.xray_version = result.xray_version.trim()
  result.services.sort((first, second) => first.service_id.localeCompare(second.service_id))
  return result
}

export function configurationsEqual(first: EditableConfiguration, second: EditableConfiguration): boolean {
  return JSON.stringify(configurationForSave(first)) === JSON.stringify(configurationForSave(second))
}

export function cloneConfiguration(value: EditableConfiguration): EditableConfiguration {
  return {
    xray_version: value.xray_version,
    services: value.services.map((service) => ({ ...service, vless_reality: service.vless_reality == null ? undefined : { ...service.vless_reality }, shadowsocks: service.shadowsocks == null ? undefined : { ...service.shadowsocks } })),
    egress_lines: value.egress_lines.map((line) => ({ ...line, direct: line.direct == null ? undefined : { ...line.direct }, socks5: line.socks5 == null ? undefined : { ...line.socks5 }, shadowsocks: line.shadowsocks == null ? undefined : { ...line.shadowsocks } })),
    access_rules: value.access_rules.map((rule) => ({ ...rule, source_ips: [...rule.source_ips], protocols: [...rule.protocols], destination_ips: [...rule.destination_ips], domains: [...rule.domains], authorization_ids: [...rule.authorization_ids], service_ids: [...rule.service_ids] })),
  }
}

export function moveItem<T>(values: T[], index: number, offset: number): T[] {
  const target = index + offset
  if (target < 0 || target >= values.length) return values
  const result = [...values]
  ;[result[index], result[target]] = [result[target], result[index]]
  return result
}

export function csv(value: string): string[] {
  return [...new Set(value.split(",").map((item) => item.trim()).filter(Boolean))]
}

function nextID(prefix: string, existing: string[]): string {
  if (!existing.includes(prefix)) return prefix
  let suffix = 2
  while (existing.includes(`${prefix}-${suffix}`)) suffix += 1
  return `${prefix}-${suffix}`
}
