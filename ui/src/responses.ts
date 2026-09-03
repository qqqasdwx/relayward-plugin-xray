import type {
  AccessRule,
  EditableConfiguration,
  EgressLine,
  EgressProbe,
  EndpointPortDiagnostic,
  NetworkAddress,
  NodeAuthorization,
  ProxyService,
  RoutingProtocol,
  ServicePortDiagnostic,
  ServiceType,
  StoredConfiguration,
  XrayVersion,
} from "@/types"

const routingProtocols = new Set<RoutingProtocol>(["http", "tls", "quic", "bittorrent"])

export function parseServiceTypes(value: unknown): ServiceType[] {
  return array(object(value).service_types).map((item) => {
    const entry = object(item)
    return { id: string(entry.id), display_name: string(entry.display_name) }
  })
}

export function parseXrayVersions(value: unknown): XrayVersion[] {
  return array(object(value).versions).map((item) => {
    const entry = object(item)
    return { version: string(entry.version), prerelease: boolean(entry.prerelease) }
  })
}

export function parseStored(value: unknown): StoredConfiguration {
  const record = object(value)
  const result: StoredConfiguration = { exists: boolean(record.exists), node_id: string(record.node_id) }
  if (!result.exists) return result
  result.generation = integer(record.generation)
  result.version = optionalString(record.version)
  result.sha256 = optionalString(record.sha256)
  result.configuration = parseConfiguration(record.configuration)
  return result
}

export function parseDiagnostics(value: unknown): ServicePortDiagnostic[] {
  return array(object(value).diagnostics).map((item) => {
    const entry = object(item)
    const network = string(entry.network)
    const state = string(entry.local_state)
    if (network !== "tcp" && network !== "udp") throw new Error("invalid network diagnostic")
    if (state !== "unknown" && state !== "listening" && state !== "not_listening") throw new Error("invalid network diagnostic")
    return {
      service_id: string(entry.service_id),
      network,
      local_port: integer(entry.local_port),
      listen_address: string(entry.listen_address),
      local_state: state,
      local_observed_at_unix_nano: unixNano(entry.local_observed_at_unix_nano),
      endpoints: array(entry.endpoints).map(parseEndpointDiagnostic),
    }
  })
}

export function parseAddresses(value: unknown): NetworkAddress[] {
  return array(object(value).addresses).map((item) => {
    const entry = object(item)
    const family = string(entry.family)
    if (family !== "ipv4" && family !== "ipv6") throw new Error("invalid address")
    return { address: string(entry.address), family, interface: string(entry.interface) }
  })
}

export function parseAuthorizations(value: unknown): NodeAuthorization[] {
  return array(object(value).authorizations).map((item) => {
    const entry = object(item)
    return {
      id: string(entry.id),
      user_identifier: string(entry.userIdentifier ?? entry.user_identifier),
      enabled: boolean(entry.enabled),
      service_ids: strings(entry.serviceIds ?? entry.service_ids),
    }
  })
}

export function parseProbe(value: unknown): EgressProbe {
  const entry = object(value)
  return {
    line_id: string(entry.line_id),
    address: string(entry.address),
    country: optionalString(entry.country),
    colocation: optionalString(entry.colocation),
    observed_at_unix_nano: unixNano(entry.observed_at_unix_nano),
    elapsed_millis: integer(entry.elapsed_millis),
  }
}

function parseConfiguration(value: unknown): EditableConfiguration {
  const record = object(value)
  return {
    xray_version: string(record.xray_version),
    services: array(record.services).map(parseService),
    egress_lines: array(record.egress_lines).map(parseEgressLine),
    access_rules: array(record.access_rules).map(parseAccessRule),
  }
}

function parseService(value: unknown): ProxyService {
  const record = object(value)
  const type = string(record.type)
  if (type !== "vless-reality" && type !== "shadowsocks") throw new Error("invalid service")
  const result: ProxyService = {
    type,
    enabled: boolean(record.enabled),
    service_id: string(record.service_id),
    display_name: string(record.display_name),
    port: integer(record.port),
    accept_proxy_protocol: boolean(record.accept_proxy_protocol),
  }
  if (type === "vless-reality") {
    result.vless_reality = { target: string(object(record.vless_reality).target) }
  } else {
    const method = shadowsocksMethod(object(record.shadowsocks).method)
    result.shadowsocks = { method }
  }
  return result
}

function parseEgressLine(value: unknown): EgressLine {
  const record = object(value)
  const type = string(record.type)
  if (type !== "direct" && type !== "socks5" && type !== "shadowsocks") throw new Error("invalid egress line")
  const result: EgressLine = {
    line_id: string(record.line_id),
    display_name: string(record.display_name),
    enabled: boolean(record.enabled),
    vless_route: integer(record.vless_route),
    type,
  }
  if (type === "direct") {
    result.direct = { send_through: string(object(record.direct).send_through) }
  }
  if (type === "socks5") {
    const item = object(record.socks5)
    result.socks5 = {
      address: string(item.address),
      port: integer(item.port),
      use_authentication: boolean(item.use_authentication),
      username: string(item.username),
      password: string(item.password),
      password_configured: boolean(item.password_configured),
    }
  }
  if (type === "shadowsocks") {
    const item = object(record.shadowsocks)
    result.shadowsocks = {
      address: string(item.address),
      port: integer(item.port),
      method: shadowsocksMethod(item.method),
      password: string(item.password),
      password_configured: boolean(item.password_configured),
    }
  }
  return result
}

function parseAccessRule(value: unknown): AccessRule {
  const record = object(value)
  const action = string(record.action)
  if (action !== "block" && action !== "egress") throw new Error("invalid access rule")
  const network = string(record.network)
  if (network !== "" && network !== "tcp" && network !== "udp" && network !== "tcp,udp") throw new Error("invalid network")
  const protocols = strings(record.protocols)
  if (!protocols.every((protocol): protocol is RoutingProtocol => routingProtocols.has(protocol as RoutingProtocol))) {
    throw new Error("invalid routing protocol")
  }
  return {
    rule_id: string(record.rule_id),
    display_name: string(record.display_name),
    enabled: boolean(record.enabled),
    source_ips: strings(record.source_ips),
    network,
    protocols,
    destination_ips: strings(record.destination_ips),
    domains: strings(record.domains),
    destination_port: string(record.destination_port),
    authorization_ids: strings(record.authorization_ids),
    service_ids: strings(record.service_ids),
    action,
    egress_line_id: optionalString(record.egress_line_id),
  }
}

function parseEndpointDiagnostic(value: unknown): EndpointPortDiagnostic {
  const entry = object(value)
  const kind = string(entry.kind)
  const reachability = string(entry.reachability)
  const reason = string(entry.reason)
  if (kind !== "direct" && kind !== "nat" && kind !== "domain" && kind !== "managed_ddns") throw new Error("invalid endpoint diagnostic")
  if (reachability !== "reachable" && reachability !== "unreachable" && reachability !== "not_tested") throw new Error("invalid endpoint diagnostic")
  if (reason !== "" && reason !== "node_offline" && reason !== "local_not_listening" && reason !== "endpoint_unavailable" &&
    reason !== "proxied_endpoint" && reason !== "unsupported_network" && reason !== "dns_failed" &&
    reason !== "connection_refused" && reason !== "timeout" && reason !== "network_unreachable") {
    throw new Error("invalid endpoint diagnostic")
  }
  return {
    endpoint_id: string(entry.endpoint_id),
    display_name: string(entry.display_name),
    kind,
    address: string(entry.address),
    port: integer(entry.port),
    reachability,
    reason,
  }
}

function shadowsocksMethod(value: unknown): "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm" {
  const method = string(value)
  if (method !== "2022-blake3-aes-128-gcm" && method !== "2022-blake3-aes-256-gcm") throw new Error("invalid method")
  return method
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value == null || Array.isArray(value)) throw new Error("invalid response")
  return value as Record<string, unknown>
}

function array(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error("invalid response")
  return value
}

function string(value: unknown): string {
  if (typeof value !== "string") throw new Error("invalid response")
  return value
}

function optionalString(value: unknown): string | undefined {
  return value == null ? undefined : string(value)
}

function boolean(value: unknown): boolean {
  if (typeof value !== "boolean") throw new Error("invalid response")
  return value
}

function integer(value: unknown): number {
  if (!Number.isSafeInteger(value)) throw new Error("invalid response")
  return value as number
}

function unixNano(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) throw new Error("invalid response")
  return value
}

function strings(value: unknown): string[] {
  return array(value).map(string)
}
