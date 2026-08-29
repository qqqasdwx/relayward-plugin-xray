import type {
  DNSConfiguration,
  DNSServer,
  EditableConfiguration,
  Locale,
  ProxyService,
  RoutingRule,
  ServiceType,
  StoredConfiguration,
} from "@/types"

export function cloneServices(values: ProxyService[]): ProxyService[] {
  return values.map((service) => ({
    ...service,
    tcp: {
      ...service.tcp,
      header: {
        ...service.tcp.header,
        request: service.tcp.header.request == null ? undefined : {
          ...service.tcp.header.request,
          path: [...service.tcp.header.request.path],
          headers: cloneHeaders(service.tcp.header.request.headers),
        },
        response: service.tcp.header.response == null ? undefined : {
          ...service.tcp.header.response,
          headers: cloneHeaders(service.tcp.header.response.headers),
        },
      },
    },
    sockopt: service.sockopt == null ? undefined : {
      ...service.sockopt,
      custom: service.sockopt.custom.map((option) => ({ ...option })),
    },
    sniffing: {
      ...service.sniffing,
      dest_override: [...service.sniffing.dest_override],
      ips_excluded: [...service.sniffing.ips_excluded],
      domains_excluded: [...service.sniffing.domains_excluded],
    },
    vless_reality: service.vless_reality == null ? undefined : {
      ...service.vless_reality,
      test_seed: [...service.vless_reality.test_seed],
      fallbacks: service.vless_reality.fallbacks.map((fallback) => ({ ...fallback })),
      server_names: [...service.vless_reality.server_names],
      short_ids: [...service.vless_reality.short_ids],
      limit_fallback_upload: service.vless_reality.limit_fallback_upload == null ? undefined : { ...service.vless_reality.limit_fallback_upload },
      limit_fallback_download: service.vless_reality.limit_fallback_download == null ? undefined : { ...service.vless_reality.limit_fallback_download },
    },
    shadowsocks: service.shadowsocks == null ? undefined : { ...service.shadowsocks },
  }))
}

function cloneHeaders(values: Record<string, string[]>): Record<string, string[]> {
  return Object.fromEntries(Object.entries(values).map(([name, entries]) => [name, [...entries]]))
}

export function cloneRoutingRules(values: RoutingRule[]): RoutingRule[] {
  return values.map((rule) => ({
    ...rule,
    domains: [...rule.domains],
    ip_cidrs: [...rule.ip_cidrs],
    protocols: [...rule.protocols],
  }))
}

export function cloneDNSConfiguration(value: DNSConfiguration): DNSConfiguration {
  return {
    enabled: value.enabled,
    query_strategy: value.query_strategy,
    servers: value.servers.map((server) => ({ ...server, domains: [...server.domains] })),
  }
}

export function defaultDNSConfiguration(locale: Locale): DNSConfiguration {
  return {
    enabled: false,
    query_strategy: "use-ip",
    servers: [{
      server_id: "system",
      display_name: locale === "zh-CN" ? "系统 DNS" : "System DNS",
      enabled: true,
      transport: "system",
      address: "",
      port: 0,
      domains: [],
    }],
  }
}

export function nextServiceDefaults(services: ProxyService[], serviceTypes: ServiceType[], preferredType?: string): ProxyService {
  const serviceType = preferredType ?? serviceTypes[0]?.id ?? "vless-reality"
  const shadowsocks = serviceType === "shadowsocks"
  const idPrefix = shadowsocks ? "shadowsocks" : "vless-reality"
  let suffix = services.length === 0 ? 1 : 2
  let serviceID = services.every((service) => service.service_id !== idPrefix) ? idPrefix : `${idPrefix}-${suffix}`
  while (services.some((service) => service.service_id === serviceID)) {
    suffix += 1
    serviceID = `${idPrefix}-${suffix}`
  }
  let port = shadowsocks ? 8388 : services.length === 0 ? 443 : 8443
  while (services.some((service) => service.port === port) && port < 65535) port += 1
  const common: ProxyService = {
    type: serviceType,
    enabled: true,
    service_id: serviceID,
    display_name: shadowsocks ? "Shadowsocks" : services.length === 0 ? "VLESS Reality" : `VLESS Reality ${services.length + 1}`,
    listen: "0.0.0.0",
    port,
    public_host: "edge.example.com",
    public_port: port,
    tcp: {
      accept_proxy_protocol: false,
      header: { type: "none" },
    },
    sockopt: undefined,
    sniffing: {
      enabled: true,
      dest_override: ["http", "tls", "quic", "fakedns"],
      metadata_only: false,
      route_only: false,
      ips_excluded: [],
      domains_excluded: [],
    },
  }
  if (shadowsocks) {
    return {
      ...common,
      shadowsocks: {
        method: "2022-blake3-aes-256-gcm",
        network: "tcp,udp",
        server_key: "",
        iv_check: true,
      },
    }
  }
  return {
    ...common,
    vless_reality: {
      decryption: "none",
      encryption: "none",
      test_seed: [],
      fallbacks: [],
      show: false,
      xver: 0,
      target: "addons.mozilla.org:443",
      server_names: ["addons.mozilla.org"],
      private_key: "",
      public_key: "",
      short_ids: [],
      min_client_version: "1.0.0",
      max_client_version: "",
      max_time_diff: 0,
      mldsa65_seed: "",
      mldsa65_verify: "",
      master_key_log: "",
      flow: "xtls-rprx-vision",
      fingerprint: "chrome",
      spider_x: "/",
    },
  }
}

export function nextRoutingRuleDefaults(rules: RoutingRule[], locale: Locale): RoutingRule {
  let suffix = rules.length + 1
  let ruleID = `routing-rule-${suffix}`
  while (rules.some((rule) => rule.rule_id === ruleID)) {
    suffix += 1
    ruleID = `routing-rule-${suffix}`
  }
  return {
    rule_id: ruleID,
    display_name: locale === "zh-CN" ? `路由规则 ${suffix}` : `Routing rule ${suffix}`,
    enabled: true,
    domains: [],
    ip_cidrs: [],
    protocols: [],
    action: "blocked",
  }
}

export function nextDNSServerDefaults(servers: DNSServer[], locale: Locale): DNSServer {
  let suffix = servers.length + 1
  let serverID = `dns-server-${suffix}`
  while (servers.some((server) => server.server_id === serverID)) {
    suffix += 1
    serverID = `dns-server-${suffix}`
  }
  return {
    server_id: serverID,
    display_name: locale === "zh-CN" ? `DNS 服务器 ${suffix}` : `DNS server ${suffix}`,
    enabled: true,
    transport: "udp",
    address: "1.1.1.1",
    port: 53,
    domains: [],
  }
}

export function configurationFromStored(
  stored: StoredConfiguration,
  locale: Locale,
): EditableConfiguration {
  if (!stored.exists || stored.configuration == null) {
    return {
      xray_version: "26.3.27",
      api_port: 10085,
      services: [],
      routing: { rules: [] },
      dns: defaultDNSConfiguration(locale),
    }
  }
  const value = stored.configuration
  const dns = value.dns?.query_strategy || value.dns?.servers?.length > 0
    ? cloneDNSConfiguration(value.dns)
    : defaultDNSConfiguration(locale)
  return {
    xray_version: value.xray_version,
    api_port: value.api_port,
    services: cloneServices(Array.isArray(value.services) ? value.services : []),
    routing: { rules: cloneRoutingRules(Array.isArray(value.routing?.rules) ? value.routing.rules : []) },
    dns,
  }
}

export function configurationForSave(value: EditableConfiguration): EditableConfiguration {
  return {
    xray_version: value.xray_version.trim(),
    api_port: value.api_port,
    services: cloneServices(value.services).sort((first, second) => first.service_id.localeCompare(second.service_id)),
    routing: { rules: cloneRoutingRules(value.routing.rules) },
    dns: cloneDNSConfiguration(value.dns),
  }
}

export interface NamedChanges {
  added: string[]
  updated: string[]
  removed: string[]
  reordered: boolean
}

export interface ConfigurationChanges {
  runtime: Array<"xray_version" | "api_port">
  services: NamedChanges
  routing: NamedChanges
  dns: Array<"enabled" | "query_strategy">
  dnsServers: NamedChanges
}

export function configurationsEqual(first: EditableConfiguration, second: EditableConfiguration): boolean {
  return deepEqual(configurationForSave(first), configurationForSave(second))
}

export function configurationChanges(before: EditableConfiguration, after: EditableConfiguration): ConfigurationChanges {
  const previous = configurationForSave(before)
  const current = configurationForSave(after)
  return {
    runtime: [
      ...(previous.xray_version === current.xray_version ? [] : ["xray_version" as const]),
      ...(previous.api_port === current.api_port ? [] : ["api_port" as const]),
    ],
    services: namedChanges(previous.services, current.services, (value) => value.service_id, (value) => value.display_name),
    routing: namedChanges(previous.routing.rules, current.routing.rules, (value) => value.rule_id, (value) => value.display_name),
    dns: [
      ...(previous.dns.enabled === current.dns.enabled ? [] : ["enabled" as const]),
      ...(previous.dns.query_strategy === current.dns.query_strategy ? [] : ["query_strategy" as const]),
    ],
    dnsServers: namedChanges(previous.dns.servers, current.dns.servers, (value) => value.server_id, (value) => value.display_name),
  }
}

function namedChanges<T>(before: T[], after: T[], id: (value: T) => string, name: (value: T) => string): NamedChanges {
  const previous = new Map(before.map((value) => [id(value), value]))
  const current = new Map(after.map((value) => [id(value), value]))
  const sharedBefore = before.map(id).filter((value) => current.has(value))
  const sharedAfter = after.map(id).filter((value) => previous.has(value))
  return {
    added: after.filter((value) => !previous.has(id(value))).map(name),
    updated: after.filter((value) => previous.has(id(value)) && !deepEqual(previous.get(id(value)), value)).map(name),
    removed: before.filter((value) => !current.has(id(value))).map(name),
    reordered: !deepEqual(sharedBefore, sharedAfter),
  }
}

function deepEqual(first: unknown, second: unknown): boolean {
  if (Object.is(first, second)) return true
  if (Array.isArray(first) || Array.isArray(second)) {
    if (!Array.isArray(first) || !Array.isArray(second) || first.length !== second.length) return false
    return first.every((value, index) => deepEqual(value, second[index]))
  }
  if (isPlainRecord(first) || isPlainRecord(second)) {
    if (!isPlainRecord(first) || !isPlainRecord(second)) return false
    const firstKeys = Object.keys(first).sort()
    const secondKeys = Object.keys(second).sort()
    return deepEqual(firstKeys, secondKeys) && firstKeys.every((key) => deepEqual(first[key], second[key]))
  }
  return false
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}

export function lines(value: string): string[] {
  return value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean)
}

export function moveItem<T>(values: T[], index: number, offset: number): T[] {
  const target = index + offset
  if (target < 0 || target >= values.length) return values
  const result = [...values]
  ;[result[index], result[target]] = [result[target], result[index]]
  return result
}
