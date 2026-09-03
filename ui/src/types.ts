export type Locale = "zh-CN" | "en"
export type Theme = "light" | "dark"

export interface ServiceType { id: string; display_name: string }
export interface XrayVersion { version: string; prerelease: boolean }

export type ShadowsocksMethod = "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm"

export interface ProxyService {
  type: "vless-reality" | "shadowsocks"
  enabled: boolean
  service_id: string
  display_name: string
  port: number
  accept_proxy_protocol: boolean
  vless_reality?: { target: string }
  shadowsocks?: { method: ShadowsocksMethod }
}

export type EgressType = "direct" | "socks5" | "shadowsocks"
export interface DirectEgress { send_through: string }
export interface SOCKS5Egress {
  address: string; port: number; use_authentication: boolean
  username: string; password: string; password_configured: boolean
}
export interface ShadowsocksEgress {
  address: string; port: number; method: ShadowsocksMethod
  password: string; password_configured: boolean
}
export interface EgressLine {
  line_id: string
  display_name: string
  enabled: boolean
  vless_route: number
  type: EgressType
  direct?: DirectEgress
  socks5?: SOCKS5Egress
  shadowsocks?: ShadowsocksEgress
}

export type RoutingProtocol = "http" | "tls" | "quic" | "bittorrent"
export interface AccessRule {
  rule_id: string
  display_name: string
  enabled: boolean
  source_ips: string[]
  network: "" | "tcp" | "udp" | "tcp,udp"
  protocols: RoutingProtocol[]
  destination_ips: string[]
  domains: string[]
  destination_port: string
  authorization_ids: string[]
  service_ids: string[]
  action: "block" | "egress"
  egress_line_id?: string
}

export interface EditableConfiguration {
  xray_version: string
  services: ProxyService[]
  egress_lines: EgressLine[]
  access_rules: AccessRule[]
}

export interface StoredConfiguration {
  exists: boolean
  node_id: string
  generation?: number
  version?: string
  sha256?: string
  configuration?: EditableConfiguration
}

export interface NodeAuthorization {
  id: string; user_identifier: string; enabled: boolean; service_ids: string[]
}
export interface NetworkAddress { address: string; family: "ipv4" | "ipv6"; interface: string }
export interface EgressProbe {
  line_id: string; address: string; country?: string; colocation?: string
  observed_at_unix_nano: number; elapsed_millis: number
}

export type LocalListenerState = "unknown" | "listening" | "not_listening"
export type PortReachability = "reachable" | "unreachable" | "not_tested"
export type PortProbeReason = "" | "node_offline" | "local_not_listening" | "endpoint_unavailable" | "proxied_endpoint" | "unsupported_network" | "dns_failed" | "connection_refused" | "timeout" | "network_unreachable"
export interface EndpointPortDiagnostic {
  endpoint_id: string; display_name: string; kind: "direct" | "nat" | "domain" | "managed_ddns"
  address: string; port: number; reachability: PortReachability; reason: PortProbeReason
}
export interface ServicePortDiagnostic {
  service_id: string; network: "tcp" | "udp"; local_port: number; listen_address: string
  local_state: LocalListenerState; local_observed_at_unix_nano: number; endpoints: EndpointPortDiagnostic[]
}
