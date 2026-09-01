export type Locale = "zh-CN" | "en"
export type Theme = "light" | "dark"

export interface ServiceType {
  id: string
  display_name: string
}

export interface VLESSReality {
  target: string
}

export type ShadowsocksMethod =
  | "2022-blake3-aes-128-gcm"
  | "2022-blake3-aes-256-gcm"
  | "aes-128-gcm"
  | "aes-256-gcm"
  | "chacha20-ietf-poly1305"
  | "xchacha20-ietf-poly1305"

export interface ShadowsocksSettings {
  method: ShadowsocksMethod
  network: "tcp" | "udp" | "tcp,udp"
  server_key: string
  iv_check: boolean
}

export interface TCPHeader {
  type: "none" | "http"
  request?: {
    version: string
    method: string
    path: string[]
    headers: Record<string, string[]>
  }
  response?: {
    version: string
    status: string
    reason: string
    headers: Record<string, string[]>
  }
}

export interface TCPSettings {
  accept_proxy_protocol: boolean
  header: TCPHeader
}

export interface SocketSettings {
  mark: number
  tcp_fast_open: boolean
  tproxy: "off" | "redirect" | "tproxy"
  accept_proxy_protocol: boolean
  tcp_mptcp: boolean
  tcp_keep_alive_interval: number
  tcp_keep_alive_idle: number
  tcp_max_seg: number
  tcp_user_timeout: number
  tcp_window_clamp: number
  tcp_congestion: "" | "bbr" | "cubic" | "reno"
  v6_only: boolean
  custom: CustomSockopt[]
}

export interface CustomSockopt {
  system: "" | "linux"
  network: "" | "tcp" | "tcp4" | "tcp6"
  level: string
  opt: string
  type: "int" | "str"
  value: string
}

export type SniffingDestination = "http" | "tls" | "quic" | "fakedns"

export interface Sniffing {
  enabled: boolean
  dest_override: SniffingDestination[]
  metadata_only: boolean
  route_only: boolean
  ips_excluded: string[]
  domains_excluded: string[]
}

export interface ProxyService {
  type: string
  enabled: boolean
  service_id: string
  display_name: string
  listen: string
  port: number
  tcp: TCPSettings
  sockopt?: SocketSettings
  sniffing: Sniffing
  vless_reality?: VLESSReality
  shadowsocks?: ShadowsocksSettings
}

export type RoutingProtocol = "http" | "tls" | "quic" | "bittorrent"

export type OutboundProtocol = "freedom" | "blackhole"
export type OutboundDomainStrategy = "" | "AsIs" | "UseIP" | "UseIPv4" | "UseIPv6" | "UseIPv6v4" | "UseIPv4v6" | "ForceIP" | "ForceIPv6v4" | "ForceIPv6" | "ForceIPv4v6" | "ForceIPv4"

export interface FreedomFragment {
  packets: string
  length: string
  interval: string
  max_split: string
}

export interface FreedomNoise {
  type: "rand" | "str" | "base64" | "hex"
  packet: string
  delay: string
  apply_to: "ip" | "ipv4" | "ipv6"
}

export interface FreedomFinalRule {
  action: "allow" | "block"
  network: "" | "tcp" | "udp" | "tcp,udp"
  port: string
  ips: string[]
  block_delay: string
}

export interface FreedomOutboundSettings {
  domain_strategy: OutboundDomainStrategy
  redirect: string
  user_level: number
  proxy_protocol: 0 | 1 | 2
  fragment?: FreedomFragment
  noises: FreedomNoise[]
  final_rules: FreedomFinalRule[]
}

export interface BlackholeOutboundSettings {
  response_type: "" | "none" | "http"
}

export interface XrayOutbound {
  tag: string
  protocol: OutboundProtocol
  freedom?: FreedomOutboundSettings
  blackhole?: BlackholeOutboundSettings
}

export interface RoutingRule {
  rule_id: string
  display_name: string
  enabled: boolean
  source_ips: string[]
  source_port: string
  vless_route: string
  network: "" | "tcp" | "udp" | "tcp,udp"
  protocols: RoutingProtocol[]
  attributes: Record<string, string>
  destination_ips: string[]
  domains: string[]
  users: string[]
  destination_port: string
  inbound_tags: string[]
  outbound_tag: string
}

export type DNSTransport = "system" | "udp" | "tcp" | "doh"
export type DNSQueryStrategy = "use-ip" | "use-ipv4" | "use-ipv6"

export interface DNSServer {
  server_id: string
  display_name: string
  enabled: boolean
  transport: DNSTransport
  address: string
  port: number
  domains: string[]
}

export interface DNSConfiguration {
  enabled: boolean
  query_strategy: DNSQueryStrategy
  servers: DNSServer[]
}

export interface EditableConfiguration {
  xray_version: string
  api_port: number
  services: ProxyService[]
  outbounds: XrayOutbound[]
  routing: { rules: RoutingRule[] }
  dns: DNSConfiguration
}

export interface StoredConfiguration {
  exists: boolean
  node_id: string
  generation?: number
  version?: string
  sha256?: string
  configuration?: EditableConfiguration
}

export type LocalListenerState = "unknown" | "listening" | "not_listening"
export type PortReachability = "reachable" | "unreachable" | "not_tested"
export type PortProbeReason =
  | ""
  | "node_offline"
  | "local_not_listening"
  | "endpoint_unavailable"
  | "proxied_endpoint"
  | "unsupported_network"
  | "dns_failed"
  | "connection_refused"
  | "timeout"
  | "network_unreachable"

export interface EndpointPortDiagnostic {
  endpoint_id: string
  display_name: string
  kind: "direct" | "nat" | "domain" | "managed_ddns"
  address: string
  port: number
  reachability: PortReachability
  reason: PortProbeReason
}

export interface ServicePortDiagnostic {
  service_id: string
  network: "tcp" | "udp"
  local_port: number
  listen_address: string
  local_state: LocalListenerState
  local_observed_at_unix_nano: number
  endpoints: EndpointPortDiagnostic[]
}
