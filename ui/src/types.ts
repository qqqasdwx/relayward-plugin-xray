export type Locale = "zh-CN" | "en"
export type Theme = "light" | "dark"

export interface ServiceType {
  id: string
  display_name: string
}

export interface VLESSReality {
  decryption: string
  encryption: string
  test_seed: number[]
  fallbacks: VLESSFallback[]
  show: boolean
  xver: number
  target: string
  server_names: string[]
  private_key: string
  public_key: string
  short_ids: string[]
  min_client_version: string
  max_client_version: string
  max_time_diff: number
  mldsa65_seed: string
  mldsa65_verify: string
  master_key_log: string
  limit_fallback_upload?: RealityLimitFallback
  limit_fallback_download?: RealityLimitFallback
  flow: string
  fingerprint: string
  spider_x: string
}

export interface VLESSFallback {
  name: string
  alpn: string
  path: string
  dest: string
  xver: number
}

export interface RealityLimitFallback {
  after_bytes: number
  bytes_per_sec: number
  burst_bytes_per_sec: number
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
  public_host: string
  public_port: number
  tcp: TCPSettings
  sockopt?: SocketSettings
  sniffing: Sniffing
  vless_reality: VLESSReality
}

export type RoutingAction = "blocked" | "direct"
export type RoutingProtocol = "http" | "tls" | "quic" | "bittorrent"

export interface RoutingRule {
  rule_id: string
  display_name: string
  enabled: boolean
  domains: string[]
  ip_cidrs: string[]
  protocols: RoutingProtocol[]
  action: RoutingAction
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
