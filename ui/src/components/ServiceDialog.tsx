import { useState } from "react"
import { CheckCircle2, CircleHelp, CircleMinus, Plus, Server, Trash2, XCircle } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { Translator } from "@/i18n"
import {
  capabilities,
  clientCores,
  compatibilityFor,
  type CapabilityID,
  type ClientCore,
} from "@/inboundCompatibility"
import type {
  CustomSockopt,
  ProxyService,
  RealityLimitFallback,
  SniffingDestination,
  SocketSettings,
  TCPHeader,
  VLESSFallback,
} from "@/types"

const fingerprints = ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn", "unsafe"]
const sniffingDestinations: SniffingDestination[] = ["http", "tls", "quic", "fakedns"]
type FieldScope = "server" | CapabilityID

interface ServiceDialogProps {
  initial: ProxyService
  editingID: string | null
  existingIDs: string[]
  t: Translator
  onClose: () => void
  onApply: (service: ProxyService) => void
}

function lines(value: string): string[] {
  return value.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean)
}

function headerLines(value: Record<string, string[]> | undefined): string {
  return Object.entries(value ?? {}).flatMap(([name, entries]) => entries.map((entry) => `${name}: ${entry}`)).join("\n")
}

function parseHeaders(value: string): Record<string, string[]> {
  const result: Record<string, string[]> = {}
  for (const line of value.split(/\r?\n/)) {
    const separator = line.indexOf(":")
    if (separator < 1) continue
    const name = line.slice(0, separator).trim()
    const entry = line.slice(separator + 1).trim()
    if (name === "" || entry === "") continue
    result[name] = [...(result[name] ?? []), entry]
  }
  return result
}

function defaultHTTPHeader(): TCPHeader {
  return {
    type: "http",
    request: { version: "1.1", method: "GET", path: ["/"], headers: {} },
    response: { version: "1.1", status: "200", reason: "OK", headers: {} },
  }
}

function defaultSocketSettings(): SocketSettings {
  return {
    mark: 0,
    tcp_fast_open: false,
    tproxy: "off",
    accept_proxy_protocol: false,
    tcp_mptcp: false,
    tcp_keep_alive_interval: 0,
    tcp_keep_alive_idle: 0,
    tcp_max_seg: 0,
    tcp_user_timeout: 0,
    tcp_window_clamp: 0,
    tcp_congestion: "",
    v6_only: false,
    custom: [],
  }
}

function emptyFallback(): VLESSFallback {
  return { name: "", alpn: "", path: "", dest: "", xver: 0 }
}

function emptyLimitFallback(): RealityLimitFallback {
  return { after_bytes: 0, bytes_per_sec: 0, burst_bytes_per_sec: 0 }
}

function emptyCustomSockopt(): CustomSockopt {
  return { system: "linux", network: "", level: "6", opt: "", type: "int", value: "" }
}

export function ServiceDialog({ initial, editingID, existingIDs, t, onClose, onApply }: ServiceDialogProps) {
  const [value, setValue] = useState<ProxyService>(() => structuredClone(initial))
  const [duplicate, setDuplicate] = useState(false)

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const normalized: ProxyService = {
      ...value,
      service_id: value.service_id.trim(),
      display_name: value.display_name.trim(),
      listen: value.listen.trim(),
      public_host: value.public_host.trim(),
      sockopt: value.sockopt == null ? undefined : {
        ...value.sockopt,
        custom: value.sockopt.custom.map((option) => ({
          ...option,
          network: (option.network ?? "").trim() as CustomSockopt["network"],
          level: option.level.trim(),
          opt: option.opt.trim(),
          value: option.value.trim(),
        })),
      },
      vless_reality: {
        ...value.vless_reality,
        decryption: value.vless_reality.decryption.trim(),
        encryption: value.vless_reality.encryption.trim(),
        fallbacks: value.vless_reality.fallbacks.map((fallback) => ({
          ...fallback,
          name: fallback.name.trim(),
          alpn: fallback.alpn.trim(),
          path: fallback.path.trim(),
          dest: fallback.dest.trim(),
        })),
        target: value.vless_reality.target.trim(),
        server_names: value.vless_reality.server_names.map((item) => item.trim()).filter(Boolean),
        private_key: value.vless_reality.private_key.trim(),
        public_key: value.vless_reality.public_key.trim(),
        short_ids: value.vless_reality.short_ids.map((item) => item.trim()).filter(Boolean),
        min_client_version: value.vless_reality.min_client_version.trim(),
        max_client_version: value.vless_reality.max_client_version.trim(),
        mldsa65_seed: value.vless_reality.mldsa65_seed.trim(),
        mldsa65_verify: value.vless_reality.mldsa65_verify.trim(),
        master_key_log: value.vless_reality.master_key_log.trim(),
        spider_x: value.vless_reality.spider_x.trim(),
      },
    }
    const duplicateID = existingIDs.some((id) => id === normalized.service_id && id !== editingID)
    setDuplicate(duplicateID)
    if (duplicateID || !event.currentTarget.reportValidity()) return
    onApply(normalized)
  }

  const reality = value.vless_reality
  const sockopt = value.sockopt
  const compatibility = compatibilityFor(value)

  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="max-h-[calc(100vh-2rem)] overflow-y-auto sm:max-w-5xl" closeLabel={t("Close")}>
        <form className="grid gap-6" onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{t(editingID == null ? "Add inbound" : "Edit inbound")}</DialogTitle>
            <DialogDescription>VLESS · RAW · REALITY</DialogDescription>
          </DialogHeader>

          <CompatibilitySummary compatibility={compatibility} t={t} />

          <Tabs defaultValue="basic" className="min-w-0 gap-5">
            <div className="overflow-x-auto">
              <TabsList className="grid w-full min-w-[38rem] grid-cols-5">
                <TabsTrigger value="basic">{t("Basic")}</TabsTrigger>
                <TabsTrigger value="protocol">{t("Protocol")}</TabsTrigger>
                <TabsTrigger value="transport">{t("Transport")}</TabsTrigger>
                <TabsTrigger value="security">{t("Security")}</TabsTrigger>
                <TabsTrigger value="sniffing">{t("Sniffing")}</TabsTrigger>
              </TabsList>
            </div>

            <TabsContent value="basic" className="grid gap-5">
              <SwitchField label={t("Enable")} help={t("Controls whether this inbound is included in the Xray configuration.")} checked={value.enabled} scope="server" t={t} onChange={(enabled) => setValue({ ...value, enabled })} />
              <div className="grid gap-4">
                <TextField label={t("Remark")} help={t("A readable name used to identify this inbound in Relayward and subscriptions.")} value={value.display_name} maxLength={100} required scope="server" t={t} onChange={(display_name) => setValue({ ...value, display_name })} />
                <div className="grid gap-2">
                  <FieldLabel label={t("Inbound tag")} help={t("The unique Xray inbound tag. It is also used by routing, authorization, and telemetry.")} scope="server" t={t} />
                  <Input
                    id="inbound-tag"
                    value={value.service_id}
                    disabled={editingID != null}
                    pattern="[a-z0-9][a-z0-9._\-]{0,63}"
                    maxLength={64}
                    required
                    aria-invalid={duplicate}
                    onChange={(event) => { setValue({ ...value, service_id: event.target.value }); setDuplicate(false) }}
                  />
                  {duplicate ? <p className="text-sm text-destructive">{t("Inbound tag already exists.")}</p> : null}
                </div>
                <ReadOnlyField label={t("Protocol")} help={t("The client protocol accepted by this inbound. This version currently supports VLESS.")} value="VLESS" scope="vless" t={t} />
                <TextField label={t("Address")} help={t("The local address Xray listens on. Use 0.0.0.0 to listen on all IPv4 interfaces.")} value={value.listen} required scope="server" t={t} onChange={(listen) => setValue({ ...value, listen })} />
                <NumberField label={t("Port")} help={t("The local TCP port Xray listens on for this inbound.")} value={value.port} min={1} max={65535} required scope="server" t={t} onChange={(port) => setValue({ ...value, port })} />
                <TextField label={t("Share address")} help={t("The public domain or IP written into subscription links. It may differ from the listen address behind NAT or a relay.")} value={value.public_host} required scope="vless" t={t} onChange={(public_host) => setValue({ ...value, public_host })} />
                <NumberField label={t("Share port")} help={t("The public port written into subscription links. It may differ from the listen port after port forwarding.")} value={value.public_port} min={1} max={65535} required scope="vless" t={t} onChange={(public_port) => setValue({ ...value, public_port })} />
              </div>
            </TabsContent>

            <TabsContent value="protocol" className="grid gap-5">
              <div className="grid gap-4">
                <div className="grid gap-2">
                  <FieldLabel label={t("Flow")} help={t("Select xtls-rprx-vision to enable XTLS Vision for authorization clients, or None to leave flow unset.")} scope="vision" t={t} />
                  <Select value={reality.flow === "" ? "none" : reality.flow} onValueChange={(flow) => setValue({ ...value, vless_reality: { ...reality, flow: flow === "none" ? "" : flow } })}>
                    <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                    <SelectContent><SelectItem value="none">None</SelectItem><SelectItem value="xtls-rprx-vision">xtls-rprx-vision</SelectItem></SelectContent>
                  </Select>
                </div>
                <TextField label="Vision testseed" help={t("Optional four positive integers used by XTLS Vision padding tests. Leave empty to use Xray defaults.")} value={reality.test_seed.join(", ")} placeholder="900, 500, 900, 256" scope="server" t={t} onChange={(raw) => setValue({ ...value, vless_reality: { ...reality, test_seed: numberList(raw) } })} />
              </div>

              <RestrictedParameters t={t}>
                <TextAreaField label={t("Decryption")} help={t("VLESS inbound decryption setting. Keep none unless a supported VLESS encryption scheme requires another value.")} value={reality.decryption} required scope="server" t={t} onChange={(decryption) => setValue({ ...value, vless_reality: { ...reality, decryption } })} />
                <TextAreaField label={t("Encryption")} help={t("VLESS encryption negotiation setting sent to clients. Keep none for the standard VLESS REALITY configuration.")} value={reality.encryption} required scope="vless-encryption" t={t} onChange={(encryption) => setValue({ ...value, vless_reality: { ...reality, encryption } })} />
              </RestrictedParameters>

              <ListSection title={t("Fallbacks")} help={t("Routes non-VLESS traffic received on this port to another local or network destination.")} actionLabel={t("Add fallback")} scope="server" t={t} onAdd={() => setValue({ ...value, vless_reality: { ...reality, fallbacks: [...reality.fallbacks, emptyFallback()] } })}>
                {reality.fallbacks.map((fallback, index) => (
                  <div key={index} className="grid gap-4 border-t pt-4 first:border-t-0 first:pt-0">
                    <TextField label={t("Name")} help={t("Optional TLS server name used to select this fallback.")} value={fallback.name} scope="server" t={t} onChange={(name) => updateFallback(value, setValue, index, { ...fallback, name })} />
                    <TextField label="ALPN" help={t("Optional negotiated ALPN value used to select this fallback, such as h2 or http/1.1.")} value={fallback.alpn} scope="server" t={t} onChange={(alpn) => updateFallback(value, setValue, index, { ...fallback, alpn })} />
                    <TextField label={t("Path")} help={t("Optional first-packet path used to select this fallback. It must start with a slash.")} value={fallback.path} placeholder="/" scope="server" t={t} onChange={(path) => updateFallback(value, setValue, index, { ...fallback, path })} />
                    <TextField label={t("Destination")} help={t("Where matching fallback traffic is forwarded: a port, host:port, Unix socket, abstract socket, or built-in destination.")} value={fallback.dest} required scope="server" t={t} onChange={(dest) => updateFallback(value, setValue, index, { ...fallback, dest })} />
                    <NumberField label="Xver" help={t("PROXY protocol version sent to the fallback destination: 0 disables it, 1 uses v1, and 2 uses v2.")} value={fallback.xver} min={0} max={2} scope="server" t={t} onChange={(xver) => updateFallback(value, setValue, index, { ...fallback, xver })} />
                    <div className="flex items-end justify-end">
                      <Button type="button" variant="outline" size="icon" title={t("Delete fallback")} aria-label={t("Delete fallback")} onClick={() => setValue({ ...value, vless_reality: { ...reality, fallbacks: reality.fallbacks.filter((_, candidate) => candidate !== index) } })}><Trash2 /></Button>
                    </div>
                  </div>
                ))}
              </ListSection>
            </TabsContent>

            <TabsContent value="transport" className="grid gap-5">
              <div className="grid gap-4">
                <ReadOnlyField label={t("Transport")} help={t("The transport used by this inbound. RAW is Xray's direct TCP byte stream.")} value="RAW" scope="vless" t={t} />
                <SwitchField label="Proxy Protocol" help={t("Reads the original source address from a PROXY protocol header sent by a trusted upstream relay. Do not enable it for direct client connections.")} checked={value.tcp.accept_proxy_protocol} scope="server" t={t} onChange={(accept_proxy_protocol) => setValue({ ...value, tcp: { ...value.tcp, accept_proxy_protocol } })} />
              </div>

              <RestrictedParameters t={t}>
                <SwitchField label={t("HTTP camouflage")} help={t("Adds an HTTP-shaped RAW header for compatible clients. This is traffic camouflage, not an HTTP server.")} checked={value.tcp.header.type === "http"} scope="raw-http" t={t} onChange={(enabled) => setValue({ ...value, tcp: { ...value.tcp, header: enabled ? defaultHTTPHeader() : { type: "none" } } })} />
                {value.tcp.header.type === "http" && value.tcp.header.request && value.tcp.header.response ? (
                  <div className="grid gap-4">
                    <TextField label={t("Request version")} help={t("HTTP version placed in the camouflage request line, normally 1.1.")} value={value.tcp.header.request.version} scope="raw-http" t={t} onChange={(version) => setValue({ ...value, tcp: { ...value.tcp, header: { ...value.tcp.header, request: { ...value.tcp.header.request!, version } } } })} />
                    <TextField label={t("Request method")} help={t("HTTP method placed in the camouflage request line, normally GET.")} value={value.tcp.header.request.method} scope="raw-http" t={t} onChange={(method) => setValue({ ...value, tcp: { ...value.tcp, header: { ...value.tcp.header, request: { ...value.tcp.header.request!, method } } } })} />
                    <TextAreaField label={t("Request path")} help={t("Candidate request paths for HTTP camouflage, one per line. Each path must start with a slash.")} value={value.tcp.header.request.path.join("\n")} scope="raw-http" t={t} onChange={(raw) => setValue({ ...value, tcp: { ...value.tcp, header: { ...value.tcp.header, request: { ...value.tcp.header.request!, path: lines(raw) } } } })} />
                    <TextAreaField label={t("Request headers")} help={t("HTTP camouflage request headers, one Name: Value entry per line. Repeated names are supported.")} value={headerLines(value.tcp.header.request.headers)} placeholder="Host: example.com" scope="raw-http" t={t} onChange={(raw) => setValue({ ...value, tcp: { ...value.tcp, header: { ...value.tcp.header, request: { ...value.tcp.header.request!, headers: parseHeaders(raw) } } } })} />
                    <TextField label={t("Response version")} help={t("HTTP version placed in the camouflage response line, normally 1.1.")} value={value.tcp.header.response.version} scope="raw-http" t={t} onChange={(version) => setValue({ ...value, tcp: { ...value.tcp, header: { ...value.tcp.header, response: { ...value.tcp.header.response!, version } } } })} />
                    <TextField label={t("Response status")} help={t("HTTP status code placed in the camouflage response, normally 200.")} value={value.tcp.header.response.status} scope="raw-http" t={t} onChange={(status) => setValue({ ...value, tcp: { ...value.tcp, header: { ...value.tcp.header, response: { ...value.tcp.header.response!, status } } } })} />
                    <TextField label={t("Response reason")} help={t("HTTP reason phrase placed in the camouflage response, normally OK.")} value={value.tcp.header.response.reason} scope="raw-http" t={t} onChange={(reason) => setValue({ ...value, tcp: { ...value.tcp, header: { ...value.tcp.header, response: { ...value.tcp.header.response!, reason } } } })} />
                    <TextAreaField label={t("Response headers")} help={t("HTTP camouflage response headers, one Name: Value entry per line. Repeated names are supported.")} value={headerLines(value.tcp.header.response.headers)} scope="raw-http" t={t} onChange={(raw) => setValue({ ...value, tcp: { ...value.tcp, header: { ...value.tcp.header, response: { ...value.tcp.header.response!, headers: parseHeaders(raw) } } } })} />
                  </div>
                ) : null}
              </RestrictedParameters>

              <ListSection title="Sockopt" help={t("Advanced operating-system socket options for this inbound listener. Leave disabled unless the deployment requires them.")} actionLabel="Sockopt" actionSwitch checked={sockopt != null} scope="server" t={t} onSwitch={(enabled) => setValue({ ...value, sockopt: enabled ? defaultSocketSettings() : undefined })}>
                {sockopt ? (
                  <>
                    <div className="grid gap-4">
                      <NumberField label="Route Mark" help={t("Linux socket mark applied to accepted connections for policy routing or firewall matching. 0 leaves it unset.")} value={sockopt.mark} min={0} t={t} onChange={(mark) => updateSockopt(value, setValue, { ...sockopt, mark })} />
                      <NumberField label="TCP Keep Alive Interval" help={t("Seconds between TCP keepalive probes after probing begins. 0 uses the operating-system default.")} value={sockopt.tcp_keep_alive_interval} min={0} t={t} onChange={(tcp_keep_alive_interval) => updateSockopt(value, setValue, { ...sockopt, tcp_keep_alive_interval })} />
                      <NumberField label="TCP Keep Alive Idle" help={t("Idle seconds before TCP keepalive probing begins. 0 uses the operating-system default.")} value={sockopt.tcp_keep_alive_idle} min={0} t={t} onChange={(tcp_keep_alive_idle) => updateSockopt(value, setValue, { ...sockopt, tcp_keep_alive_idle })} />
                      <NumberField label="TCP Max Seg" help={t("TCP maximum segment size in bytes. 0 leaves the operating-system default unchanged.")} value={sockopt.tcp_max_seg} min={0} t={t} onChange={(tcp_max_seg) => updateSockopt(value, setValue, { ...sockopt, tcp_max_seg })} />
                      <NumberField label="TCP User Timeout" help={t("Maximum milliseconds transmitted data may remain unacknowledged. 0 uses the operating-system default.")} value={sockopt.tcp_user_timeout} min={0} t={t} onChange={(tcp_user_timeout) => updateSockopt(value, setValue, { ...sockopt, tcp_user_timeout })} />
                      <NumberField label="TCP Window Clamp" help={t("Maximum advertised TCP receive window in bytes. 0 leaves it unchanged.")} value={sockopt.tcp_window_clamp} min={0} t={t} onChange={(tcp_window_clamp) => updateSockopt(value, setValue, { ...sockopt, tcp_window_clamp })} />
                      <div className="grid gap-2">
                        <FieldLabel label="TCP Congestion" help={t("Linux TCP congestion-control algorithm used by this listener. Default leaves the system setting unchanged.")} t={t} />
                        <Select value={sockopt.tcp_congestion === "" ? "default" : sockopt.tcp_congestion} onValueChange={(tcp_congestion: "default" | "bbr" | "cubic" | "reno") => updateSockopt(value, setValue, { ...sockopt, tcp_congestion: tcp_congestion === "default" ? "" : tcp_congestion })}>
                          <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                          <SelectContent><SelectItem value="default">{t("Default")}</SelectItem><SelectItem value="bbr">bbr</SelectItem><SelectItem value="cubic">cubic</SelectItem><SelectItem value="reno">reno</SelectItem></SelectContent>
                        </Select>
                      </div>
                      <div className="grid gap-2">
                        <FieldLabel label="TProxy" help={t("Transparent-proxy listener mode. Keep Off for ordinary proxy inbounds.")} t={t} />
                        <Select value={sockopt.tproxy} onValueChange={(tproxy: SocketSettings["tproxy"]) => updateSockopt(value, setValue, { ...sockopt, tproxy })}>
                          <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                          <SelectContent><SelectItem value="off">Off</SelectItem><SelectItem value="redirect">Redirect</SelectItem><SelectItem value="tproxy">TProxy</SelectItem></SelectContent>
                        </Select>
                      </div>
                    </div>
                    <div className="grid gap-3">
                      <SwitchField label="Proxy Protocol (Sockopt)" help={t("Enables PROXY protocol parsing at the socket layer. Use only when a trusted upstream always sends the header.")} checked={sockopt.accept_proxy_protocol} t={t} onChange={(accept_proxy_protocol) => updateSockopt(value, setValue, { ...sockopt, accept_proxy_protocol })} />
                      <SwitchField label="TCP Fast Open" help={t("Allows compatible clients to send data during the TCP handshake when supported by the operating system.")} checked={sockopt.tcp_fast_open} t={t} onChange={(tcp_fast_open) => updateSockopt(value, setValue, { ...sockopt, tcp_fast_open })} />
                      <SwitchField label="Multipath TCP" help={t("Enables Multipath TCP for the listener when the Linux kernel supports it.")} checked={sockopt.tcp_mptcp} t={t} onChange={(tcp_mptcp) => updateSockopt(value, setValue, { ...sockopt, tcp_mptcp })} />
                      <SwitchField label={t("IPv6 only")} help={t("When listening on IPv6, prevents the socket from also accepting IPv4-mapped connections.")} checked={sockopt.v6_only} t={t} onChange={(v6_only) => updateSockopt(value, setValue, { ...sockopt, v6_only })} />
                    </div>
                    <ListSection title={t("Custom sockopt")} help={t("Raw Linux socket options for advanced cases not covered by the standard fields.")} actionLabel={t("Add custom option")} t={t} onAdd={() => updateSockopt(value, setValue, { ...sockopt, custom: [...sockopt.custom, emptyCustomSockopt()] })}>
                      {sockopt.custom.map((option, index) => (
                        <div key={index} className="grid gap-4 border-t pt-4 first:border-t-0 first:pt-0">
                          <ReadOnlyField label={t("System")} help={t("Operating system on which this custom socket option is applied. Relayward nodes currently use Linux.")} value="linux" t={t} />
                          <div className="grid gap-2">
                            <FieldLabel label={t("Network")} help={t("Restricts the custom socket option to all sockets, TCP, TCP over IPv4, or TCP over IPv6.")} t={t} />
                            <Select value={(option.network ?? "") === "" ? "all" : option.network} onValueChange={(network: "all" | "tcp" | "tcp4" | "tcp6") => updateCustomSockopt(value, setValue, index, { ...option, network: network === "all" ? "" : network })}>
                              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                              <SelectContent><SelectItem value="all">{t("All")}</SelectItem><SelectItem value="tcp">tcp</SelectItem><SelectItem value="tcp4">tcp4</SelectItem><SelectItem value="tcp6">tcp6</SelectItem></SelectContent>
                            </Select>
                          </div>
                          <TextField label={t("Level")} help={t("Numeric socket-option level passed to setsockopt, for example 6 for IPPROTO_TCP.")} value={option.level} required t={t} onChange={(level) => updateCustomSockopt(value, setValue, index, { ...option, level })} />
                          <TextField label={t("Opt")} help={t("Numeric socket-option name passed to setsockopt.")} value={option.opt} required t={t} onChange={(opt) => updateCustomSockopt(value, setValue, index, { ...option, opt })} />
                          <div className="grid gap-2">
                            <FieldLabel label={t("Type")} help={t("How Xray encodes the custom socket-option value: signed integer or string.")} t={t} />
                            <Select value={option.type} onValueChange={(type: "int" | "str") => updateCustomSockopt(value, setValue, index, { ...option, type })}>
                              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                              <SelectContent><SelectItem value="int">int</SelectItem><SelectItem value="str">str</SelectItem></SelectContent>
                            </Select>
                          </div>
                          <TextField label={t("Value")} help={t("Value passed to setsockopt using the selected type.")} value={option.value} required t={t} onChange={(entry) => updateCustomSockopt(value, setValue, index, { ...option, value: entry })} />
                          <div className="flex items-end justify-end">
                            <Button type="button" variant="outline" size="icon" title={t("Delete custom option")} aria-label={t("Delete custom option")} onClick={() => updateSockopt(value, setValue, { ...sockopt, custom: sockopt.custom.filter((_, candidate) => candidate !== index) })}><Trash2 /></Button>
                          </div>
                        </div>
                      ))}
                    </ListSection>
                  </>
                ) : null}
              </ListSection>
            </TabsContent>

            <TabsContent value="security" className="grid gap-5">
              <ReadOnlyField label={t("Security")} help={t("The transport security used by this inbound. REALITY authenticates the server without a conventional TLS certificate.")} value="REALITY" scope="reality" t={t} />
              <div className="grid gap-4">
                <SwitchField label={t("Show")} help={t("Enables additional REALITY handshake information in Xray logs. Leave disabled for normal operation.")} checked={reality.show} scope="server" t={t} onChange={(show) => setValue({ ...value, vless_reality: { ...reality, show } })} />
                <NumberField label="Xver" help={t("PROXY protocol version used when REALITY forwards invalid handshakes to Target: 0 disables it, 1 uses v1, and 2 uses v2.")} value={reality.xver} min={0} max={2} scope="server" t={t} onChange={(xver) => setValue({ ...value, vless_reality: { ...reality, xver } })} />
                <div className="grid gap-2">
                  <FieldLabel label="uTLS" help={t("Browser TLS fingerprint sent by subscription clients when connecting to this REALITY inbound.")} scope="reality" t={t} />
                  <Select value={reality.fingerprint} onValueChange={(fingerprint) => setValue({ ...value, vless_reality: { ...reality, fingerprint } })}>
                    <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                    <SelectContent>{fingerprints.map((fingerprint) => <SelectItem key={fingerprint} value={fingerprint}>{fingerprint === "ios" ? "iOS" : fingerprint}</SelectItem>)}</SelectContent>
                  </Select>
                </div>
                <TextField label={t("Target")} help={t("A real TLS destination in host:port form used to disguise rejected or unauthenticated REALITY connections.")} value={reality.target} placeholder="addons.mozilla.org:443" required scope="server" t={t} onChange={(target) => setValue({ ...value, vless_reality: { ...reality, target } })} />
                <TextAreaField label="SNI" help={t("Server names accepted by REALITY, one per line. Clients use one of these values as serverName.")} value={reality.server_names.join("\n")} required scope="reality" t={t} onChange={(raw) => setValue({ ...value, vless_reality: { ...reality, server_names: lines(raw) } })} />
                <NumberField label={t("Maximum time difference (ms)")} help={t("Maximum permitted clock difference between client and server in milliseconds. 0 disables this check.")} value={reality.max_time_diff} min={0} scope="server" t={t} onChange={(max_time_diff) => setValue({ ...value, vless_reality: { ...reality, max_time_diff } })} />
                <TextField label={t("Minimum client version")} help={t("Optional minimum REALITY client version accepted by the server. Leave empty for no lower bound.")} value={reality.min_client_version} placeholder="1.0.0" scope="server" t={t} onChange={(min_client_version) => setValue({ ...value, vless_reality: { ...reality, min_client_version } })} />
                <TextField label={t("Maximum client version")} help={t("Optional maximum REALITY client version accepted by the server. Leave empty for no upper bound.")} value={reality.max_client_version} scope="server" t={t} onChange={(max_client_version) => setValue({ ...value, vless_reality: { ...reality, max_client_version } })} />
                <TextAreaField label="Short IDs" help={t("REALITY short identifiers accepted by the server, one hexadecimal value per line. Leave empty to generate one automatically.")} value={reality.short_ids.join("\n")} placeholder={t("Leave empty to generate automatically")} scope="reality" t={t} onChange={(raw) => setValue({ ...value, vless_reality: { ...reality, short_ids: lines(raw) } })} />
                <TextField label="SpiderX" help={t("Initial path used by compatible REALITY clients for crawler behavior. It is written into subscription links.")} value={reality.spider_x} required scope="spider-x" t={t} onChange={(spider_x) => setValue({ ...value, vless_reality: { ...reality, spider_x } })} />
                <TextAreaField label={t("Public key")} help={t("Public key derived from the REALITY private key and written into subscription links. It is generated after saving.")} value={reality.public_key} readOnly placeholder={t("Generated after saving")} scope="reality" t={t} onChange={() => undefined} />
                <TextAreaField label={t("Private key")} help={t("Server private key for REALITY. Leave empty to generate a new key pair when the inbound is saved.")} value={reality.private_key} placeholder={t("Leave empty to generate automatically")} scope="server" t={t} onChange={(private_key) => setValue({ ...value, vless_reality: { ...reality, private_key } })} />
                <TextField label={t("Master key log")} help={t("Optional server-side path for writing TLS master secrets for debugging. It exposes sensitive session keys and should normally be empty.")} value={reality.master_key_log} scope="server" t={t} onChange={(master_key_log) => setValue({ ...value, vless_reality: { ...reality, master_key_log } })} />
              </div>

              <RestrictedParameters t={t}>
                <TextAreaField label="mldsa65 Seed" help={t("Optional server-side ML-DSA-65 seed for post-quantum REALITY authentication. Leave empty to disable it.")} value={reality.mldsa65_seed} scope="server" t={t} onChange={(mldsa65_seed) => setValue({ ...value, vless_reality: { ...reality, mldsa65_seed } })} />
                <TextAreaField label="mldsa65 Verify" help={t("ML-DSA-65 verification value derived from the seed and provided to compatible clients.")} value={reality.mldsa65_verify} scope="mldsa" t={t} onChange={(mldsa65_verify) => setValue({ ...value, vless_reality: { ...reality, mldsa65_verify } })} />
              </RestrictedParameters>

              <ListSection title={t("Limit fallback")} help={t("Rate limits traffic forwarded to the REALITY Target after an invalid handshake. It does not limit authenticated proxy traffic.")} actionLabel={t("Limit fallback")} actionSwitch checked={reality.limit_fallback_upload != null || reality.limit_fallback_download != null} scope="server" t={t} onSwitch={(enabled) => setValue({ ...value, vless_reality: { ...reality, limit_fallback_upload: enabled ? emptyLimitFallback() : undefined, limit_fallback_download: enabled ? emptyLimitFallback() : undefined } })}>
                {reality.limit_fallback_upload && reality.limit_fallback_download ? (
                  <div className="grid gap-6">
                    <LimitFallbackFields title={t("Limit fallback upload")} value={reality.limit_fallback_upload} onChange={(limit_fallback_upload) => setValue({ ...value, vless_reality: { ...reality, limit_fallback_upload } })} t={t} />
                    <LimitFallbackFields title={t("Limit fallback download")} value={reality.limit_fallback_download} onChange={(limit_fallback_download) => setValue({ ...value, vless_reality: { ...reality, limit_fallback_download } })} t={t} />
                  </div>
                ) : null}
              </ListSection>
            </TabsContent>

            <TabsContent value="sniffing" className="grid gap-5">
              <SwitchField label={t("Enable")} help={t("Lets Xray inspect initial traffic metadata to identify the destination protocol or domain for routing.")} checked={value.sniffing.enabled} scope="server" t={t} onChange={(enabled) => setValue({ ...value, sniffing: { ...value.sniffing, enabled } })} />
              {value.sniffing.enabled ? (
                <>
                  <div className="grid gap-3">
                    <FieldLabel label={t("Destination override")} help={t("Protocols whose sniffed destination may replace the original destination for routing or connection handling.")} scope="server" t={t} />
                    <div className="grid gap-3">
                      {sniffingDestinations.map((destination) => (
                        <label key={destination} className="flex cursor-pointer items-center gap-3 rounded-lg border p-3 text-sm">
                          <Checkbox checked={value.sniffing.dest_override.includes(destination)} onCheckedChange={(checked) => setValue({ ...value, sniffing: { ...value.sniffing, dest_override: checked ? [...value.sniffing.dest_override, destination] : value.sniffing.dest_override.filter((item) => item !== destination) } })} />
                          {destination}
                        </label>
                      ))}
                    </div>
                  </div>
                  <div className="grid gap-3">
                    <SwitchField label={t("Metadata only")} help={t("Uses connection metadata without inspecting application payload. Protocol and domain detection may be limited.")} checked={value.sniffing.metadata_only} scope="server" t={t} onChange={(metadata_only) => setValue({ ...value, sniffing: { ...value.sniffing, metadata_only } })} />
                    <SwitchField label={t("Route only")} help={t("Uses the sniffed destination only for routing while preserving the original destination for the outbound connection.")} checked={value.sniffing.route_only} scope="server" t={t} onChange={(route_only) => setValue({ ...value, sniffing: { ...value.sniffing, route_only } })} />
                  </div>
                  <TextAreaField label={t("Excluded IPs")} help={t("IP addresses, CIDRs, or geoip expressions that sniffing must not override, one per line.")} value={value.sniffing.ips_excluded.join("\n")} placeholder="geoip:private" scope="server" t={t} onChange={(raw) => setValue({ ...value, sniffing: { ...value.sniffing, ips_excluded: lines(raw) } })} />
                  <TextAreaField label={t("Excluded domains")} help={t("Domain expressions that sniffing must not override, one per line.")} value={value.sniffing.domains_excluded.join("\n")} placeholder="domain:example.com" scope="server" t={t} onChange={(raw) => setValue({ ...value, sniffing: { ...value.sniffing, domains_excluded: lines(raw) } })} />
                </>
              ) : null}
            </TabsContent>
          </Tabs>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t("Cancel")}</Button>
            <Button type="submit">{t("Apply inbound")}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function updateFallback(value: ProxyService, setValue: (value: ProxyService) => void, index: number, fallback: VLESSFallback) {
  const fallbacks = value.vless_reality.fallbacks.map((candidate, candidateIndex) => candidateIndex === index ? fallback : candidate)
  setValue({ ...value, vless_reality: { ...value.vless_reality, fallbacks } })
}

function updateSockopt(value: ProxyService, setValue: (value: ProxyService) => void, sockopt: SocketSettings) {
  setValue({ ...value, sockopt })
}

function updateCustomSockopt(value: ProxyService, setValue: (value: ProxyService) => void, index: number, option: CustomSockopt) {
  if (value.sockopt == null) return
  const custom = value.sockopt.custom.map((candidate, candidateIndex) => candidateIndex === index ? option : candidate)
  setValue({ ...value, sockopt: { ...value.sockopt, custom } })
}

function numberList(value: string): number[] {
  if (value.trim() === "") return []
  return value.split(/[\s,]+/).map(Number).filter((item) => Number.isInteger(item))
}

function FieldLabel({ label, help, scope = "server", t }: { label: string; help: string; scope?: FieldScope; t: Translator }) {
  return (
    <div className="grid min-w-0 gap-1.5">
      <div className="flex min-w-0 items-center gap-1.5">
        <Label>{label}</Label>
        <Tooltip>
          <TooltipTrigger asChild>
            <button type="button" className="inline-flex size-5 shrink-0 cursor-help items-center justify-center rounded-sm text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label={`${label}: ${help}`}>
              <CircleHelp className="size-3.5" aria-hidden="true" />
            </button>
          </TooltipTrigger>
          <TooltipContent side="top" sideOffset={6} className="max-w-72 whitespace-normal leading-relaxed">{help}</TooltipContent>
        </Tooltip>
      </div>
      <FieldScopeBadges scope={scope} t={t} />
    </div>
  )
}

function ReadOnlyField({ label, help, value, scope = "server", t }: { label: string; help: string; value: string; scope?: FieldScope; t: Translator }) {
  return <div className="grid gap-2"><FieldLabel label={label} help={help} scope={scope} t={t} /><div className="flex h-9 items-center rounded-md border bg-muted/50 px-3 text-sm text-muted-foreground">{value}</div></div>
}

function TextField({ label, help, value, placeholder, required, maxLength, scope = "server", t, onChange }: { label: string; help: string; value: string; placeholder?: string; required?: boolean; maxLength?: number; scope?: FieldScope; t: Translator; onChange: (value: string) => void }) {
  return <div className="grid gap-2"><FieldLabel label={label} help={help} scope={scope} t={t} /><Input value={value} placeholder={placeholder} required={required} maxLength={maxLength} onChange={(event) => onChange(event.target.value)} /></div>
}

function NumberField({ label, help, value, min, max, required, scope = "server", t, onChange }: { label: string; help: string; value: number; min: number; max?: number; required?: boolean; scope?: FieldScope; t: Translator; onChange: (value: number) => void }) {
  return <div className="grid gap-2"><FieldLabel label={label} help={help} scope={scope} t={t} /><Input type="number" value={value} min={min} max={max} required={required} onChange={(event) => onChange(Number(event.target.value))} /></div>
}

function TextAreaField({ label, help, value, placeholder, required, readOnly, scope = "server", t, onChange }: { label: string; help: string; value: string; placeholder?: string; required?: boolean; readOnly?: boolean; scope?: FieldScope; t: Translator; onChange: (value: string) => void }) {
  return <div className="grid gap-2"><FieldLabel label={label} help={help} scope={scope} t={t} /><Textarea value={value} placeholder={placeholder} required={required} readOnly={readOnly} onChange={(event) => onChange(event.target.value)} /></div>
}

function SwitchField({ label, help, checked, scope = "server", t, onChange }: { label: string; help: string; checked: boolean; scope?: FieldScope; t: Translator; onChange: (value: boolean) => void }) {
  return <div className="flex min-h-14 items-center justify-between gap-4 rounded-lg border px-4 py-3"><FieldLabel label={label} help={help} scope={scope} t={t} /><Switch checked={checked} onCheckedChange={onChange} /></div>
}

function FieldScopeBadges({ scope, t }: { scope: FieldScope; t: Translator }) {
  if (scope === "server") {
    return <Badge variant="outline" className="text-muted-foreground"><Server />{t("Server only")}</Badge>
  }
  const capability = capabilities[scope]
  return (
    <div className="flex min-w-0 flex-wrap gap-1.5">
      {clientCores.map((core) => (
        <CoreBadge key={core} core={core} support={capability.cores[core]} t={t} />
      ))}
    </div>
  )
}

function CoreBadge({ core, support, t }: { core: ClientCore; support: (typeof capabilities)[CapabilityID]["cores"][ClientCore]; t: Translator }) {
  const name = coreName(core)
  if (support.status === "not-generated") {
    return <Badge variant="outline" className="border-destructive/30 bg-destructive/5 text-destructive"><XCircle />{name} · {t("Not generated")}</Badge>
  }
  if (support.status === "optional-ignored") {
    return <Badge variant="outline" className="text-muted-foreground"><CircleMinus />{name} · {t("Not required")}</Badge>
  }
  const evidence = support.evidence === "minimum" ? t("From {version}", { version: support.version }) : t("Verified {version}", { version: support.version })
  return <Badge variant="outline" className="border-success/30 bg-success-soft text-success"><CheckCircle2 />{name} · {evidence}</Badge>
}

function CompatibilitySummary({ compatibility, t }: { compatibility: ReturnType<typeof compatibilityFor>; t: Translator }) {
  return (
    <section className="grid gap-3 rounded-lg border bg-muted/30 p-4" aria-live="polite">
      <div className="grid gap-1">
        <h3 className="text-sm font-medium">{t("Client compatibility")}</h3>
        <p className="text-sm text-muted-foreground">{t("Updated from the parameters currently enabled below.")}</p>
      </div>
      <div className="grid gap-2">
        {compatibility.map((entry) => (
          <div key={entry.core} className="flex min-w-0 items-start gap-3 rounded-md border bg-background px-3 py-2.5 text-sm">
            {entry.supported ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" aria-hidden="true" /> : <XCircle className="mt-0.5 size-4 shrink-0 text-destructive" aria-hidden="true" />}
            <div className="min-w-0">
              <span className="font-medium">{coreName(entry.core)}</span>
              <span className="text-muted-foreground"> · {entry.supported
                ? entry.requirement?.evidence === "minimum"
                  ? t("Supported from {version}", { version: entry.requirement.version })
                  : t("Supported; verified with {version}", { version: entry.requirement?.version ?? "" })
                : t("Subscription not generated: {parameters}", { parameters: entry.blockers.map((blocker) => t(capabilities[blocker].label)).join(t(", ")) })}</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}

function RestrictedParameters({ children, t }: { children: React.ReactNode; t: Translator }) {
  return (
    <section className="grid gap-4 border-t border-dashed pt-5">
      <div className="grid gap-1">
        <h3 className="text-sm font-medium">{t("Restricted connection parameters")}</h3>
        <p className="text-sm text-muted-foreground">{t("These parameters are shown directly, but not every client core can use them.")}</p>
      </div>
      {children}
    </section>
  )
}

function coreName(core: ClientCore): string {
  if (core === "xray") return "Xray"
  if (core === "sing-box") return "sing-box"
  return "Mihomo"
}

function ListSection({ title, help, actionLabel, onAdd, actionSwitch, checked, onSwitch, scope = "server", t, children }: { title: string; help: string; actionLabel: string; onAdd?: () => void; actionSwitch?: boolean; checked?: boolean; onSwitch?: (checked: boolean) => void; scope?: FieldScope; t: Translator; children: React.ReactNode }) {
  return (
    <section className="grid gap-4 rounded-lg border p-4">
      <div className="flex items-center justify-between gap-4">
        <FieldLabel label={title} help={help} scope={scope} t={t} />
        {actionSwitch ? <Switch checked={checked} onCheckedChange={onSwitch} aria-label={actionLabel} /> : <Button type="button" variant="outline" size="sm" onClick={onAdd}><Plus />{actionLabel}</Button>}
      </div>
      {children}
    </section>
  )
}

function LimitFallbackFields({ title, value, onChange, t }: { title: string; value: RealityLimitFallback; onChange: (value: RealityLimitFallback) => void; t: Translator }) {
  return (
    <div className="grid gap-4">
      <h4 className="text-sm font-medium">{title}</h4>
      <NumberField label={t("After bytes")} help={t("Number of fallback bytes sent before rate limiting starts.")} value={value.after_bytes} min={0} scope="server" t={t} onChange={(after_bytes) => onChange({ ...value, after_bytes })} />
      <NumberField label={t("Bytes per second")} help={t("Sustained fallback transfer limit in bytes per second; 0 disables this limit.")} value={value.bytes_per_sec} min={0} scope="server" t={t} onChange={(bytes_per_sec) => onChange({ ...value, bytes_per_sec })} />
      <NumberField label={t("Burst bytes per second")} help={t("Temporary fallback burst allowance in bytes per second; 0 disables the burst allowance.")} value={value.burst_bytes_per_sec} min={0} scope="server" t={t} onChange={(burst_bytes_per_sec) => onChange({ ...value, burst_bytes_per_sec })} />
    </div>
  )
}
