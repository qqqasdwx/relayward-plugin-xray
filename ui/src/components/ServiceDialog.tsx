import { useState } from "react"
import { CheckCircle2, CircleHelp, CircleMinus, RefreshCw, Server, XCircle } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
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
import { randomVLESSPort } from "@/configuration"
import type { Translator } from "@/i18n"
import {
  capabilities,
  clientCores,
  compatibilityFor,
  type CapabilityID,
  type ClientCore,
} from "@/inboundCompatibility"
import type {
  ProxyService,
  SniffingDestination,
  ServiceType,
  ShadowsocksMethod,
} from "@/types"

const shadowsocksMethods: ShadowsocksMethod[] = [
  "2022-blake3-aes-256-gcm",
  "2022-blake3-aes-128-gcm",
  "aes-256-gcm",
  "aes-128-gcm",
  "chacha20-ietf-poly1305",
  "xchacha20-ietf-poly1305",
]
const sniffingDestinations: SniffingDestination[] = ["http", "tls", "quic", "fakedns"]
type FieldScope = "server" | CapabilityID

interface ServiceDialogProps {
  initial: ProxyService
  editingID: string | null
  existingIDs: string[]
  occupiedPorts: number[]
  apiPort: number
  serviceTypes: ServiceType[]
  createService: (type: string) => ProxyService
  t: Translator
  onClose: () => void
  onApply: (service: ProxyService) => void
}

function lines(value: string): string[] {
  return value.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean)
}

export function ServiceDialog({ initial, editingID, existingIDs, occupiedPorts, apiPort, serviceTypes, createService, t, onClose, onApply }: ServiceDialogProps) {
  const [value, setValue] = useState<ProxyService>(() => structuredClone(initial))
  const [duplicate, setDuplicate] = useState(false)

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const normalized: ProxyService = {
      ...value,
      service_id: value.service_id.trim(),
      display_name: value.display_name.trim(),
      listen: value.listen.trim(),
    }
    if (value.type === "shadowsocks" && value.shadowsocks != null) {
      normalized.vless_reality = undefined
      normalized.shadowsocks = {
        ...value.shadowsocks,
        server_key: value.shadowsocks.server_key.trim(),
      }
    } else if (value.vless_reality != null) {
      normalized.shadowsocks = undefined
      normalized.vless_reality = {
        target: value.vless_reality.target.trim(),
      }
    }
    const duplicateID = existingIDs.some((id) => id === normalized.service_id && id !== editingID)
    setDuplicate(duplicateID)
    if (duplicateID || portConflict || !event.currentTarget.reportValidity()) return
    onApply(normalized)
  }

  const reality = value.vless_reality!
  const portConflict = value.port === apiPort || occupiedPorts.includes(value.port)
  const compatibility = compatibilityFor(value)

  const typeField = (
    <FieldRow label={t("Inbound protocol")} help={t("Select the protocol accepted by this inbound. The protocol cannot be changed after the inbound is added.")} scope="server" t={t}>
      <Select disabled={editingID != null} value={value.type} onValueChange={(type) => setValue(createService(type))}>
        <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
        <SelectContent>{serviceTypes.map((type) => <SelectItem key={type.id} value={type.id}>{type.display_name}</SelectItem>)}</SelectContent>
      </Select>
    </FieldRow>
  )

  if (value.type === "shadowsocks" && value.shadowsocks != null) {
    const shadowsocks = value.shadowsocks
    const methodScope: FieldScope = shadowsocks.method.startsWith("2022-") ? "shadowsocks-2022" : "shadowsocks"
    return (
      <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
        <DialogContent className="h-[calc(100vh-2rem)] overflow-hidden sm:max-w-[calc(100vw-3rem)] xl:max-w-7xl" closeLabel={t("Close")}>
          <form className="grid min-h-0 grid-rows-[auto_minmax(0,1fr)_auto] gap-6 overflow-hidden" onSubmit={submit}>
            <DialogHeader>
              <DialogTitle>{t(editingID == null ? "Add inbound" : "Edit inbound")}</DialogTitle>
              <DialogDescription>Shadowsocks · TCP/UDP</DialogDescription>
            </DialogHeader>

            <div className="grid min-h-0 min-w-0 grid-rows-[auto_minmax(0,1fr)] items-stretch gap-6 overflow-hidden lg:grid-cols-[minmax(0,1fr)_20rem] lg:grid-rows-1">
              <Tabs defaultValue="basic" className="min-h-0 min-w-0 gap-5 overflow-hidden [&_[data-slot=tabs-content]]:min-h-0 [&_[data-slot=tabs-content]]:overflow-y-auto [&_[data-slot=tabs-content]]:pr-3 [&_[data-slot=tabs-content]]:[scrollbar-gutter:stable]">
                <TabsList className="grid h-auto w-full grid-cols-2 gap-1 p-1 sm:grid-cols-4">
                  <TabsTrigger value="basic" className="h-9">{t("Basic")}</TabsTrigger>
                  <TabsTrigger value="protocol" className="h-9">{t("Protocol")}</TabsTrigger>
                  <TabsTrigger value="transport" className="h-9">{t("Transport")}</TabsTrigger>
                  <TabsTrigger value="sniffing" className="h-9">{t("Sniffing")}</TabsTrigger>
                </TabsList>

                <TabsContent value="basic" className="grid gap-5">
                  <FormCard>
                    <SwitchField label={t("Enable")} help={t("Controls whether this inbound is included in the Xray configuration.")} checked={value.enabled} scope="server" t={t} onChange={(enabled) => setValue({ ...value, enabled })} />
                    {typeField}
                    <TextField label={t("Remark")} help={t("A readable name used to identify this inbound in Relayward and subscriptions.")} value={value.display_name} maxLength={100} required scope="server" t={t} onChange={(display_name) => setValue({ ...value, display_name })} />
                    <FieldRow label={t("Inbound tag")} help={t("The unique Xray inbound tag. It is also used by routing, authorization, and telemetry.")} scope="server" t={t}>
                      <div className="grid gap-2">
                        <Input id="inbound-tag" value={value.service_id} disabled={editingID != null} pattern="[a-z0-9][a-z0-9._\-]{0,63}" maxLength={64} required aria-invalid={duplicate} onChange={(event) => { setValue({ ...value, service_id: event.target.value }); setDuplicate(false) }} />
                        {duplicate ? <p className="text-sm text-destructive">{t("Inbound tag already exists.")}</p> : null}
                      </div>
                    </FieldRow>
                    <ReadOnlyField label={t("Protocol")} help={t("The client protocol accepted by this inbound.")} value="Shadowsocks" scope="shadowsocks" t={t} />
                    <TextField label={t("Address")} help={t("The local address Xray listens on. Use 0.0.0.0 to listen on all IPv4 interfaces.")} value={value.listen} required scope="server" t={t} onChange={(listen) => setValue({ ...value, listen })} />
                    <NumberField label={t("Port")} help={t("The local port Xray listens on for this inbound.")} value={value.port} min={1} max={65535} required scope="server" t={t} onChange={(port) => setValue({ ...value, port })} />
                  </FormCard>
                </TabsContent>

                <TabsContent value="protocol" className="grid gap-5">
                  <FormCard>
                    <FieldRow label={t("Encryption method")} help={t("The Shadowsocks cipher used by the server and generated client subscriptions.")} scope={methodScope} t={t}>
                      <Select value={shadowsocks.method} onValueChange={(method: ShadowsocksMethod) => setValue({ ...value, shadowsocks: { ...shadowsocks, method, server_key: "" } })}>
                        <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                        <SelectContent>{shadowsocksMethods.map((method) => <SelectItem key={method} value={method}>{method}</SelectItem>)}</SelectContent>
                      </Select>
                    </FieldRow>
                    {shadowsocks.method.startsWith("2022-") ? (
                      <TextAreaField label={t("Server key")} help={t("The Shadowsocks 2022 server key. Leave empty to generate a method-sized key when saving.")} value={shadowsocks.server_key} placeholder={t("Leave empty to generate automatically")} scope="server" t={t} onChange={(server_key) => setValue({ ...value, shadowsocks: { ...shadowsocks, server_key } })} />
                    ) : (
                      <SwitchField label="IV check" help={t("Rejects repeated initialization vectors for traditional AEAD methods to reduce replay risk.")} checked={shadowsocks.iv_check} scope="server" t={t} onChange={(iv_check) => setValue({ ...value, shadowsocks: { ...shadowsocks, iv_check } })} />
                    )}
                  </FormCard>
                </TabsContent>

                <TabsContent value="transport" className="grid gap-5">
                  <FormCard>
                    <FieldRow label={t("Network")} help={t("Select whether this Shadowsocks inbound accepts TCP, UDP, or both.")} scope="server" t={t}>
                      <Select value={shadowsocks.network} onValueChange={(network: "tcp" | "udp" | "tcp,udp") => setValue({ ...value, shadowsocks: { ...shadowsocks, network } })}>
                        <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                        <SelectContent><SelectItem value="tcp,udp">TCP + UDP</SelectItem><SelectItem value="tcp">TCP</SelectItem><SelectItem value="udp">UDP</SelectItem></SelectContent>
                      </Select>
                    </FieldRow>
                  </FormCard>
                </TabsContent>

                <TabsContent value="sniffing" className="grid gap-5">
                  <FormCard>
                    <SwitchField label={t("Enable")} help={t("Lets Xray inspect initial traffic metadata to identify the destination protocol or domain for routing.")} checked={value.sniffing.enabled} scope="server" t={t} onChange={(enabled) => setValue({ ...value, sniffing: { ...value.sniffing, enabled } })} />
                    {value.sniffing.enabled ? (
                      <>
                        <FieldRow label={t("Destination override")} help={t("Protocols whose sniffed destination may replace the original destination for routing or connection handling.")} scope="server" t={t}>
                          <div className="grid gap-3">
                            {sniffingDestinations.map((destination) => (
                              <label key={destination} className="flex cursor-pointer items-center gap-3 rounded-lg border p-3 text-sm">
                                <Checkbox checked={value.sniffing.dest_override.includes(destination)} onCheckedChange={(checked) => setValue({ ...value, sniffing: { ...value.sniffing, dest_override: checked ? [...value.sniffing.dest_override, destination] : value.sniffing.dest_override.filter((item) => item !== destination) } })} />
                                {destination}
                              </label>
                            ))}
                          </div>
                        </FieldRow>
                        <SwitchField label={t("Metadata only")} help={t("Uses connection metadata without inspecting application payload. Protocol and domain detection may be limited.")} checked={value.sniffing.metadata_only} scope="server" t={t} onChange={(metadata_only) => setValue({ ...value, sniffing: { ...value.sniffing, metadata_only } })} />
                        <SwitchField label={t("Route only")} help={t("Uses the sniffed destination only for routing while preserving the original destination for the outbound connection.")} checked={value.sniffing.route_only} scope="server" t={t} onChange={(route_only) => setValue({ ...value, sniffing: { ...value.sniffing, route_only } })} />
                        <TextAreaField label={t("Excluded IPs")} help={t("IP addresses, CIDRs, or geoip expressions that sniffing must not override, one per line.")} value={value.sniffing.ips_excluded.join("\n")} placeholder="geoip:private" scope="server" t={t} onChange={(raw) => setValue({ ...value, sniffing: { ...value.sniffing, ips_excluded: lines(raw) } })} />
                        <TextAreaField label={t("Excluded domains")} help={t("Domain expressions that sniffing must not override, one per line.")} value={value.sniffing.domains_excluded.join("\n")} placeholder="domain:example.com" scope="server" t={t} onChange={(raw) => setValue({ ...value, sniffing: { ...value.sniffing, domains_excluded: lines(raw) } })} />
                      </>
                    ) : null}
                  </FormCard>
                </TabsContent>
              </Tabs>

              <CompatibilitySummary compatibility={compatibility} t={t} />
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose}>{t("Cancel")}</Button>
              <Button type="submit">{t(editingID == null ? "Add inbound" : "Apply inbound")}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    )
  }

  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="h-[calc(100vh-2rem)] overflow-hidden sm:max-w-[calc(100vw-3rem)] xl:max-w-7xl" closeLabel={t("Close")}>
        <form className="grid min-h-0 grid-rows-[auto_minmax(0,1fr)_auto] gap-6 overflow-hidden" onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{t(editingID == null ? "Add inbound" : "Edit inbound")}</DialogTitle>
            <DialogDescription>VLESS · RAW · REALITY</DialogDescription>
          </DialogHeader>

          <div className="grid min-h-0 min-w-0 grid-rows-[auto_minmax(0,1fr)] items-stretch gap-6 overflow-hidden lg:grid-cols-[minmax(0,1fr)_20rem] lg:grid-rows-1">
            <Tabs defaultValue="basic" className="min-h-0 min-w-0 gap-5 overflow-hidden [&_[data-slot=tabs-content]]:min-h-0 [&_[data-slot=tabs-content]]:overflow-y-auto [&_[data-slot=tabs-content]]:pr-3 [&_[data-slot=tabs-content]]:[scrollbar-gutter:stable]">
              <TabsList className="grid h-auto w-full grid-cols-3 gap-1 p-1">
                <TabsTrigger value="basic" className="h-9">{t("Basic")}</TabsTrigger>
                <TabsTrigger value="listener" className="h-9">{t("Listener")}</TabsTrigger>
                <TabsTrigger value="reality" className="h-9">REALITY</TabsTrigger>
              </TabsList>

              <TabsContent value="basic" className="grid gap-5">
                <FormCard>
                  <SwitchField label={t("Enable")} help={t("Controls whether this inbound is included in the Xray configuration.")} checked={value.enabled} scope="server" t={t} onChange={(enabled) => setValue({ ...value, enabled })} />
                  {typeField}
                  <TextField label={t("Remark")} help={t("A readable name used to identify this inbound in Relayward and subscriptions.")} value={value.display_name} maxLength={100} required scope="server" t={t} onChange={(display_name) => setValue({ ...value, display_name })} />
                  <FieldRow label={t("Inbound tag")} help={t("The unique Xray inbound tag. It is also used by routing, authorization, and telemetry.")} scope="server" t={t}>
                    <div className="grid gap-2">
                      <Input id="inbound-tag" value={value.service_id} disabled={editingID != null} pattern="[a-z0-9][a-z0-9._\-]{0,63}" maxLength={64} required aria-invalid={duplicate} onChange={(event) => { setValue({ ...value, service_id: event.target.value }); setDuplicate(false) }} />
                      {duplicate ? <p className="text-sm text-destructive">{t("Inbound tag already exists.")}</p> : null}
                    </div>
                  </FieldRow>
                  <ReadOnlyField label={t("Protocol")} help={t("The client protocol accepted by this inbound.")} value="VLESS" scope="vless" t={t} />
                </FormCard>
              </TabsContent>

              <TabsContent value="listener" className="grid gap-5">
                <FormCard>
                  <ReadOnlyField label={t("Listen address")} help={t("VLESS listens on all node network interfaces.")} value="0.0.0.0" t={t} />
                  <PortField
                    value={value.port}
                    conflict={portConflict}
                    t={t}
                    onChange={(port) => setValue({ ...value, port })}
                    onRandomize={() => {
                      const port = randomVLESSPort([...occupiedPorts, apiPort], value.port)
                      setValue({ ...value, port })
                    }}
                  />
                  <ReadOnlyField label={t("Transport")} help={t("The transport used by this inbound. RAW is Xray's direct TCP byte stream.")} value="RAW" scope="vless" t={t} />
                  <SwitchField label="PROXY Protocol" help={t("Reads the original source address from a PROXY protocol header sent by a trusted upstream relay. Do not enable it for direct client connections.")} checked={value.tcp.accept_proxy_protocol} scope="server" t={t} onChange={(accept_proxy_protocol) => setValue({ ...value, tcp: { ...value.tcp, accept_proxy_protocol } })} />
                  <ReadOnlyField label={t("Sniffing")} help={t("The plugin always sniffs HTTP, TLS, and QUIC destinations for routing without replacing the original target.")} value="HTTP · TLS · QUIC · routeOnly" t={t} />
                </FormCard>
              </TabsContent>

              <TabsContent value="reality" className="grid gap-5">
                <FormCard>
                  <ReadOnlyField label={t("Security")} help={t("The transport security used by this inbound. REALITY authenticates the server without a conventional TLS certificate.")} value="REALITY" scope="reality" t={t} />
                  <TextField label={t("Camouflage target")} help={t("A real TLS destination in host:port form used to disguise rejected or unauthenticated REALITY connections.")} value={reality.target} placeholder="www.tesla.com:443" required scope="server" t={t} onChange={(target) => setValue({ ...value, vless_reality: { target } })} />
                  <ReadOnlyField label="SNI" help={t("The plugin derives the only accepted SNI from the camouflage target.")} value={targetHost(reality.target) || t("Derived after a valid target is entered")} scope="reality" t={t} />
                  <ReadOnlyField label={t("Credentials")} help={t("The plugin generates and preserves the REALITY key pair and one 16-character Short ID.")} value={t("Managed by plugin")} scope="reality" t={t} />
                  <ReadOnlyField label={t("Fallback protection")} help={t("Rejected handshakes are restricted to the exact camouflage SNI and use fixed upload and download limits.")} value={t("Enabled")} t={t} />
                </FormCard>
              </TabsContent>

            </Tabs>

            <CompatibilitySummary compatibility={compatibility} t={t} />
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t("Cancel")}</Button>
            <Button type="submit">{t(editingID == null ? "Add inbound" : "Apply inbound")}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function targetHost(target: string): string {
  const separator = target.lastIndexOf(":")
  return separator > 0 ? target.slice(0, separator) : ""
}

function FormCard({ children }: { children: React.ReactNode }) {
  return (
    <Card className="min-w-0 gap-0 py-4 sm:py-6">
      <CardContent className="grid min-w-0 gap-5 px-4 sm:px-6">{children}</CardContent>
    </Card>
  )
}

function FieldLabel({ label, help, scope = "server", t }: { label: string; help: string; scope?: FieldScope; t: Translator }) {
  const capability = scope === "server" ? null : capabilities[scope]
  const compatibilityLabel = capability == null
    ? ""
    : clientCores.map((core) => `${coreName(core)}: ${supportDescription(capability.cores[core], t)}`).join("; ")
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1.5 sm:justify-end sm:text-right">
      <div className="flex min-w-0 items-center gap-1.5">
        <Label>{label}</Label>
        <Tooltip>
          <TooltipTrigger asChild>
            <button type="button" className="inline-flex size-5 shrink-0 cursor-help items-center justify-center rounded-sm text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label={`${label}: ${help}${compatibilityLabel === "" ? "" : `. ${compatibilityLabel}`}`}>
              <CircleHelp className="size-3.5" aria-hidden="true" />
            </button>
          </TooltipTrigger>
          <TooltipContent side="top" sideOffset={6} className="max-w-80 whitespace-normal p-3 text-left leading-relaxed">
            <div className="grid gap-2.5">
              <p>{help}</p>
              {capability ? (
                <div className="grid gap-1.5 border-t border-primary-foreground/20 pt-2">
                  {clientCores.map((core) => {
                    const support = capability.cores[core]
                    return (
                      <div key={core} className="flex items-center justify-between gap-4">
                        <span>{coreName(core)}</span>
                        <span className="flex items-center gap-1 text-right">
                          {support.status === "supported" ? <CheckCircle2 className="size-3.5" aria-hidden="true" /> : support.status === "not-generated" ? <XCircle className="size-3.5" aria-hidden="true" /> : <CircleMinus className="size-3.5" aria-hidden="true" />}
                          {supportDescription(support, t)}
                        </span>
                      </div>
                    )
                  })}
                </div>
              ) : null}
            </div>
          </TooltipContent>
        </Tooltip>
      </div>
      <FieldScopeBadges scope={scope} t={t} />
    </div>
  )
}

function FieldRow({ label, help, scope = "server", t, children }: { label: string; help: string; scope?: FieldScope; t: Translator; children: React.ReactNode }) {
  return (
    <div className="grid min-w-0 gap-2 sm:grid-cols-[10rem_minmax(0,1fr)] sm:items-start sm:gap-4">
      <FieldLabel label={label} help={help} scope={scope} t={t} />
      <div className="grid min-w-0 max-w-2xl gap-2">
        {children}
        <FieldCompatibilityBadges scope={scope} t={t} />
      </div>
    </div>
  )
}

function ReadOnlyField({ label, help, value, scope = "server", t }: { label: string; help: string; value: string; scope?: FieldScope; t: Translator }) {
  return <FieldRow label={label} help={help} scope={scope} t={t}><div className="flex h-9 items-center rounded-md border bg-muted/50 px-3 text-sm text-muted-foreground">{value}</div></FieldRow>
}

function TextField({ label, help, value, placeholder, required, maxLength, scope = "server", t, onChange }: { label: string; help: string; value: string; placeholder?: string; required?: boolean; maxLength?: number; scope?: FieldScope; t: Translator; onChange: (value: string) => void }) {
  return <FieldRow label={label} help={help} scope={scope} t={t}><Input value={value} placeholder={placeholder} required={required} maxLength={maxLength} onChange={(event) => onChange(event.target.value)} /></FieldRow>
}

function NumberField({ label, help, value, min, max, required, scope = "server", t, onChange }: { label: string; help: string; value: number; min: number; max?: number; required?: boolean; scope?: FieldScope; t: Translator; onChange: (value: number) => void }) {
  return <FieldRow label={label} help={help} scope={scope} t={t}><Input type="number" value={value} min={min} max={max} required={required} onChange={(event) => onChange(Number(event.target.value))} /></FieldRow>
}

function PortField({ value, conflict, t, onChange, onRandomize }: { value: number; conflict: boolean; t: Translator; onChange: (value: number) => void; onRandomize: () => void }) {
  return (
    <FieldRow label={t("Listening port")} help={t("A random port from 20000 to 29999 avoids common service ports and the Linux default ephemeral range.")} scope="server" t={t}>
      <div className="grid gap-2">
        <div className="flex gap-2">
          <Input type="number" value={value} min={1} max={65535} required aria-invalid={conflict} onChange={(event) => onChange(Number(event.target.value))} />
          <Button type="button" variant="outline" size="icon" title={t("Generate another random port")} aria-label={t("Generate another random port")} onClick={onRandomize}>
            <RefreshCw />
          </Button>
        </div>
        {conflict ? <p className="text-sm text-destructive">{t("This port conflicts with the local API or another inbound.")}</p> : null}
      </div>
    </FieldRow>
  )
}

function TextAreaField({ label, help, value, placeholder, required, readOnly, scope = "server", t, onChange }: { label: string; help: string; value: string; placeholder?: string; required?: boolean; readOnly?: boolean; scope?: FieldScope; t: Translator; onChange: (value: string) => void }) {
  return <FieldRow label={label} help={help} scope={scope} t={t}><Textarea value={value} placeholder={placeholder} required={required} readOnly={readOnly} onChange={(event) => onChange(event.target.value)} /></FieldRow>
}

function SwitchField({ label, help, checked, scope = "server", t, onChange }: { label: string; help: string; checked: boolean; scope?: FieldScope; t: Translator; onChange: (value: boolean) => void }) {
  return <FieldRow label={label} help={help} scope={scope} t={t}><div className="flex h-9 items-center"><Switch checked={checked} onCheckedChange={onChange} /></div></FieldRow>
}

function FieldScopeBadges({ scope, t }: { scope: FieldScope; t: Translator }) {
  if (scope === "server") {
    return <Badge variant="outline" className="text-muted-foreground"><Server />{t("Server only")}</Badge>
  }
  const capability = capabilities[scope]
  return capability.restricted
    ? <Badge variant="outline" className="border-destructive/30 bg-destructive/5 text-destructive">{t("Restricted")}</Badge>
    : null
}

function FieldCompatibilityBadges({ scope, t }: { scope: FieldScope; t: Translator }) {
  if (scope === "server") return null
  const capability = capabilities[scope]
  return (
    <div className="grid grid-cols-3 gap-1.5 sm:flex sm:flex-wrap">
      {clientCores.map((core) => {
        const support = capability.cores[core]
        const detail = support.status === "supported"
          ? `${support.version}${support.evidence === "minimum" ? "+" : ""}`
          : support.status === "not-generated" ? t("Not generated") : t("Not required")
        return (
          <Badge
            key={core}
            variant="outline"
            className={support.status === "supported" ? "min-w-0 border-success/30 bg-success-soft px-1.5 text-success sm:px-2" : support.status === "not-generated" ? "min-w-0 border-destructive/30 bg-destructive/5 px-1.5 text-destructive sm:px-2" : "min-w-0 px-1.5 text-muted-foreground sm:px-2"}
            title={`${coreName(core)} · ${supportDescription(support, t)}`}
          >
            {support.status === "supported" ? <CheckCircle2 aria-hidden="true" /> : support.status === "not-generated" ? <XCircle aria-hidden="true" /> : <CircleMinus aria-hidden="true" />}
            <span className="truncate">{coreName(core)}</span>
            <span className="hidden sm:inline">· {detail}</span>
          </Badge>
        )
      })}
    </div>
  )
}

function supportDescription(support: (typeof capabilities)[CapabilityID]["cores"][ClientCore], t: Translator): string {
  if (support.status === "not-generated") {
    return t("Not generated")
  }
  if (support.status === "optional-ignored") {
    return t("Not required")
  }
  return support.evidence === "minimum" ? t("From {version}", { version: support.version }) : t("Verified {version}", { version: support.version })
}

function CompatibilitySummary({ compatibility, t }: { compatibility: ReturnType<typeof compatibilityFor>; t: Translator }) {
  return (
    <section className="order-first grid gap-2 self-start rounded-lg border bg-background p-2 shadow-sm lg:order-last lg:gap-3 lg:p-4" aria-live="polite">
      <div className="col-span-full grid gap-1">
        <h3 className="text-sm font-medium">{t("Client compatibility")}</h3>
        <p className="hidden text-sm text-muted-foreground sm:block">{t("Updated from the parameters currently enabled below.")}</p>
      </div>
      <div className="grid grid-cols-3 gap-2 lg:grid-cols-1">
        {compatibility.map((entry) => {
          const description = entry.supported
            ? entry.requirement?.evidence === "minimum"
              ? t("Supported from {version}", { version: entry.requirement.version })
              : t("Supported; verified with {version}", { version: entry.requirement?.version ?? "" })
            : t("Subscription not generated: {parameters}", { parameters: entry.blockers.map((blocker) => t(capabilities[blocker].label)).join(t(", ")) })
          return (
            <div key={entry.core} className="flex min-w-0 flex-col items-center gap-1 rounded-md border bg-muted/20 px-1 py-1.5 text-center text-xs lg:flex-row lg:items-start lg:gap-3 lg:px-3 lg:py-2.5 lg:text-left lg:text-sm" title={`${coreName(entry.core)} · ${description}`}>
              {entry.supported ? <CheckCircle2 className="size-4 shrink-0 text-success lg:mt-0.5" aria-hidden="true" /> : <XCircle className="size-4 shrink-0 text-destructive lg:mt-0.5" aria-hidden="true" />}
              <div className="min-w-0">
                <span className="font-medium">{coreName(entry.core)}</span>
                <span className="hidden text-muted-foreground lg:inline"> · {description}</span>
                <span className="sr-only lg:hidden"> · {description}</span>
              </div>
            </div>
          )
        })}
      </div>
    </section>
  )
}

function coreName(core: ClientCore): string {
  if (core === "xray") return "Xray"
  if (core === "sing-box") return "sing-box"
  return "Mihomo"
}
