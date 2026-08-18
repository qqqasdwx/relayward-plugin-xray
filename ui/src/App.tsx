import { useEffect, useMemo, useRef, useState } from "react"
import { RefreshCw, Save } from "lucide-react"

import { DNSPanel } from "@/components/DNSPanel"
import { DNSServerDialog } from "@/components/DNSServerDialog"
import { RoutingPanel } from "@/components/RoutingPanel"
import { RoutingRuleDialog } from "@/components/RoutingRuleDialog"
import { RuntimePanel } from "@/components/RuntimePanel"
import { ServiceDialog } from "@/components/ServiceDialog"
import { ServicesPanel } from "@/components/ServicesPanel"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  configurationForSave,
  configurationFromStored,
  moveItem,
  nextDNSServerDefaults,
  nextRoutingRuleDefaults,
  nextServiceDefaults,
} from "@/configuration"
import { translator } from "@/i18n"
import { createClient, type RelaywardUIClient } from "@/sdk"
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

interface DialogState<T> {
  initial: T
  editingID: string | null
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string")
}

function isNumberArray(value: unknown): value is number[] {
  return Array.isArray(value) && value.every((item) => Number.isInteger(item))
}

function isStringArrayRecord(value: unknown): value is Record<string, string[]> {
  return isRecord(value) && Object.values(value).every(isStringArray)
}

function isTCPHeader(value: unknown): boolean {
  if (!isRecord(value) || (value.type !== "none" && value.type !== "http")) return false
  if (value.type === "none") return value.request == null && value.response == null
  if (!isRecord(value.request) || !isRecord(value.response)) return false
  return typeof value.request.version === "string" && typeof value.request.method === "string" &&
    isStringArray(value.request.path) && isStringArrayRecord(value.request.headers) &&
    typeof value.response.version === "string" && typeof value.response.status === "string" &&
    typeof value.response.reason === "string" && isStringArrayRecord(value.response.headers)
}

function isCustomSockopt(value: unknown): boolean {
  return isRecord(value) && (value.system === "" || value.system === "linux") &&
    (value.network === "" || value.network === "tcp" || value.network === "tcp4" || value.network === "tcp6") &&
    typeof value.level === "string" && typeof value.opt === "string" &&
    (value.type === "int" || value.type === "str") && typeof value.value === "string"
}

function isSocketSettings(value: unknown): boolean {
  return isRecord(value) && Number.isInteger(value.mark) && typeof value.tcp_fast_open === "boolean" &&
    (value.tproxy === "off" || value.tproxy === "redirect" || value.tproxy === "tproxy") &&
    typeof value.accept_proxy_protocol === "boolean" && typeof value.tcp_mptcp === "boolean" &&
    Number.isInteger(value.tcp_keep_alive_interval) && Number.isInteger(value.tcp_keep_alive_idle) &&
    Number.isInteger(value.tcp_max_seg) && Number.isInteger(value.tcp_user_timeout) &&
    Number.isInteger(value.tcp_window_clamp) &&
    (value.tcp_congestion === "" || value.tcp_congestion === "bbr" || value.tcp_congestion === "cubic" || value.tcp_congestion === "reno") &&
    typeof value.v6_only === "boolean" && Array.isArray(value.custom) && value.custom.every(isCustomSockopt)
}

function isFallback(value: unknown): boolean {
  return isRecord(value) && typeof value.name === "string" && typeof value.alpn === "string" &&
    typeof value.path === "string" && typeof value.dest === "string" && Number.isInteger(value.xver)
}

function isLimitFallback(value: unknown): boolean {
  return isRecord(value) && Number.isInteger(value.after_bytes) && Number.isInteger(value.bytes_per_sec) &&
    Number.isInteger(value.burst_bytes_per_sec)
}

function isService(value: unknown): value is ProxyService {
  if (!isRecord(value) || !isRecord(value.vless_reality) || !isRecord(value.tcp) ||
      !isRecord(value.tcp.header) || !isRecord(value.sniffing)) return false
  if (value.sockopt != null && !isSocketSettings(value.sockopt)) return false
  if (value.vless_reality.limit_fallback_upload != null && !isLimitFallback(value.vless_reality.limit_fallback_upload)) return false
  if (value.vless_reality.limit_fallback_download != null && !isLimitFallback(value.vless_reality.limit_fallback_download)) return false
  return typeof value.type === "string" && typeof value.enabled === "boolean" &&
    typeof value.service_id === "string" && typeof value.display_name === "string" &&
    typeof value.listen === "string" && Number.isInteger(value.port) && typeof value.public_host === "string" && Number.isInteger(value.public_port) &&
    typeof value.tcp.accept_proxy_protocol === "boolean" && isTCPHeader(value.tcp.header) &&
    typeof value.sniffing.enabled === "boolean" && isStringArray(value.sniffing.dest_override) &&
    typeof value.sniffing.metadata_only === "boolean" && typeof value.sniffing.route_only === "boolean" &&
    isStringArray(value.sniffing.ips_excluded) && isStringArray(value.sniffing.domains_excluded) &&
    typeof value.vless_reality.show === "boolean" && Number.isInteger(value.vless_reality.xver) &&
    typeof value.vless_reality.decryption === "string" && typeof value.vless_reality.encryption === "string" &&
    isNumberArray(value.vless_reality.test_seed) && Array.isArray(value.vless_reality.fallbacks) && value.vless_reality.fallbacks.every(isFallback) &&
    typeof value.vless_reality.target === "string" && isStringArray(value.vless_reality.server_names) &&
    typeof value.vless_reality.private_key === "string" && typeof value.vless_reality.public_key === "string" && isStringArray(value.vless_reality.short_ids) &&
    typeof value.vless_reality.min_client_version === "string" && typeof value.vless_reality.max_client_version === "string" &&
    Number.isInteger(value.vless_reality.max_time_diff) && typeof value.vless_reality.flow === "string" &&
    typeof value.vless_reality.mldsa65_seed === "string" && typeof value.vless_reality.mldsa65_verify === "string" &&
    typeof value.vless_reality.master_key_log === "string" &&
    typeof value.vless_reality.fingerprint === "string" && typeof value.vless_reality.spider_x === "string"
}

function isRoutingRule(value: unknown): value is RoutingRule {
  if (!isRecord(value)) return false
  return typeof value.rule_id === "string" && typeof value.display_name === "string" &&
    typeof value.enabled === "boolean" && isStringArray(value.domains) && isStringArray(value.ip_cidrs) &&
    isStringArray(value.protocols) && (value.action === "blocked" || value.action === "direct")
}

function isDNSServer(value: unknown): value is DNSServer {
  if (!isRecord(value)) return false
  return typeof value.server_id === "string" && typeof value.display_name === "string" &&
    typeof value.enabled === "boolean" && ["system", "udp", "tcp", "doh"].includes(String(value.transport)) &&
    typeof value.address === "string" && Number.isInteger(value.port) && isStringArray(value.domains)
}

function isConfiguration(value: unknown): value is EditableConfiguration {
  if (!isRecord(value) || !isRecord(value.routing) || !isRecord(value.dns)) return false
  return typeof value.xray_version === "string" && Number.isInteger(value.api_port) &&
    Array.isArray(value.services) && value.services.every(isService) &&
    Array.isArray(value.routing.rules) && value.routing.rules.every(isRoutingRule) &&
    typeof value.dns.enabled === "boolean" && ["use-ip", "use-ipv4", "use-ipv6"].includes(String(value.dns.query_strategy)) &&
    Array.isArray(value.dns.servers) && value.dns.servers.every(isDNSServer)
}

function parseServiceTypes(response: unknown): ServiceType[] {
  if (!isRecord(response) || !Array.isArray(response.service_types)) throw new Error("Relayward returned invalid service types")
  return response.service_types.map((value) => {
    if (!isRecord(value) || typeof value.id !== "string" || typeof value.display_name !== "string") {
      throw new Error("Relayward returned invalid service types")
    }
    return { id: value.id, display_name: value.display_name }
  })
}

function parseStored(response: unknown): StoredConfiguration {
  if (!isRecord(response) || typeof response.exists !== "boolean" || typeof response.node_id !== "string") {
    throw new Error("Relayward returned an invalid Xray configuration")
  }
  if (!response.exists) return { exists: false, node_id: response.node_id }
  if (!Number.isInteger(response.generation) || !isConfiguration(response.configuration)) {
    throw new Error("Relayward returned an invalid Xray configuration")
  }
  return {
    exists: true,
    node_id: response.node_id,
    generation: response.generation as number,
    version: typeof response.version === "string" ? response.version : undefined,
    sha256: typeof response.sha256 === "string" ? response.sha256 : undefined,
    configuration: response.configuration,
  }
}

function errorMessage(cause: unknown, fallback: string) {
  return cause instanceof Error && cause.message ? cause.message : fallback
}

export function App() {
  const clientRef = useRef<RelaywardUIClient | null>(null)
  const formRef = useRef<HTMLFormElement | null>(null)
  const [locale, setLocale] = useState<Locale>("en")
  const [serviceTypes, setServiceTypes] = useState<ServiceType[]>([])
  const [nodeID, setNodeID] = useState("")
  const [stored, setStored] = useState<StoredConfiguration | null>(null)
  const [draft, setDraft] = useState<EditableConfiguration | null>(null)
  const [busy, setBusy] = useState(true)
  const [notice, setNotice] = useState("")
  const [error, setError] = useState("")
  const [serviceDialog, setServiceDialog] = useState<DialogState<ProxyService> | null>(null)
  const [routingDialog, setRoutingDialog] = useState<DialogState<RoutingRule> | null>(null)
  const [dnsDialog, setDNSDialog] = useState<DialogState<DNSServer> | null>(null)
  const t = useMemo(() => translator(locale), [locale])
  useEffect(() => {
    let cancelled = false
    let client: RelaywardUIClient | null = null
    let bootstrapLocale: Locale = "en"
    async function bootstrap() {
      try {
        client = createClient()
        clientRef.current = client
        const context = await client.context()
        if (cancelled) return
        bootstrapLocale = context.locale
        document.documentElement.lang = context.locale
        document.documentElement.dataset.theme = context.theme
        setLocale(context.locale)
        if (context.scope?.kind !== "node") throw new Error(translator(context.locale)("Xray requires a node context."))
        const scopedNodeID = context.scope.node_id
        setNodeID(scopedNodeID)
        const types = parseServiceTypes(await client.rpc("service-types.list", {}))
        if (types.length === 0) throw new Error("Relayward returned invalid service types")
        const loaded = parseStored(await client.rpc("configuration.get", { node_id: scopedNodeID }))
        if (cancelled) return
        setServiceTypes(types)
        setStored(loaded)
        setDraft(configurationFromStored(loaded, context.locale))
      } catch (cause) {
        if (!cancelled) setError(errorMessage(cause, translator(bootstrapLocale)("The request could not be completed.")))
      } finally {
        if (!cancelled) setBusy(false)
      }
    }
    void bootstrap()
    return () => {
      cancelled = true
      client?.dispose()
      if (clientRef.current === client) clientRef.current = null
    }
  }, [])

  function markChanged(value: EditableConfiguration) {
    setDraft(value)
    setNotice(t("Configuration changes are ready. Save to publish them."))
    setError("")
  }

  async function refreshConfiguration() {
    const client = clientRef.current
    if (client == null || nodeID === "") return
    setBusy(true)
    setNotice("")
    setError("")
    try {
      const loaded = parseStored(await client.rpc("configuration.get", { node_id: nodeID }))
      setStored(loaded)
      setDraft(configurationFromStored(loaded, locale))
    } catch (cause) {
      setError(errorMessage(cause, t("The request could not be completed.")))
    } finally {
      setBusy(false)
    }
  }

  async function confirmDelete(title: string, message: string) {
    const client = clientRef.current
    if (client == null) return false
    try {
      return await client.confirm({ title, message, confirm_label: t("Delete"), destructive: true })
    } catch (cause) {
      setError(errorMessage(cause, t("The request could not be completed.")))
      return false
    }
  }

  async function saveConfiguration(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const client = clientRef.current
    if (client == null || draft == null || nodeID === "" || busy || !formRef.current?.reportValidity()) return
    if (draft.dns.enabled && !draft.dns.servers.some((server) => server.enabled)) {
      setError(t("Enabled DNS requires at least one enabled server."))
      return
    }
    setBusy(true)
    setNotice("")
    setError("")
    try {
      await client.rpc("configuration.save", {
        node_id: nodeID,
        expected_generation: stored?.exists ? stored.generation ?? 0 : 0,
        configuration: configurationForSave(draft),
      })
      const loaded = parseStored(await client.rpc("configuration.get", { node_id: nodeID }))
      setStored(loaded)
      setDraft(configurationFromStored(loaded, locale))
      setNotice(t("Configuration saved."))
    } catch (cause) {
      setError(errorMessage(cause, t("The request could not be completed.")))
    } finally {
      setBusy(false)
    }
  }

  function openNewService() {
    if (draft == null) return
    if (draft.services.length >= 64) { setError(t("A node can contain at most 64 inbounds.")); return }
    setServiceDialog({ initial: nextServiceDefaults(draft.services, serviceTypes), editingID: null })
  }

  function applyService(inbound: ProxyService) {
    if (draft == null || serviceDialog == null) return
    const services = serviceDialog.editingID == null
      ? [...draft.services, inbound]
      : draft.services.map((candidate) => candidate.service_id === serviceDialog.editingID ? inbound : candidate)
    services.sort((first, second) => first.service_id.localeCompare(second.service_id))
    markChanged({ ...draft, services })
    setServiceDialog(null)
  }

  async function deleteService(inbound: ProxyService) {
    if (draft == null || !await confirmDelete(t("Delete inbound"), t("Delete {name}? The change is published only after you save the configuration.", { name: inbound.display_name }))) return
    markChanged({ ...draft, services: draft.services.filter((candidate) => candidate.service_id !== inbound.service_id) })
  }

  function openNewRoutingRule() {
    if (draft == null) return
    if (draft.routing.rules.length >= 128) { setError(t("A node can contain at most 128 routing rules.")); return }
    setRoutingDialog({ initial: nextRoutingRuleDefaults(draft.routing.rules, locale), editingID: null })
  }

  function applyRoutingRule(rule: RoutingRule) {
    if (draft == null || routingDialog == null) return
    const rules = routingDialog.editingID == null
      ? [...draft.routing.rules, rule]
      : draft.routing.rules.map((candidate) => candidate.rule_id === routingDialog.editingID ? rule : candidate)
    markChanged({ ...draft, routing: { rules } })
    setRoutingDialog(null)
  }

  async function deleteRoutingRule(rule: RoutingRule) {
    if (draft == null || !await confirmDelete(t("Delete routing rule"), t("Delete {name}? The rule remains active until you save the configuration.", { name: rule.display_name }))) return
    markChanged({ ...draft, routing: { rules: draft.routing.rules.filter((candidate) => candidate.rule_id !== rule.rule_id) } })
  }

  function openNewDNSServer() {
    if (draft == null) return
    if (draft.dns.servers.length >= 16) { setError(t("A node can contain at most 16 DNS servers.")); return }
    setDNSDialog({ initial: nextDNSServerDefaults(draft.dns.servers, locale), editingID: null })
  }

  function applyDNSServer(server: DNSServer) {
    if (draft == null || dnsDialog == null) return
    const servers = dnsDialog.editingID == null
      ? [...draft.dns.servers, server]
      : draft.dns.servers.map((candidate) => candidate.server_id === dnsDialog.editingID ? server : candidate)
    markChanged({ ...draft, dns: { ...draft.dns, servers } })
    setDNSDialog(null)
  }

  async function deleteDNSServer(server: DNSServer) {
    if (draft == null || !await confirmDelete(t("Delete DNS server"), t("Delete {name}? The server remains active until you save the configuration.", { name: server.display_name }))) return
    markChanged({ ...draft, dns: { ...draft.dns, servers: draft.dns.servers.filter((candidate) => candidate.server_id !== server.server_id) } })
  }

  function changeDNS(value: DNSConfiguration) {
    if (draft != null) markChanged({ ...draft, dns: value })
  }

  return (
    <main className="grid min-h-screen grid-cols-[minmax(0,1fr)] content-start gap-6 p-4 lg:p-6">
      {notice ? <div role="status" className="rounded-lg border bg-muted/50 px-4 py-3 text-sm">{notice}</div> : null}
      {error ? <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">{error}</div> : null}

      {draft != null ? (
        <Card className="min-w-0">
          <form ref={formRef} className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-6" onSubmit={(event) => void saveConfiguration(event)}>
            <CardContent className="min-w-0">
              <Tabs defaultValue="services" className="min-w-0 gap-6">
                <div className="overflow-x-auto">
                  <TabsList className="grid w-full min-w-[28rem] grid-cols-4">
                    <TabsTrigger value="services">{t("Inbounds")}</TabsTrigger>
                    <TabsTrigger value="routing">{t("Routing")}</TabsTrigger>
                    <TabsTrigger value="dns">{t("DNS")}</TabsTrigger>
                    <TabsTrigger value="runtime">{t("Runtime")}</TabsTrigger>
                  </TabsList>
                </div>
                <TabsContent value="services" className="min-w-0">
                  <ServicesPanel services={draft.services} busy={busy} t={t} onAdd={openNewService} onEdit={(service) => setServiceDialog({ initial: service, editingID: service.service_id })} onDelete={(service) => void deleteService(service)} />
                </TabsContent>
                <TabsContent value="routing" className="min-w-0">
                  <RoutingPanel rules={draft.routing.rules} busy={busy} t={t} onAdd={openNewRoutingRule} onEdit={(rule) => setRoutingDialog({ initial: rule, editingID: rule.rule_id })} onDelete={(rule) => void deleteRoutingRule(rule)} onMove={(index, offset) => markChanged({ ...draft, routing: { rules: moveItem(draft.routing.rules, index, offset) } })} />
                </TabsContent>
                <TabsContent value="dns" className="min-w-0">
                  <DNSPanel value={draft.dns} busy={busy} t={t} onChange={changeDNS} onAdd={openNewDNSServer} onEdit={(server) => setDNSDialog({ initial: server, editingID: server.server_id })} onDelete={(server) => void deleteDNSServer(server)} onMove={(index, offset) => changeDNS({ ...draft.dns, servers: moveItem(draft.dns.servers, index, offset) })} />
                </TabsContent>
                <TabsContent value="runtime" className="min-w-0">
                  <RuntimePanel value={draft} busy={busy} t={t} onChange={markChanged} />
                </TabsContent>
              </Tabs>
            </CardContent>
            <CardFooter className="flex-col items-stretch justify-between gap-4 border-t sm:flex-row sm:items-center">
              <span className="text-sm text-muted-foreground">{stored?.exists ? t("Generation {generation}", { generation: stored.generation ?? 0 }) : t("Not configured")}</span>
              <div className="flex flex-col gap-2 sm:flex-row">
                <Button type="button" variant="outline" disabled={busy} onClick={() => void refreshConfiguration()}>
                  <RefreshCw className={busy ? "animate-spin" : undefined} />{t("Refresh")}
                </Button>
                <Button type="submit" disabled={busy}>
                  <Save />{busy ? t("Saving...") : t("Save configuration")}
                </Button>
              </div>
            </CardFooter>
          </form>
        </Card>
      ) : busy ? (
        <Card><CardContent className="grid min-h-40 place-content-center text-sm text-muted-foreground">{t("Loading...")}</CardContent></Card>
      ) : null}

      {serviceDialog ? <ServiceDialog initial={serviceDialog.initial} editingID={serviceDialog.editingID} existingIDs={draft?.services.map((service) => service.service_id) ?? []} t={t} onClose={() => setServiceDialog(null)} onApply={applyService} /> : null}
      {routingDialog ? <RoutingRuleDialog initial={routingDialog.initial} editingID={routingDialog.editingID} existingIDs={draft?.routing.rules.map((rule) => rule.rule_id) ?? []} t={t} onClose={() => setRoutingDialog(null)} onApply={applyRoutingRule} /> : null}
      {dnsDialog ? <DNSServerDialog initial={dnsDialog.initial} editingID={dnsDialog.editingID} existingIDs={draft?.dns.servers.map((server) => server.server_id) ?? []} t={t} onClose={() => setDNSDialog(null)} onApply={applyDNSServer} /> : null}
    </main>
  )
}
