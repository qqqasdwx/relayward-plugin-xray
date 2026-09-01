import { useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { Activity, Globe2, Network, RefreshCw, Route, Save, Send } from "lucide-react"

import { DNSPanel } from "@/components/DNSPanel"
import { DNSServerDialog } from "@/components/DNSServerDialog"
import { OutboundDialog } from "@/components/OutboundDialog"
import { OutboundsPanel } from "@/components/OutboundsPanel"
import { RoutingPanel } from "@/components/RoutingPanel"
import { RoutingRuleDialog } from "@/components/RoutingRuleDialog"
import { RuntimePanel } from "@/components/RuntimePanel"
import { ServiceDialog } from "@/components/ServiceDialog"
import { ServicesPanel } from "@/components/ServicesPanel"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  configurationChanges,
  configurationForSave,
  configurationFromStored,
  configurationsEqual,
  moveItem,
  nextDNSServerDefaults,
  nextOutboundDefaults,
  nextRoutingRuleDefaults,
  nextServiceDefaults,
  type ConfigurationChanges,
  type NamedChanges,
} from "@/configuration"
import { translator, type Translator } from "@/i18n"
import { createClient, type RelaywardUIClient } from "@/sdk"
import type {
  DNSConfiguration,
  DNSServer,
  EditableConfiguration,
  Locale,
  ProxyService,
  RoutingRule,
  ServicePortDiagnostic,
  ServiceType,
  StoredConfiguration,
  XrayOutbound,
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

function isService(value: unknown): value is ProxyService {
  if (!isRecord(value) || !isRecord(value.tcp) || !isRecord(value.tcp.header) || !isRecord(value.sniffing)) return false
  if (value.sockopt != null && !isSocketSettings(value.sockopt)) return false
  const common = typeof value.type === "string" && typeof value.enabled === "boolean" &&
    typeof value.service_id === "string" && typeof value.display_name === "string" &&
    typeof value.listen === "string" && Number.isInteger(value.port) &&
    typeof value.tcp.accept_proxy_protocol === "boolean" && isTCPHeader(value.tcp.header) &&
    typeof value.sniffing.enabled === "boolean" && isStringArray(value.sniffing.dest_override) &&
    typeof value.sniffing.metadata_only === "boolean" && typeof value.sniffing.route_only === "boolean" &&
    isStringArray(value.sniffing.ips_excluded) && isStringArray(value.sniffing.domains_excluded)
  if (!common) return false
  if (value.type === "shadowsocks") {
    return value.vless_reality == null && isRecord(value.shadowsocks) &&
      ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"].includes(String(value.shadowsocks.method)) &&
      ["tcp", "udp", "tcp,udp"].includes(String(value.shadowsocks.network)) &&
      typeof value.shadowsocks.server_key === "string" && typeof value.shadowsocks.iv_check === "boolean"
  }
  if (value.type !== "vless-reality" || !isRecord(value.vless_reality) || value.shadowsocks != null) return false
  return typeof value.vless_reality.target === "string"
}

function isRoutingRule(value: unknown): value is RoutingRule {
  if (!isRecord(value)) return false
  return typeof value.rule_id === "string" && typeof value.display_name === "string" &&
    typeof value.enabled === "boolean" && isStringArray(value.source_ips) && typeof value.source_port === "string" &&
    typeof value.vless_route === "string" && ["", "tcp", "udp", "tcp,udp"].includes(String(value.network)) &&
    isStringArray(value.protocols) && isRecord(value.attributes) && Object.values(value.attributes).every((item) => typeof item === "string") &&
    isStringArray(value.destination_ips) && isStringArray(value.domains) && isStringArray(value.users) &&
    typeof value.destination_port === "string" && isStringArray(value.inbound_tags) && typeof value.outbound_tag === "string"
}

function isFreedomFragment(value: unknown): boolean {
  return isRecord(value) && typeof value.packets === "string" && typeof value.length === "string" &&
    typeof value.interval === "string" && typeof value.max_split === "string"
}

function isFreedomNoise(value: unknown): boolean {
  return isRecord(value) && ["rand", "str", "base64", "hex"].includes(String(value.type)) &&
    typeof value.packet === "string" && typeof value.delay === "string" && ["ip", "ipv4", "ipv6"].includes(String(value.apply_to))
}

function isFreedomFinalRule(value: unknown): boolean {
  return isRecord(value) && ["allow", "block"].includes(String(value.action)) &&
    ["", "tcp", "udp", "tcp,udp"].includes(String(value.network)) && typeof value.port === "string" &&
    isStringArray(value.ips) && typeof value.block_delay === "string"
}

function isOutbound(value: unknown): value is XrayOutbound {
  if (!isRecord(value) || typeof value.tag !== "string") return false
  if (value.protocol === "freedom") {
    if (!isRecord(value.freedom) || value.blackhole != null) return false
    return ["", "AsIs", "UseIP", "UseIPv4", "UseIPv6", "UseIPv6v4", "UseIPv4v6", "ForceIP", "ForceIPv6v4", "ForceIPv6", "ForceIPv4v6", "ForceIPv4"].includes(String(value.freedom.domain_strategy)) &&
      typeof value.freedom.redirect === "string" && Number.isInteger(value.freedom.user_level) &&
      [0, 1, 2].includes(Number(value.freedom.proxy_protocol)) &&
      (value.freedom.fragment == null || isFreedomFragment(value.freedom.fragment)) &&
      Array.isArray(value.freedom.noises) && value.freedom.noises.every(isFreedomNoise) &&
      Array.isArray(value.freedom.final_rules) && value.freedom.final_rules.every(isFreedomFinalRule)
  }
  return value.protocol === "blackhole" && value.freedom == null && isRecord(value.blackhole) &&
    ["", "none", "http"].includes(String(value.blackhole.response_type))
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
    Array.isArray(value.outbounds) && value.outbounds.every(isOutbound) &&
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

function parseDiagnostics(response: unknown): ServicePortDiagnostic[] {
  if (!isRecord(response) || !Array.isArray(response.diagnostics)) {
    throw new Error("Relayward returned invalid network diagnostics")
  }
  return response.diagnostics.map((value) => {
    if (!isRecord(value) || typeof value.service_id !== "string" ||
      (value.network !== "tcp" && value.network !== "udp") || !Number.isInteger(value.local_port) ||
      typeof value.listen_address !== "string" ||
      !["unknown", "listening", "not_listening"].includes(String(value.local_state)) ||
      typeof value.local_observed_at_unix_nano !== "number" || !Array.isArray(value.endpoints)) {
      throw new Error("Relayward returned invalid network diagnostics")
    }
    const endpoints = value.endpoints.map((endpoint) => {
      if (!isRecord(endpoint) || typeof endpoint.endpoint_id !== "string" || typeof endpoint.display_name !== "string" ||
        !["direct", "nat", "domain", "managed_ddns"].includes(String(endpoint.kind)) ||
        typeof endpoint.address !== "string" || !Number.isInteger(endpoint.port) ||
        !["reachable", "unreachable", "not_tested"].includes(String(endpoint.reachability)) ||
        !["", "node_offline", "local_not_listening", "endpoint_unavailable", "proxied_endpoint", "unsupported_network", "dns_failed", "connection_refused", "timeout", "network_unreachable"].includes(String(endpoint.reason))) {
        throw new Error("Relayward returned invalid network diagnostics")
      }
      return endpoint as unknown as ServicePortDiagnostic["endpoints"][number]
    })
    return { ...value, endpoints } as unknown as ServicePortDiagnostic
  })
}

function errorMessage(cause: unknown, fallback: string) {
  return cause instanceof Error && cause.message ? cause.message : fallback
}

export function App() {
  const clientRef = useRef<RelaywardUIClient | null>(null)
  const formRef = useRef<HTMLFormElement | null>(null)
  const diagnosticsRequestRef = useRef(0)
  const [locale, setLocale] = useState<Locale>("en")
  const [serviceTypes, setServiceTypes] = useState<ServiceType[]>([])
  const [nodeID, setNodeID] = useState("")
  const [stored, setStored] = useState<StoredConfiguration | null>(null)
  const [baseline, setBaseline] = useState<EditableConfiguration | null>(null)
  const [draft, setDraft] = useState<EditableConfiguration | null>(null)
  const [diagnostics, setDiagnostics] = useState<ServicePortDiagnostic[]>([])
  const [diagnosticsBusy, setDiagnosticsBusy] = useState(false)
  const [diagnosticsFailed, setDiagnosticsFailed] = useState(false)
  const [busy, setBusy] = useState(true)
  const [saving, setSaving] = useState(false)
  const [notice, setNotice] = useState("")
  const [error, setError] = useState("")
  const [serviceDialog, setServiceDialog] = useState<DialogState<ProxyService> | null>(null)
  const [outboundDialog, setOutboundDialog] = useState<DialogState<XrayOutbound> | null>(null)
  const [routingDialog, setRoutingDialog] = useState<DialogState<RoutingRule> | null>(null)
  const [dnsDialog, setDNSDialog] = useState<DialogState<DNSServer> | null>(null)
  const t = useMemo(() => translator(locale), [locale])
  const dirty = useMemo(() => draft != null && baseline != null && !configurationsEqual(baseline, draft), [baseline, draft])
  useEffect(() => {
    let cancelled = false
    let client: RelaywardUIClient | null = null
    const diagnosticRequests = diagnosticsRequestRef
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
        const initial = configurationFromStored(loaded, context.locale)
        setServiceTypes(types)
        setStored(loaded)
        setBaseline(configurationForSave(initial))
        setDraft(initial)
        void loadDiagnostics(client, scopedNodeID, loaded.exists)
      } catch (cause) {
        if (!cancelled) setError(errorMessage(cause, translator(bootstrapLocale)("The request could not be completed.")))
      } finally {
        if (!cancelled) setBusy(false)
      }
    }
    void bootstrap()
    return () => {
      cancelled = true
      diagnosticRequests.current++
      client?.dispose()
      if (clientRef.current === client) clientRef.current = null
    }
  }, [])

  function markChanged(value: EditableConfiguration) {
    setDraft(value)
    setNotice("")
    setError("")
  }

  async function loadDiagnostics(client: RelaywardUIClient, targetNodeID: string, configured: boolean) {
    const requestID = ++diagnosticsRequestRef.current
    setDiagnosticsBusy(true)
    setDiagnosticsFailed(false)
    if (!configured) {
      setDiagnostics([])
      setDiagnosticsBusy(false)
      return
    }
    try {
      const loaded = parseDiagnostics(await client.rpc("diagnostics.get", { node_id: targetNodeID }))
      if (diagnosticsRequestRef.current === requestID) setDiagnostics(loaded)
    } catch {
      if (diagnosticsRequestRef.current === requestID) {
        setDiagnostics([])
        setDiagnosticsFailed(true)
      }
    } finally {
      if (diagnosticsRequestRef.current === requestID) setDiagnosticsBusy(false)
    }
  }

  async function refreshConfiguration() {
    const client = clientRef.current
    if (client == null || nodeID === "") return
    setBusy(true)
    setNotice("")
    setError("")
    try {
      const loaded = parseStored(await client.rpc("configuration.get", { node_id: nodeID }))
      const refreshed = configurationFromStored(loaded, locale)
      setStored(loaded)
      setBaseline(configurationForSave(refreshed))
      setDraft(refreshed)
      void loadDiagnostics(client, nodeID, loaded.exists)
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
    if (client == null || draft == null || baseline == null || nodeID === "" || busy || saving || !dirty || !formRef.current?.reportValidity()) return
    if (draft.dns.enabled && !draft.dns.servers.some((server) => server.enabled)) {
      setError(t("Enabled DNS requires at least one enabled server."))
      return
    }
    setSaving(true)
    try {
      const confirmed = await client.confirm({
        title: t("Save Xray configuration?"),
        message: formatConfigurationChanges(configurationChanges(baseline, draft), t),
        confirm_label: t("Save configuration"),
        destructive: false,
      })
      if (!confirmed) return
      setNotice("")
      setError("")
      await client.rpc("configuration.save", {
        node_id: nodeID,
        expected_generation: stored?.exists ? stored.generation ?? 0 : 0,
        configuration: configurationForSave(draft),
      })
      const loaded = parseStored(await client.rpc("configuration.get", { node_id: nodeID }))
      const saved = configurationFromStored(loaded, locale)
      setStored(loaded)
      setBaseline(configurationForSave(saved))
      setDraft(saved)
      void loadDiagnostics(client, nodeID, loaded.exists)
      setNotice(t("Configuration saved."))
    } catch (cause) {
      setError(errorMessage(cause, t("The request could not be completed.")))
    } finally {
      setSaving(false)
    }
  }

  function openNewService() {
    if (draft == null) return
    if (draft.services.length >= 64) { setError(t("A node can contain at most 64 inbounds.")); return }
    setServiceDialog({ initial: nextServiceDefaults(draft.services, serviceTypes, undefined, [draft.api_port]), editingID: null })
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
    markChanged({
      ...draft,
      services: draft.services.filter((candidate) => candidate.service_id !== inbound.service_id),
    })
  }

  function openNewOutbound() {
    if (draft == null) return
    if (draft.outbounds.length >= 64) { setError(t("A node can contain at most 64 outbounds.")); return }
    setOutboundDialog({ initial: nextOutboundDefaults(draft.outbounds), editingID: null })
  }

  function applyOutbound(outbound: XrayOutbound) {
    if (draft == null || outboundDialog == null) return
    const previousTag = outboundDialog.editingID
    const outbounds = previousTag == null
      ? [...draft.outbounds, outbound]
      : draft.outbounds.map((candidate) => candidate.tag === previousTag ? outbound : candidate)
    const rules = previousTag == null || previousTag === outbound.tag
      ? draft.routing.rules
      : draft.routing.rules.map((rule) => rule.outbound_tag === previousTag ? { ...rule, outbound_tag: outbound.tag } : rule)
    markChanged({ ...draft, outbounds, routing: { rules } })
    setOutboundDialog(null)
  }

  async function deleteOutbound(outbound: XrayOutbound) {
    if (draft == null) return
    const affected = draft.routing.rules.filter((rule) => rule.outbound_tag === outbound.tag)
    const message = affected.length === 0
      ? t("Delete outbound {tag}? The change is published only after you save the configuration.", { tag: outbound.tag })
      : t("Delete outbound {tag} and {count} routing rules that use it?", { tag: outbound.tag, count: affected.length })
    if (!await confirmDelete(t("Delete outbound"), message)) return
    markChanged({
      ...draft,
      outbounds: draft.outbounds.filter((candidate) => candidate.tag !== outbound.tag),
      routing: { rules: draft.routing.rules.filter((rule) => rule.outbound_tag !== outbound.tag) },
    })
  }

  function openNewRoutingRule() {
    if (draft == null) return
    if (draft.routing.rules.length >= 128) { setError(t("A node can contain at most 128 routing rules.")); return }
    setRoutingDialog({ initial: nextRoutingRuleDefaults(draft.routing.rules), editingID: null })
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

  const interactionBusy = busy || saving
  const actions = (
    <ConfigurationActions
      stored={stored}
      dirty={dirty}
      busy={interactionBusy}
      saving={saving}
      t={t}
      onRefresh={() => void refreshConfiguration()}
    />
  )

  return (
    <main className="grid min-h-screen grid-cols-[minmax(0,1fr)] content-start gap-6 p-4 lg:p-6">
      {notice ? <div role="status" className="rounded-lg border bg-muted/50 px-4 py-3 text-sm">{notice}</div> : null}
      {error ? <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">{error}</div> : null}

      {draft != null ? (
        <form ref={formRef} className="min-w-0" onSubmit={(event) => void saveConfiguration(event)}>
          <Tabs defaultValue="services" orientation="vertical" className="min-w-0 gap-4 md:grid md:grid-cols-[11rem_minmax(0,1fr)] md:items-start md:gap-6">
            <PluginTabNavigation t={t} />
            <ConfigurationTab value="services" actions={actions}>
              <ServicesPanel services={draft.services} diagnostics={diagnostics} diagnosticsBusy={diagnosticsBusy} diagnosticsFailed={diagnosticsFailed} busy={interactionBusy} t={t} onAdd={openNewService} onEdit={(service) => setServiceDialog({ initial: service, editingID: service.service_id })} onDelete={(service) => void deleteService(service)} />
            </ConfigurationTab>
            <ConfigurationTab value="outbounds" actions={actions}>
              <OutboundsPanel outbounds={draft.outbounds} busy={interactionBusy} t={t} onAdd={openNewOutbound} onEdit={(outbound) => setOutboundDialog({ initial: outbound, editingID: outbound.tag })} onDelete={(outbound) => void deleteOutbound(outbound)} onMove={(index, offset) => markChanged({ ...draft, outbounds: moveItem(draft.outbounds, index, offset) })} />
            </ConfigurationTab>
            <ConfigurationTab value="routing" actions={actions}>
              <RoutingPanel services={draft.services} rules={draft.routing.rules} busy={interactionBusy} t={t} onAdd={openNewRoutingRule} onEdit={(rule) => setRoutingDialog({ initial: rule, editingID: rule.rule_id })} onDelete={(rule) => void deleteRoutingRule(rule)} onMove={(index, offset) => markChanged({ ...draft, routing: { rules: moveItem(draft.routing.rules, index, offset) } })} onToggle={(rule, enabled) => markChanged({ ...draft, routing: { rules: draft.routing.rules.map((candidate) => candidate.rule_id === rule.rule_id ? { ...candidate, enabled } : candidate) } })} />
            </ConfigurationTab>
            <ConfigurationTab value="dns" actions={actions}>
              <DNSPanel value={draft.dns} busy={interactionBusy} t={t} onChange={changeDNS} onAdd={openNewDNSServer} onEdit={(server) => setDNSDialog({ initial: server, editingID: server.server_id })} onDelete={(server) => void deleteDNSServer(server)} onMove={(index, offset) => changeDNS({ ...draft.dns, servers: moveItem(draft.dns.servers, index, offset) })} />
            </ConfigurationTab>
            <ConfigurationTab value="runtime" actions={actions}>
              <RuntimePanel value={draft} busy={interactionBusy} t={t} onChange={markChanged} />
            </ConfigurationTab>
          </Tabs>
        </form>
      ) : busy ? (
        <Card><CardContent className="grid min-h-40 place-content-center text-sm text-muted-foreground">{t("Loading...")}</CardContent></Card>
      ) : null}

      {serviceDialog ? <ServiceDialog initial={serviceDialog.initial} editingID={serviceDialog.editingID} existingIDs={draft?.services.map((service) => service.service_id) ?? []} occupiedPorts={draft?.services.filter((service) => service.service_id !== serviceDialog.editingID).map((service) => service.port) ?? []} apiPort={draft?.api_port ?? 0} serviceTypes={serviceTypes} createService={(type) => nextServiceDefaults(draft?.services ?? [], serviceTypes, type, draft == null ? [] : [draft.api_port])} t={t} onClose={() => setServiceDialog(null)} onApply={applyService} /> : null}
      {outboundDialog ? <OutboundDialog initial={outboundDialog.initial} editingTag={outboundDialog.editingID} outbounds={draft?.outbounds ?? []} t={t} onClose={() => setOutboundDialog(null)} onApply={applyOutbound} /> : null}
      {routingDialog && draft ? <RoutingRuleDialog initial={routingDialog.initial} editingID={routingDialog.editingID} services={draft.services} outbounds={draft.outbounds} t={t} onClose={() => setRoutingDialog(null)} onApply={applyRoutingRule} /> : null}
      {dnsDialog ? <DNSServerDialog initial={dnsDialog.initial} editingID={dnsDialog.editingID} existingIDs={draft?.dns.servers.map((server) => server.server_id) ?? []} t={t} onClose={() => setDNSDialog(null)} onApply={applyDNSServer} /> : null}
    </main>
  )
}

function ConfigurationTab({ value, actions, children }: { value: string; actions: ReactNode; children: ReactNode }) {
  return (
    <TabsContent value={value} className="min-w-0">
      <Card className="min-w-0">
        <CardContent className="grid min-w-0 gap-6">
          {children}
          {actions}
        </CardContent>
      </Card>
    </TabsContent>
  )
}

function ConfigurationActions({ stored, dirty, busy, saving, t, onRefresh }: {
  stored: StoredConfiguration | null
  dirty: boolean
  busy: boolean
  saving: boolean
  t: Translator
  onRefresh: () => void
}) {
  return (
    <div className="flex flex-col items-stretch justify-between gap-4 border-t pt-6 sm:flex-row sm:items-center">
      <span className="text-sm text-muted-foreground">{stored?.exists ? t("Generation {generation}", { generation: stored.generation ?? 0 }) : t("Not configured")}</span>
      <div className="flex flex-col gap-2 sm:flex-row">
        <Button type="button" variant="outline" disabled={busy} onClick={onRefresh}>
          <RefreshCw className={busy && !saving ? "animate-spin" : undefined} />{t("Refresh")}
        </Button>
        <Button type="submit" disabled={busy || !dirty}>
          <Save />{saving ? t("Saving...") : t("Save configuration")}
        </Button>
      </div>
    </div>
  )
}

function formatConfigurationChanges(changes: ConfigurationChanges, t: Translator): string {
  const lines = [t("The following changes will be published:")]
  if (changes.runtime.length > 0) {
    const fields = changes.runtime.map((field) => t(field === "xray_version" ? "Xray version" : "Local API port"))
    lines.push(`• ${t("Runtime")}: ${fields.join(t(", "))}`)
  }
  appendNamedChanges(lines, t("Inbounds"), changes.services, t)
  appendNamedChanges(lines, t("Outbounds"), changes.outbounds, t)
  appendNamedChanges(lines, t("Routing"), changes.routing, t)
  if (changes.dns.length > 0) {
    const fields = changes.dns.map((field) => t(field === "enabled" ? "Enabled status" : "Query strategy"))
    lines.push(`• ${t("DNS")}: ${fields.join(t(", "))}`)
  }
  appendNamedChanges(lines, t("DNS servers"), changes.dnsServers, t)
  const message = lines.join("\n")
  if (message.length <= 900) return message
  const suffix = `\n${t("Additional changes are omitted.")}`
  return `${message.slice(0, 900 - suffix.length)}${suffix}`
}

function appendNamedChanges(lines: string[], label: string, changes: NamedChanges, t: Translator) {
  const details: string[] = []
  if (changes.added.length > 0) details.push(t("Added: {items}", { items: summarizeNames(changes.added, t) }))
  if (changes.updated.length > 0) details.push(t("Modified: {items}", { items: summarizeNames(changes.updated, t) }))
  if (changes.removed.length > 0) details.push(t("Removed: {items}", { items: summarizeNames(changes.removed, t) }))
  if (changes.reordered) details.push(t("Order changed"))
  if (details.length > 0) lines.push(`• ${label}: ${details.join(t("; "))}`)
}

function summarizeNames(names: string[], t: Translator): string {
  const visible = names.slice(0, 3).join(t(", "))
  return names.length > 3 ? `${visible}${t(" and {count} more", { count: names.length - 3 })}` : visible
}

function PluginTabNavigation({ t }: { t: Translator }) {
  return (
    <TabsList variant="sidebar" aria-label={t("Xray configuration")}>
      <TabsTrigger variant="sidebar" value="services"><Network />{t("Inbounds")}</TabsTrigger>
      <TabsTrigger variant="sidebar" value="outbounds"><Send />{t("Outbounds")}</TabsTrigger>
      <TabsTrigger variant="sidebar" value="routing"><Route />{t("Routing")}</TabsTrigger>
      <TabsTrigger variant="sidebar" value="dns"><Globe2 />{t("DNS")}</TabsTrigger>
      <TabsTrigger variant="sidebar" value="runtime"><Activity />{t("Runtime")}</TabsTrigger>
    </TabsList>
  )
}
