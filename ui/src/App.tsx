import { Activity, Gauge, Network, RefreshCw, Route, Save, Send } from "lucide-react"
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react"

import { AccessRuleDialog } from "@/components/AccessRuleDialog"
import { AccessRulesPanel } from "@/components/AccessRulesPanel"
import { EgressLineDialog } from "@/components/EgressLineDialog"
import { EgressLinesPanel } from "@/components/EgressLinesPanel"
import { OverviewPanel } from "@/components/OverviewPanel"
import { RuntimePanel } from "@/components/RuntimePanel"
import { ServiceDialog } from "@/components/ServiceDialog"
import { ServicesPanel } from "@/components/ServicesPanel"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { configurationForSave, configurationFromStored, configurationsEqual, moveItem, nextAccessRuleDefaults, nextEgressLineDefaults, nextServiceDefaults } from "@/configuration"
import { translator } from "@/i18n"
import { parseAddresses, parseAuthorizations, parseDiagnostics, parseProbe, parseServiceTypes, parseStored, parseXrayVersions } from "@/responses"
import { createClient, type RelaywardUIClient } from "@/sdk"
import type { AccessRule, EditableConfiguration, EgressLine, EgressProbe, Locale, NetworkAddress, NodeAuthorization, ProxyService, ServicePortDiagnostic, ServiceType, StoredConfiguration, XrayVersion } from "@/types"

interface DialogState<T> { initial: T; editingID: string | null }

export function App() {
  const clientRef = useRef<RelaywardUIClient | null>(null)
  const formRef = useRef<HTMLFormElement | null>(null)
  const [locale, setLocale] = useState<Locale>("en")
  const [nodeID, setNodeID] = useState("")
  const [serviceTypes, setServiceTypes] = useState<ServiceType[]>([])
  const [xrayVersions, setXrayVersions] = useState<XrayVersion[]>([])
  const [versionError, setVersionError] = useState("")
  const [stored, setStored] = useState<StoredConfiguration | null>(null)
  const [baseline, setBaseline] = useState<EditableConfiguration | null>(null)
  const [draft, setDraft] = useState<EditableConfiguration | null>(null)
  const [diagnostics, setDiagnostics] = useState<ServicePortDiagnostic[]>([])
  const [addresses, setAddresses] = useState<NetworkAddress[]>([])
  const [authorizations, setAuthorizations] = useState<NodeAuthorization[]>([])
  const [probes, setProbes] = useState<Record<string, EgressProbe>>({})
  const [probing, setProbing] = useState("")
  const [busy, setBusy] = useState(true)
  const [saving, setSaving] = useState(false)
  const [diagnosticsBusy, setDiagnosticsBusy] = useState(false)
  const [notice, setNotice] = useState("")
  const [error, setError] = useState("")
  const [serviceDialog, setServiceDialog] = useState<DialogState<ProxyService> | null>(null)
  const [egressDialog, setEgressDialog] = useState<DialogState<EgressLine> | null>(null)
  const [accessDialog, setAccessDialog] = useState<DialogState<AccessRule> | null>(null)
  const dialogReturnFocusRef = useRef<HTMLElement | null>(null)
  const t = useMemo(() => translator(locale), [locale])
  const dirty = useMemo(() => draft != null && baseline != null && !configurationsEqual(baseline, draft), [baseline, draft])

  useEffect(() => {
    let disposed = false
    let client: RelaywardUIClient | null = null
    async function bootstrap() {
      try {
        client = createClient()
        clientRef.current = client
        const context = await client.context()
        if (disposed) return
        document.documentElement.lang = context.locale
        document.documentElement.dataset.theme = context.theme
        setLocale(context.locale)
        if (context.scope?.kind !== "node") throw new Error(translator(context.locale)("Xray requires a node context."))
        const id = context.scope.node_id
        const [typesResponse, configurationResponse, versions] = await Promise.all([
          client.rpc("service-types.list", {}),
          client.rpc("configuration.get", { node_id: id }),
          client.rpc("xray-versions.list", {}).then(parseXrayVersions).catch((cause) => {
            if (!disposed) setVersionError(message(cause, translator(context.locale)("Official Xray versions could not be loaded.")))
            return []
          }),
        ])
        if (disposed) return
        const types = parseServiceTypes(typesResponse)
        const loaded = parseStored(configurationResponse)
        const initial = configurationFromStored(loaded, versions[0]?.version)
        setNodeID(id); setServiceTypes(types); setXrayVersions(versions); setStored(loaded); setBaseline(configurationForSave(initial)); setDraft(initial)
        void loadSupportingData(client, id, loaded.exists, translator(context.locale))
      } catch (cause) {
        if (!disposed) setError(message(cause, "The request could not be completed."))
      } finally {
        if (!disposed) setBusy(false)
      }
    }
    void bootstrap()
    return () => { disposed = true; client?.dispose(); if (clientRef.current === client) clientRef.current = null }
  }, [])

  async function loadSupportingData(client: RelaywardUIClient, id: string, configured: boolean, translate: ReturnType<typeof translator>) {
    setDiagnosticsBusy(true)
    const requests: Promise<unknown>[] = [
      client.rpc("authorizations.list", { node_id: id }),
      client.rpc("network.addresses", { node_id: id, input: {} }),
    ]
    if (configured) requests.push(client.rpc("diagnostics.get", { node_id: id }))
    const results = await Promise.allSettled(requests)
    const authorizationResult = parsedResult(results[0], parseAuthorizations, [])
    const addressResult = parsedResult(results[1], parseAddresses, [])
    const diagnosticResult = configured ? parsedResult(results[2], parseDiagnostics, []) : { value: [], failed: false }
    setAuthorizations(authorizationResult.value)
    setAddresses(addressResult.value)
    setDiagnostics(diagnosticResult.value)
    if (authorizationResult.failed || addressResult.failed || diagnosticResult.failed) setError(translate("Some node data could not be loaded."))
    setDiagnosticsBusy(false)
  }

  function changed(value: EditableConfiguration) { setDraft(value); setNotice(""); setError("") }

  async function refresh() {
    const client = clientRef.current
    if (client == null || nodeID === "") return
    setBusy(true); setNotice(""); setError("")
    try {
      const [configurationResponse, versions] = await Promise.all([
        client.rpc("configuration.get", { node_id: nodeID }),
        client.rpc("xray-versions.list", {}).then((response) => { setVersionError(""); return parseXrayVersions(response) }).catch((cause) => {
          setVersionError(message(cause, t("Official Xray versions could not be loaded.")))
          return xrayVersions
        }),
      ])
      const loaded = parseStored(configurationResponse)
      const value = configurationFromStored(loaded, versions[0]?.version)
      setXrayVersions(versions); setStored(loaded); setBaseline(configurationForSave(value)); setDraft(value); setProbes({})
      await loadSupportingData(client, nodeID, loaded.exists, t)
    } catch (cause) { setError(message(cause, t("The request could not be completed."))) }
    finally { setBusy(false) }
  }

  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const client = clientRef.current
    if (client == null || draft == null || baseline == null || !dirty || busy || saving || !formRef.current?.reportValidity()) return
    setSaving(true); setNotice(""); setError("")
    try {
      const confirmed = await client.confirm({ title: t("Save Xray configuration?"), message: summarizeChanges(baseline, draft, t), confirm_label: t("Save configuration"), destructive: false })
      if (!confirmed) return
      await client.rpc("configuration.save", { node_id: nodeID, expected_generation: stored?.exists ? stored.generation ?? 0 : 0, configuration: configurationForSave(draft) })
      const loaded = parseStored(await client.rpc("configuration.get", { node_id: nodeID }))
      const value = configurationFromStored(loaded)
      setStored(loaded); setBaseline(configurationForSave(value)); setDraft(value); setProbes({}); setNotice(t("Configuration saved."))
      void loadSupportingData(client, nodeID, true, t)
    } catch (cause) { setError(message(cause, t("The request could not be completed."))) }
    finally { setSaving(false) }
  }

  async function confirmDelete(title: string, body: string): Promise<boolean> {
    try { return await clientRef.current!.confirm({ title, message: body, confirm_label: t("Delete"), destructive: true }) }
    catch (cause) { setError(message(cause, t("The request could not be completed."))); return false }
  }

  function rememberDialogTrigger() {
    dialogReturnFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
  }
  function restoreDialogFocus() {
    const trigger = dialogReturnFocusRef.current
    dialogReturnFocusRef.current = null
    window.requestAnimationFrame(() => trigger?.focus({ preventScroll: true }))
  }

  function openService() {
    if (draft == null) return
    rememberDialogTrigger()
    setServiceDialog({ initial: nextServiceDefaults(draft.services, serviceTypes), editingID: null })
  }
  function editService(service: ProxyService) {
    rememberDialogTrigger()
    setServiceDialog({ initial: service, editingID: service.service_id })
  }
  function closeServiceDialog() { setServiceDialog(null); restoreDialogFocus() }
  function applyService(service: ProxyService) {
    if (draft == null || serviceDialog == null) return
    const services = serviceDialog.editingID == null ? [...draft.services, service] : draft.services.map((item) => item.service_id === serviceDialog.editingID ? service : item)
    changed({ ...draft, services: services.sort((a, b) => a.service_id.localeCompare(b.service_id)) }); closeServiceDialog()
  }
  async function deleteService(service: ProxyService) {
    if (draft == null || !await confirmDelete(t("Delete inbound"), t("Delete {name}?", { name: service.display_name }))) return
    const rules = draft.access_rules.map((rule) => ({ ...rule, service_ids: rule.service_ids.filter((id) => id !== service.service_id) })).filter(hasCondition)
    changed({ ...draft, services: draft.services.filter((item) => item.service_id !== service.service_id), access_rules: rules })
  }

  function openEgress() { if (draft) { rememberDialogTrigger(); setEgressDialog({ initial: nextEgressLineDefaults(draft.egress_lines), editingID: null }) } }
  function editEgress(line: EgressLine) { rememberDialogTrigger(); setEgressDialog({ initial: line, editingID: line.line_id }) }
  function closeEgressDialog() { setEgressDialog(null); restoreDialogFocus() }
  function applyEgress(line: EgressLine) {
    if (draft == null || egressDialog == null) return
    const lines = egressDialog.editingID == null ? [...draft.egress_lines, line] : draft.egress_lines.map((item) => item.line_id === egressDialog.editingID ? line : item)
    changed({ ...draft, egress_lines: lines }); closeEgressDialog()
  }
  async function deleteEgress(line: EgressLine) {
    if (draft == null || !await confirmDelete(t("Delete egress line"), t("Delete {name} and access rules that use it?", { name: line.display_name }))) return
    changed({ ...draft, egress_lines: draft.egress_lines.filter((item) => item.line_id !== line.line_id), access_rules: draft.access_rules.filter((rule) => rule.action !== "egress" || rule.egress_line_id !== line.line_id) })
  }
  async function probeEgress(line: EgressLine) {
    const client = clientRef.current
    if (client == null) return
    setProbing(line.line_id); setError("")
    try {
      const probe = parseProbe(await client.rpc("egress.probe", { node_id: nodeID, input: { line_id: line.line_id } }))
      setProbes((current) => ({ ...current, [line.line_id]: probe }))
    } catch (cause) { setError(message(cause, t("Egress test failed."))) }
    finally { setProbing("") }
  }

  function openAccessRule() { if (draft) { rememberDialogTrigger(); setAccessDialog({ initial: nextAccessRuleDefaults(draft.access_rules), editingID: null }) } }
  function editAccessRule(rule: AccessRule) { rememberDialogTrigger(); setAccessDialog({ initial: rule, editingID: rule.rule_id }) }
  function closeAccessDialog() { setAccessDialog(null); restoreDialogFocus() }
  function applyAccessRule(rule: AccessRule) {
    if (draft == null || accessDialog == null) return
    const rules = accessDialog.editingID == null ? [...draft.access_rules, rule] : draft.access_rules.map((item) => item.rule_id === accessDialog.editingID ? rule : item)
    changed({ ...draft, access_rules: rules }); closeAccessDialog()
  }
  async function deleteAccessRule(rule: AccessRule) {
    if (draft == null || !await confirmDelete(t("Delete access rule"), t("Delete {name}?", { name: rule.display_name }))) return
    changed({ ...draft, access_rules: draft.access_rules.filter((item) => item.rule_id !== rule.rule_id) })
  }

  const interactionBusy = busy || saving
  const actions = <Actions stored={stored} dirty={dirty} busy={interactionBusy} saving={saving} t={t} onRefresh={() => void refresh()} />
  return (
    <main className="grid min-h-screen min-w-0 content-start gap-6 p-4 lg:p-6">
      {notice ? <div role="status" className="rounded-lg border bg-muted/50 px-4 py-3 text-sm">{notice}</div> : null}
      {error ? <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">{error}</div> : null}
      {draft ? <form ref={formRef} className="min-w-0" onSubmit={(event) => void save(event)}><Tabs defaultValue="overview" orientation="vertical" className="min-w-0 gap-4 md:grid md:grid-cols-[12rem_minmax(0,1fr)] md:items-start md:gap-8"><Navigation t={t} />
        <Page value="overview" actions={actions}><OverviewPanel configuration={draft} stored={stored} diagnostics={diagnostics} diagnosticsBusy={diagnosticsBusy} t={t} /></Page>
        <Page value="services" actions={actions}><ServicesPanel services={draft.services} diagnostics={diagnostics} busy={interactionBusy} t={t} onAdd={openService} onEdit={editService} onDelete={(service) => void deleteService(service)} /></Page>
        <Page value="egress" actions={actions}><EgressLinesPanel lines={draft.egress_lines} probes={probes} probing={probing} busy={interactionBusy} dirty={dirty} t={t} onAdd={openEgress} onEdit={editEgress} onDelete={(line) => void deleteEgress(line)} onProbe={(line) => void probeEgress(line)} /></Page>
        <Page value="access" actions={actions}><AccessRulesPanel rules={draft.access_rules} lines={draft.egress_lines} busy={interactionBusy} t={t} onAdd={openAccessRule} onEdit={editAccessRule} onDelete={(rule) => void deleteAccessRule(rule)} onMove={(index, offset) => changed({ ...draft, access_rules: moveItem(draft.access_rules, index, offset) })} onToggle={(rule, enabled) => changed({ ...draft, access_rules: draft.access_rules.map((item) => item.rule_id === rule.rule_id ? { ...item, enabled } : item) })} /></Page>
        <Page value="runtime" actions={actions}><RuntimePanel value={draft} stored={stored} addresses={addresses} versions={xrayVersions} versionError={versionError} busy={interactionBusy} t={t} onChange={changed} /></Page>
      </Tabs></form> : <Card><CardContent className="grid min-h-40 place-content-center text-sm text-muted-foreground">{busy ? t("Loading...") : null}</CardContent></Card>}
      {serviceDialog && draft ? <ServiceDialog initial={serviceDialog.initial} editingID={serviceDialog.editingID} existingIDs={draft.services.map((item) => item.service_id)} occupiedPorts={draft.services.filter((item) => item.service_id !== serviceDialog.editingID).map((item) => item.port)} serviceTypes={serviceTypes} createService={(type) => nextServiceDefaults(draft.services, serviceTypes, type)} busy={interactionBusy} t={t} onClose={closeServiceDialog} onApply={applyService} /> : null}
      {egressDialog && draft ? <EgressLineDialog initial={egressDialog.initial} editingID={egressDialog.editingID} lines={draft.egress_lines} addresses={addresses} t={t} onClose={closeEgressDialog} onApply={applyEgress} /> : null}
      {accessDialog && draft ? <AccessRuleDialog initial={accessDialog.initial} authorizations={authorizations} services={draft.services} lines={draft.egress_lines} t={t} onClose={closeAccessDialog} onApply={applyAccessRule} /> : null}
    </main>
  )
}

function Navigation({ t }: { t: ReturnType<typeof translator> }) { return <TabsList variant="sidebar" aria-label={t("Xray configuration")}><TabsTrigger variant="sidebar" value="overview"><Gauge />{t("Overview")}</TabsTrigger><TabsTrigger variant="sidebar" value="services"><Network />{t("Inbounds")}</TabsTrigger><TabsTrigger variant="sidebar" value="egress"><Send />{t("Egress lines")}</TabsTrigger><TabsTrigger variant="sidebar" value="access"><Route />{t("Access rules")}</TabsTrigger><TabsTrigger variant="sidebar" value="runtime"><Activity />{t("Runtime")}</TabsTrigger></TabsList> }
function Page({ value, actions, children }: { value: string; actions: ReactNode; children: ReactNode }) { return <TabsContent value={value} className="min-w-0"><Card><CardContent className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-6">{children}{actions}</CardContent></Card></TabsContent> }
function Actions({ stored, dirty, busy, saving, t, onRefresh }: { stored: StoredConfiguration | null; dirty: boolean; busy: boolean; saving: boolean; t: ReturnType<typeof translator>; onRefresh: () => void }) { return <div className="flex flex-col items-stretch justify-between gap-4 border-t pt-6 sm:flex-row sm:items-center"><span className="text-sm text-muted-foreground">{stored?.exists ? t("Generation {generation}", { generation: stored.generation ?? 0 }) : t("Not configured")}</span><div className="flex flex-wrap gap-2"><Button type="button" variant="outline" disabled={busy} onClick={onRefresh}><RefreshCw className={busy && !saving ? "animate-spin" : undefined} />{t("Refresh")}</Button><Button type="submit" disabled={busy || !dirty}><Save />{saving ? t("Saving...") : t("Save configuration")}</Button></div></div> }

function summarizeChanges(before: EditableConfiguration, after: EditableConfiguration, t: ReturnType<typeof translator>): string {
  const parts = [t("The following changes will be published:")]
  if (before.xray_version !== after.xray_version) parts.push(`• ${t("Xray version")}: ${before.xray_version} → ${after.xray_version}`)
  appendEntityChanges(parts, t("Inbounds"), before.services, after.services, (item) => item.service_id, (item) => item.display_name, t)
  appendEntityChanges(parts, t("Egress lines"), before.egress_lines, after.egress_lines, (item) => item.line_id, (item) => item.display_name, t)
  appendEntityChanges(parts, t("Access rules"), before.access_rules, after.access_rules, (item) => item.rule_id, (item) => item.display_name, t)
  return parts.join("\n").slice(0, 1000)
}
function appendEntityChanges<T>(parts: string[], label: string, before: T[], after: T[], id: (item: T) => string, name: (item: T) => string, t: ReturnType<typeof translator>) { const previous = new Map(before.map((item) => [id(item), item])); const current = new Map(after.map((item) => [id(item), item])); const added = after.filter((item) => !previous.has(id(item))).map(name); const removed = before.filter((item) => !current.has(id(item))).map(name); const changed = after.filter((item) => previous.has(id(item)) && JSON.stringify(previous.get(id(item))) !== JSON.stringify(item)).map(name); const values = [...(added.length ? [t("Added: {items}", { items: added.join(", ") })] : []), ...(changed.length ? [t("Modified: {items}", { items: changed.join(", ") })] : []), ...(removed.length ? [t("Removed: {items}", { items: removed.join(", ") })] : [])]; if (values.length) parts.push(`• ${label}: ${values.join("; ")}`) }
function hasCondition(rule: AccessRule): boolean { return rule.source_ips.length + rule.protocols.length + rule.destination_ips.length + rule.domains.length + rule.authorization_ids.length + rule.service_ids.length > 0 || rule.network !== "" || rule.destination_port !== "" }
function parsedResult<T>(result: PromiseSettledResult<unknown> | undefined, parse: (value: unknown) => T, fallback: T): { value: T; failed: boolean } {
  if (result?.status !== "fulfilled") return { value: fallback, failed: true }
  try { return { value: parse(result.value), failed: false } }
  catch { return { value: fallback, failed: true } }
}

function message(cause: unknown, fallback: string): string { return cause instanceof Error && cause.message ? cause.message : fallback }
