import { CircleCheck, CircleHelp, CircleX, Plus } from "lucide-react"

import { EmptyList } from "@/components/EmptyList"
import { EntityActions } from "@/components/EntityActions"
import { StatusBadge } from "@/components/StatusBadge"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import type { Translator } from "@/i18n"
import type { EndpointPortDiagnostic, ProxyService, ServicePortDiagnostic } from "@/types"

interface ServicesPanelProps {
  services: ProxyService[]
  diagnostics: ServicePortDiagnostic[]
  diagnosticsBusy: boolean
  diagnosticsFailed: boolean
  busy: boolean
  t: Translator
  onAdd: () => void
  onEdit: (service: ProxyService) => void
  onDelete: (service: ProxyService) => void
}

export function ServicesPanel({ services: inbounds, diagnostics, diagnosticsBusy, diagnosticsFailed, busy, t, onAdd, onEdit, onDelete }: ServicesPanelProps) {
  return (
    <div className="grid min-w-0 gap-6">
      <div className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="grid min-w-0 gap-1">
          <h2 className="font-semibold">{t("Inbounds")}</h2>
          <p className="break-words text-sm text-muted-foreground">{t("Xray inbounds configured on this node")}</p>
        </div>
        <Button type="button" disabled={busy} onClick={onAdd}><Plus />{t("Add inbound")}</Button>
      </div>

      {inbounds.length === 0 ? (
        <EmptyList title={t("No inbounds configured")} detail={t("Add an inbound to accept client connections")} />
      ) : (
        <div className="min-w-0 divide-y rounded-lg border">
          {inbounds.map((inbound) => (
            <article key={inbound.service_id} className="grid min-w-0 gap-4 px-4 py-4 md:grid-cols-[minmax(0,1fr)_minmax(12rem,0.8fr)_auto] md:items-center">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <strong className="truncate text-sm font-medium">{inbound.display_name}</strong>
                  <StatusBadge enabled={inbound.enabled} t={t} />
                </div>
                <p className="mt-1 truncate font-mono text-xs text-muted-foreground">{inbound.service_id}</p>
              </div>
              <div className="grid min-w-0 gap-1 text-sm text-muted-foreground">
                <span className="break-words">{inbound.type === "shadowsocks" && inbound.shadowsocks != null
                  ? `Shadowsocks · ${inbound.shadowsocks.network.toUpperCase()} · ${inbound.shadowsocks.method}`
                  : "VLESS · RAW · REALITY"}</span>
                <span className="break-words">{t("Listen {address}:{port}", { address: inbound.listen, port: inbound.port })}</span>
              </div>
              <EntityActions busy={busy} t={t} onEdit={() => onEdit(inbound)} onDelete={() => onDelete(inbound)} />
              {inbound.enabled ? (
                <InboundDiagnostics
                  inbound={inbound}
                  values={diagnostics.filter((value) => value.service_id === inbound.service_id && value.local_port === inbound.port)}
                  busy={diagnosticsBusy}
                  failed={diagnosticsFailed}
                  t={t}
                />
              ) : null}
            </article>
          ))}
        </div>
      )}
    </div>
  )
}

function InboundDiagnostics({ inbound, values, busy, failed, t }: {
  inbound: ProxyService
  values: ServicePortDiagnostic[]
  busy: boolean
  failed: boolean
  t: Translator
}) {
  if (busy) {
    return <div className="md:col-span-3"><Badge variant="outline" className="text-muted-foreground"><CircleHelp />{t("Checking port status")}</Badge></div>
  }
  if (failed) {
    return <div className="md:col-span-3"><Badge variant="outline" className="border-destructive/30 bg-destructive/5 text-destructive"><CircleX />{t("Port status check failed")}</Badge></div>
  }
  if (values.length === 0) {
    return <div className="md:col-span-3"><Badge variant="outline" className="text-muted-foreground"><CircleHelp />{t("Port status unknown")}</Badge></div>
  }
  return (
    <div className="min-w-0 divide-y rounded-md border bg-muted/20 md:col-span-3">
      {values.map((value) => (
        <div key={`${value.network}-${value.local_port}`} className="grid min-w-0 gap-3 px-3 py-3">
          <DiagnosticRow
            label={t("Local {network}", { network: value.network.toUpperCase() })}
            address={`${value.listen_address || inbound.listen}:${value.local_port}`}
            state={value.local_state}
            t={t}
          />
          {value.endpoints.map((endpoint) => <EndpointRow key={endpoint.endpoint_id} value={endpoint} t={t} />)}
        </div>
      ))}
    </div>
  )
}

function DiagnosticRow({ label, address, state, t }: {
  label: string
  address: string
  state: "unknown" | "listening" | "not_listening"
  t: Translator
}) {
  const healthy = state === "listening"
  const failed = state === "not_listening"
  return (
    <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-center gap-2 text-sm"><span className="font-medium">{label}</span><span className="break-all text-muted-foreground">{address}</span></div>
      <Badge variant="outline" className={healthy ? "border-success/30 bg-success-soft text-success" : failed ? "border-destructive/30 bg-destructive/5 text-destructive" : "text-muted-foreground"}>
        {healthy ? <CircleCheck /> : failed ? <CircleX /> : <CircleHelp />}{t(healthy ? "Listening" : failed ? "Not listening" : "Unknown")}
      </Badge>
    </div>
  )
}

function EndpointRow({ value, t }: { value: EndpointPortDiagnostic; t: Translator }) {
  const reachable = value.reachability === "reachable"
  const unreachable = value.reachability === "unreachable"
  const suggestNetworkChecks = unreachable && value.reason !== "dns_failed"
  const status = reachable ? "Publicly reachable" : unreachable ? "Publicly unreachable" : endpointReason(value.reason)
  return (
    <div className="grid min-w-0 gap-2 border-t pt-3 first:border-t-0 first:pt-0">
      <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-center gap-2 text-sm"><span className="font-medium">{value.display_name}</span><span className="break-all text-muted-foreground">{value.address ? `${value.address}:${value.port}` : t("Endpoint unavailable")}</span></div>
        <Badge variant="outline" className={reachable ? "border-success/30 bg-success-soft text-success" : unreachable ? "border-destructive/30 bg-destructive/5 text-destructive" : "text-muted-foreground"}>
          {reachable ? <CircleCheck /> : unreachable ? <CircleX /> : <CircleHelp />}{t(status)}
        </Badge>
      </div>
      {suggestNetworkChecks ? <p className="text-sm text-destructive">{t("Check the host firewall, cloud firewall, or NAT port forwarding.")}</p> : null}
    </div>
  )
}

function endpointReason(reason: EndpointPortDiagnostic["reason"]): string {
  switch (reason) {
  case "node_offline": return "Node offline"
  case "local_not_listening": return "Local port is not listening"
  case "endpoint_unavailable": return "Endpoint unavailable"
  case "proxied_endpoint": return "Source port cannot be verified through the proxy"
  case "unsupported_network": return "UDP public reachability is not tested"
  case "dns_failed": return "Endpoint DNS resolution failed"
  default: return "Not tested"
  }
}
