import { Activity, CircleX, Network, Route, Send, ShieldAlert } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { firewallCommand, probeReasonMessage } from "@/diagnosticsPresentation"
import type { Translator } from "@/i18n"
import type { EditableConfiguration, EndpointPortDiagnostic, ServicePortDiagnostic, StoredConfiguration } from "@/types"

export function OverviewPanel({ configuration, stored, diagnostics, diagnosticsBusy, t }: {
  configuration: EditableConfiguration
  stored: StoredConfiguration | null
  diagnostics: ServicePortDiagnostic[]
  diagnosticsBusy: boolean
  t: Translator
}) {
  const metrics = [
    { label: t("Enabled inbounds"), value: configuration.services.filter((item) => item.enabled).length, icon: Network },
    { label: t("Enabled egress lines"), value: configuration.egress_lines.filter((item) => item.enabled).length, icon: Send },
    { label: t("Enabled access rules"), value: configuration.access_rules.filter((item) => item.enabled).length, icon: Route },
    { label: t("Configuration generation"), value: stored?.exists ? stored.generation ?? 0 : "-", icon: Activity },
  ]
  return (
    <div className="grid min-w-0 gap-6">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {metrics.map((metric) => <div key={metric.label} className="rounded-lg border p-4"><div className="flex items-center justify-between gap-3 text-sm font-medium"><span>{metric.label}</span><metric.icon className="size-4 text-muted-foreground" /></div><div className="mt-2 text-2xl font-bold">{metric.value}</div></div>)}
      </div>
      <div className="grid gap-3">
        <div><h2 className="font-semibold">{t("Port status")}</h2><p className="mt-1 text-sm text-muted-foreground">{t("Local listeners and public endpoints are checked separately.")}</p></div>
        <div className="divide-y rounded-lg border">
          {diagnosticsBusy ? <p className="p-4 text-sm text-muted-foreground">{t("Checking port status")}</p> : null}
          {!diagnosticsBusy && diagnostics.length === 0 ? <p className="p-4 text-sm text-muted-foreground">{t("No port status available")}</p> : null}
          {diagnostics.map((item) => (
            <PortStatus key={`${item.service_id}-${item.network}`} diagnostic={item} t={t} />
          ))}
        </div>
      </div>
    </div>
  )
}

function PortStatus({ diagnostic, t }: { diagnostic: ServicePortDiagnostic; t: Translator }) {
  const localLabel = diagnostic.local_state === "listening" ? "Listening" : diagnostic.local_state === "not_listening" ? "Not listening" : "Unknown"
  const address = diagnostic.listen_address ? `${diagnostic.listen_address}:${diagnostic.local_port}` : t("Not reported")
  return (
    <section>
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 text-sm">
        <div className="min-w-0"><strong>{diagnostic.service_id}</strong><p className="mt-1 text-muted-foreground">{t("Local listener")} · {diagnostic.network.toUpperCase()} · {address}</p></div>
        <Badge variant={diagnostic.local_state === "not_listening" ? "destructive" : diagnostic.local_state === "listening" ? "outline" : "secondary"} className={diagnostic.local_state === "listening" ? "border-success/30 bg-success-soft text-success" : undefined}>
          {t(localLabel)}
        </Badge>
      </div>
      <div className="divide-y border-t bg-muted/20">
        {diagnostic.endpoints.length === 0 ? <p className="px-4 py-3 text-sm text-muted-foreground">{t("No public endpoints configured")}</p> : diagnostic.endpoints.map((endpoint) => (
          <PublicEndpointStatus key={endpoint.endpoint_id} diagnostic={diagnostic} endpoint={endpoint} t={t} />
        ))}
      </div>
    </section>
  )
}

function PublicEndpointStatus({ diagnostic, endpoint, t }: { diagnostic: ServicePortDiagnostic; endpoint: EndpointPortDiagnostic; t: Translator }) {
  const unreachable = endpoint.reachability === "unreachable"
  const reachable = endpoint.reachability === "reachable"
  const command = firewallCommand(diagnostic, endpoint)
  return (
    <div className="grid gap-3 px-4 py-3 text-sm sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
      <div className="min-w-0">
        <div className="flex min-w-0 items-center gap-2">
          {reachable ? <Network className="size-4 shrink-0 text-primary" /> : unreachable ? <CircleX className="size-4 shrink-0 text-destructive" /> : <Network className="size-4 shrink-0 text-muted-foreground" />}
          <strong className="truncate">{endpoint.display_name}</strong>
          <span className="truncate text-muted-foreground">{endpoint.address ? `${endpoint.address}:${endpoint.port}` : t("Address unavailable")}</span>
        </div>
        {reachable ? <p className="mt-1 pl-6 text-muted-foreground">{t("A successful TCP connection does not verify that traffic reached the node or that the proxy protocol works.")}</p> : null}
        {endpoint.reason ? <p className="mt-1 pl-6 text-muted-foreground">{t(probeReasonMessage(endpoint.reason))}</p> : null}
        {command ? <div className="mt-3 ml-6 grid gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-3"><p className="flex items-start gap-2"><ShieldAlert className="mt-0.5 size-4 shrink-0 text-destructive" /><span>{t("Check the cloud firewall, NAT mapping, and host firewall.")}</span></p><code className="w-fit max-w-full overflow-x-auto rounded bg-background px-2 py-1 font-mono text-xs text-foreground">{command}</code></div> : null}
      </div>
      <Badge variant={unreachable ? "destructive" : reachable ? "outline" : "secondary"}>
        {t(reachable ? "TCP connection accepted" : unreachable ? "TCP connection failed" : "Not tested")}
      </Badge>
    </div>
  )
}
