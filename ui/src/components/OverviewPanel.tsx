import { Activity, Network, Route, Send } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import type { Translator } from "@/i18n"
import type { EditableConfiguration, ServicePortDiagnostic, StoredConfiguration } from "@/types"

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
        <h2 className="font-semibold">{t("Listener status")}</h2>
        <div className="divide-y rounded-lg border">
          {diagnosticsBusy ? <p className="p-4 text-sm text-muted-foreground">{t("Checking port status")}</p> : null}
          {!diagnosticsBusy && diagnostics.length === 0 ? <p className="p-4 text-sm text-muted-foreground">{t("No listener status available")}</p> : null}
          {diagnostics.map((item) => (
            <div key={`${item.service_id}-${item.network}`} className="flex flex-wrap items-center justify-between gap-3 p-4 text-sm">
              <div><strong>{item.service_id}</strong><span className="ml-2 text-muted-foreground">{item.network.toUpperCase()} · {item.listen_address}:{item.local_port}</span></div>
              <Badge variant={item.local_state === "not_listening" ? "destructive" : item.local_state === "listening" ? "outline" : "secondary"} className={item.local_state === "listening" ? "border-success/30 bg-success-soft text-success" : undefined}>
                {t(item.local_state === "listening" ? "Listening" : item.local_state === "not_listening" ? "Not listening" : "Unknown")}
              </Badge>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
