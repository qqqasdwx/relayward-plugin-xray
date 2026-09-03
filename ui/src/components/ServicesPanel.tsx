import { Plus } from "lucide-react"

import { EntityActions } from "@/components/EntityActions"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import type { Translator } from "@/i18n"
import type { ProxyService, ServicePortDiagnostic } from "@/types"

export function ServicesPanel({ services, diagnostics, busy, t, onAdd, onEdit, onDelete }: {
  services: ProxyService[]; diagnostics: ServicePortDiagnostic[]; busy: boolean; t: Translator
  onAdd: () => void; onEdit: (service: ProxyService) => void; onDelete: (service: ProxyService) => void
}) {
  return (
    <div className="grid min-w-0 gap-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div><h2 className="font-semibold">{t("Inbounds")}</h2><p className="text-sm text-muted-foreground">{t("Client entry points on this node")}</p></div>
        <Button type="button" disabled={busy} onClick={onAdd}><Plus />{t("Add inbound")}</Button>
      </div>
      <div className="divide-y rounded-lg border">
        {services.length === 0 ? <p className="p-6 text-sm text-muted-foreground">{t("No inbounds configured")}</p> : services.map((service) => {
          const states = diagnostics.filter((item) => item.service_id === service.service_id)
          const healthy = states.length > 0 && states.every((item) => item.local_state === "listening")
          return (
            <article key={service.service_id} className="grid gap-4 p-4 md:grid-cols-[minmax(0,1fr)_minmax(12rem,0.7fr)_auto] md:items-center">
              <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><strong className="truncate text-sm">{service.display_name}</strong><Badge variant="secondary">{service.type === "vless-reality" ? "VLESS" : "Shadowsocks"}</Badge><Badge variant={service.enabled ? "outline" : "secondary"} className={service.enabled ? "border-success/30 bg-success-soft text-success" : undefined}>{t(service.enabled ? "Enabled" : "Disabled status")}</Badge></div><p className="mt-1 truncate text-sm text-muted-foreground">{service.service_id}</p></div>
              <div className="text-sm"><div>{t("Port")} {service.port} · {service.type === "shadowsocks" ? "TCP / UDP" : "TCP"}</div>{service.enabled && states.length > 0 ? <div className={healthy ? "text-success" : "text-destructive"}>{t(healthy ? "Listening" : "Not listening")}</div> : null}</div>
              <EntityActions busy={busy} index={0} count={1} t={t} onEdit={() => onEdit(service)} onDelete={() => onDelete(service)} />
            </article>
          )
        })}
      </div>
    </div>
  )
}
