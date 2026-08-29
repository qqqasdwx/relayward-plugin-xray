import { Plus } from "lucide-react"

import { EmptyList } from "@/components/EmptyList"
import { EntityActions } from "@/components/EntityActions"
import { StatusBadge } from "@/components/StatusBadge"
import { Button } from "@/components/ui/button"
import type { Translator } from "@/i18n"
import type { ProxyService } from "@/types"

interface ServicesPanelProps {
  services: ProxyService[]
  busy: boolean
  t: Translator
  onAdd: () => void
  onEdit: (service: ProxyService) => void
  onDelete: (service: ProxyService) => void
}

export function ServicesPanel({ services: inbounds, busy, t, onAdd, onEdit, onDelete }: ServicesPanelProps) {
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
                  : "VLESS · TCP · REALITY"}</span>
                <span className="break-words">{t("Listen {address}:{port}", { address: inbound.listen, port: inbound.port })}</span>
                <span className="break-words">{t("Share {host}:{port}", { host: inbound.public_host, port: inbound.public_port })}</span>
              </div>
              <EntityActions busy={busy} t={t} onEdit={() => onEdit(inbound)} onDelete={() => onDelete(inbound)} />
            </article>
          ))}
        </div>
      )}
    </div>
  )
}
