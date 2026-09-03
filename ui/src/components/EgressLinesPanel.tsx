import { FlaskConical, Loader2, Plus } from "lucide-react"

import { EntityActions } from "@/components/EntityActions"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import type { Translator } from "@/i18n"
import type { EgressLine, EgressProbe } from "@/types"

export function EgressLinesPanel({ lines, probes, probing, busy, dirty, t, onAdd, onEdit, onDelete, onProbe }: {
  lines: EgressLine[]; probes: Record<string, EgressProbe>; probing: string; busy: boolean; dirty: boolean; t: Translator
  onAdd: () => void; onEdit: (line: EgressLine) => void; onDelete: (line: EgressLine) => void; onProbe: (line: EgressLine) => void
}) {
  return (
    <div className="grid min-w-0 gap-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"><div><h2 className="font-semibold">{t("Egress lines")}</h2><p className="text-sm text-muted-foreground">{t("VLESS subscriptions can select a named egress line")}</p></div><Button type="button" disabled={busy} onClick={onAdd}><Plus />{t("Add egress line")}</Button></div>
      <div className="divide-y rounded-lg border">
        {lines.map((line) => {
          const probe = probes[line.line_id]
          const endpoint = line.type === "direct" ? line.direct?.send_through || t("System default") : line.type === "socks5" ? `${line.socks5?.address}:${line.socks5?.port}` : `${line.shadowsocks?.address}:${line.shadowsocks?.port}`
          return (
            <article key={line.line_id} className="grid gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_minmax(12rem,0.8fr)_minmax(10rem,0.6fr)_auto] lg:items-center">
              <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><strong className="truncate text-sm">{line.display_name}</strong><Badge variant="secondary">{line.type}</Badge>{line.line_id === "default" ? <Badge variant="outline">{t("Default")}</Badge> : null}<Badge variant={line.enabled ? "outline" : "secondary"} className={line.enabled ? "border-success/30 bg-success-soft text-success" : undefined}>{t(line.enabled ? "Enabled" : "Disabled status")}</Badge></div><p className="mt-1 truncate text-sm text-muted-foreground">{endpoint}</p></div>
              <div className="text-sm"><span className="text-muted-foreground">VLESS route</span><strong className="ml-2">{line.vless_route}</strong></div>
              <div className="text-sm">{probe ? <><strong>{probe.address}</strong><div className="text-muted-foreground">{[probe.country, probe.colocation, `${probe.elapsed_millis} ms`].filter(Boolean).join(" · ")}</div></> : <span className="text-muted-foreground">{t("Not tested")}</span>}</div>
              <div className="flex items-center justify-end gap-1"><Button type="button" variant="ghost" size="icon" title={t("Test egress")} aria-label={t("Test egress")} disabled={busy || dirty || !line.enabled || probing !== ""} onClick={() => onProbe(line)}>{probing === line.line_id ? <Loader2 className="animate-spin" /> : <FlaskConical />}</Button><EntityActions busy={busy} t={t} onEdit={() => onEdit(line)} onDelete={line.line_id === "default" ? undefined : () => onDelete(line)} /></div>
            </article>
          )
        })}
      </div>
    </div>
  )
}
