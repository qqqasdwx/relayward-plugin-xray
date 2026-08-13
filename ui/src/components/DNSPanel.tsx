import { Plus } from "lucide-react"

import { EmptyList } from "@/components/EmptyList"
import { EntityActions } from "@/components/EntityActions"
import { StatusBadge } from "@/components/StatusBadge"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import type { Translator } from "@/i18n"
import type { DNSConfiguration, DNSQueryStrategy, DNSServer } from "@/types"

function endpoint(server: DNSServer, t: Translator) {
  if (server.transport === "system") return t("System resolver")
  if (server.transport === "doh") return server.address
  const address = server.address.includes(":") ? `[${server.address}]` : server.address
  return `${address}:${server.port}`
}

interface DNSPanelProps {
  value: DNSConfiguration
  busy: boolean
  t: Translator
  onChange: (value: DNSConfiguration) => void
  onAdd: () => void
  onEdit: (server: DNSServer) => void
  onDelete: (server: DNSServer) => void
  onMove: (index: number, offset: number) => void
}

export function DNSPanel({ value, busy, t, onChange, onAdd, onEdit, onDelete, onMove }: DNSPanelProps) {
  return (
    <div className="grid min-w-0 gap-6">
      <div className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="grid min-w-0 gap-1">
          <h2 className="font-semibold">{t("DNS resolution")}</h2>
          <p className="break-words text-sm text-muted-foreground">{t("Ordered resolvers for Xray routing and direct outbound connections")}</p>
        </div>
        <div className="flex items-center gap-2">
          <Label htmlFor="dns-enabled">{t("Enabled")}</Label>
          <Switch id="dns-enabled" checked={value.enabled} disabled={busy} onCheckedChange={(enabled) => onChange({ ...value, enabled })} />
        </div>
      </div>

      <div className="grid min-w-0 max-w-sm gap-2">
        <Label htmlFor="dns-query-strategy">{t("Query strategy")}</Label>
        <Select value={value.query_strategy} disabled={busy} onValueChange={(queryStrategy: DNSQueryStrategy) => onChange({ ...value, query_strategy: queryStrategy })}>
          <SelectTrigger id="dns-query-strategy" className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="use-ip">{t("IPv4 and IPv6")}</SelectItem>
            <SelectItem value="use-ipv4">{t("IPv4 only")}</SelectItem>
            <SelectItem value="use-ipv6">{t("IPv6 only")}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="flex min-w-0 flex-col gap-4 border-t pt-6 sm:flex-row sm:items-center sm:justify-between">
        <div className="grid min-w-0 gap-1">
          <h3 className="font-semibold">{t("DNS servers")}</h3>
          <p className="text-sm text-muted-foreground">{t("Servers are queried in the configured order")}</p>
        </div>
        <Button type="button" disabled={busy} onClick={onAdd}><Plus />{t("Add server")}</Button>
      </div>

      {value.servers.length === 0 ? (
        <EmptyList title={t("No DNS servers configured")} detail={t("Add and enable a server before enabling DNS")} />
      ) : (
        <div className="min-w-0 divide-y rounded-lg border">
          {value.servers.map((server, index) => (
            <article key={server.server_id} className="grid min-w-0 gap-4 px-4 py-4 md:grid-cols-[minmax(0,1fr)_minmax(15rem,0.8fr)_auto] md:items-center">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <strong className="truncate text-sm font-medium">{server.display_name}</strong>
                  <StatusBadge enabled={server.enabled} t={t} />
                </div>
                <p className="mt-1 truncate font-mono text-xs text-muted-foreground">{server.server_id}</p>
              </div>
              <div className="grid min-w-0 gap-1 text-sm text-muted-foreground">
                <span>{server.transport === "system" ? t("System resolver") : server.transport === "doh" ? t("DNS over HTTPS") : server.transport.toUpperCase()}</span>
                <span className="truncate" title={endpoint(server, t)}>{endpoint(server, t)}</span>
                <span>{t("Domains {domains}", { domains: server.domains.length })}</span>
              </div>
              <EntityActions busy={busy} index={index} count={value.servers.length} t={t} onMove={(offset) => onMove(index, offset)} onEdit={() => onEdit(server)} onDelete={() => onDelete(server)} />
            </article>
          ))}
        </div>
      )}
    </div>
  )
}
