import { Badge } from "@/components/ui/badge"
import { Combobox } from "@/components/ui/combobox"
import { Label } from "@/components/ui/label"
import type { Translator } from "@/i18n"
import type { EditableConfiguration, NetworkAddress, StoredConfiguration, XrayVersion } from "@/types"

export function RuntimePanel({ value, stored, addresses, versions, versionError, busy, t, onChange }: {
  value: EditableConfiguration; stored: StoredConfiguration | null; addresses: NetworkAddress[]; versions: XrayVersion[]; versionError: string; busy: boolean; t: Translator
  onChange: (value: EditableConfiguration) => void
}) {
  return (
    <div className="grid min-w-0 gap-6">
      <div><h2 className="font-semibold">{t("Runtime")}</h2><p className="text-sm text-muted-foreground">{t("Xray release and node runtime state")}</p></div>
      <div className="grid gap-4 md:grid-cols-2">
        <div className="grid gap-2"><Label htmlFor="xray-version">{t("Xray version")}</Label><Combobox id="xray-version" value={value.xray_version} options={versionOptions(versions, value.xray_version, t)} searchPlaceholder={t("Search Xray versions")} emptyText={t("No matching versions")} required disabled={busy || versions.length === 0} onValueChange={(xray_version) => onChange({ ...value, xray_version })} />{versionError ? <p className="text-sm text-destructive" role="alert">{versionError}</p> : null}</div>
        <div className="grid gap-2"><Label>{t("Configuration state")}</Label><div className="flex min-h-10 items-center rounded-md border px-3 text-sm"><Badge variant={stored?.exists ? "outline" : "secondary"}>{stored?.exists ? t("Generation {generation}", { generation: stored.generation ?? 0 }) : t("Not configured")}</Badge></div></div>
      </div>
      <div className="grid gap-3"><h3 className="text-sm font-semibold">{t("Node addresses")}</h3><div className="divide-y rounded-lg border">{addresses.length === 0 ? <p className="p-4 text-sm text-muted-foreground">{t("No usable node addresses reported")}</p> : addresses.map((address) => <div key={address.address} className="flex flex-wrap items-center justify-between gap-3 p-4 text-sm"><strong className="break-all">{address.address}</strong><span className="text-muted-foreground">{address.family.toUpperCase()} · {address.interface}</span></div>)}</div></div>
      <div className="grid gap-3"><h3 className="text-sm font-semibold">{t("Managed runtime settings")}</h3><div className="grid gap-3 rounded-lg border p-4 text-sm sm:grid-cols-2"><div><span className="text-muted-foreground">{t("Local API")}</span><strong className="ml-2">127.0.0.1:10085</strong></div><div><span className="text-muted-foreground">{t("DNS")}</span><strong className="ml-2">{t("System resolver")}</strong></div></div></div>
    </div>
  )
}

function versionOptions(versions: XrayVersion[], current: string, t: Translator) {
  const options = versions.map((item) => ({ value: item.version, label: item.prerelease ? `${item.version} · ${t("Pre-release")}` : item.version }))
  if (current !== "" && !versions.some((item) => item.version === current)) options.unshift({ value: current, label: `${current} · ${t("Saved version")}` })
  return options
}
