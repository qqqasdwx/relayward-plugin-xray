import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import type { Translator } from "@/i18n"
import type { EditableConfiguration } from "@/types"

export function RuntimePanel({ value, busy, t, onChange }: {
  value: EditableConfiguration
  busy: boolean
  t: Translator
  onChange: (value: EditableConfiguration) => void
}) {
  return (
    <div className="grid min-w-0 gap-6">
      <div className="grid min-w-0 gap-1">
        <h2 className="font-semibold">{t("Local runtime")}</h2>
        <p className="text-sm text-muted-foreground">{t("Xray release and private control endpoint")}</p>
      </div>
      <div className="grid min-w-0 gap-4 md:grid-cols-3">
        <div className="grid min-w-0 gap-2">
          <Label htmlFor="xray-version">{t("Xray version")}</Label>
          <Input id="xray-version" inputMode="decimal" value={value.xray_version} placeholder="26.3.27" disabled={busy} required onChange={(event) => onChange({ ...value, xray_version: event.target.value })} />
        </div>
        <div className="grid min-w-0 gap-2">
          <Label htmlFor="api-port">{t("Local API port")}</Label>
          <Input id="api-port" type="number" min={1024} max={65535} value={value.api_port} disabled={busy} required onChange={(event) => onChange({ ...value, api_port: Number(event.target.value) })} />
        </div>
        <div className="grid min-w-0 gap-2">
          <Label>{t("Supported transport")}</Label>
          <div className="flex min-h-9 min-w-0 items-center break-words rounded-md border bg-muted/50 px-3 py-2 text-sm text-muted-foreground">VLESS REALITY · Shadowsocks</div>
        </div>
      </div>
    </div>
  )
}
