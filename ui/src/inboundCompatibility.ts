import type { ProxyService } from "@/types"

export const clientCores = ["xray", "sing-box", "mihomo"] as const

export type ClientCore = (typeof clientCores)[number]
export type CapabilityID = "vless" | "vision" | "reality" | "raw-http" | "vless-encryption" | "mldsa" | "spider-x" | "shadowsocks" | "shadowsocks-2022"
export type SupportEvidence =
  | { status: "supported"; version: string; evidence: "minimum" | "verified"; rank: number }
  | { status: "not-generated" }
  | { status: "optional-ignored" }

export interface CapabilityDefinition {
  label: string
  restricted: boolean
  cores: Record<ClientCore, SupportEvidence>
}

export const capabilities: Record<CapabilityID, CapabilityDefinition> = {
  vless: {
    label: "VLESS",
    restricted: false,
    cores: {
      xray: minimum("1.0.0", 100),
      "sing-box": minimum("1.1.0", 100),
      mihomo: verified("1.19.29", 100),
    },
  },
  vision: {
    label: "XTLS Vision",
    restricted: false,
    cores: {
      xray: minimum("1.6.2", 200),
      "sing-box": minimum("1.2.0", 200),
      mihomo: verified("1.19.29", 350),
    },
  },
  reality: {
    label: "REALITY",
    restricted: false,
    cores: {
      xray: minimum("1.8.0", 300),
      "sing-box": minimum("1.2.0", 300),
      mihomo: minimum("1.14.3", 300),
    },
  },
  "raw-http": {
    label: "RAW HTTP camouflage",
    restricted: true,
    cores: {
      xray: verified("26.7.28", 700),
      "sing-box": { status: "not-generated" },
      mihomo: { status: "not-generated" },
    },
  },
  "vless-encryption": {
    label: "VLESS Encryption",
    restricted: true,
    cores: {
      xray: minimum("25.8.29", 500),
      "sing-box": { status: "not-generated" },
      mihomo: minimum("1.19.13", 500),
    },
  },
  mldsa: {
    label: "ML-DSA",
    restricted: true,
    cores: {
      xray: minimum("25.7.23", 600),
      "sing-box": { status: "not-generated" },
      mihomo: { status: "not-generated" },
    },
  },
  "spider-x": {
    label: "SpiderX",
    restricted: false,
    cores: {
      xray: minimum("1.8.0", 300),
      "sing-box": { status: "optional-ignored" },
      mihomo: { status: "optional-ignored" },
    },
  },
  shadowsocks: {
    label: "Shadowsocks",
    restricted: false,
    cores: {
      xray: verified("26.3.27", 100),
      "sing-box": verified("1.13.2", 100),
      mihomo: verified("1.19.29", 100),
    },
  },
  "shadowsocks-2022": {
    label: "Shadowsocks 2022",
    restricted: false,
    cores: {
      xray: verified("26.3.27", 200),
      "sing-box": verified("1.13.2", 200),
      mihomo: verified("1.19.29", 200),
    },
  },
}

export interface CoreCompatibility {
  core: ClientCore
  supported: boolean
  requirement?: Extract<SupportEvidence, { status: "supported" }>
  blockers: CapabilityID[]
}

export function activeCapabilities(service: ProxyService): CapabilityID[] {
  if (service.type === "shadowsocks" && service.shadowsocks != null) {
    return service.shadowsocks.method.startsWith("2022-")
      ? ["shadowsocks", "shadowsocks-2022"]
      : ["shadowsocks"]
  }
  const active: CapabilityID[] = ["vless", "reality"]
  if (service.vless_reality?.flow !== "") active.push("vision")
  if (service.tcp.header.type === "http") active.push("raw-http")
  if (service.vless_reality?.encryption.trim() !== "" && service.vless_reality?.encryption.trim() !== "none") active.push("vless-encryption")
  if (service.vless_reality?.mldsa65_verify.trim() !== "") active.push("mldsa")
  if (service.vless_reality?.spider_x !== "" && service.vless_reality?.spider_x !== "/") active.push("spider-x")
  return active
}

export function compatibilityFor(service: ProxyService): CoreCompatibility[] {
  const active = activeCapabilities(service)
  return clientCores.map((core) => {
    const evidence = active.map((capability) => ({ capability, support: capabilities[capability].cores[core] }))
    const blockers = evidence
      .filter((entry) => entry.support.status === "not-generated")
      .map((entry) => entry.capability)
    const requirements = evidence
      .map((entry) => entry.support)
      .filter((support): support is Extract<SupportEvidence, { status: "supported" }> => support.status === "supported")
      .sort((left, right) => right.rank - left.rank)
    return { core, supported: blockers.length === 0, requirement: requirements[0], blockers }
  })
}

function minimum(version: string, rank: number): SupportEvidence {
  return { status: "supported", version, evidence: "minimum", rank }
}

function verified(version: string, rank: number): SupportEvidence {
  return { status: "supported", version, evidence: "verified", rank }
}
