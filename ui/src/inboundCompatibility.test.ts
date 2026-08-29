import { describe, expect, it } from "vitest"

import { capabilities, compatibilityFor } from "@/inboundCompatibility"
import { nextServiceDefaults } from "@/configuration"

describe("inbound compatibility", () => {
  it("keeps the default VLESS REALITY configuration compatible with all generated formats", () => {
    const result = compatibilityFor(nextServiceDefaults([], []))

    expect(result.map(({ core, supported, blockers }) => ({ core, supported, blockers }))).toEqual([
      { core: "xray", supported: true, blockers: [] },
      { core: "sing-box", supported: true, blockers: [] },
      { core: "mihomo", supported: true, blockers: [] },
    ])
  })

  it("reports every enabled restricted parameter per generated format", () => {
    const service = nextServiceDefaults([], [])
    service.tcp.header.type = "http"
    service.vless_reality!.encryption = "mlkem768x25519plus.native.0rtt.key"
    service.vless_reality!.mldsa65_verify = "verify"

    const result = compatibilityFor(service)

    expect(result[0]).toMatchObject({ core: "xray", supported: true, blockers: [] })
    expect(result[0]?.requirement).toMatchObject({ version: "26.7.28", evidence: "verified" })
    expect(result[1]).toMatchObject({ core: "sing-box", supported: false, blockers: ["raw-http", "vless-encryption", "mldsa"] })
    expect(result[2]).toMatchObject({ core: "mihomo", supported: false, blockers: ["raw-http", "mldsa"] })
  })

  it("distinguishes minimum versions from versions that were only verified", () => {
    expect(capabilities.reality.cores.mihomo).toMatchObject({ status: "supported", evidence: "minimum", version: "1.14.3" })
    expect(capabilities.vision.cores.mihomo).toMatchObject({ status: "supported", evidence: "verified", version: "1.19.29" })
    expect(capabilities["raw-http"].cores["sing-box"]).toEqual({ status: "not-generated" })
  })

  it("does not restrict subscriptions for an empty or none encryption value", () => {
    const service = nextServiceDefaults([], [])
    service.vless_reality!.encryption = "  none  "

    expect(compatibilityFor(service).every((entry) => entry.supported)).toBe(true)
  })

  it("only applies ML-DSA client restrictions when the verification value is present", () => {
    const service = nextServiceDefaults([], [])
    service.vless_reality!.mldsa65_seed = "server-only-seed"

    expect(compatibilityFor(service).every((entry) => entry.supported)).toBe(true)

    service.vless_reality!.mldsa65_verify = "client-verification-value"
    expect(compatibilityFor(service).map(({ core, supported }) => ({ core, supported }))).toEqual([
      { core: "xray", supported: true },
      { core: "sing-box", supported: false },
      { core: "mihomo", supported: false },
    ])
  })
})
