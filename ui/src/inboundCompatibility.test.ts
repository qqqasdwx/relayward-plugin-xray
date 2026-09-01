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

  it("distinguishes minimum versions from versions that were only verified", () => {
    expect(capabilities.reality.cores.mihomo).toMatchObject({ status: "supported", evidence: "minimum", version: "1.14.3" })
    expect(capabilities.vision.cores.mihomo).toMatchObject({ status: "supported", evidence: "verified", version: "1.19.29" })
    expect(capabilities["shadowsocks-2022"].cores["sing-box"]).toMatchObject({ status: "supported", evidence: "verified", version: "1.13.2" })
  })
})
