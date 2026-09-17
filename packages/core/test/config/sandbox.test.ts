import { describe, expect, test } from "bun:test"
import { Schema } from "effect"
import { Config } from "@opencode-ai/core/config"
import { ConfigV1 } from "@opencode-ai/core/v1/config/config"
import { ConfigMigrateV1 } from "@opencode-ai/core/v1/config/migrate"

describe("ConfigSandbox", () => {
  test("decodes NVX configuration in current and compatibility schemas", () => {
    const input = {
      sandbox: {
        backend: "nvx",
        path: "/opt/nvx",
        processors: 4,
        memory_mib: 256,
        cpus: "0,2,4,6,8,10",
        snapshot: false,
        network: {
          address: "10.0.0.2/24",
          egress: "deny",
          allow: ["140.82.112.0/20:tcp:443"],
        },
      },
    }

    expect(Schema.decodeUnknownSync(Config.Info)(input).sandbox).toMatchObject(input.sandbox)
    const legacy = Schema.decodeUnknownSync(ConfigV1.Info)(input)
    expect(legacy.sandbox).toMatchObject(input.sandbox)
    expect(ConfigMigrateV1.migrate(legacy).sandbox).toMatchObject(input.sandbox)
  })

  test("rejects unsupported NVX processor counts", () => {
    expect(() =>
      Schema.decodeUnknownSync(Config.Info)({
        sandbox: {
          backend: "nvx",
          path: "/opt/nvx",
          processors: 3,
        },
      }),
    ).toThrow()
  })
})
