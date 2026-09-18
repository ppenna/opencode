import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { once } from "node:events"
import { createServer, type Socket } from "node:net"
import { gunzipSync, gzipSync } from "node:zlib"
import { describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { ChildProcess } from "effect/unstable/process"
import { AppNodeBuilder } from "@opencode-ai/core/effect/app-node-builder"
import { LayerNode } from "@opencode-ai/core/effect/layer-node"
import { ConfigSandbox } from "@opencode-ai/core/config/sandbox"
import { CrossSpawnSpawner } from "@opencode-ai/core/cross-spawn-spawner"
import { FSUtil } from "@opencode-ai/core/fs-util"
import { Global } from "@opencode-ai/core/global"
import { NvxSandbox } from "@opencode-ai/core/sandbox/nvx"
import { addIdentity } from "@opencode-ai/core/sandbox/nvx-initramfs"
import { CompletionMarkerFilter } from "@opencode-ai/core/sandbox/nvx-output"
import { Client } from "@opencode-ai/core/sandbox/nvx-protocol"
import { testEffect } from "../lib/effect"

const effect = testEffect(AppNodeBuilder.build(LayerNode.group([FSUtil.node, CrossSpawnSpawner.node])))
const liveNvx = process.env.OPENCODE_TEST_NVX_BUNDLE ? effect.live : effect.live.skip

describe("NvxSandbox", () => {
  test("adds a writable host identity to the NVX initramfs", () => {
    const original = gzipSync(
      newc([
        ["etc/passwd", Buffer.from("root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n")],
        ["etc/group", Buffer.from("root:x:0:root\nnobody:x:65534:\n")],
      ]),
    )
    const output = gunzipSync(addIdentity(original, 1000, 1000))

    expect(output.includes(Buffer.from("opencode1000:x:1000:1000:OpenCode NVX:/tmp:/bin/sh\n"))).toBe(true)
    expect(output.includes(Buffer.from("opencode1000:x:1000:\n"))).toBe(true)
  })

  test("rejects an existing UID with a different primary GID", () => {
    const original = gzipSync(
      newc([
        ["etc/passwd", Buffer.from("user:x:1000:2000:user:/home/user:/bin/sh\n")],
        ["etc/group", Buffer.from("user:x:2000:\n")],
      ]),
    )

    expect(() => addIdentity(original, 1000, 1000)).toThrow("does not use GID 1000")
  })

  test("installs the generic snapshot handoff into the initramfs", () => {
    const original = gzipSync(
      newc([
        [
          "init",
          Buffer.from(`#!/bin/sh
if [ "$sandbox_mode" = false ]; then
    mount_virtfs
fi
`),
        ],
        ["etc/passwd", Buffer.from("root:x:0:0:root:/root:/bin/sh\n")],
        ["etc/group", Buffer.from("root:x:0:root\n")],
      ]),
    )
    const output = gunzipSync(addIdentity(original, 1000, 1000, true))

    expect(output.includes(Buffer.from("mount_virtfs"))).toBe(true)
    expect(output.includes(Buffer.from("/sbin/nvx-snapshot"))).toBe(true)
    expect(output.includes(Buffer.from("OPENCODE-NVX-SNAPSHOT-READY"))).toBe(true)
    expect(output.includes(Buffer.from("/tmp/opencode-snapshot-ready"))).toBe(true)
  })

  test("removes a completion marker across output frames", () => {
    const marker = Buffer.from("\x1eopencode-nvx-marker\x1f")
    const filter = new CompletionMarkerFilter(marker)

    const output = [
      ...filter.write(Buffer.from("before\x1eopencode-")),
      ...filter.write(Buffer.from("nvx-marker\x1fmiddle\x1eopencode-nvx-marker\x1fafter")),
      ...filter.finish(),
    ]

    expect(Buffer.concat(output).toString()).toBe("beforemiddleafter")
  })

  test("flushes stderr when no completion marker arrives", () => {
    const filter = new CompletionMarkerFilter(Buffer.from("marker"))

    const output = [...filter.write(Buffer.from("stderr")), ...filter.finish()]

    expect(Buffer.concat(output).toString()).toBe("stderr")
  })

  test("reuses one authenticated managed exec session", async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), "opencode-nvx-protocol-"))
    const endpoint = path.join(directory, "control.sock")
    const capability = Buffer.alloc(32, 7)
    const handled: Promise<void>[] = []
    const server = createServer((socket) => {
      handled.push(
        serveSession(socket, capability).finally(() => {
          socket.destroy()
        }),
      )
    })

    try {
      server.listen(endpoint)
      await once(server, "listening")

      const stdout: Uint8Array[] = []
      const stderr: Uint8Array[] = []
      const client = await Client.connect(endpoint, capability, 1000)
      await client.ping(1000)
      const result = await client.exec(["/bin/sh", "-c", "exit 3"], {
        timeoutMs: 5000,
        responseTimeoutMs: 1000,
        stdout: (chunk) => {
          stdout.push(chunk)
        },
        stderr: (chunk) => {
          stderr.push(chunk)
        },
      })
      await client.stop(1000)
      client.close()

      await Promise.all(handled)
      expect(result).toEqual({ exitCode: 3, category: "exit" })
      expect(Buffer.concat(stdout).toString()).toBe("out")
      expect(Buffer.concat(stderr).toString()).toBe("err")
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
      await fs.rm(directory, { recursive: true, force: true })
    }
  })

  test("reconnects when restore resets the first control attachment", async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), "opencode-nvx-reconnect-"))
    const endpoint = path.join(directory, "control.sock")
    const capability = Buffer.alloc(32, 9)
    let connections = 0
    const handled: Promise<void>[] = []
    const server = createServer((socket) => {
      connections++
      handled.push(
        (async () => {
          const reader = new Reader(socket)
          const attached = await record(reader)
          expect(attached.type).toBe(2)
          if (connections === 1) {
            socket.destroy()
            return
          }
          socket.write(Uint8Array.from(outer(7, 1n, Buffer.alloc(0), 0n)))
          const ping = await record(reader)
          socket.write(Uint8Array.from(outer(5, 1n, app(0x81, ping.payload.readBigUInt64LE(8), 0), 1n)))
        })().finally(() => socket.destroy()),
      )
    })

    try {
      server.listen(endpoint)
      await once(server, "listening")
      const client = await Client.connect(endpoint, capability, 1000)
      await client.ping(1000)
      client.close()
      await Promise.all(handled)
      expect(connections).toBe(2)
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
      await fs.rm(directory, { recursive: true, force: true })
    }
  })
})

async function serveSession(socket: Socket, capability: Buffer) {
  const reader = new Reader(socket)
  const attached = await record(reader)
  expect(attached.type).toBe(2)
  expect(attached.payload.toString("hex")).toBe(capability.toString("hex"))
  socket.write(Uint8Array.from(outer(7, 1n, Buffer.alloc(0), 0n)))

  const ping = await record(reader)
  expect(ping.sequence).toBe(0n)
  expect(ping.payload.readUInt8(5)).toBe(1)
  socket.write(Uint8Array.from(outer(5, 1n, app(0x81, ping.payload.readBigUInt64LE(8), 0), 1n)))

  const exec = await record(reader)
  expect(exec.sequence).toBe(1n)
  expect(exec.payload.readUInt8(5)).toBe(2)
  const requestID = exec.payload.readBigUInt64LE(8)
  socket.write(Uint8Array.from(outer(5, 1n, app(0x82, requestID, 0, Buffer.from("out")), 2n)))
  socket.write(Uint8Array.from(outer(5, 1n, app(0x83, requestID, 0, Buffer.from("err")), 3n)))
  socket.write(Uint8Array.from(outer(5, 1n, app(0x84, requestID, 3, Buffer.from("exit")), 4n)))

  const stop = await record(reader)
  expect(stop.sequence).toBe(2n)
  expect(stop.payload.readUInt8(5)).toBe(3)
  socket.write(Uint8Array.from(outer(5, 1n, app(0x85, stop.payload.readBigUInt64LE(8), 0), 5n)))
}

liveNvx(
  "runs a writable command through a real NVX microVM",
  Effect.acquireUseRelease(
    Effect.promise(() => fs.mkdtemp(path.join(os.tmpdir(), "opencode-nvx-live-"))),
    (directory) =>
      Effect.gen(function* () {
        const filesystem = yield* FSUtil.Service
        const sandbox = yield* NvxSandbox.create({
          config: new ConfigSandbox.Nvx({
            backend: "nvx",
            path: process.env.OPENCODE_TEST_NVX_BUNDLE!,
            snapshot: false,
          }),
          directory,
          fs: filesystem,
        })
        const result = yield* runSandbox(
          sandbox,
          directory,
          "printf 'sandbox-ok' > result.txt && printf 'warm' > /tmp/opencode-nvx-state && id -u",
        )

        expect(result.exitCode).toBe(0)
        expect(result.output.toString().trim()).toBe(String(process.platform === "win32" ? 65534 : process.getuid?.()))
        expect(yield* Effect.promise(() => fs.readFile(path.join(directory, "result.txt"), "utf8"))).toBe("sandbox-ok")
        expect((yield* runSandbox(sandbox, directory, "cat /tmp/opencode-nvx-state")).output.toString()).toBe("warm")
        expect((yield* runSandbox(sandbox, directory, ":")).output.toString()).toBe("")
        expect((yield* runSandbox(sandbox, directory, "printf guest-error >&2")).output.toString()).toBe("guest-error")

        const timedOut = yield* runSandbox(sandbox, directory, "sleep 5", 100)
        expect(timedOut.category).toBe("timeout")
        expect((yield* runSandbox(sandbox, directory, "cat /tmp/opencode-nvx-state")).output.toString()).toBe("warm")
      }),
    (directory) => Effect.promise(() => fs.rm(directory, { recursive: true, force: true })),
  ),
  30_000,
)

liveNvx(
  "captures one generic snapshot and restores later runtimes",
  Effect.acquireUseRelease(
    Effect.promise(() => fs.mkdtemp(path.join(os.tmpdir(), "opencode-nvx-snapshot-"))),
    (directory) =>
      Effect.gen(function* () {
        const filesystem = yield* FSUtil.Service
        const snapshots = path.join(Global.Path.cache, "nvx", "snapshots")
        const before = new Set(
          yield* Effect.promise(() =>
            fs.readdir(snapshots).catch((error: NodeJS.ErrnoException) => {
              if (error.code === "ENOENT") return []
              throw error
            }),
          ),
        )
        const run = (command: string) =>
          Effect.scoped(
            Effect.gen(function* () {
              const sandbox = yield* NvxSandbox.create({
                config: new ConfigSandbox.Nvx({
                  backend: "nvx",
                  path: process.env.OPENCODE_TEST_NVX_BUNDLE!,
                }),
                directory,
                fs: filesystem,
              })
              return yield* runSandbox(sandbox, directory, command)
            }),
          )

        const first = yield* run("printf session-one >/tmp/session-one; printf host-state > restore-proof")
        expect(first.exitCode).toBe(0)
        const afterFirst = yield* Effect.promise(() => fs.readdir(snapshots))
        const created = afterFirst.filter((entry) => !before.has(entry))
        expect(created).toHaveLength(1)
        const template = path.join(snapshots, created[0])
        yield* Effect.addFinalizer(() =>
          Effect.promise(() => fs.rm(template, { recursive: true, force: true })).pipe(Effect.ignore),
        )
        for (const file of ["manifest.bin", "state.bin", "memory.bin"]) {
          expect(yield* Effect.promise(() => fs.stat(path.join(template, "snapshot", file)))).toBeDefined()
        }

        const restored = yield* run("test ! -e /tmp/session-one && cat restore-proof")
        expect(restored.exitCode).toBe(0)
        expect(restored.output.toString()).toBe("host-state")
        expect(yield* Effect.promise(() => fs.readdir(snapshots))).toEqual(afterFirst)
      }),
    (directory) => Effect.promise(() => fs.rm(directory, { recursive: true, force: true })),
  ),
  60_000,
)

const runSandbox = (sandbox: NvxSandbox.Interface, directory: string, command: string, timeoutMs = 10_000) =>
  Effect.gen(function* () {
    const output: Uint8Array[] = []
    const result = yield* sandbox.execute(
      ChildProcess.make(command, [], {
        cwd: directory,
        shell: "/bin/sh",
        stdin: "ignore",
      }),
      {
        timeoutMs,
        output: (_channel, chunk) => {
          output.push(chunk)
        },
      },
    )
    return { ...result, output: Buffer.concat(output) }
  })

class Reader {
  private readonly iterator: AsyncIterator<Uint8Array>
  private buffer = Buffer.alloc(0)

  constructor(socket: Socket) {
    this.iterator = socket[Symbol.asyncIterator]()
  }

  async read(length: number) {
    while (this.buffer.length < length) {
      const next = await this.iterator.next()
      if (next.done) throw new Error("socket closed")
      this.buffer = Buffer.concat([this.buffer, Buffer.from(next.value)])
    }
    const result = this.buffer.subarray(0, length)
    this.buffer = this.buffer.subarray(length)
    return result
  }
}

async function record(reader: Reader) {
  const header = await reader.read(44)
  const length = header.readUInt32LE(40)
  return {
    type: header.readUInt8(6),
    sequence: header.readBigUInt64LE(32),
    payload: await reader.read(length),
  }
}

function outer(type: number, epoch: bigint, payload: Buffer, sequence: bigint) {
  const result = Buffer.alloc(44 + payload.length)
  result.write("NVXS")
  result.writeUInt16LE(1, 4)
  result.writeUInt8(type, 6)
  Buffer.alloc(16, 1).copy(result, 8)
  result.writeBigUInt64LE(epoch, 24)
  result.writeBigUInt64LE(sequence, 32)
  result.writeUInt32LE(payload.length, 40)
  payload.copy(result, 44)
  return result
}

function app(kind: number, requestID: bigint, status: number, payload = Buffer.alloc(0)) {
  const result = Buffer.alloc(24 + payload.length)
  result.write("NVXC")
  result.writeUInt8(1, 4)
  result.writeUInt8(kind, 5)
  result.writeBigUInt64LE(requestID, 8)
  result.writeInt32LE(status, 16)
  result.writeUInt32LE(payload.length, 20)
  payload.copy(result, 24)
  return result
}

function newc(entries: ReadonlyArray<readonly [string, Buffer]>) {
  const output = Buffer.concat([
    ...entries.map(([name, content], index) => entry(name, content, index + 1)),
    entry("TRAILER!!!", Buffer.alloc(0), entries.length + 1),
  ])
  return Buffer.concat([output, Buffer.alloc((512 - (output.length % 512)) % 512)])
}

function entry(name: string, content: Buffer, inode: number) {
  const filename = Buffer.from(name + "\0")
  const values = [inode, 0o100644, 0, 0, 1, 0, content.length, 0, 0, 0, 0, filename.length, 0]
  const header = Buffer.from("070701" + values.map((value) => value.toString(16).padStart(8, "0")).join(""))
  return Buffer.concat([
    header,
    filename,
    Buffer.alloc((4 - ((header.length + filename.length) % 4)) % 4),
    content,
    Buffer.alloc((4 - (content.length % 4)) % 4),
  ])
}
