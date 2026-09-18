export * as NvxSandbox from "./nvx"

import os from "node:os"
import path from "node:path"
import { createHash } from "node:crypto"
import { constants } from "node:fs"
import fsNode from "node:fs/promises"
import { spawn } from "node:child_process"
import { Effect, Option, Schema, Scope, Semaphore } from "effect"
import { systemError } from "effect/PlatformError"
import { ChildProcess } from "effect/unstable/process"
import { ConfigSandbox } from "../config/sandbox"
import { FSUtil } from "../fs-util"
import { Global } from "../global"
import { prepare } from "./nvx-initramfs"
import { CompletionMarkerFilter } from "./nvx-output"
import { Client, type ExitCategory } from "./nvx-protocol"

const BASE_TUNING =
  "tsc=reliable no_timer_check random.trust_cpu=on rcupdate.rcu_expedited=1 nokaslr mitigations=off cryptomgr.notests quiet loglevel=0"
const SAFE_TUNING = "quiet loglevel=0"
const GUEST_RESPONSE_TIMEOUT_MS = 60 * 60 * 1000
const SNAPSHOT_FORMAT = 2
const SNAPSHOT_TIMEOUT_MS = 30_000
const SNAPSHOT_READY_MARKER = Buffer.from("OPENCODE-NVX-SNAPSHOT-READY")
const SnapshotLock = Schema.fromJsonString(
  Schema.Struct({
    token: Schema.String,
    pid: Schema.Number,
  }),
)
const decodeSnapshotLock = Schema.decodeUnknownOption(SnapshotLock)

interface Artifacts {
  readonly openvmm: string
  readonly kernel: string
  readonly initramfs: string
}

interface Instance {
  readonly client: Client
  readonly process: HostProcess
  readonly stateDir: string
  readonly release?: () => Promise<void>
  stopped: boolean
}

interface SnapshotTemplate {
  readonly root: string
  readonly snapshot: string
  readonly endpoint: string
  readonly captureLock: string
  readonly runtimeLock: string
}

interface HostProcess {
  readonly child: ReturnType<typeof spawn>
  readonly stdout: NonNullable<ReturnType<typeof spawn>["stdout"]>
  readonly stderr: NonNullable<ReturnType<typeof spawn>["stderr"]>
  readonly exitPromise: Promise<number>
  readonly exit: Effect.Effect<number, Error>
}

export interface ExecuteOptions {
  readonly timeoutMs: number
  readonly signal?: AbortSignal
  readonly output?: (channel: "stdout" | "stderr", chunk: Uint8Array) => void | Promise<void>
}

export interface ExecuteResult {
  readonly exitCode: number | null
  readonly category: ExitCategory | "aborted"
}

export interface Interface {
  readonly execute: (
    command: ChildProcess.Command,
    options: ExecuteOptions,
  ) => Effect.Effect<ExecuteResult, ReturnType<typeof spawnError>>
}

export const create = Effect.fn("NvxSandbox.create")(function* (input: {
  readonly config: ConfigSandbox.Nvx
  readonly directory: string
  readonly fs: FSUtil.Interface
}) {
  const scope = yield* Scope.Scope
  const semaphore = yield* Semaphore.make(1)
  const directory = yield* input.fs.resolve(input.directory)
  const mount = yield* input.fs.resolve(path.resolve(directory, input.config.mount ?? "."))
  if (!FSUtil.contains(mount, directory))
    throw new Error(`NVX mount must contain the active directory: ${mount} does not contain ${directory}`)
  if (mount.includes(",")) throw new Error(`NVX mount paths containing commas are unsupported: ${mount}`)

  const hypervisor = resolveHypervisor(input.config.hypervisor ?? "auto")
  const processors = input.config.processors ?? 1
  const memoryMiB = input.config.memory_mib ?? 128
  const startupTimeout = input.config.startup_timeout ?? 10_000
  const uid = input.config.uid ?? defaultIdentity("uid")
  const gid = input.config.gid ?? defaultIdentity("gid")
  const guestMount = process.platform === "win32" ? "/workspace" : mount
  const snapshots = input.config.snapshot !== false
  let current: Instance | undefined

  const shutdown = Effect.fn("NvxSandbox.shutdown")(function* (instance: Instance, force = false) {
    if (instance.stopped) return
    instance.stopped = true
    if (current === instance) current = undefined

    if (!force && isRunning(instance.process)) {
      yield* clientCall((signal) => instance.client.stop(startupTimeout, signal)).pipe(
        Effect.as(true),
        Effect.timeoutOrElse({
          duration: "3 seconds",
          orElse: () => Effect.succeed(false),
        }),
        Effect.catch((error) =>
          Effect.logWarning("NVX graceful shutdown failed; terminating OpenVMM", { error }).pipe(Effect.as(false)),
        ),
      )
      yield* instance.process.exit.pipe(
        Effect.timeoutOrElse({ duration: "3 seconds", orElse: () => Effect.void }),
        Effect.ignore,
      )
    }
    instance.client.close()
    if (isRunning(instance.process)) yield* terminate(instance.process)
    yield* instance.process.exit.pipe(
      Effect.timeoutOrElse({ duration: "5 seconds", orElse: () => Effect.void }),
      Effect.ignore,
    )
    yield* input.fs.remove(instance.stateDir, { recursive: true, force: true }).pipe(Effect.ignore)
    if (instance.release) yield* Effect.promise(instance.release).pipe(Effect.ignore)
  })

  const start = Effect.fn("NvxSandbox.start")(function* () {
    const artifacts = yield* resolveArtifacts(input.fs, directory, input.config)
    const initramfs = yield* prepare({
      fs: input.fs,
      source: artifacts.initramfs,
      cache: path.join(Global.Path.cache, "nvx", "initramfs"),
      uid,
      gid,
      snapshot: snapshots,
    })
    const cpuSet = yield* resolveCpuSet(input.fs, input.config.cpus, processors)
    const prepared = { ...artifacts, initramfs }
    const template = snapshots
      ? yield* ensureSnapshot({
          fs: input.fs,
          artifacts: prepared,
          config: input.config,
          cpuSet,
          guestMount,
          hostMount: mount,
          hypervisor,
          memoryMiB,
          processors,
          startupTimeout,
          uid,
          gid,
        })
      : undefined
    if (template) yield* Effect.logDebug("restoring NVX generic snapshot", { snapshot: template.snapshot })
    const release = template ? yield* acquireRuntimeLock(template) : undefined
    const id = crypto.randomUUID()
    const stateDir = path.join(Global.Path.tmp, "nvx", id)
    yield* input.fs.makeDirectory(stateDir, { recursive: true, mode: 0o700 })
    if (process.platform !== "win32") yield* input.fs.chmod(stateDir, 0o700)

    const endpoint = template ? template.endpoint : controlEndpoint(stateDir, id)
    if (template && process.platform !== "win32") {
      yield* input.fs.makeDirectory(path.dirname(endpoint), { recursive: true, mode: 0o700 })
      yield* input.fs.chmod(path.dirname(endpoint), 0o700)
      yield* input.fs.remove(endpoint, { force: true }).pipe(Effect.ignore)
    }
    const capability = crypto.getRandomValues(new Uint8Array(32))
    const args = template
      ? restoreArguments({
          config: input.config,
          endpoint,
          guestMount,
          hostMount: mount,
          hypervisor,
          processors,
          report: path.join(stateDir, "outcome.json"),
          snapshot: template.snapshot,
        })
      : coldArguments({
          artifacts: prepared,
          config: input.config,
          endpoint,
          hypervisor,
          memoryMiB,
          processors,
          uid,
          gid,
          report: path.join(stateDir, "outcome.json"),
          mount: { guest: guestMount, host: mount },
        })
    const cleanupStart = Effect.all(
      [
        input.fs.remove(stateDir, { recursive: true, force: true }).pipe(Effect.ignore),
        ...(release ? [Effect.promise(release).pipe(Effect.ignore)] : []),
      ],
      { discard: true },
    )
    const host = yield* startHost(
      cpuSet ? "taskset" : artifacts.openvmm,
      cpuSet ? ["-c", cpuSet, artifacts.openvmm, ...args] : args,
      capability,
      path.join(stateDir, "auth.pipe"),
    ).pipe(Effect.tapError(() => cleanupStart))
    yield* Scope.addFinalizer(scope, terminate(host).pipe(Effect.ignore))
    const observed = observeHost(host, template ? SNAPSHOT_READY_MARKER : undefined)

    const connected = clientCall(async (signal) => {
      const client = await Client.connect(endpoint, capability, startupTimeout, signal)
      try {
        await client.ping(startupTimeout, signal)
        return client
      } catch (error) {
        client.close()
        throw error
      }
    })
    const ready = template
      ? Effect.all([connected, observed.ready], { concurrency: "unbounded" }).pipe(
          Effect.map(([client]) => client),
          Effect.timeoutOrElse({
            duration: `${startupTimeout} millis`,
            orElse: () => Effect.fail(new Error(`Timed out waiting for restored NVX workspace: ${mount}`)),
          }),
        )
      : connected
    const exited = host.exit.pipe(
      Effect.flatMap((code) => Effect.fail(new Error(`OpenVMM exited with status ${code} before NVX became ready`))),
    )
    const client = yield* Effect.raceFirst(ready, exited).pipe(
      Effect.tapError(() =>
        Effect.all(
          [
            terminate(host).pipe(Effect.ignore),
            cleanupStart,
            ...(template
              ? [input.fs.remove(template.snapshot, { recursive: true, force: true }).pipe(Effect.ignore)]
              : []),
          ],
          { discard: true },
        ),
      ),
      Effect.catch((error) =>
        Effect.fail(
          new Error(
            `${error instanceof Error ? error.message : String(error)}${
              observed.tail().length ? `\n--- OpenVMM output ---\n${observed.tail().toString("utf8")}` : ""
            }`,
            { cause: error },
          ),
        ),
      ),
    )
    const instance: Instance = {
      client,
      process: host,
      stateDir,
      release,
      stopped: false,
    }
    current = instance
    yield* Scope.addFinalizer(scope, shutdown(instance).pipe(Effect.ignore))
    return instance
  })

  const instance = Effect.fn("NvxSandbox.instance")(function* () {
    if (current && isRunning(current.process)) return current
    if (current) yield* shutdown(current, true)
    return yield* start()
  })

  const execute: Interface["execute"] = Effect.fn("NvxSandbox.execute")(function* (command, options) {
    if (command._tag !== "StandardCommand")
      return yield* Effect.fail(spawnError("execute", "piped commands are unsupported by NVX"))
    if (command.options.additionalFds)
      return yield* Effect.fail(spawnError("execute", "additional file descriptors are unsupported by NVX"))
    if (command.options.stdin !== undefined && command.options.stdin !== "ignore")
      return yield* Effect.fail(spawnError("execute", "stdin is unsupported by the NVX managed exec protocol"))

    return yield* semaphore.withPermits(1)(
      Effect.gen(function* () {
        const active = yield* instance().pipe(
          Effect.mapError((cause) =>
            spawnError("start", cause instanceof Error ? cause.message : String(cause), cause),
          ),
        )
        const cwd = yield* input.fs.resolve(path.resolve(command.options.cwd ?? mount))
        const execution = yield* Effect.try({
          try: () => guestArguments(command, input.config, mount, guestMount, cwd),
          catch: (cause) => spawnError("execute", cause instanceof Error ? cause.message : String(cause), cause),
        })
        const filter = new CompletionMarkerFilter(execution.marker)
        const output = (channel: "stdout" | "stderr", chunks: Uint8Array[]) =>
          Effect.promise(async () => {
            for (const chunk of chunks) await options.output?.(channel, chunk)
          })
        const flush = () => output("stderr", filter.finish())

        return yield* clientCall((signal) =>
          active.client.exec(execution.args, {
            timeoutMs: options.timeoutMs,
            responseTimeoutMs: Math.max(options.timeoutMs, GUEST_RESPONSE_TIMEOUT_MS),
            signal: options.signal ? AbortSignal.any([signal, options.signal]) : signal,
            stdout: (chunk) => options.output?.("stdout", chunk),
            stderr: async (chunk) => {
              for (const output of filter.write(chunk)) await options.output?.("stderr", output)
            },
          }),
        ).pipe(
          Effect.tap(() => flush()),
          Effect.map((result): ExecuteResult => ({ exitCode: result.exitCode, category: result.category })),
          Effect.catch((cause) =>
            Effect.gen(function* () {
              yield* flush()
              yield* shutdown(active, true).pipe(Effect.ignore)
              if (options.signal?.aborted) return { exitCode: null, category: "aborted" } satisfies ExecuteResult
              return yield* Effect.fail(
                spawnError("execute", cause instanceof Error ? cause.message : String(cause), cause),
              )
            }),
          ),
          Effect.onInterrupt(() => shutdown(active, true).pipe(Effect.ignore)),
        )
      }),
    )
  })

  return { execute } satisfies Interface
})

function guestArguments(
  command: ChildProcess.StandardCommand,
  config: ConfigSandbox.Nvx,
  hostMount: string,
  guestMount: string,
  cwd: string,
) {
  if (!FSUtil.contains(hostMount, cwd)) throw new Error(`NVX working directory is outside the configured mount: ${cwd}`)
  const relative = path.relative(hostMount, cwd)
  const guestCwd =
    process.platform === "win32" ? path.posix.join(guestMount, ...relative.split(path.sep).filter(Boolean)) : cwd
  const source =
    command.options.extendEnv === false
      ? (command.options.env ?? {})
      : {
          ...process.env,
          ...command.options.env,
        }
  const environment = Object.entries({
    ...Object.fromEntries(
      (config.pass_env ?? []).flatMap((key) => {
        const value = source[key]
        return value === undefined ? [] : [[key, value]]
      }),
    ),
    ...config.environment,
  }).map(([key, value]) => {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new Error(`Invalid NVX environment variable name: ${key}`)
    if (value.includes("\0")) throw new Error(`NVX environment variable contains NUL: ${key}`)
    return `${key}=${value}`
  })
  const target =
    command.options.shell === undefined || command.options.shell === false
      ? [command.command, ...command.args]
      : [config.shell ?? "/bin/sh", "-c", command.command]
  // NVX checks child exit after a 25 ms output poll. This private marker wakes silent commands and is stripped host-side.
  const token = `opencode-nvx-${crypto.randomUUID().replaceAll("-", "")}`
  const args = [
    "/bin/sh",
    "-c",
    'cwd=$1; marker=$2; shift 2; cd "$cwd"; status=$?; if [ "$status" -eq 0 ]; then "$@"; status=$?; fi; printf "\\036%s\\037" "$marker" >&2; exit "$status"',
    "opencode",
    guestCwd,
    token,
    ...(environment.length ? ["env", ...environment] : []),
    ...target,
  ]
  if (args.length > 64) throw new Error("NVX command exceeds the 64-argument managed exec limit")
  for (const arg of args) {
    if (!arg || Buffer.byteLength(arg) > 4096 || arg.includes("\0"))
      throw new Error("NVX command contains an empty, NUL-containing, or larger than 4096-byte argument")
  }
  return {
    args,
    marker: Buffer.concat([Buffer.from([0x1e]), Buffer.from(token), Buffer.from([0x1f])]),
  }
}

function coldArguments(input: {
  readonly artifacts: Artifacts
  readonly config: ConfigSandbox.Nvx
  readonly endpoint: string
  readonly hypervisor: "kvm" | "mshv" | "whp"
  readonly memoryMiB: number
  readonly processors: 1 | 2 | 4 | 8
  readonly uid: number
  readonly gid: number
  readonly report: string
  readonly snapshot?: string
  readonly mount?: {
    readonly guest: string
    readonly host: string
  }
}) {
  const tuning = input.config.performance_tuning === false ? SAFE_TUNING : BASE_TUNING
  const args = [
    "--single-process",
    "--machine",
    "microvm",
    "--processors",
    String(input.processors),
    "--hypervisor",
    input.hypervisor,
    "--memory",
    `${input.memoryMiB}M`,
    "--kernel",
    input.artifacts.kernel,
    "--initrd",
    input.artifacts.initramfs,
    "--cmdline",
    `${input.hypervisor === "kvm" ? "clocksource=kvm-clock " : ""}${tuning}${
      input.snapshot ? " opencode_snapshot=1" : ""
    }`,
    "--microvm-workload-identity",
    `${input.uid}:${input.gid}`,
    "--microvm-lifecycle",
    "managed",
    "--virtio-console",
    "none",
    "--microvm-control-console",
    `listen=${input.endpoint}`,
    "--microvm-control-auth-stdin",
    "--microvm-report",
    input.report,
  ]
  if (input.mount) args.push("--mount", `${input.mount.guest},${input.mount.host},rw`)
  if (input.snapshot) args.push("--snapshot-destination", input.snapshot)
  args.push(...networkArguments(input.config, false))
  return args
}

function restoreArguments(input: {
  readonly config: ConfigSandbox.Nvx
  readonly endpoint: string
  readonly guestMount: string
  readonly hostMount: string
  readonly hypervisor: "kvm" | "mshv" | "whp"
  readonly processors: 1 | 2 | 4 | 8
  readonly report: string
  readonly snapshot: string
}) {
  return [
    "--single-process",
    "--machine",
    "microvm",
    "--processors",
    String(input.processors),
    "--hypervisor",
    input.hypervisor,
    "--restore-snapshot",
    input.snapshot,
    "--restore-entropy",
    "--mount",
    `${input.guestMount},${input.hostMount},rw`,
    "--microvm-control-console",
    `listen=${input.endpoint}`,
    "--microvm-control-auth-stdin",
    "--microvm-report",
    input.report,
    ...networkArguments(input.config, true),
  ]
}

function networkArguments(config: ConfigSandbox.Nvx, restore: boolean) {
  const network = config.network
  if (!network) return []
  const args = [
    ...(restore ? [] : ["--net", network.address]),
    "--network-profile",
    "portable",
    "--network-ingress",
    "deny",
    "--network-egress",
    network.egress ?? "deny",
    "--host-loopback",
    network.host_loopback ?? "deny",
  ]
  for (const rule of network.allow ?? []) args.push("--network-egress-allow", rule)
  for (const rule of network.deny ?? []) args.push("--network-egress-deny", rule)
  for (const forward of network.forward ?? []) args.push("--host-loopback-forward", forward)
  if (network.proxy) args.push("--network-proxy", network.proxy)
  return args
}

const snapshotTemplate = Effect.fn("NvxSandbox.snapshotTemplate")(function* (input: {
  readonly artifacts: Artifacts
  readonly config: ConfigSandbox.Nvx
  readonly guestMount: string
  readonly hostMount: string
  readonly hypervisor: "kvm" | "mshv" | "whp"
  readonly memoryMiB: number
  readonly processors: 1 | 2 | 4 | 8
  readonly uid: number
  readonly gid: number
}) {
  const files = yield* Effect.tryPromise({
    try: () =>
      Promise.all(
        [input.artifacts.openvmm, input.artifacts.kernel, input.artifacts.initramfs].map(async (file) => {
          const info = await fsNode.stat(file, { bigint: true })
          return {
            path: file,
            size: info.size.toString(),
            mtime: info.mtimeNs.toString(),
          }
        }),
      ),
    catch: (cause) => (cause instanceof Error ? cause : new Error(String(cause))),
  })
  const key = createHash("sha256")
    .update(
      JSON.stringify({
        format: SNAPSHOT_FORMAT,
        platform: process.platform,
        arch: process.arch,
        hostname: os.hostname(),
        cpu: os.cpus()[0]?.model,
        files,
        hypervisor: input.hypervisor,
        memoryMiB: input.memoryMiB,
        processors: input.processors,
        uid: input.uid,
        gid: input.gid,
        guestMount: input.guestMount,
        hostMount: input.hostMount,
        performanceTuning: input.config.performance_tuning !== false,
        network: input.config.network,
      }),
    )
    .digest("hex")
  const id = key.slice(0, 24)
  const root = path.join(Global.Path.cache, "nvx", "snapshots", id)
  const endpoint = controlEndpoint(root, id)
  return {
    root,
    snapshot: path.join(root, "snapshot"),
    endpoint,
    captureLock: path.join(root, "capture.lock"),
    runtimeLock: path.join(root, "runtime.lock"),
  } satisfies SnapshotTemplate
})

const snapshotValid = Effect.fn("NvxSandbox.snapshotValid")(function* (
  fs: FSUtil.Interface,
  template: SnapshotTemplate,
) {
  return yield* Effect.all(
    ["manifest.bin", "state.bin", "memory.bin"].map((file) => fs.isFile(path.join(template.snapshot, file))),
  ).pipe(Effect.map((files) => files.every(Boolean)))
})

const claimSnapshot = Effect.fn("NvxSandbox.claimSnapshot")(function* (
  fs: FSUtil.Interface,
  template: SnapshotTemplate,
) {
  yield* fs.makeDirectory(template.root, { recursive: true, mode: 0o700 })
  const result = yield* Effect.tryPromise({
    try: async () => {
      const deadline = Date.now() + SNAPSHOT_TIMEOUT_MS
      while (true) {
        if (
          await Promise.all(
            ["manifest.bin", "state.bin", "memory.bin"].map((file) =>
              fsNode
                .stat(path.join(template.snapshot, file))
                .then((info) => info.isFile())
                .catch(() => false),
            ),
          ).then((files) => files.every(Boolean))
        )
          return false
        try {
          await fsNode.mkdir(template.captureLock, { mode: 0o700 })
          return true
        } catch (error) {
          if (!isErrorCode(error, "EEXIST")) throw error
          const info = await fsNode.stat(template.captureLock).catch(() => undefined)
          if (info && Date.now() - info.mtimeMs > SNAPSHOT_TIMEOUT_MS) {
            await fsNode.rm(template.captureLock, { recursive: true, force: true })
            continue
          }
          if (Date.now() >= deadline)
            throw new Error(`Timed out waiting for NVX snapshot ${template.snapshot}`, { cause: error })
          await new Promise<void>((resolve) => setTimeout(resolve, 50))
        }
      }
    },
    catch: (cause) => (cause instanceof Error ? cause : new Error(String(cause))),
  })
  return result
})

const acquireRuntimeLock = Effect.fn("NvxSandbox.acquireRuntimeLock")(function* (template: SnapshotTemplate) {
  const token = crypto.randomUUID()
  yield* Effect.tryPromise({
    try: async () => {
      await fsNode.mkdir(template.root, { recursive: true, mode: 0o700 })
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const file = await fsNode.open(template.runtimeLock, "wx", 0o600)
          await file.writeFile(JSON.stringify({ token, pid: process.pid }))
          await file.close()
          return
        } catch (error) {
          if (!isErrorCode(error, "EEXIST")) throw error
          const owner = await readSnapshotLock(template.runtimeLock)
          if (owner && processRunning(owner.pid))
            throw new Error(`NVX snapshot is already active for this mount: ${template.snapshot}`, { cause: error })
          await fsNode.rm(template.runtimeLock, { force: true })
        }
      }
      throw new Error(`Failed to acquire NVX snapshot runtime lock: ${template.runtimeLock}`)
    },
    catch: (cause) => (cause instanceof Error ? cause : new Error(String(cause))),
  })
  return async () => {
    const owner = await readSnapshotLock(template.runtimeLock)
    if (owner?.token === token) await fsNode.rm(template.runtimeLock, { force: true })
  }
})

function processRunning(pid: number) {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return !isErrorCode(error, "ESRCH")
  }
}

function observeHost(host: HostProcess, marker?: Buffer) {
  let tail = Buffer.alloc(0)
  let search = Buffer.alloc(0)
  let resolve = () => {}
  const ready = marker ? new Promise<void>((done) => (resolve = done)) : Promise.resolve()
  const append = (chunk: Uint8Array) => {
    const next = Buffer.concat([tail, chunk])
    tail = next.length > 64 * 1024 ? next.subarray(next.length - 64 * 1024) : next
    if (!marker) return
    search = Buffer.concat([search, chunk])
    if (search.includes(marker)) resolve()
    if (search.length > marker.length) search = search.subarray(search.length - marker.length)
  }
  host.stdout.on("data", append)
  host.stderr.on("data", append)
  return {
    tail: () => tail,
    ready: Effect.tryPromise({
      try: () => ready,
      catch: (cause) => (cause instanceof Error ? cause : new Error(String(cause))),
    }),
  }
}

async function readSnapshotLock(file: string) {
  const value = await fsNode.readFile(file, "utf8").catch(() => undefined)
  return value ? Option.getOrUndefined(decodeSnapshotLock(value)) : undefined
}

function isErrorCode(error: unknown, code: string): error is Error & { code: string } {
  return error instanceof Error && "code" in error && error.code === code
}

const ensureSnapshot = Effect.fn("NvxSandbox.ensureSnapshot")(function* (input: {
  readonly fs: FSUtil.Interface
  readonly artifacts: Artifacts
  readonly config: ConfigSandbox.Nvx
  readonly cpuSet: string | undefined
  readonly guestMount: string
  readonly hostMount: string
  readonly hypervisor: "kvm" | "mshv" | "whp"
  readonly memoryMiB: number
  readonly processors: 1 | 2 | 4 | 8
  readonly startupTimeout: number
  readonly uid: number
  readonly gid: number
}) {
  const template = yield* snapshotTemplate(input)
  if (yield* snapshotValid(input.fs, template)) return template
  if (!(yield* claimSnapshot(input.fs, template))) return template

  yield* Effect.gen(function* () {
    if (yield* snapshotValid(input.fs, template)) return
    yield* Effect.logInfo("capturing NVX generic snapshot", { snapshot: template.snapshot })
    yield* input.fs.remove(template.snapshot, { recursive: true, force: true }).pipe(Effect.ignore)
    yield* captureSnapshot({ ...input, template })
    if (!(yield* snapshotValid(input.fs, template)))
      throw new Error(`NVX snapshot capture did not publish a complete artifact: ${template.snapshot}`)
  }).pipe(Effect.ensuring(input.fs.remove(template.captureLock, { recursive: true, force: true }).pipe(Effect.ignore)))
  return template
})

const captureSnapshot = Effect.fn("NvxSandbox.captureSnapshot")(function* (input: {
  readonly fs: FSUtil.Interface
  readonly artifacts: Artifacts
  readonly config: ConfigSandbox.Nvx
  readonly cpuSet: string | undefined
  readonly guestMount: string
  readonly hostMount: string
  readonly hypervisor: "kvm" | "mshv" | "whp"
  readonly memoryMiB: number
  readonly processors: 1 | 2 | 4 | 8
  readonly startupTimeout: number
  readonly uid: number
  readonly gid: number
  readonly template: SnapshotTemplate
}) {
  if (process.platform !== "win32") {
    const endpointDir = path.dirname(input.template.endpoint)
    yield* input.fs.makeDirectory(endpointDir, { recursive: true, mode: 0o700 })
    yield* input.fs.chmod(endpointDir, 0o700)
    yield* input.fs.remove(input.template.endpoint, { force: true }).pipe(Effect.ignore)
  }

  const stateDir = path.join(input.template.root, `capture-${crypto.randomUUID()}`)
  yield* input.fs.makeDirectory(stateDir, { recursive: true, mode: 0o700 })
  if (process.platform !== "win32") yield* input.fs.chmod(stateDir, 0o700)
  const capability = crypto.getRandomValues(new Uint8Array(32))
  const args = coldArguments({
    artifacts: input.artifacts,
    config: input.config,
    endpoint: input.template.endpoint,
    hypervisor: input.hypervisor,
    memoryMiB: input.memoryMiB,
    processors: input.processors,
    uid: input.uid,
    gid: input.gid,
    report: path.join(stateDir, "outcome.json"),
    snapshot: input.template.snapshot,
    mount: { guest: input.guestMount, host: input.hostMount },
  })
  const host = yield* startHost(
    input.cpuSet ? "taskset" : input.artifacts.openvmm,
    input.cpuSet ? ["-c", input.cpuSet, input.artifacts.openvmm, ...args] : args,
    capability,
    path.join(stateDir, "auth.pipe"),
  ).pipe(Effect.tapError(() => input.fs.remove(stateDir, { recursive: true, force: true }).pipe(Effect.ignore)))
  let output = Buffer.alloc(0)
  const appendOutput = (chunk: Uint8Array) => {
    const next = Buffer.concat([output, chunk])
    output = next.length > 64 * 1024 ? next.subarray(next.length - 64 * 1024) : next
  }
  host.stdout.on("data", appendOutput)
  host.stderr.on("data", appendOutput)

  yield* Effect.gen(function* () {
    const trigger = clientCall(async (signal) => {
      const client = await Client.connect(input.template.endpoint, capability, input.startupTimeout, signal)
      try {
        await client.ping(input.startupTimeout, signal)
        await client.exec(["/bin/sh", "-c", "touch /tmp/opencode-snapshot-request"], {
          timeoutMs: 5000,
          responseTimeoutMs: input.startupTimeout,
          signal,
          stdout: () => {},
          stderr: () => {},
        })
      } finally {
        client.close()
      }
    })
    const exited = host.exit.pipe(
      Effect.flatMap((code) =>
        Effect.fail(
          new Error(
            `OpenVMM exited with status ${code} before NVX snapshot capture was triggered${
              output.length ? `\n--- OpenVMM output ---\n${output.toString("utf8")}` : ""
            }`,
          ),
        ),
      ),
    )
    yield* Effect.raceFirst(trigger, exited)
    const code = yield* host.exit.pipe(
      Effect.timeoutOrElse({
        duration: `${SNAPSHOT_TIMEOUT_MS} millis`,
        orElse: () => Effect.fail(new Error(`Timed out capturing NVX snapshot: ${input.template.snapshot}`)),
      }),
    )
    if (code !== 0)
      throw new Error(
        `OpenVMM exited with status ${code} while capturing NVX snapshot${
          output.length ? `\n--- OpenVMM output ---\n${output.toString("utf8")}` : ""
        }`,
      )
  }).pipe(
    Effect.ensuring(terminate(host).pipe(Effect.ignore)),
    Effect.ensuring(input.fs.remove(stateDir, { recursive: true, force: true }).pipe(Effect.ignore)),
  )
})

const resolveArtifacts = Effect.fn("NvxSandbox.resolveArtifacts")(function* (
  fs: FSUtil.Interface,
  directory: string,
  config: ConfigSandbox.Nvx,
) {
  if (process.platform !== "linux" && process.platform !== "win32")
    throw new Error(`NVX is unsupported on ${process.platform}`)
  if (process.arch !== "x64") throw new Error(`NVX currently requires an x64 host, received ${process.arch}`)

  const root = yield* fs.resolve(path.resolve(directory, config.path))
  const executable = process.platform === "win32" ? "openvmm.exe" : "openvmm"
  const layouts = [
    {
      openvmm: path.join(root, "bin", executable),
      kernel: path.join(root, "guest", "vmlinux"),
      initramfs: path.join(root, "guest", "initramfs.cpio.gz"),
    },
    {
      openvmm: path.join(root, "openvmm", "target", "release", executable),
      kernel: path.join(root, "build", "vmlinux"),
      initramfs: path.join(root, "build", "initramfs.cpio.gz"),
    },
  ]
  const configured = {
    openvmm: config.openvmm ? path.resolve(root, config.openvmm) : undefined,
    kernel: config.kernel ? path.resolve(root, config.kernel) : undefined,
    initramfs: config.initramfs ? path.resolve(root, config.initramfs) : undefined,
  }
  for (const layout of layouts) {
    const artifacts: Artifacts = {
      openvmm: configured.openvmm ?? layout.openvmm,
      kernel: configured.kernel ?? layout.kernel,
      initramfs: configured.initramfs ?? layout.initramfs,
    }
    if (
      (yield* fs.isFile(artifacts.openvmm)) &&
      (yield* fs.isFile(artifacts.kernel)) &&
      (yield* fs.isFile(artifacts.initramfs))
    )
      return artifacts
  }
  throw new Error(
    `NVX artifacts were not found under ${root}; expected an extracted release or an NVX checkout after download/build`,
  )
})

const resolveCpuSet = Effect.fn("NvxSandbox.resolveCpuSet")(function* (
  fs: FSUtil.Interface,
  configured: string | false | undefined,
  processors: number,
) {
  if (process.platform !== "linux" || configured === false) return undefined
  const cpus = configured ? parseCpuSet(configured) : yield* physicalCpuRepresentatives(fs)
  const required = processors + 2
  if (cpus.size < required)
    throw new Error(
      `NVX CPU affinity selects ${cpus.size} CPUs; ${processors} vCPUs require at least ${required}. Set sandbox.cpus to false to disable benchmark-style affinity.`,
    )
  return [...cpus].sort((a, b) => a - b).join(",")
})

const physicalCpuRepresentatives = Effect.fn("NvxSandbox.physicalCpuRepresentatives")(function* (fs: FSUtil.Interface) {
  const entries = yield* fs
    .readDirectoryEntries("/sys/devices/system/cpu")
    .pipe(Effect.catch(() => Effect.succeed([] as FSUtil.DirEntry[])))
  const siblingSets = new Set<string>()
  const representatives = new Set<number>()
  for (const entry of entries.filter((entry) => entry.type === "directory" && /^cpu\d+$/.test(entry.name))) {
    const siblings = yield* fs
      .readFileStringSafe(path.join("/sys/devices/system/cpu", entry.name, "topology", "thread_siblings_list"))
      .pipe(Effect.catch(() => Effect.succeed(undefined)))
    if (!siblings) continue
    const cpus = parseCpuSet(siblings.trim())
    const key = [...cpus].sort((a, b) => a - b).join(",")
    if (siblingSets.has(key)) continue
    siblingSets.add(key)
    representatives.add(Math.min(...cpus))
  }
  if (representatives.size) return representatives
  return new Set(os.cpus().map((_, index) => index))
})

function parseCpuSet(input: string) {
  const cpus = new Set<number>()
  for (const part of input.split(",")) {
    const value = part.trim()
    if (!value) throw new Error(`Invalid NVX CPU set: ${input}`)
    const range = value.split("-")
    if (range.length > 2) throw new Error(`Invalid NVX CPU set: ${input}`)
    const start = Number.parseInt(range[0], 10)
    const end = range.length === 2 ? Number.parseInt(range[1], 10) : start
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || start > end)
      throw new Error(`Invalid NVX CPU set: ${input}`)
    for (let cpu = start; cpu <= end; cpu++) cpus.add(cpu)
  }
  return cpus
}

function resolveHypervisor(configured: "auto" | "kvm" | "mshv" | "whp") {
  const hypervisor = configured === "auto" ? (process.platform === "win32" ? "whp" : "kvm") : configured
  if (process.platform === "win32" && hypervisor !== "whp")
    throw new Error(`NVX hypervisor ${hypervisor} is unsupported on Windows`)
  if (process.platform === "linux" && hypervisor === "whp")
    throw new Error("NVX hypervisor whp is unsupported on Linux")
  if (process.platform !== "linux" && process.platform !== "win32")
    throw new Error(`NVX is unsupported on ${process.platform}`)
  return hypervisor
}

function defaultIdentity(kind: "uid" | "gid") {
  if (process.platform === "win32") return 65534
  const value = kind === "uid" ? process.getuid?.() : process.getgid?.()
  if (!value) throw new Error(`NVX requires a non-root ${kind}; configure sandbox.${kind} explicitly`)
  return value
}

function controlEndpoint(root: string, id: string) {
  if (process.platform === "win32") return `//./pipe/openvmm-microvm-${id.replaceAll("-", "")}`
  return path.join(root, "control.sock")
}

function clientCall<A>(fn: (signal: AbortSignal) => Promise<A>) {
  return Effect.tryPromise({
    try: fn,
    catch: (cause) => cause,
  })
}

function startHost(command: string, args: readonly string[], capability: Uint8Array, authPipe: string) {
  return Effect.tryPromise({
    try: () =>
      process.platform === "linux"
        ? startLinuxHost(command, args, capability, authPipe)
        : startWindowsHost(command, args, capability),
    catch: (cause) => (cause instanceof Error ? cause : new Error(String(cause))),
  })
}

async function startLinuxHost(command: string, args: readonly string[], capability: Uint8Array, authPipe: string) {
  const fifo = spawn("mkfifo", [authPipe], { stdio: "ignore", windowsHide: true })
  const code = await new Promise<number>((resolve, reject) => {
    fifo.once("error", reject)
    fifo.once("exit", (status) => resolve(status ?? 1))
  })
  if (code !== 0) throw new Error(`mkfifo exited with status ${code}`)
  const keeper = await fsNode.open(authPipe, constants.O_RDWR | constants.O_NONBLOCK)
  try {
    const reader = await fsNode.open(authPipe, constants.O_RDONLY)
    try {
      const writer = await fsNode.open(authPipe, constants.O_WRONLY)
      try {
        await keeper.close()
        const written = await writer.write(capability)
        if (written.bytesWritten !== capability.length)
          throw new Error(`Short write to NVX authentication pipe: ${written.bytesWritten}/${capability.length}`)
      } finally {
        await writer.close()
      }
      return hostProcess(
        spawn(command, args, {
          stdio: [reader.fd, "pipe", "pipe"],
          detached: true,
          windowsHide: true,
          env: hostEnvironment(),
        }),
      )
    } finally {
      await reader.close()
    }
  } finally {
    await keeper.close().catch(() => {})
  }
}

async function startWindowsHost(command: string, args: readonly string[], capability: Uint8Array) {
  const host = hostProcess(
    spawn(command, args, {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      env: hostEnvironment(),
    }),
  )
  if (!host.child.stdin) throw new Error("OpenVMM authentication stdin is unavailable")
  host.child.stdin.end(capability)
  return host
}

function hostProcess(child: ReturnType<typeof spawn>): HostProcess {
  if (!child.stdout || !child.stderr) throw new Error("OpenVMM output pipes are unavailable")
  const exitPromise = new Promise<number>((resolve, reject) => {
    child.once("error", reject)
    child.once("exit", (code) => resolve(code ?? 1))
  })
  return {
    child,
    stdout: child.stdout,
    stderr: child.stderr,
    exitPromise,
    exit: Effect.tryPromise({
      try: () => exitPromise,
      catch: (cause) => (cause instanceof Error ? cause : new Error(String(cause))),
    }),
  }
}

function hostEnvironment() {
  return Object.fromEntries(
    Object.entries({
      ...process.env,
      OPENVMM_LOG: "off",
      OPENVMM_STARTUP_PROFILE: undefined,
    }).filter((entry): entry is [string, string] => entry[1] !== undefined),
  )
}

const terminate = Effect.fn("NvxSandbox.terminateHost")(function* (host: HostProcess) {
  if (!isRunning(host)) return
  yield* Effect.sync(() => host.child.kill("SIGTERM"))
  const stopped = yield* host.exit.pipe(
    Effect.as(true),
    Effect.timeoutOrElse({ duration: "3 seconds", orElse: () => Effect.succeed(false) }),
    Effect.catch(() => Effect.succeed(true)),
  )
  if (stopped || !isRunning(host)) return
  yield* Effect.sync(() => host.child.kill("SIGKILL"))
  yield* host.exit.pipe(Effect.timeoutOrElse({ duration: "3 seconds", orElse: () => Effect.void }), Effect.ignore)
})

function isRunning(host: HostProcess) {
  return host.child.exitCode === null && host.child.signalCode === null
}

function spawnError(method: string, description?: string, cause?: unknown) {
  return systemError({ _tag: "Unknown", module: "NvxSandbox", method, description, cause })
}
