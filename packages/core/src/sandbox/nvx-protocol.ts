import { randomBytes } from "node:crypto"
import { createConnection, type Socket } from "node:net"

const OUTER_HEADER_BYTES = 44
const OUTER_MAX_PAYLOAD = 65_536
const OUTER_HOST_ATTACH = 2
const OUTER_RESET = 3
const OUTER_DATA = 5
const OUTER_WAIT = 6
const OUTER_READY = 7
const OUTER_ERROR = 8

const APP_HEADER_BYTES = 24
const APP_MAX_ARGUMENTS = 64
const APP_MAX_ARGUMENT_BYTES = 4096
const APP_PING = 1
const APP_EXEC = 2
const APP_STOP = 3
const APP_READY = 0x81
const APP_STDOUT = 0x82
const APP_STDERR = 0x83
const APP_EXIT = 0x84
const APP_STOPPED = 0x85
const APP_ERROR = 0xff

export type ExitCategory = "exit" | "timeout" | "output-limit" | "signal" | "failed"

export interface ExecResult {
  readonly exitCode: number
  readonly category: ExitCategory
}

interface OuterRecord {
  readonly type: number
  readonly instanceID: Buffer
  readonly epoch: bigint
  readonly sequence: bigint
  readonly payload: Buffer
}

class SocketStream {
  private readonly iterator: AsyncIterator<Uint8Array>
  private buffer: Buffer = Buffer.alloc(0)

  constructor(private readonly socket: Socket) {
    this.iterator = socket[Symbol.asyncIterator]()
  }

  async readExact(length: number, deadline: number, signal?: AbortSignal) {
    while (this.buffer.length < length) {
      const next = await within(this.iterator.next(), deadline, signal, "NVX control response timed out")
      if (next.done) throw new Error("NVX control endpoint closed")
      this.buffer = Buffer.concat([this.buffer, Buffer.from(next.value)])
    }
    const output = this.buffer.subarray(0, length)
    this.buffer = this.buffer.subarray(length)
    return output
  }

  async write(data: Uint8Array, deadline: number, signal?: AbortSignal) {
    await within(
      new Promise<void>((resolve, reject) => {
        this.socket.write(data, (error) => {
          if (error) reject(error)
          else resolve()
        })
      }),
      deadline,
      signal,
      "NVX control request timed out",
    )
  }

  close() {
    this.socket.destroy()
  }
}

export class Client {
  private instanceID: Buffer = Buffer.alloc(16)
  private epoch = 0n
  private sendSequence = 0n
  private receiveSequence = 0n

  private constructor(private readonly stream: SocketStream) {}

  static async connect(endpoint: string, capability: Uint8Array, timeoutMs: number, signal?: AbortSignal) {
    if (capability.length !== 32 || capability.every((byte) => byte === 0))
      throw new Error("NVX control capability must be 32 nonzero bytes")

    const deadline = Date.now() + timeoutMs
    let last: unknown
    while (Date.now() < deadline) {
      const stream = new SocketStream(await connect(endpoint, deadline, signal))
      const client = new Client(stream)
      try {
        await client.writeOuter(OUTER_HOST_ATTACH, Buffer.alloc(16), 0n, 0n, Buffer.from(capability), deadline, signal)
        while (true) {
          const record = await client.readOuter(deadline, signal)
          if (record.payload.length) throw new Error("NVX control attach response carried an invalid payload")
          if (record.type === OUTER_WAIT) continue
          if (record.type === OUTER_ERROR) throw new Error("NVX control capability authentication failed")
          if (record.type !== OUTER_READY || record.instanceID.equals(Buffer.alloc(16)) || record.epoch === 0n)
            throw new Error("NVX control endpoint returned an invalid attach response")
          client.instanceID = record.instanceID
          client.epoch = record.epoch
          client.receiveSequence = record.sequence + 1n
          return client
        }
      } catch (error) {
        stream.close()
        if (signal?.aborted || String(error).includes("capability authentication failed")) throw error
        last = error
        if (Date.now() >= deadline) break
        await sleep(25, deadline, signal)
      }
    }
    throw new Error(`NVX control session did not become ready: ${endpoint}`, { cause: last })
  }

  async ping(timeoutMs: number, signal?: AbortSignal) {
    const requestID = nextRequestID()
    const deadline = Date.now() + timeoutMs
    await this.sendApp(APP_PING, requestID, Buffer.alloc(0), deadline, signal)
    const response = await this.readApp(deadline, signal)
    if (
      response.kind !== APP_READY ||
      response.requestID !== requestID ||
      response.status !== 0 ||
      response.payload.length
    )
      throw new Error("NVX guest did not acknowledge readiness")
  }

  async exec(
    args: readonly string[],
    input: {
      readonly timeoutMs: number
      readonly responseTimeoutMs: number
      readonly signal?: AbortSignal
      readonly stdout: (chunk: Uint8Array) => void | Promise<void>
      readonly stderr: (chunk: Uint8Array) => void | Promise<void>
    },
  ): Promise<ExecResult> {
    if (args.length < 1 || args.length > APP_MAX_ARGUMENTS)
      throw new Error("NVX exec requires between 1 and 64 arguments")
    if (!args[0]?.startsWith("/")) throw new Error("NVX exec entrypoint must be absolute")
    if (input.timeoutMs < 0 || input.timeoutMs > 3_600_000)
      throw new Error("NVX exec timeout must be between 0 and 3600000 milliseconds")

    const encoded = args.map((arg) => {
      const value = Buffer.from(arg)
      if (!value.length || value.length > APP_MAX_ARGUMENT_BYTES || value.includes(0))
        throw new Error("NVX exec argument is empty, contains NUL, or exceeds 4096 bytes")
      const item = Buffer.alloc(4 + value.length)
      item.writeUInt32LE(value.length)
      value.copy(item, 4)
      return item
    })
    const payload = Buffer.alloc(8 + encoded.reduce((total, item) => total + item.length, 0))
    payload.writeUInt32LE(input.timeoutMs)
    payload.writeUInt16LE(args.length, 4)
    encoded.reduce((offset, item) => {
      item.copy(payload, offset)
      return offset + item.length
    }, 8)
    if (payload.length + APP_HEADER_BYTES > OUTER_MAX_PAYLOAD)
      throw new Error("NVX exec request exceeds the control protocol limit")

    const request = nextRequestID()
    const deadline = Date.now() + input.responseTimeoutMs
    await this.sendApp(APP_EXEC, request, payload, deadline, input.signal)
    while (true) {
      const response = await this.readApp(deadline, input.signal)
      if (response.requestID !== request) throw new Error("NVX guest returned a mismatched request ID")
      if (response.kind === APP_STDOUT) {
        await input.stdout(response.payload)
        continue
      }
      if (response.kind === APP_STDERR) {
        await input.stderr(response.payload)
        continue
      }
      if (response.kind === APP_ERROR)
        throw new Error(
          `NVX guest rejected exec (status=${response.status}, category=${response.payload.toString("ascii")})`,
        )
      if (response.kind !== APP_EXIT) throw new Error("NVX guest returned an invalid exec response")
      const category = response.payload.toString("ascii")
      if (!isExitCategory(category)) throw new Error(`NVX guest returned unsupported exit category: ${category}`)
      return { exitCode: response.status, category }
    }
  }

  async stop(timeoutMs: number, signal?: AbortSignal) {
    const requestID = nextRequestID()
    const deadline = Date.now() + timeoutMs
    await this.sendApp(APP_STOP, requestID, Buffer.alloc(0), deadline, signal)
    const response = await this.readApp(deadline, signal)
    if (
      response.kind !== APP_STOPPED ||
      response.requestID !== requestID ||
      response.status !== 0 ||
      response.payload.length
    )
      throw new Error("NVX guest did not acknowledge stop")
  }

  close() {
    this.stream.close()
  }

  private async sendApp(kind: number, requestID: bigint, payload: Buffer, deadline: number, signal?: AbortSignal) {
    const frame = Buffer.alloc(APP_HEADER_BYTES + payload.length)
    frame.write("NVXC")
    frame.writeUInt8(1, 4)
    frame.writeUInt8(kind, 5)
    frame.writeBigUInt64LE(requestID, 8)
    frame.writeUInt32LE(payload.length, 20)
    payload.copy(frame, APP_HEADER_BYTES)
    await this.writeOuter(OUTER_DATA, this.instanceID, this.epoch, this.sendSequence, frame, deadline, signal)
    this.sendSequence += 1n
  }

  private async readApp(deadline: number, signal?: AbortSignal) {
    const record = await this.readOuter(deadline, signal)
    if (record.type === OUTER_RESET) throw new Error("NVX control session was reset")
    if (
      record.type !== OUTER_DATA ||
      !record.instanceID.equals(this.instanceID) ||
      record.epoch !== this.epoch ||
      record.sequence !== this.receiveSequence ||
      record.payload.length < APP_HEADER_BYTES
    )
      throw new Error("NVX control endpoint returned an invalid data record")
    this.receiveSequence += 1n

    const header = record.payload.subarray(0, APP_HEADER_BYTES)
    const payload = record.payload.subarray(APP_HEADER_BYTES)
    if (
      header.toString("ascii", 0, 4) !== "NVXC" ||
      header.readUInt8(4) !== 1 ||
      header.readUInt16LE(6) !== 0 ||
      header.readUInt32LE(20) !== payload.length
    )
      throw new Error("NVX control endpoint returned an invalid application frame")
    return {
      kind: header.readUInt8(5),
      requestID: header.readBigUInt64LE(8),
      status: header.readInt32LE(16),
      payload,
    }
  }

  private async writeOuter(
    type: number,
    instanceID: Buffer,
    epoch: bigint,
    sequence: bigint,
    payload: Buffer,
    deadline: number,
    signal?: AbortSignal,
  ) {
    if (payload.length > OUTER_MAX_PAYLOAD) throw new Error("NVX control payload exceeds the protocol limit")
    const record = Buffer.alloc(OUTER_HEADER_BYTES + payload.length)
    record.write("NVXS")
    record.writeUInt16LE(1, 4)
    record.writeUInt8(type, 6)
    instanceID.copy(record, 8)
    record.writeBigUInt64LE(epoch, 24)
    record.writeBigUInt64LE(sequence, 32)
    record.writeUInt32LE(payload.length, 40)
    payload.copy(record, OUTER_HEADER_BYTES)
    await this.stream.write(record, deadline, signal)
  }

  private async readOuter(deadline: number, signal?: AbortSignal): Promise<OuterRecord> {
    const header = await this.stream.readExact(OUTER_HEADER_BYTES, deadline, signal)
    const length = header.readUInt32LE(40)
    if (
      header.toString("ascii", 0, 4) !== "NVXS" ||
      header.readUInt16LE(4) !== 1 ||
      header.readUInt8(7) !== 0 ||
      length > OUTER_MAX_PAYLOAD
    )
      throw new Error("NVX control endpoint returned an invalid outer record")
    return {
      type: header.readUInt8(6),
      instanceID: Buffer.from(header.subarray(8, 24)),
      epoch: header.readBigUInt64LE(24),
      sequence: header.readBigUInt64LE(32),
      payload: length ? await this.stream.readExact(length, deadline, signal) : Buffer.alloc(0),
    }
  }
}

async function connect(endpoint: string, deadline: number, signal?: AbortSignal) {
  const target = endpoint.startsWith("//./pipe/") ? `\\\\.\\pipe\\${endpoint.slice("//./pipe/".length)}` : endpoint
  let last: unknown
  while (Date.now() < deadline) {
    try {
      return await connectOnce(target, Math.min(deadline, Date.now() + 250), signal)
    } catch (error) {
      last = error
      if (Date.now() >= deadline) break
      await sleep(25, deadline, signal)
    }
  }
  throw new Error(`NVX control endpoint did not become available: ${endpoint}`, { cause: last })
}

function connectOnce(endpoint: string, deadline: number, signal?: AbortSignal) {
  return new Promise<Socket>((resolve, reject) => {
    if (signal?.aborted) return reject(abortError(signal))
    const socket = createConnection(endpoint)
    const timer = setTimeout(
      () => fail(new Error(`NVX control endpoint did not become available: ${endpoint}`)),
      Math.max(1, deadline - Date.now()),
    )
    const cleanup = () => {
      clearTimeout(timer)
      signal?.removeEventListener("abort", onabort)
      socket.off("connect", onconnect)
      socket.off("error", onerror)
    }
    const fail = (error: Error) => {
      cleanup()
      socket.destroy()
      reject(error)
    }
    const onconnect = () => {
      cleanup()
      socket.setNoDelay(true)
      resolve(socket)
    }
    const onerror = (error: Error) => fail(error)
    const onabort = () => fail(abortError(signal!))
    signal?.addEventListener("abort", onabort, { once: true })
    socket.once("connect", onconnect)
    socket.once("error", onerror)
  })
}

function within<T>(promise: Promise<T>, deadline: number, signal: AbortSignal | undefined, message: string) {
  return new Promise<T>((resolve, reject) => {
    if (signal?.aborted) return reject(abortError(signal))
    const remaining = deadline - Date.now()
    if (remaining <= 0) return reject(new Error(message))

    const timer = setTimeout(() => {
      cleanup()
      reject(new Error(message))
    }, remaining)
    const onabort = () => {
      cleanup()
      reject(abortError(signal!))
    }
    const cleanup = () => {
      clearTimeout(timer)
      signal?.removeEventListener("abort", onabort)
    }
    signal?.addEventListener("abort", onabort, { once: true })
    promise.then(
      (value) => {
        cleanup()
        resolve(value)
      },
      (error) => {
        cleanup()
        reject(error)
      },
    )
  })
}

function sleep(duration: number, deadline: number, signal?: AbortSignal) {
  return within(
    new Promise<void>((resolve) => setTimeout(resolve, Math.min(duration, Math.max(0, deadline - Date.now())))),
    deadline,
    signal,
    "NVX control endpoint did not become available",
  )
}

function nextRequestID() {
  const value = randomBytes(8).readBigUInt64LE()
  return value === 0n ? 1n : value
}

function abortError(signal: AbortSignal) {
  if (signal.reason instanceof Error) return signal.reason
  const error = new Error("Aborted")
  error.name = "AbortError"
  return error
}

function isExitCategory(input: string): input is ExitCategory {
  return input === "exit" || input === "timeout" || input === "output-limit" || input === "signal" || input === "failed"
}
