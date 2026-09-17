import { createHash } from "node:crypto"
import fsNode from "node:fs/promises"
import { gunzipSync, gzipSync } from "node:zlib"
import { Effect } from "effect"
import type { FSUtil } from "../fs-util"

const HEADER_BYTES = 110
const REGULAR_FILE_MODE = 0o100644
const SNAPSHOT_INIT_VERSION = 2

export const prepare = Effect.fn("NvxSandbox.prepareInitramfs")(function* (input: {
  readonly fs: FSUtil.Interface
  readonly source: string
  readonly cache: string
  readonly uid: number
  readonly gid: number
  readonly snapshot?: boolean
}) {
  const variant = input.snapshot ? `snapshot-${SNAPSHOT_INIT_VERSION}` : "cold"
  const source = yield* Effect.tryPromise({
    try: () => fsNode.stat(input.source, { bigint: true }),
    catch: (cause) => (cause instanceof Error ? cause : new Error(String(cause))),
  })
  const key = createHash("sha256")
    .update(
      JSON.stringify({
        source: input.source,
        size: source.size.toString(),
        mtime: source.mtimeNs.toString(),
        uid: input.uid,
        gid: input.gid,
        variant,
      }),
    )
    .digest("hex")
  const target = `${input.cache}/${key}.cpio.gz`
  if (yield* input.fs.existsSafe(target)) return target

  const compressed = Buffer.from(yield* input.fs.readFile(input.source))
  const output = addIdentity(compressed, input.uid, input.gid, input.snapshot)
  const temporary = `${target}.${crypto.randomUUID()}.tmp`
  yield* input.fs.makeDirectory(input.cache, { recursive: true })
  yield* input.fs.writeFile(temporary, output)
  yield* input.fs.rename(temporary, target).pipe(
    Effect.catchIf(
      (error) => error.reason._tag === "AlreadyExists",
      () => input.fs.remove(temporary, { force: true }),
    ),
    Effect.ensuring(input.fs.remove(temporary, { force: true }).pipe(Effect.ignore)),
  )
  return target
})

export function addIdentity(compressed: Uint8Array, uid: number, gid: number, snapshot = false) {
  const archive = gunzipSync(compressed)
  const files = readFiles(archive)
  const passwd = files.get("etc/passwd")
  const group = files.get("etc/group")
  if (!passwd || !group) throw new Error("NVX initramfs does not contain etc/passwd and etc/group")

  const users = lines(passwd.toString("utf8"))
  const matches = users.filter((line) => Number.parseInt(line.split(":")[2] ?? "", 10) === uid)
  if (matches.length > 1) throw new Error(`NVX initramfs contains multiple users with UID ${uid}`)
  if (matches.length === 1) {
    const fields = matches[0].split(":")
    if (Number.parseInt(fields[3] ?? "", 10) !== gid)
      throw new Error(`NVX initramfs user with UID ${uid} does not use GID ${gid}`)
    fields[5] = "/tmp"
    fields[6] = "/bin/sh"
    users[users.indexOf(matches[0])] = fields.join(":")
  } else {
    const names = new Set(users.map((line) => line.split(":")[0]))
    const base = `opencode${uid}`
    const name = names.has(base) ? `${base}-${crypto.randomUUID().slice(0, 8)}` : base
    users.push(`${name}:x:${uid}:${gid}:OpenCode NVX:/tmp:/bin/sh`)
  }

  const groups = lines(group.toString("utf8"))
  if (!groups.some((line) => Number.parseInt(line.split(":")[2] ?? "", 10) === gid)) {
    const names = new Set(groups.map((line) => line.split(":")[0]))
    const base = `opencode${gid}`
    const name = names.has(base) ? `${base}-${crypto.randomUUID().slice(0, 8)}` : base
    groups.push(`${name}:x:${gid}:`)
  }

  const entries: Array<readonly [string, Buffer, number?]> = [
    ["etc/passwd", Buffer.from(users.join("\n") + "\n")],
    ["etc/group", Buffer.from(groups.join("\n") + "\n")],
  ]
  if (snapshot) {
    const init = files.get("init")
    if (!init) throw new Error("NVX initramfs does not contain init")
    entries.push(["init", snapshotInit(init), 0o100755])
  }

  return gzipSync(Buffer.concat([archive, newc(entries)]), { level: 9 })
}

function readFiles(archive: Uint8Array) {
  const files = new Map<string, Buffer>()
  let offset = 0
  while (offset + 6 <= archive.length) {
    while (offset < archive.length && archive[offset] === 0) offset++
    if (offset + HEADER_BYTES > archive.length) break

    const header = Buffer.from(archive.subarray(offset, offset + HEADER_BYTES))
    if (header.toString("ascii", 0, 6) !== "070701" && header.toString("ascii", 0, 6) !== "070702")
      throw new Error(`NVX initramfs contains unsupported cpio data at byte ${offset}`)
    const size = field(header, 6 + 6 * 8)
    const nameSize = field(header, 6 + 11 * 8)
    offset += HEADER_BYTES
    if (nameSize < 1 || offset + nameSize > archive.length) throw new Error("NVX initramfs cpio name is truncated")

    const name = Buffer.from(archive.subarray(offset, offset + nameSize - 1))
      .toString("utf8")
      .replace(/^\.\//, "")
    offset = align(offset + nameSize)
    if (offset + size > archive.length) throw new Error(`NVX initramfs cpio entry is truncated: ${name}`)
    if (name !== "TRAILER!!!") files.set(name, Buffer.from(archive.subarray(offset, offset + size)))
    offset = align(offset + size)
  }
  return files
}

function newc(entries: ReadonlyArray<readonly [string, Buffer, number?]>) {
  const output = Buffer.concat([
    ...entries.map(([name, content, mode], index) => entry(name, content, index + 1, mode)),
    entry("TRAILER!!!", Buffer.alloc(0), entries.length + 1),
  ])
  return Buffer.concat([output, Buffer.alloc((512 - (output.length % 512)) % 512)])
}

function entry(name: string, content: Buffer, inode: number, mode = REGULAR_FILE_MODE) {
  const filename = Buffer.from(name + "\0")
  const values = [inode, mode, 0, 0, 1, 0, content.length, 0, 0, 0, 0, filename.length, 0]
  const header = Buffer.from("070701" + values.map((value) => value.toString(16).padStart(8, "0")).join(""))
  const namePadding = Buffer.alloc((4 - ((header.length + filename.length) % 4)) % 4)
  const dataPadding = Buffer.alloc((4 - (content.length % 4)) % 4)
  return Buffer.concat([header, filename, namePadding, content, dataPadding])
}

function field(header: Buffer, offset: number) {
  return Number.parseInt(header.toString("ascii", offset, offset + 8), 16)
}

function align(value: number) {
  return (value + 3) & ~3
}

function lines(input: string) {
  return input
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter(Boolean)
}

function snapshotInit(content: Buffer) {
  const source = content.toString("utf8")
  const original = `if [ "$sandbox_mode" = false ]; then
    mount_virtfs
fi
`
  if (!source.includes(original)) throw new Error("NVX initramfs init does not contain the expected host-mount hook")
  return Buffer.from(
    source.replace(
      original,
      `if [ "$sandbox_mode" = false ]; then
    case "$cmdline" in
        *" opencode_snapshot=1 "*)
            mount_virtfs
            (
                while [ ! -e /tmp/opencode-snapshot-request ]; do
                    sleep 0.01
                done
                sleep 0.1
                /sbin/nvx-snapshot
                rm -f /tmp/opencode-snapshot-request
                : >/tmp/opencode-snapshot-ready
                printf 'OPENCODE-NVX-SNAPSHOT-READY\\n' >/dev/hvc0
            ) &
            ;;
        *) mount_virtfs ;;
    esac
fi
`,
    ),
  )
}
