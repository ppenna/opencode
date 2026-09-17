export * as ConfigSandbox from "./sandbox"

import { Schema } from "effect"
import { PositiveInt } from "../schema"

const Identity = Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 0xffff_ffff }))

export class Network extends Schema.Class<Network>("ConfigV2.Sandbox.Network")({
  address: Schema.String,
  egress: Schema.Literals(["allow", "deny"]).pipe(Schema.optional),
  allow: Schema.String.pipe(Schema.Array, Schema.optional),
  deny: Schema.String.pipe(Schema.Array, Schema.optional),
  host_loopback: Schema.Literals(["allow", "deny"]).pipe(Schema.optional),
  proxy: Schema.String.pipe(Schema.optional),
  forward: Schema.String.pipe(Schema.Array, Schema.optional),
}) {}

export class Nvx extends Schema.Class<Nvx>("ConfigV2.Sandbox.Nvx")({
  backend: Schema.Literal("nvx"),
  path: Schema.String,
  openvmm: Schema.String.pipe(Schema.optional),
  kernel: Schema.String.pipe(Schema.optional),
  initramfs: Schema.String.pipe(Schema.optional),
  mount: Schema.String.pipe(Schema.optional),
  shell: Schema.String.pipe(Schema.optional),
  memory_mib: PositiveInt.pipe(Schema.optional),
  processors: Schema.Union([Schema.Literal(1), Schema.Literal(2), Schema.Literal(4), Schema.Literal(8)]).pipe(
    Schema.optional,
  ),
  hypervisor: Schema.Literals(["auto", "kvm", "mshv", "whp"]).pipe(Schema.optional),
  cpus: Schema.Union([Schema.String, Schema.Literal(false)]).pipe(Schema.optional),
  performance_tuning: Schema.Boolean.pipe(Schema.optional),
  snapshot: Schema.Boolean.pipe(Schema.optional),
  startup_timeout: PositiveInt.pipe(Schema.optional),
  uid: Identity.pipe(Schema.optional),
  gid: Identity.pipe(Schema.optional),
  pass_env: Schema.String.pipe(Schema.Array, Schema.optional),
  environment: Schema.Record(Schema.String, Schema.String).pipe(Schema.optional),
  network: Network.pipe(Schema.optional),
}) {}

export const Info = Schema.Union([Schema.Literal(false), Nvx])
export type Info = typeof Info.Type
