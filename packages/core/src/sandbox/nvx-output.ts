export class CompletionMarkerFilter {
  private pending = Buffer.alloc(0)

  constructor(private readonly marker: Buffer) {
    if (!marker.length) throw new Error("NVX completion marker cannot be empty")
  }

  write(chunk: Uint8Array) {
    const output: Uint8Array[] = []
    const data = Buffer.concat([this.pending, chunk])
    let offset = 0
    while (true) {
      const index = data.indexOf(this.marker, offset)
      if (index < 0) break
      if (index > offset) output.push(data.subarray(offset, index))
      offset = index + this.marker.length
    }

    const remaining = data.subarray(offset)
    const keep = Math.min(this.marker.length - 1, remaining.length)
    const ready = remaining.length - keep
    if (ready > 0) output.push(remaining.subarray(0, ready))
    this.pending = remaining.subarray(ready)
    return output
  }

  finish() {
    const output = this.pending.length ? [this.pending] : []
    this.pending = Buffer.alloc(0)
    return output
  }
}
