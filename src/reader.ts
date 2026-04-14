/**
 * Auditpipe reader — reads BSM binary records directly from /dev/auditpipe.
 *
 * Replaces the praudit spawn + XML parsing pipeline with direct binary reading.
 */

import { extractRecords } from "./bsm-parser.ts";
import type { AuditEvent } from "./schema.ts";

const DEFAULT_AUDITPIPE = "/dev/auditpipe";
const MAX_BUFFER = 1_048_576; // 1 MB

export interface ReaderOptions {
  auditpipePath?: string;
  onEvent: (event: AuditEvent) => Promise<void>;
  onError?: (error: string) => void;
}

export class AuditPipeReader {
  private running = false;
  private readonly opts: Required<ReaderOptions>;

  constructor(opts: ReaderOptions) {
    this.opts = {
      auditpipePath: opts.auditpipePath ?? DEFAULT_AUDITPIPE,
      onEvent: opts.onEvent,
      onError: opts.onError ?? ((msg) => console.error(`[bsmtap] ${msg}`)),
    };
  }

  async start(): Promise<void> {
    this.running = true;
    console.error(`[bsmtap] Opening ${this.opts.auditpipePath}`);

    const file = Bun.file(this.opts.auditpipePath);
    const stream = file.stream();
    const reader = stream.getReader();
    let buffer = new Uint8Array(0) as Uint8Array<ArrayBufferLike>;

    try {
      for (;;) {
        if (!this.running) break;

        const { done, value } = await reader.read();
        if (done) break;

        // Append new data to buffer
        buffer = concat(buffer, value);

        // Extract and process complete records
        const { events, consumed } = extractRecords(buffer);
        buffer = buffer.slice(consumed);

        for (const event of events) {
          try {
            await this.opts.onEvent(event);
          } catch (err) {
            this.opts.onError(`Failed to write event: ${err}`);
          }
        }

        // Safety cap on buffer growth
        if (buffer.byteLength > MAX_BUFFER) {
          this.opts.onError(`Buffer exceeded ${MAX_BUFFER} bytes, discarding`);
          buffer = new Uint8Array(0);
        }
      }
    } catch (err) {
      if (this.running) {
        this.opts.onError(`Read error: ${err}`);
      }
    } finally {
      reader.releaseLock();
    }
  }

  stop(): void {
    this.running = false;
  }
}

function concat(a: Uint8Array<ArrayBufferLike>, b: Uint8Array<ArrayBufferLike>): Uint8Array {
  if (a.byteLength === 0) return new Uint8Array(b);
  const result = new Uint8Array(a.byteLength + b.byteLength);
  result.set(a);
  result.set(b, a.byteLength);
  return result;
}
