/**
 * Auditpipe reader — reads BSM binary records directly from /dev/auditpipe.
 *
 * Uses fs.openSync + fs.readSync instead of Bun.file().stream() because
 * Bun's file stream API doesn't work correctly with character devices
 * like /dev/auditpipe (it blocks forever on the first read).
 */

import { closeSync, openSync, readSync } from "node:fs";
import { extractRecords } from "./bsm-parser.ts";
import type { AuditEvent } from "./schema.ts";

const DEFAULT_AUDITPIPE = "/dev/auditpipe";
const READ_BUFFER_SIZE = 65_536; // 64 KB per read
const MAX_BUFFER = 1_048_576; // 1 MB accumulated

export interface ReaderOptions {
  auditpipePath?: string;
  onEvent: (event: AuditEvent) => Promise<void>;
  onError?: (error: string) => void;
}

export class AuditPipeReader {
  private running = false;
  private fd: number | null = null;
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

    this.fd = openSync(this.opts.auditpipePath, "r");
    const readBuf = Buffer.alloc(READ_BUFFER_SIZE);
    let buffer = new Uint8Array(0) as Uint8Array<ArrayBufferLike>;

    try {
      while (this.running) {
        // readSync blocks until auditpipe has data — this is expected
        // for character devices. It returns when audit events arrive.
        const bytesRead = readSync(this.fd, readBuf);
        if (bytesRead === 0) {
          // EOF — device closed (shouldn't happen for auditpipe)
          break;
        }

        // Append new data to buffer
        buffer = concat(buffer, readBuf.subarray(0, bytesRead));

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
      if (this.fd !== null) {
        try {
          closeSync(this.fd);
        } catch {
          // fd may already be closed
        }
        this.fd = null;
      }
    }
  }

  stop(): void {
    this.running = false;
    // Close the fd to unblock the readSync call
    if (this.fd !== null) {
      try {
        closeSync(this.fd);
      } catch {
        // fd may already be closed
      }
      this.fd = null;
    }
  }
}

function concat(a: Uint8Array<ArrayBufferLike>, b: Uint8Array<ArrayBufferLike>): Uint8Array {
  if (a.byteLength === 0) return new Uint8Array(b);
  const result = new Uint8Array(a.byteLength + b.byteLength);
  result.set(a);
  result.set(b, a.byteLength);
  return result;
}
