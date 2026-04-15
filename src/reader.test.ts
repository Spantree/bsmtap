import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditPipeReader } from "./reader.ts";
import type { AuditEvent } from "./schema.ts";

/** Helper: build a big-endian buffer from a sequence of typed values. */
function bsm(...parts: (number | [string, number])[]): Uint8Array {
  let size = 0;
  for (const part of parts) {
    if (typeof part === "number") size += 1;
    else {
      const [type] = part;
      if (type === "u16") size += 2;
      else if (type === "u32") size += 4;
      else if (type === "u64") size += 8;
    }
  }
  const buf = new ArrayBuffer(size);
  const view = new DataView(buf);
  let off = 0;
  for (const part of parts) {
    if (typeof part === "number") {
      view.setUint8(off, part);
      off += 1;
    } else {
      const [type, val] = part;
      if (type === "u16") {
        view.setUint16(off, val, false);
        off += 2;
      } else if (type === "u32") {
        view.setUint32(off, val, false);
        off += 4;
      } else if (type === "u64") {
        view.setBigUint64(off, BigInt(val), false);
        off += 8;
      }
    }
  }
  return new Uint8Array(buf);
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.byteLength, 0);
  const result = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    result.set(a, off);
    off += a.byteLength;
  }
  return result;
}

/** Build a minimal BSM record (header32 + return32 + trailer). */
function buildRecord(eventType: number, errno = 0, retval = 0): Uint8Array {
  // Header32: 18 bytes, Return32: 6 bytes, Trailer: 7 bytes = 31
  const totalSize = 31;
  const header = bsm(
    0x14,
    ["u32", totalSize],
    11,
    ["u16", eventType],
    ["u16", 0],
    ["u32", 1776000000],
    ["u32", 123000],
  );
  const ret = bsm(0x27, errno, ["u32", retval]);
  const trailer = bsm(0x13, ["u16", 0xb105], ["u32", totalSize]);
  return concat(header, ret, trailer);
}

/** Write binary data to a temp file and return its path. */
function writeTempFile(data: Uint8Array): { path: string; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "reader-test-"));
  const path = join(dir, "auditpipe");
  writeFileSync(path, data);
  return { path, dir };
}

describe("AuditPipeReader", () => {
  const dirs: string[] = [];

  function cleanup() {
    for (const dir of dirs) {
      rmSync(dir, { recursive: true, force: true });
    }
    dirs.length = 0;
  }

  test("reads and parses a single record from a file", async () => {
    const record = buildRecord(180); // execve(2)
    const { path, dir } = writeTempFile(record);
    dirs.push(dir);

    const events: AuditEvent[] = [];
    const reader = new AuditPipeReader({
      auditpipePath: path,
      onEvent: async (event) => {
        events.push(event);
      },
    });

    await reader.start();
    cleanup();

    expect(events).toHaveLength(1);
    expect(events[0]?.event).toBe("execve(2)");
    expect(events[0]?.return?.errval).toBe("success");
  });

  test("reads multiple records from a file", async () => {
    const r1 = buildRecord(180); // execve(2)
    const r2 = buildRecord(43001); // user authentication
    const r3 = buildRecord(3); // open(2)
    const data = concat(r1, r2, r3);
    const { path, dir } = writeTempFile(data);
    dirs.push(dir);

    const events: AuditEvent[] = [];
    const reader = new AuditPipeReader({
      auditpipePath: path,
      onEvent: async (event) => {
        events.push(event);
      },
    });

    await reader.start();
    cleanup();

    expect(events).toHaveLength(3);
    expect(events[0]?.event).toBe("execve(2)");
    expect(events[1]?.event).toBe("user authentication");
    expect(events[2]?.event).toBe("open(2)");
  });

  test("calls onError when onEvent throws", async () => {
    const record = buildRecord(180);
    const { path, dir } = writeTempFile(record);
    dirs.push(dir);

    const errors: string[] = [];
    const reader = new AuditPipeReader({
      auditpipePath: path,
      onEvent: async () => {
        throw new Error("write failed");
      },
      onError: (msg) => {
        errors.push(msg);
      },
    });

    await reader.start();
    cleanup();

    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("Failed to write event");
    expect(errors[0]).toContain("write failed");
  });

  test("stop() causes start() to resolve", async () => {
    // Use an empty file — Bun.file().stream() will return done immediately,
    // but this verifies the stop mechanism doesn't break anything
    const { path, dir } = writeTempFile(new Uint8Array(0));
    dirs.push(dir);

    const reader = new AuditPipeReader({
      auditpipePath: path,
      onEvent: async () => {},
    });

    reader.stop();
    await reader.start();
    cleanup();
    // If we get here, start() resolved — test passes
  });

  test("skips garbage bytes and recovers", async () => {
    const garbage = new Uint8Array([0xff, 0xfe, 0xfd]);
    const record = buildRecord(180);
    const data = concat(garbage, record);
    const { path, dir } = writeTempFile(data);
    dirs.push(dir);

    const events: AuditEvent[] = [];
    const reader = new AuditPipeReader({
      auditpipePath: path,
      onEvent: async (event) => {
        events.push(event);
      },
    });

    await reader.start();
    cleanup();

    expect(events).toHaveLength(1);
    expect(events[0]?.event).toBe("execve(2)");
  });

  test("uses default auditpipe path when not specified", () => {
    const reader = new AuditPipeReader({
      onEvent: async () => {},
    });
    // Verify it was constructed without error — the default path
    // (/dev/auditpipe) won't be opened until start() is called
    expect(reader).toBeDefined();
  });

  test("uses default onError when not specified", async () => {
    const record = buildRecord(180);
    const { path, dir } = writeTempFile(record);
    dirs.push(dir);

    // Should not throw even without onError
    const reader = new AuditPipeReader({
      auditpipePath: path,
      onEvent: async () => {
        throw new Error("test error");
      },
    });

    await reader.start();
    cleanup();
  });
});
