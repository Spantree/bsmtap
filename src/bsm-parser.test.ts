import { describe, expect, test } from "bun:test";
import { extractRecords, parseRecord } from "./bsm-parser.ts";

/** Helper: build a big-endian buffer from a sequence of typed values. */
function bsm(...parts: (number | [string, number])[]): Uint8Array {
  // First pass: calculate total size
  let size = 0;
  for (const part of parts) {
    if (typeof part === "number") {
      size += 1; // uint8
    } else {
      const [type] = part;
      if (type === "u16") size += 2;
      else if (type === "u32") size += 4;
      else if (type === "u64") size += 8;
    }
  }
  const buf = new ArrayBuffer(size);
  const view = new DataView(buf);
  const arr = new Uint8Array(buf);
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
  return arr;
}

/** Build a NUL-terminated length-prefixed string (for path/text tokens). */
function bsmString(s: string): Uint8Array {
  const encoded = new TextEncoder().encode(s);
  const len = encoded.byteLength + 1; // include NUL
  const buf = new Uint8Array(2 + len);
  const view = new DataView(buf.buffer);
  view.setUint16(0, len, false);
  buf.set(encoded, 2);
  buf[2 + encoded.byteLength] = 0; // NUL
  return buf;
}

/** Build NUL-terminated exec args (count + NUL-terminated strings). */
function bsmExecArgs(...args: string[]): Uint8Array {
  const parts: Uint8Array[] = [];
  // 4-byte count
  const countBuf = new Uint8Array(4);
  new DataView(countBuf.buffer).setUint32(0, args.length, false);
  parts.push(countBuf);
  for (const arg of args) {
    const encoded = new TextEncoder().encode(arg);
    const withNul = new Uint8Array(encoded.byteLength + 1);
    withNul.set(encoded);
    withNul[encoded.byteLength] = 0;
    parts.push(withNul);
  }
  const total = parts.reduce((s, p) => s + p.byteLength, 0);
  const result = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    result.set(p, off);
    off += p.byteLength;
  }
  return result;
}

/** Concatenate multiple Uint8Arrays. */
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

/** Build a complete BSM record with header32, payload tokens, and trailer. */
function buildRecord(eventType: number, ...tokens: Uint8Array[]): Uint8Array {
  // Header32: 1(id) + 4(size) + 1(ver) + 2(event) + 2(mod) + 4(sec) + 4(msec) = 18
  // Trailer: 1(id) + 2(magic) + 4(size) = 7
  const payloadSize = tokens.reduce((s, t) => s + t.byteLength, 0);
  const totalSize = 18 + payloadSize + 7;

  const header = bsm(
    0x14, // AUT_HEADER32
    ["u32", totalSize],
    11, // version
    ["u16", eventType],
    ["u16", 0], // modifier
    ["u32", 1776000000], // seconds (2026-04-14 ~10:00 UTC)
    ["u32", 123000], // microseconds (123ms = 123000μs)
  );

  const trailer = bsm(
    0x13, // AUT_TRAILER
    ["u16", 0xb105], // magic
    ["u32", totalSize],
  );

  return concat(header, ...tokens, trailer);
}

// --- Token builders ---

function subjectToken(opts: {
  auid?: number;
  uid?: number;
  gid?: number;
  ruid?: number;
  rgid?: number;
  pid?: number;
  sid?: number;
  port?: number;
  ip?: [number, number, number, number];
}): Uint8Array {
  // Subject32 (0x24)
  return bsm(
    0x24,
    ["u32", opts.auid ?? 501],
    ["u32", opts.uid ?? 501],
    ["u32", opts.gid ?? 20],
    ["u32", opts.ruid ?? 501],
    ["u32", opts.rgid ?? 20],
    ["u32", opts.pid ?? 1234],
    ["u32", opts.sid ?? 100001],
    ["u32", opts.port ?? 1234],
    ...(opts.ip ?? [127, 0, 0, 1]).map((b) => b as number),
  );
}

function subject32ExToken(opts: {
  auid?: number;
  uid?: number;
  gid?: number;
  ruid?: number;
  rgid?: number;
  pid?: number;
  sid?: number;
  port?: number;
  ipv6?: boolean;
}): Uint8Array {
  // Subject32_EX (0x7a) with IPv4
  if (opts.ipv6) {
    return bsm(
      0x7a,
      ["u32", opts.auid ?? 501],
      ["u32", opts.uid ?? 501],
      ["u32", opts.gid ?? 20],
      ["u32", opts.ruid ?? 501],
      ["u32", opts.rgid ?? 20],
      ["u32", opts.pid ?? 9012],
      ["u32", opts.sid ?? 100002],
      ["u32", opts.port ?? 9012],
      ["u32", 16], // AU_IPv6
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1, // ::1
    );
  }
  return bsm(
    0x7a,
    ["u32", opts.auid ?? 501],
    ["u32", opts.uid ?? 501],
    ["u32", opts.gid ?? 20],
    ["u32", opts.ruid ?? 501],
    ["u32", opts.rgid ?? 20],
    ["u32", opts.pid ?? 1234],
    ["u32", opts.sid ?? 100001],
    ["u32", opts.port ?? 1234],
    ["u32", 4], // AU_IPv4
    127,
    0,
    0,
    1,
  );
}

function returnToken(errno: number, retval: number): Uint8Array {
  return bsm(0x27, errno, ["u32", retval]);
}

function pathToken(path: string): Uint8Array {
  return concat(new Uint8Array([0x23]), bsmString(path));
}

function textToken(text: string): Uint8Array {
  return concat(new Uint8Array([0x28]), bsmString(text));
}

function execArgsToken(...args: string[]): Uint8Array {
  return concat(new Uint8Array([0x3c]), bsmExecArgs(...args));
}

function attrToken(mode: number, uid: number, gid: number, fsid: number, nodeid: number, device: number): Uint8Array {
  return bsm(
    0x3e, // AUT_ATTR32
    ["u32", mode],
    ["u32", uid],
    ["u32", gid],
    ["u32", fsid],
    ["u64", nodeid],
    ["u32", device],
  );
}

function argToken(argNum: number, value: number, desc: string): Uint8Array {
  return concat(bsm(0x2d, argNum, ["u32", value]), bsmString(desc));
}

// --- 64-bit token builders ---

function subject64Token(opts: { pid?: number; port?: number }): Uint8Array {
  // Subject64 (0x75) — port is uint64
  return bsm(
    0x75,
    ["u32", 501], // auid
    ["u32", 501], // uid
    ["u32", 20], // gid
    ["u32", 501], // ruid
    ["u32", 20], // rgid
    ["u32", opts.pid ?? 1234],
    ["u32", 100001], // sid
    ["u64", opts.port ?? 1234], // port (64-bit)
    127,
    0,
    0,
    1,
  );
}

function subject64ExToken(opts: { pid?: number; ipv6?: boolean }): Uint8Array {
  // Subject64_EX (0x7c) — port is uint64, variable address
  if (opts.ipv6) {
    return bsm(
      0x7c,
      ["u32", 501],
      ["u32", 501],
      ["u32", 20],
      ["u32", 501],
      ["u32", 20],
      ["u32", opts.pid ?? 9012],
      ["u32", 100002],
      ["u64", 9012], // port (64-bit)
      ["u32", 16], // AU_IPv6
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1, // ::1
    );
  }
  return bsm(
    0x7c,
    ["u32", 501],
    ["u32", 501],
    ["u32", 20],
    ["u32", 501],
    ["u32", 20],
    ["u32", opts.pid ?? 1234],
    ["u32", 100001],
    ["u64", 1234], // port (64-bit)
    ["u32", 4], // AU_IPv4
    127,
    0,
    0,
    1,
  );
}

function return64Token(errno: number, retval: number): Uint8Array {
  return bsm(0x72, errno, ["u64", retval]);
}

function attr64Token(mode: number, uid: number, gid: number, fsid: number, nodeid: number, device: number): Uint8Array {
  return bsm(
    0x73, // AUT_ATTR64
    ["u32", mode],
    ["u32", uid],
    ["u32", gid],
    ["u32", fsid],
    ["u64", nodeid],
    ["u64", device], // 64-bit device
  );
}

function arg64Token(argNum: number, value: number, desc: string): Uint8Array {
  return concat(bsm(0x71, argNum, ["u64", value]), bsmString(desc));
}

/** Build a record with header64 (0x74). */
function buildRecord64(eventType: number, ...tokens: Uint8Array[]): Uint8Array {
  // Header64: 1(id) + 4(size) + 1(ver) + 2(event) + 2(mod) + 8(sec) + 8(usec) = 26
  const payloadSize = tokens.reduce((s, t) => s + t.byteLength, 0);
  const totalSize = 26 + payloadSize + 7;
  const header = bsm(
    0x74, // AUT_HEADER64
    ["u32", totalSize],
    11,
    ["u16", eventType],
    ["u16", 0],
    ["u64", 1776000000], // seconds
    ["u64", 123000], // microseconds
  );
  const trailer = bsm(0x13, ["u16", 0xb105], ["u32", totalSize]);
  return concat(header, ...tokens, trailer);
}

/** Build a record with header32_ex (0x15) with IPv4. */
function buildRecord32Ex(eventType: number, ...tokens: Uint8Array[]): Uint8Array {
  // Header32_EX: 1(id) + 4(size) + 1(ver) + 2(event) + 2(mod) + 4(addrType) + 4(ipv4) + 4(sec) + 4(usec) = 26
  const payloadSize = tokens.reduce((s, t) => s + t.byteLength, 0);
  const totalSize = 26 + payloadSize + 7;
  const header = bsm(
    0x15, // AUT_HEADER32_EX
    ["u32", totalSize],
    11,
    ["u16", eventType],
    ["u16", 0],
    ["u32", 4], // AU_IPv4
    127,
    0,
    0,
    1,
    ["u32", 1776000000],
    ["u32", 123000],
  );
  const trailer = bsm(0x13, ["u16", 0xb105], ["u32", totalSize]);
  return concat(header, ...tokens, trailer);
}

/** Build a record with header64_ex (0x79) with IPv4. */
function buildRecord64Ex(eventType: number, ...tokens: Uint8Array[]): Uint8Array {
  // Header64_EX: 1(id) + 4(size) + 1(ver) + 2(event) + 2(mod) + 4(addrType) + 4(ipv4) + 8(sec) + 8(usec) = 34
  const payloadSize = tokens.reduce((s, t) => s + t.byteLength, 0);
  const totalSize = 34 + payloadSize + 7;
  const header = bsm(
    0x79, // AUT_HEADER64_EX
    ["u32", totalSize],
    11,
    ["u16", eventType],
    ["u16", 0],
    ["u32", 4], // AU_IPv4
    127,
    0,
    0,
    1,
    ["u64", 1776000000],
    ["u64", 123000],
  );
  const trailer = bsm(0x13, ["u16", 0xb105], ["u32", totalSize]);
  return concat(header, ...tokens, trailer);
}

// --- Tests ---

describe("parseRecord", () => {
  test("parses execve record with subject, exec_args, path, attr, return", () => {
    const record = buildRecord(
      180, // execve(2)
      subjectToken({ pid: 1234 }),
      execArgsToken("/usr/bin/ls", "-la", "/tmp"),
      pathToken("/usr/bin/ls"),
      attrToken(0o100755, 0, 0, 16777220, 12345678, 16777220),
      returnToken(0, 0),
    );

    const event = parseRecord(record);

    expect(event.event).toBe("execve(2)");
    expect(event.version).toBe("11");
    expect(event.modifier).toBe("0");
    expect(event.timestamp).toContain("2026");

    expect(event.subject).not.toBeNull();
    expect(event.subject!.pid).toBe("1234");
    expect(event.subject!.uid).toBe("501");
    expect(event.subject!.tid).toBe("1234 127.0.0.1");

    expect(event.execArgs).toEqual(["/usr/bin/ls", "-la", "/tmp"]);
    expect(event.paths).toEqual(["/usr/bin/ls"]);

    expect(event.attributes).toHaveLength(1);
    expect(event.attributes[0]?.mode).toBe("100755");
    expect(event.attributes[0]?.uid).toBe("0");

    expect(event.return).not.toBeNull();
    expect(event.return!.errval).toBe("success");
    expect(event.return!.retval).toBe("0");
  });

  test("parses user authentication record with text", () => {
    const record = buildRecord(
      43001, // user authentication
      subjectToken({ auid: 501, uid: 501, pid: 69, sid: 100005, port: 69 }),
      textToken("Verify password for record type Users 'oompa' node '/Local/Default'"),
      returnToken(0, 0),
    );

    const event = parseRecord(record);
    expect(event.event).toBe("user authentication");
    expect(event.subject!.pid).toBe("69");
    expect(event.text).toEqual(["Verify password for record type Users 'oompa' node '/Local/Default'"]);
    expect(event.return!.errval).toBe("success");
  });

  test("parses open(2) record with argument tokens", () => {
    const record = buildRecord(
      112, // open(2) - read
      subjectToken({ pid: 5678 }),
      argToken(2, 0, "mode"),
      pathToken("/etc/passwd"),
      attrToken(0o100644, 0, 0, 16777220, 87654321, 16777220),
      returnToken(0, 3),
    );

    const event = parseRecord(record);
    expect(event.event).toBe("open(2) - read");
    expect(event.paths).toEqual(["/etc/passwd"]);
    expect(event.arguments).toHaveLength(1);
    expect(event.arguments[0]?.argNum).toBe("2");
    expect(event.arguments[0]?.value).toBe("0x0");
    expect(event.arguments[0]?.desc).toBe("mode");
    expect(event.return!.retval).toBe("3");
  });

  test("parses subject32_ex with IPv6", () => {
    const record = buildRecord(
      44901, // OpenSSH login
      subject32ExToken({ pid: 9012, sid: 100002, port: 9012, ipv6: true }),
      textToken("successful login feniix"),
      returnToken(0, 0),
    );

    const event = parseRecord(record);
    expect(event.event).toBe("OpenSSH login");
    expect(event.subject).not.toBeNull();
    expect(event.subject!.pid).toBe("9012");
    expect(event.subject!.tid).toBe("9012 ::1");
    expect(event.text).toEqual(["successful login feniix"]);
  });

  test("handles record with no subject", () => {
    const record = buildRecord(
      45014, // system boot
      returnToken(0, 0),
    );

    const event = parseRecord(record);
    expect(event.event).toBe("system boot");
    expect(event.subject).toBeNull();
    expect(event.return).not.toBeNull();
  });

  test("handles record with no return", () => {
    const record = buildRecord(
      45000, // audit startup
      textToken("audit startup"),
    );

    const event = parseRecord(record);
    expect(event.event).toBe("audit startup");
    expect(event.return).toBeNull();
    expect(event.text).toEqual(["audit startup"]);
  });

  test("handles multiple paths", () => {
    const record = buildRecord(
      38, // rename(2)
      subjectToken({ auid: 0, uid: 0, gid: 0, ruid: 0, rgid: 0, pid: 1, sid: 0, port: 0 }),
      pathToken("/tmp/old"),
      pathToken("/tmp/new"),
      returnToken(0, 0),
    );

    const event = parseRecord(record);
    expect(event.paths).toEqual(["/tmp/old", "/tmp/new"]);
  });

  test("failure return includes errno description", () => {
    const record = buildRecord(
      3, // open(2)
      subjectToken({}),
      returnToken(13, 0xffffffff), // EACCES
    );

    const event = parseRecord(record);
    expect(event.return!.errval).toBe("failure: Permission denied");
  });

  test("unknown event type uses numeric fallback", () => {
    const record = buildRecord(60000, returnToken(0, 0));

    const event = parseRecord(record);
    expect(event.event).toBe("60000");
  });

  test("timestamp is ISO 8601", () => {
    const record = buildRecord(
      180, // execve(2)
      returnToken(0, 0),
    );

    const event = parseRecord(record);
    // 1776000000 seconds + 123000 microseconds (= 123ms)
    expect(event.timestamp).toBe(new Date(1776000000 * 1000 + 123).toISOString());
  });

  test("trailer magic mismatch logs error but doesn't crash", () => {
    // Build a record manually with bad trailer magic
    const header = bsm(
      0x14,
      ["u32", 25], // 18 header + 7 trailer
      11,
      ["u16", 180],
      ["u16", 0],
      ["u32", 1776000000],
      ["u32", 0],
    );
    const badTrailer = bsm(
      0x13,
      ["u16", 0xdead], // wrong magic
      ["u32", 25],
    );
    const record = concat(header, badTrailer);
    // Should not throw
    const event = parseRecord(record);
    expect(event.event).toBe("execve(2)");
  });

  test("survives truncated record without crashing", () => {
    // Build a valid record then chop it in the middle of a token
    const record = buildRecord(180, subjectToken({ pid: 42 }), pathToken("/usr/bin/ls"), returnToken(0, 0));
    // Chop in the middle of the path token (keep header + subject + partial path)
    const truncated = record.subarray(0, 18 + 37 + 5); // header + subject32 + partial path
    const event = parseRecord(truncated);
    // Should have parsed the header and subject, path aborted gracefully
    expect(event.event).toBe("execve(2)");
    expect(event.subject).not.toBeNull();
    expect(event.subject!.pid).toBe("42");
    expect(event.paths).toHaveLength(0); // path was truncated
  });

  test("survives corrupt string length without crashing", () => {
    // Build a path token with a length field larger than the buffer
    const header = bsm(
      0x14,
      ["u32", 32], // claim 32 bytes total
      11,
      ["u16", 180],
      ["u16", 0],
      ["u32", 1776000000],
      ["u32", 123000],
    );
    const badPath = bsm(
      0x23, // AUT_PATH
      ["u16", 9999], // absurdly large string length
    );
    const trailer = bsm(0x13, ["u16", 0xb105], ["u32", 32]);
    const record = concat(header, badPath, trailer);
    // Should not throw — bounds check should bail
    const event = parseRecord(record);
    expect(event.event).toBe("execve(2)");
    expect(event.paths).toHaveLength(0);
  });

  // --- 64-bit and extended header variants ---

  test("parses record with header64", () => {
    const record = buildRecord64(180, subjectToken({ pid: 42 }), returnToken(0, 0));
    const event = parseRecord(record);
    expect(event.event).toBe("execve(2)");
    expect(event.version).toBe("11");
    expect(event.subject!.pid).toBe("42");
    expect(event.return!.errval).toBe("success");
    expect(event.timestamp).toContain("2026");
  });

  test("parses record with header32_ex", () => {
    const record = buildRecord32Ex(43001, textToken("auth test"), returnToken(0, 0));
    const event = parseRecord(record);
    expect(event.event).toBe("user authentication");
    expect(event.text).toEqual(["auth test"]);
    expect(event.timestamp).toContain("2026");
  });

  test("parses record with header64_ex", () => {
    const record = buildRecord64Ex(44901, textToken("ssh login"), returnToken(0, 0));
    const event = parseRecord(record);
    expect(event.event).toBe("OpenSSH login");
    expect(event.text).toEqual(["ssh login"]);
    expect(event.timestamp).toContain("2026");
  });

  // --- 64-bit subject variants ---

  test("parses subject64 (64-bit port)", () => {
    const record = buildRecord(180, subject64Token({ pid: 7777, port: 12345 }), returnToken(0, 0));
    const event = parseRecord(record);
    expect(event.subject).not.toBeNull();
    expect(event.subject!.pid).toBe("7777");
    expect(event.subject!.tid).toBe("12345 127.0.0.1");
  });

  test("parses subject64_ex with IPv4", () => {
    const record = buildRecord(180, subject64ExToken({ pid: 8888 }), returnToken(0, 0));
    const event = parseRecord(record);
    expect(event.subject!.pid).toBe("8888");
    expect(event.subject!.tid).toBe("1234 127.0.0.1");
  });

  test("parses subject64_ex with IPv6", () => {
    const record = buildRecord(180, subject64ExToken({ pid: 9999, ipv6: true }), returnToken(0, 0));
    const event = parseRecord(record);
    expect(event.subject!.pid).toBe("9999");
    expect(event.subject!.tid).toBe("9012 ::1");
  });

  // --- 64-bit return ---

  test("parses return64", () => {
    const record = buildRecord(180, return64Token(0, 42));
    const event = parseRecord(record);
    expect(event.return!.errval).toBe("success");
    expect(event.return!.retval).toBe("42");
  });

  test("return64 with errno", () => {
    const record = buildRecord(180, return64Token(2, 0)); // ENOENT
    const event = parseRecord(record);
    expect(event.return!.errval).toBe("failure: No such file or directory");
  });

  // --- 64-bit attribute ---

  test("parses attr64 (64-bit device)", () => {
    const record = buildRecord(180, attr64Token(0o100644, 0, 0, 16777220, 12345, 16777220), returnToken(0, 0));
    const event = parseRecord(record);
    expect(event.attributes).toHaveLength(1);
    expect(event.attributes[0]?.mode).toBe("100644");
    expect(event.attributes[0]?.device).toBe("16777220");
  });

  // --- 64-bit argument ---

  test("parses arg64", () => {
    const record = buildRecord(180, arg64Token(1, 0xdeadbeef, "flags"), returnToken(0, 0));
    const event = parseRecord(record);
    expect(event.arguments).toHaveLength(1);
    expect(event.arguments[0]?.argNum).toBe("1");
    expect(event.arguments[0]?.value).toBe("0xdeadbeef");
    expect(event.arguments[0]?.desc).toBe("flags");
  });

  // --- Unknown token ---

  test("unknown token logs and skips rest of record", () => {
    // Inject an unknown token (0xff) before the return token
    const unknownToken = new Uint8Array([0xff, 0x00, 0x00]);
    const record = buildRecord(180, unknownToken, returnToken(0, 0));
    const event = parseRecord(record);
    expect(event.event).toBe("execve(2)");
    // Return should be missing because unknown token skipped to end
    expect(event.return).toBeNull();
  });

  // --- subject32_ex with IPv4 (not just IPv6) ---

  test("parses subject32_ex with IPv4", () => {
    const record = buildRecord(180, subject32ExToken({ pid: 5555 }), returnToken(0, 0));
    const event = parseRecord(record);
    expect(event.subject!.pid).toBe("5555");
    expect(event.subject!.tid).toBe("1234 127.0.0.1");
  });

  // --- Trailer size mismatch ---

  test("trailer size mismatch logs error but doesn't crash", () => {
    const header = bsm(0x14, ["u32", 25], 11, ["u16", 180], ["u16", 0], ["u32", 1776000000], ["u32", 0]);
    const badTrailer = bsm(0x13, ["u16", 0xb105], ["u32", 999]); // wrong size
    const record = concat(header, badTrailer);
    const event = parseRecord(record);
    expect(event.event).toBe("execve(2)");
  });

  // --- Empty exec args ---

  test("exec_args with count=0 produces empty array", () => {
    const emptyExecArgs = concat(new Uint8Array([0x3c]), bsm(["u32", 0]));
    const record = buildRecord(180, emptyExecArgs, returnToken(0, 0));
    const event = parseRecord(record);
    expect(event.execArgs).toEqual([]);
  });

  // --- Empty string tokens ---

  test("path with length=1 (just NUL) produces empty string", () => {
    // length=1 means just the NUL terminator
    const emptyPath = concat(new Uint8Array([0x23]), bsm(["u16", 1]), new Uint8Array([0]));
    const record = buildRecord(180, emptyPath, returnToken(0, 0));
    const event = parseRecord(record);
    expect(event.paths).toEqual([""]);
  });

  test("survives exec_args with count exceeding buffer", () => {
    // Exec args token claiming 100 args but only containing 1
    const header = bsm(0x14, ["u32", 40], 11, ["u16", 180], ["u16", 0], ["u32", 1776000000], ["u32", 123000]);
    const execArgs = concat(
      bsm(0x3c, ["u32", 100]), // claims 100 args
      new TextEncoder().encode("hello\0"), // only 1 arg
    );
    const trailer = bsm(0x13, ["u16", 0xb105], ["u32", 40]);
    const record = concat(header, execArgs, trailer);
    const event = parseRecord(record);
    expect(event.event).toBe("execve(2)");
    // Should parse the one valid arg and stop, not crash
    expect(event.execArgs.length).toBeGreaterThanOrEqual(1);
  });
});

describe("extractRecords", () => {
  test("extracts a single complete record", () => {
    const record = buildRecord(180, returnToken(0, 0));
    const { events, consumed } = extractRecords(record);
    expect(events).toHaveLength(1);
    expect(events[0]!.event).toBe("execve(2)");
    expect(consumed).toBe(record.byteLength);
  });

  test("extracts multiple records from one buffer", () => {
    const r1 = buildRecord(180, returnToken(0, 0));
    const r2 = buildRecord(43001, textToken("test"), returnToken(0, 0));
    const buf = concat(r1, r2);

    const { events, consumed } = extractRecords(buf);
    expect(events).toHaveLength(2);
    expect(events[0]!.event).toBe("execve(2)");
    expect(events[1]!.event).toBe("user authentication");
    expect(consumed).toBe(buf.byteLength);
  });

  test("returns partial buffer when record is incomplete", () => {
    const record = buildRecord(180, returnToken(0, 0));
    // Chop off last 3 bytes to simulate partial read
    const partial = record.subarray(0, record.byteLength - 3);

    const { events, consumed } = extractRecords(partial);
    expect(events).toHaveLength(0);
    expect(consumed).toBe(0);
  });

  test("handles empty buffer", () => {
    const { events, consumed } = extractRecords(new Uint8Array(0));
    expect(events).toHaveLength(0);
    expect(consumed).toBe(0);
  });

  test("skips garbage bytes and resyncs on next header", () => {
    const garbage = new Uint8Array([0xff, 0xfe, 0xfd]);
    const record = buildRecord(180, returnToken(0, 0));
    const buf = concat(garbage, record);

    const { events, consumed } = extractRecords(buf);
    expect(events).toHaveLength(1);
    expect(events[0]!.event).toBe("execve(2)");
    expect(consumed).toBe(buf.byteLength);
  });
});
