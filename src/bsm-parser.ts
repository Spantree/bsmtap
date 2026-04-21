/**
 * OpenBSM binary token parser.
 *
 * Parses BSM binary records from /dev/auditpipe into AuditEvent objects.
 * All multi-byte integers are big-endian regardless of host architecture.
 *
 * Reference: openbsm/openbsm bsm_token.h, bsm_io.c
 */

import type { AuditArgument, AuditAttribute, AuditEvent, AuditIdentity, AuditReturn, AuditSubject } from "./schema.ts";

// --- Token type IDs ---

const AUT_HEADER32 = 0x14;
const AUT_HEADER32_EX = 0x15;
const AUT_HEADER64 = 0x74;
const AUT_HEADER64_EX = 0x79;
const AUT_TRAILER = 0x13;
const AUT_SUBJECT32 = 0x24;
const AUT_SUBJECT64 = 0x75;
const AUT_SUBJECT32_EX = 0x7a;
const AUT_SUBJECT64_EX = 0x7c;
const AUT_RETURN32 = 0x27;
const AUT_RETURN64 = 0x72;
const AUT_PATH = 0x23;
const AUT_TEXT = 0x28;
const AUT_EXEC_ARGS = 0x3c;
const AUT_ARG32 = 0x2d;
const AUT_ARG64 = 0x71;
const AUT_DATA = 0x21;
const AUT_IN_ADDR = 0x2a;
const AUT_ATTR32 = 0x3e;
const AUT_ATTR64 = 0x73;
const AUT_IDENTITY = 0xed;

const TRAILER_MAGIC = 0xb105;
const textDecoder = new TextDecoder();

// --- Event name lookup (common AUE_* events) ---
// Loaded lazily from /etc/security/audit_event if available, otherwise uses this fallback map.

const KNOWN_EVENTS: Record<number, string> = {
  1: "exit(2)",
  2: "fork(2)",
  3: "open(2)",
  4: "creat(2)",
  5: "link(2)",
  6: "unlink(2)",
  7: "exec(2)",
  23: "setuid(2)",
  24: "setgid(2)",
  27: "setgroups(2)",
  33: "access(2)",
  38: "rename(2)",
  39: "stat(2)",
  42: "read(2)",
  43: "write(2)",
  45: "pipe(2)",
  51: "socket(2)",
  52: "connect(2)",
  61: "kill(2)",
  62: "ioctl(2)",
  72: "chown(2)",
  73: "fchown(2)",
  78: "chmod(2)",
  79: "fchmod(2)",
  104: "bind(2)",
  105: "listen(2)",
  112: "open(2) - read",
  113: "open(2) - read,creat",
  114: "open(2) - read,trunc",
  115: "open(2) - read,creat,trunc",
  116: "open(2) - write",
  117: "open(2) - write,creat",
  118: "open(2) - write,trunc",
  119: "open(2) - write,creat,trunc",
  120: "open(2) - read,write",
  121: "open(2) - read,write,creat",
  122: "open(2) - read,write,trunc",
  123: "open(2) - read,write,creat,trunc",
  124: "open_extended(2) - read",
  131: "mkdir(2)",
  132: "rmdir(2)",
  176: "mount(2)",
  180: "execve(2)",
  183: "seteuid(2)",
  184: "setegid(2)",
  187: "sigaction(2)",
  210: "fcntl(2)",
  224: "shutdown(2)",
  252: "chdir(2)",
  43001: "user authentication",
  43002: "user access authorization",
  44901: "OpenSSH login",
  44902: "OpenSSH logout",
  45000: "audit startup",
  45001: "audit shutdown",
  45014: "system boot",
  45015: "system halt",
  6152: "MAC framework policy exception",
  6153: "MAC framework policy set",
};

// --- Errno lookup (common values) ---

const ERRNO_NAMES: Record<number, string> = {
  0: "success",
  1: "Operation not permitted",
  2: "No such file or directory",
  5: "Input/output error",
  13: "Permission denied",
  17: "File exists",
  20: "Not a directory",
  21: "Is a directory",
  22: "Invalid argument",
  28: "No space left on device",
  35: "Resource temporarily unavailable",
};

/** Parse a complete BSM binary record into an AuditEvent. */
export function parseRecord(buf: Uint8Array): AuditEvent {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let offset = 0;

  const event: AuditEvent = {
    timestamp: "",
    event: "",
    modifier: "",
    version: "",
    subject: null,
    return: null,
    paths: [],
    execArgs: [],
    text: [],
    attributes: [],
    arguments: [],
    identity: null,
  };

  // Record size is always at byte 1 (right after the 1-byte token ID) for all header types
  const recordSize = buf.byteLength >= 5 ? view.getUint32(1, false) : 0;

  while (offset < buf.byteLength) {
    const tokenId = buf[offset]!;
    offset += 1;

    try {
      switch (tokenId) {
        case AUT_HEADER32:
          offset = parseHeader32(view, offset, event);
          break;
        case AUT_HEADER64:
          offset = parseHeader64(view, offset, event);
          break;
        case AUT_HEADER32_EX:
          offset = parseHeader32Ex(view, offset, event);
          break;
        case AUT_HEADER64_EX:
          offset = parseHeader64Ex(view, offset, event);
          break;
        case AUT_SUBJECT32:
          offset = parseSubject32(view, offset, event);
          break;
        case AUT_SUBJECT64:
          offset = parseSubject64(view, offset, event);
          break;
        case AUT_SUBJECT32_EX:
          offset = parseSubject32Ex(view, offset, event);
          break;
        case AUT_SUBJECT64_EX:
          offset = parseSubject64Ex(view, offset, event);
          break;
        case AUT_RETURN32:
          offset = parseReturn32(view, offset, event);
          break;
        case AUT_RETURN64:
          offset = parseReturn64(view, offset, event);
          break;
        case AUT_PATH:
          offset = parsePath(view, offset, buf, event);
          break;
        case AUT_TEXT:
          offset = parseText(view, offset, buf, event);
          break;
        case AUT_DATA:
          offset = parseData(view, offset, buf);
          break;
        case AUT_IN_ADDR:
          offset = offset + 4;
          break;
        case AUT_EXEC_ARGS:
          offset = parseExecArgs(view, offset, buf, event);
          break;
        case AUT_ARG32:
          offset = parseArg32(view, offset, buf, event);
          break;
        case AUT_ARG64:
          offset = parseArg64(view, offset, buf, event);
          break;
        case AUT_ATTR32:
          offset = parseAttr32(view, offset, event);
          break;
        case AUT_ATTR64:
          offset = parseAttr64(view, offset, event);
          break;
        case AUT_IDENTITY:
          offset = parseIdentity(view, offset, buf, event);
          break;
        case AUT_TRAILER:
          offset = parseTrailer(view, offset, recordSize);
          break;
        default:
          console.error(
            `[bsmtap] Unknown token 0x${tokenId.toString(16)} at offset ${offset - 1}, skipping rest of record`,
          );
          offset = buf.byteLength;
          break;
      }
    } catch (err) {
      // A malformed token must not crash the daemon — emit partial event data
      console.error(`[bsmtap] Error parsing token 0x${tokenId.toString(16)} at offset ${offset - 1}: ${err}`);
      break;
    }
  }

  return event;
}

// --- Header parsers ---

function parseHeader32(view: DataView, off: number, event: AuditEvent): number {
  const version = view.getUint8(off + 4);
  const eventType = view.getUint16(off + 5, false);
  const modifier = view.getUint16(off + 7, false);
  const seconds = view.getUint32(off + 9, false);
  const usec = view.getUint32(off + 13, false);

  event.version = String(version);
  event.event = KNOWN_EVENTS[eventType] ?? String(eventType);
  event.modifier = String(modifier);
  event.timestamp = toIso8601(seconds, usec);

  return off + 17;
}

function parseHeader64(view: DataView, off: number, event: AuditEvent): number {
  const version = view.getUint8(off + 4);
  const eventType = view.getUint16(off + 5, false);
  const modifier = view.getUint16(off + 7, false);
  const seconds = Number(view.getBigUint64(off + 9, false));
  const usec = Number(view.getBigUint64(off + 17, false));

  event.version = String(version);
  event.event = KNOWN_EVENTS[eventType] ?? String(eventType);
  event.modifier = String(modifier);
  event.timestamp = toIso8601(seconds, usec);

  return off + 25;
}

function parseHeader32Ex(view: DataView, off: number, event: AuditEvent): number {
  const version = view.getUint8(off + 4);
  const eventType = view.getUint16(off + 5, false);
  const modifier = view.getUint16(off + 7, false);
  const addrType = view.getUint32(off + 9, false);
  const addrLen = addrType === 4 ? 4 : 16;
  const seconds = view.getUint32(off + 13 + addrLen, false);
  const usec = view.getUint32(off + 17 + addrLen, false);

  event.version = String(version);
  event.event = KNOWN_EVENTS[eventType] ?? String(eventType);
  event.modifier = String(modifier);
  event.timestamp = toIso8601(seconds, usec);

  return off + 21 + addrLen;
}

function parseHeader64Ex(view: DataView, off: number, event: AuditEvent): number {
  const version = view.getUint8(off + 4);
  const eventType = view.getUint16(off + 5, false);
  const modifier = view.getUint16(off + 7, false);
  const addrType = view.getUint32(off + 9, false);
  const addrLen = addrType === 4 ? 4 : 16;
  const seconds = Number(view.getBigUint64(off + 13 + addrLen, false));
  const usec = Number(view.getBigUint64(off + 21 + addrLen, false));

  event.version = String(version);
  event.event = KNOWN_EVENTS[eventType] ?? String(eventType);
  event.modifier = String(modifier);
  event.timestamp = toIso8601(seconds, usec);

  return off + 29 + addrLen;
}

// --- Subject parsers ---

function parseSubject32(view: DataView, off: number, event: AuditEvent): number {
  const port = view.getUint32(off + 28, false);
  const ip = formatIpv4(view, off + 32);
  event.subject = readSubjectFields(view, off, `${port} ${ip}`);
  return off + 36;
}

function parseSubject64(view: DataView, off: number, event: AuditEvent): number {
  const port = Number(view.getBigUint64(off + 28, false));
  const ip = formatIpv4(view, off + 36);
  event.subject = readSubjectFields(view, off, `${port} ${ip}`);
  return off + 40;
}

function parseSubject32Ex(view: DataView, off: number, event: AuditEvent): number {
  const port = view.getUint32(off + 28, false);
  const addrType = view.getUint32(off + 32, false);
  const addrLen = addrType === 4 ? 4 : 16;
  const ip = addrLen === 4 ? formatIpv4(view, off + 36) : formatIpv6(view, off + 36);
  event.subject = readSubjectFields(view, off, `${port} ${ip}`);
  return off + 36 + addrLen;
}

function parseSubject64Ex(view: DataView, off: number, event: AuditEvent): number {
  const port = Number(view.getBigUint64(off + 28, false));
  const addrType = view.getUint32(off + 36, false);
  const addrLen = addrType === 4 ? 4 : 16;
  const ip = addrLen === 4 ? formatIpv4(view, off + 40) : formatIpv6(view, off + 40);
  event.subject = readSubjectFields(view, off, `${port} ${ip}`);
  return off + 40 + addrLen;
}

function readSubjectFields(view: DataView, off: number, tid: string): AuditSubject {
  return {
    auditUid: String(view.getUint32(off, false)),
    uid: String(view.getUint32(off + 4, false)),
    gid: String(view.getUint32(off + 8, false)),
    ruid: String(view.getUint32(off + 12, false)),
    rgid: String(view.getUint32(off + 16, false)),
    pid: String(view.getUint32(off + 20, false)),
    sid: String(view.getUint32(off + 24, false)),
    tid,
  };
}

// --- Return parsers ---

function parseReturn32(view: DataView, off: number, event: AuditEvent): number {
  const errno = view.getUint8(off);
  const retval = view.getUint32(off + 1, false);
  event.return = makeReturn(errno, retval);
  return off + 5;
}

function parseReturn64(view: DataView, off: number, event: AuditEvent): number {
  const errno = view.getUint8(off);
  const retval = Number(view.getBigUint64(off + 1, false));
  event.return = makeReturn(errno, retval);
  return off + 9;
}

function makeReturn(errno: number, retval: number): AuditReturn {
  const errval = errno === 0 ? "success" : `failure: ${ERRNO_NAMES[errno] ?? `errno ${errno}`}`;
  return { errval, retval: String(retval) };
}

// --- String token parsers ---

function parsePath(view: DataView, off: number, buf: Uint8Array, event: AuditEvent): number {
  const len = view.getUint16(off, false);
  if (off + 2 + len > buf.byteLength) return buf.byteLength;
  const str = decodeString(buf, off + 2, len);
  event.paths.push(str);
  return off + 2 + len;
}

function parseText(view: DataView, off: number, buf: Uint8Array, event: AuditEvent): number {
  const len = view.getUint16(off, false);
  if (off + 2 + len > buf.byteLength) return buf.byteLength;
  const str = decodeString(buf, off + 2, len);
  event.text.push(str);
  return off + 2 + len;
}

function parseExecArgs(view: DataView, off: number, buf: Uint8Array, event: AuditEvent): number {
  const count = view.getUint32(off, false);
  if (count > 10_000) return off + 4; // sanity cap — no real exec has 10k args
  let pos = off + 4;
  for (let i = 0; i < count; i++) {
    if (pos >= buf.byteLength) break;
    const nulIdx = buf.indexOf(0, pos);
    if (nulIdx === -1 || nulIdx >= buf.byteLength) break;
    event.execArgs.push(textDecoder.decode(buf.subarray(pos, nulIdx)));
    pos = nulIdx + 1;
  }
  return pos;
}

// --- Data token parser ---

const DATA_UNIT_SIZES = [1, 2, 4, 8] as const;

function parseData(view: DataView, off: number, buf: Uint8Array): number {
  // how_to_print(1) + basic_unit(1) + unit_count(1) + data(variable)
  const basicUnit = view.getUint8(off + 1);
  const unitCount = view.getUint8(off + 2);
  // Fallback to 1-byte units for unrecognized basicUnit values (defensive)
  const unitSize = DATA_UNIT_SIZES[basicUnit] ?? 1;
  const end = off + 3 + unitCount * unitSize;
  if (end > buf.byteLength) return buf.byteLength;
  return end;
}

// --- Argument parsers ---

function parseArg32(view: DataView, off: number, buf: Uint8Array, event: AuditEvent): number {
  const argNum = view.getUint8(off);
  const value = view.getUint32(off + 1, false);
  const descLen = view.getUint16(off + 5, false);
  if (off + 7 + descLen > buf.byteLength) return buf.byteLength;
  const desc = decodeString(buf, off + 7, descLen);
  event.arguments.push({ argNum: String(argNum), value: `0x${value.toString(16)}`, desc });
  return off + 7 + descLen;
}

function parseArg64(view: DataView, off: number, buf: Uint8Array, event: AuditEvent): number {
  const argNum = view.getUint8(off);
  const value = view.getBigUint64(off + 1, false);
  const descLen = view.getUint16(off + 9, false);
  if (off + 11 + descLen > buf.byteLength) return buf.byteLength;
  const desc = decodeString(buf, off + 11, descLen);
  event.arguments.push({ argNum: String(argNum), value: `0x${value.toString(16)}`, desc });
  return off + 11 + descLen;
}

// --- Attribute parsers ---

function parseAttr32(view: DataView, off: number, event: AuditEvent): number {
  event.attributes.push(readAttrFields(view, off, 4));
  return off + 28;
}

function parseAttr64(view: DataView, off: number, event: AuditEvent): number {
  event.attributes.push(readAttrFields(view, off, 8));
  return off + 32;
}

function readAttrFields(view: DataView, off: number, devSize: number): AuditAttribute {
  const mode = view.getUint32(off, false);
  const uid = view.getUint32(off + 4, false);
  const gid = view.getUint32(off + 8, false);
  const fsid = view.getUint32(off + 12, false);
  const nodeid = view.getBigUint64(off + 16, false);
  const device = devSize === 4 ? view.getUint32(off + 24, false) : Number(view.getBigUint64(off + 24, false));
  return {
    mode: mode.toString(8).padStart(6, "0"),
    uid: String(uid),
    gid: String(gid),
    fsid: String(fsid),
    nodeid: String(nodeid),
    device: String(device),
  };
}

// --- Identity parser (Apple AUT_IDENTITY 0xed) ---

function parseIdentity(view: DataView, off: number, buf: Uint8Array, event: AuditEvent): number {
  // signer_type(4) + signing_id_len(2) + signing_id(n) + truncated(1) +
  // team_id_len(2) + team_id(n) + truncated(1) + cdhash_len(2) + cdhash(n)
  if (off + 6 > buf.byteLength) return buf.byteLength;
  const signerType = view.getUint32(off, false);
  const signingIdLen = view.getUint16(off + 4, false);
  if (off + 6 + signingIdLen + 1 > buf.byteLength) return buf.byteLength;
  const signingId = decodeString(buf, off + 6, signingIdLen);
  let pos = off + 6 + signingIdLen + 1; // +1 for truncated flag

  if (pos + 2 > buf.byteLength) return buf.byteLength;
  const teamIdLen = view.getUint16(pos, false);
  if (pos + 2 + teamIdLen + 1 > buf.byteLength) return buf.byteLength;
  const teamId = decodeString(buf, pos + 2, teamIdLen);
  pos = pos + 2 + teamIdLen + 1; // +1 for truncated flag

  if (pos + 2 > buf.byteLength) return buf.byteLength;
  const cdhashLen = view.getUint16(pos, false);
  if (pos + 2 + cdhashLen > buf.byteLength) return buf.byteLength;
  const cdhashBytes = buf.subarray(pos + 2, pos + 2 + cdhashLen);
  const cdhash = Array.from(cdhashBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  event.identity = { signerType, signingId, teamId, cdhash };
  return pos + 2 + cdhashLen;
}

// --- Trailer ---

function parseTrailer(view: DataView, off: number, expectedSize: number): number {
  const magic = view.getUint16(off, false);
  const size = view.getUint32(off + 2, false);
  if (magic !== TRAILER_MAGIC) {
    console.error(`[bsmtap] Bad trailer magic: 0x${magic.toString(16)} (expected 0xb105)`);
  }
  if (expectedSize > 0 && size !== expectedSize) {
    console.error(`[bsmtap] Trailer size mismatch: ${size} vs header ${expectedSize}`);
  }
  return off + 6;
}

// --- Helpers ---

/** Convert Unix seconds + microseconds (tv_sec, tv_usec) to ISO 8601. */
function toIso8601(seconds: number, usec: number): string {
  const date = new Date(seconds * 1000 + Math.floor(usec / 1000));
  return date.toISOString();
}

function formatIpv4(view: DataView, off: number): string {
  return `${view.getUint8(off)}.${view.getUint8(off + 1)}.${view.getUint8(off + 2)}.${view.getUint8(off + 3)}`;
}

function formatIpv6(view: DataView, off: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 8; i++) {
    parts.push(view.getUint16(off + i * 2, false).toString(16));
  }
  // Find the longest run of consecutive zeros (RFC 5952: collapse the longest, first wins ties)
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (parts[i] === "0") {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) return parts.join(":");
  const before = parts.slice(0, bestStart).join(":");
  const after = parts.slice(bestStart + bestLen).join(":");
  return `${before}::${after}`;
}

/** Decode a NUL-terminated length-prefixed string. Length includes the NUL byte. */
function decodeString(buf: Uint8Array, off: number, len: number): string {
  if (len <= 1) return "";
  return textDecoder.decode(buf.subarray(off, off + len - 1));
}

// --- Stream record extraction ---

/**
 * Extract complete BSM records from a binary buffer.
 * Returns parsed records and the number of bytes consumed.
 */
export function extractRecords(buf: Uint8Array): { events: AuditEvent[]; consumed: number } {
  const events: AuditEvent[] = [];
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let offset = 0;

  while (offset < buf.byteLength) {
    // Need at least 1 (token ID) + 4 (size) bytes to read header
    if (buf.byteLength - offset < 5) break;

    const tokenId = buf[offset]!;
    if (
      tokenId !== AUT_HEADER32 &&
      tokenId !== AUT_HEADER64 &&
      tokenId !== AUT_HEADER32_EX &&
      tokenId !== AUT_HEADER64_EX
    ) {
      // Not a header — skip byte and try to resync
      offset += 1;
      continue;
    }

    const recordSize = view.getUint32(offset + 1, false);

    if (recordSize < 7 || recordSize > 1_048_576) {
      // Invalid size — skip and resync
      offset += 1;
      continue;
    }

    // Wait for complete record
    if (buf.byteLength - offset < recordSize) break;

    const recordBuf = buf.subarray(offset, offset + recordSize);
    try {
      events.push(parseRecord(recordBuf));
    } catch (err) {
      console.error(`[bsmtap] Failed to parse record at offset ${offset}: ${err}`);
    }
    offset += recordSize;
  }

  return { events, consumed: offset };
}
