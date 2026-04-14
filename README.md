# bsmtap

A streaming daemon that taps macOS OpenBSM audit events from `/dev/auditpipe` and writes structured JSON Lines to disk.

## What it does

```
/dev/auditpipe (binary BSM) --> bsmtap --> /var/log/bsmtap/audit.jsonl (JSON Lines)
```

bsmtap reads the macOS kernel audit stream directly, parses OpenBSM binary tokens in-process (no `praudit` dependency), and emits one JSON object per audit event. Designed to run as a root LaunchDaemon.

## Output format

Each line is a JSON object:

```json
{
  "timestamp": "2026-04-14T10:30:00.123Z",
  "event": "execve(2)",
  "modifier": "0",
  "version": "11",
  "subject": {
    "auditUid": "501",
    "uid": "501",
    "gid": "20",
    "ruid": "501",
    "rgid": "20",
    "pid": "1234",
    "sid": "100001",
    "tid": "1234 127.0.0.1"
  },
  "return": { "errval": "success", "retval": "0" },
  "paths": ["/usr/bin/ls"],
  "execArgs": ["/usr/bin/ls", "-la", "/tmp"],
  "text": [],
  "attributes": [{ "mode": "100755", "uid": "0", "gid": "0", "fsid": "16777220", "nodeid": "12345678", "device": "16777220" }],
  "arguments": [],
  "raw": ""
}
```

## Requirements

- macOS (Apple Silicon or Intel)
- [Bun](https://bun.sh) runtime
- Root privileges (`/dev/auditpipe` requires root)
- `auditd` enabled and configured

## Install

```bash
bun install
```

## Usage

```bash
# Run directly (requires root)
sudo bun run src/main.ts

# Build standalone binary
bun run build
sudo ./bsmtap
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BSMTAP_OUTPUT` | `/var/log/bsmtap/audit.jsonl` | JSON Lines output path |
| `BSMTAP_PID` | `/var/run/bsmtap.pid` | PID file path (for newsyslog SIGHUP) |
| `AUDITPIPE_PATH` | `/dev/auditpipe` | Audit pipe device path |

### Signals

- `SIGHUP` - reopen output file (for log rotation)
- `SIGTERM` / `SIGINT` - graceful shutdown

### Log rotation

bsmtap supports log rotation via `SIGHUP`. It writes its PID to the file specified by `BSMTAP_PID` (default `/var/run/bsmtap.pid`) so that log rotation tools can signal it.

**With newsyslog** (macOS built-in), add to `/etc/newsyslog.d/bsmtap.conf`:

```
# logfilename                    [owner:group] mode count size(KB) when flags [/pid_file]
/var/log/bsmtap/audit.jsonl       root:wheel    640  5     10240    *    N     /var/run/bsmtap.pid
```

The `N` flag keeps rotated files uncompressed (queryable with `jq`). newsyslog will:

1. Rename `audit.jsonl` to `audit.jsonl.0`
2. Send `SIGHUP` to the PID in `/var/run/bsmtap.pid`
3. bsmtap closes the old file descriptor and opens a fresh `audit.jsonl`

**Manual rotation:**

```bash
mv /var/log/bsmtap/audit.jsonl /var/log/bsmtap/audit.jsonl.1
kill -HUP $(cat /var/run/bsmtap.pid)
```

## Supported BSM tokens

| Token | ID | Description |
|-------|-----|------------|
| header32 / header64 | 0x14 / 0x74 | Record header with timestamp |
| header32_ex / header64_ex | 0x15 / 0x79 | Extended header with host address |
| subject32 / subject64 | 0x24 / 0x75 | Process subject |
| subject32_ex / subject64_ex | 0x7a / 0x7c | Extended subject with IPv6 |
| return32 / return64 | 0x27 / 0x72 | Syscall return value |
| path | 0x23 | File path |
| text | 0x28 | Text string |
| exec_args | 0x3c | Command-line arguments |
| arg32 / arg64 | 0x2d / 0x71 | Syscall argument |
| attr32 / attr64 | 0x3e / 0x73 | File attributes |
| trailer | 0x13 | Record trailer (integrity check) |

Unknown tokens are logged and skipped without crashing.

## Testing

```bash
bun test              # run tests
bun test --coverage   # run with coverage report
```

Coverage: 100% functions, 99.6% lines.

## Architecture

Two core modules, zero runtime dependencies:

- **`bsm-parser.ts`** - Parses OpenBSM binary tokens using `DataView` (big-endian). Extracts complete records from a byte stream, handles all 32/64-bit token variants, and survives malformed data gracefully.
- **`reader.ts`** - Reads `/dev/auditpipe` via `Bun.file().stream()`, feeds chunks to the parser, delivers events to the writer.
- **`writer.ts`** - Appends JSON Lines to disk with `O_APPEND`. Writes PID file for newsyslog. Reopens on SIGHUP for log rotation.

## License

Apache License 2.0 - see [LICENSE](LICENSE).

Copyright 2026 Spantree Technology Group, LLC.
