import pkg from "../package.json";
import { AuditPipeReader } from "./reader.ts";
import { JsonLineFileWriter } from "./writer.ts";

const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  console.log(`bsmtap v${pkg.version} — ${pkg.description}

Taps macOS OpenBSM audit events and streams them as JSON Lines.

Usage: bsmtap [options]

Options:
  -h, --help       Show this help message
  -v, --version    Show version number

Environment variables:
  BSMTAP_OUTPUT    Output file path (default: /var/log/bsmtap/audit.jsonl)
  BSMTAP_PID       PID file path (default: /var/run/bsmtap.pid)
  AUDITPIPE_PATH   Audit pipe device (default: /dev/auditpipe)`);
  process.exit(0);
}

if (args.includes("--version") || args.includes("-v")) {
  console.log(pkg.version);
  process.exit(0);
}

const OUTPUT_PATH = process.env.BSMTAP_OUTPUT ?? "/var/log/bsmtap/audit.jsonl";
const PID_PATH = process.env.BSMTAP_PID ?? "/var/run/bsmtap.pid";
const AUDITPIPE_PATH = process.env.AUDITPIPE_PATH ?? "/dev/auditpipe";

console.error(`[bsmtap] Starting (pid=${process.pid})`);
console.error(`[bsmtap]   output: ${OUTPUT_PATH}`);
console.error(`[bsmtap]   auditpipe: ${AUDITPIPE_PATH}`);

const writer = new JsonLineFileWriter(OUTPUT_PATH, PID_PATH);
writer.open();

const reader = new AuditPipeReader({
  auditpipePath: AUDITPIPE_PATH,
  onEvent: async (event) => {
    await writer.write(event);
  },
  onError: (msg) => {
    console.error(`[bsmtap] ${msg}`);
  },
});

function shutdown(): void {
  console.error("[bsmtap] Shutting down...");
  reader.stop();
  writer.close();
  console.error("[bsmtap] Shutdown complete");
  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
process.on("SIGHUP", () => {
  console.error("[bsmtap] Received SIGHUP — reopening output file");
  writer.reopen();
});

reader.start().catch((err) => {
  console.error(`[bsmtap] Fatal: ${err}`);
  writer.close();
  process.exit(1);
});
