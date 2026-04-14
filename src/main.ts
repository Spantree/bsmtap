import { AuditPipeReader } from "./reader.ts";
import { JsonLineFileWriter } from "./writer.ts";

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
