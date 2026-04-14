import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AuditEvent } from "./schema.ts";
import { JsonLineFileWriter } from "./writer.ts";

function makeEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    timestamp: "2026-04-14T10:30:00.123Z",
    event: "execve(2)",
    modifier: "0",
    version: "11",
    subject: null,
    return: { errval: "success", retval: "0" },
    paths: [],
    execArgs: [],
    text: [],
    attributes: [],
    arguments: [],
    raw: "<record />",
    ...overrides,
  };
}

describe("JsonLineFileWriter", () => {
  const dirs: string[] = [];

  afterEach(() => {
    for (const dir of dirs) {
      rmSync(dir, { recursive: true, force: true });
    }
    dirs.length = 0;
  });

  function makeTempDir(): string {
    const dir = mkdtempSync(join(tmpdir(), "audit-bridge-test-"));
    dirs.push(dir);
    return dir;
  }

  test("writes JSON Lines to output file", async () => {
    const dir = makeTempDir();
    const outputPath = join(dir, "audit.jsonl");
    const pidPath = join(dir, "bridge.pid");

    const writer = new JsonLineFileWriter(outputPath, pidPath);
    writer.open();

    await writer.write(makeEvent({ event: "event1" }));
    await writer.write(makeEvent({ event: "event2" }));
    writer.close();

    const lines = readFileSync(outputPath, "utf-8").trim().split("\n");
    expect(lines).toHaveLength(2);

    const parsed1 = JSON.parse(lines[0] as string);
    expect(parsed1.event).toBe("event1");

    const parsed2 = JSON.parse(lines[1] as string);
    expect(parsed2.event).toBe("event2");
  });

  test("writes PID file on open and removes on close", async () => {
    const dir = makeTempDir();
    const outputPath = join(dir, "audit.jsonl");
    const pidPath = join(dir, "bridge.pid");

    const writer = new JsonLineFileWriter(outputPath, pidPath);
    writer.open();

    expect(existsSync(pidPath)).toBe(true);
    const pid = readFileSync(pidPath, "utf-8").trim();
    expect(pid).toBe(String(process.pid));

    writer.close();
    expect(existsSync(pidPath)).toBe(false);
  });

  test("each line is valid JSON", async () => {
    const dir = makeTempDir();
    const outputPath = join(dir, "audit.jsonl");
    const pidPath = join(dir, "bridge.pid");

    const writer = new JsonLineFileWriter(outputPath, pidPath);
    writer.open();

    for (let i = 0; i < 5; i++) {
      await writer.write(makeEvent({ event: `event-${i}` }));
    }
    writer.close();

    const lines = readFileSync(outputPath, "utf-8").trim().split("\n");
    expect(lines).toHaveLength(5);
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  test("reopen creates new file handle", async () => {
    const dir = makeTempDir();
    const outputPath = join(dir, "audit.jsonl");
    const pidPath = join(dir, "bridge.pid");

    const writer = new JsonLineFileWriter(outputPath, pidPath);
    writer.open();

    await writer.write(makeEvent({ event: "before-rotate" }));

    // Simulate newsyslog: rename old file, then signal reopen
    const rotatedPath = join(dir, "audit.jsonl.0");
    const { renameSync } = await import("node:fs");
    renameSync(outputPath, rotatedPath);

    writer.reopen();

    await writer.write(makeEvent({ event: "after-rotate" }));
    writer.close();

    // Old file should have the pre-rotation event
    const oldLines = readFileSync(rotatedPath, "utf-8").trim().split("\n");
    expect(oldLines).toHaveLength(1);
    expect(JSON.parse(oldLines[0] as string).event).toBe("before-rotate");

    // New file should have the post-rotation event
    const newLines = readFileSync(outputPath, "utf-8").trim().split("\n");
    expect(newLines).toHaveLength(1);
    expect(JSON.parse(newLines[0] as string).event).toBe("after-rotate");
  });

  test("SIGHUP triggers reopen when wired as in main.ts", async () => {
    const dir = makeTempDir();
    const outputPath = join(dir, "audit.jsonl");
    const pidPath = join(dir, "bridge.pid");

    const writer = new JsonLineFileWriter(outputPath, pidPath);
    writer.open();

    // Wire SIGHUP → reopen, as main.ts does
    const handler = () => writer.reopen();
    process.on("SIGHUP", handler);

    await writer.write(makeEvent({ event: "before-sighup" }));

    // Simulate newsyslog: rename old file, then signal
    const rotatedPath = join(dir, "audit.jsonl.0");
    const { renameSync } = await import("node:fs");
    renameSync(outputPath, rotatedPath);

    process.kill(process.pid, "SIGHUP");
    // Allow signal handler to run
    await new Promise((resolve) => setTimeout(resolve, 50));

    await writer.write(makeEvent({ event: "after-sighup" }));

    process.removeListener("SIGHUP", handler);
    writer.close();

    const oldLines = readFileSync(rotatedPath, "utf-8").trim().split("\n");
    expect(oldLines).toHaveLength(1);
    expect(JSON.parse(oldLines[0] as string).event).toBe("before-sighup");

    const newLines = readFileSync(outputPath, "utf-8").trim().split("\n");
    expect(newLines).toHaveLength(1);
    expect(JSON.parse(newLines[0] as string).event).toBe("after-sighup");
  });
});
