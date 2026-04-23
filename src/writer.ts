import { closeSync, constants, openSync, unlinkSync, write, writeFileSync } from "node:fs";
import type { AuditEvent, Writer } from "./schema.ts";

export class JsonLineFileWriter implements Writer {
  private fd: number | null = null;
  private readonly outputPath: string;
  private readonly pidPath: string;

  constructor(outputPath: string, pidPath: string) {
    this.outputPath = outputPath;
    this.pidPath = pidPath;
  }

  open(): void {
    try {
      this.fd = openSync(this.outputPath, constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND);
    } catch (err: unknown) {
      const code = err instanceof Error && "code" in err ? (err as NodeJS.ErrnoException).code : undefined;
      if (code === "ENOENT") {
        const dir = this.outputPath.replace(/\/[^/]*$/, "");
        throw new Error(`Output directory does not exist: ${dir}`);
      }
      throw err;
    }
    this.writePidFile();
  }

  async write(event: AuditEvent): Promise<void> {
    if (this.fd === null) throw new Error("Writer not opened");
    const buf = Buffer.from(`${JSON.stringify(event)}\n`);
    const fd = this.fd;
    return new Promise((resolve, reject) => {
      write(fd, buf, 0, buf.length, null, (err) => (err ? reject(err) : resolve()));
    });
  }

  close(): void {
    if (this.fd !== null) {
      closeSync(this.fd);
      this.fd = null;
    }
    this.removePidFile();
  }

  /** Called on SIGHUP — close old fd and reopen for newsyslog rotation. */
  reopen(): void {
    if (this.fd !== null) {
      closeSync(this.fd);
    }
    try {
      this.fd = openSync(this.outputPath, constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND);
    } catch (err: unknown) {
      const code = err instanceof Error && "code" in err ? (err as NodeJS.ErrnoException).code : undefined;
      if (code === "ENOENT") {
        const dir = this.outputPath.replace(/\/[^/]*$/, "");
        throw new Error(`Output directory does not exist: ${dir}`);
      }
      throw err;
    }
    console.error("[bsmtap] Reopened output file after rotation");
  }

  private writePidFile(): void {
    try {
      writeFileSync(this.pidPath, `${process.pid}\n`);
    } catch (err) {
      console.error(`[bsmtap] Failed to write PID file: ${err}`);
    }
  }

  private removePidFile(): void {
    try {
      unlinkSync(this.pidPath);
    } catch {
      // PID file may already be gone
    }
  }
}
