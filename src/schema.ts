/** Structured representation of a macOS OpenBSM audit event, parsed from binary BSM tokens. */
export interface AuditEvent {
  /** ISO 8601 timestamp of the event. */
  timestamp: string;
  /** Event name from the BSM header token (e.g., "execve(2)", "user authentication", "OpenSSH login"). */
  event: string;
  /** Numeric event modifier flags. */
  modifier: string;
  /** BSM header version (typically "11" for OpenBSM 1.1). */
  version: string;
  /** Subject who triggered the event (may be null for system-level events). */
  subject: AuditSubject | null;
  /** Return value of the audited operation. */
  return: AuditReturn | null;
  /** File paths referenced in the event. */
  paths: string[];
  /** Command-line arguments from exec_args tokens (when present). */
  execArgs: string[];
  /** Text tokens (e.g., authentication messages). */
  text: string[];
  /** File attribute tokens. */
  attributes: AuditAttribute[];
  /** Argument tokens (syscall arguments). */
  arguments: AuditArgument[];
}

export interface AuditSubject {
  /** Audit user ID (login name or numeric). */
  auditUid: string;
  /** Effective user ID. */
  uid: string;
  /** Effective group ID. */
  gid: string;
  /** Real user ID. */
  ruid: string;
  /** Real group ID. */
  rgid: string;
  /** Process ID. */
  pid: string;
  /** Session ID. */
  sid: string;
  /** Terminal ID — compound "port ip" value. */
  tid: string;
}

export interface AuditReturn {
  /** Error description (e.g., "success", "failure: Operation not permitted"). */
  errval: string;
  /** Numeric return value. */
  retval: string;
}

export interface AuditAttribute {
  mode: string;
  uid: string;
  gid: string;
  fsid: string;
  nodeid: string;
  device: string;
}

export interface AuditArgument {
  argNum: string;
  value: string;
  desc: string;
}

/** Writer interface for pluggable output sinks. */
export interface Writer {
  write(event: AuditEvent): Promise<void>;
  close(): void | Promise<void>;
}
