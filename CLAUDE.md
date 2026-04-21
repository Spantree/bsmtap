# bsmtap

BSM-to-JSON streaming daemon — taps macOS OpenBSM audit events from `/dev/auditpipe` into structured JSON Lines.

## Commands

- `bun test` — run all tests
- `bun test --coverage` — run tests with coverage
- `bun run typecheck` — typecheck (tsc --noEmit)
- `bun run lint:fix` — auto-fix lint + formatting
- `bun run format` — auto-fix formatting only
- `bun run lint:ci` — lint check as CI runs it

### Pre-push verification

Run all three CI checks before pushing:

```sh
bun run lint:ci && bun run typecheck && bun test
```

## Code style

Enforced by Biome — do not override manually:

- Double quotes, trailing commas, 2-space indent, 120-char line width
- Imports are auto-organized by Biome

## Architecture

All source is in `src/`:

- `schema.ts` — `AuditEvent` and related types (the shared contract)
- `bsm-parser.ts` — binary token parser: each token type has a `parse*` function that takes `(view, offset, [buf], event)` and returns the new offset. All multi-byte reads are big-endian.
- `reader.ts` — `AuditPipeReader`: reads raw bytes from `/dev/auditpipe`, uses `extractRecords()` to frame and parse
- `writer.ts` — `JsonLineFileWriter`: writes `AuditEvent` objects as JSON Lines with SIGHUP-based file rotation
- `main.ts` — wires reader → writer

## Gotchas

- Adding a field to `AuditEvent` in `schema.ts` requires updating the initializer in `bsm-parser.ts:parseRecord` AND `makeEvent()` in `writer.test.ts` — typecheck catches this
- Token parser tests use binary builder helpers (`bsm()`, `buildRecord()`, token-specific builders) at the top of `bsm-parser.test.ts`
- CI runs on Ubuntu but the daemon targets macOS — reader tests use temp FIFOs to simulate `/dev/auditpipe`
