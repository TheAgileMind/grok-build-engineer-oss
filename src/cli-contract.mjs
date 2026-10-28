import { validateRunReceipt } from "./contracts.mjs";
import { redactForBoundary } from "./redaction.mjs";

export const CLI_CONTRACT_VERSION = "agent-platform.grok-build-engineer-cli.v2";
export const CLI_OPERATIONS = Object.freeze(["prepare", "submit", "status", "collect", "cancel", "repair"]);
export const MUTATING_OPERATIONS = Object.freeze(["submit", "collect", "cancel", "repair"]);
export const CLI_EXIT_CODES = Object.freeze({ ok: 0, rejected: 65, not_found: 66, invalid_input: 64, recovery_required: 75, unsupported: 69, internal: 70 });
export const MIGRATION_REQUIRED = Object.freeze({ code: "migration_required", message: "Use scripts/grok-delegate.mjs for mutating lifecycle operations." });
const LIVE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const LIVE_DIGEST = /^sha256:[a-f0-9]{64}$/;

export function validateLiveReceipt(value, taskRunId = null) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("live receipt must be an object");
  if (value.contractVersion !== "agent-platform.grok-build-engineer-one-shot.v1") throw new TypeError("live receipt contractVersion is unsupported");
  if (typeof value.taskRunId !== "string" || (taskRunId !== null && value.taskRunId !== taskRunId)) throw new TypeError("live receipt taskRunId is invalid");
  if (typeof value.requestId !== "string" || !/^[a-z][a-z0-9_-]{2,63}$/.test(value.requestId)) throw new TypeError("live receipt requestId is invalid");
  if (!['starting', 'running'].includes(value.state)) throw new TypeError("live receipt state is invalid");
  if (typeof value.ownerNonce !== "string" || !value.ownerNonce) throw new TypeError("live receipt ownerNonce is invalid");
  if (typeof value.sessionId !== "string" || !LIVE_UUID.test(value.sessionId)) throw new TypeError("live receipt sessionId is invalid");
  if (value.state === "starting" ? value.pid !== null && value.pid !== undefined : !Number.isSafeInteger(value.pid) || value.pid < 2) throw new TypeError("live receipt pid is invalid");
  if (!value.binding || typeof value.binding !== "object" || typeof value.binding.sourceSha !== "string" || typeof value.binding.repositoryRoot !== "string" || typeof value.binding.worktree !== "string" || !LIVE_DIGEST.test(value.binding.custodyDigest) || !LIVE_DIGEST.test(value.binding.diffDigest)) throw new TypeError("live receipt binding is invalid");
  return value;
}

export function validateCliRequest(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("CLI request must be an object");
  if (!CLI_OPERATIONS.includes(value.operation)) throw new TypeError("CLI operation is unsupported");
  if (value.operation !== "prepare" && (typeof value.taskRunId !== "string" || !value.taskRunId)) throw new TypeError("CLI taskRunId is required");
  return Object.freeze({ contractVersion: CLI_CONTRACT_VERSION, operation: value.operation, taskRunId: value.taskRunId });
}

export function cliResponse(operation, taskRunId = null, result = {}) {
  if (!CLI_OPERATIONS.includes(operation)) throw new TypeError("CLI operation is unsupported");
  if (result.receipt !== undefined && result.receipt !== null) { if (["starting", "running"].includes(result.receipt.state)) validateLiveReceipt(result.receipt, taskRunId); else validateRunReceipt(result.receipt); }
  return Object.freeze({ contractVersion: CLI_CONTRACT_VERSION, ok: true, operation, taskRunId, ...result });
}

export function cliErrorResponse(operation = null, taskRunId = null, error = {}) {
  const code = error?.code ?? "cli_error";
  return Object.freeze({ contractVersion: CLI_CONTRACT_VERSION, ok: false, operation, taskRunId, error: { code, message: String(redactForBoundary(error?.message ?? error)).slice(0, 512) }, exitCode: CLI_EXIT_CODES[code] ?? (code === "recovery_required" ? CLI_EXIT_CODES.recovery_required : CLI_EXIT_CODES.invalid_input) });
}

export function cliHelpResponse() {
  return Object.freeze({ contractVersion: CLI_CONTRACT_VERSION, ok: true, operation: "help", taskRunId: null, usage: Object.freeze({
    prepare: "grok-delegate prepare --input <task-or-repair-packet.json>",
    submit: "grok-delegate submit --packet <prepared-task.json> [--approval <approval.json>]",
    status: "grok-delegate status --state-root <directory> --task-run-id <id>",
    repair: "grok-delegate repair --packet <prepared-repair.json> --findings <findings.json> [--approval <approval.json>]",
    collect: "grok-delegate collect --state-root <directory> --task-run-id <id> --acceptance <acceptance.json>",
    cancel: "grok-delegate cancel --state-root <directory> --task-run-id <id>"
  }) });
}

export function migrationRequiredResponse(tool) {
  if (!["grok_submit", "grok_collect", "grok_cancel"].includes(tool)) throw new TypeError("tool is not a retired mutating MCP operation");
  return Object.freeze({ contractVersion: CLI_CONTRACT_VERSION, ok: false, tool, error: MIGRATION_REQUIRED });
}
