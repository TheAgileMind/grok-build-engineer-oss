import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { PRETOOL_GUARD_VERSION } from "./pretool-guard.mjs";

const GUARD_SCRIPT = fileURLToPath(new URL("../scripts/grok-pretool-guard.mjs", import.meta.url));
const GUARD_EVENT_VERSION = "agent-platform.grok-build-engineer-pretool-event.v1";
const MAX_GUARD_EVIDENCE_BYTES = 1024 * 1024;
const MAX_GUARD_EVENTS = 10_000;
function digest(value) { return `sha256:${createHash("sha256").update(value).digest("hex")}`; }
function plainDirectory(path, label) { if (existsSync(path) && (!lstatSync(path).isDirectory() || lstatSync(path).isSymbolicLink())) throw new TypeError(`${label} must be a plain directory`); }
function plainFile(path, label) {
  if (!existsSync(path)) throw new TypeError(`${label} does not exist`);
  const details = lstatSync(path);
  if (!details.isFile() || details.isSymbolicLink() || (details.mode & 0o170000) === 0o120000) throw new TypeError(`${label} must be a plain regular file`);
  if (details.size > MAX_GUARD_EVIDENCE_BYTES) throw new TypeError(`${label} exceeds its bounded byte allowance`);
  return details;
}
function quote(value) { return `"${String(value).replaceAll('"', '\\"')}"`; }
function hookEvent(value) { return typeof value === "string" && ["pre_tool_use", "pretooluse"].includes(value.toLowerCase().replaceAll("-", "_")); }
function rewritesInput(hook) {
  if (!hook || typeof hook !== "object") return false;
  return hook.inputRewrite === true || hook.input_rewrite === true || hook.rewritesInput === true || hook.rewrites_input === true || hook.modifiesInput === true || hook.modifies_input === true || ["rewrite", "input_rewriter", "input-rewriter", "transform"].includes(String(hook.hookType ?? hook.type ?? hook.kind ?? hook.effect ?? "").toLowerCase());
}

export function installPreToolGuard({ packet, policy, sessionId, nodeExecutable = process.execPath, hookRoot = join(homedir(), ".grok", "hooks") }) {
  if (policy?.network !== "none") throw new TypeError("network policy is unavailable to the Grok hook guard");
  const worktree = resolve(packet.worktree);
  const policyDirectory = join(resolve(packet.stateRoot), "guards");
  mkdirSync(policyDirectory, { recursive: true, mode: 0o700 });
  const policyPath = join(policyDirectory, `${packet.taskRunId}-${packet.requestId}.json`);
  const evidencePath = join(policyDirectory, `${packet.taskRunId}-${packet.requestId}.events.jsonl`);
  const payload = Object.freeze({ contractVersion: PRETOOL_GUARD_VERSION, taskRunId: packet.taskRunId, requestId: packet.requestId, sessionId, worktree, paths: [...policy.paths], commands: [...policy.commands], tools: [...policy.tools], network: policy.network });
  const policyBytes = Buffer.from(`${JSON.stringify(payload)}\n`, "utf8");
  const policyDigest = digest(policyBytes);
  if (existsSync(policyPath) || existsSync(evidencePath)) throw new TypeError("guard evidence already exists");
  writeFileSync(policyPath, policyBytes, { flag: "wx", mode: 0o600 });
  writeFileSync(evidencePath, "", { flag: "wx", mode: 0o600 });
  const hooksDirectory = resolve(hookRoot);
  const sourceRoot = dirname(hooksDirectory);
  const hooksExisted = existsSync(hooksDirectory);
  const hookPath = join(hooksDirectory, `grok-build-engineer-${packet.requestId}.json`);
  const command = `${quote(nodeExecutable)} ${quote(GUARD_SCRIPT)} --policy ${quote(policyPath)} --digest ${policyDigest} --evidence ${quote(evidencePath)}`;
  try {
    plainDirectory(sourceRoot, "Grok user configuration path");
    plainDirectory(hooksDirectory, "Grok user hook path");
    mkdirSync(hooksDirectory, { recursive: true });
    if (existsSync(hookPath)) throw new TypeError("guard hook overlay already exists");
    const hook = { hooks: { PreToolUse: [{ hooks: [{ type: "command", command, timeout: 10 }] }] } };
    writeFileSync(hookPath, `${JSON.stringify(hook)}\n`, { flag: "wx", mode: 0o600 });
  } catch (error) {
    try { if (existsSync(hookPath)) unlinkSync(hookPath); } catch {}
    try { if (existsSync(policyPath)) unlinkSync(policyPath); } catch {}
    try { if (existsSync(evidencePath)) unlinkSync(evidencePath); } catch {}
    throw error;
  }
  const hookDigest = digest(readFileSync(hookPath));
  let removed = false;
  return Object.freeze({
    hookPath, hookDigest, policyPath, policyDigest, evidencePath, command, sourceRoot, hooksDirectory,
    verify() {
      if (!existsSync(hookPath) || digest(readFileSync(hookPath)) !== hookDigest || !existsSync(policyPath) || digest(readFileSync(policyPath)) !== policyDigest) throw new TypeError("guard overlay integrity check failed");
      plainFile(evidencePath, "guard event evidence");
      return true;
    },
    readEvidence() {
      plainFile(evidencePath, "guard event evidence");
      const text = readFileSync(evidencePath, "utf8");
      if (!text) return Object.freeze([]);
      const lines = text.split("\n");
      if (lines.pop() !== "" || lines.length > MAX_GUARD_EVENTS) throw new TypeError("guard event evidence is malformed");
      const records = lines.map((line, index) => {
        let record;
        try { record = JSON.parse(line); } catch { throw new TypeError(`guard event evidence record ${index} is malformed`); }
        if (!record || typeof record !== "object" || Array.isArray(record) || Object.keys(record).length !== 8 || ["contractVersion", "taskRunId", "requestId", "sessionId", "decision", "reason", "toolName", "eventDigest"].some((key) => !Object.prototype.hasOwnProperty.call(record, key))) throw new TypeError(`guard event evidence record ${index} is invalid`);
        if (record.contractVersion !== GUARD_EVENT_VERSION || record.taskRunId !== payload.taskRunId || record.requestId !== payload.requestId || record.sessionId !== payload.sessionId || !["allow", "deny"].includes(record.decision) || typeof record.reason !== "string" || record.reason.length === 0 || record.reason.length > 512 || typeof record.toolName !== "string" || record.toolName.length === 0 || record.toolName.length > 512 || typeof record.eventDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(record.eventDigest)) throw new TypeError(`guard event evidence record ${index} is invalid`);
        return Object.freeze({ ...record });
      });
      return Object.freeze(records);
    },
    remove() {
      if (removed) return;
      let integrityError = null;
      try { this.verify(); } catch (error) { integrityError = error; }
      try { if (existsSync(hookPath)) unlinkSync(hookPath); } finally {
        try { if (existsSync(policyPath)) unlinkSync(policyPath); } finally {
          if (!hooksExisted && existsSync(hooksDirectory)) rmdirSync(hooksDirectory);
          removed = true;
        }
      }
      if (integrityError) throw integrityError;
    }
  });
}

export function assertGuardDiscovered(inspect, overlay) {
  if (!inspect || typeof inspect !== "object") throw new TypeError("Grok hook inspection is invalid");
  if (!overlay || typeof overlay !== "object" || typeof overlay.command !== "string" || typeof overlay.hooksDirectory !== "string") throw new TypeError("Grok guard overlay is invalid");
  const target = resolve(overlay.hookPath).toLowerCase();
  const hooks = Array.isArray(inspect.hooks) ? inspect.hooks : [];
  const loaded = hooks.some((hook) => hookEvent(hook?.event ?? hook?.hookEventName ?? hook?.hook_event_name) && loadedController(hook, overlay));
  if (!loaded) throw new TypeError(`Grok did not discover the controller PreToolUse hook: ${basename(target)}`);
  if (hooks.some((hook) => hookEvent(hook?.event ?? hook?.hookEventName ?? hook?.hook_event_name) && !loadedController(hook, overlay) && rewritesInput(hook))) throw new TypeError("Grok has a competing input-rewriting PreToolUse hook");
  return true;
}
function loadedController(hook, overlay) { return hook?.hookType === "command" && hook?.target === overlay.command && hook?.source?.type === "user" && resolve(hook?.source?.path ?? "").toLowerCase() === resolve(overlay.hooksDirectory).toLowerCase(); }

export function assertNoCompetingInputHooks(inspect, overlay) {
  if (!inspect || typeof inspect !== "object" || !Array.isArray(inspect.hooks)) throw new TypeError("Grok hook inspection is invalid");
  if (inspect.hooks.some((hook) => hookEvent(hook?.event ?? hook?.hookEventName ?? hook?.hook_event_name) && !loadedController(hook, overlay) && rewritesInput(hook))) throw new TypeError("Grok has a competing input-rewriting PreToolUse hook");
  return true;
}
