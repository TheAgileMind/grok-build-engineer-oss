#!/usr/bin/env node
import { createHash, timingSafeEqual } from "node:crypto";
import { appendFileSync, lstatSync, readFileSync } from "node:fs";
import { evaluatePreToolUse } from "../src/pretool-guard.mjs";

const MAX_INPUT_BYTES = 1024 * 1024;
const MAX_EVIDENCE_BYTES = 1024 * 1024;
const GUARD_EVENT_VERSION = "agent-platform.grok-build-engineer-pretool-event.v1";
function digest(value) { return `sha256:${createHash("sha256").update(value).digest("hex")}`; }
function argument(name) { const index = process.argv.indexOf(name); return index >= 0 ? process.argv[index + 1] : undefined; }
function sameDigest(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || left.length !== right.length) return false;
  return timingSafeEqual(Buffer.from(left), Buffer.from(right));
}
function explicitDeny(reason) {
  process.stdout.write(`${JSON.stringify({ decision: "deny", reason })}\n`);
  process.exitCode = 2;
}
function eventSessionId(event) {
  const value = event?.sessionId ?? event?.session_id ?? event?.params?.sessionId ?? event?.params?.session_id;
  return typeof value === "string" && value.length > 0 && value.length <= 512 ? value : null;
}
function eventToolName(event) {
  const value = event?.toolName ?? event?.tool_name ?? event?.tool?.name;
  return typeof value === "string" && value.length > 0 && value.length <= 512 ? value : "unknown";
}
function appendEvidence(evidencePath, policy, rawInput, decision) {
  const details = lstatSync(evidencePath);
  if (!details.isFile() || details.isSymbolicLink() || (details.mode & 0o170000) === 0o120000) throw new Error("guard evidence path is unsafe");
  const record = {
    contractVersion: GUARD_EVENT_VERSION,
    taskRunId: policy.taskRunId,
    requestId: policy.requestId,
    sessionId: policy.sessionId,
    decision: decision.decision,
    reason: String(decision.reason ?? "guard decision").slice(0, 512),
    toolName: eventToolName(JSON.parse(rawInput.toString("utf8"))),
    eventDigest: digest(rawInput)
  };
  const serialized = Buffer.from(`${JSON.stringify(record)}\n`, "utf8");
  if (details.size + serialized.length > MAX_EVIDENCE_BYTES) throw new Error("guard evidence exceeds limit");
  appendFileSync(evidencePath, serialized);
}

try {
  const policyPath = argument("--policy");
  const expectedDigest = argument("--digest");
  const evidencePath = argument("--evidence");
  if (!policyPath || !expectedDigest || !evidencePath) throw new Error("guard arguments are missing");
  const policyBytes = readFileSync(policyPath);
  if (!sameDigest(digest(policyBytes), expectedDigest)) throw new Error("guard policy digest mismatch");
  const chunks = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    total += chunk.length;
    if (total > MAX_INPUT_BYTES) throw new Error("hook input exceeds limit");
    chunks.push(chunk);
  }
  const rawInput = Buffer.concat(chunks);
  const event = JSON.parse(rawInput.toString("utf8"));
  const policy = JSON.parse(policyBytes.toString("utf8"));
  const markerMatches = sameDigest(process.env.GROK_BUILD_ENGINEER_GUARD_DIGEST ?? "", expectedDigest);
  const sessionMatches = eventSessionId(event) === policy.sessionId;
  // User hooks are discovered by every local Grok process. A matching marker
  // is the preferred scope signal, but providers may omit inherited env vars;
  // the immutable session binding is the fallback. An unrelated session is
  // never granted by this overlay.
  if (!markerMatches && !sessionMatches) process.exit(0);
  if (!sessionMatches) {
    explicitDeny("Grok Build Engineer guard session binding is missing or invalid");
  } else {
    const decision = evaluatePreToolUse(event, policy);
    appendEvidence(evidencePath, policy, rawInput, decision);
    if (decision.decision === "deny") explicitDeny(decision.reason);
  }
} catch {
  explicitDeny("Grok Build Engineer guard failed closed");
}
