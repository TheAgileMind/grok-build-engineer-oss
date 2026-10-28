import path from "node:path";
import { isAbsolute } from "node:path";

/** Accept POSIX or Windows absolute paths so Windows fixtures validate on POSIX test hosts. */
export function isAbsolutePath(value) {
  return typeof value === "string" && (isAbsolute(value) || path.win32.isAbsolute(value));
}

export const CONTRACT_VERSIONS = Object.freeze({
  submission: "agent-platform.grok-builder-submission.v1", profile: "agent-platform.grok-builder-profile.v1",
  grant: "agent-platform.grok-builder-grant.v1", job: "agent-platform.grok-builder-job.v1",
  attempt: "agent-platform.grok-builder-attempt.v1", event: "agent-platform.grok-builder-event.v1",
  candidate: "agent-platform.grok-builder-candidate.v1", validation: "agent-platform.grok-builder-validation.v1",
  collection: "agent-platform.grok-builder-collection.v1", cancellation: "agent-platform.grok-builder-cancellation.v1",
  error: "agent-platform.grok-builder-error.v1", usage: "agent-platform.grok-builder-usage.v1",
  cost: "agent-platform.grok-builder-cost.v1",
  jobAuthority: "agent-platform.grok-builder-job-authority.v1",
  activationScope: "agent-platform.grok-build-engineer-scope.v1",
  taskPacket: "agent-platform.grok-build-engineer-task.v2",
  approvalPacket: "agent-platform.grok-build-engineer-approval.v1",
  runPolicy: "agent-platform.grok-build-engineer-policy.v1",
  runReceipt: "agent-platform.grok-build-engineer-receipt.v1",
  repairFindings: "agent-platform.grok-build-engineer-repair-findings.v1",
  acceptance: "agent-platform.grok-build-engineer-acceptance.v1"
});
export const TASK_DELIVERY = Object.freeze({ ARTIFACT_ONLY: "artifact_only" });

const MAX_DEPTH = 7, MAX_ARRAY = 128, MAX_KEYS = 32, MAX_STRING = 16_384, MAX_SERIALIZED_BYTES = 65_536, MAX_INTEGER = 2_147_483_647;
const ID = /^[a-z][a-z0-9_-]{2,63}$/, DIGEST = /^sha256:[a-f0-9]{64}$/, GIT_SHA = /^[a-f0-9]{40}$/;
const PROCESS_FIELDS = new Set(["executable", "shell", "cwd", "workingdirectory", "environment", "env", "stateroot", "argv", "arguments", "validationcommand", "validationcommands"]);

function fail(message) { throw new TypeError(message); }
function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value)); }
function exact(value, keys, label) {
  if (!object(value)) fail(`${label} must be an object`);
  const extras = Object.keys(value).filter((key) => !keys.includes(key));
  const missing = keys.filter((key) => !(key in value));
  if (extras.length) fail(`${label} has unsupported fields: ${extras.join(", ")}`);
  if (missing.length) fail(`${label} is missing fields: ${missing.join(", ")}`);
}
function exactOptional(value, requiredKeys, optionalKeys, label) {
  if (!object(value)) fail(`${label} must be an object`);
  const keys = [...requiredKeys, ...optionalKeys];
  const extras = Object.keys(value).filter((key) => !keys.includes(key));
  const missing = requiredKeys.filter((key) => !(key in value));
  if (extras.length) fail(`${label} has unsupported fields: ${extras.join(", ")}`);
  if (missing.length) fail(`${label} is missing fields: ${missing.join(", ")}`);
}
function fieldName(key) { return key.replace(/[-_]/g, "").toLowerCase(); }
function noProcessFields(value, label, seen = new WeakSet()) {
  if (value === null || typeof value !== "object") return;
  if (seen.has(value)) fail(`${label} must not be cyclic`);
  seen.add(value);
  if (Array.isArray(value)) return value.forEach((entry, index) => noProcessFields(entry, `${label}[${index}]`, seen));
  if (!object(value)) fail(`${label} must contain JSON data only`);
  Object.entries(value).forEach(([key, entry]) => {
    if (PROCESS_FIELDS.has(fieldName(key))) fail(`${label}.${key} is a caller-supplied process-control field`);
    noProcessFields(entry, `${label}.${key}`, seen);
  });
}
function finite(value, label, depth = 0, seen = new WeakSet()) {
  if (depth > MAX_DEPTH) fail(`${label} exceeds maximum depth`);
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") { if (!Number.isFinite(value)) fail(`${label} must contain finite numbers`); return; }
  if (typeof value === "string") { if (value.length > MAX_STRING) fail(`${label} exceeds maximum length`); return; }
  if (typeof value !== "object" || seen.has(value)) fail(`${label} must contain finite, non-cyclic JSON data`);
  seen.add(value);
  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY) fail(`${label} exceeds maximum array length`);
    return value.forEach((entry, index) => finite(entry, `${label}[${index}]`, depth + 1, seen));
  }
  if (!object(value)) fail(`${label} must contain JSON data only`);
  const entries = Object.entries(value);
  if (entries.length > MAX_KEYS) fail(`${label} exceeds maximum object keys`);
  entries.forEach(([key, entry]) => { if (key.length > 128) fail(`${label} has an oversized key`); finite(entry, `${label}.${key}`, depth + 1, seen); });
}
function text(value, label) { if (typeof value !== "string" || value.trim() === "") fail(`${label} must be a non-empty string`); if (value.length > MAX_STRING) fail(`${label} exceeds maximum length`); return value; }
function identifier(value, label) { if (typeof value !== "string" || !ID.test(value)) fail(`${label} must be a valid identifier`); return value; }
function digest(value, label) { if (typeof value !== "string" || !DIGEST.test(value)) fail(`${label} must be a sha256 digest`); return value; }
function integer(value, label, min = 0) { if (!Number.isInteger(value) || value < min || value > MAX_INTEGER) fail(`${label} must be an integer from ${min} through ${MAX_INTEGER}`); return value; }
function time(value, label) { text(value, label); if (Number.isNaN(Date.parse(value))) fail(`${label} must be an ISO timestamp`); return value; }
function absolute(value, label) { text(value, label); if (!isAbsolutePath(value)) fail(`${label} must be absolute`); return value; }
function relative(value, label) {
  const path = text(value, label).replaceAll("\\", "/");
  if (isAbsolute(path) || path.startsWith("/") || path.split("/").some((part) => ["", ".", ".."].includes(part)) || path === ".git" || path.startsWith(".git/")) fail(`${label} must be a safe repository-relative path`);
  return path;
}
function strings(value, label, { min = 0, normalize = text } = {}) {
  if (!Array.isArray(value) || value.length < min || value.length > MAX_ARRAY) fail(`${label} must be a bounded array`);
  const items = value.map((entry, index) => normalize(entry, `${label}[${index}]`));
  if (new Set(items).size !== items.length) fail(`${label} must not contain duplicates`);
  return value;
}
function versioned(value, keys, version, label) { exact(value, keys, label); noProcessFields(value, label); finite(value, label); if (Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_SERIALIZED_BYTES) fail(`${label} exceeds maximum serialized size`); if (value.contractVersion !== version) fail(`${label} contractVersion is unsupported`); return value; }
function enumValue(value, allowed, label) { if (!allowed.includes(value)) fail(`${label} is invalid`); return value; }

export function assertAbsoluteStateRoot(value) { return absolute(value, "stateRoot"); }

export function validateSubmission(value) {
  versioned(value, ["contractVersion", "submissionId", "mode", "idempotencyKey", "profileId", "continuation", "source", "task", "findings"], CONTRACT_VERSIONS.submission, "submission");
  identifier(value.submissionId, "submission.submissionId"); enumValue(value.mode, ["new", "repair"], "submission.mode"); identifier(value.idempotencyKey, "submission.idempotencyKey"); identifier(value.profileId, "submission.profileId");
  exact(value.source, ["repositoryRoot", "sourceSha", "destinationRoot", "branchPolicy"], "submission.source"); absolute(value.source.repositoryRoot, "submission.source.repositoryRoot"); if (!GIT_SHA.test(value.source.sourceSha)) fail("submission.source.sourceSha must be a full Git SHA"); absolute(value.source.destinationRoot, "submission.source.destinationRoot"); enumValue(value.source.branchPolicy, ["detached", "unique_mission_branch"], "submission.source.branchPolicy");
  exact(value.task, ["title", "instructions", "dataClass", "contextPaths"], "submission.task"); text(value.task.title, "submission.task.title"); text(value.task.instructions, "submission.task.instructions"); identifier(value.task.dataClass, "submission.task.dataClass"); strings(value.task.contextPaths, "submission.task.contextPaths", { normalize: relative });
  if (!Array.isArray(value.findings) || value.findings.length > MAX_ARRAY) fail("submission.findings must be a bounded array");
  value.findings.forEach((finding, index) => { exact(finding, ["code", "message"], `submission.findings[${index}]`); identifier(finding.code, `submission.findings[${index}].code`); text(finding.message, `submission.findings[${index}].message`); });
  if (value.mode === "new") {
    if (value.continuation !== null) fail("submission.continuation must be null for new work");
    if (value.findings.length !== 0) fail("submission.findings must be empty for new work");
  } else {
    if (Object.hasOwn(value.continuation ?? {}, "expectedCandidateDigest")) {
      exact(value.continuation, ["jobId", "expectedAttemptId", "expectedCandidateDigest"], "submission.continuation");
      identifier(value.continuation.jobId, "submission.continuation.jobId"); identifier(value.continuation.expectedAttemptId, "submission.continuation.expectedAttemptId"); digest(value.continuation.expectedCandidateDigest, "submission.continuation.expectedCandidateDigest");
    } else {
      exact(value.continuation, ["jobId", "expectedAttemptId", "expectedNativeSessionId"], "submission.continuation");
      identifier(value.continuation.jobId, "submission.continuation.jobId"); identifier(value.continuation.expectedAttemptId, "submission.continuation.expectedAttemptId"); text(value.continuation.expectedNativeSessionId, "submission.continuation.expectedNativeSessionId");
    }
    if (value.findings.length === 0) fail("submission.findings must be non-empty for repair work");
  }
  return value;
}
export function validateProfile(value) {
  versioned(value, ["contractVersion", "profileId", "name", "status", "capabilityDigest", "limits"], CONTRACT_VERSIONS.profile, "profile"); identifier(value.profileId, "profile.profileId"); text(value.name, "profile.name"); enumValue(value.status, ["approved", "disabled"], "profile.status"); digest(value.capabilityDigest, "profile.capabilityDigest");
  exact(value.limits, ["initializationTimeoutMs", "idleTimeoutMs", "overallTimeoutMs", "cancellationTimeoutMs", "maximumFrameBytes", "maximumEventBytes", "maximumEventsPerMinute", "maximumActiveJobs"], "profile.limits"); Object.entries(value.limits).forEach(([key, entry]) => integer(entry, `profile.limits.${key}`, 1)); return value;
}
export function validateGrant(value) {
  versioned(value, ["contractVersion", "grantId", "jobId", "worktreeCustodyDigest", "profileDigest", "operation", "service", "direction", "dataClasses", "sourcePaths", "recipients", "endpoints", "payloadBoundary", "expiresAt", "nonce", "authorityClass", "issuer", "receiptDigest"], CONTRACT_VERSIONS.grant, "grant"); identifier(value.grantId, "grant.grantId"); identifier(value.jobId, "grant.jobId"); digest(value.worktreeCustodyDigest, "grant.worktreeCustodyDigest"); digest(value.profileDigest, "grant.profileDigest"); identifier(value.operation, "grant.operation"); identifier(value.service, "grant.service"); enumValue(value.direction, ["egress", "ingress"], "grant.direction"); strings(value.dataClasses, "grant.dataClasses", { min: 1, normalize: identifier }); strings(value.sourcePaths, "grant.sourcePaths", { normalize: relative }); strings(value.recipients, "grant.recipients", { min: 1 }); strings(value.endpoints, "grant.endpoints", { min: 1 }); identifier(value.payloadBoundary, "grant.payloadBoundary"); time(value.expiresAt, "grant.expiresAt"); identifier(value.nonce, "grant.nonce"); enumValue(value.authorityClass, ["local_policy", "human_enforced"], "grant.authorityClass");
  if (value.authorityClass === "local_policy") { if (value.issuer !== "local_policy" || value.receiptDigest !== null) fail("local-policy grant must use the local_policy issuer and no receiptDigest"); } else { if (value.issuer !== "human_approval_broker") fail("human-enforced grant issuer is invalid"); digest(value.receiptDigest, "grant.receiptDigest"); }
  return value;
}
export function validateJob(value) {
  versioned(value, ["contractVersion", "jobId", "submissionId", "state", "profileDigest", "sourceCustodyDigest", "eventCursor"], CONTRACT_VERSIONS.job, "job"); identifier(value.jobId, "job.jobId"); identifier(value.submissionId, "job.submissionId"); enumValue(value.state, ["queued", "preflighting", "starting", "running", "awaiting_codex_input", "candidate_ready", "repairing", "cancelling", "cancelled", "accepted", "rejected", "failed", "recovery_required", "integrity_failed"], "job.state"); digest(value.profileDigest, "job.profileDigest"); digest(value.sourceCustodyDigest, "job.sourceCustodyDigest"); integer(value.eventCursor, "job.eventCursor"); return value;
}
export function validateAttempt(value) { versioned(value, ["contractVersion", "attemptId", "jobId", "number", "state", "profileDigest"], CONTRACT_VERSIONS.attempt, "attempt"); identifier(value.attemptId, "attempt.attemptId"); identifier(value.jobId, "attempt.jobId"); integer(value.number, "attempt.number", 1); enumValue(value.state, ["queued", "running", "candidate_ready", "cancelled", "failed", "recovery_required"], "attempt.state"); digest(value.profileDigest, "attempt.profileDigest"); return value; }
export function validateEvent(value) { versioned(value, ["contractVersion", "eventId", "jobId", "attemptId", "fencingToken", "nativeSessionId", "requestId", "cursor", "sequence", "kind", "occurredAt", "data"], CONTRACT_VERSIONS.event, "event"); identifier(value.eventId, "event.eventId"); identifier(value.jobId, "event.jobId"); identifier(value.attemptId, "event.attemptId"); integer(value.fencingToken, "event.fencingToken", 1); identifier(value.nativeSessionId, "event.nativeSessionId"); identifier(value.requestId, "event.requestId"); integer(value.cursor, "event.cursor", 1); integer(value.sequence, "event.sequence", 1); enumValue(value.kind, ["progress", "input_required", "candidate_ready", "warning", "failure", "cancelled"], "event.kind"); time(value.occurredAt, "event.occurredAt"); return value; }
export function validateCandidate(value) { versioned(value, ["contractVersion", "candidateId", "jobId", "attemptId", "manifestDigest", "createdAt", "changedPaths"], CONTRACT_VERSIONS.candidate, "candidate"); identifier(value.candidateId, "candidate.candidateId"); identifier(value.jobId, "candidate.jobId"); identifier(value.attemptId, "candidate.attemptId"); digest(value.manifestDigest, "candidate.manifestDigest"); time(value.createdAt, "candidate.createdAt"); strings(value.changedPaths, "candidate.changedPaths", { normalize: relative }); return value; }
export function validateValidation(value) { versioned(value, ["contractVersion", "validationId", "candidateId", "disposition", "evidenceDigest", "completedAt"], CONTRACT_VERSIONS.validation, "validation"); identifier(value.validationId, "validation.validationId"); identifier(value.candidateId, "validation.candidateId"); enumValue(value.disposition, ["passed", "failed", "not_run"], "validation.disposition"); digest(value.evidenceDigest, "validation.evidenceDigest"); time(value.completedAt, "validation.completedAt"); return value; }
export function validateCollection(value) { versioned(value, ["contractVersion", "collectionId", "jobId", "expectedAttemptId", "expectedCandidateDigest", "disposition", "validationEvidenceRef", "validationEvidenceDigest", "idempotencyKey"], CONTRACT_VERSIONS.collection, "collection"); identifier(value.collectionId, "collection.collectionId"); identifier(value.jobId, "collection.jobId"); identifier(value.expectedAttemptId, "collection.expectedAttemptId"); digest(value.expectedCandidateDigest, "collection.expectedCandidateDigest"); enumValue(value.disposition, ["accepted", "rejected", "repair_requested"], "collection.disposition"); identifier(value.validationEvidenceRef, "collection.validationEvidenceRef"); digest(value.validationEvidenceDigest, "collection.validationEvidenceDigest"); identifier(value.idempotencyKey, "collection.idempotencyKey"); return value; }
export function validateCancellation(value) { versioned(value, ["contractVersion", "cancellationId", "jobId", "reason", "idempotencyKey"], CONTRACT_VERSIONS.cancellation, "cancellation"); identifier(value.cancellationId, "cancellation.cancellationId"); identifier(value.jobId, "cancellation.jobId"); identifier(value.reason, "cancellation.reason"); identifier(value.idempotencyKey, "cancellation.idempotencyKey"); return value; }
export function validateJobAuthority(value) {
  // This is a controller-owned immutable authority record, not a caller
  // submission.  Its reviewed validationCommands field is intentionally
  // process-shaped, so retain strict JSON/bounds checks without applying the
  // caller-process-field prohibition used by public contracts.
  exact(value, ["contractVersion", "authorityId", "runtimeId", "sourceSha", "dataClasses", "provider", "model", "disclosure", "costCeilingUsd", "validationCommands", "acceptanceCriteria", "externalEffects", "authorizationBasis", "expiresAt", "receiptDigest"], "job authority");
  finite(value, "job authority"); if (Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_SERIALIZED_BYTES) fail("job authority exceeds maximum serialized size");
  if (value.contractVersion !== CONTRACT_VERSIONS.jobAuthority) fail("job authority contractVersion is unsupported");
  identifier(value.authorityId, "job authority.authorityId"); identifier(value.runtimeId, "job authority.runtimeId");
  if (!GIT_SHA.test(value.sourceSha)) fail("job authority.sourceSha must be a full Git SHA");
  strings(value.dataClasses, "job authority.dataClasses", { min: 1, normalize: identifier });
  for (const key of ["provider", "model", "disclosure", "authorizationBasis"]) text(value[key], `job authority.${key}`);
  // This plugin's attested ACP launch is the xAI Grok Build agent. Custom
  // providers/models require a distinct capability profile whose launch and
  // inspection evidence can actually prove that selection.
  enumValue(value.provider, ["xai"], "job authority.provider");
  // `grok-build` was the original CLI alias. Current first-party Grok Build
  // accounts expose the same coding agent as `grok-4.6`; keep both explicit
  // and fail closed for every other model.
  enumValue(value.model, ["grok-build", "grok-4.6"], "job authority.model");
  if (!Number.isFinite(value.costCeilingUsd) || value.costCeilingUsd < 0 || value.costCeilingUsd > 10_000) fail("job authority.costCeilingUsd is invalid");
  for (const key of ["validationCommands", "acceptanceCriteria", "externalEffects"]) strings(value[key], `job authority.${key}`, { min: 0, normalize: text });
  time(value.expiresAt, "job authority.expiresAt"); digest(value.receiptDigest, "job authority.receiptDigest");
  return value;
}
export function validateError(value) { versioned(value, ["contractVersion", "code", "message", "retryable"], CONTRACT_VERSIONS.error, "error"); identifier(value.code, "error.code"); text(value.message, "error.message"); if (typeof value.retryable !== "boolean") fail("error.retryable must be a boolean"); return value; }
export function validateNormalizedUsage(value) { versioned(value, ["contractVersion", "inputTokens", "outputTokens", "totalTokens"], CONTRACT_VERSIONS.usage, "usage"); integer(value.inputTokens, "usage.inputTokens"); integer(value.outputTokens, "usage.outputTokens"); integer(value.totalTokens, "usage.totalTokens"); if (value.totalTokens !== value.inputTokens + value.outputTokens) fail("usage.totalTokens must equal inputTokens plus outputTokens"); return value; }
export function validateNormalizedCost(value) { versioned(value, ["contractVersion", "currency", "amountMicros", "source"], CONTRACT_VERSIONS.cost, "cost"); if (value.currency !== "USD") fail("cost.currency must be USD"); integer(value.amountMicros, "cost.amountMicros"); enumValue(value.source, ["provider_reported", "host_measured"], "cost.source"); return value; }

/** One-shot runner contracts are intentionally separate from legacy MCP jobs. */
export function validateTaskPacket(value) {
  exact(value, ["contractVersion", "taskRunId", "requestId", "mode", "delivery", "repositoryRoot", "worktree", "sourceSha", "task", "policy", "provider", "stateRoot", "approval", "continuation", "findingsDigest"], "taskPacket"); finite(value, "taskPacket"); if (Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_SERIALIZED_BYTES) fail("taskPacket exceeds maximum serialized size"); if (value.contractVersion !== CONTRACT_VERSIONS.taskPacket) fail("taskPacket contractVersion is unsupported");
  identifier(value.taskRunId, "taskPacket.taskRunId"); identifier(value.requestId, "taskPacket.requestId"); enumValue(value.mode, ["implementation", "repair"], "taskPacket.mode"); enumValue(value.delivery, Object.values(TASK_DELIVERY), "taskPacket.delivery"); absolute(value.repositoryRoot, "taskPacket.repositoryRoot"); absolute(value.worktree, "taskPacket.worktree"); if (!GIT_SHA.test(value.sourceSha)) fail("taskPacket.sourceSha must be a full Git SHA"); absolute(value.stateRoot, "taskPacket.stateRoot");
  exact(value.task, ["title", "instructions", "contextPaths"], "taskPacket.task"); text(value.task.title, "taskPacket.task.title"); text(value.task.instructions, "taskPacket.task.instructions"); strings(value.task.contextPaths, "taskPacket.task.contextPaths", { normalize: relative });
  exact(value.policy, ["allowedPaths", "allowedCommands", "allowedEnvironment", "network", "tools", "timeouts", "repairBudget"], "taskPacket.policy"); strings(value.policy.allowedPaths, "taskPacket.policy.allowedPaths", { min: 1, normalize: relative }); strings(value.policy.allowedCommands, "taskPacket.policy.allowedCommands", { normalize: text }); strings(value.policy.allowedEnvironment, "taskPacket.policy.allowedEnvironment", { normalize: (entry, label) => { const normalized = text(entry, label); if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(normalized)) fail(`${label} is not an environment name`); return normalized; } }); enumValue(value.policy.network, ["none"], "taskPacket.policy.network"); strings(value.policy.tools, "taskPacket.policy.tools", { normalize: text }); if (value.policy.tools.length !== 0) fail("artifact-only task packet cannot expose provider tools");
  exact(value.policy.timeouts, ["startMs", "turnMs", "idleMs", "cancelMs"], "taskPacket.policy.timeouts"); for (const key of ["startMs", "turnMs", "idleMs", "cancelMs"]) integer(value.policy.timeouts[key], `taskPacket.policy.timeouts.${key}`, 1); integer(value.policy.repairBudget, "taskPacket.policy.repairBudget"); if (value.policy.repairBudget > 1) fail("taskPacket.policy.repairBudget must not exceed one");
  exact(value.provider, ["executable", "model"], "taskPacket.provider"); absolute(value.provider.executable, "taskPacket.provider.executable"); text(value.provider.model, "taskPacket.provider.model");
  validateApprovalPacket(value.approval);
  if (value.mode === "implementation") { if (value.continuation !== null || value.findingsDigest !== null) fail("implementation task packet cannot contain repair continuation or findings"); }
  else { exact(value.continuation, ["priorTaskRunId", "priorRequestId", "priorSessionId", "priorReceiptDigest", "priorSourceSha", "priorRepositoryRoot", "priorWorktree", "priorDiffDigest"], "taskPacket.continuation"); identifier(value.continuation.priorTaskRunId, "taskPacket.continuation.priorTaskRunId"); identifier(value.continuation.priorRequestId, "taskPacket.continuation.priorRequestId"); text(value.continuation.priorSessionId, "taskPacket.continuation.priorSessionId"); digest(value.continuation.priorReceiptDigest, "taskPacket.continuation.priorReceiptDigest"); if (!GIT_SHA.test(value.continuation.priorSourceSha)) fail("taskPacket continuation priorSourceSha must be a full Git SHA"); absolute(value.continuation.priorRepositoryRoot, "taskPacket.continuation.priorRepositoryRoot"); absolute(value.continuation.priorWorktree, "taskPacket.continuation.priorWorktree"); digest(value.continuation.priorDiffDigest, "taskPacket.continuation.priorDiffDigest"); digest(value.findingsDigest, "taskPacket.findingsDigest"); if (value.policy.repairBudget !== 1) fail("repair task packet requires one repair budget"); }
  return value;
}
export function validateApprovalPacket(value) {
  versioned(value, ["contractVersion", "approvalId", "packetDigest", "issuedAt", "expiresAt", "approvedBy", "authorizationStatement"], CONTRACT_VERSIONS.approvalPacket, "approvalPacket"); identifier(value.approvalId, "approvalPacket.approvalId"); digest(value.packetDigest, "approvalPacket.packetDigest"); time(value.issuedAt, "approvalPacket.issuedAt"); time(value.expiresAt, "approvalPacket.expiresAt"); text(value.approvedBy, "approvalPacket.approvedBy"); text(value.authorizationStatement, "approvalPacket.authorizationStatement"); if (Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)) fail("approvalPacket expiresAt must follow issuedAt"); return value;
}
export function validateRunReceipt(value) {
  exact(value, ["contractVersion", "taskRunId", "requestId", "mode", "state", "startedAt", "finishedAt", "ownerNonce", "binding", "requested", "observed", "allowedScope", "changedFiles", "validationEvidence", "diagnostics"], "runReceipt"); finite(value, "runReceipt"); if (Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_SERIALIZED_BYTES) fail("runReceipt exceeds maximum serialized size"); if (value.contractVersion !== CONTRACT_VERSIONS.runReceipt) fail("runReceipt contractVersion is unsupported"); identifier(value.taskRunId, "runReceipt.taskRunId"); identifier(value.requestId, "runReceipt.requestId"); enumValue(value.mode, ["implementation", "repair"], "runReceipt.mode"); enumValue(value.state, ["candidate", "failed", "cancelled", "recovery_required"], "runReceipt.state"); time(value.startedAt, "runReceipt.startedAt"); time(value.finishedAt, "runReceipt.finishedAt"); text(value.ownerNonce, "runReceipt.ownerNonce"); exact(value.binding, ["sourceSha", "repositoryRoot", "worktree", "custodyDigest", "diffDigest"], "runReceipt.binding"); if (!GIT_SHA.test(value.binding.sourceSha)) fail("runReceipt.binding.sourceSha must be a full Git SHA"); absolute(value.binding.repositoryRoot, "runReceipt.binding.repositoryRoot"); absolute(value.binding.worktree, "runReceipt.binding.worktree"); digest(value.binding.custodyDigest, "runReceipt.binding.custodyDigest"); digest(value.binding.diffDigest, "runReceipt.binding.diffDigest"); exact(value.requested, ["model", "executable"], "runReceipt.requested"); text(value.requested.model, "runReceipt.requested.model"); absolute(value.requested.executable, "runReceipt.requested.executable"); exact(value.observed, ["model", "sessionId", "exitCode"], "runReceipt.observed"); text(value.observed.model, "runReceipt.observed.model"); if (value.observed.sessionId !== null) text(value.observed.sessionId, "runReceipt.observed.sessionId"); if (value.observed.exitCode !== null && !Number.isInteger(value.observed.exitCode)) fail("runReceipt.observed.exitCode must be an integer or null"); exact(value.allowedScope, ["worktree", "paths", "commands", "network", "tools", "environment"], "runReceipt.allowedScope"); absolute(value.allowedScope.worktree, "runReceipt.allowedScope.worktree"); strings(value.allowedScope.paths, "runReceipt.allowedScope.paths", { min: 1, normalize: relative }); strings(value.allowedScope.commands, "runReceipt.allowedScope.commands", { normalize: text }); strings(value.allowedScope.tools, "runReceipt.allowedScope.tools", { normalize: text }); strings(value.allowedScope.environment, "runReceipt.allowedScope.environment", { normalize: text }); enumValue(value.allowedScope.network, ["none", "public_read"], "runReceipt.allowedScope.network"); if (!Array.isArray(value.changedFiles) || value.changedFiles.length > MAX_ARRAY) fail("runReceipt.changedFiles must be a bounded array"); value.changedFiles.forEach((entry, i) => { const keys = entry && Object.prototype.hasOwnProperty.call(entry, "previousPath") ? ["path", "status", "previousPath"] : ["path", "status"]; exact(entry, keys, `runReceipt.changedFiles[${i}]`); relative(entry.path, `runReceipt.changedFiles[${i}].path`); text(entry.status, `runReceipt.changedFiles[${i}].status`); if (entry.previousPath !== undefined) relative(entry.previousPath, `runReceipt.changedFiles[${i}].previousPath`); }); if (!Array.isArray(value.validationEvidence) || value.validationEvidence.length > MAX_ARRAY) fail("runReceipt.validationEvidence must be a bounded array"); value.validationEvidence.forEach((entry, i) => { exact(entry, ["command", "exitCode", "outputDigest"], `runReceipt.validationEvidence[${i}]`); text(entry.command, `runReceipt.validationEvidence[${i}].command`); integer(entry.exitCode, `runReceipt.validationEvidence[${i}].exitCode`); digest(entry.outputDigest, "runReceipt.validationEvidence[${i}].outputDigest"); }); exactOptional(value.diagnostics, ["code", "message", "stderrDigest"], ["frameDigest", "category", "status"], "runReceipt.diagnostics"); text(value.diagnostics.code, "runReceipt.diagnostics.code"); text(value.diagnostics.message, "runReceipt.diagnostics.message"); if (value.diagnostics.stderrDigest !== null) digest(value.diagnostics.stderrDigest, "runReceipt.diagnostics.stderrDigest"); if (value.diagnostics.frameDigest !== undefined) digest(value.diagnostics.frameDigest, "runReceipt.diagnostics.frameDigest"); if (value.diagnostics.category !== undefined) { if (typeof value.diagnostics.category !== "string" || !/^[a-z][a-z0-9_-]{0,63}$/.test(value.diagnostics.category)) fail("runReceipt.diagnostics.category is invalid"); } if (value.diagnostics.status !== undefined) { if (typeof value.diagnostics.status === "number") integer(value.diagnostics.status, "runReceipt.diagnostics.status"); else if (typeof value.diagnostics.status !== "string" || value.diagnostics.status.length === 0 || value.diagnostics.status.length > 64) fail("runReceipt.diagnostics.status is invalid"); } return value;
}

export function validateRepairFindings(value) { versioned(value, ["contractVersion", "taskRunId", "requestId", "priorReceiptDigest", "sourceSha", "repositoryRoot", "worktree", "createdAt", "findings"], CONTRACT_VERSIONS.repairFindings, "repairFindings"); identifier(value.taskRunId, "repairFindings.taskRunId"); identifier(value.requestId, "repairFindings.requestId"); digest(value.priorReceiptDigest, "repairFindings.priorReceiptDigest"); if (!GIT_SHA.test(value.sourceSha)) fail("repairFindings.sourceSha must be a full Git SHA"); absolute(value.repositoryRoot, "repairFindings.repositoryRoot"); absolute(value.worktree, "repairFindings.worktree"); time(value.createdAt, "repairFindings.createdAt"); if (!Array.isArray(value.findings) || value.findings.length === 0 || value.findings.length > MAX_ARRAY) fail("repairFindings.findings must be a non-empty bounded array"); value.findings.forEach((entry, i) => { exact(entry, ["code", "message"], `repairFindings.findings[${i}]`); identifier(entry.code, `repairFindings.findings[${i}].code`); text(entry.message, `repairFindings.findings[${i}].message`); }); return value; }
export function validateAcceptanceDecision(value) { versioned(value, ["contractVersion", "taskRunId", "requestId", "receiptDigest", "custodyDigest", "disposition", "decidedAt", "idempotencyKey", "validationEvidenceRef", "validationEvidenceDigest"], CONTRACT_VERSIONS.acceptance, "acceptance"); identifier(value.taskRunId, "acceptance.taskRunId"); identifier(value.requestId, "acceptance.requestId"); digest(value.receiptDigest, "acceptance.receiptDigest"); digest(value.custodyDigest, "acceptance.custodyDigest"); enumValue(value.disposition, ["accepted", "rejected"], "acceptance.disposition"); time(value.decidedAt, "acceptance.decidedAt"); identifier(value.idempotencyKey, "acceptance.idempotencyKey"); identifier(value.validationEvidenceRef, "acceptance.validationEvidenceRef"); digest(value.validationEvidenceDigest, "acceptance.validationEvidenceDigest"); return value; }
