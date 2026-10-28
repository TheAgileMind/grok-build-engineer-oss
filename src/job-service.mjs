import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join, normalize, resolve } from "node:path";

import { CONTRACT_VERSIONS, validateCancellation, validateCollection, validateSubmission } from "./contracts.mjs";
import { createAcpSessionAdapter } from "./acp-session.mjs";
import { createHeadlessSessionAdapter, HEADLESS_ADAPTER_VERSION } from "./headless-session.mjs";
import { IdempotencyConflictError, IntegrityError, JobStore, LeaseConflictError } from "./job-store.mjs";
import { getCapabilityProfile } from "./profiles.mjs";
import {
  admitWorktree, createAdmittedWorktree, digestOf, inventoryWorktreeCandidate,
  reserveAdmittedDestination, revalidateWorktreeCustody
} from "./worktree-custody.mjs";
import { redactForBoundary } from "./redaction.mjs";

const SERVICE_VERSION = "agent-platform.grok-builder-job-service.v2";
const SEALED_VERSION = "agent-platform.grok-builder-service-envelope.v1";
const CONTEXT_VERSION = "agent-platform.grok-builder-service-context.v1";
const PROFILE_ATTESTATION_BINDING_VERSION = "agent-platform.grok-builder-profile-attestation-binding.v1";
const LEGACY_PROFILE_PROOF_VERSION = "agent-platform.grok-builder-legacy-profile-reattestation.v1";
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const IDENTIFIER = /^[a-z][a-z0-9_-]{2,63}$/;
const ACTIVE_STATES = new Set(["preflighting", "starting", "running", "awaiting_codex_input", "repairing", "cancelling"]);
const EXECUTION_STATES = new Set(["preflighting", "starting", "running", "awaiting_codex_input"]);
const RECOVERABLE_HEADLESS_FAILURES = new Set(["headless_failure", "headless_child_lost", "headless_cli_error", "headless_stream_invalid", "headless_terminal_invalid"]);
const ENVELOPE_BYTES = 64 * 1024;
const RUNTIME_BYTES = 64 * 1024;
const MANIFEST_BYTES = 5 * 1024 * 1024;
const EVENT_VALUE_BYTES = 32 * 1024;

const stableId = (prefix, value) => `${prefix}-${digestOf(value).slice(7, 39)}`;
export const jobIdForSubmission = (submissionId) => stableId("job", { submissionId });
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));

function requireDigest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) throw new TypeError(`${label} must be a sha256 digest`);
  return value;
}
function requireIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new TypeError(`${label} must be an identifier`);
  return value;
}
function validateChildProcessIdentity(value, { required = false } = {}) {
  if (value === null || value === undefined) {
    if (required) throw new IntegrityError("runtime child process identity is required");
    return null;
  }
  exact(value, ["pid", "startedAt"], "runtime child process identity");
  if (!Number.isSafeInteger(value.pid) || value.pid < 1 || typeof value.startedAt !== "string" || Number.isNaN(Date.parse(value.startedAt))) {
    throw new IntegrityError("runtime child process identity is malformed");
  }
  return Object.freeze({ pid: value.pid, startedAt: new Date(value.startedAt).toISOString() });
}
function exact(value, names, label) {
  if (!isObject(value) || Object.keys(value).sort().join("|") !== [...names].sort().join("|")) {
    throw new TypeError(`${label} has unsupported or missing fields`);
  }
}
function toDate(clock) {
  const value = clock();
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new TypeError("clock returned an invalid time");
  return date;
}
function timestamp(clock) { return toDate(clock).toISOString(); }
function canonicalDestination(value) {
  if (typeof value !== "string" || value.length === 0) throw new TypeError("destination root is required");
  return normalize(resolve(value)).replaceAll("\\", "/").toLowerCase();
}
function absent(path, label) {
  try {
    const details = lstatSync(path);
    if (details.isSymbolicLink()) throw new IntegrityError(`${label} must not be a link`);
    return false;
  } catch (error) {
    if (error?.code === "ENOENT") return true;
    throw error;
  }
}
function sealRecord(envelope) { return { contractVersion: SEALED_VERSION, envelope, digest: digestOf(envelope) }; }
function safeReadSeal(path, label, maximumBytes) {
  try {
    const details = lstatSync(path);
    if (!details.isFile() || details.isSymbolicLink() || details.size < 2 || details.size > maximumBytes) throw new Error("not a bounded plain file");
    const record = JSON.parse(readFileSync(path, "utf8"));
    exact(record, ["contractVersion", "envelope", "digest"], label);
    if (record.contractVersion !== SEALED_VERSION || digestOf(record.envelope) !== record.digest) throw new Error("seal digest differs");
    return record.envelope;
  } catch (error) {
    if (error instanceof IntegrityError) throw error;
    throw new IntegrityError(`${label} is missing, linked, truncated, or tampered`);
  }
}
function safeWriteSeal(path, envelope, { label, maximumBytes, immutable = false } = {}) {
  const record = sealRecord(envelope);
  const encoded = `${JSON.stringify(record)}\n`;
  if (Buffer.byteLength(encoded, "utf8") > maximumBytes) throw new IntegrityError(`${label} exceeds its durable bound`);
  if (existsSync(path)) {
    const prior = safeReadSeal(path, label, maximumBytes);
    if (immutable) {
      if (digestOf(prior) !== record.digest) throw new IntegrityError(`${label} is immutable and differs`);
      return prior;
    }
    const details = lstatSync(path);
    if (!details.isFile() || details.isSymbolicLink()) throw new IntegrityError(`${label} must not be replaced through a link`);
  }
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  // A failed/aborted atomic write can leave its temporary sibling behind.
  // Never let that stale path prevent an exact recovery replay from writing
  // the same immutable content again.
  const temporary = `${path}.${process.pid}.${randomBytes(8).toString("hex")}.next`;
  let descriptor;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, encoded, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor); descriptor = undefined;
    renameSync(temporary, path);
    try {
      const parent = openSync(dirname(path), "r");
      try { fsyncSync(parent); } finally { closeSync(parent); }
    } catch { /* Windows may not permit directory fsync; the sealed file was fsynced. */ }
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  return envelope;
}

function serviceContext(submission, jobId) {
  const context = {
    contractVersion: CONTEXT_VERSION,
    operation: "submit",
    mode: "new",
    jobId,
    submissionId: submission.submissionId,
    idempotencyKey: submission.idempotencyKey,
    submissionDigest: digestOf(submission),
    sourceDigest: digestOf(submission.source),
    taskDigest: digestOf(submission.task),
    profileId: submission.profileId,
    dataClass: submission.task.dataClass
  };
  return { contextDigest: digestOf(context), context };
}
function validateServiceContext(value, jobId) {
  exact(value, ["contextDigest", "context"], "durable service context");
  requireDigest(value.contextDigest, "durable service context digest");
  exact(value.context, ["contractVersion", "operation", "mode", "jobId", "submissionId", "idempotencyKey", "submissionDigest", "sourceDigest", "taskDigest", "profileId", "dataClass"], "durable service context value");
  if (value.context.contractVersion !== CONTEXT_VERSION || value.context.operation !== "submit" || value.context.mode !== "new" || value.context.jobId !== jobId) {
    throw new IntegrityError("durable service context identity differs");
  }
  for (const field of ["submissionDigest", "sourceDigest", "taskDigest"]) requireDigest(value.context[field], `durable service context ${field}`);
  requireIdentifier(value.context.submissionId, "durable service context submissionId");
  requireIdentifier(value.context.idempotencyKey, "durable service context idempotencyKey");
  requireIdentifier(value.context.profileId, "durable service context profileId");
  requireIdentifier(value.context.dataClass, "durable service context dataClass");
  if (digestOf(value.context) !== value.contextDigest) throw new IntegrityError("durable service context digest differs");
  return value;
}
function actionList(state) {
  // Repairs are a mode of the stable submit tool, not a fifth public tool.
  if (state === "candidate_ready") return ["grok_collect", "grok_submit", "grok_cancel"];
  if (state === "queued" || state === "recovery_required" || ACTIVE_STATES.has(state)) return ["grok_status", "grok_cancel"];
  return ["grok_status"];
}
function makePrompt(submission) {
  const repair = submission.mode === "repair"
    ? `\n\nRepair findings:\n${submission.findings.map((finding) => `- ${finding.code}: ${finding.message}`).join("\n")}`
    : "";
  // Candidate publication is controller-owned.  The provider receives the
  // engineering task and repair findings only; model-authored marker text is
  // narrative evidence and must never be an authority token.
  return `${submission.task.title}\n\n${submission.task.instructions}${repair}\n\nCompletion protocol:\nAfter completing the implementation and tests, report what changed and the validation performed.`;
}
function compactEventValue(value) {
  if (value === undefined) return null;
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string" || Array.isArray(value) || isObject(value)) {
    const bytes = Buffer.byteLength(JSON.stringify(value), "utf8");
    if (bytes > EVENT_VALUE_BYTES) throw new IntegrityError("normalized ACP event value exceeds its bound");
    return structuredClone(value);
  }
  throw new IntegrityError("normalized ACP event value is malformed");
}

/** Provider-free U6 composition with exactly four public operations. */
export function createJobService({
  store = null,
  stateRoot = null,
  clock = () => new Date(),
  ownerId = null,
  authority = null,
  profileFactory = null,
  custody = null,
  acpFactory = createAcpSessionAdapter,
  acp = null,
  executionAdapterFactory = null,
  transport = null,
  acknowledgePreStartCancellation = null,
  acknowledgeRuntimeRecovery = null,
  timers = globalThis,
  leaseDurationMs = 300_000,
  heartbeatMs = 30_000
} = {}) {
  // An execution owner is a process/service-instance capability, not a
  // product-wide role name.  Sharing a default here would let two MCP server
  // processes impersonate one another's unexpired lease and fence.
  ownerId ??= `svc-${randomBytes(16).toString("hex")}`;
  requireIdentifier(ownerId, "ownerId");
  if (!Number.isSafeInteger(leaseDurationMs) || !Number.isSafeInteger(heartbeatMs) || heartbeatMs < 1 || heartbeatMs >= leaseDurationMs) {
    throw new TypeError("lease heartbeat bounds are invalid");
  }
  const jobs = store ?? new JobStore({ stateRoot });
  const custodyApi = custody ?? {
    admit: admitWorktree,
    reserve: reserveAdmittedDestination,
    create: createAdmittedWorktree,
    inventory: inventoryWorktreeCandidate,
    revalidate: revalidateWorktreeCustody
  };
  const selectedAdapterFactory = executionAdapterFactory ?? acpFactory;
  const selectedTransport = transport ?? acp;
  // Preserve the immutable failure vocabulary of historical/injected ACP
  // jobs. Headless loss is intentionally a distinct class because spawning
  // the finite CLI is already an ambiguous provider-prompt boundary and must
  // never enter ACP's pre-prompt replay path.
  const adapterFailureCode = executionAdapterFactory === null ? "acp_failure" : "execution_adapter_failure";
  if (selectedAdapterFactory === createAcpSessionAdapter) {
    exact(acp, ["launch", "inspectChild", "classifyPermission", "authorizePermission", "environment"], "host ACP dependencies");
    for (const method of ["launch", "inspectChild", "classifyPermission", "authorizePermission"]) {
      if (typeof acp[method] !== "function") throw new TypeError(`host ACP ${method} is required`);
    }
    if (!acp.environment || typeof acp.environment !== "object" || Array.isArray(acp.environment)) {
      throw new TypeError("host ACP exact environment is required");
    }
  }
  if (selectedAdapterFactory === createHeadlessSessionAdapter) {
    exact(selectedTransport, ["spawnImpl", "killTree", "inspectChild", "environment"], "headless transport dependencies");
    for (const method of ["spawnImpl", "killTree", "inspectChild"]) if (typeof selectedTransport[method] !== "function") throw new TypeError(`headless transport ${method} is required`);
    if (!selectedTransport.environment || typeof selectedTransport.environment !== "object" || Array.isArray(selectedTransport.environment)) throw new TypeError("headless transport exact environment is required");
  }

  const volatile = new Map();
  const active = new Map();
  // This is only a local retry cache for a fence that this service has
  // already acquired after an expired-process recovery.  It never supplies
  // authority by itself: restart clears it, and every use is checked against
  // the durable owner/token/expiry before a host acknowledgement is retried.
  const recoveryFences = new Map();
  const snapshot = (jobId) => jobs.readVerified(jobId);
  const now = () => typeof jobs.now === "function" ? jobs.now() : toDate(clock).getTime();
  const envelopePath = (jobId) => join(jobs.jobDir(jobId), "service-envelope.json");
  const runtimePath = (jobId, attemptId) => join(jobs.jobDir(jobId), `runtime-${attemptId}.json`);
  const processIdentityPath = (jobId, attemptId) => join(jobs.jobDir(jobId), `process-${attemptId}.json`);
  const continuationProcessIdentityPath = (jobId, attemptId, identity) => join(jobs.jobDir(jobId), `process-${attemptId}-continuation-${digestOf(identity).slice(7, 39)}.json`);
  const manifestPath = (jobId, manifestDigest) => join(jobs.jobDir(jobId), `candidate-${manifestDigest.slice(7)}.json`);

  function makeEnvelope(jobId, context, profile, preliminary, linkedCustody = null) {
    return {
      contractVersion: SERVICE_VERSION,
      jobId,
      contextDigest: context.contextDigest,
      submissionDigest: context.context.submissionDigest,
      sourceCustodyDigest: preliminary.sourceCustodyDigest,
      profileId: profile.profileId,
      profileDigest: profile.profileDigest,
      attestationDigest: digestOf(profile.attestation),
      attestationBindingVersion: PROFILE_ATTESTATION_BINDING_VERSION,
      attestationFingerprint: requireDigest(profile.attestation.fingerprint, "profile attestation fingerprint"),
      custody: linkedCustody
    };
  }
  function validateEnvelope(value, jobId) {
    const legacy = isObject(value) && !Object.hasOwn(value, "attestationFingerprint") && !Object.hasOwn(value, "attestationBindingVersion");
    exact(value, ["contractVersion", "jobId", "contextDigest", "submissionDigest", "sourceCustodyDigest", "profileId", "profileDigest", "attestationDigest", ...(legacy ? [] : ["attestationBindingVersion", "attestationFingerprint"]), "custody"], "service envelope");
    if (value.contractVersion !== SERVICE_VERSION || value.jobId !== jobId) throw new IntegrityError("service envelope identity differs");
    for (const field of ["contextDigest", "submissionDigest", "sourceCustodyDigest", "profileDigest", "attestationDigest"]) requireDigest(value[field], `service envelope ${field}`);
    if (!legacy) {
      if (value.attestationBindingVersion !== PROFILE_ATTESTATION_BINDING_VERSION) throw new IntegrityError("service envelope attestation binding version differs");
      requireDigest(value.attestationFingerprint, "service envelope attestationFingerprint");
    }
    requireIdentifier(value.profileId, "service envelope profileId");
    if (value.custody !== null && !isObject(value.custody)) throw new IntegrityError("service envelope custody is malformed");
    return value;
  }
  function writeEnvelope(jobId, envelope) {
    validateEnvelope(envelope, jobId);
    return safeWriteSeal(envelopePath(jobId), envelope, { label: "service envelope", maximumBytes: ENVELOPE_BYTES });
  }
  function verifyEnvelopeAdmission(jobId, envelope, current) {
    validateEnvelope(envelope, jobId);
    const context = validateServiceContext(current.serviceContext, jobId);
    if (envelope.contextDigest !== context.contextDigest || envelope.submissionDigest !== context.context.submissionDigest ||
        envelope.sourceCustodyDigest !== current.admission.sourceCustodyDigest || envelope.profileDigest !== current.job.profileDigest) {
      throw new IntegrityError("service envelope is not journal-bound to admission");
    }
    if (current.serviceRuntime === null || current.serviceRuntime === undefined) {
      if (envelope.custody !== null) throw new IntegrityError("service envelope has unjournaled worktree custody");
    } else {
      if (!envelope.custody || digestOf(envelope.custody) !== current.serviceRuntime.custodyDigest ||
          envelope.custody.worktreeCustodyDigest !== current.serviceRuntime.worktreeCustodyDigest ||
          digestOf(envelope.custody.destinationRoot) !== current.serviceRuntime.destinationDigest) {
        throw new IntegrityError("service envelope worktree custody is not journal-bound");
      }
    }
    return envelope;
  }
  function loadEnvelope(jobId, current = snapshot(jobId)) {
    const envelope = safeReadSeal(envelopePath(jobId), "service envelope", ENVELOPE_BYTES);
    return verifyEnvelopeAdmission(jobId, envelope, current);
  }
  function writeRuntime(jobId, attempt, requestId, nativeSessionId, fence, profileDigest, worktreeCustodyDigest, grantDigest, receiptDigest, childProcessIdentity = null) {
    if (typeof nativeSessionId !== "string" || nativeSessionId.length === 0 || nativeSessionId.length > 512) throw new IntegrityError("native session identifier is malformed");
    const runtime = {
      contractVersion: SERVICE_VERSION,
      jobId,
      attemptId: attempt.attemptId,
      requestId,
      nativeSessionId,
      fencingToken: fence,
      profileDigest,
      worktreeCustodyDigest,
      grantDigest,
      receiptDigest,
      childProcessIdentity: validateChildProcessIdentity(childProcessIdentity)
    };
    safeWriteSeal(runtimePath(jobId, attempt.attemptId), runtime, { label: "runtime session evidence", maximumBytes: RUNTIME_BYTES, immutable: true });
    return runtime;
  }
  function writeProcessIdentity(jobId, attempt, childProcessIdentity, { continuation = false } = {}) {
    const runtime = readRuntime(jobId, attempt.attemptId);
    if (runtime.attemptId !== attempt.attemptId) throw new IntegrityError("runtime session evidence crossed the process identity boundary");
    const identity = validateChildProcessIdentity(childProcessIdentity, { required: true });
    if (runtime.childProcessIdentity !== null) {
      if (!continuation) throw new IntegrityError("runtime session evidence crossed the process identity boundary");
      const rawRuntime = safeReadSeal(runtimePath(jobId, attempt.attemptId), "runtime session evidence", RUNTIME_BYTES);
      const sidecar = {
        contractVersion: SERVICE_VERSION,
        jobId,
        attemptId: attempt.attemptId,
        requestId: rawRuntime.requestId,
        nativeSessionId: rawRuntime.nativeSessionId,
        fencingToken: rawRuntime.fencingToken,
        childProcessIdentity: identity,
        priorProcessIdentityDigest: digestOf(runtime.childProcessIdentity),
        runtimeEvidenceDigest: digestOf(rawRuntime)
      };
      safeWriteSeal(continuationProcessIdentityPath(jobId, attempt.attemptId, identity), sidecar, { label: "continuation process identity evidence", maximumBytes: RUNTIME_BYTES, immutable: true });
      return sidecar;
    }
    const sidecar = {
      contractVersion: SERVICE_VERSION,
      jobId,
      attemptId: attempt.attemptId,
      requestId: runtime.requestId,
      nativeSessionId: runtime.nativeSessionId,
      fencingToken: runtime.fencingToken,
      childProcessIdentity: identity,
      runtimeEvidenceDigest: digestOf(runtime)
    };
    safeWriteSeal(processIdentityPath(jobId, attempt.attemptId), sidecar, { label: "process identity evidence", maximumBytes: RUNTIME_BYTES, immutable: true });
    return sidecar;
  }
  function readRuntime(jobId, attemptId) {
    const runtime = safeReadSeal(runtimePath(jobId, attemptId), "runtime session evidence", RUNTIME_BYTES);
    exact(runtime, ["contractVersion", "jobId", "attemptId", "requestId", "nativeSessionId", "fencingToken", "profileDigest", "worktreeCustodyDigest", "grantDigest", "receiptDigest", "childProcessIdentity"], "runtime session evidence");
    if (runtime.contractVersion !== SERVICE_VERSION || runtime.jobId !== jobId || runtime.attemptId !== attemptId ||
        typeof runtime.nativeSessionId !== "string" || runtime.nativeSessionId.length === 0 || runtime.nativeSessionId.length > 512 ||
        !Number.isSafeInteger(runtime.fencingToken) || runtime.fencingToken < 1) throw new IntegrityError("runtime session evidence differs");
    for (const field of ["profileDigest", "worktreeCustodyDigest", "grantDigest", "receiptDigest"]) requireDigest(runtime[field], `runtime session ${field}`);
    requireIdentifier(runtime.requestId, "runtime session requestId");
    runtime.childProcessIdentity = validateChildProcessIdentity(runtime.childProcessIdentity);
    if (!absent(processIdentityPath(jobId, attemptId), "process identity evidence")) {
      const sidecar = safeReadSeal(processIdentityPath(jobId, attemptId), "process identity evidence", RUNTIME_BYTES);
      exact(sidecar, ["contractVersion", "jobId", "attemptId", "requestId", "nativeSessionId", "fencingToken", "childProcessIdentity", "runtimeEvidenceDigest"], "process identity evidence");
      if (sidecar.contractVersion !== SERVICE_VERSION || sidecar.jobId !== jobId || sidecar.attemptId !== attemptId || sidecar.requestId !== runtime.requestId || sidecar.nativeSessionId !== runtime.nativeSessionId || sidecar.fencingToken !== runtime.fencingToken || sidecar.runtimeEvidenceDigest !== digestOf(runtime)) throw new IntegrityError("process identity evidence differs from base runtime evidence");
      const identity = validateChildProcessIdentity(sidecar.childProcessIdentity, { required: true });
      if (runtime.childProcessIdentity !== null && digestOf(runtime.childProcessIdentity) !== digestOf(identity)) throw new IntegrityError("process identity evidence conflicts with runtime evidence");
      runtime.childProcessIdentity = identity;
    }
    return runtime;
  }
  function readManifest(jobId, manifestDigest) {
    const manifest = safeReadSeal(manifestPath(jobId, manifestDigest), "candidate manifest", MANIFEST_BYTES);
    const legacy = !Object.hasOwn(manifest, "recoveryRepairAuthority");
    const profileBound = Object.hasOwn(manifest, "profileAttestationBindingVersion") || Object.hasOwn(manifest, "profileAttestationFingerprint") || Object.hasOwn(manifest, "legacyRecoveryProfileProofDigest");
    exact(manifest, ["contractVersion", "jobId", "attemptId", "sourceSha", "sourceCustodyDigest", "worktreeCustodyDigest", "profileDigest", "nativeSessionId", "requestId", "runtimeEvidenceDigest", "providerCandidateDigest", "terminalEventDigest", "protectedGitMetadata", "inventoryDigest", "inventory", "grantDigest", "receiptDigest", "createdAt", ...(legacy ? [] : ["recoveryRepairAuthority"]), ...(profileBound ? ["profileAttestationBindingVersion", "profileAttestationFingerprint", "legacyRecoveryProfileProofDigest"] : [])], "candidate manifest");
    if (manifest.contractVersion !== SERVICE_VERSION || manifest.jobId !== jobId || digestOf(manifest) !== manifestDigest ||
        typeof manifest.sourceSha !== "string" || !/^[a-f0-9]{40}$/.test(manifest.sourceSha) || typeof manifest.nativeSessionId !== "string" || manifest.nativeSessionId.length === 0 || manifest.nativeSessionId.length > 512) {
      throw new IntegrityError("candidate manifest identity differs");
    }
    for (const field of ["sourceCustodyDigest", "worktreeCustodyDigest", "profileDigest", "runtimeEvidenceDigest", "providerCandidateDigest", "terminalEventDigest", "inventoryDigest", "grantDigest", "receiptDigest"]) requireDigest(manifest[field], `candidate manifest ${field}`);
    if (profileBound) {
      if (manifest.profileAttestationBindingVersion !== PROFILE_ATTESTATION_BINDING_VERSION) throw new IntegrityError("candidate manifest profile attestation binding version differs");
      requireDigest(manifest.profileAttestationFingerprint, "candidate manifest profileAttestationFingerprint");
      if (manifest.legacyRecoveryProfileProofDigest !== null) requireDigest(manifest.legacyRecoveryProfileProofDigest, "candidate manifest legacyRecoveryProfileProofDigest");
    }
    requireIdentifier(manifest.attemptId, "candidate manifest attemptId"); requireIdentifier(manifest.requestId, "candidate manifest requestId");
    if (!legacy && manifest.recoveryRepairAuthority !== null) {
      exact(manifest.recoveryRepairAuthority, ["findingsDigest", "expectedAttemptId", "expectedNativeSessionId", "recoveryProofDigest", "repairGrantDigest", "repairReceiptDigest", "requestDigest"], "candidate recovery repair authority");
      for (const field of ["findingsDigest", "recoveryProofDigest", "repairGrantDigest", "repairReceiptDigest", "requestDigest"]) requireDigest(manifest.recoveryRepairAuthority[field], `candidate recovery repair authority ${field}`);
      requireIdentifier(manifest.recoveryRepairAuthority.expectedAttemptId, "candidate recovery repair authority attempt");
      if (typeof manifest.recoveryRepairAuthority.expectedNativeSessionId !== "string" || manifest.recoveryRepairAuthority.expectedNativeSessionId.length === 0 || manifest.recoveryRepairAuthority.expectedNativeSessionId.length > 512) throw new IntegrityError("candidate recovery repair native session is malformed");
    }
    if (!isObject(manifest.inventory) || !isObject(manifest.protectedGitMetadata) || Number.isNaN(Date.parse(manifest.createdAt))) throw new IntegrityError("candidate manifest payload is malformed");
    return manifest;
  }
  function resolveProfile(profileId) {
    if (typeof profileFactory !== "function") throw new TypeError("an injected exact profile attestation and inspection are required");
    const profile = profileFactory(profileId);
    if (!isObject(profile) || profile.profileId !== profileId || !isObject(profile.attestation) || !isObject(profile.inspection) || profile.attestation.profileId !== profileId || profile.attestation.profileDigest !== profile.profileDigest) {
      throw new IntegrityError("exact injected profile attestation and inspection are required");
    }
    requireDigest(profile.profileDigest, "profile digest");
    requireDigest(profile.attestation.fingerprint, "profile attestation fingerprint");
    return profile;
  }
  function profileEnvelopeBinding(jobId, state, envelope, profile, { permitLegacyAuthority = false } = {}) {
    const context = validateServiceContext(state.serviceContext, jobId);
    const fingerprint = requireDigest(profile.attestation.fingerprint, "current profile attestation fingerprint");
    if (profile.profileId !== envelope.profileId || profile.profileDigest !== envelope.profileDigest ||
        state.job.profileDigest !== envelope.profileDigest || context.context.profileId !== envelope.profileId) {
      throw new IntegrityError("profile identity differs from durable admission");
    }
    if (Object.hasOwn(envelope, "attestationFingerprint")) {
      if (envelope.attestationBindingVersion !== PROFILE_ATTESTATION_BINDING_VERSION) throw new IntegrityError("profile attestation binding version drifted");
      if (envelope.attestationFingerprint !== fingerprint) {
        if (!permitLegacyAuthority) throw new IntegrityError("stable profile attestation fingerprint drifted");
        // Model selection first became durable in the headless 0.4.5 admission
        // record. Those jobs already bind the approved absolute Grok binary,
        // binary digest, inspected inventory, named profile digest, source
        // custody, and host-selected model. Their older fingerprint also
        // hashed volatile launcher values (for example Codex PATH/TEMP
        // shims), so a fresh local controller process could falsely look like
        // a different trusted host. Treat that known schema boundary as
        // continuity, while retaining explicit one-use re-attestation for all
        // older admissions that cannot prove the complete headless authority.
        if (["grok-build", "grok-4.6"].includes(state.admission?.model)) {
          return Object.freeze({ attestationFingerprint: fingerprint, legacyRecoveryProfileProofDigest: null, profileReattestationProof: null });
        }
        const migrationProof = {
          contractVersion: LEGACY_PROFILE_PROOF_VERSION, operation: "repair_profile_reattestation_v1",
          jobId, profileId: envelope.profileId, profileDigest: envelope.profileDigest,
          oldAttestationFingerprint: envelope.attestationFingerprint, newAttestationFingerprint: fingerprint,
          contextDigest: context.contextDigest, sourceCustodyDigest: envelope.sourceCustodyDigest,
          worktreeCustodyDigest: envelope.custody?.worktreeCustodyDigest ?? null
        };
        return Object.freeze({ attestationFingerprint: fingerprint, legacyRecoveryProfileProofDigest: digestOf(migrationProof), profileReattestationProof: Object.freeze(migrationProof) });
      }
      return Object.freeze({ attestationFingerprint: fingerprint, legacyRecoveryProfileProofDigest: null, profileReattestationProof: null });
    }
    // Old envelopes recorded the whole timestamped attestation. They remain
    // valid in-process when that exact attestation is still available. Across
    // a restart, only a one-use repair authority may admit a fresh, stable
    // re-attestation; its proof includes the opaque historical digest so a
    // changed legacy envelope produces a different authority request.
    if (!permitLegacyAuthority) {
      if (digestOf(profile.attestation) !== envelope.attestationDigest) throw new IntegrityError("legacy profile attestation cannot be revalidated without repair authority");
      return Object.freeze({ attestationFingerprint: fingerprint, legacyRecoveryProfileProofDigest: null, profileReattestationProof: null });
    }
    const legacyProof = {
      contractVersion: LEGACY_PROFILE_PROOF_VERSION, operation: "repair_profile_reattestation", jobId,
      profileId: envelope.profileId, profileDigest: envelope.profileDigest,
      legacyAttestationDigest: envelope.attestationDigest, currentAttestationFingerprint: fingerprint,
      contextDigest: context.contextDigest, sourceCustodyDigest: envelope.sourceCustodyDigest,
      worktreeCustodyDigest: envelope.custody?.worktreeCustodyDigest ?? null
    };
    return Object.freeze({ attestationFingerprint: fingerprint, legacyRecoveryProfileProofDigest: digestOf(legacyProof), profileReattestationProof: Object.freeze(legacyProof) });
  }
  function profileLimit(profile) {
    const immutable = getCapabilityProfile(profile.profileId);
    if (immutable.limits.maximumActiveJobs !== 1) throw new IntegrityError("U6 only supports an immutable maximumActiveJobs=1 profile");
    return immutable.limits.maximumActiveJobs;
  }
  function approve(request) {
    if (typeof authority !== "function") throw new TypeError("injected protected host authority is required");
    const decision = authority(Object.freeze(request));
    exact(decision, Object.hasOwn(decision ?? {}, "model") ? ["allowed", "grantDigest", "receiptDigest", "model"] : ["allowed", "grantDigest", "receiptDigest"], "host authority decision");
    if (decision.allowed !== true) throw new IntegrityError("host authority denied protected scope");
    if (decision.model !== undefined && !["grok-build", "grok-4.6"].includes(decision.model)) throw new IntegrityError("host authority selected an unsupported model");
    return { grantDigest: requireDigest(decision.grantDigest, "authority grantDigest"), receiptDigest: requireDigest(decision.receiptDigest, "authority receiptDigest"), model: decision.model ?? null };
  }
  function authorityRequest({ submission, jobId, context, profile, preliminary, mode, candidate = null, findingsDigest = null, legacyRecoveryProfileProofDigest = null, profileReattestationProof = null, runtimeRecoveryProofDigest = null }) {
    return {
      operation: "grok_submit",
      mode,
      jobId,
      submissionDigest: context.context.submissionDigest,
      contextDigest: context.contextDigest,
      sourceSha: preliminary.sourceSha,
      sourceCustodyDigest: preliminary.sourceCustodyDigest,
      // Authority must bind the immutable source repository selected by
      // custody admission; it cannot reconstruct this from caller metadata.
      repositoryRoot: preliminary.sourceRoot,
      destinationRoot: preliminary.destinationRoot,
      destinationDigest: digestOf(canonicalDestination(preliminary.destinationRoot)),
      profileDigest: profile.profileDigest,
      dataClass: submission.task.dataClass,
      contextPathsDigest: digestOf(submission.task.contextPaths),
      candidateDigest: candidate?.manifestDigest ?? null,
      candidateAttemptId: candidate?.attemptId ?? null,
      findingsDigest,
      // Repairs carry a different public submission envelope from the
      // original admission.  Bind its exact prompt-bearing fields too, so a
      // host decision cannot accidentally approve a prompt different from the
      // request it reviewed.
      repairSubmissionDigest: mode === "repair" ? digestOf(submission) : null,
      repairTaskDigest: mode === "repair" ? digestOf(submission.task) : null,
      repairSourceDigest: mode === "repair" ? digestOf(submission.source) : null,
      legacyRecoveryProfileProofDigest,
      profileReattestationProof,
      runtimeRecoveryProofDigest,
      requiredScopes: ["provider", "private_disclosure", "cost", "worktree"]
    };
  }
  function eventSessionReference(nativeSessionId) { return stableId("session", { nativeSessionId: nativeSessionId ?? "unbound" }); }
  function continuationMatchesNativeSession(expectedNativeSessionId, nativeSessionId) {
    // Status/events deliberately expose a stable pseudonymous reference, not
    // the sealed ACP session identifier.  Accept that public continuation
    // token while retaining raw-ID compatibility for already-issued local
    // recovery packets.  The raw identifier remains the value used to resume
    // the ACP session and the value sealed in durable runtime evidence.
    return expectedNativeSessionId === nativeSessionId || expectedNativeSessionId === eventSessionReference(nativeSessionId);
  }
  function append(jobId, attempt, fence, nativeSessionId, requestId, kind, data) {
    const state = snapshot(jobId);
    const cursor = state.job.eventCursor + 1;
    const event = {
      contractVersion: CONTRACT_VERSIONS.event,
      eventId: stableId("event", { jobId, cursor, kind, data }),
      jobId,
      attemptId: attempt.attemptId,
      fencingToken: fence,
      nativeSessionId: eventSessionReference(nativeSessionId),
      requestId,
      cursor,
      sequence: cursor,
      kind,
      occurredAt: timestamp(clock),
      data
    };
    jobs.appendEvent(jobId, event, { fence });
    return event;
  }
  function providerCandidateEvent(jobId, attemptId, providerCandidateDigest = null) {
    const events = jobs.readStatus(jobId, { afterCursor: 0 }).events;
    const event = events.filter((entry) => entry.kind === "progress" && entry.attemptId === attemptId &&
      entry.data?.type === "provider_candidate_ready" && DIGEST.test(entry.data?.providerCandidateDigest) &&
      (providerCandidateDigest === null || entry.data.providerCandidateDigest === providerCandidateDigest)).at(-1) ?? null;
    if (!event) throw new IntegrityError("journal-bound provider candidate evidence is absent");
    return { event, events };
  }
  function hasProviderCandidateEvent(jobId, attemptId) {
    return jobs.readStatus(jobId, { afterCursor: 0 }).events.some((entry) => entry.kind === "progress" && entry.attemptId === attemptId &&
      entry.data?.type === "provider_candidate_ready" && DIGEST.test(entry.data?.providerCandidateDigest));
  }
  function runtimeSessionBoundEvent(jobId, attempt, runtime) {
    const events = jobs.readStatus(jobId, { afterCursor: 0 }).events;
    const event = events.filter((entry) => entry.kind === "progress" && entry.attemptId === attempt.attemptId &&
      entry.data?.type === "native_session_bound").at(-1) ?? null;
    if (!event || event.requestId !== runtime.requestId || event.fencingToken !== runtime.fencingToken ||
        event.nativeSessionId !== eventSessionReference(runtime.nativeSessionId)) {
      throw new IntegrityError("runtime session evidence is not journal-bound to its native session event");
    }
    return event;
  }
  function candidatePublication(jobId, attempt, runtime, profile, custody, providerCandidateDigest) {
    const state = snapshot(jobId);
    if (!custody?.linkedWorktree || runtime.attemptId !== attempt.attemptId || runtime.profileDigest !== profile.profileDigest ||
        runtime.worktreeCustodyDigest !== custody.worktreeCustodyDigest || runtime.grantDigest !== state.bindings.grantDigest ||
        runtime.receiptDigest !== state.bindings.receiptDigest) {
      throw new IntegrityError("candidate publication evidence does not bind the active attempt");
    }
    runtimeSessionBoundEvent(jobId, attempt, runtime);
    const { event: providerEvent, events } = providerCandidateEvent(jobId, attempt.attemptId, providerCandidateDigest);
    const inventory = custodyApi.inventory(custody);
    if (!inventory || !isObject(inventory) || !Array.isArray(inventory.entries) || !isObject(inventory.protectedGitMetadata)) {
      throw new IntegrityError("candidate inventory is malformed");
    }
    const recoveryRepairAuthority = state.recoveryRepair === null ? null : {
      findingsDigest: state.recoveryRepair.findingsDigest, expectedAttemptId: state.recoveryRepair.expectedAttemptId,
      expectedNativeSessionId: state.recoveryRepair.expectedNativeSessionId, recoveryProofDigest: state.recoveryRepair.recoveryProofDigest,
      repairGrantDigest: state.recoveryRepair.repairGrantDigest, repairReceiptDigest: state.recoveryRepair.repairReceiptDigest,
      requestDigest: digestOf(state.recoveryRepair)
    };
    if (recoveryRepairAuthority !== null && (recoveryRepairAuthority.expectedAttemptId !== attempt.attemptId || recoveryRepairAuthority.expectedNativeSessionId !== runtime.nativeSessionId)) {
      throw new IntegrityError("recovery repair authority does not bind the active native session");
    }
    const profileBinding = profileEnvelopeBinding(jobId, state, loadEnvelope(jobId, state), profile, { permitLegacyAuthority: recoveryRepairAuthority !== null });
    const manifest = {
      contractVersion: SERVICE_VERSION, jobId, attemptId: attempt.attemptId, sourceSha: custody.sourceSha,
      sourceCustodyDigest: custody.sourceCustodyDigest, worktreeCustodyDigest: custody.worktreeCustodyDigest,
      profileDigest: profile.profileDigest, nativeSessionId: runtime.nativeSessionId, requestId: runtime.requestId,
      runtimeEvidenceDigest: digestOf(runtime), providerCandidateDigest,
      // Later recovery/failure/convenience events must not alter the terminal
      // evidence that was attested when the provider produced its candidate.
      terminalEventDigest: digestOf(events.filter((entry) => entry.cursor <= providerEvent.cursor)),
      protectedGitMetadata: inventory.protectedGitMetadata, inventoryDigest: inventory.inventoryDigest, inventory,
      grantDigest: state.bindings.grantDigest, receiptDigest: state.bindings.receiptDigest,
      profileAttestationBindingVersion: PROFILE_ATTESTATION_BINDING_VERSION,
      profileAttestationFingerprint: profileBinding.attestationFingerprint,
      legacyRecoveryProfileProofDigest: profileBinding.legacyRecoveryProfileProofDigest,
      recoveryRepairAuthority,
      createdAt: providerEvent.occurredAt
    };
    const manifestDigest = digestOf(manifest);
    const candidate = {
      contractVersion: CONTRACT_VERSIONS.candidate, candidateId: stableId("candidate", { jobId, manifestDigest }), jobId,
      attemptId: attempt.attemptId, manifestDigest, createdAt: manifest.createdAt,
      changedPaths: inventory.entries.map((entry) => entry.path)
    };
    return { manifest, manifestDigest, candidate };
  }
  function publishCandidatePublication(jobId, attempt, runtime, profile, custody, providerCandidateDigest, lease, { recovery = false } = {}) {
    const publication = candidatePublication(jobId, attempt, runtime, profile, custody, providerCandidateDigest);
    safeWriteSeal(manifestPath(jobId, publication.manifestDigest), publication.manifest, { label: "candidate manifest", maximumBytes: MANIFEST_BYTES, immutable: true });
    jobs.publishCandidate(jobId, {
      candidate: publication.candidate, providerCandidateDigest, grantDigest: publication.manifest.grantDigest,
      receiptDigest: publication.manifest.receiptDigest, idempotencyKey: stableId("candidatepub", { jobId, manifestDigest: publication.manifestDigest }),
      fence: lease.fencingToken, recovery
    });
    return publication;
  }
  // A journaled terminal provider event proves this exact job's child has
  // completed.  It is the narrow exception that can retire an expired global
  // execution slot: the stale slot must still bind this job and immutable
  // profile, its digest must be supplied to JobStore, and the replacement is
  // immediately released with a durable receipt.  Never use a completed job
  // to evict another job's stale capacity record.
  function releaseRecoveredExecutionSlot(jobId, profileDigest, lease) {
    requireDigest(profileDigest, "recovered execution slot profile digest");
    const slot = jobs.readExecutionSlot();
    if (slot === null) return false;
    // Capacity owned by another job is deliberately irrelevant to a
    // terminal operation on this job: it must neither block collection nor
    // be evicted by an unrelated candidate/cancellation proof.
    if (slot.jobId !== jobId || slot.profileDigest !== profileDigest) return false;
    if (slot.ownerId === ownerId && slot.fencingToken === lease.fencingToken) {
      return jobs.releaseExecutionSlot(jobId, { ownerId, fencingToken: lease.fencingToken, profileDigest });
    }
    if (slot.expiresAt > now()) {
      throw new LeaseConflictError("terminal recovery cannot replace a live service execution slot");
    }
    const replacement = jobs.acquireExecutionSlot(jobId, {
      ownerId,
      fencingToken: lease.fencingToken,
      profileDigest,
      expiresAt: lease.expiresAt,
      maximumActiveJobs: 1,
      priorSlotProofDigest: slot.digest
    });
    return jobs.releaseExecutionSlot(jobId, {
      ownerId,
      fencingToken: replacement.fencingToken,
      profileDigest
    });
  }
  function recoverCandidatePublication(jobId, state = snapshot(jobId)) {
    if (!(["running", "recovery_required"].includes(state.job.state)) || state.bindings.candidate !== null) return false;
    const attempt = state.attempts.at(-1);
    if (!attempt) return false;
    const { event, events } = providerCandidateEvent(jobId, attempt.attemptId);
    const envelope = loadEnvelope(jobId, state);
    if (!envelope.custody) throw new IntegrityError("candidate recovery has no journal-bound worktree custody");
    const profile = resolveProfile(envelope.profileId);
    profileEnvelopeBinding(jobId, state, envelope, profile, { permitLegacyAuthority: state.recoveryRepair !== null });
    const runtime = readRuntime(jobId, attempt.attemptId);
    runtimeSessionBoundEvent(jobId, attempt, runtime);
    const providerProofDigest = digestOf({
      jobId, attemptId: attempt.attemptId, requestId: runtime.requestId, providerEventId: event.eventId,
      providerCandidateDigest: event.data.providerCandidateDigest,
      terminalEventDigest: digestOf(events.filter((entry) => entry.cursor <= event.cursor))
    });
    const lease = currentLease(jobId, state, {
      allowExpiredRecovery: Boolean(state.lease && state.lease.expiresAt <= now()),
      priorOwnerProofDigest: providerProofDigest
    });
    releaseRecoveredExecutionSlot(jobId, profile.profileDigest, lease);
    const publication = publishCandidatePublication(jobId, attempt, runtime, profile, envelope.custody, event.data.providerCandidateDigest, lease, { recovery: true });
    try { append(jobId, attempt, lease.fencingToken, runtime.nativeSessionId, runtime.requestId, "candidate_ready", { candidateId: publication.candidate.candidateId, manifestDigest: publication.manifestDigest }); }
    catch { /* atomic publication already makes status/collection truthful. */ }
    return true;
  }
  function candidateBinding(jobId, expected = null) {
    const state = snapshot(jobId);
    const current = state.bindings?.candidate ? { candidate: state.bindings.candidate, binding: state.bindings } : null;
    const history = state.candidateHistory.map((entry) => ({ candidate: entry.candidate ?? null, binding: entry })).filter((entry) => entry.candidate);
    const sources = current ? [current, ...history] : history;
    // Candidate-ready operations must default to the active binding. History
    // exists only to validate an explicitly identified superseded candidate
    // during repair/recovery; choosing the last historical entry here makes a
    // repaired candidate appear stale at status/collection boundaries.
    const selected = expected === null ? (current ?? history.at(-1)) : sources.find((entry) => entry.candidate.attemptId === expected.expectedAttemptId && entry.candidate.manifestDigest === expected.expectedCandidateDigest);
    if (!selected) throw new IntegrityError("candidate preconditions are unavailable");
    const manifest = readManifest(jobId, selected.candidate.manifestDigest);
    if (manifest.attemptId !== selected.candidate.attemptId || manifest.providerCandidateDigest !== selected.binding.providerCandidateDigest) {
      throw new IntegrityError("candidate manifest or provider digest differs from the durable binding");
    }
    return { state, candidate: selected.candidate, binding: selected.binding, manifest };
  }
  function validateCandidate(jobId, expected = null) {
    const selected = candidateBinding(jobId, expected);
    const envelope = loadEnvelope(jobId, selected.state);
    if (!envelope.custody || selected.manifest.sourceCustodyDigest !== envelope.sourceCustodyDigest ||
        selected.manifest.worktreeCustodyDigest !== envelope.custody.worktreeCustodyDigest || selected.manifest.profileDigest !== envelope.profileDigest ||
        selected.manifest.grantDigest !== selected.binding.grantDigest || selected.manifest.receiptDigest !== selected.binding.receiptDigest) {
      throw new IntegrityError("candidate manifest does not bind custody, profile, and authority evidence");
    }
    const recoveryRepairAuthority = selected.manifest.recoveryRepairAuthority ?? null;
    if (selected.state.recoveryRepair === null) {
      if (recoveryRepairAuthority !== null) throw new IntegrityError("candidate has unexpected recovery repair authority evidence");
    } else if (recoveryRepairAuthority === null || recoveryRepairAuthority.requestDigest !== digestOf(selected.state.recoveryRepair) ||
        recoveryRepairAuthority.findingsDigest !== selected.state.recoveryRepair.findingsDigest ||
        recoveryRepairAuthority.expectedAttemptId !== selected.state.recoveryRepair.expectedAttemptId ||
        recoveryRepairAuthority.expectedNativeSessionId !== selected.state.recoveryRepair.expectedNativeSessionId ||
        recoveryRepairAuthority.recoveryProofDigest !== selected.state.recoveryRepair.recoveryProofDigest ||
        recoveryRepairAuthority.repairGrantDigest !== selected.state.recoveryRepair.repairGrantDigest ||
        recoveryRepairAuthority.repairReceiptDigest !== selected.state.recoveryRepair.repairReceiptDigest) {
      throw new IntegrityError("candidate recovery repair authority differs from the durable request");
    }
    const runtime = readRuntime(jobId, selected.manifest.attemptId);
    if (digestOf(runtime) !== selected.manifest.runtimeEvidenceDigest || runtime.nativeSessionId !== selected.manifest.nativeSessionId ||
        runtime.requestId !== selected.manifest.requestId || runtime.worktreeCustodyDigest !== envelope.custody.worktreeCustodyDigest ||
        runtime.grantDigest !== selected.binding.grantDigest || runtime.receiptDigest !== selected.binding.receiptDigest) {
      throw new IntegrityError("candidate runtime session evidence differs");
    }
    runtimeSessionBoundEvent(jobId, { attemptId: selected.manifest.attemptId }, runtime);
    const { event: providerEvent, events } = providerCandidateEvent(jobId, selected.manifest.attemptId, selected.binding.providerCandidateDigest);
    if (selected.manifest.terminalEventDigest !== digestOf(events.filter((entry) => entry.cursor <= providerEvent.cursor))) {
      throw new IntegrityError("candidate terminal event evidence differs");
    }
    const inventory = custodyApi.revalidate(envelope.custody, selected.manifest.inventory);
    if (!inventory || inventory.inventoryDigest !== selected.manifest.inventoryDigest) throw new IntegrityError("candidate worktree inventory drifted");
    const profile = resolveProfile(envelope.profileId);
    const profileBinding = profileEnvelopeBinding(jobId, selected.state, envelope, profile, { permitLegacyAuthority: selected.state.recoveryRepair !== null });
    if (Object.hasOwn(selected.manifest, "profileAttestationFingerprint")) {
      if (selected.manifest.profileAttestationBindingVersion !== PROFILE_ATTESTATION_BINDING_VERSION ||
          selected.manifest.profileAttestationFingerprint !== profileBinding.attestationFingerprint ||
          selected.manifest.legacyRecoveryProfileProofDigest !== profileBinding.legacyRecoveryProfileProofDigest) {
        throw new IntegrityError("candidate profile re-attestation evidence differs");
      }
    } else if (profileBinding.legacyRecoveryProfileProofDigest !== null) {
      throw new IntegrityError("legacy candidate lacks authorized profile re-attestation evidence");
    }
    return { envelope, profile, profileBinding, ...selected, runtime };
  }
  // Candidate-ready evidence is already independently revalidated above:
  // immutable binding, manifest, runtime/native-session journal event,
  // provider terminal event, custody inventory, and profile attestation.  It
  // is therefore the only proof a fresh service may use to rotate an expired
  // candidate lease for collection, repair, or terminal cancellation.
  function candidateTerminalProof(jobId, checked) {
    const { event, events } = providerCandidateEvent(jobId, checked.candidate.attemptId, checked.binding.providerCandidateDigest);
    const terminalEventDigest = digestOf(events.filter((entry) => entry.cursor <= event.cursor));
    if (terminalEventDigest !== checked.manifest.terminalEventDigest) {
      throw new IntegrityError("candidate terminal proof differs from the immutable manifest");
    }
    return digestOf({
      operation: "candidate_terminal_recovery",
      jobId,
      attemptId: checked.candidate.attemptId,
      candidateDigest: checked.candidate.manifestDigest,
      providerCandidateDigest: checked.binding.providerCandidateDigest,
      runtimeEvidenceDigest: checked.manifest.runtimeEvidenceDigest,
      terminalEventDigest,
      providerEventId: event.eventId
    });
  }
  function candidateLease(jobId, checked) {
    const state = checked.state;
    return currentLease(jobId, state, {
      allowExpiredRecovery: Boolean(state.lease && state.lease.expiresAt <= now()),
      priorOwnerProofDigest: candidateTerminalProof(jobId, checked)
    });
  }
  function currentLease(jobId, state = snapshot(jobId), { allowExpiredRecovery = false, priorOwnerProofDigest = null } = {}) {
    const fromActive = active.get(jobId)?.lease;
    const existing = fromActive ?? state.lease;
    if (existing && existing.ownerId === ownerId && existing.expiresAt > now()) return existing;
    if (priorOwnerProofDigest !== null) requireDigest(priorOwnerProofDigest, "prior owner proof digest");
    const recoveryProof = allowExpiredRecovery && existing && existing.expiresAt <= now()
      ? (priorOwnerProofDigest ?? state.serviceContext?.contextDigest ?? null)
      : null;
    return jobs.acquireExecutionLease(jobId, { ownerId, durationMs: leaseDurationMs, priorOwnerProofDigest: recoveryProof });
  }
  function hasLocalRecoveryFence(jobId, state) {
    const remembered = recoveryFences.get(jobId), lease = state.lease;
    return Boolean(remembered && lease && remembered.fencingToken === lease.fencingToken &&
      lease.ownerId === ownerId && lease.expiresAt > now());
  }
  function rememberRecoveryFence(jobId, lease) {
    recoveryFences.set(jobId, { fencingToken: lease.fencingToken });
  }
  function fence(correlation) {
    const state = snapshot(correlation.jobId);
    if (!state.lease || state.lease.ownerId !== ownerId || state.lease.fencingToken !== correlation.fencingToken || state.lease.expiresAt <= now()) return false;
    if (EXECUTION_STATES.has(state.job.state)) return true;
    return state.job.state === "cancelling" && Boolean(active.get(correlation.jobId)?.runtime);
  }
  function markRecovery(jobId, lease, code, attempt = null, nativeSessionId = null, requestId = null, evidence = null) {
    if (!lease) return;
    try {
      const state = snapshot(jobId);
      if (!ACTIVE_STATES.has(state.job.state)) return;
      const currentAttempt = attempt ?? state.attempts.at(-1);
      if (currentAttempt) {
        const childClose = evidence?.childClose;
        const failureKind = ["activation_required", "child_lost", "recovery_required", "session_failure", "headless_failure", "headless_child_lost", "headless_cli_error", "headless_stream_invalid", "headless_terminal_invalid"].includes(evidence?.failureKind) ? evidence.failureKind : null;
        const serviceStage = ["runtime_revalidation", "execution_slot", "state_transition", "adapter_creation", "adapter_start", "adapter_profile_drift", "adapter_guard", "adapter_child_launch", "adapter_child_launch_plan", "adapter_child_spawn", "adapter_child_identity", "adapter_child_parity", "runtime_wait"].includes(evidence?.serviceStage) ? evidence.serviceStage : null;
        const diagnostics = evidence?.diagnostics && isObject(evidence.diagnostics) ? redactForBoundary({
          adapterVersion: typeof evidence.diagnostics.adapterVersion === "string" ? evidence.diagnostics.adapterVersion : null,
          argvDigest: typeof evidence.diagnostics.argvDigest === "string" && DIGEST.test(evidence.diagnostics.argvDigest) ? evidence.diagnostics.argvDigest : null,
          stderrBytes: Number.isSafeInteger(evidence.diagnostics.stderrBytes) && evidence.diagnostics.stderrBytes >= 0 ? evidence.diagnostics.stderrBytes : 0,
          stderrDigest: typeof evidence.diagnostics.stderrDigest === "string" && DIGEST.test(evidence.diagnostics.stderrDigest) ? evidence.diagnostics.stderrDigest : null,
          stderrTail: typeof evidence.diagnostics.stderrTail === "string" ? evidence.diagnostics.stderrTail.slice(-8192) : null,
          protocolFrameType: typeof evidence.diagnostics.protocolFrameType === "string" ? evidence.diagnostics.protocolFrameType.slice(0, 128) : null,
          protocolFrameBytes: Number.isSafeInteger(evidence.diagnostics.protocolFrameBytes) && evidence.diagnostics.protocolFrameBytes >= 0 ? evidence.diagnostics.protocolFrameBytes : null,
          protocolFrameDigest: typeof evidence.diagnostics.protocolFrameDigest === "string" && DIGEST.test(evidence.diagnostics.protocolFrameDigest) ? evidence.diagnostics.protocolFrameDigest : null,
          protocolFrameKeys: Array.isArray(evidence.diagnostics.protocolFrameKeys) ? evidence.diagnostics.protocolFrameKeys.filter((key) => typeof key === "string" && key.length <= 128).slice(0, 64) : [],
          protocolErrorMessage: typeof evidence.diagnostics.protocolErrorMessage === "string" ? evidence.diagnostics.protocolErrorMessage.slice(0, 1024) : null
        }) : null;
        const failureData = { code, ...(failureKind ? { failureKind } : {}), ...(serviceStage ? { serviceStage } : {}), ...(diagnostics ? { diagnostics } : {}), ...(childClose ? { childClose: {
          code: childClose.code === null || Number.isSafeInteger(childClose.code) ? (childClose.code ?? null) : null,
          signal: typeof childClose.signal === "string" && /^[A-Z0-9_]{1,32}$/.test(childClose.signal) ? childClose.signal : null,
          spawnError: childClose.spawnError === true,
          stderrBytes: Number.isSafeInteger(childClose.stderrBytes) && childClose.stderrBytes >= 0 ? childClose.stderrBytes : 0,
          stderrLimitExceeded: childClose.stderrLimitExceeded === true
        } } : {}) };
        try { append(jobId, currentAttempt, lease.fencingToken, nativeSessionId, requestId ?? stableId("request", { jobId, attemptId: currentAttempt.attemptId }), "failure", failureData); } catch { /* transition below remains authoritative */ }
      }
      if (ACTIVE_STATES.has(snapshot(jobId).job.state)) {
        try {
          jobs.transition(jobId, "recovery_required", { fence: lease.fencingToken, allowRecovery: true });
        } catch (error) {
          // A heartbeat may discover expiry just after it stopped the child.
          // JobStore accepts this only if the exact old owner/fence is still
          // current; a rotated fence is deliberately left untouched.
          if (error instanceof LeaseConflictError) {
            jobs.recordRecovery(jobId, { ownerId, fencingToken: lease.fencingToken, code });
          } else throw error;
        }
      }
    } catch { /* a corrupt store is already fail-closed to callers */ }
  }
  function createAdapter(hooks) {
    if (selectedAdapterFactory === createHeadlessSessionAdapter) return createHeadlessSessionAdapter({
      spawnImpl: selectedTransport.spawnImpl,
      killTree: selectedTransport.killTree,
      inspectChild: selectedTransport.inspectChild,
      environment: selectedTransport.environment,
      ...hooks
    });
    if (selectedAdapterFactory !== createAcpSessionAdapter) return selectedAdapterFactory(hooks);
    return createAcpSessionAdapter({
      launch: acp.launch,
      inspectChild: acp.inspectChild,
      classifyPermission: acp.classifyPermission,
      authorizePermission: acp.authorizePermission,
      // Preserve the injected host's exact environment object: on Windows a
      // copied process.env can change case-sensitive presence semantics and
      // invalidate an otherwise valid frozen attestation.
      environment: acp.environment,
      ...hooks
    });
  }
  function sameRepair(history, request) {
    const prior = history?.repairRequest;
    return prior && prior.findingsDigest === request.findingsDigest && prior.expectedAttemptId === request.expectedAttemptId && prior.expectedCandidateDigest === request.expectedCandidateDigest;
  }
  function validateRepairSubmissionContext(jobId, submission, state = snapshot(jobId)) {
    const context = validateServiceContext(state.serviceContext, jobId);
    if (submission.profileId !== context.context.profileId || submission.task.dataClass !== context.context.dataClass ||
        digestOf(submission.source) !== context.context.sourceDigest || digestOf(submission.task) !== context.context.taskDigest) {
      throw new IntegrityError("repair source, task, data class, or profile differs from immutable admission");
    }
    return context;
  }
  // The built-in ACP adapter journals native_session_bound (and writes the
  // matching immutable runtime seal) *before* it can send a provider prompt.
  // A process can still die between recording the first attempt and that
  // callback.  This is the only active-state gap that may be retried from an
  // exact public submit replay: the old lease and its own slot must be expired,
  // and the durable record must prove that attempt never crossed the
  // prompt-capable native-session boundary.  Anything less is cancellation
  // territory, never a second provider prompt.
  function prePromptRecoveryEvidence(jobId, state = snapshot(jobId)) {
    if (!(["running", "recovery_required"].includes(state.job.state)) || !state.serviceRuntime || state.bindings.candidate !== null ||
        state.bindings.providerCandidateDigest !== null || state.candidateHistory.length !== 0 || state.usage !== null || state.cancellation !== null ||
        state.attempts.length < 1 || !state.lease) return null;
    // A raw running record is still the narrow one-attempt process-loss route.
    // A durable ACP failure may chain only when every prior attempt carries the
    // same pre-prompt proof; anything else can never create another prompt.
    if (state.job.state === "running" && state.attempts.length !== 1) return null;
    let hasNativeRuntimeEvidence = false;
    const attempts = state.attempts.map((attempt, index) => {
      if (attempt.jobId !== jobId || attempt.number !== index + 1 || attempt.profileDigest !== state.job.profileDigest) {
        throw new IntegrityError("pre-prompt recovery attempt identity differs");
      }
      if (!absent(runtimePath(jobId, attempt.attemptId), "pre-prompt runtime evidence")) {
        hasNativeRuntimeEvidence = true;
      }
      return attempt;
    });
    // A sealed native-session record proves this is not a pre-prompt retry.
    // Exact mode:new replays must still return their durable receipt without
    // scheduling or re-prompting; same-session repair is the only continuation.
    if (hasNativeRuntimeEvidence) return null;
    const envelope = loadEnvelope(jobId, state);
    if (!envelope.custody || envelope.profileDigest !== state.job.profileDigest) {
      throw new IntegrityError("pre-prompt recovery custody is not journal-bound");
    }
    const events = jobs.readStatus(jobId, { afterCursor: 0 }).events;
    const attemptProofs = attempts.map((attempt) => {
      const attemptEvents = events.filter((event) => event.attemptId === attempt.attemptId);
      const crossedPromptBoundary = attemptEvents.some((event) => event.kind === "candidate_ready" ||
        ["native_session_bound", "native_terminal", "provider_candidate_ready", "candidate_signal", "usage"].includes(event.data?.type));
      if (crossedPromptBoundary) throw new IntegrityError("pre-prompt recovery has prompt-capable journal evidence");
      if (state.job.state === "recovery_required" && (attemptEvents.length !== 1 || attemptEvents[0].kind !== "failure" || attemptEvents[0].data?.code !== "acp_failure")) {
        throw new IntegrityError("pre-prompt recovery lacks an exact ACP failure receipt");
      }
      return Object.freeze({ attemptId: attempt.attemptId, attemptNumber: attempt.number, eventDigest: digestOf(attemptEvents) });
    });
    const slot = jobs.readExecutionSlot();
    if (slot !== null) {
      if (slot.jobId !== jobId || slot.profileDigest !== state.job.profileDigest || slot.ownerId !== state.lease.ownerId ||
          slot.fencingToken !== state.lease.fencingToken || slot.expiresAt !== state.lease.expiresAt) {
        throw new LeaseConflictError("pre-prompt recovery cannot replace an unrelated execution slot");
      }
    }
    const proof = {
      operation: "pre_prompt_attempt_recovery",
      jobId,
      contextDigest: validateServiceContext(state.serviceContext, jobId).contextDigest,
      sourceCustodyDigest: state.admission.sourceCustodyDigest,
      profileDigest: state.job.profileDigest,
      serviceRuntimeDigest: state.serviceRuntime.custodyDigest,
      attempts: attemptProofs,
      priorLease: state.lease,
      priorSlotDigest: slot?.digest ?? null,
      eventDigest: digestOf(events)
    };
    return Object.freeze({ ...proof, proofDigest: digestOf(proof) });
  }
  function verifyPrePromptRecoveryAfterFence(jobId, recovery, lease) {
    if (!recovery || !DIGEST.test(recovery.proofDigest) || !lease || lease.ownerId !== ownerId) {
      throw new IntegrityError("pre-prompt recovery fence is malformed");
    }
    const state = snapshot(jobId);
    const current = prePromptRecoveryEvidence(jobId, {
      ...state,
      // The replacement fence is expected to differ from the proof's old
      // lease.  Revalidate every other durable fact after fencing the prior
      // owner so a late native-session bind cannot become a new prompt.
      lease: recovery.priorLease
    });
    if (!current || current.proofDigest !== recovery.proofDigest || state.lease.ownerId !== ownerId ||
        state.lease.fencingToken !== lease.fencingToken || state.lease.expiresAt !== lease.expiresAt) {
      throw new IntegrityError("pre-prompt recovery evidence changed before replacement launch");
    }
    return current;
  }
  // A runtime-bound recovery is fundamentally different from the narrow
  // pre-prompt retry above.  It may resume only the sealed native session and
  // only before we have journaled evidence that a repair prompt was sent.  The
  // proof deliberately excludes the mutable service lease: a later process
  // may rotate that lease, but cannot change the sealed runtime, custody, or
  // prompt-boundary journal evidence.
  function runtimeRecoveryRepairEvidence(jobId, submission = null, state = snapshot(jobId)) {
    if (!(state.job.state === "running" || state.job.state === "recovery_required" || state.job.state === "repairing") || !state.serviceRuntime ||
        state.bindings.candidate !== null || state.bindings.providerCandidateDigest !== null || state.candidateHistory.length !== 0 ||
        state.usage !== null || state.cancellation !== null || state.attempts.length < 1) {
      throw new IntegrityError("runtime recovery repair preconditions are unavailable");
    }
    const attempts = state.attempts;
    for (const [index, item] of attempts.entries()) {
      if (item.jobId !== jobId || item.number !== index + 1 || item.profileDigest !== state.job.profileDigest) {
        throw new IntegrityError("runtime recovery repair attempt differs");
      }
    }
    const attempt = attempts.at(-1);
    const envelope = loadEnvelope(jobId, state);
    if (!envelope.custody || envelope.profileDigest !== state.job.profileDigest ||
        envelope.custody.worktreeCustodyDigest !== state.serviceRuntime.worktreeCustodyDigest) {
      throw new IntegrityError("runtime recovery repair custody differs");
    }
    if (submission !== null) {
      validateRepairSubmissionContext(jobId, submission, state);
      replayLinkedCustody(jobId, state, submission);
    }
    else if (custodyApi.revalidate(envelope.custody) === null) throw new IntegrityError("runtime recovery repair custody cannot be revalidated");
    const profile = resolveProfile(envelope.profileId);
    const profileBinding = profileEnvelopeBinding(jobId, state, envelope, profile, { permitLegacyAuthority: true });
    for (const prior of attempts.slice(0, -1)) {
      if (!absent(runtimePath(jobId, prior.attemptId), "runtime recovery repair prior runtime evidence")) {
        throw new IntegrityError("runtime recovery repair prior attempt crossed the native session boundary");
      }
    }
    const runtime = readRuntime(jobId, attempt.attemptId);
    if (runtime.profileDigest !== profile.profileDigest || runtime.worktreeCustodyDigest !== envelope.custody.worktreeCustodyDigest ||
        runtime.grantDigest !== state.bindings.grantDigest || runtime.receiptDigest !== state.bindings.receiptDigest) {
      throw new IntegrityError("runtime recovery repair runtime differs");
    }
    runtimeSessionBoundEvent(jobId, attempt, runtime);
    const events = jobs.readStatus(jobId, { afterCursor: 0 }).events;
    const priorAttemptProofs = attempts.slice(0, -1).map((prior) => {
      const priorEvents = events.filter((event) => event.attemptId === prior.attemptId);
      if (priorEvents.length !== 1 || priorEvents[0].kind !== "failure" || priorEvents[0].data?.code !== "acp_failure") {
        throw new IntegrityError("runtime recovery repair prior attempt lacks exact ACP failure evidence");
      }
      return { attemptId: prior.attemptId, attemptNumber: prior.number, eventDigest: digestOf(priorEvents) };
    });
    const attemptEvents = events.filter((event) => event.attemptId === attempt.attemptId);
    const sessionBound = attemptEvents.filter((event) => event.kind === "progress" && event.data?.type === "native_session_bound");
    const failureEvents = attemptEvents.filter((event) => event.kind === "failure");
    const failures = failureEvents.filter((event) => event.data?.code === "acp_failure" ||
      (event.data?.code === "execution_adapter_failure" && RECOVERABLE_HEADLESS_FAILURES.has(event.data?.failureKind) &&
        event.data?.diagnostics?.adapterVersion === HEADLESS_ADAPTER_VERSION) ||
      (state.recoveryRepair !== null && event.data?.code === "service_execution_failed"));
    const crossedTerminalBoundary = attemptEvents.some((event) => event.kind === "candidate_ready" ||
      ["native_terminal", "provider_candidate_ready", "candidate_signal", "usage", "recovery_repair_prompted"].includes(event.data?.type));
    const rawRunningProcessLoss = failures.length === 0;
    if (sessionBound.length !== 1 || crossedTerminalBoundary || failureEvents.length !== failures.length) {
      throw new IntegrityError("runtime recovery repair journal evidence differs");
    }
    if (rawRunningProcessLoss && (attempts.length !== 1 || !["running", "repairing", "recovery_required"].includes(state.job.state) ||
        attemptEvents.some((event) => event.kind !== "progress"))) {
      throw new IntegrityError("runtime recovery repair raw-running evidence differs");
    }
    const firstFailureIndex = rawRunningProcessLoss ? -1 : attemptEvents.indexOf(failures[0]);
    let retryFailureTail = rawRunningProcessLoss ? [] : attemptEvents.slice(firstFailureIndex + 1);
    if (!rawRunningProcessLoss && (firstFailureIndex < 0 || retryFailureTail.some((event) => event.kind !== "failure" ||
        !["acp_failure", "execution_adapter_failure", "service_execution_failed"].includes(event.data?.code)))) {
      throw new IntegrityError("runtime recovery repair retry tail has intervening journal evidence");
    }
    const expectedSessionReference = eventSessionReference(runtime.nativeSessionId);
    if (rawRunningProcessLoss && attemptEvents.some((event) => event.requestId !== runtime.requestId ||
        event.nativeSessionId !== expectedSessionReference || !Number.isInteger(event.fencingToken) || event.fencingToken < runtime.fencingToken)) {
      throw new IntegrityError("runtime recovery repair raw-running correlation differs");
    }
    let priorFailureFence = runtime.fencingToken - 1;
    for (const event of failures) {
      if (event.requestId !== runtime.requestId || event.nativeSessionId !== expectedSessionReference ||
          !Number.isInteger(event.fencingToken) || event.fencingToken <= priorFailureFence) {
        throw new IntegrityError("runtime recovery repair failure evidence differs from the sealed request, session, or fence sequence");
      }
      priorFailureFence = event.fencingToken;
    }
    if (state.recoveryRepair === null && retryFailureTail.length !== 0) {
      throw new IntegrityError("runtime recovery repair failures lack a durable repair request");
    }
    const originalEvents = rawRunningProcessLoss ? events : events.filter((event) => event.attemptId !== attempt.attemptId || event.cursor <= failures[0].cursor);
    const originalProof = {
      operation: rawRunningProcessLoss ? "runtime_raw_running_process_loss_recovery_repair" : "runtime_native_session_recovery_repair",
      jobId, attemptId: attempt.attemptId, nativeSessionId: runtime.nativeSessionId, requestId: runtime.requestId,
      runtimeFence: runtime.fencingToken, runtimeEvidenceDigest: digestOf(runtime), childProcessIdentity: runtime.childProcessIdentity, contextDigest: validateServiceContext(state.serviceContext, jobId).contextDigest,
      sourceCustodyDigest: state.admission.sourceCustodyDigest, profileDigest: profile.profileDigest,
      profileAttestationFingerprint: profileBinding.attestationFingerprint,
      legacyRecoveryProfileProofDigest: profileBinding.legacyRecoveryProfileProofDigest,
      profileReattestationProof: profileBinding.profileReattestationProof,
      custodyDigest: state.serviceRuntime.custodyDigest, worktreeCustodyDigest: envelope.custody.worktreeCustodyDigest,
      priorAttempts: priorAttemptProofs, eventDigest: digestOf(originalEvents)
    };
    const currentAuthorityProofDigest = digestOf(originalProof);
    let opaqueHistoricalAuthorization = null;
    if (state.recoveryRepair !== null && state.recoveryRepair.recoveryProofDigest !== currentAuthorityProofDigest) {
      // Some already-authorized repairs were journaled by an intermediate
      // controller whose proof schema is not reconstructible by this build.
      // Treat that digest as opaque only when the hash-chained journal proves
      // the exact one-use mutation and its correlated post-request failure.
      // This lane can replay an authorization; it can never create one.
      const zeroDigest = `sha256:${"0".repeat(64)}`;
      if (submission === null || digestOf(submission.findings) !== state.recoveryRepair.findingsDigest ||
          state.recoveryRepair.repairGrantDigest === zeroDigest || state.recoveryRepair.repairReceiptDigest === zeroDigest) {
        throw new IntegrityError("runtime recovery repair opaque authorization preconditions differ");
      }
      const verified = jobs.readVerified(jobId, { includeRecords: true });
      const requestRecords = verified.records.filter((record) => record.type === "idempotent_mutation" &&
        record.payload?.effect?.type === "recovery_repair_requested");
      if (requestRecords.length !== 1) throw new IntegrityError("runtime recovery repair opaque authorization journal differs");
      const requestRecord = requestRecords[0], mutation = requestRecord.payload;
      if (digestOf(mutation.effect.payload) !== digestOf(state.recoveryRepair) || mutation.idempotency?.operation !== "recovery_repair" ||
          mutation.idempotency?.key !== submission.idempotencyKey || jobs.replayOperation(jobId, {
            operation: "recovery_repair", idempotencyKey: submission.idempotencyKey, request: state.recoveryRepair
          }) === null) {
        throw new IntegrityError("runtime recovery repair opaque authorization receipt differs");
      }
      if (retryFailureTail.length === 0) {
        // Intermediate controllers could authorize recovery directly from a
        // raw-running job. In that shape the first attempt failure is itself
        // the post-request load failure, not an earlier failure followed by a
        // retry tail. Admit it only when the verified journal places that
        // exact correlated failure after the one-use authority mutation.
        const eventRecordById = new Map(verified.records.filter((record) => record.type === "event").map((record) => [record.payload?.eventId, record]));
        retryFailureTail = failures.filter((event) => eventRecordById.get(event.eventId)?.cursor > requestRecord.cursor);
      }
      if (retryFailureTail.length === 0) throw new IntegrityError("runtime recovery repair opaque authorization lacks a post-request failure");
      const tailEventIds = new Set(retryFailureTail.map((event) => event.eventId));
      const tailRecords = verified.records.filter((record) => record.type === "event" && tailEventIds.has(record.payload?.eventId));
      if (tailRecords.length !== retryFailureTail.length || tailRecords.some((record) => record.cursor <= requestRecord.cursor)) {
        throw new IntegrityError("runtime recovery repair opaque failure tail predates authorization");
      }
      opaqueHistoricalAuthorization = {
        version: "agent-platform.grok-builder-opaque-recovery-authorization.v1",
        storedRecoveryProofDigest: state.recoveryRepair.recoveryProofDigest,
        currentRecoveryProofDigest: currentAuthorityProofDigest,
        profileAttestationFingerprint: profileBinding.attestationFingerprint,
        legacyRecoveryProfileProofDigest: profileBinding.legacyRecoveryProfileProofDigest,
        requestRecordDigest: requestRecord.digest,
        idempotencyReceiptDigest: digestOf(mutation.idempotency)
      };
    }
    const authorityProofDigest = state.recoveryRepair?.recoveryProofDigest ?? currentAuthorityProofDigest;
    if (state.recoveryRepair !== null && (state.recoveryRepair.expectedAttemptId !== attempt.attemptId ||
        state.recoveryRepair.expectedNativeSessionId !== runtime.nativeSessionId || state.recoveryRepair.recoveryProofDigest !== authorityProofDigest)) {
      throw new IntegrityError("runtime recovery repair retry does not bind the original authorized proof");
    }
    // Keep the one-use authority request immutable. A retry gets a separate
    // fence proof over that request and the exact post-request failure tail.
    const retryProof = retryFailureTail.length === 0 ? null : {
      operation: "runtime_native_session_recovery_repair_retry", jobId, attemptId: attempt.attemptId,
      nativeSessionId: runtime.nativeSessionId, originalRecoveryProofDigest: authorityProofDigest,
      recoveryRepairRequestDigest: digestOf(state.recoveryRepair),
      ...(opaqueHistoricalAuthorization === null ? {} : { opaqueHistoricalAuthorization }),
      failureTail: retryFailureTail.map((event) => ({ eventId: event.eventId, cursor: event.cursor, fencingToken: event.fencingToken, requestId: event.requestId, eventDigest: digestOf(event) })),
      eventDigest: digestOf(events)
    };
    const proofDigest = retryProof === null ? authorityProofDigest : digestOf(retryProof);
    return Object.freeze({ ...originalProof, authorityProofDigest, retryProof, proofDigest, rawRunningProcessLoss, attempt, runtime, profile, envelope });
  }
  function runtimeRecoveryRepairSlotProof(jobId, profileDigest) {
    const slot = jobs.readExecutionSlot();
    if (slot === null) return null;
    if (slot.jobId !== jobId || slot.profileDigest !== profileDigest) {
      throw new LeaseConflictError("runtime recovery repair cannot replace an unrelated execution slot");
    }
    if (slot.expiresAt > now()) throw new LeaseConflictError("runtime recovery repair waits for the prior execution slot to expire");
    return slot.digest;
  }
  function verifyRuntimeRecoveryRepairAfterFence(jobId, submission, recovery, lease) {
    if (!recovery || !DIGEST.test(recovery.proofDigest) || !lease || lease.ownerId !== ownerId) {
      throw new IntegrityError("runtime recovery repair fence is malformed");
    }
    const current = runtimeRecoveryRepairEvidence(jobId, submission);
    if (current.proofDigest !== recovery.proofDigest || current.attempt.attemptId !== recovery.expectedAttemptId ||
        current.runtime.nativeSessionId !== recovery.expectedNativeSessionId) {
      throw new IntegrityError("runtime recovery repair evidence changed before session resume");
    }
    const state = snapshot(jobId);
    if (state.lease?.ownerId !== ownerId || state.lease.fencingToken !== lease.fencingToken || state.lease.expiresAt !== lease.expiresAt) {
      throw new IntegrityError("runtime recovery repair replacement lease differs");
    }
    return current;
  }
  function replayLinkedCustody(jobId, state, submission) {
    const custody = state.serviceRuntime?.custody;
    if (!custody || !custody.linkedWorktree || custody.jobId !== jobId || custody.sourceRoot !== submission.source.repositoryRoot ||
        custody.sourceSha !== submission.source.sourceSha || custody.destinationRoot !== submission.source.destinationRoot ||
        custody.branchPolicy !== submission.source.branchPolicy || custody.sourceCustodyDigest !== state.admission.sourceCustodyDigest ||
        custody.sourceCustodyDigest !== state.job.sourceCustodyDigest || state.serviceRuntime.custodyDigest !== digestOf(custody) ||
        state.serviceRuntime.worktreeCustodyDigest !== custody.worktreeCustodyDigest ||
        state.serviceRuntime.destinationDigest !== digestOf(custody.destinationRoot)) {
      throw new IntegrityError("replayed linked worktree custody differs from immutable admission");
    }
    const inventory = custodyApi.revalidate(custody);
    if (inventory === null || inventory === undefined) throw new IntegrityError("replayed linked worktree custody cannot be revalidated");
    return custody;
  }
  function prepareNewReplay(jobId, submission, context) {
    const state = snapshot(jobId);
    const durable = validateServiceContext(state.serviceContext, jobId);
    if (durable.contextDigest !== context.contextDigest || durable.context.idempotencyKey !== submission.idempotencyKey) throw new IdempotencyConflictError("submission idempotency key or request digest differs");
    const receipt = jobs.replayOperation(jobId, { operation: "submit", idempotencyKey: submission.idempotencyKey, request: { serviceContext: context } });
    if (!receipt) throw new IntegrityError("admission replay receipt is absent");
    const resumablePreflight = (state.job.state === "preflighting" || state.job.state === "recovery_required") && state.attempts.length === 0 && state.serviceRuntime;
    const prePromptRecovery = active.has(jobId) ? null : prePromptRecoveryEvidence(jobId, state);
    // Never rotate a still-live owner merely because the status projection is
    // recovery_required.  The caller may replay after expiry, at which point
    // the exact evidence is rechecked again under the replacement fence.
    const resumablePrePrompt = prePromptRecovery !== null && state.lease.expiresAt <= now();
    if ((state.job.state !== "queued" && !resumablePreflight && !resumablePrePrompt) || active.has(jobId)) return { receipt, runtime: null };
    const profile = resolveProfile(submission.profileId);
    if (state.job.profileDigest !== profile.profileDigest) throw new IntegrityError("replayed submission profile differs");
    // Once preflight has journaled a linked worktree, its destination is no
    // longer admissible as new.  Exact replay proves it against the immutable
    // submission/admission and revalidates that same custody instead.
    const preliminary = state.serviceRuntime?.custody
      ? replayLinkedCustody(jobId, state, submission)
      : custodyApi.admit({ jobId, source: submission.source, stateRoot: jobs.stateRoot });
    if (!preliminary || preliminary.sourceCustodyDigest !== state.admission.sourceCustodyDigest ||
        canonicalDestination(preliminary.destinationRoot) !== state.admission.destinationRoot) {
      throw new IntegrityError("replayed source custody or destination differs");
    }
    let envelope;
    if (state.serviceRuntime) {
      const attachedCustody = state.serviceRuntime.custody;
      if (absent(envelopePath(jobId), "service envelope")) {
        envelope = writeEnvelope(jobId, makeEnvelope(jobId, context, profile, preliminary, attachedCustody));
      } else {
        const persisted = safeReadSeal(envelopePath(jobId), "service envelope", ENVELOPE_BYTES);
        validateEnvelope(persisted, jobId);
        // A crash between service-runtime journaling and envelope replacement
        // leaves the older no-custody seal, which may be completed from the
        // immutable runtime record.  A custody-bearing seal is instead
        // validated against the current runtime as-is; temporarily pretending
        // that runtime is absent would incorrectly classify its custody as
        // unjournaled on a valid replay.
        if (persisted.custody === null) {
          const raw = verifyEnvelopeAdmission(jobId, persisted, { ...state, serviceRuntime: null });
          envelope = writeEnvelope(jobId, { ...raw, custody: attachedCustody });
        } else envelope = loadEnvelope(jobId, state);
      }
    } else if (absent(envelopePath(jobId), "service envelope")) envelope = writeEnvelope(jobId, makeEnvelope(jobId, context, profile, preliminary));
    else envelope = loadEnvelope(jobId, state);
    if (envelope.profileDigest !== profile.profileDigest || envelope.sourceCustodyDigest !== preliminary.sourceCustodyDigest) throw new IntegrityError("replayed envelope differs");
    const runtime = { submission, profile, preliminary, custody: envelope.custody, envelope, nativeSessionId: null, model: state.admission.model ?? "grok-build", prePromptRecovery: resumablePrePrompt ? prePromptRecovery : null };
    volatile.set(jobId, runtime);
    return { receipt, runtime };
  }
  function prepareRepairReplay(submission) {
    const jobId = submission.continuation.jobId;
    validateRepairSubmissionContext(jobId, submission);
    const request = { findingsDigest: digestOf(submission.findings), expectedAttemptId: submission.continuation.expectedAttemptId, expectedCandidateDigest: submission.continuation.expectedCandidateDigest };
    const replay = jobs.replayOperation(jobId, { operation: "repair", idempotencyKey: submission.idempotencyKey, request });
    const state = snapshot(jobId);
    if (replay === null) return { replay: null, request, state };
    if (state.job.state !== "repairing") return { replay, request, state };
    const candidate = validateCandidate(jobId, submission.continuation);
    if (submission.profileId !== candidate.envelope.profileId) throw new IntegrityError("repair profile differs from immutable candidate profile");
    const history = state.candidateHistory.at(-1);
    if (!sameRepair(history, request)) throw new IntegrityError("durable repair request differs");
    const lease = candidateLease(jobId, candidate);
    releaseRecoveredExecutionSlot(jobId, candidate.profile.profileDigest, lease);
    volatile.set(jobId, { submission, profile: candidate.profile, preliminary: null, custody: candidate.envelope.custody, envelope: candidate.envelope, nativeSessionId: candidate.manifest.nativeSessionId, model: state.admission.model ?? "grok-build" });
    schedule(jobId, { lease, nativeSessionId: candidate.manifest.nativeSessionId });
    return { replay, request, state: snapshot(jobId) };
  }
  function drainQueue() {
    for (const [jobId, runtime] of volatile) {
      let state;
      try { state = snapshot(jobId).job.state; } catch { continue; }
      if (!active.has(jobId) && (state === "queued" || state === "repairing")) schedule(jobId, { nativeSessionId: runtime.nativeSessionId });
    }
  }
  function schedule(jobId, { lease = null, nativeSessionId = null } = {}) {
    if (active.has(jobId)) return;
    const record = { task: null, runtime: null, lease, slot: null, profileDigest: null };
    active.set(jobId, record);
    record.task = Promise.resolve().then(async () => {
      let heldSlot = false;
      let serviceStage = "runtime_revalidation";
      let attempt = null;
      let requestId = null;
      let sessionId = nativeSessionId;
      try {
        const runtime = volatile.get(jobId);
        if (!runtime) throw new IntegrityError("launch material is absent after restart");
        const before = snapshot(jobId);
        const noAttemptRuntimeRecovery = (before.job.state === "preflighting" || before.job.state === "recovery_required") &&
          before.attempts.length === 0 && before.serviceRuntime !== null;
        const prePromptRecovery = runtime.prePromptRecovery ?? null;
        const runtimeRecoveryRepair = runtime.recoveryRepair ?? null;
        let runtimeRepairEvidence = null;
        if (prePromptRecovery !== null && prePromptRecoveryEvidence(jobId, before)?.proofDigest !== prePromptRecovery.proofDigest) {
          throw new IntegrityError("pre-prompt recovery evidence no longer matches the replay");
        }
        if (runtimeRecoveryRepair !== null) {
          runtimeRepairEvidence = runtimeRecoveryRepairEvidence(jobId, runtime.submission, before);
          if (runtimeRepairEvidence.proofDigest !== runtimeRecoveryRepair.proofDigest) {
            throw new IntegrityError("runtime recovery repair evidence no longer matches the replay");
          }
        }
        record.lease = lease ?? currentLease(jobId, before, {
          // A queued/repairing record has not passed the preflight launch
          // boundary.  A no-attempt runtime record is equally safe only when
          // its exact journal-bound custody is present; the context digest is
          // supplied as the explicit replay proof to JobStore.
          allowExpiredRecovery: before.job.state === "queued" || before.job.state === "repairing" || noAttemptRuntimeRecovery || prePromptRecovery !== null || runtimeRecoveryRepair !== null,
          priorOwnerProofDigest: runtimeRecoveryRepair?.proofDigest ?? prePromptRecovery?.proofDigest ?? null
        });
        if (prePromptRecovery !== null) verifyPrePromptRecoveryAfterFence(jobId, prePromptRecovery, record.lease);
        if (runtimeRecoveryRepair !== null) verifyRuntimeRecoveryRepairAfterFence(jobId, runtime.submission, runtimeRecoveryRepair, record.lease);
        record.profileDigest = runtime.profile.profileDigest;
        serviceStage = "execution_slot";
        try {
          record.slot = jobs.acquireExecutionSlot(jobId, {
            ownerId, fencingToken: record.lease.fencingToken, profileDigest: runtime.profile.profileDigest,
            expiresAt: record.lease.expiresAt, maximumActiveJobs: profileLimit(runtime.profile),
            priorSlotProofDigest: runtimeRecoveryRepair !== null
              ? runtimeRecoveryRepairSlotProof(jobId, runtime.profile.profileDigest)
              : prePromptRecovery?.priorSlotDigest ?? null
          });
          heldSlot = true;
        } catch (error) {
          if (error instanceof LeaseConflictError && (before.job.state === "queued" || before.job.state === "repairing")) return;
          throw error;
        }
        serviceStage = "state_transition";
        const state = snapshot(jobId);
        if (state.job.state === "queued" || state.job.state === "repairing") {
          jobs.transition(jobId, "preflighting", { fence: record.lease.fencingToken });
        } else if (prePromptRecovery !== null && state.job.state === "running") {
          // The replacement owner first records an explicit recovery boundary;
          // this makes the otherwise raw running state auditable before it can
          // create attempt two.
          jobs.transition(jobId, "recovery_required", { fence: record.lease.fencingToken, allowRecovery: true });
          jobs.transition(jobId, "preflighting", { fence: record.lease.fencingToken });
        } else if (state.job.state === "recovery_required" &&
          (runtimeRecoveryRepair !== null || prePromptRecovery !== null || (state.attempts.length === 0 && state.serviceRuntime))) {
          jobs.transition(jobId, "preflighting", { fence: record.lease.fencingToken });
        } else if (state.job.state !== "preflighting" || state.attempts.length !== 0 || !state.serviceRuntime) {
          throw new IntegrityError("job is not safely schedulable");
        }
        if (!runtime.custody?.linkedWorktree) {
          const preCreationEnvelope = loadEnvelope(jobId);
          runtime.custody = custodyApi.create(custodyApi.reserve(runtime.preliminary, jobs));
          jobs.bindServiceRuntime(jobId, {
            custodyDigest: digestOf(runtime.custody),
            worktreeCustodyDigest: runtime.custody.worktreeCustodyDigest,
            destinationDigest: digestOf(runtime.custody.destinationRoot),
            custody: runtime.custody,
            fence: record.lease.fencingToken
          });
          runtime.envelope = writeEnvelope(jobId, { ...preCreationEnvelope, custody: runtime.custody });
        }
        jobs.transition(jobId, "starting", { fence: record.lease.fencingToken });
        if (runtimeRecoveryRepair !== null) {
          attempt = runtimeRepairEvidence.attempt;
          requestId = runtimeRepairEvidence.runtime.requestId;
          sessionId = runtimeRecoveryRepair.expectedNativeSessionId;
        } else {
          const number = jobs.readAttempts(jobId).length + 1;
          attempt = { contractVersion: CONTRACT_VERSIONS.attempt, attemptId: stableId("attempt", { jobId, number }), jobId, number, state: "queued", profileDigest: runtime.profile.profileDigest };
          jobs.recordAttempt(jobId, attempt, { fence: record.lease.fencingToken });
        }
        jobs.transition(jobId, "running", { fence: record.lease.fencingToken });
        requestId ??= stableId("request", { jobId, attemptId: attempt.attemptId });
        serviceStage = "adapter_creation";
        const adapter = createAdapter({
          verifyFence: async (correlation) => fence(correlation),
          verifyCustody: async () => {
            try {
              const current = loadEnvelope(jobId);
              if (!current.custody || current.custody.worktreeCustodyDigest !== runtime.custody.worktreeCustodyDigest) return false;
              return custodyApi.revalidate(current.custody) !== null;
            } catch { return false; }
          },
          onSessionBound: async (bound) => {
            // The runtime seal/event pair is the prompt boundary.  Reject a
            // late old-process callback before either record is written; ACP
            // cannot send its prompt until this awaited hook returns.
            if (!fence({ jobId, fencingToken: record.lease.fencingToken })) {
              throw new LeaseConflictError("native session binding lost its execution fence");
            }
            if (runtimeRecoveryRepair !== null) {
              if (bound.nativeSessionId !== runtimeRecoveryRepair.expectedNativeSessionId) {
                throw new IntegrityError("recovered native session identity differs");
              }
              const evidence = readRuntime(jobId, attempt.attemptId);
              runtimeSessionBoundEvent(jobId, attempt, evidence);
              sessionId = evidence.nativeSessionId;
              return;
            }
            sessionId = bound.nativeSessionId;
            const authorityBinding = snapshot(jobId).bindings;
            writeRuntime(jobId, attempt, requestId, sessionId, record.lease.fencingToken, runtime.profile.profileDigest, runtime.custody.worktreeCustodyDigest, authorityBinding.grantDigest, authorityBinding.receiptDigest, bound.childProcessIdentity ?? null);
            append(jobId, attempt, record.lease.fencingToken, sessionId, requestId, "progress", { type: "native_session_bound" });
          },
          onProcessStarted: async (started) => {
            if (!fence({ jobId, fencingToken: record.lease.fencingToken }) || started.nativeSessionId !== sessionId || started.requestId !== requestId) throw new LeaseConflictError("headless process identity lost its execution fence");
            writeProcessIdentity(jobId, attempt, started.childProcessIdentity, { continuation: runtimeRecoveryRepair !== null });
          },
          onPromptDispatch: async (dispatch = {}) => {
            if (dispatch.ambiguity === "headless_spawn_is_prompt_boundary") {
              append(jobId, attempt, record.lease.fencingToken, sessionId, requestId, "progress", {
                type: "headless_spawn_boundary",
                adapterVersion: typeof dispatch.adapterVersion === "string" ? dispatch.adapterVersion : null,
                argvDigest: typeof dispatch.argvDigest === "string" && DIGEST.test(dispatch.argvDigest) ? dispatch.argvDigest : null,
                effectiveLaunch: compactEventValue(dispatch.effectiveLaunch),
                ambiguity: "provider_prompt_acceptance_is_not_separately_proven"
              });
            }
            if (runtimeRecoveryRepair !== null) {
              append(jobId, attempt, record.lease.fencingToken, sessionId, requestId, "progress", { type: "recovery_repair_prompted", dispatchVersion: "agent-platform.grok-builder-prompt-dispatch.v1" });
            }
          },
          onEvent: async (event) => {
            const kind = event.kind === "input_required" ? "input_required" : event.kind === "cancelled" ? "cancelled" : ["warning", "permission_denied"].includes(event.kind) ? "warning" : "progress";
            append(jobId, attempt, record.lease.fencingToken, event.nativeSessionId ?? sessionId, requestId, kind, { type: event.kind, value: compactEventValue(event.value) });
          },
          onFailure: async (failure) => markRecovery(jobId, record.lease, adapterFailureCode, attempt, sessionId, requestId, failure),
          beforeCancel: async () => {},
          onCancelAcknowledged: async () => acknowledgeCancellation(jobId, record.lease)
        });
        let execution = null, authorityLost = false;
        const heartbeat = timers.setInterval?.(() => {
          try {
            const renewed = jobs.renewExecutionLease(jobId, { ownerId, fencingToken: record.lease.fencingToken, durationMs: leaseDurationMs });
            jobs.renewExecutionSlot(jobId, { ownerId, fencingToken: renewed.fencingToken, profileDigest: runtime.profile.profileDigest, expiresAt: renewed.expiresAt });
            record.lease = renewed;
          } catch {
            authorityLost = true;
            try { execution?.child?.stop?.(); } catch { /* stop is best effort after durable loss */ }
            markRecovery(jobId, record.lease, "lease_renewal_failed", attempt, sessionId, requestId);
          }
        }, heartbeatMs);
        try {
          // The launcher can spend significant time starting a native session.
          // Begin the lease/slot heartbeat before that await so a slow ACP host
          // cannot silently outlive its durable authority.
          serviceStage = "adapter_start";
          execution = await adapter.start({
            jobId, attemptId: attempt.attemptId, requestId, fencingToken: record.lease.fencingToken,
            attestation: runtime.profile.attestation, inspection: runtime.profile.inspection,
            stateRoot, worktree: runtime.custody.destinationRoot, prompt: makePrompt(runtime.submission),
            nativeSessionId: sessionId, model: runtime.model ?? "grok-build"
          });
          // A custom or future adapter may not resolve start until after the
          // heartbeat has already detected lost authority. Never publish that
          // late handle or consume its terminal result.
          if (authorityLost || snapshot(jobId).job.state === "recovery_required") {
            try { execution.child?.stop?.(); } catch { /* authority is already lost; stop remains best effort */ }
            return;
          }
          record.runtime = execution;
          serviceStage = "runtime_wait";
          // A cancellation can arrive while ACP is launching/initializing: the
          // durable intent then predates the runtime handle.  Do not let that
          // gap self-certify a pre-start cancellation; immediately re-drive the
          // real protocol cancellation once the child handle exists.
          if (snapshot(jobId).job.state === "cancelling") {
            await execution.cancel();
            return;
          }
          const outcome = await execution.done;
          if (outcome.state === "cancelled") return;
          if (outcome.state !== "candidate_ready" || typeof outcome.assistantOutputDigest !== "string" || !DIGEST.test(outcome.assistantOutputDigest)) {
            throw new IntegrityError("execution adapter result lacks normalized current-turn assistant output evidence");
          }
          if (outcome.usage !== undefined || outcome.cost !== undefined) jobs.recordUsage(jobId, { usage: outcome.usage ?? null, cost: outcome.cost ?? null, fence: record.lease.fencingToken });
          append(jobId, attempt, record.lease.fencingToken, sessionId, requestId, "progress", { type: "native_terminal" });
          // This event binds normalized current-turn output and terminal
          // protocol evidence before the locally derived manifest is written.
          // Marker text, if present in the narrative, has no authority effect.
          append(jobId, attempt, record.lease.fencingToken, sessionId, requestId, "progress", {
            type: "provider_candidate_ready", providerCandidateDigest: outcome.assistantOutputDigest,
            terminalEvidenceDigest: typeof outcome.terminalEvidenceDigest === "string" && DIGEST.test(outcome.terminalEvidenceDigest)
              ? outcome.terminalEvidenceDigest : null
          });
          const runtimeEvidence = readRuntime(jobId, attempt.attemptId);
          const publication = publishCandidatePublication(jobId, attempt, runtimeEvidence, runtime.profile, runtime.custody, outcome.assistantOutputDigest, record.lease);
          append(jobId, attempt, record.lease.fencingToken, sessionId, requestId, "candidate_ready", { candidateId: publication.candidate.candidateId, manifestDigest: publication.manifestDigest });
        } finally {
          if (heartbeat !== undefined && heartbeat !== null) timers.clearInterval?.(heartbeat);
        }
      } catch (error) {
        if (!(error instanceof LeaseConflictError && (snapshot(jobId).job.state === "queued" || snapshot(jobId).job.state === "repairing"))) {
          const safeStage = serviceStage === "adapter_start" && ["adapter_profile_drift", "adapter_guard", "adapter_child_launch", "adapter_child_launch_plan", "adapter_child_spawn", "adapter_child_identity", "adapter_child_parity"].includes(error?.safeStage)
            ? error.safeStage
            : serviceStage;
          markRecovery(jobId, record.lease, "service_execution_failed", attempt, sessionId, requestId, { serviceStage: safeStage });
        }
      } finally {
        if (heldSlot && record.lease && record.profileDigest) {
          try { jobs.releaseExecutionSlot(jobId, { ownerId, fencingToken: record.lease.fencingToken, profileDigest: record.profileDigest }); } catch { /* retained slot fails closed rather than widening concurrency */ }
        }
        active.delete(jobId);
        try {
          if (!["queued", "repairing"].includes(snapshot(jobId).job.state)) volatile.delete(jobId);
        } catch { volatile.delete(jobId); }
        if (heldSlot) drainQueue();
      }
    });
  }
  function acknowledgeCancellation(jobId, lease) {
    const state = snapshot(jobId);
    const cancellation = state.cancellation;
    if (!cancellation) throw new IntegrityError("cancellation intent is absent");
    jobs.acknowledgeCancellation(jobId, {
      expectedCancellationDigest: cancellation.cancellationDigest,
      idempotencyKey: stableId("cancelack", { jobId, cancellationDigest: cancellation.cancellationDigest }),
      fence: lease.fencingToken
    });
    terminalCleanup(jobId);
  }
  function recordCancellationRecovery(jobId, lease) {
    try {
      const state = snapshot(jobId);
      if (state.job.state !== "cancelling" || !lease) return;
      const attempt = state.attempts.at(-1);
      if (attempt) append(jobId, attempt, lease.fencingToken, null, stableId("request", { jobId, attemptId: attempt.attemptId }), "failure", { code: "cancellation_acknowledgement_lost" });
    } catch { /* the durable cancellation intent remains the recovery boundary */ }
  }
  function result(jobId, state = snapshot(jobId).job) {
    return Object.freeze({ jobId, state: state.state, cursor: state.eventCursor, nextActions: actionList(state.state) });
  }
  function terminalCleanup(jobId, state = snapshot(jobId).job) {
    if (!["accepted", "rejected", "cancelled"].includes(state.state)) return null;
    try { jobs.releaseReservation(jobId); return "released"; }
    catch { return "pending"; }
  }
  function terminalResult(jobId, state = snapshot(jobId).job) {
    const base = result(jobId, state), cleanup = terminalCleanup(jobId, state);
    return cleanup === null ? base : Object.freeze({ ...base, cleanup });
  }

  function submit(submission) {
    validateSubmission(submission);
    if (submission.mode === "repair") return submitRepair(submission);
    const jobId = jobIdForSubmission(submission.submissionId);
    const context = serviceContext(submission, jobId);
    if (!absent(jobs.snapshotPath(jobId), "job snapshot")) {
      const replay = prepareNewReplay(jobId, submission, context);
      const state = snapshot(jobId).job;
      // prepareNewReplay is the proof gate for every replayable state.  Do not
      // duplicate that narrower decision here: an unprompted raw-running
      // attempt is deliberately resumable only when its evidence qualified.
      if (replay.runtime !== null) schedule(jobId);
      return Object.freeze({ ...replay.receipt, nextActions: actionList(state.state) });
    }
    const claim = jobs.claimServiceSubmission(jobId, { idempotencyKey: submission.idempotencyKey, contextDigest: context.contextDigest });
    if (claim.status === "admitted") {
      const replay = prepareNewReplay(jobId, submission, context);
      return Object.freeze({ ...replay.receipt, nextActions: actionList(snapshot(jobId).job.state) });
    }
    if (!["claimed", "recovered"].includes(claim.status)) throw new LeaseConflictError("an exact submission admission is pending durable completion");
    const profile = resolveProfile(submission.profileId);
    const preliminary = custodyApi.admit({ jobId, source: submission.source, stateRoot: jobs.stateRoot });
    if (!preliminary || typeof preliminary.sourceCustodyDigest !== "string" || typeof preliminary.sourceRoot !== "string" || preliminary.sourceRoot !== submission.source.repositoryRoot || preliminary.destinationRoot !== submission.source.destinationRoot) throw new IntegrityError("immutable source admission did not bind the requested destination");
    const decision = approve(authorityRequest({ submission, jobId, context, profile, preliminary, mode: "new" }));
    const job = {
      contractVersion: CONTRACT_VERSIONS.job, jobId, submissionId: submission.submissionId, state: "queued",
      profileDigest: profile.profileDigest, sourceCustodyDigest: preliminary.sourceCustodyDigest, eventCursor: 0
    };
    const receipt = jobs.submit({
      job,
      admission: { destinationRoot: preliminary.destinationRoot, grantDigest: decision.grantDigest, receiptDigest: decision.receiptDigest, sourceCustodyDigest: preliminary.sourceCustodyDigest, profileDigest: profile.profileDigest, ...(decision.model === null ? {} : { model: decision.model }) },
      idempotencyKey: submission.idempotencyKey,
      serviceContext: context
    });
    const envelope = writeEnvelope(jobId, makeEnvelope(jobId, context, profile, preliminary));
    volatile.set(jobId, { submission, profile, preliminary, custody: null, envelope, nativeSessionId: null, model: decision.model ?? "grok-build" });
    schedule(jobId);
    return Object.freeze({ ...receipt, nextActions: actionList(receipt.state) });
  }
  function submitRepair(submission) {
    if (Object.hasOwn(submission.continuation, "expectedNativeSessionId")) return submitRuntimeRecoveryRepair(submission);
    const jobId = submission.continuation.jobId;
    const replayed = prepareRepairReplay(submission);
    if (replayed.replay !== null) return result(jobId, replayed.state.job);
    const history = replayed.state.candidateHistory.at(-1);
    if (replayed.state.job.state === "repairing" && history?.repairRequest) {
      throw new IdempotencyConflictError(sameRepair(history, replayed.request)
        ? "an active repair must use its original idempotency key"
        : "a different repair finding set is already active");
    }
    const candidate = validateCandidate(jobId, submission.continuation);
    if (submission.profileId !== candidate.envelope.profileId) throw new IntegrityError("repair profile differs from the immutable candidate profile");
    // Claim the current execution fence before asking a one-use host authority
    // for a repair grant; losing contenders must not consume approval.
    const lease = candidateLease(jobId, candidate);
    releaseRecoveredExecutionSlot(jobId, candidate.profile.profileDigest, lease);
    const decision = approve(authorityRequest({
      submission, jobId, context: validateServiceContext(replayed.state.serviceContext, jobId), profile: candidate.profile,
      preliminary: candidate.envelope.custody, mode: "repair", candidate: candidate.candidate, findingsDigest: replayed.request.findingsDigest
    }));
    jobs.requestRepair(jobId, {
      idempotencyKey: submission.idempotencyKey, findingsDigest: replayed.request.findingsDigest,
      expectedAttemptId: submission.continuation.expectedAttemptId, expectedCandidateDigest: submission.continuation.expectedCandidateDigest,
      repairGrantDigest: decision.grantDigest, repairReceiptDigest: decision.receiptDigest, fence: lease.fencingToken
    });
    volatile.set(jobId, { submission, profile: candidate.profile, preliminary: null, custody: candidate.envelope.custody, envelope: candidate.envelope, nativeSessionId: candidate.manifest.nativeSessionId, model: decision.model ?? replayed.state.admission.model ?? "grok-build" });
    schedule(jobId, { lease, nativeSessionId: candidate.manifest.nativeSessionId });
    return result(jobId);
  }
  function submitRuntimeRecoveryRepair(submission) {
    const jobId = submission.continuation.jobId;
    let state = snapshot(jobId);
    const repairContext = validateRepairSubmissionContext(jobId, submission, state);
    const stored = state.recoveryRepair;
    const submittedFindingsDigest = digestOf(submission.findings);
    // Once the idempotent recovery-repair mutation exists, a completed retry
    // can be answered from that durable request alone.  Requiring the
    // pre-prompt evidence again after candidate publication would turn a
    // successful one-prompt repair into a misleading integrity failure.
    if (stored && stored.findingsDigest === submittedFindingsDigest && stored.expectedAttemptId === submission.continuation.expectedAttemptId &&
        continuationMatchesNativeSession(submission.continuation.expectedNativeSessionId, stored.expectedNativeSessionId)) {
      const completedReplay = jobs.replayOperation(jobId, { operation: "recovery_repair", idempotencyKey: submission.idempotencyKey, request: stored });
      if (completedReplay !== null && state.job.state === "candidate_ready") return result(jobId);
      if (completedReplay !== null && active.has(jobId)) return result(jobId);
    }
    const evidence = runtimeRecoveryRepairEvidence(jobId, submission, state);
    if (submission.profileId !== evidence.profile.profileId || submission.continuation.expectedAttemptId !== evidence.attempt.attemptId ||
        !continuationMatchesNativeSession(submission.continuation.expectedNativeSessionId, evidence.runtime.nativeSessionId)) {
      throw new IntegrityError("runtime recovery repair continuation differs from sealed evidence");
    }
    const requestBase = {
      findingsDigest: submittedFindingsDigest, expectedAttemptId: evidence.attempt.attemptId,
      expectedNativeSessionId: evidence.runtime.nativeSessionId, recoveryProofDigest: evidence.authorityProofDigest
    };
    if (stored && stored.findingsDigest === requestBase.findingsDigest && stored.expectedAttemptId === requestBase.expectedAttemptId &&
        stored.expectedNativeSessionId === requestBase.expectedNativeSessionId && stored.recoveryProofDigest === requestBase.recoveryProofDigest) {
      const replay = jobs.replayOperation(jobId, { operation: "recovery_repair", idempotencyKey: submission.idempotencyKey, request: stored });
      if (replay === null || !["repairing", "recovery_required"].includes(state.job.state)) throw new IntegrityError("runtime recovery repair replay state differs");
      if (active.has(jobId)) return result(jobId);
      runtimeRecoveryRepairSlotProof(jobId, evidence.profile.profileDigest);
      const lease = currentLease(jobId, state, { allowExpiredRecovery: Boolean(state.lease && state.lease.expiresAt <= now()), priorOwnerProofDigest: evidence.proofDigest });
      volatile.set(jobId, {
        submission, profile: evidence.profile, preliminary: null, custody: evidence.envelope.custody, envelope: evidence.envelope,
        nativeSessionId: evidence.runtime.nativeSessionId, model: state.admission.model ?? "grok-build", recoveryRepair: { ...stored, proofDigest: evidence.proofDigest }
      });
      schedule(jobId, { lease, nativeSessionId: evidence.runtime.nativeSessionId });
      return result(jobId);
    }
    const rawRunningProcessLoss = evidence.rawRunningProcessLoss && ["running", "recovery_required"].includes(state.job.state) && state.recoveryRepair === null;
    if (!rawRunningProcessLoss && state.job.state !== "recovery_required") throw new IntegrityError("only recovery_required or proven raw-running process-loss jobs may resume a sealed native session");
    const priorLease = state.lease;
    if (rawRunningProcessLoss && (!priorLease || priorLease.expiresAt > now() || active.has(jobId))) {
      throw new LeaseConflictError("raw-running recovery waits for expiry and absence of a live local execution");
    }
    runtimeRecoveryRepairSlotProof(jobId, evidence.profile.profileDigest);
    const lease = currentLease(jobId, state, {
      allowExpiredRecovery: Boolean(state.lease && state.lease.expiresAt <= now()), priorOwnerProofDigest: evidence.proofDigest
    });
    if (rawRunningProcessLoss) {
      const childAbsenceRequest = Object.freeze({
        operation: "runtime_raw_running_child_absence", jobId, attemptId: evidence.attempt.attemptId,
        nativeSessionId: evidence.runtime.nativeSessionId, requestId: evidence.runtime.requestId,
        childProcessIdentity: validateChildProcessIdentity(evidence.runtime.childProcessIdentity, { required: true }),
        priorOwnerId: priorLease.ownerId, priorFencingToken: priorLease.fencingToken, priorExpiresAt: priorLease.expiresAt,
        replacementOwnerId: lease.ownerId, replacementFencingToken: lease.fencingToken, childAbsenceRequired: true
      });
      if (typeof acknowledgeRuntimeRecovery !== "function" || acknowledgeRuntimeRecovery(childAbsenceRequest) !== true) {
        throw new IntegrityError("host child-absence acknowledgement is required before raw-running recovery repair");
      }
      releaseRecoveredExecutionSlot(jobId, evidence.profile.profileDigest, lease);
      if (state.job.state !== "recovery_required") jobs.transition(jobId, "recovery_required", { fence: lease.fencingToken, allowRecovery: true });
    }
    const decision = approve(authorityRequest({
      submission, jobId, context: repairContext, profile: evidence.profile,
      preliminary: evidence.envelope.custody, mode: "repair", findingsDigest: submittedFindingsDigest,
      legacyRecoveryProfileProofDigest: evidence.legacyRecoveryProfileProofDigest,
      profileReattestationProof: evidence.profileReattestationProof,
      runtimeRecoveryProofDigest: evidence.authorityProofDigest
    }));
    const request = { ...requestBase, repairGrantDigest: decision.grantDigest, repairReceiptDigest: decision.receiptDigest };
    jobs.requestRecoveryRepair(jobId, { idempotencyKey: submission.idempotencyKey, ...request, fence: lease.fencingToken });
    state = snapshot(jobId);
    volatile.set(jobId, {
      submission, profile: evidence.profile, preliminary: null, custody: evidence.envelope.custody, envelope: evidence.envelope,
      nativeSessionId: evidence.runtime.nativeSessionId, model: decision.model ?? state.admission.model ?? "grok-build", recoveryRepair: { ...request, proofDigest: evidence.proofDigest }
    });
    schedule(jobId, { lease, nativeSessionId: evidence.runtime.nativeSessionId });
    return result(jobId);
  }
  function status({ jobId, afterCursor = 0 }) {
    // Use one stable observer read for both events and state. A second raw
    // snapshot read can race the provider worker's next journal append even
    // after readStatus itself has observed a consistent pair.
    let observed = jobs.readStatus(jobId, { afterCursor, includeSnapshot: true });
    let state = observed.snapshot;
    let job = observed.job;
    let candidate = null;
    try {
      const attempt = state.attempts.at(-1);
      if (!active.has(jobId) && state.bindings.candidate === null && attempt && ["running", "recovery_required"].includes(state.job.state) &&
          hasProviderCandidateEvent(jobId, attempt.attemptId)) {
        const recovered = recoverCandidatePublication(jobId, state);
        state = snapshot(jobId);
        if (recovered) {
          // Recovery may append the convenience candidate_ready event. Replay
          // from the caller's original cursor so the returned cursor can never
          // skip an event that the client has not observed.
          observed = jobs.readStatus(jobId, { afterCursor, includeSnapshot: true });
          state = observed.snapshot;
          job = observed.job;
        }
      }
      if (state.job.state === "candidate_ready") {
        const checked = validateCandidate(jobId);
        job = state.job;
        candidate = { candidateId: checked.candidate.candidateId, attemptId: checked.candidate.attemptId, manifestDigest: checked.candidate.manifestDigest, providerCandidateDigest: checked.binding.providerCandidateDigest };
      } else if (state.job.state === "cancelling" && !active.get(jobId)?.runtime) {
        job = { ...state.job, state: "recovery_required", recoveryReason: "cancellation_acknowledgement_required" };
      } else if (ACTIVE_STATES.has(state.job.state) && !volatile.has(jobId)) {
        job = { ...state.job, state: "recovery_required", recoveryReason: "restart_requires_explicit_recovery" };
      } else if ((state.job.state === "queued" || state.job.state === "repairing") && volatile.has(jobId) && !active.has(jobId)) {
        schedule(jobId, { nativeSessionId: volatile.get(jobId).nativeSessionId });
      }
    } catch {
      job = { ...state.job, state: "recovery_required", recoveryReason: "sealed_evidence_revalidation_failed" };
    }
    const cleanup = terminalCleanup(jobId, state.job);
    return Object.freeze({ job: { ...job, nextActions: actionList(job.state) }, events: observed.events, candidate, usage: state.usage?.usage ?? null, cost: state.usage?.cost ?? null, cleanup });
  }
  function collect(collection) {
    validateCollection(collection);
    const replay = jobs.replayOperation(collection.jobId, { operation: "collection", idempotencyKey: collection.idempotencyKey, request: collection });
    if (replay !== null) return terminalResult(collection.jobId, snapshot(collection.jobId).job);
    const checked = validateCandidate(collection.jobId, collection);
    const lease = candidateLease(collection.jobId, checked);
    releaseRecoveredExecutionSlot(collection.jobId, checked.profile.profileDigest, lease);
    jobs.disposeCandidate(collection.jobId, { collection, fence: lease.fencingToken });
    return terminalResult(collection.jobId);
  }
  async function cancel(cancellation) {
    validateCancellation(cancellation);
    const request = { reason: cancellation.reason };
    const replay = jobs.replayOperation(cancellation.jobId, { operation: "cancellation_intent", idempotencyKey: cancellation.idempotencyKey, request });
    let state = snapshot(cancellation.jobId);
    if (replay !== null && state.job.state === "cancelled") {
      return Object.freeze({ ...terminalResult(cancellation.jobId, state.job), cancellationDigest: state.cancellation?.cancellationDigest ?? null });
    }
    const hasActiveExecution = active.has(cancellation.jobId);
    // A current in-process launch (even one without a runtime handle yet)
    // must finish through ACP cancellation.  Only a process-loss replay may
    // ask the host to prove the child is absent.
    // A restarted host exposes an orphaned active record as recovery_required
    // through status(), but the durable state can still be raw running when
    // the prior process vanished before persisting its failure callback.  Let
    // cancellation close that exact gap only after lease expiry and the same
    // sealed child-absence proof required for durable recovery_required jobs.
    const recoveryCancellation = replay === null &&
      (state.job.state === "recovery_required" || state.job.state === "running") &&
      !hasActiveExecution;
    let recoveryChildProcessIdentity = null;
    const replayedLostCancellation = replay !== null && state.job.state === "cancelling" && !hasActiveExecution;
    let checkedCandidate = null;
    if (replay === null && state.job.state === "candidate_ready") checkedCandidate = validateCandidate(cancellation.jobId);
    if (replayedLostCancellation && state.cancellation?.fromState === "candidate_ready") checkedCandidate = validateCandidate(cancellation.jobId);
    let lease = active.get(cancellation.jobId)?.lease ?? null;
    const exactCancellationProof = !state.cancellation ? null : digestOf({
      operation: "replayed_cancellation_recovery", jobId: cancellation.jobId,
      cancellationDigest: state.cancellation.cancellationDigest
    });
    const recoveredProof = checkedCandidate === null ? exactCancellationProof : candidateTerminalProof(cancellation.jobId, checkedCandidate);
    if ((recoveryCancellation || replayedLostCancellation) && !hasLocalRecoveryFence(cancellation.jobId, state) &&
      (!state.lease || state.lease.expiresAt > now())) {
      throw new LeaseConflictError("lost cancellation acknowledgement waits for expiry of the prior execution lease");
    }
    if (recoveryCancellation && state.job.state === "running") {
      const recoveryAttempt = state.attempts.at(-1);
      if (!recoveryAttempt) throw new IntegrityError("raw-running cancellation lacks attempt evidence");
      recoveryChildProcessIdentity = readRuntime(cancellation.jobId, recoveryAttempt.attemptId).childProcessIdentity;
      if (recoveryChildProcessIdentity === null) throw new IntegrityError("raw-running cancellation lacks sealed child identity");
    }
    if (replay === null) {
      const recoveryProofDigest = recoveryCancellation ? digestOf({
        operation: "recovery_cancellation", jobId: cancellation.jobId, cancellationId: cancellation.cancellationId,
        idempotencyKey: cancellation.idempotencyKey, reason: cancellation.reason
      }) : null;
      lease ??= checkedCandidate === null
        ? currentLease(cancellation.jobId, state, { allowExpiredRecovery: recoveryCancellation, priorOwnerProofDigest: recoveryProofDigest })
        : candidateLease(cancellation.jobId, checkedCandidate);
      if (recoveryCancellation) {
        rememberRecoveryFence(cancellation.jobId, lease);
        const childAbsent = typeof acknowledgePreStartCancellation === "function" && await acknowledgePreStartCancellation(Object.freeze({
          jobId: cancellation.jobId, cancellationDigest: null, fencingToken: lease.fencingToken,
          originState: state.job.state, childAbsenceRequired: true, childProcessIdentity: recoveryChildProcessIdentity
        }));
        if (childAbsent !== true) throw new IntegrityError("host child-absence acknowledgement is required before cancelling recovery");
        releaseRecoveredExecutionSlot(cancellation.jobId, state.job.profileDigest, lease);
      }
      jobs.beginCancellation(cancellation.jobId, { reason: cancellation.reason, idempotencyKey: cancellation.idempotencyKey, fence: lease.fencingToken });
      state = snapshot(cancellation.jobId);
      if (recoveryCancellation) {
        try { acknowledgeCancellation(cancellation.jobId, lease); }
        catch { recordCancellationRecovery(cancellation.jobId, lease); }
        state = snapshot(cancellation.jobId);
        if (state.job.state === "cancelled") recoveryFences.delete(cancellation.jobId);
        return Object.freeze({ ...terminalResult(cancellation.jobId, state.job), cancellationDigest: state.cancellation?.cancellationDigest ?? null });
      }
    } else {
      lease ??= currentLease(cancellation.jobId, state, {
        allowExpiredRecovery: replayedLostCancellation,
        priorOwnerProofDigest: recoveredProof
      });
      if (replayedLostCancellation) {
        rememberRecoveryFence(cancellation.jobId, lease);
        const childAbsent = typeof acknowledgePreStartCancellation === "function" && await acknowledgePreStartCancellation(Object.freeze({
          jobId: cancellation.jobId, cancellationDigest: state.cancellation?.cancellationDigest ?? null, fencingToken: lease.fencingToken,
          originState: "recovery_required", childAbsenceRequired: true
        }));
        if (childAbsent !== true) throw new IntegrityError("host child-absence acknowledgement is required before replaying cancellation recovery");
        releaseRecoveredExecutionSlot(cancellation.jobId, state.job.profileDigest, lease);
        try { acknowledgeCancellation(cancellation.jobId, lease); }
        catch { recordCancellationRecovery(cancellation.jobId, lease); }
        state = snapshot(cancellation.jobId);
        if (state.job.state === "cancelled") recoveryFences.delete(cancellation.jobId);
        return Object.freeze({ ...terminalResult(cancellation.jobId, state.job), cancellationDigest: state.cancellation?.cancellationDigest ?? null });
      }
    }
    if (state.job.state === "cancelled") return Object.freeze({ ...terminalResult(cancellation.jobId), cancellationDigest: state.cancellation?.cancellationDigest ?? null });
    const runtime = active.get(cancellation.jobId)?.runtime;
    if (runtime) {
      try { await runtime.cancel(); }
      catch { recordCancellationRecovery(cancellation.jobId, lease); }
    } else if (["queued", "preflighting", "repairing", "candidate_ready"].includes(state.cancellation?.fromState) &&
      typeof acknowledgePreStartCancellation === "function" && await acknowledgePreStartCancellation(Object.freeze({
        jobId: cancellation.jobId, cancellationDigest: state.cancellation?.cancellationDigest ?? null, fencingToken: lease.fencingToken,
        originState: state.cancellation.fromState, childAbsenceRequired: true
      }))) {
      try {
        if (checkedCandidate !== null) releaseRecoveredExecutionSlot(cancellation.jobId, checkedCandidate.profile.profileDigest, lease);
        acknowledgeCancellation(cancellation.jobId, lease);
      }
      catch { recordCancellationRecovery(cancellation.jobId, lease); }
    } else {
      recordCancellationRecovery(cancellation.jobId, lease);
    }
    state = snapshot(cancellation.jobId);
    return Object.freeze({ ...terminalResult(cancellation.jobId, state.job), cancellationDigest: state.cancellation?.cancellationDigest ?? null });
  }

  const service = { submit, status, collect, cancel };
  Object.defineProperty(service, "runtimePolicy", {
    value: Object.freeze({ leaseDurationMs, heartbeatMs }),
    enumerable: false,
    configurable: false,
    writable: false
  });
  return Object.freeze(service);
}
