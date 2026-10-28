import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { dirname, isAbsolute, join, normalize, resolve } from "node:path";

import {
  assertAbsoluteStateRoot, validateAttempt, validateCandidate, validateCollection, validateEvent,
  validateGrant, validateJob, validateNormalizedCost, validateNormalizedUsage
} from "./contracts.mjs";
import { redactForBoundary } from "./redaction.mjs";
import { assertTransition, isTerminal } from "./lifecycle.mjs";

const STORE_VERSION = "agent-platform.grok-builder-job-store.v1";
const JOURNAL_VERSION = "agent-platform.grok-builder-job-journal.v1";
const EXECUTION_SLOT_VERSION = "agent-platform.grok-builder-execution-slot.v1";
const SUBMISSION_CLAIM_VERSION = "agent-platform.grok-builder-submission-claim.v1";
const DEFAULT_SUBMISSION_CLAIM_LEASE_MS = 30_000;
const MAX_JOURNAL_BYTES = 4 * 1024 * 1024;
const FORBIDDEN_KEYS = new Set([
  "argv", "arguments", "launchargv", "launcharguments", "rawacpframe", "rawacpframes", "acpframe", "acpframes",
  "stdout", "stderr", "rawstdout", "rawstderr", "exception", "stack", "environment", "env"
]);
const ACTIVE_EXECUTION_STATES = new Set(["preflighting", "starting", "running", "awaiting_codex_input", "repairing", "cancelling"]);
const RELEASE_ELIGIBLE_STATES = new Set(["accepted", "rejected", "cancelled", "failed"]);
const RESERVATION_DURABILITY = "file_fsynced_parent_flush_unavailable";

export class IntegrityError extends Error { constructor(message) { super(message); this.name = "IntegrityError"; } }
export class LeaseConflictError extends Error { constructor(message) { super(message); this.name = "LeaseConflictError"; } }
export class IdempotencyConflictError extends Error { constructor(message) { super(message); this.name = "IdempotencyConflictError"; } }

function fail(message) { throw new TypeError(message); }
function hash(value) { return `sha256:${createHash("sha256").update(value).digest("hex")}`; }
function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
function digestOf(value) { return hash(canonical(value)); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value)); }
function safeIdentifier(value, label) {
  if (typeof value !== "string" || !/^[a-z][a-z0-9_-]{2,63}$/.test(value)) fail(`${label} must be a valid identifier`);
  return value;
}
function safeSessionIdentifier(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 512) fail(`${label} must be bounded text`);
  return value;
}
function safeDigest(value, label) {
  if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/.test(value)) fail(`${label} must be a sha256 digest`);
  return value;
}
function fieldName(key) { return key.replace(/[-_]/g, "").toLowerCase(); }
function assertPersistable(value, label, seen = new WeakSet()) {
  if (value === null || ["string", "number", "boolean"].includes(typeof value)) return;
  if (typeof value !== "object" || value instanceof Error) fail(`${label} must not contain exception objects`);
  if (seen.has(value)) fail(`${label} must not be cyclic`);
  seen.add(value);
  if (Array.isArray(value)) { value.forEach((entry, index) => assertPersistable(entry, `${label}[${index}]`, seen)); return; }
  if (!plainObject(value)) fail(`${label} must contain plain JSON data`);
  Object.entries(value).forEach(([key, entry]) => {
    if (FORBIDDEN_KEYS.has(fieldName(key))) fail(`${label}.${key} is forbidden durable raw process data`);
    assertPersistable(entry, `${label}.${key}`, seen);
  });
}
function normalizeForStorage(value, label) {
  assertPersistable(value, label);
  const original = structuredClone(value);
  const redacted = redactForBoundary(original);
  restoreSafeCounters(original, redacted);
  return redacted;
}
function restoreSafeCounters(original, redacted) {
  if (original === null || typeof original !== "object" || redacted === null || typeof redacted !== "object") return;
  if (Array.isArray(original) && Array.isArray(redacted)) {
    original.forEach((entry, index) => restoreSafeCounters(entry, redacted[index]));
    return;
  }
  for (const [key, value] of Object.entries(original)) {
    if (["fencingToken", "inputTokens", "outputTokens", "totalTokens"].includes(key) && Number.isSafeInteger(value)) redacted[key] = value;
    else if (key in redacted) restoreSafeCounters(value, redacted[key]);
  }
}
function json(value) { return `${JSON.stringify(value)}\n`; }
function uniqueTemp(path) { return `${path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`; }
function durableWrite(path, value) {
  const temporary = uniqueTemp(path);
  let descriptor;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, json(value), "utf8");
    fsyncSync(descriptor);
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
  renameSync(temporary, path);
  let durability = "file_fsynced_parent_flush_unavailable";
  try {
    const parent = openSync(dirname(path), "r");
    try { fsyncSync(parent); durability = "file_and_parent_fsynced"; } finally { closeSync(parent); }
  } catch { /* Windows commonly cannot fsync a directory; do not overstate durability. */ }
  return durability;
}
function appendDurable(path, value) {
  const descriptor = openSync(path, "a", 0o600);
  try { writeFileSync(descriptor, json(value), "utf8"); fsyncSync(descriptor); } finally { closeSync(descriptor); }
}
function readJson(path, label) {
  try {
    const details = lstatSync(path);
    if (!details.isFile() || details.isSymbolicLink()) throw new Error("not a plain file");
    return JSON.parse(readFileSync(path, "utf8"));
  } catch { throw new IntegrityError(`${label} is missing or malformed`); }
}
function idempotencyDigest(operation, request) { return digestOf({ operation, request: normalizeForStorage(request, `idempotency.${operation}`) }); }
function canonicalDestination(destinationRoot) {
  if (typeof destinationRoot !== "string" || !isAbsolute(destinationRoot)) fail("admission.destinationRoot must be absolute");
  return normalize(resolve(destinationRoot)).replaceAll("\\", "/").toLowerCase();
}
function destinationPathsOverlap(left, right) {
  return left === right || left.startsWith(`${right}/`) || right.startsWith(`${left}/`);
}
function exactKeys(value, keys, label) {
  if (!plainObject(value)) fail(`${label} must be a plain object`);
  const actual = Object.keys(value).sort(), expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has unsupported or missing fields`);
}
function reservationFileStem(destinationDigest) { return destinationDigest.slice("sha256:".length); }
function validateReservationRecord(value) {
  exactKeys(value, ["contractVersion", "destinationDigest", "canonicalDestination", "jobId", "createdAt", "durability"], "reservation");
  if (value.contractVersion !== STORE_VERSION) fail("reservation contract version is unsupported");
  safeDigest(value.destinationDigest, "reservation.destinationDigest"); safeIdentifier(value.jobId, "reservation.jobId");
  if (!Number.isSafeInteger(value.createdAt) || value.createdAt < 0) fail("reservation.createdAt is invalid");
  if (value.durability !== RESERVATION_DURABILITY && value.durability !== "file_and_parent_fsynced") fail("reservation.durability is invalid");
  const normalized = canonicalDestination(value.canonicalDestination);
  if (normalized !== value.canonicalDestination || hash(normalized) !== value.destinationDigest) fail("reservation canonical destination is invalid");
  return value;
}
function validateClaimRecord(value) {
  exactKeys(value, ["contractVersion", "destinationDigest", "canonicalDestination", "jobId", "reservationDigest", "durability"], "active claim");
  if (value.contractVersion !== STORE_VERSION) fail("active claim contract version is unsupported");
  safeDigest(value.destinationDigest, "active claim.destinationDigest"); safeDigest(value.reservationDigest, "active claim.reservationDigest"); safeIdentifier(value.jobId, "active claim.jobId");
  if (value.durability !== RESERVATION_DURABILITY && value.durability !== "file_and_parent_fsynced") fail("active claim.durability is invalid");
  const normalized = canonicalDestination(value.canonicalDestination);
  if (normalized !== value.canonicalDestination || hash(normalized) !== value.destinationDigest) fail("active claim canonical destination is invalid");
  return value;
}
function validateReleaseReceipt(value) {
  exactKeys(value, ["contractVersion", "destinationDigest", "canonicalDestination", "jobId", "reservationDigest", "jobState", "releasedAt", "status", "durability"], "release receipt");
  if (value.contractVersion !== STORE_VERSION || value.status !== "released") fail("release receipt is invalid");
  safeDigest(value.destinationDigest, "release receipt.destinationDigest"); safeDigest(value.reservationDigest, "release receipt.reservationDigest"); safeIdentifier(value.jobId, "release receipt.jobId");
  if (!RELEASE_ELIGIBLE_STATES.has(value.jobState) || !Number.isSafeInteger(value.releasedAt) || value.releasedAt < 0) fail("release receipt terminal evidence is invalid");
  if (value.durability !== RESERVATION_DURABILITY && value.durability !== "file_and_parent_fsynced") fail("release receipt.durability is invalid");
  const normalized = canonicalDestination(value.canonicalDestination);
  if (normalized !== value.canonicalDestination || hash(normalized) !== value.destinationDigest) fail("release receipt canonical destination is invalid");
  return value;
}
function executionSlotDigest(value) {
  const { digest, ...unsigned } = value;
  return digestOf(unsigned);
}
function validateExecutionSlot(value) {
  exactKeys(value, ["contractVersion", "jobId", "ownerId", "fencingToken", "profileDigest", "expiresAt", "digest"], "execution slot");
  if (value.contractVersion !== EXECUTION_SLOT_VERSION) fail("execution slot version is unsupported");
  safeIdentifier(value.jobId, "execution slot.jobId"); safeIdentifier(value.ownerId, "execution slot.ownerId");
  if (!Number.isSafeInteger(value.fencingToken) || value.fencingToken < 1 || !Number.isSafeInteger(value.expiresAt) || value.expiresAt < 0) fail("execution slot fence or expiry is invalid");
  safeDigest(value.profileDigest, "execution slot.profileDigest"); safeDigest(value.digest, "execution slot.digest");
  if (executionSlotDigest(value) !== value.digest) throw new IntegrityError("execution slot digest differs");
  return value;
}
function executionSlotReleaseDigest(value) {
  const { digest, ...unsigned } = value;
  return digestOf(unsigned);
}
function validateExecutionSlotRelease(value) {
  exactKeys(value, ["contractVersion", "jobId", "ownerId", "fencingToken", "profileDigest", "slotDigest", "releasedAt", "digest"], "execution slot release");
  if (value.contractVersion !== EXECUTION_SLOT_VERSION) fail("execution slot release version is unsupported");
  safeIdentifier(value.jobId, "execution slot release.jobId"); safeIdentifier(value.ownerId, "execution slot release.ownerId");
  if (!Number.isSafeInteger(value.fencingToken) || value.fencingToken < 1 || !Number.isSafeInteger(value.releasedAt) || value.releasedAt < 0) fail("execution slot release is invalid");
  safeDigest(value.profileDigest, "execution slot release.profileDigest"); safeDigest(value.slotDigest, "execution slot release.slotDigest"); safeDigest(value.digest, "execution slot release.digest");
  if (executionSlotReleaseDigest(value) !== value.digest) throw new IntegrityError("execution slot release digest differs");
  return value;
}
function submissionClaimDigest(value) {
  const { digest, ...unsigned } = value;
  return digestOf(unsigned);
}
function validateSubmissionClaim(value) {
  exactKeys(value, ["contractVersion", "jobId", "idempotencyKey", "contextDigest", "createdAt", "digest"], "submission claim");
  if (value.contractVersion !== SUBMISSION_CLAIM_VERSION) fail("submission claim version is unsupported");
  safeIdentifier(value.jobId, "submission claim.jobId"); safeIdentifier(value.idempotencyKey, "submission claim.idempotencyKey"); safeDigest(value.contextDigest, "submission claim.contextDigest");
  if (!Number.isSafeInteger(value.createdAt) || value.createdAt < 0) fail("submission claim.createdAt is invalid");
  safeDigest(value.digest, "submission claim.digest");
  if (submissionClaimDigest(value) !== value.digest) throw new IntegrityError("submission claim digest differs");
  return value;
}

export class JobStore {
  constructor({ stateRoot, custodyRevalidator = null, now = () => Date.now(), faults = null, submissionClaimLeaseMs = DEFAULT_SUBMISSION_CLAIM_LEASE_MS } = {}) {
    this.stateRoot = assertAbsoluteStateRoot(stateRoot);
    this.custodyRevalidator = custodyRevalidator;
    this.now = now;
    this.faults = faults;
    if (!Number.isSafeInteger(submissionClaimLeaseMs) || submissionClaimLeaseMs < 1) fail("submissionClaimLeaseMs is invalid");
    this.submissionClaimLeaseMs = submissionClaimLeaseMs;
    this.localLeases = new Map();
    mkdirSync(this.stateRoot, { recursive: true, mode: 0o700 });
    for (const part of ["jobs", "reservations", "claims", "retired-claims", "releases", "locks", "idempotency", "slots", "slot-releases", "submission-claims"]) mkdirSync(join(this.stateRoot, part), { recursive: true, mode: 0o700 });
  }

  jobDir(jobId) { return join(this.stateRoot, "jobs", safeIdentifier(jobId, "jobId")); }
  snapshotPath(jobId) { return join(this.jobDir(jobId), "snapshot.json"); }
  journalPath(jobId) { return join(this.jobDir(jobId), "journal.ndjson"); }
  lockPath(name) { return join(this.stateRoot, "locks", `${name}.lock`); }
  reservationPath(destinationDigest, jobId) {
    safeDigest(destinationDigest, "destinationDigest"); safeIdentifier(jobId, "jobId");
    return join(this.stateRoot, "reservations", `${reservationFileStem(destinationDigest)}--${jobId}.json`);
  }
  activeClaimPath(destinationDigest) { safeDigest(destinationDigest, "destinationDigest"); return join(this.stateRoot, "claims", `${reservationFileStem(destinationDigest)}.json`); }
  retiredClaimPath(destinationDigest, jobId) {
    safeDigest(destinationDigest, "destinationDigest"); safeIdentifier(jobId, "jobId");
    return join(this.stateRoot, "retired-claims", `${reservationFileStem(destinationDigest)}--${jobId}.json`);
  }
  releaseReceiptPath(jobId) { return join(this.stateRoot, "releases", `${safeIdentifier(jobId, "jobId")}.json`); }
  submitIdempotencyPath(key) { return join(this.stateRoot, "idempotency", `${hash(key).slice(7)}.json`); }
  executionSlotPath() { return join(this.stateRoot, "slots", "service-execution.json"); }
  executionSlotReleasePath(jobId, fencingToken, slotDigest) {
    safeDigest(slotDigest, "slotDigest");
    return join(this.stateRoot, "slot-releases", `${safeIdentifier(jobId, "jobId")}-${fencingToken}-${slotDigest.slice(7)}.json`);
  }
  executionSlotReleasePaths(jobId, fencingToken) {
    const directory = join(this.stateRoot, "slot-releases");
    if (!existsSync(directory)) return [];
    const prefix = `${safeIdentifier(jobId, "jobId")}-${fencingToken}-`;
    return readdirSync(directory, { withFileTypes: true })
      .filter((entry) => entry.name.startsWith(prefix) && entry.name.endsWith(".json"))
      .map((entry) => {
        if (!entry.isFile() || !/^sha256:[a-f0-9]{64}$/.test(`sha256:${entry.name.slice(prefix.length, -5)}`)) {
          throw new IntegrityError("execution slot release evidence is malformed");
        }
        return join(directory, entry.name);
      });
  }
  submissionClaimPath(jobId) { return join(this.stateRoot, "submission-claims", `${safeIdentifier(jobId, "jobId")}.json`); }

  withLock(name, callback) {
    const path = this.lockPath(name);
    let descriptor;
    try { descriptor = openSync(path, "wx", 0o600); }
    catch (error) { if (error?.code === "EEXIST") throw new LeaseConflictError(`mutation lock is held for ${name}`); throw error; }
    try { return callback(); } finally { closeSync(descriptor); rmSync(path, { force: true }); }
  }

  submit({ job, admission, idempotencyKey, serviceContext = null }) {
    validateJob(job);
    if (job.state !== "queued" || job.eventCursor !== 0) fail("new jobs must be queued with cursor zero");
    safeIdentifier(idempotencyKey, "idempotencyKey");
    const normalizedAdmission = this.validateAdmission(admission);
    const normalizedServiceContext = serviceContext === null ? null : this.validateServiceContext(serviceContext);
    // A service context is immutable admission identity.  It intentionally
    // lets a retry prove exact caller intent before profile/custody/authority
    // callbacks reconstruct the rest of admission material.
    const request = normalizedServiceContext === null
      ? { job, admission: normalizedAdmission }
      : { serviceContext: normalizedServiceContext };
    const requestDigest = idempotencyDigest("submit", request);
    return this.withLock(`submit-${hash(idempotencyKey).slice(7)}`, () => {
      const submitIdempotencyPath = this.submitIdempotencyPath(idempotencyKey);
      if (existsSync(submitIdempotencyPath)) {
        const record = readJson(submitIdempotencyPath, "submission idempotency record");
        if (record.operation !== "submit" || record.key !== idempotencyKey || record.requestDigest !== requestDigest) {
          throw new IdempotencyConflictError("idempotency key was reused with a different request digest");
        }
        return structuredClone(record.result);
      }
      const jobPath = this.snapshotPath(job.jobId);
      if (existsSync(jobPath)) {
        const existing = this.readVerified(job.jobId);
        return this.replay(existing, "submit", idempotencyKey, requestDigest);
      }
      const reservation = this.reserve(normalizedAdmission.destinationRoot, job.jobId);
      mkdirSync(this.jobDir(job.jobId), { recursive: false, mode: 0o700 });
      const admissionIdempotency = { operation: "submit", key: idempotencyKey, requestDigest,
        result: { jobId: job.jobId, state: job.state, cursor: 0 } };
      const record = {
        contractVersion: JOURNAL_VERSION, cursor: 0, sequence: 0, type: "admission", previousDigest: null,
        payload: normalizeForStorage({ job, admission: normalizedAdmission, reservation, serviceContext: normalizedServiceContext, idempotency: admissionIdempotency }, "admission")
      };
      record.digest = digestOf(record);
      appendDurable(this.journalPath(job.jobId), record);
      const snapshot = this.snapshotFromAdmission(record);
      this.commitSnapshot(job.jobId, snapshot);
      durableWrite(submitIdempotencyPath, snapshot.idempotency[0]);
      return structuredClone(snapshot.idempotency[0].result);
    });
  }

  readJob(jobId) { return structuredClone(this.readVerified(jobId).job); }
  readAttempts(jobId) { return structuredClone(this.readVerified(jobId).attempts); }
  readServiceContext(jobId) { return structuredClone(this.readVerified(jobId).serviceContext ?? null); }
  readServiceRuntime(jobId) { return structuredClone(this.readVerified(jobId).serviceRuntime ?? null); }
  claimServiceSubmission(jobId, { idempotencyKey, contextDigest } = {}) {
    safeIdentifier(jobId, "jobId"); safeIdentifier(idempotencyKey, "idempotencyKey"); safeDigest(contextDigest, "contextDigest");
    return this.withLock(`submission-claim-${jobId}`, () => {
      if (existsSync(this.snapshotPath(jobId))) {
        const existing = this.readVerified(jobId), context = existing.serviceContext;
        if (!context || context.contextDigest !== contextDigest || context.context?.idempotencyKey !== idempotencyKey) {
          throw new IdempotencyConflictError("submitted job identity differs from its admission claim");
        }
        return { status: "admitted" };
      }
      const path = this.submissionClaimPath(jobId);
      if (existsSync(path)) {
        const claim = validateSubmissionClaim(readJson(path, "submission claim"));
        if (claim.contextDigest !== contextDigest || claim.idempotencyKey !== idempotencyKey) {
          throw new IdempotencyConflictError("submission claim idempotency key or request digest differs");
        }
        if (this.now() - claim.createdAt >= this.submissionClaimLeaseMs) {
          const recovered = { ...claim, createdAt: this.now() };
          recovered.digest = submissionClaimDigest(recovered);
          durableWrite(path, recovered);
          return { status: "recovered" };
        }
        return { status: "pending" };
      }
      const claim = { contractVersion: SUBMISSION_CLAIM_VERSION, jobId, idempotencyKey, contextDigest, createdAt: this.now() };
      claim.digest = submissionClaimDigest(claim);
      this.exclusiveDurableCreate(path, claim);
      return { status: "claimed" };
    });
  }
  replayOperation(jobId, { operation, idempotencyKey, request } = {}) {
    if (typeof operation !== "string" || !operation) fail("operation is required"); safeIdentifier(idempotencyKey, "idempotencyKey");
    const snapshot = this.readVerified(jobId), requestDigest = idempotencyDigest(operation, request);
    const receipt = snapshot.idempotency.find((entry) => entry.key === idempotencyKey);
    if (!receipt) return null;
    if (receipt.operation !== operation || receipt.requestDigest !== requestDigest) throw new IdempotencyConflictError("idempotency key was reused with a different operation or request digest");
    return structuredClone(receipt.result);
  }
  bindServiceContext(jobId, { contextDigest, context, fence } = {}) {
    const normalized = this.validateServiceContext({ contextDigest, context });
    return this.withLock(`job-${jobId}`, () => {
      const snapshot = this.readVerified(jobId);
      if (!snapshot.lease || snapshot.job.state !== "queued") throw new IntegrityError("service context may only be added to a leased queued admission");
      this.assertFence(snapshot, fence);
      if (snapshot.serviceContext) {
        if (snapshot.serviceContext.contextDigest !== normalized.contextDigest || canonical(snapshot.serviceContext.context) !== canonical(normalized.context)) throw new IntegrityError("service context is immutable");
        return structuredClone(snapshot.serviceContext);
      }
      const next = this.mutateSnapshot(jobId, snapshot, "service_context", normalized, (entry) => { entry.serviceContext = normalized; });
      return structuredClone(next.serviceContext);
    });
  }
  bindServiceRuntime(jobId, { custodyDigest, worktreeCustodyDigest, destinationDigest, custody, fence } = {}) {
    const runtime = this.validateServiceRuntime({ custodyDigest, worktreeCustodyDigest, destinationDigest, custody });
    return this.withLock(`job-${jobId}`, () => {
      const snapshot = this.readVerified(jobId);
      if (snapshot.job.state !== "preflighting" || !snapshot.lease) throw new IntegrityError("service runtime may only bind during a leased preflight");
      this.assertFence(snapshot, fence);
      if (snapshot.serviceRuntime) {
        if (canonical(snapshot.serviceRuntime) !== canonical(runtime)) throw new IntegrityError("service runtime custody is immutable");
        return structuredClone(snapshot.serviceRuntime);
      }
      const next = this.mutateSnapshot(jobId, snapshot, "service_runtime", runtime, (entry) => { entry.serviceRuntime = runtime; });
      if (this.faults?.afterServiceRuntime) throw new Error("injected failure after durable service runtime context");
      return structuredClone(next.serviceRuntime);
    });
  }
  readStatus(jobId, { afterCursor = 0, includeSnapshot = false } = {}) {
    if (typeof includeSnapshot !== "boolean") fail("includeSnapshot must be boolean");
    const lockPath = this.lockPath(`job-${jobId}`);
    let verified = null;
    let lastError = null;
    const waitBuffer = new Int32Array(new SharedArrayBuffer(4));
    // Status is an observer. It must never replay an in-flight journal tail
    // into the snapshot while another process owns the mutation lock. Codex
    // can issue MCP calls through different plugin workers, so a status poll
    // may otherwise catch the narrow append-before-snapshot window and turn a
    // healthy provider run into a service error and worker restart.
    // A store that owns the live lease shares the writer's event loop, so its
    // synchronous read cannot interleave with its own mutation and must not
    // block timer heartbeats. The bounded stability loop is only for foreign
    // observer workers.
    if (this.localLeases.has(jobId)) verified = this.readVerified(jobId, { includeRecords: true, recoverTail: false });
    for (let attempt = 0; verified === null && attempt < 50; attempt += 1) {
      if (existsSync(lockPath)) {
        Atomics.wait(waitBuffer, 0, 0, 10);
        continue;
      }
      try {
        verified = this.readVerified(jobId, { includeRecords: true, recoverTail: false });
        if (!existsSync(lockPath)) break;
        verified = null;
      } catch (error) {
        lastError = error;
      }
      Atomics.wait(waitBuffer, 0, 0, 10);
    }
    if (verified === null) throw lastError ?? new LeaseConflictError("status read could not observe a stable job snapshot");
    const { snapshot, records } = verified;
    if (!Number.isSafeInteger(afterCursor) || afterCursor < 0 || afterCursor > snapshot.job.eventCursor) {
      throw new RangeError("status cursor is stale or in the future");
    }
    const events = records.filter((record) => record.type === "event" && record.payload.cursor > afterCursor)
      .map((record) => structuredClone(record.payload));
    const result = { job: this.effectiveJob(snapshot), events };
    return includeSnapshot ? { ...result, snapshot: structuredClone(snapshot) } : result;
  }
  openJob(jobId) {
    const snapshot = this.readVerified(jobId);
    return this.effectiveJob(snapshot);
  }

  recover(jobId, { ownerId, durationMs = 30_000, priorOwnerProofDigest = null, custodyRevalidator = this.custodyRevalidator } = {}) {
    let snapshot = this.readVerified(jobId);
    if (snapshot.job.state === "candidate_ready") {
      if (!this.revalidate(snapshot, custodyRevalidator)) throw new IntegrityError("candidate custody revalidation failed");
      return this.openJob(jobId);
    }
    const lease = this.acquireExecutionLease(jobId, { ownerId, durationMs, priorOwnerProofDigest });
    snapshot = this.transition(jobId, "recovery_required", { fence: lease.fencingToken, allowRecovery: true });
    return this.transition(jobId, "preflighting", { fence: lease.fencingToken });
  }

  acquireExecutionLease(jobId, { ownerId, durationMs = 30_000, priorOwnerProofDigest = null } = {}) {
    safeIdentifier(ownerId, "ownerId");
    if (!Number.isSafeInteger(durationMs) || durationMs < 1 || durationMs > 3_600_000) fail("durationMs must be bounded positive integer");
    return this.withLock(`job-${jobId}`, () => {
      const snapshot = this.readVerified(jobId);
      if (isTerminal(snapshot.job.state)) throw new LeaseConflictError("terminal jobs cannot acquire execution leases");
      const current = snapshot.lease;
      if (current && current.expiresAt > this.now() && current.ownerId !== ownerId) throw new LeaseConflictError("execution lease is held by another owner");
      if (current && current.expiresAt <= this.now()) {
        if (priorOwnerProofDigest === null) throw new LeaseConflictError("expired execution lease requires priorOwnerProofDigest");
        safeDigest(priorOwnerProofDigest, "priorOwnerProofDigest");
      } else if (priorOwnerProofDigest !== null) safeDigest(priorOwnerProofDigest, "priorOwnerProofDigest");
      const fencingToken = (current?.fencingToken ?? 0) + 1;
      const lease = { ownerId, fencingToken, expiresAt: this.now() + durationMs };
      const written = this.mutateSnapshot(jobId, snapshot, "lease_acquired", { lease, priorOwnerProofDigest }, (next) => { next.lease = lease; });
      this.localLeases.set(jobId, structuredClone(written.lease));
      return structuredClone(written.lease);
    });
  }

  // Renewal never rotates the fencing token: a running child keeps one exact
  // authority identity for its entire lifetime.
  renewExecutionLease(jobId, { ownerId, fencingToken, durationMs = 30_000 } = {}) {
    safeIdentifier(ownerId, "ownerId");
    if (!Number.isSafeInteger(fencingToken) || fencingToken < 1) fail("fencingToken must be a positive integer");
    if (!Number.isSafeInteger(durationMs) || durationMs < 1 || durationMs > 3_600_000) fail("durationMs must be bounded positive integer");
    return this.withLock(`job-${jobId}`, () => {
      const snapshot = this.readVerified(jobId), current = snapshot.lease;
      if (!current || current.ownerId !== ownerId || current.fencingToken !== fencingToken || current.expiresAt <= this.now()) {
        throw new LeaseConflictError("only the current unexpired lease owner may renew its fence");
      }
      if (isTerminal(snapshot.job.state)) throw new LeaseConflictError("terminal jobs cannot renew execution leases");
      const lease = { ownerId, fencingToken, expiresAt: this.now() + durationMs };
      const written = this.mutateSnapshot(jobId, snapshot, "lease_renewed", { lease }, (next) => { next.lease = lease; });
      this.localLeases.set(jobId, structuredClone(written.lease));
      return structuredClone(written.lease);
    });
  }

  readExecutionSlot() {
    const path = this.executionSlotPath();
    if (!existsSync(path)) return null;
    try { return structuredClone(validateExecutionSlot(readJson(path, "execution slot"))); }
    catch (error) { if (error instanceof IntegrityError) throw error; throw new IntegrityError("execution slot is malformed or tampered"); }
  }

  // One durable service-wide slot deliberately keeps U6 at the immutable
  // profile limit of one even when each job constructs an ACP adapter.
  acquireExecutionSlot(jobId, { ownerId, fencingToken, profileDigest, expiresAt, maximumActiveJobs = 1, priorSlotProofDigest = null } = {}) {
    safeIdentifier(jobId, "jobId"); safeIdentifier(ownerId, "ownerId"); safeDigest(profileDigest, "profileDigest");
    if (!Number.isSafeInteger(fencingToken) || fencingToken < 1 || !Number.isSafeInteger(expiresAt) || expiresAt <= this.now()) fail("execution slot fence or expiry is invalid");
    if (maximumActiveJobs !== 1) fail("U6 service execution slot supports only the immutable maximumActiveJobs=1 profile limit");
    return this.withLock("execution-slot-global", () => {
      const existing = this.readExecutionSlot();
      if (existing) {
        if (existing.expiresAt > this.now()) {
          if (existing.jobId !== jobId || existing.ownerId !== ownerId || existing.fencingToken !== fencingToken || existing.profileDigest !== profileDigest) {
            throw new LeaseConflictError("the durable service execution slot is held by another active job");
          }
          return existing;
        }
        // Expiry alone never proves a provider child died.  An operator-owned
        // recovery proof must explicitly bind the stale durable slot record.
        if (priorSlotProofDigest === null) throw new LeaseConflictError("expired service execution slot requires priorSlotProofDigest");
        safeDigest(priorSlotProofDigest, "priorSlotProofDigest");
        if (priorSlotProofDigest !== existing.digest) throw new LeaseConflictError("priorSlotProofDigest does not bind the expired service execution slot");
      }
      const record = { contractVersion: EXECUTION_SLOT_VERSION, jobId, ownerId, fencingToken, profileDigest, expiresAt };
      record.digest = executionSlotDigest(record);
      durableWrite(this.executionSlotPath(), record);
      return structuredClone(record);
    });
  }

  renewExecutionSlot(jobId, { ownerId, fencingToken, profileDigest, expiresAt } = {}) {
    safeIdentifier(jobId, "jobId"); safeIdentifier(ownerId, "ownerId"); safeDigest(profileDigest, "profileDigest");
    if (!Number.isSafeInteger(fencingToken) || fencingToken < 1 || !Number.isSafeInteger(expiresAt) || expiresAt <= this.now()) fail("execution slot fence or expiry is invalid");
    return this.withLock("execution-slot-global", () => {
      const current = this.readExecutionSlot();
      if (!current || current.expiresAt <= this.now() || current.jobId !== jobId || current.ownerId !== ownerId ||
          current.fencingToken !== fencingToken || current.profileDigest !== profileDigest) {
        throw new LeaseConflictError("only the current unexpired slot owner may renew execution capacity");
      }
      const record = { contractVersion: EXECUTION_SLOT_VERSION, jobId, ownerId, fencingToken, profileDigest, expiresAt };
      record.digest = executionSlotDigest(record);
      durableWrite(this.executionSlotPath(), record);
      return structuredClone(record);
    });
  }

  releaseExecutionSlot(jobId, { ownerId, fencingToken, profileDigest } = {}) {
    safeIdentifier(jobId, "jobId"); safeIdentifier(ownerId, "ownerId"); safeDigest(profileDigest, "profileDigest");
    if (!Number.isSafeInteger(fencingToken) || fencingToken < 1) fail("execution slot fencingToken is invalid");
    return this.withLock("execution-slot-global", () => {
      const current = this.readExecutionSlot();
      if (current === null) {
        const receiptPaths = this.executionSlotReleasePaths(jobId, fencingToken);
        if (receiptPaths.length === 0) return false;
        for (const receiptPath of receiptPaths) {
          const receipt = validateExecutionSlotRelease(readJson(receiptPath, "execution slot release"));
          if (receipt.jobId !== jobId || receipt.fencingToken !== fencingToken || receipt.ownerId !== ownerId || receipt.profileDigest !== profileDigest) {
            throw new IntegrityError("execution slot release receipt differs");
          }
        }
        return true;
      }
      if (current.jobId !== jobId || current.ownerId !== ownerId || current.fencingToken !== fencingToken || current.profileDigest !== profileDigest) {
        throw new LeaseConflictError("only the current slot owner may release execution capacity");
      }
      const receiptPath = this.executionSlotReleasePath(jobId, fencingToken, current.digest);
      if (existsSync(receiptPath)) {
        const prior = validateExecutionSlotRelease(readJson(receiptPath, "execution slot release"));
        if (prior.jobId !== jobId || prior.ownerId !== ownerId || prior.fencingToken !== fencingToken || prior.profileDigest !== profileDigest || prior.slotDigest !== current.digest) {
          throw new IntegrityError("execution slot release receipt differs");
        }
      } else {
        const receipt = {
          contractVersion: EXECUTION_SLOT_VERSION, jobId, ownerId, fencingToken, profileDigest,
          slotDigest: current.digest, releasedAt: this.now()
        };
        receipt.digest = executionSlotReleaseDigest(receipt);
        this.exclusiveDurableCreate(receiptPath, receipt);
      }
      rmSync(this.executionSlotPath(), { force: true });
      return true;
    });
  }

  transition(jobId, to, { fence, allowRecovery = false } = {}) {
    return this.withLock(`job-${jobId}`, () => {
      const snapshot = this.readVerified(jobId);
      if (allowRecovery) {
        if (to !== "recovery_required" || !ACTIVE_EXECUTION_STATES.has(snapshot.job.state)) {
          fail("allowRecovery only permits an active execution transition to recovery_required");
        }
      } else {
        if (to === "cancelling" || to === "cancelled") {
          fail("cancellation state transitions require beginCancellation or acknowledgeCancellation");
        }
        assertTransition(snapshot.job.state, to);
      }
      this.assertFence(snapshot, fence);
      return this.mutateSnapshot(jobId, snapshot, "transition", { from: snapshot.job.state, to }, (next) => { next.job.state = to; });
    });
  }

  // A heartbeat can discover that its own lease expired before it could renew.
  // Its stale fence must never perform normal work, but it may durably report
  // recovery_required when (and only when) no newer owner rotated the fence.
  // This gives restart logic a truthful state instead of leaving a dead child
  // looking "running" forever.
  recordRecovery(jobId, { ownerId, fencingToken, code } = {}) {
    safeIdentifier(ownerId, "ownerId");
    if (!Number.isSafeInteger(fencingToken) || fencingToken < 1) fail("recovery fencingToken is invalid");
    safeIdentifier(code, "recovery code");
    return this.withLock(`job-${jobId}`, () => {
      const snapshot = this.readVerified(jobId);
      if (isTerminal(snapshot.job.state) || snapshot.job.state === "recovery_required") return this.effectiveJob(snapshot);
      if (!ACTIVE_EXECUTION_STATES.has(snapshot.job.state) || !snapshot.lease ||
          snapshot.lease.ownerId !== ownerId || snapshot.lease.fencingToken !== fencingToken) {
        throw new LeaseConflictError("only the exact execution fence may record recovery");
      }
      return this.mutateSnapshot(jobId, snapshot, "recovery_required", { from: snapshot.job.state, code }, (next) => {
        next.job.state = "recovery_required";
      }).job;
    });
  }

  appendEvent(jobId, event, { fence } = {}) {
    validateEvent(event);
    return this.withLock(`job-${jobId}`, () => {
      const snapshot = this.readVerified(jobId);
      this.assertFence(snapshot, fence);
      if (isTerminal(snapshot.job.state)) fail("terminal jobs are immutable");
      if (event.jobId !== jobId || event.fencingToken !== fence) fail("event does not match the current job fence");
      if (event.cursor !== snapshot.job.eventCursor + 1 || event.sequence !== snapshot.eventSequence + 1) fail("event cursor or sequence is not monotonic");
      const payload = normalizeForStorage(event, "event");
      return this.mutateSnapshot(jobId, snapshot, "event", payload, (next) => {
        next.job.eventCursor = event.cursor;
        next.eventSequence = event.sequence;
      });
    });
  }

  recordAttempt(jobId, attempt, { fence } = {}) {
    validateAttempt(attempt);
    if (attempt.jobId !== jobId) fail("attempt jobId does not match");
    return this.withLock(`job-${jobId}`, () => {
      const snapshot = this.readVerified(jobId);
      this.assertFence(snapshot, fence);
      if (isTerminal(snapshot.job.state)) fail("terminal jobs are immutable");
      if (attempt.profileDigest !== snapshot.job.profileDigest) fail("attempt profileDigest does not match the job");
      const existing = snapshot.attempts.find((entry) => entry.attemptId === attempt.attemptId);
      if (existing) {
        if (canonical(existing) !== canonical(attempt)) throw new IntegrityError("attempt records are immutable; use a new attempt id");
        return structuredClone(existing);
      }
      if (attempt.number !== snapshot.attempts.length + 1) fail("attempt number must be exactly the next monotonic attempt number");
      this.mutateSnapshot(jobId, snapshot, "attempt_recorded", attempt, (next) => { next.attempts.push(attempt); });
      return structuredClone(attempt);
    });
  }

  bindEvidence(jobId, { candidate = null, grant = null, grantDigest = null, receiptDigest = null, providerCandidateDigest = null, fence } = {}) {
    if (candidate !== null) validateCandidate(candidate);
    if (grant !== null) validateGrant(grant);
    if (grantDigest !== null) safeDigest(grantDigest, "grantDigest");
    if (receiptDigest !== null) safeDigest(receiptDigest, "receiptDigest");
    if (providerCandidateDigest !== null) safeDigest(providerCandidateDigest, "providerCandidateDigest");
    return this.withLock(`job-${jobId}`, () => {
      const snapshot = this.readVerified(jobId);
      this.assertFence(snapshot, fence);
      if (isTerminal(snapshot.job.state)) fail("terminal jobs are immutable");
      const currentAttempt = snapshot.attempts.at(-1);
      if (candidate?.jobId !== jobId || candidate?.attemptId !== currentAttempt?.attemptId) {
        fail("candidate must bind to this job and its current attempt");
      }
      const binding = normalizeForStorage({ candidate, grantDigest: grant ? digestOf(grant) : grantDigest, receiptDigest, providerCandidateDigest }, "evidence");
      if (snapshot.bindings.candidate) {
        if (canonical(snapshot.bindings) !== canonical(binding)) throw new IntegrityError("candidate, grant, or receipt binding is immutable");
        return structuredClone(snapshot.job);
      }
      if (binding.grantDigest !== snapshot.bindings.grantDigest || binding.receiptDigest !== snapshot.bindings.receiptDigest || binding.candidate === null) {
        throw new IntegrityError("candidate, grant, or receipt binding is immutable");
      }
      return this.mutateSnapshot(jobId, snapshot, "evidence_bound", binding, (next) => { next.bindings = binding; });
    });
  }

  // The candidate manifest is written by the service before this call.  This
  // one journal mutation makes its digest, provider signal, authority, and
  // candidate_ready state inseparable for replay and crash recovery.
  publishCandidate(jobId, { candidate, providerCandidateDigest, grantDigest, receiptDigest, idempotencyKey, fence, recovery = false } = {}) {
    validateCandidate(candidate); safeDigest(providerCandidateDigest, "providerCandidateDigest");
    safeDigest(grantDigest, "grantDigest"); safeDigest(receiptDigest, "receiptDigest"); safeIdentifier(idempotencyKey, "idempotencyKey");
    if (typeof recovery !== "boolean") fail("candidate publication recovery flag is invalid");
    if (candidate.jobId !== jobId) fail("candidate jobId does not match");
    const request = { candidate, providerCandidateDigest, grantDigest, receiptDigest, recovery };
    if (this.faults?.beforeCandidatePublication) throw new Error("injected failure before atomic candidate publication");
    return this.withLock(`job-${jobId}`, () => this.idempotentMutation(jobId, "candidate_publication", idempotencyKey, request, fence, (snapshot) => {
      if (snapshot.job.state !== "running" && !(recovery && snapshot.job.state === "recovery_required")) {
        fail("only a running or explicitly recovered job may publish a candidate");
      }
      const currentAttempt = snapshot.attempts.at(-1);
      if (!currentAttempt || currentAttempt.attemptId !== candidate.attemptId) fail("candidate must bind to the current attempt");
      if (snapshot.bindings.candidate !== null) fail("a candidate is already bound for this attempt");
      if (snapshot.bindings.grantDigest !== grantDigest || snapshot.bindings.receiptDigest !== receiptDigest) {
        throw new IntegrityError("candidate authority does not match the active admission or repair authority");
      }
      if (snapshot.job.state === "running") assertTransition(snapshot.job.state, "candidate_ready");
      return { type: "candidate_published", payload: { candidate, providerCandidateDigest, grantDigest, receiptDigest } };
    }));
  }

  beginCancellation(jobId, { reason, idempotencyKey, fence } = {}) {
    safeIdentifier(reason, "reason"); safeIdentifier(idempotencyKey, "idempotencyKey");
    return this.withLock(`job-${jobId}`, () => this.idempotentMutation(jobId, "cancellation_intent", idempotencyKey, { reason }, fence, (snapshot, { requestDigest }) => {
      if (snapshot.job.state === "cancelling") fail("a cancellation intent is already pending acknowledgement");
      assertTransition(snapshot.job.state, "cancelling");
      const cancellationDigest = digestOf({ jobId, operation: "cancellation_intent", idempotencyKey, requestDigest });
      return {
        type: "cancellation_intent",
        payload: { from: snapshot.job.state, cancellation: { reason, cancellationDigest, fromState: snapshot.job.state } },
        result: { cancellationDigest }
      };
    }));
  }

  // Compatibility alias: it records intent only and can never self-certify a cancellation.
  cancel(jobId, options = {}) { return this.beginCancellation(jobId, options); }

  acknowledgeCancellation(jobId, { expectedCancellationDigest, idempotencyKey, fence } = {}) {
    safeDigest(expectedCancellationDigest, "expectedCancellationDigest"); safeIdentifier(idempotencyKey, "idempotencyKey");
    const request = { expectedCancellationDigest };
    return this.withLock(`job-${jobId}`, () => this.idempotentMutation(jobId, "cancellation_acknowledgement", idempotencyKey, request, fence, (snapshot) => {
      if (snapshot.job.state !== "cancelling" || snapshot.cancellation?.cancellationDigest !== expectedCancellationDigest) {
        fail("cancellation acknowledgement preconditions do not match the durable intent");
      }
      assertTransition(snapshot.job.state, "cancelled");
      return { type: "cancellation_acknowledged", payload: request };
    }));
  }

  disposeCandidate(jobId, { collection, fence } = {}) {
    validateCollection(collection);
    if (collection.jobId !== jobId) fail("collection jobId does not match");
    return this.withLock(`job-${jobId}`, () => this.idempotentMutation(jobId, "collection", collection.idempotencyKey, collection, fence, (snapshot) => {
      if (snapshot.job.state !== "candidate_ready") fail("only candidate_ready jobs may be collected");
      if (snapshot.bindings.candidate?.attemptId !== collection.expectedAttemptId || snapshot.bindings.candidate?.manifestDigest !== collection.expectedCandidateDigest) {
        fail("collection preconditions do not match the bound candidate");
      }
      return { type: "collection", payload: collection };
    }));
  }

  requestRepair(jobId, { idempotencyKey, findingsDigest, expectedAttemptId, expectedCandidateDigest, repairGrantDigest = null, repairReceiptDigest = null, fence } = {}) {
    safeIdentifier(idempotencyKey, "idempotencyKey"); safeDigest(findingsDigest, "findingsDigest");
    safeIdentifier(expectedAttemptId, "expectedAttemptId"); safeDigest(expectedCandidateDigest, "expectedCandidateDigest");
    if (repairGrantDigest !== null) safeDigest(repairGrantDigest, "repairGrantDigest"); if (repairReceiptDigest !== null) safeDigest(repairReceiptDigest, "repairReceiptDigest");
    // Authority is durable evidence on the effect, not caller replay identity:
    // a retry must be checked before it can ask the host for another grant.
    const request = { findingsDigest, expectedAttemptId, expectedCandidateDigest };
    const effectPayload = { ...request, repairGrantDigest, repairReceiptDigest };
    return this.withLock(`job-${jobId}`, () => this.idempotentMutation(jobId, "repair", idempotencyKey, request, fence, (snapshot) => {
      if (snapshot.job.state === "repairing") {
        const history = snapshot.candidateHistory.at(-1), archived = history?.candidate;
        if (archived?.attemptId !== expectedAttemptId || archived?.manifestDigest !== expectedCandidateDigest) {
          fail("repair continuation preconditions do not match the archived candidate");
        }
        if (history.repairRequest && canonical(history.repairRequest) !== canonical(effectPayload)) fail("a different repair request is already active");
        return { type: "repair_continued", payload: effectPayload };
      }
      if (snapshot.job.state !== "candidate_ready") fail("only candidate_ready jobs may request repair");
      if (snapshot.bindings.candidate?.attemptId !== expectedAttemptId || snapshot.bindings.candidate?.manifestDigest !== expectedCandidateDigest) {
        fail("repair preconditions do not match the bound candidate");
      }
      return { type: "repair_requested", payload: effectPayload };
    }));
  }

  requestRecoveryRepair(jobId, { idempotencyKey, findingsDigest, expectedAttemptId, expectedNativeSessionId, recoveryProofDigest, repairGrantDigest, repairReceiptDigest, fence } = {}) {
    safeIdentifier(idempotencyKey, "idempotencyKey"); safeDigest(findingsDigest, "findingsDigest"); safeIdentifier(expectedAttemptId, "expectedAttemptId"); safeSessionIdentifier(expectedNativeSessionId, "expectedNativeSessionId"); safeDigest(recoveryProofDigest, "recoveryProofDigest"); safeDigest(repairGrantDigest, "repairGrantDigest"); safeDigest(repairReceiptDigest, "repairReceiptDigest");
    const request = { findingsDigest, expectedAttemptId, expectedNativeSessionId, recoveryProofDigest, repairGrantDigest, repairReceiptDigest };
    return this.withLock(`job-${jobId}`, () => this.idempotentMutation(jobId, "recovery_repair", idempotencyKey, request, fence, (snapshot) => {
      if (snapshot.job.state === "repairing") {
        if (!snapshot.recoveryRepair || canonical(snapshot.recoveryRepair) !== canonical(request)) fail("a different runtime recovery repair is already active");
        return { type: "recovery_repair_continued", payload: request };
      }
      if (snapshot.job.state !== "recovery_required") fail("only recovery_required jobs may resume a native session");
      return { type: "recovery_repair_requested", payload: request };
    }));
  }

  recordUsage(jobId, { usage = null, cost = null, fence } = {}) {
    if (usage === null && cost === null) return {};
    if (usage !== null) validateNormalizedUsage(usage);
    if (cost !== null) validateNormalizedCost(cost);
    return this.withLock(`job-${jobId}`, () => {
      const snapshot = this.readVerified(jobId);
      this.assertFence(snapshot, fence);
      if (isTerminal(snapshot.job.state)) fail("terminal jobs are immutable");
      return this.mutateSnapshot(jobId, snapshot, "usage", normalizeForStorage({ usage, cost }, "usage"), (next) => { next.usage = { usage, cost }; });
    });
  }

  validateAdmission(admission) {
    if (!plainObject(admission)) fail("admission must be a plain object");
    const allowed = ["destinationRoot", "grantDigest", "receiptDigest", "sourceCustodyDigest", "profileDigest", "model"];
    const extras = Object.keys(admission).filter((key) => !allowed.includes(key));
    if (extras.length) fail(`admission has unsupported fields: ${extras.join(", ")}`);
    const normalized = normalizeForStorage(admission, "admission");
    normalized.destinationRoot = canonicalDestination(normalized.destinationRoot);
    for (const key of ["grantDigest", "receiptDigest", "sourceCustodyDigest", "profileDigest"]) safeDigest(normalized[key], `admission.${key}`);
    if (normalized.model !== undefined && !["grok-build", "grok-4.6"].includes(normalized.model)) fail("admission.model is invalid");
    return normalized;
  }

  // The service owns the exact schema of this small, digest-only context.  The
  // store nevertheless verifies its immutable digest and a conservative size
  // bound so an admission can never be redirected by a mutable sidecar.
  validateServiceContext(value) {
    exactKeys(value, ["contextDigest", "context"], "service context");
    safeDigest(value.contextDigest, "serviceContext.contextDigest");
    if (!plainObject(value.context)) fail("serviceContext.context must be a plain object");
    const context = normalizeForStorage(value.context, "serviceContext.context");
    if (Buffer.byteLength(canonical(context), "utf8") > 16 * 1024) fail("serviceContext.context exceeds its bound");
    if (digestOf(context) !== value.contextDigest) throw new IntegrityError("serviceContext.context digest differs");
    return { contextDigest: value.contextDigest, context };
  }

  validateServiceRuntime(value) {
    exactKeys(value, ["custodyDigest", "worktreeCustodyDigest", "destinationDigest", "custody"], "service runtime");
    safeDigest(value.custodyDigest, "serviceRuntime.custodyDigest"); safeDigest(value.worktreeCustodyDigest, "serviceRuntime.worktreeCustodyDigest"); safeDigest(value.destinationDigest, "serviceRuntime.destinationDigest");
    if (!plainObject(value.custody)) fail("serviceRuntime.custody must be a plain object");
    const custody = normalizeForStorage(value.custody, "serviceRuntime.custody");
    if (Buffer.byteLength(canonical(custody), "utf8") > 64 * 1024) fail("serviceRuntime.custody exceeds its bound");
    if (digestOf(custody) !== value.custodyDigest || custody.worktreeCustodyDigest !== value.worktreeCustodyDigest || digestOf(custody.destinationRoot) !== value.destinationDigest) {
      throw new IntegrityError("serviceRuntime custody digest differs");
    }
    return { custodyDigest: value.custodyDigest, worktreeCustodyDigest: value.worktreeCustodyDigest, destinationDigest: value.destinationDigest, custody };
  }

  exclusiveDurableCreate(path, value) {
    let descriptor;
    try {
      descriptor = openSync(path, "wx", 0o600);
      writeFileSync(descriptor, json(value), "utf8");
      fsyncSync(descriptor);
    } finally { if (descriptor !== undefined) closeSync(descriptor); }
    try {
      const parent = openSync(dirname(path), "r");
      try { fsyncSync(parent); } finally { closeSync(parent); }
    } catch { /* The record itself keeps the conservative durability classification. */ }
  }

  flushParent(path) {
    try {
      const parent = openSync(dirname(path), "r");
      try { fsyncSync(parent); } finally { closeSync(parent); }
    } catch { /* Windows commonly cannot flush a directory descriptor. */ }
  }

  readReservation(destinationDigest, jobId) {
    let path;
    try { path = this.reservationPath(destinationDigest, jobId); }
    catch { throw new IntegrityError("destination reservation reference is malformed or tampered"); }
    const value = readJson(path, "destination reservation");
    try { return validateReservationRecord(value); }
    catch { throw new IntegrityError("destination reservation is malformed or tampered"); }
  }

  readClaim(path) {
    const value = readJson(path, "active destination claim");
    try { return validateClaimRecord(value); }
    catch { throw new IntegrityError("active destination claim is malformed or tampered"); }
  }

  readReleaseReceipt(reservation, { required = false } = {}) {
    const path = this.releaseReceiptPath(reservation.jobId);
    if (!existsSync(path)) {
      if (required) throw new IntegrityError("released reservation is missing its durable release receipt");
      return null;
    }
    const value = readJson(path, "reservation release receipt");
    try { validateReleaseReceipt(value); }
    catch { throw new IntegrityError("reservation release receipt is malformed or tampered"); }
    if (value.jobId !== reservation.jobId || value.destinationDigest !== reservation.destinationDigest ||
        value.canonicalDestination !== reservation.canonicalDestination || value.reservationDigest !== digestOf(reservation)) {
      throw new IntegrityError("reservation release receipt does not bind immutable reservation evidence");
    }
    return value;
  }

  directoryFiles(path, label) {
    let entries;
    try { entries = readdirSync(path, { withFileTypes: true }); }
    catch { throw new IntegrityError(`${label} directory is unavailable`); }
    for (const entry of entries) if (!entry.isFile()) throw new IntegrityError(`${label} contains a non-regular entry`);
    return entries.map((entry) => entry.name).sort();
  }

  enumerateReservations() {
    const files = this.directoryFiles(join(this.stateRoot, "reservations"), "reservation evidence");
    return files.map((name) => {
      const match = /^([a-f0-9]{64})--([a-z][a-z0-9_-]{2,63})\.json$/.exec(name);
      if (!match) throw new IntegrityError("reservation evidence has an unexpected filename");
      const reservation = this.readReservation(`sha256:${match[1]}`, match[2]);
      if (reservationFileStem(reservation.destinationDigest) !== match[1] || reservation.jobId !== match[2]) {
        throw new IntegrityError("reservation evidence filename does not bind its contents");
      }
      return reservation;
    });
  }

  enumerateReleaseReceipts() {
    const files = this.directoryFiles(join(this.stateRoot, "releases"), "reservation release receipts");
    return files.map((name) => {
      const match = /^([a-z][a-z0-9_-]{2,63})\.json$/.exec(name);
      if (!match) throw new IntegrityError("reservation release receipt has an unexpected filename");
      const value = readJson(join(this.stateRoot, "releases", name), "reservation release receipt");
      try { validateReleaseReceipt(value); }
      catch { throw new IntegrityError("reservation release receipt is malformed or tampered"); }
      if (value.jobId !== match[1]) throw new IntegrityError("reservation release receipt filename does not bind its contents");
      return value;
    });
  }

  enumerateRetiredClaims() {
    const files = this.directoryFiles(join(this.stateRoot, "retired-claims"), "retired active claims");
    return files.map((name) => {
      const match = /^([a-f0-9]{64})--([a-z][a-z0-9_-]{2,63})\.json$/.exec(name);
      if (!match) throw new IntegrityError("retired active claim has an unexpected filename");
      const claim = this.readClaim(join(this.stateRoot, "retired-claims", name));
      if (reservationFileStem(claim.destinationDigest) !== match[1] || claim.jobId !== match[2]) {
        throw new IntegrityError("retired active claim filename does not bind its contents");
      }
      return claim;
    });
  }

  enumerateActiveClaims({ allowPendingReservation = null } = {}) {
    const reservations = this.enumerateReservations();
    const receipts = this.enumerateReleaseReceipts();
    const retiredClaims = this.enumerateRetiredClaims();
    const files = this.directoryFiles(join(this.stateRoot, "claims"), "active destination claims");
    const claims = files.map((name) => {
      const match = /^([a-f0-9]{64})\.json$/.exec(name);
      if (!match) throw new IntegrityError("active destination claim has an unexpected filename");
      const claim = this.readClaim(join(this.stateRoot, "claims", name));
      if (reservationFileStem(claim.destinationDigest) !== match[1]) throw new IntegrityError("active destination claim filename does not bind its contents");
      const reservation = this.readReservation(claim.destinationDigest, claim.jobId);
      if (claim.canonicalDestination !== reservation.canonicalDestination || claim.reservationDigest !== digestOf(reservation)) {
        throw new IntegrityError("active destination claim does not bind immutable reservation evidence");
      }
      return { claim, reservation };
    });
    for (let index = 0; index < claims.length; index += 1) {
      for (let other = index + 1; other < claims.length; other += 1) {
        if (destinationPathsOverlap(claims[index].claim.canonicalDestination, claims[other].claim.canonicalDestination)) {
          throw new IntegrityError("durable active destination claims overlap");
        }
      }
    }
    const keyFor = (record) => `${record.destinationDigest}:${record.jobId}`;
    const active = new Map(claims.map(({ claim, reservation }) => [keyFor(claim), { claim, reservation }]));
    const reservationByKey = new Map();
    for (const reservation of reservations) {
      const key = keyFor(reservation);
      if (reservationByKey.has(key)) throw new IntegrityError("duplicate immutable reservation evidence exists");
      reservationByKey.set(key, reservation);
    }
    const receiptByKey = new Map();
    for (const receipt of receipts) {
      const key = keyFor(receipt);
      if (receiptByKey.has(key)) throw new IntegrityError("duplicate reservation release receipts exist");
      receiptByKey.set(key, receipt);
    }
    const retiredByKey = new Map();
    for (const retired of retiredClaims) {
      const key = keyFor(retired);
      if (retiredByKey.has(key)) throw new IntegrityError("duplicate retired active claims exist");
      retiredByKey.set(key, retired);
    }
    const matchingReservation = (record, reservation) => record && record.jobId === reservation.jobId &&
      record.destinationDigest === reservation.destinationDigest && record.canonicalDestination === reservation.canonicalDestination &&
      record.reservationDigest === digestOf(reservation);
    let pendingReservation = null;
    for (const reservation of reservations) {
      const key = keyFor(reservation);
      const current = active.get(`${reservation.destinationDigest}:${reservation.jobId}`);
      const receipt = receiptByKey.get(key);
      const retired = retiredByKey.get(key);
      if (current) {
        if (current.claim.reservationDigest !== digestOf(reservation)) throw new IntegrityError("active claim reservation digest drifted");
        if (retired) throw new IntegrityError("active and retired claim evidence conflict");
        if (receipt && !matchingReservation(receipt, reservation)) throw new IntegrityError("release receipt does not bind active reservation evidence");
        continue;
      }
      if (receipt || retired) {
        if (!matchingReservation(receipt, reservation) || !matchingReservation(retired, reservation)) {
          throw new IntegrityError("released reservation evidence is incomplete or does not bind immutable reservation evidence");
        }
        continue;
      }
      if (allowPendingReservation && reservation.jobId === allowPendingReservation.jobId &&
          reservation.destinationDigest === allowPendingReservation.destinationDigest &&
          reservation.canonicalDestination === allowPendingReservation.canonicalDestination) {
        if (pendingReservation !== null) throw new IntegrityError("duplicate pending reservation evidence exists");
        pendingReservation = reservation;
        continue;
      }
      throw new IntegrityError("reservation evidence is pending without an active claim or release receipt");
    }
    for (const receipt of receipts) {
      const reservation = reservationByKey.get(keyFor(receipt));
      if (!reservation || !matchingReservation(receipt, reservation)) throw new IntegrityError("orphaned reservation release receipt exists");
    }
    for (const retired of retiredClaims) {
      const reservation = reservationByKey.get(keyFor(retired));
      if (!reservation || !matchingReservation(retired, reservation)) throw new IntegrityError("orphaned retired active-claim evidence exists");
    }
    return { claims, reservations, pendingReservation };
  }

  activateReservationClaim(reservation) {
    const claim = {
      contractVersion: STORE_VERSION, destinationDigest: reservation.destinationDigest,
      canonicalDestination: reservation.canonicalDestination, jobId: reservation.jobId,
      reservationDigest: digestOf(reservation), durability: RESERVATION_DURABILITY
    };
    const path = this.activeClaimPath(reservation.destinationDigest);
    try { this.exclusiveDurableCreate(path, claim); }
    catch (error) {
      if (error?.code !== "EEXIST") throw error;
      const existing = this.readClaim(path);
      if (existing.jobId !== reservation.jobId || existing.reservationDigest !== digestOf(reservation) ||
          existing.canonicalDestination !== reservation.canonicalDestination) {
        throw new LeaseConflictError("canonical destination active claim already exists");
      }
    }
    return structuredClone(reservation);
  }

  reserve(destinationRoot, jobId) {
    const canonical = canonicalDestination(destinationRoot);
    const destinationDigest = hash(canonical);
    safeIdentifier(jobId, "jobId");
    return this.withLock("reservation-global", () => {
      const scan = this.enumerateActiveClaims({ allowPendingReservation: { jobId, destinationDigest, canonicalDestination: canonical } });
      const { claims, reservations, pendingReservation } = scan;
      const own = claims.find(({ claim }) => claim.destinationDigest === destinationDigest && claim.jobId === jobId);
      if (own) return structuredClone(own.reservation);
      const priorJobReservations = reservations.filter((reservation) => reservation.jobId === jobId);
      if (priorJobReservations.some((reservation) => reservation.destinationDigest !== destinationDigest)) {
        throw new LeaseConflictError("a job may hold only one canonical destination reservation");
      }
      const priorJobReservation = priorJobReservations[0] ?? null;
      if (priorJobReservation && pendingReservation === null) return structuredClone(priorJobReservation);
      for (const { claim } of claims) {
        if (destinationPathsOverlap(canonical, claim.canonicalDestination)) {
          throw new LeaseConflictError("canonical destination reservation overlaps an active claim");
        }
      }
      if (pendingReservation !== null) return this.activateReservationClaim(pendingReservation);
      const reservation = {
        contractVersion: STORE_VERSION, destinationDigest, canonicalDestination: canonical, jobId, createdAt: this.now(),
        durability: RESERVATION_DURABILITY
      };
      const reservationPath = this.reservationPath(destinationDigest, jobId);
      try { this.exclusiveDurableCreate(reservationPath, reservation); }
      catch (error) {
        if (error?.code !== "EEXIST") throw error;
        throw new LeaseConflictError("immutable reservation evidence already exists without an active claim");
      }
      if (this.faults?.afterReservationEvidence) throw new Error("injected failure after reservation evidence");
      return this.activateReservationClaim(reservation);
    });
  }

  releaseReservation(jobId) {
    safeIdentifier(jobId, "jobId");
    return this.withLock("reservation-global", () => {
      const snapshot = this.readVerified(jobId);
      if (!RELEASE_ELIGIBLE_STATES.has(snapshot.job.state)) fail("reservation release requires an independently verified allowed terminal job state");
      const reservation = snapshot.reservation;
      const { claims } = this.enumerateActiveClaims();
      const active = claims.find(({ claim }) => claim.destinationDigest === reservation.destinationDigest && claim.jobId === jobId);
      let receipt = this.readReleaseReceipt(reservation);
      if (receipt === null) {
        if (!active) throw new IntegrityError("reservation release is pending or ambiguous because no active claim is present");
        receipt = {
          contractVersion: STORE_VERSION, destinationDigest: reservation.destinationDigest,
          canonicalDestination: reservation.canonicalDestination, jobId, reservationDigest: digestOf(reservation),
          jobState: snapshot.job.state, releasedAt: this.now(), status: "released", durability: RESERVATION_DURABILITY
        };
        try { this.exclusiveDurableCreate(this.releaseReceiptPath(jobId), receipt); }
        catch (error) {
          if (error?.code !== "EEXIST") throw error;
          receipt = this.readReleaseReceipt(reservation, { required: true });
        }
      }
      if (this.faults?.afterReleaseReceipt) throw new Error("injected failure after reservation release receipt");
      const activePath = this.activeClaimPath(reservation.destinationDigest);
      const retiredPath = this.retiredClaimPath(reservation.destinationDigest, jobId);
      if (existsSync(activePath)) {
        const current = this.readClaim(activePath);
        if (current.jobId !== jobId || current.reservationDigest !== digestOf(reservation) || current.canonicalDestination !== reservation.canonicalDestination) {
          throw new IntegrityError("active claim does not bind the terminal job reservation");
        }
        if (existsSync(retiredPath)) throw new IntegrityError("reservation release has conflicting retired-claim evidence");
        renameSync(activePath, retiredPath);
        this.flushParent(activePath);
        this.flushParent(retiredPath);
      } else {
        if (!existsSync(retiredPath)) throw new IntegrityError("reservation release is pending or ambiguous after receipt persistence");
        const retired = this.readClaim(retiredPath);
        if (retired.jobId !== jobId || retired.reservationDigest !== digestOf(reservation) || retired.canonicalDestination !== reservation.canonicalDestination) {
          throw new IntegrityError("retired claim does not bind the terminal job reservation");
        }
      }
      return { jobId, destinationDigest: reservation.destinationDigest, status: "released", releasedAt: receipt.releasedAt };
    });
  }

  snapshotFromAdmission(record) {
    const { job, admission, reservation, serviceContext = null, idempotency } = record.payload;
    if (serviceContext !== null) this.validateServiceContext(serviceContext);
    return {
      contractVersion: STORE_VERSION, journalCursor: 0, journalDigest: record.digest, sequence: 0, eventSequence: 0, job,
      admission, reservation, bindings: { candidate: null, grantDigest: admission.grantDigest, receiptDigest: admission.receiptDigest, providerCandidateDigest: null },
      lease: null, usage: null, attempts: [], candidateHistory: [], recoveryRepair: null, cancellation: null, serviceContext, serviceRuntime: null, idempotency: [idempotency], durability: "unknown"
    };
  }

  readVerified(jobId, { includeRecords = false, recoverTail = true } = {}) {
    if (typeof recoverTail !== "boolean") fail("recoverTail must be boolean");
    let snapshot = readJson(this.snapshotPath(jobId), "job snapshot");
    if (snapshot.contractVersion !== STORE_VERSION) throw new IntegrityError("job snapshot version is unsupported");
    validateJob(snapshot.job);
    if (!Number.isSafeInteger(snapshot.journalCursor) || snapshot.journalCursor < 0 || !Number.isSafeInteger(snapshot.sequence) || snapshot.sequence < 0) throw new IntegrityError("job snapshot cursor is invalid");
    if (!plainObject(snapshot.reservation)) throw new IntegrityError("job snapshot reservation reference is malformed");
    const reservation = this.readReservation(snapshot.reservation.destinationDigest, jobId);
    if (canonical(reservation) !== canonical(snapshot.reservation) || reservation.jobId !== jobId) throw new IntegrityError("destination reservation was mutated");
    const text = (() => { try { return readFileSync(this.journalPath(jobId), "utf8"); } catch { throw new IntegrityError("journal is missing"); } })();
    if (Buffer.byteLength(text, "utf8") > MAX_JOURNAL_BYTES || !text.endsWith("\n")) throw new IntegrityError("journal is truncated or exceeds its bound");
    const lines = text.split("\n").filter(Boolean);
    if (lines.length === 0) throw new IntegrityError("journal is empty");
    let previousDigest = null, latest = null;
    const records = lines.map((line, index) => {
      let record;
      try { record = JSON.parse(line); } catch { throw new IntegrityError("journal contains malformed JSON"); }
      const { digest, ...unsignedRecord } = record;
      if (record.contractVersion !== JOURNAL_VERSION || record.previousDigest !== previousDigest || digest !== digestOf(unsignedRecord)) {
        throw new IntegrityError("journal hash chain is invalid");
      }
      if (record.cursor !== index || record.sequence < 0) throw new IntegrityError("journal cursor is reordered or duplicated");
      previousDigest = record.digest; latest = record;
      return record;
    });
    const replayed = this.replayJournal(records);
    const observed = {
      journalCursor: snapshot.journalCursor, journalDigest: snapshot.journalDigest, sequence: snapshot.sequence, eventSequence: snapshot.eventSequence,
      job: snapshot.job, admission: snapshot.admission, reservation: snapshot.reservation, bindings: snapshot.bindings,
      lease: snapshot.lease, usage: snapshot.usage, attempts: snapshot.attempts, candidateHistory: snapshot.candidateHistory, recoveryRepair: snapshot.recoveryRepair ?? null,
      cancellation: snapshot.cancellation ?? null, serviceContext: snapshot.serviceContext ?? null, serviceRuntime: snapshot.serviceRuntime ?? null, idempotency: snapshot.idempotency
    };
    const atTail = snapshot.journalCursor === lines.length - 1 && snapshot.journalDigest === latest.digest;
    if (snapshot.job.eventCursor > snapshot.journalCursor || snapshot.journalCursor >= lines.length || records[snapshot.journalCursor]?.digest !== snapshot.journalDigest) {
      throw new IntegrityError("snapshot cursor or digest does not match journal");
    }
    if (!atTail) {
      // A crash can occur after an fsynced, hash-chained journal append but
      // before its snapshot replace.  Recover only when the on-disk snapshot
      // exactly proves the complete journal prefix; any malformed, replaced,
      // or semantically divergent prefix remains fail-closed and untouched.
      if (!recoverTail) throw new IntegrityError("snapshot has a pending journal tail");
      const prefix = this.replayJournal(records.slice(0, snapshot.journalCursor + 1));
      if (canonical(prefix) !== canonical(observed)) throw new IntegrityError("snapshot does not faithfully represent the committed journal prefix");
      snapshot = this.commitSnapshot(jobId, { contractVersion: STORE_VERSION, ...replayed });
    } else if (canonical(replayed) !== canonical(observed)) {
      throw new IntegrityError("snapshot does not faithfully represent the committed journal");
    }
    if (snapshot.recoveryRepair === undefined) snapshot.recoveryRepair = null;
    if (snapshot.cancellation === undefined) snapshot.cancellation = null;
    return includeRecords ? { snapshot, records } : snapshot;
  }

  replayJournal(records) {
    const admission = records[0].payload;
    if (records[0] && records[0].type !== "admission") throw new IntegrityError("journal does not begin with immutable admission");
    if (admission.serviceContext !== null && admission.serviceContext !== undefined) this.validateServiceContext(admission.serviceContext);
    const state = {
      journalCursor: 0, journalDigest: records[0].digest, sequence: 0, eventSequence: 0, job: structuredClone(admission.job),
      admission: structuredClone(admission.admission), reservation: structuredClone(admission.reservation), serviceContext: structuredClone(admission.serviceContext ?? null),
      bindings: { candidate: null, grantDigest: admission.admission.grantDigest, receiptDigest: admission.admission.receiptDigest, providerCandidateDigest: null },
      lease: null, usage: null, attempts: [], candidateHistory: [], recoveryRepair: null, cancellation: null, serviceRuntime: null, idempotency: [admission.idempotency]
    };
    for (const record of records.slice(1)) {
      const payload = record.payload;
      state.journalCursor = record.cursor; state.journalDigest = record.digest; state.sequence = record.sequence;
      if (record.type === "lease_acquired" || record.type === "lease_renewed") state.lease = payload.lease;
      else if (record.type === "service_context") state.serviceContext = this.validateServiceContext(payload);
      else if (record.type === "service_runtime") state.serviceRuntime = this.validateServiceRuntime(payload);
      else if (record.type === "transition") state.job.state = payload.to;
      else if (record.type === "recovery_required") {
        if (!plainObject(payload) || typeof payload.from !== "string") throw new IntegrityError("recovery record is malformed");
        safeIdentifier(payload.code, "recovery code");
        state.job.state = "recovery_required";
      }
      else if (record.type === "event") { state.job.eventCursor = payload.cursor; state.eventSequence = payload.sequence; }
      else if (record.type === "attempt_recorded") state.attempts.push(payload);
      else if (record.type === "evidence_bound") state.bindings = payload;
      else if (record.type === "collection") {
        state.job.state = payload.disposition === "accepted" ? "accepted" : payload.disposition === "rejected" ? "rejected" : "repairing";
        if (state.job.state === "repairing") {
          state.candidateHistory.push(state.bindings);
          state.bindings = { candidate: null, grantDigest: state.admission.grantDigest, receiptDigest: state.admission.receiptDigest, providerCandidateDigest: null };
        }
      }
      else if (record.type === "repair_requested") {
        state.candidateHistory.push({ ...state.bindings, repairRequest: payload });
        state.bindings = {
          candidate: null,
          grantDigest: payload.repairGrantDigest ?? state.admission.grantDigest,
          receiptDigest: payload.repairReceiptDigest ?? state.admission.receiptDigest,
          providerCandidateDigest: null
        };
        state.job.state = "repairing";
      }
      else if (record.type === "usage") state.usage = payload;
      else if (record.type === "idempotency") state.idempotency.push(payload);
      else if (record.type === "idempotent_mutation") {
        if (!plainObject(payload) || !plainObject(payload.effect) || !plainObject(payload.idempotency) ||
            typeof payload.effect.type !== "string" || !("payload" in payload.effect)) {
          throw new IntegrityError("idempotent mutation record is malformed");
        }
        try { this.applyIdempotentEffect(state, payload.effect.type, payload.effect.payload); }
        catch (error) {
          if (error instanceof IntegrityError) throw error;
          throw new IntegrityError("idempotent mutation effect is malformed");
        }
        state.idempotency.push(payload.idempotency);
      }
      else throw new IntegrityError("journal contains an unsupported record type");
    }
    return state;
  }

  applyIdempotentEffect(snapshot, type, payload) {
    if (type === "candidate_published") {
      if (!plainObject(payload)) fail("candidate publication effect must be a plain object");
      exactKeys(payload, ["candidate", "providerCandidateDigest", "grantDigest", "receiptDigest"], "candidate publication effect");
      validateCandidate(payload.candidate); safeDigest(payload.providerCandidateDigest, "candidate publication provider digest");
      safeDigest(payload.grantDigest, "candidate publication grant"); safeDigest(payload.receiptDigest, "candidate publication receipt");
      snapshot.bindings = {
        candidate: structuredClone(payload.candidate), grantDigest: payload.grantDigest,
        receiptDigest: payload.receiptDigest, providerCandidateDigest: payload.providerCandidateDigest
      };
      snapshot.job.state = "candidate_ready";
      return;
    }
    if (type === "collection") {
      validateCollection(payload);
      const to = payload.disposition === "accepted" ? "accepted" : payload.disposition === "rejected" ? "rejected" : "repairing";
      if (to === "repairing") {
        snapshot.candidateHistory.push(snapshot.bindings);
        snapshot.bindings = { candidate: null, grantDigest: snapshot.admission.grantDigest, receiptDigest: snapshot.admission.receiptDigest, providerCandidateDigest: null };
      }
      snapshot.job.state = to;
      return;
    }
    if (type === "repair_requested") {
      if (!plainObject(payload)) fail("repair effect must be a plain object");
      safeDigest(payload.findingsDigest, "repair effect findingsDigest"); safeIdentifier(payload.expectedAttemptId, "repair effect expectedAttemptId");
      safeDigest(payload.expectedCandidateDigest, "repair effect expectedCandidateDigest"); if (payload.repairGrantDigest !== null) safeDigest(payload.repairGrantDigest, "repair effect grant"); if (payload.repairReceiptDigest !== null) safeDigest(payload.repairReceiptDigest, "repair effect receipt");
      snapshot.candidateHistory.push({ ...snapshot.bindings, repairRequest: structuredClone(payload) });
      snapshot.bindings = {
        candidate: null,
        grantDigest: payload.repairGrantDigest ?? snapshot.admission.grantDigest,
        receiptDigest: payload.repairReceiptDigest ?? snapshot.admission.receiptDigest,
        providerCandidateDigest: null
      };
      snapshot.job.state = "repairing";
      return;
    }
    if (type === "repair_continued") {
      if (!plainObject(payload)) fail("repair continuation effect must be a plain object");
      safeDigest(payload.findingsDigest, "repair continuation findingsDigest"); safeIdentifier(payload.expectedAttemptId, "repair continuation expectedAttemptId");
      safeDigest(payload.expectedCandidateDigest, "repair continuation expectedCandidateDigest"); if (payload.repairGrantDigest !== null) safeDigest(payload.repairGrantDigest, "repair continuation grant"); if (payload.repairReceiptDigest !== null) safeDigest(payload.repairReceiptDigest, "repair continuation receipt");
      const history = snapshot.candidateHistory.at(-1);
      if (!history?.candidate) fail("repair continuation requires an archived candidate");
      if (history.repairRequest && canonical(history.repairRequest) !== canonical(payload)) fail("a different repair request is already active");
      history.repairRequest = structuredClone(payload);
      snapshot.bindings = {
        candidate: null,
        grantDigest: payload.repairGrantDigest ?? snapshot.admission.grantDigest,
        receiptDigest: payload.repairReceiptDigest ?? snapshot.admission.receiptDigest,
        providerCandidateDigest: null
      };
      return;
    }
    if (type === "recovery_repair_requested" || type === "recovery_repair_continued") {
      if (!plainObject(payload)) fail("runtime recovery repair effect must be a plain object");
      exactKeys(payload, ["findingsDigest", "expectedAttemptId", "expectedNativeSessionId", "recoveryProofDigest", "repairGrantDigest", "repairReceiptDigest"], "runtime recovery repair effect");
      safeDigest(payload.findingsDigest, "runtime recovery repair findingsDigest"); safeIdentifier(payload.expectedAttemptId, "runtime recovery repair attempt"); safeSessionIdentifier(payload.expectedNativeSessionId, "runtime recovery repair native session"); safeDigest(payload.recoveryProofDigest, "runtime recovery repair proof"); safeDigest(payload.repairGrantDigest, "runtime recovery repair grant"); safeDigest(payload.repairReceiptDigest, "runtime recovery repair receipt");
      if (type === "recovery_repair_continued") {
        if (!snapshot.recoveryRepair || canonical(snapshot.recoveryRepair) !== canonical(payload)) fail("a different runtime recovery repair is already active");
        return;
      }
      snapshot.recoveryRepair = structuredClone(payload); snapshot.job.state = "repairing";
      return;
    }
    if (type === "cancellation_intent") {
      exactKeys(payload, ["from", "cancellation"], "cancellation intent effect");
      if (typeof payload.from !== "string" || !plainObject(payload.cancellation)) fail("cancellation intent effect is malformed");
      exactKeys(payload.cancellation, ["reason", "cancellationDigest", "fromState"], "cancellation intent");
      safeIdentifier(payload.cancellation.reason, "cancellation intent reason"); safeDigest(payload.cancellation.cancellationDigest, "cancellation intent digest");
      if (payload.cancellation.fromState !== payload.from || typeof payload.cancellation.fromState !== "string") fail("cancellation origin state is malformed");
      snapshot.job.state = "cancelling";
      snapshot.cancellation = structuredClone(payload.cancellation);
      return;
    }
    if (type === "cancellation_acknowledged") {
      exactKeys(payload, ["expectedCancellationDigest"], "cancellation acknowledgement effect");
      safeDigest(payload.expectedCancellationDigest, "cancellation acknowledgement digest");
      snapshot.job.state = "cancelled";
      return;
    }
    throw new IntegrityError("idempotent mutation has an unsupported effect type");
  }

  assertFence(snapshot, fence) {
    if (!snapshot.lease) return;
    if (!Number.isSafeInteger(fence) || fence !== snapshot.lease.fencingToken || snapshot.lease.expiresAt <= this.now()) throw new LeaseConflictError("current execution fence is required");
  }

  effectiveJob(snapshot) {
    if (ACTIVE_EXECUTION_STATES.has(snapshot.job.state)) {
      const localLease = this.localLeases.get(snapshot.job.jobId);
      if (localLease && snapshot.lease && localLease.fencingToken === snapshot.lease.fencingToken &&
          localLease.ownerId === snapshot.lease.ownerId && snapshot.lease.expiresAt > this.now()) {
        return structuredClone(snapshot.job);
      }
      return { ...structuredClone(snapshot.job), state: "recovery_required", recoveryReason: "active_execution_reopened" };
    }
    if (snapshot.job.state === "candidate_ready" && !this.revalidate(snapshot)) {
      return { ...structuredClone(snapshot.job), state: "recovery_required", recoveryReason: "custody_revalidation_required" };
    }
    return structuredClone(snapshot.job);
  }

  revalidate(snapshot, callback = this.custodyRevalidator) {
    if (typeof callback !== "function") return false;
    try { return callback(structuredClone({ job: snapshot.job, admission: snapshot.admission, bindings: snapshot.bindings })) === true; } catch { return false; }
  }

  replay(snapshot, operation, key, requestDigest) {
    const record = snapshot.idempotency.find((entry) => entry.key === key);
    if (!record) fail("job already exists with different submission identity");
    if (record.operation !== operation || record.requestDigest !== requestDigest) throw new IdempotencyConflictError("idempotency key was reused with a different operation or request digest");
    return structuredClone(record.result);
  }

  idempotentMutation(jobId, operation, key, request, fence, callback) {
    const snapshot = this.readVerified(jobId);
    const requestDigest = idempotencyDigest(operation, request);
    const existing = snapshot.idempotency.find((entry) => entry.key === key);
    if (existing) {
      if (existing.operation !== operation || existing.requestDigest !== requestDigest) throw new IdempotencyConflictError("idempotency key was reused with a different operation or request digest");
      return structuredClone(existing.result);
    }
    if (isTerminal(snapshot.job.state)) fail("terminal jobs are immutable");
    this.assertFence(snapshot, fence);
    const effect = callback(snapshot, { requestDigest });
    if (!plainObject(effect) || typeof effect.type !== "string" || !("payload" in effect) ||
        ("result" in effect && !plainObject(effect.result))) {
      fail("idempotent mutation callback must describe one durable effect");
    }
    const effectPayload = normalizeForStorage(effect.payload, `idempotent mutation.${effect.type}`);
    const resultExtras = normalizeForStorage(effect.result ?? {}, `idempotent mutation.${effect.type}.result`);
    if (["jobId", "state", "cursor"].some((field) => field in resultExtras)) {
      fail("idempotent mutation result must not override the committed job result");
    }
    const prospective = structuredClone(snapshot);
    this.applyIdempotentEffect(prospective, effect.type, effectPayload);
    const result = { jobId, state: prospective.job.state, cursor: prospective.job.eventCursor, ...resultExtras };
    const receipt = { operation, key, requestDigest, result };
    const mutation = { effect: { type: effect.type, payload: effectPayload }, idempotency: receipt };
    const withRecord = this.mutateSnapshot(jobId, snapshot, "idempotent_mutation", mutation, (next) => {
      this.applyIdempotentEffect(next, mutation.effect.type, mutation.effect.payload);
      next.idempotency.push(mutation.idempotency);
    });
    if (this.faults?.afterIdempotentMutation) throw new Error("injected failure after idempotent mutation commit");
    return structuredClone(withRecord.idempotency.at(-1).result);
  }

  mutateSnapshot(jobId, snapshot, type, payload, apply) {
    const record = {
      contractVersion: JOURNAL_VERSION, cursor: snapshot.journalCursor + 1, sequence: snapshot.sequence + 1,
      type, previousDigest: snapshot.journalDigest, payload: normalizeForStorage(payload, `journal.${type}`)
    };
    record.digest = digestOf(record);
    appendDurable(this.journalPath(jobId), record);
    if (this.faults?.afterJournal) throw new Error("injected failure after journal append");
    const next = structuredClone(snapshot);
    next.journalCursor = record.cursor; next.journalDigest = record.digest; next.sequence = record.sequence;
    apply(next);
    this.commitSnapshot(jobId, next);
    if (isTerminal(next.job.state)) this.localLeases.delete(jobId);
    return next;
  }

  commitSnapshot(jobId, snapshot) {
    snapshot.durability = "file_fsynced_parent_flush_unavailable";
    const observed = durableWrite(this.snapshotPath(jobId), snapshot);
    snapshot.durability = observed;
    return snapshot;
  }
}
