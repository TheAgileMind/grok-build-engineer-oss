import assert from "node:assert/strict";
import { closeSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { CONTRACT_VERSIONS } from "../src/contracts.mjs";
import { JobStore, IdempotencyConflictError, IntegrityError, LeaseConflictError } from "../src/job-store.mjs";
import { assertTransition, canTransition, isTerminal } from "../src/lifecycle.mjs";

const digest = `sha256:${"a".repeat(64)}`;
const digestB = `sha256:${"b".repeat(64)}`;
const timestamp = "2026-08-14T00:00:00.000Z";

function stateRoot() { return mkdtempSync(join(tmpdir(), "grok-job-store-")); }
function cleanup(root) { rmSync(root, { recursive: true, force: true }); }

test("a stale exact submission claim is atomically renewed for one recovery attempt", () => {
  const root = stateRoot(); let now = 1_000;
  try {
    const store = new JobStore({ stateRoot: root, now: () => now, submissionClaimLeaseMs: 100 });
    const request = { idempotencyKey: "submit-001", contextDigest: digest };
    assert.deepEqual(store.claimServiceSubmission("job-001", request), { status: "claimed" });
    assert.deepEqual(store.claimServiceSubmission("job-001", request), { status: "pending" });
    now += 101;
    assert.deepEqual(store.claimServiceSubmission("job-001", request), { status: "recovered" });
    assert.deepEqual(store.claimServiceSubmission("job-001", request), { status: "pending" }, "the renewed lease excludes a concurrent retrier");
    assert.throws(() => store.claimServiceSubmission("job-001", { ...request, contextDigest: digestB }), IdempotencyConflictError);
  } finally { cleanup(root); }
});
function job(jobId = "job-001") {
  return {
    contractVersion: CONTRACT_VERSIONS.job, jobId, submissionId: `submission-${jobId.slice(4)}`,
    state: "queued", profileDigest: digest, sourceCustodyDigest: digestB, eventCursor: 0
  };
}
function admission(root, name = "destination") {
  return {
    destinationRoot: join(root, name), grantDigest: digest, receiptDigest: digestB,
    sourceCustodyDigest: digestB, profileDigest: digest
  };
}
function event(jobId, fence, cursor, sequence = cursor) {
  return {
    contractVersion: CONTRACT_VERSIONS.event, eventId: `event-${String(cursor).padStart(3, "0")}`,
    jobId, attemptId: "attempt-001", fencingToken: fence, nativeSessionId: "session-001",
    requestId: `request-${String(cursor).padStart(3, "0")}`, cursor, sequence,
    kind: "progress", occurredAt: timestamp,
    data: { message: "safe progress" }
  };
}
function collection(jobId, disposition, key) {
  return {
    contractVersion: CONTRACT_VERSIONS.collection, collectionId: `collect-${key.slice(-3)}`,
    jobId, expectedAttemptId: "attempt-001", expectedCandidateDigest: digest,
    disposition, validationEvidenceRef: "validation-001", validationEvidenceDigest: digestB,
    idempotencyKey: key
  };
}
function candidate(jobId) {
  return {
    contractVersion: CONTRACT_VERSIONS.candidate, candidateId: "candidate-001", jobId,
    attemptId: "attempt-001", manifestDigest: digest, createdAt: timestamp, changedPaths: ["src/index.mjs"]
  };
}
function attempt(jobId) {
  return { contractVersion: CONTRACT_VERSIONS.attempt, attemptId: "attempt-001", jobId, number: 1, state: "queued", profileDigest: digest };
}
function moveToCandidate(store, jobId, fence) {
  if (store.readAttempts(jobId).length === 0) store.recordAttempt(jobId, attempt(jobId), { fence });
  store.transition(jobId, "preflighting", { fence });
  store.transition(jobId, "starting", { fence });
  store.transition(jobId, "running", { fence });
  store.bindEvidence(jobId, { candidate: candidate(jobId), grantDigest: digest, receiptDigest: digestB, fence });
  store.transition(jobId, "candidate_ready", { fence });
}
function createJob(root, jobId = "job-001", destination = "destination") {
  const store = new JobStore({ stateRoot: root });
  store.submit({ job: job(jobId), admission: admission(root, destination), idempotencyKey: `submit-${jobId.slice(4)}` });
  return store;
}
function journalRecords(root, jobId = "job-001") {
  return readFileSync(join(root, "jobs", jobId, "journal.ndjson"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
}
function atomicMutation(root, operation) {
  const records = journalRecords(root).filter((record) => record.type === "idempotent_mutation" && record.payload.idempotency.operation === operation);
  assert.equal(records.length, 1, `${operation} must have one durable effect-and-receipt record`);
  return records[0];
}

test("lifecycle admits only explicit paths and keeps terminal states immutable", () => {
  assert.equal(canTransition("queued", "preflighting"), true);
  assert.equal(canTransition("awaiting_codex_input", "cancelling"), true);
  assert.equal(canTransition("candidate_ready", "repairing"), true);
  assert.equal(canTransition("candidate_ready", "accepted"), true);
  assert.equal(canTransition("candidate_ready", "rejected"), true);
  assert.equal(canTransition("candidate_ready", "cancelling"), true);
  assert.equal(canTransition("recovery_required", "running"), false);
  assert.equal(canTransition("recovery_required", "cancelling"), true);
  assert.equal(canTransition("accepted", "running"), false);
  assert.equal(isTerminal("cancelled"), true);
  assert.throws(() => assertTransition("queued", "running"), /not allowed/);
});

test("persists a fresh job, restores candidate-ready only after custody revalidation, and flags active restart", () => {
  const root = stateRoot();
  try {
    const store = createJob(root);
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
    store.recordAttempt("job-001", attempt("job-001"), { fence: lease.fencingToken });
    moveToCandidate(store, "job-001", lease.fencingToken);
    assert.equal(new JobStore({ stateRoot: root, custodyRevalidator: () => true }).openJob("job-001").state, "candidate_ready");
    assert.equal(new JobStore({ stateRoot: root }).readAttempts("job-001")[0].attemptId, "attempt-001");
    assert.equal(new JobStore({ stateRoot: root, custodyRevalidator: () => false }).openJob("job-001").state, "recovery_required");

    const activeRoot = stateRoot();
    try {
      const active = createJob(activeRoot);
      const activeLease = active.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
      active.transition("job-001", "preflighting", { fence: activeLease.fencingToken });
      assert.equal(active.readStatus("job-001").job.state, "preflighting", "the current lease owner reports its live state");
      assert.equal(active.openJob("job-001").state, "preflighting");
      assert.equal(new JobStore({ stateRoot: activeRoot }).openJob("job-001").state, "recovery_required");
      assert.equal(new JobStore({ stateRoot: activeRoot }).readStatus("job-001").job.state, "recovery_required");
    } finally { cleanup(activeRoot); }
  } finally { cleanup(root); }
});

test("status can return events and their exact stable snapshot in one observer read", () => {
  const root = stateRoot();
  try {
    const store = createJob(root);
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
    store.appendEvent("job-001", event("job-001", lease.fencingToken, 1), { fence: lease.fencingToken });
    const observed = store.readStatus("job-001", { afterCursor: 0, includeSnapshot: true });
    assert.equal(observed.snapshot.job.eventCursor, 1);
    assert.equal(observed.events.length, 1);
    assert.equal(observed.events[0].cursor, observed.snapshot.job.eventCursor);
    assert.deepEqual(store.readStatus("job-001", { afterCursor: 0 }), { job: observed.job, events: observed.events });
  } finally { cleanup(root); }
});

test("idempotent collection and repair operations replay their original result but reject digest conflicts", () => {
  const root = stateRoot();
  try {
    const store = createJob(root);
    const replay = store.submit({ job: job(), admission: admission(root), idempotencyKey: "submit-001" });
    assert.equal(replay.state, "queued");
    assert.throws(() => store.submit({ job: job("job-002"), admission: admission(root, "other"), idempotencyKey: "submit-001" }), IdempotencyConflictError);

    const collectRoot = stateRoot();
    try {
      const collectStore = createJob(collectRoot);
      const collectLease = collectStore.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
      moveToCandidate(collectStore, "job-001", collectLease.fencingToken);
      const accepted = collection("job-001", "accepted", "collect-001");
      assert.deepEqual(collectStore.disposeCandidate("job-001", { collection: accepted, fence: collectLease.fencingToken }),
        collectStore.disposeCandidate("job-001", { collection: accepted, fence: collectLease.fencingToken }));
      assert.throws(() => collectStore.requestRepair("job-001", {
        idempotencyKey: "collect-001", findingsDigest: digest, expectedAttemptId: "attempt-001",
        expectedCandidateDigest: digest, fence: collectLease.fencingToken
      }), IdempotencyConflictError);

      const repairRoot = stateRoot();
      try {
        const repairStore = createJob(repairRoot);
        const repairLease = repairStore.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
        moveToCandidate(repairStore, "job-001", repairLease.fencingToken);
        const repair = repairStore.requestRepair("job-001", { idempotencyKey: "repair-001", findingsDigest: digest,
          expectedAttemptId: "attempt-001", expectedCandidateDigest: digest, fence: repairLease.fencingToken });
        assert.deepEqual(repair, repairStore.requestRepair("job-001", { idempotencyKey: "repair-001", findingsDigest: digest,
          expectedAttemptId: "attempt-001", expectedCandidateDigest: digest, fence: repairLease.fencingToken }));
        assert.throws(() => repairStore.requestRepair("job-001", { idempotencyKey: "repair-001", findingsDigest: digestB,
          expectedAttemptId: "attempt-001", expectedCandidateDigest: digest, fence: repairLease.fencingToken }), IdempotencyConflictError);
      } finally { cleanup(repairRoot); }
    } finally { cleanup(collectRoot); }
  } finally { cleanup(root); }
});

test("cancellation persists a durable intent and only a matching acknowledgement finalizes it", () => {
  const root = stateRoot();
  try {
    const store = createJob(root);
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
    moveToCandidate(store, "job-001", lease.fencingToken);
    assert.throws(() => store.transition("job-001", "cancelling", { fence: lease.fencingToken }), /beginCancellation/);
    const intent = store.cancel("job-001", {
      reason: "operator_requested", idempotencyKey: "cancel-intent-001", fence: lease.fencingToken
    });
    assert.equal(intent.state, "cancelling");
    assert.match(intent.cancellationDigest, /^sha256:/);
    assert.equal(store.readJob("job-001").state, "cancelling");
    assert.equal(store.openJob("job-001").state, "cancelling");
    assert.equal(new JobStore({ stateRoot: root }).openJob("job-001").state, "recovery_required", "a lost acknowledgement is not a cancellation result");
    assert.deepEqual(store.beginCancellation("job-001", {
      reason: "operator_requested", idempotencyKey: "cancel-intent-001", fence: lease.fencingToken
    }), intent);
    assert.throws(() => store.beginCancellation("job-001", {
      reason: "different_reason", idempotencyKey: "cancel-intent-001", fence: lease.fencingToken
    }), IdempotencyConflictError);
    assert.throws(() => store.acknowledgeCancellation("job-001", {
      expectedCancellationDigest: digestB, idempotencyKey: "cancel-ack-001", fence: lease.fencingToken
    }), /preconditions/);
    assert.throws(() => store.transition("job-001", "cancelled", { fence: lease.fencingToken }), /acknowledgeCancellation/);
    const acknowledged = store.acknowledgeCancellation("job-001", {
      expectedCancellationDigest: intent.cancellationDigest, idempotencyKey: "cancel-ack-001", fence: lease.fencingToken
    });
    assert.equal(acknowledged.state, "cancelled");
    assert.equal(store.localLeases.has("job-001"), false, "a committed terminal transition clears its local lease cache");
    assert.deepEqual(store.acknowledgeCancellation("job-001", {
      expectedCancellationDigest: intent.cancellationDigest, idempotencyKey: "cancel-ack-001", fence: lease.fencingToken
    }), acknowledged);
    assert.throws(() => store.acknowledgeCancellation("job-001", {
      expectedCancellationDigest: digestB, idempotencyKey: "cancel-ack-001", fence: lease.fencingToken
    }), IdempotencyConflictError);
    assert.equal(new JobStore({ stateRoot: root }).readJob("job-001").state, "cancelled");
  } finally { cleanup(root); }
});

test("collection, repair, and cancellation phases atomically persist their idempotency receipt before a retry response", () => {
  const collectionRoot = stateRoot();
  try {
    const store = createJob(collectionRoot);
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
    moveToCandidate(store, "job-001", lease.fencingToken);
    const request = collection("job-001", "accepted", "collect-001");
    assert.throws(() => new JobStore({ stateRoot: collectionRoot, faults: { afterIdempotentMutation: true } })
      .disposeCandidate("job-001", { collection: request, fence: lease.fencingToken }), /injected failure/);
    const record = atomicMutation(collectionRoot, "collection");
    assert.equal(record.payload.effect.type, "collection");
    assert.equal(record.payload.idempotency.key, request.idempotencyKey);
    assert.deepEqual(new JobStore({ stateRoot: collectionRoot }).disposeCandidate("job-001", {
      collection: request, fence: lease.fencingToken
    }), record.payload.idempotency.result);
    assert.equal(atomicMutation(collectionRoot, "collection").payload.effect.type, "collection");
  } finally { cleanup(collectionRoot); }

  const repairRoot = stateRoot();
  try {
    const store = createJob(repairRoot);
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
    moveToCandidate(store, "job-001", lease.fencingToken);
    const request = { idempotencyKey: "repair-001", findingsDigest: digest,
      expectedAttemptId: "attempt-001", expectedCandidateDigest: digest, fence: lease.fencingToken };
    assert.throws(() => new JobStore({ stateRoot: repairRoot, faults: { afterIdempotentMutation: true } })
      .requestRepair("job-001", request), /injected failure/);
    const record = atomicMutation(repairRoot, "repair");
    assert.equal(record.payload.effect.type, "repair_requested");
    assert.deepEqual(new JobStore({ stateRoot: repairRoot }).requestRepair("job-001", request), record.payload.idempotency.result);
    assert.equal(atomicMutation(repairRoot, "repair").payload.effect.type, "repair_requested");
  } finally { cleanup(repairRoot); }

  const cancellationRoot = stateRoot();
  try {
    const store = createJob(cancellationRoot);
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
    const intentRequest = { reason: "operator_requested", idempotencyKey: "cancel-intent-001", fence: lease.fencingToken };
    assert.throws(() => new JobStore({ stateRoot: cancellationRoot, faults: { afterIdempotentMutation: true } })
      .beginCancellation("job-001", intentRequest), /injected failure/);
    const intentRecord = atomicMutation(cancellationRoot, "cancellation_intent");
    const resumed = new JobStore({ stateRoot: cancellationRoot });
    const intent = resumed.beginCancellation("job-001", intentRequest);
    assert.deepEqual(intent, intentRecord.payload.idempotency.result);
    assert.equal(atomicMutation(cancellationRoot, "cancellation_intent").payload.effect.type, "cancellation_intent");
    const acknowledgement = { expectedCancellationDigest: intent.cancellationDigest, idempotencyKey: "cancel-ack-001", fence: lease.fencingToken };
    assert.throws(() => new JobStore({ stateRoot: cancellationRoot, faults: { afterIdempotentMutation: true } })
      .acknowledgeCancellation("job-001", acknowledgement), /injected failure/);
    const acknowledgementRecord = atomicMutation(cancellationRoot, "cancellation_acknowledgement");
    assert.equal(acknowledgementRecord.payload.effect.type, "cancellation_acknowledged");
    assert.deepEqual(new JobStore({ stateRoot: cancellationRoot }).acknowledgeCancellation("job-001", acknowledgement), acknowledgementRecord.payload.idempotency.result);
    assert.equal(atomicMutation(cancellationRoot, "cancellation_acknowledgement").payload.effect.type, "cancellation_acknowledged");
    assert.equal(new JobStore({ stateRoot: cancellationRoot }).readJob("job-001").state, "cancelled");
  } finally { cleanup(cancellationRoot); }
});

test("a fully validated journal tail recovers an interrupted snapshot replace without duplicating its receipt", () => {
  const root = stateRoot();
  try {
    const store = createJob(root);
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
    moveToCandidate(store, "job-001", lease.fencingToken);
    const request = collection("job-001", "accepted", "collect-001");
    assert.throws(() => new JobStore({ stateRoot: root, faults: { afterJournal: true } })
      .disposeCandidate("job-001", { collection: request, fence: lease.fencingToken }), /injected failure/);
    const record = atomicMutation(root, "collection");
    assert.equal(record.payload.effect.type, "collection");
    assert.deepEqual(record.payload.idempotency.result, { jobId: "job-001", state: "accepted", cursor: 0 });
    const recovered = new JobStore({ stateRoot: root }).disposeCandidate("job-001", {
      collection: request, fence: lease.fencingToken
    });
    assert.deepEqual(recovered, { jobId: "job-001", state: "accepted", cursor: 0 });
    assert.equal(new JobStore({ stateRoot: root }).readJob("job-001").state, "accepted");
    assert.equal(atomicMutation(root, "collection").payload.idempotency.key, request.idempotencyKey);
  } finally { cleanup(root); }
});

test("fencing, reservation, and cross-instance lease ownership reject old or competing owners", () => {
  const root = stateRoot();
  try {
    let now = 1_000;
    const one = new JobStore({ stateRoot: root, now: () => now });
    one.submit({ job: job(), admission: admission(root), idempotencyKey: "submit-001" });
    const two = new JobStore({ stateRoot: root, now: () => now });
    assert.throws(() => two.submit({ job: job("job-002"), admission: admission(root), idempotencyKey: "submit-002" }), /reservation/);
    const first = one.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 10 });
    assert.throws(() => two.acquireExecutionLease("job-001", { ownerId: "owner-002", durationMs: 10 }), LeaseConflictError);
    one.transition("job-001", "preflighting", { fence: first.fencingToken });
    now += 11;
    assert.throws(() => two.acquireExecutionLease("job-001", { ownerId: "owner-002", durationMs: 10 }), /priorOwnerProofDigest/);
    const second = two.acquireExecutionLease("job-001", { ownerId: "owner-002", durationMs: 10, priorOwnerProofDigest: digest });
    assert.equal(second.fencingToken, first.fencingToken + 1);
    assert.equal(one.readStatus("job-001").job.state, "recovery_required", "a stale local fence never reports live execution");
    assert.throws(() => one.appendEvent("job-001", event("job-001", first.fencingToken, 1), { fence: first.fencingToken }), /fence/);
    two.appendEvent("job-001", event("job-001", second.fencingToken, 1), { fence: second.fencingToken });
    assert.throws(() => two.appendEvent("job-001", event("job-001", second.fencingToken, 3, 2), { fence: second.fencingToken }), /cursor/);
    assert.throws(() => two.readStatus("job-001", { afterCursor: 2 }), /cursor/);
    assert.equal(two.readStatus("job-001", { afterCursor: 0 }).events.length, 1);
  } finally { cleanup(root); }
});

test("rejects recovery bypasses and terminal mutations, binds candidate preconditions, and preserves attempt order", () => {
  const root = stateRoot();
  try {
    const store = createJob(root);
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
    assert.throws(() => store.transition("job-001", "running", { fence: lease.fencingToken, allowRecovery: true }), /recovery_required/);
    assert.throws(() => store.recordAttempt("job-001", { ...attempt("job-001"), number: 2 }, { fence: lease.fencingToken }), /number/);
    store.recordAttempt("job-001", attempt("job-001"), { fence: lease.fencingToken });
    assert.throws(() => store.recordAttempt("job-001", { ...attempt("job-001"), profileDigest: digestB }, { fence: lease.fencingToken }), /profileDigest/);
    moveToCandidate(store, "job-001", lease.fencingToken);
    assert.throws(() => store.disposeCandidate("job-001", {
      collection: { ...collection("job-001", "accepted", "collect-001"), expectedCandidateDigest: digestB }, fence: lease.fencingToken
    }), /candidate/);
    const accepted = collection("job-001", "accepted", "collect-001");
    store.disposeCandidate("job-001", { collection: accepted, fence: lease.fencingToken });
    assert.equal(store.localLeases.has("job-001"), false, "terminal collection also clears the local lease cache");
    const journalPath = join(root, "jobs", "job-001", "journal.ndjson");
    const journalBefore = readFileSync(journalPath, "utf8");
    assert.throws(() => store.cancel("job-001", { reason: "operator_requested", idempotencyKey: "cancel-999", fence: lease.fencingToken }), /terminal/);
    assert.equal(readFileSync(journalPath, "utf8"), journalBefore, "terminal rejection must not append evidence");
    assert.deepEqual(store.disposeCandidate("job-001", { collection: accepted, fence: lease.fencingToken }), { jobId: "job-001", state: "accepted", cursor: 0 });
  } finally { cleanup(root); }
});

test("archives repaired candidates and never reports active restart status as running", () => {
  const root = stateRoot();
  try {
    const store = createJob(root);
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
    moveToCandidate(store, "job-001", lease.fencingToken);
    store.requestRepair("job-001", { idempotencyKey: "repair-001", findingsDigest: digest,
      expectedAttemptId: "attempt-001", expectedCandidateDigest: digest, fence: lease.fencingToken });
    assert.throws(() => store.disposeCandidate("job-001", {
      collection: collection("job-001", "accepted", "collect-001"), fence: lease.fencingToken
    }), /candidate_ready/);
    store.transition("job-001", "preflighting", { fence: lease.fencingToken });
    store.transition("job-001", "starting", { fence: lease.fencingToken });
    store.transition("job-001", "running", { fence: lease.fencingToken });
    const nextAttempt = { ...attempt("job-001"), attemptId: "attempt-002", number: 2, state: "queued" };
    store.recordAttempt("job-001", nextAttempt, { fence: lease.fencingToken });
    const nextCandidate = { ...candidate("job-001"), candidateId: "candidate-002", attemptId: "attempt-002", manifestDigest: digestB };
    store.bindEvidence("job-001", { candidate: nextCandidate, grantDigest: digest, receiptDigest: digestB, fence: lease.fencingToken });
    store.transition("job-001", "candidate_ready", { fence: lease.fencingToken });
    assert.throws(() => store.disposeCandidate("job-001", {
      collection: collection("job-001", "accepted", "collect-002"), fence: lease.fencingToken
    }), /bound candidate/);
    const restarting = new JobStore({ stateRoot: root });
    assert.equal(restarting.openJob("job-001").state, "recovery_required", "candidate restart requires custody revalidation");
    assert.equal(restarting.readStatus("job-001").job.state, "recovery_required");
  } finally { cleanup(root); }
});

test("collection repair archives the candidate once, supports repair continuation, and permits a new attempt", () => {
  const root = stateRoot();
  try {
    const store = createJob(root);
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
    moveToCandidate(store, "job-001", lease.fencingToken);
    const repairCollection = collection("job-001", "repair_requested", "collect-001");
    store.disposeCandidate("job-001", { collection: repairCollection, fence: lease.fencingToken });
    const continuation = { idempotencyKey: "repair-001", findingsDigest: digest,
      expectedAttemptId: "attempt-001", expectedCandidateDigest: digest, fence: lease.fencingToken };
    assert.deepEqual(store.requestRepair("job-001", continuation), store.requestRepair("job-001", continuation));
    store.transition("job-001", "preflighting", { fence: lease.fencingToken });
    store.transition("job-001", "starting", { fence: lease.fencingToken });
    store.transition("job-001", "running", { fence: lease.fencingToken });
    store.recordAttempt("job-001", { ...attempt("job-001"), attemptId: "attempt-002", number: 2 }, { fence: lease.fencingToken });
    store.bindEvidence("job-001", { candidate: { ...candidate("job-001"), candidateId: "candidate-002", attemptId: "attempt-002", manifestDigest: digestB },
      grantDigest: digest, receiptDigest: digestB, fence: lease.fencingToken });
    store.transition("job-001", "candidate_ready", { fence: lease.fencingToken });
    assert.throws(() => store.disposeCandidate("job-001", {
      collection: { ...collection("job-001", "accepted", "collect-002"), expectedAttemptId: "attempt-001", expectedCandidateDigest: digest },
      fence: lease.fencingToken
    }), /bound candidate/);
  } finally { cleanup(root); }
});

test("detects journal and snapshot tampering without overwriting evidence", () => {
  const root = stateRoot();
  try {
    const store = createJob(root);
    const jobDir = join(root, "jobs", "job-001");
    const snapshotPath = join(jobDir, "snapshot.json");
    const original = readFileSync(snapshotPath, "utf8");
    writeFileSync(snapshotPath, original.replace('"state":"queued"', '"state":"accepted"'), "utf8");
    assert.throws(() => new JobStore({ stateRoot: root }).readJob("job-001"), IntegrityError);
    assert.match(readFileSync(snapshotPath, "utf8"), /accepted/);
  } finally { cleanup(root); }

  const truncationRoot = stateRoot();
  try {
    const store = createJob(truncationRoot);
    const journal = join(truncationRoot, "jobs", "job-001", "journal.ndjson");
    writeFileSync(journal, readFileSync(journal, "utf8").slice(0, -4), "utf8");
    assert.throws(() => new JobStore({ stateRoot: truncationRoot }).readJob("job-001"), IntegrityError);
  } finally { cleanup(truncationRoot); }

  const faultRoot = stateRoot();
  try {
    createJob(faultRoot);
    assert.throws(() => new JobStore({ stateRoot: faultRoot, faults: { afterJournal: true } })
      .acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 }), /injected failure/);
    assert.throws(() => new JobStore({ stateRoot: faultRoot }).readStatus("job-001"), /pending journal tail/,
      "status observation must not replay a possibly in-flight writer tail");
    const recovered = new JobStore({ stateRoot: faultRoot }).readVerified("job-001");
    assert.equal(recovered.job.state, "queued");
    assert.equal(recovered.lease.ownerId, "owner-001", "the validated journal tail restores the interrupted lease mutation");
  } finally { cleanup(faultRoot); }
});

test("redacts persisted state and accepts only valid optional normalized usage and cost", () => {
  const root = stateRoot();
  try {
    const store = createJob(root);
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
    store.appendEvent("job-001", {
      ...event("job-001", lease.fencingToken, 1),
      data: { authorization: "Bearer SYNTHETIC_SECRET_DO_NOT_PERSIST", endpoint: "https://user:password@example.test" }
    }, { fence: lease.fencingToken });
    store.recordUsage("job-001", {
      usage: { contractVersion: CONTRACT_VERSIONS.usage, inputTokens: 2, outputTokens: 3, totalTokens: 5 },
      cost: { contractVersion: CONTRACT_VERSIONS.cost, currency: "USD", amountMicros: 7, source: "host_measured" },
      fence: lease.fencingToken
    });
    assert.equal(store.recordUsage("job-001", { usage: null, cost: null, fence: lease.fencingToken }).usage, undefined);
    assert.throws(() => store.recordUsage("job-001", { usage: { contractVersion: CONTRACT_VERSIONS.usage, inputTokens: 1, outputTokens: 1, totalTokens: 3 }, fence: lease.fencingToken }), /totalTokens/);
    const contents = readdirSync(join(root, "jobs", "job-001")).map((file) => readFileSync(join(root, "jobs", "job-001", file), "utf8")).join("\n");
    assert.doesNotMatch(contents, /SYNTHETIC_SECRET_DO_NOT_PERSIST|password|authorization/);
  } finally { cleanup(root); }
});

test("state-root-global active claims reject ancestor overlap but allow independent-store siblings", () => {
  const root = stateRoot();
  try {
    const parent = join(root, "worktrees", "alpha");
    const first = new JobStore({ stateRoot: root });
    const claim = first.reserve(parent, "job-001");
    assert.equal(claim.jobId, "job-001");
    assert.equal(typeof claim.canonicalDestination, "string");
    const second = new JobStore({ stateRoot: root });
    assert.throws(() => second.reserve(join(parent, "child"), "job-002"), LeaseConflictError);
    assert.throws(() => second.reserve(join(root, "worktrees"), "job-003"), LeaseConflictError);
    assert.equal(second.reserve(join(root, "worktrees", "beta"), "job-004").jobId, "job-004");
    assert.equal(first.reserve(parent.replaceAll("\\", "/").toUpperCase(), "job-001").jobId, "job-001");
  } finally { cleanup(root); }
});

test("hostile or stale global claim state fails closed instead of silently freeing a destination", () => {
  const root = stateRoot();
  try {
    const first = new JobStore({ stateRoot: root });
    first.reserve(join(root, "worktrees", "alpha"), "job-001");
    const claimPath = join(root, "claims", readdirSync(join(root, "claims"))[0]);
    writeFileSync(claimPath, '{"tampered":true}\n', "utf8");
    assert.throws(() => new JobStore({ stateRoot: root }).reserve(join(root, "worktrees", "beta"), "job-002"), IntegrityError);
  } finally { cleanup(root); }

  const raceRoot = stateRoot();
  try {
    new JobStore({ stateRoot: raceRoot });
    const lock = join(raceRoot, "locks", "reservation-global.lock");
    const descriptor = openSync(lock, "wx", 0o600);
    closeSync(descriptor);
    assert.throws(() => new JobStore({ stateRoot: raceRoot }).reserve(join(raceRoot, "worktrees", "alpha"), "job-001"), LeaseConflictError);
  } finally { cleanup(raceRoot); }
});

test("terminal release retains immutable evidence, retires only the active claim, and is retry-safe", () => {
  const root = stateRoot();
  try {
    const store = createJob(root);
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
    moveToCandidate(store, "job-001", lease.fencingToken);
    store.disposeCandidate("job-001", { collection: collection("job-001", "accepted", "collect-001"), fence: lease.fencingToken });
    const released = store.releaseReservation("job-001");
    assert.equal(released.status, "released");
    assert.deepEqual(store.releaseReservation("job-001"), released);
    assert.equal(readdirSync(join(root, "claims")).length, 0);
    assert.equal(readdirSync(join(root, "releases")).length, 1);
    assert.equal(readdirSync(join(root, "reservations")).length, 1, "release keeps snapshot-bound immutable evidence");
    assert.equal(store.readJob("job-001").state, "accepted");
    assert.equal(new JobStore({ stateRoot: root }).reserve(admission(root).destinationRoot, "job-002").jobId, "job-002");
  } finally { cleanup(root); }
});

test("release receipt persistence never frees a claim before atomic retirement", () => {
  const root = stateRoot();
  try {
    const store = createJob(root);
    assert.throws(() => store.releaseReservation("job-001"), /terminal/);
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1000 });
    moveToCandidate(store, "job-001", lease.fencingToken);
    store.disposeCandidate("job-001", { collection: collection("job-001", "rejected", "collect-001"), fence: lease.fencingToken });
    assert.throws(() => new JobStore({ stateRoot: root, faults: { afterReleaseReceipt: true } }).releaseReservation("job-001"), /injected failure/);
    assert.equal(readdirSync(join(root, "claims")).length, 1, "receipt-before-retirement keeps the claim active");
    assert.throws(() => new JobStore({ stateRoot: root }).reserve(admission(root).destinationRoot, "job-002"), LeaseConflictError);
    assert.equal(store.releaseReservation("job-001").status, "released");
  } finally { cleanup(root); }
});

test("an exact retry alone can recover reservation evidence left pending before active-claim creation", () => {
  const root = stateRoot();
  try {
    const alpha = join(root, "worktrees", "alpha");
    assert.throws(() => new JobStore({ stateRoot: root, faults: { afterReservationEvidence: true } }).reserve(alpha, "job-001"), /injected failure/);
    assert.throws(() => new JobStore({ stateRoot: root }).reserve(join(root, "worktrees", "beta"), "job-002"), IntegrityError);
    assert.equal(new JobStore({ stateRoot: root }).reserve(alpha, "job-001").jobId, "job-001");
    assert.equal(readdirSync(join(root, "claims")).length, 1);
    assert.equal(new JobStore({ stateRoot: root }).reserve(join(root, "worktrees", "beta"), "job-002").jobId, "job-002");
  } finally { cleanup(root); }
});

test("one job cannot reserve a second destination and orphan release evidence fails closed", () => {
  const root = stateRoot();
  try {
    const store = new JobStore({ stateRoot: root });
    store.reserve(join(root, "worktrees", "alpha"), "job-001");
    assert.throws(() => new JobStore({ stateRoot: root }).reserve(join(root, "worktrees", "beta"), "job-001"), LeaseConflictError);
    writeFileSync(join(root, "releases", "job-999.json"), '{"junk":true}\n', "utf8");
    assert.throws(() => new JobStore({ stateRoot: root }).reserve(join(root, "worktrees", "beta"), "job-002"), IntegrityError);
  } finally { cleanup(root); }

  const retiredRoot = stateRoot();
  try {
    new JobStore({ stateRoot: retiredRoot }).reserve(join(retiredRoot, "worktrees", "alpha"), "job-001");
    writeFileSync(join(retiredRoot, "retired-claims", "junk.json"), '{"junk":true}\n', "utf8");
    assert.throws(() => new JobStore({ stateRoot: retiredRoot }).reserve(join(retiredRoot, "worktrees", "beta"), "job-002"), IntegrityError);
  } finally { cleanup(retiredRoot); }
});

test("durable execution slots renew without rotating fences, fail closed after expiry, and release with a receipt", () => {
  let now = 1_000; const root = stateRoot();
  try {
    const store = new JobStore({ stateRoot: root, now: () => now });
    store.submit({ job: job("job-001"), admission: admission(root, "one"), idempotencyKey: "submit-one" });
    store.submit({ job: job("job-002"), admission: admission(root, "two"), idempotencyKey: "submit-two" });
    const firstLease = store.acquireExecutionLease("job-001", { ownerId: "owner-one", durationMs: 100 });
    const slot = store.acquireExecutionSlot("job-001", { ownerId: "owner-one", fencingToken: firstLease.fencingToken, profileDigest: digest, expiresAt: firstLease.expiresAt });
    now = 1_050;
    const renewedLease = store.renewExecutionLease("job-001", { ownerId: "owner-one", fencingToken: firstLease.fencingToken, durationMs: 100 });
    const renewedSlot = store.renewExecutionSlot("job-001", { ownerId: "owner-one", fencingToken: renewedLease.fencingToken, profileDigest: digest, expiresAt: renewedLease.expiresAt });
    assert.equal(renewedLease.fencingToken, firstLease.fencingToken);
    assert.equal(renewedSlot.fencingToken, slot.fencingToken);
    now = renewedSlot.expiresAt + 1;
    const secondLease = store.acquireExecutionLease("job-002", { ownerId: "owner-two", durationMs: 100 });
    assert.throws(() => store.acquireExecutionSlot("job-002", { ownerId: "owner-two", fencingToken: secondLease.fencingToken, profileDigest: digest, expiresAt: secondLease.expiresAt }), /priorSlotProofDigest|expired/i);
    assert.equal(store.releaseExecutionSlot("job-001", { ownerId: "owner-one", fencingToken: renewedLease.fencingToken, profileDigest: digest }), true);
    assert.equal(readdirSync(join(root, "slot-releases")).length, 1, "slot release is durably receipted before freeing capacity");
    assert.equal(store.acquireExecutionSlot("job-002", { ownerId: "owner-two", fencingToken: secondLease.fencingToken, profileDigest: digest, expiresAt: secondLease.expiresAt }).jobId, "job-002");
  } finally { cleanup(root); }
});

test("one job and fence can release distinct attempt slots without overwriting immutable receipts", () => {
  let now = 3_000; const root = stateRoot();
  try {
    const store = new JobStore({ stateRoot: root, now: () => now });
    store.submit({ job: job(), admission: admission(root), idempotencyKey: "submit-001" });
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-one", durationMs: 1_000 });
    const first = store.acquireExecutionSlot("job-001", { ownerId: "owner-one", fencingToken: lease.fencingToken, profileDigest: digest, expiresAt: now + 100 });
    assert.equal(store.releaseExecutionSlot("job-001", { ownerId: "owner-one", fencingToken: lease.fencingToken, profileDigest: digest }), true);

    now += 1;
    const second = store.acquireExecutionSlot("job-001", { ownerId: "owner-one", fencingToken: lease.fencingToken, profileDigest: digest, expiresAt: now + 200 });
    assert.notEqual(second.digest, first.digest, "each logical attempt slot has distinct immutable evidence");
    assert.equal(store.releaseExecutionSlot("job-001", { ownerId: "owner-one", fencingToken: lease.fencingToken, profileDigest: digest }), true);
    assert.equal(readdirSync(join(root, "slot-releases")).length, 2, "both attempt release receipts are retained");
    assert.equal(store.releaseExecutionSlot("job-001", { ownerId: "owner-one", fencingToken: lease.fencingToken, profileDigest: digest }), true, "release retry recognizes verified prior receipts");
  } finally { cleanup(root); }
});

test("expired exact fences can journal recovery but cannot overwrite a rotated owner", () => {
  let now = 2_000; const root = stateRoot();
  try {
    const store = new JobStore({ stateRoot: root, now: () => now });
    store.submit({ job: job(), admission: admission(root), idempotencyKey: "submit-001" });
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-one", durationMs: 10 });
    store.transition("job-001", "preflighting", { fence: lease.fencingToken });
    now = 2_011;
    assert.equal(store.recordRecovery("job-001", { ownerId: "owner-one", fencingToken: lease.fencingToken, code: "lease_renewal_failed" }).state, "recovery_required");
    assert.equal(new JobStore({ stateRoot: root, now: () => now }).readJob("job-001").state, "recovery_required");
  } finally { cleanup(root); }
});
