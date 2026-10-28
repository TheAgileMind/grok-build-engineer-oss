import assert from "node:assert/strict";
import test from "node:test";

import {
  CONTRACT_VERSIONS,
  assertAbsoluteStateRoot,
  validateCandidate,
  validateCancellation,
  validateCollection,
  validateError,
  validateEvent,
  validateGrant,
  validateJobAuthority,
  validateJob,
  validateNormalizedCost,
  validateNormalizedUsage,
  validateProfile,
  validateSubmission,
  validateValidation,
  validateAttempt,
  validateApprovalPacket,
  validateTaskPacket
} from "../src/contracts.mjs";
import { containsSecretValue, redactForBoundary, redactAndSerialize } from "../src/redaction.mjs";
import { assertApprovedPacket, secretFreeAuthorityRecord } from "../src/authority-safety.mjs";
import { packetDigest } from "../src/task-policy.mjs";

const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const jobAuthority = {
  contractVersion: CONTRACT_VERSIONS.jobAuthority, authorityId: "authority-001", runtimeId: "runtime-001",
  sourceSha: "a".repeat(40), dataClasses: ["synthetic_public"], provider: "xai", model: "grok-build",
  disclosure: "public synthetic only", costCeilingUsd: 1, validationCommands: ["npm test"],
  acceptanceCriteria: ["tests pass"], externalEffects: [], authorizationBasis: "user approved",
  expiresAt: "2026-08-24T00:00:00.000Z", receiptDigest: digest
};

const submission = {
  contractVersion: CONTRACT_VERSIONS.submission,
  submissionId: "submission-001",
  mode: "new",
  idempotencyKey: "submit-001",
  profileId: "profile-local",
  continuation: null,
  source: {
    repositoryRoot: "C:\\work\\source",
    sourceSha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    destinationRoot: "C:\\work\\destination",
    branchPolicy: "unique_mission_branch"
  },
  task: {
    title: "Implement the bounded change",
    instructions: "Treat this as inert task data.",
    dataClass: "synthetic_public",
    contextPaths: ["src/index.mjs"]
  },
  findings: []
};

test("accepts valid versioned contract records", () => {
  assert.equal(validateJobAuthority(jobAuthority).model, "grok-build");
  assert.equal(validateJobAuthority({ ...jobAuthority, model: "grok-4.6" }).model, "grok-4.6");
  assert.deepEqual(validateSubmission(submission), submission);
  assert.equal(validateProfile({
    contractVersion: CONTRACT_VERSIONS.profile, profileId: "profile-local", name: "Local",
    status: "approved", capabilityDigest: digest,
    limits: { initializationTimeoutMs: 1_000, idleTimeoutMs: 2_000, overallTimeoutMs: 3_000,
      cancellationTimeoutMs: 1_000, maximumFrameBytes: 1_024, maximumEventBytes: 1_024,
      maximumEventsPerMinute: 100, maximumActiveJobs: 1 }
  }).profileId, "profile-local");
  assert.equal(validateGrant({
    contractVersion: CONTRACT_VERSIONS.grant, grantId: "grant-001", jobId: "job-001",
    worktreeCustodyDigest: digest, profileDigest: digest, operation: "network_read", service: "example_test",
    direction: "egress", dataClasses: ["synthetic_public"], sourcePaths: ["src/index.mjs"],
    recipients: ["recipient-001"], endpoints: ["https://example.test"], payloadBoundary: "trusted_host_mediation",
    expiresAt: "2026-08-14T00:00:00.000Z", nonce: "nonce-001", authorityClass: "local_policy",
    issuer: "local_policy", receiptDigest: null
  }).grantId, "grant-001");
  assert.equal(validateJob({
    contractVersion: CONTRACT_VERSIONS.job, jobId: "job-001", submissionId: "submission-001",
    state: "queued", profileDigest: digest, sourceCustodyDigest: digest, eventCursor: 0
  }).jobId, "job-001");
  assert.equal(validateAttempt({
    contractVersion: CONTRACT_VERSIONS.attempt, attemptId: "attempt-001", jobId: "job-001",
    number: 1, state: "queued", profileDigest: digest
  }).attemptId, "attempt-001");
  assert.equal(validateEvent({
    contractVersion: CONTRACT_VERSIONS.event, eventId: "event-001", jobId: "job-001", attemptId: "attempt-001",
    fencingToken: 1, nativeSessionId: "session-001", requestId: "request-001", cursor: 1, sequence: 1,
    kind: "progress", occurredAt: "2026-08-14T00:00:00.000Z",
    data: { message: "working" }
  }).eventId, "event-001");
  assert.equal(validateCandidate({
    contractVersion: CONTRACT_VERSIONS.candidate, candidateId: "candidate-001", jobId: "job-001",
    attemptId: "attempt-001", manifestDigest: digest, createdAt: "2026-08-14T00:00:00.000Z", changedPaths: ["src/index.mjs"]
  }).candidateId, "candidate-001");
  assert.equal(validateValidation({
    contractVersion: CONTRACT_VERSIONS.validation, validationId: "validation-001", candidateId: "candidate-001",
    disposition: "passed", evidenceDigest: digest, completedAt: "2026-08-14T00:00:00.000Z"
  }).validationId, "validation-001");
  assert.equal(validateCollection({
    contractVersion: CONTRACT_VERSIONS.collection, collectionId: "collection-001", jobId: "job-001",
    expectedAttemptId: "attempt-001", expectedCandidateDigest: digest, disposition: "accepted",
    validationEvidenceRef: "validation-001", validationEvidenceDigest: digest, idempotencyKey: "collect-001"
  }).collectionId, "collection-001");
  assert.equal(validateCancellation({
    contractVersion: CONTRACT_VERSIONS.cancellation, cancellationId: "cancel-001", jobId: "job-001",
    reason: "operator_requested", idempotencyKey: "cancel-key-001"
  }).cancellationId, "cancel-001");
  assert.equal(validateError({
    contractVersion: CONTRACT_VERSIONS.error, code: "invalid_input", message: "Safe public message", retryable: false
  }).code, "invalid_input");
  assert.equal(validateNormalizedUsage({
    contractVersion: CONTRACT_VERSIONS.usage, inputTokens: 1, outputTokens: 2, totalTokens: 3
  }).totalTokens, 3);
  assert.equal(validateNormalizedCost({
    contractVersion: CONTRACT_VERSIONS.cost, currency: "USD", amountMicros: 10, source: "provider_reported"
  }).currency, "USD");
});

test("rejects unapproved xAI models", () => {
  assert.throws(() => validateJobAuthority({ ...jobAuthority, model: "grok-4.5" }), /job authority.model is invalid/);
});

test("rejects unknown, unsafe, excessively deep, and process-control input", () => {
  assert.throws(() => validateJobAuthority({ ...jobAuthority, provider: "custom" }), /provider/);
  assert.throws(() => validateJobAuthority({ ...jobAuthority, model: "grok-4.4" }), /model/);
  assert.throws(() => validateSubmission({ ...submission, unexpected: true }), /unsupported fields/);
  assert.throws(() => validateSubmission({ ...submission, contractVersion: "v1" }), /contractVersion/);
  assert.throws(() => validateSubmission({ ...submission, submissionId: "not valid" }), /identifier/);
  assert.throws(() => validateSubmission({ ...submission, source: { ...submission.source, repositoryRoot: "relative" } }), /absolute/);
  assert.throws(() => validateSubmission({ ...submission, task: { ...submission.task, executable: "grok" } }), /process-control/);
  assert.throws(() => validateSubmission({ ...submission, task: { ...submission.task, instructions: "x".repeat(16_385) } }), /maximum length/);
  assert.throws(() => validateEvent({
    contractVersion: CONTRACT_VERSIONS.event, eventId: "event-001", jobId: "job-001", attemptId: "attempt-001",
    fencingToken: 1, nativeSessionId: "session-001", requestId: "request-001", cursor: 1, sequence: 1,
    kind: "progress", occurredAt: "2026-08-14T00:00:00.000Z",
    data: { a: { b: { c: { d: { e: { f: { g: { h: { i: "too deep" } } } } } } } } }
  }), /maximum depth/);
  assert.throws(() => assertAbsoluteStateRoot("relative-state"), /absolute/);
  assert.equal(assertAbsoluteStateRoot("C:\\state\\grok-builder"), "C:\\state\\grok-builder");
});

test("binds repair, grants, collection, correlated events, and total record size", () => {
  const repair = {
    ...submission,
    submissionId: "submission-002",
    mode: "repair",
    continuation: { jobId: "job-001", expectedAttemptId: "attempt-001", expectedCandidateDigest: digest },
    findings: [{ code: "test_failure", message: "Fix the focused failing test." }]
  };
  assert.equal(validateSubmission(repair).mode, "repair");
  assert.throws(() => validateSubmission({ ...submission, continuation: repair.continuation }), /continuation/);
  assert.throws(() => validateSubmission({ ...submission, findings: repair.findings }), /findings/);
  assert.throws(() => validateSubmission({ ...repair, continuation: null }), /continuation/);
  assert.throws(() => validateSubmission({ ...repair, findings: [] }), /findings/);

  const humanGrant = {
    contractVersion: CONTRACT_VERSIONS.grant, grantId: "grant-002", jobId: "job-001",
    worktreeCustodyDigest: digest, profileDigest: digest, operation: "network_read", service: "example_test",
    direction: "egress", dataClasses: ["synthetic_public"], sourcePaths: ["src/index.mjs"],
    recipients: ["recipient-001"], endpoints: ["https://example.test"], payloadBoundary: "trusted_host_mediation",
    expiresAt: "2026-08-14T00:00:00.000Z", nonce: "nonce-002", authorityClass: "human_enforced",
    issuer: "human_approval_broker", receiptDigest: digest
  };
  assert.equal(validateGrant(humanGrant).authorityClass, "human_enforced");
  assert.throws(() => validateGrant({ ...humanGrant, receiptDigest: null }), /receiptDigest/);
  assert.throws(() => validateGrant({ ...humanGrant, issuer: "fixture" }), /issuer/);

  const correlatedEvent = {
    contractVersion: CONTRACT_VERSIONS.event, eventId: "event-002", jobId: "job-001", attemptId: "attempt-001",
    fencingToken: 2, nativeSessionId: "session-001", requestId: "request-002", cursor: 2, sequence: 2,
    kind: "candidate_ready", occurredAt: "2026-08-14T00:00:00.000Z", data: { summary: "candidate data only" }
  };
  assert.equal(validateEvent(correlatedEvent).fencingToken, 2);
  assert.throws(() => validateEvent({ ...correlatedEvent, kind: "accepted" }), /kind/);
  assert.throws(() => validateEvent({ ...correlatedEvent, data: { a: "x".repeat(14_000), b: "x".repeat(14_000), c: "x".repeat(14_000), d: "x".repeat(14_000), e: "x".repeat(14_000) } }), /serialized size/);
});

test("redacts secret-shaped diagnostics before a serialization boundary", () => {
  const redacted = redactForBoundary({
    capabilityName: "read_repository", capabilityDigest: digest,
    authorization: "Bearer abcdefghijklmnop", nested: { refreshToken: "very-secret" },
    endpoint: "https://user:password@example.test/path",
    chunks: ["Bearer ", "abcdefghijklmnop"],
    provider: "JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.signaturevalue1234 and ghp_abcdefghijklmnopqrstuvwxyz1234567890",
    labeled: "api_key=AIzaSyA1234567890abcdefghijk",
    failure: { name: "Error", message: "Basic dXNlcjpwYXNz", stack: "private stack" }
  });
  const serialized = redactAndSerialize(redacted);
  assert.equal("authorization" in redacted, false);
  assert.equal("refreshToken" in redacted.nested, false);
  assert.equal(redacted.endpoint, "[REDACTED_CREDENTIAL_URL]");
  assert.deepEqual(redacted.chunks, ["[REDACTED]"]);
  assert.equal(redacted.failure, "[REDACTED_EXCEPTION]");
  assert.match(serialized, /read_repository/);
  assert.match(serialized, /sha256:aaaaaaaa/);
  assert.doesNotMatch(serialized, /abcdefghijklmnop|very-secret|password|private stack|dXNlcjpwYXNz|eyJhbGci|ghp_abc|AIzaSy/);
});

test("binds the complete approval object to the canonical task packet", () => {
  const packet = {
    contractVersion: CONTRACT_VERSIONS.taskPacket, taskRunId: "run-001", requestId: "request-001", mode: "implementation", delivery: "artifact_only",
    repositoryRoot: "C:/repo", worktree: "C:/repo/.worktrees/run-001", sourceSha: "a".repeat(40), stateRoot: "C:/state",
    task: { title: "Bounded task", instructions: "Do the approved work.", contextPaths: ["src"] },
    policy: { allowedPaths: ["src/**"], allowedCommands: ["node test"], allowedEnvironment: [], network: "none", tools: [], timeouts: { startMs: 1, turnMs: 1, idleMs: 1, cancelMs: 1 }, repairBudget: 0 },
    provider: { executable: "C:/grok.exe", model: "grok-build" }, continuation: null, findingsDigest: null,
    approval: { contractVersion: CONTRACT_VERSIONS.approvalPacket, approvalId: "approval-001", packetDigest: "sha256:" + "0".repeat(64), issuedAt: "2026-08-25T00:00:00.000Z", expiresAt: "2026-08-27T00:00:00.000Z", approvedBy: "owner", authorizationStatement: "Approve this exact packet." }
  };
  packet.approval.packetDigest = packetDigest(packet);
  assert.equal(validateApprovalPacket(packet.approval).authorizationStatement, "Approve this exact packet.");
  for (const field of ["contractVersion", "approvalId", "packetDigest", "issuedAt", "expiresAt", "approvedBy", "authorizationStatement"]) {
    const incomplete = structuredClone(packet);
    delete incomplete.approval[field];
    assert.throws(() => validateTaskPacket(incomplete), /approval|missing|unsupported/i, field);
  }
  assert.doesNotThrow(() => assertApprovedPacket({ packet, approval: structuredClone(packet.approval), digest: packet.approval.packetDigest, now: new Date("2026-08-26T00:00:00.000Z") }));
  for (const field of ["authorizationStatement", "expiresAt", "approvalId"]) {
    const altered = structuredClone(packet.approval); altered[field] = field === "expiresAt" ? "2026-08-28T00:00:00.000Z" : `${altered[field]}-altered`;
    assert.throws(() => assertApprovedPacket({ packet, approval: altered, digest: packet.approval.packetDigest, now: new Date("2026-08-26T00:00:00.000Z") }), /approval|packet/i, field);
  }
  for (const alter of [
    (value) => { value.sourceSha = "b".repeat(40); },
    (value) => { value.worktree = "C:/repo/.worktrees/other"; },
    (value) => { value.provider.model = "grok-4.6"; },
    (value) => { value.policy.allowedPaths = ["test/**"]; }
  ]) {
    const alteredPacket = structuredClone(packet); alter(alteredPacket);
    assert.throws(() => assertApprovedPacket({ packet: alteredPacket, approval: packet.approval, digest: packet.approval.packetDigest, now: new Date("2026-08-26T00:00:00.000Z") }), /digest|scope/i);
  }
});

test("authority filtering shares redaction detection for provider credentials but permits SHA digests", () => {
  const secretValues = [
    "sk-test1234567890123456",
    "github_pat_1234567890123456789012",
    "xoxb-1234567890",
    "AIzaSyA1234567890abcdefghijkl",
    "AKIAABCDEFGHIJKLMNOP",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.signaturevalue1234"
  ];
  for (const value of secretValues) {
    assert.equal(containsSecretValue(value), true, value);
    assert.equal(secretFreeAuthorityRecord(value), false, value);
  }
  const sha = `sha256:${"a".repeat(64)}`;
  assert.equal(containsSecretValue(sha), false);
  assert.equal(secretFreeAuthorityRecord(sha), true);
});
