import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";

import { createJobService } from "../src/job-service.mjs";
import { CONTRACT_VERSIONS } from "../src/contracts.mjs";
import { JobStore } from "../src/job-store.mjs";
import { digestOf } from "../src/worktree-custody.mjs";
import { fakeAcpAgent } from "./fake-acp-agent.mjs";
import { buildProfileAttestation, getCapabilityProfile } from "../src/profiles.mjs";
import { createHeadlessSessionAdapter } from "../src/headless-session.mjs";

const digest = (letter = "a") => `sha256:${letter.repeat(64)}`;
const digestText = (value) => `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
const sourceSha = "a".repeat(40);
function submission(overrides = {}) {
  return { contractVersion: CONTRACT_VERSIONS.submission, submissionId: "submission-001", mode: "new", idempotencyKey: "submit-001", profileId: "hermetic", continuation: null,
    source: { repositoryRoot: "C:\\source", sourceSha, destinationRoot: "C:\\worktrees\\job-001", branchPolicy: "detached" },
    task: { title: "Bounded test", instructions: "Make the local change.", dataClass: "internal", contextPaths: ["src/example.mjs"] }, findings: [], ...overrides };
}
function harness({
  delayed = true,
  acknowledge = async () => true,
  runtimeAcknowledge = null,
  root: suppliedRoot = null,
  store: suppliedStore = null,
  ownerId = undefined,
  authority: suppliedAuthority = null,
  profileFactory: suppliedProfileFactory = null,
  custody: suppliedCustody = null,
  acpFactory: suppliedAcpFactory = null,
  executionAdapterFactory = null,
  transport = null,
  timers: suppliedTimers = null,
  leaseDurationMs = undefined,
  heartbeatMs = undefined
} = {}) {
  const ownsRoot = suppliedRoot === null && suppliedStore === null;
  const root = suppliedRoot ?? suppliedStore?.stateRoot ?? mkdtempSync(join(tmpdir(), "grok-job-service-"));
  const store = suppliedStore ?? new JobStore({ stateRoot: root });
  let finish; const done = new Promise((resolve) => { finish = resolve; });
  let inventoryVersion = 1, starts = 0, prompts = 0, cancelCalls = 0; const loadedSessions = [], startedInputs = [], intervals = new Set();
  const profile = { profileId: "hermetic", profileDigest: digest("b"), attestation: { profileId: "hermetic", profileDigest: digest("b"), fingerprint: digest("8") }, inspection: {} };
  const custody = suppliedCustody ?? {
    admit({ jobId, source, stateRoot }) { return { jobId, sourceSha: source.sourceSha, sourceCustodyDigest: digest("c"), destinationRoot: source.destinationRoot, stateRoot, branchPolicy: source.branchPolicy, sourceRoot: source.repositoryRoot }; },
    reserve(admission, currentStore) { return { ...admission, reservation: currentStore.reserve(admission.destinationRoot, admission.jobId) }; },
    create(admission) { return { ...admission, linkedWorktree: true, destinationRoot: admission.destinationRoot, worktreeCustodyDigest: digest("d") }; },
    inventory() { return { inventoryDigest: digest(String(inventoryVersion)), protectedGitMetadata: { head: digest("e") }, entries: [{ path: "tracked.mjs", kind: "tracked" }, { path: "ignored.tmp", kind: "ignored" }, { path: "untracked.txt", kind: "untracked" }] }; },
    revalidate(_custody, expected = null) { const fresh = this.inventory(); if (expected && fresh.inventoryDigest !== expected.inventoryDigest) throw new Error("inventory drift"); return fresh; }
  };
  const timers = suppliedTimers ?? {
    setInterval(fn, milliseconds) { const handle = setInterval(fn, milliseconds); intervals.add(handle); return handle; },
    clearInterval(handle) { clearInterval(handle); intervals.delete(handle); }
  };
  const authority = suppliedAuthority ?? (() => ({ allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }));
  const profileFactory = suppliedProfileFactory ?? (() => structuredClone(profile));
  const defaultAcpFactory = (hooks) => ({
    async start(input) {
      starts += 1; loadedSessions.push(input.nativeSessionId ?? null); startedInputs.push(structuredClone(input));
      await hooks.onSessionBound({ nativeSessionId: input.nativeSessionId ?? "native-001" }); await hooks.onPromptDispatch({}); prompts += 1;
      return {
        done: delayed ? done.then((result) => result.useExpectedCandidateDigest === true
          ? { state: result.state, assistantOutputDigest: digest("a"), terminalEvidenceDigest: digest("b") }
          : result) : Promise.resolve({ state: "candidate_ready", assistantOutputDigest: digest("a"), terminalEvidenceDigest: digest("b") }),
        async cancel() { cancelCalls += 1; await hooks.onCancelAcknowledged({}); finish({ state: "cancelled" }); return true; }
      };
    }
  });
  const options = {
    store, stateRoot: root, authority, profileFactory, custody, acknowledgePreStartCancellation: acknowledge,
    ...(runtimeAcknowledge === null ? {} : { acknowledgeRuntimeRecovery: runtimeAcknowledge }),
    acpFactory: suppliedAcpFactory ?? defaultAcpFactory, timers
  };
  if (executionAdapterFactory !== null) options.executionAdapterFactory = executionAdapterFactory;
  if (transport !== null) options.transport = transport;
  if (ownerId !== undefined) options.ownerId = ownerId;
  if (leaseDurationMs !== undefined) options.leaseDurationMs = leaseDurationMs;
  if (heartbeatMs !== undefined) options.heartbeatMs = heartbeatMs;
  const service = createJobService(options);
  assert.deepEqual(service.runtimePolicy, {
    leaseDurationMs: leaseDurationMs ?? 300_000,
    heartbeatMs: heartbeatMs ?? 30_000
  });
  return {
    root, store, service, custody, profile,
    finish: (result = { state: "candidate_ready", useExpectedCandidateDigest: true }) => finish(result),
    mutateInventory() { inventoryVersion += 1; },
    get starts() { return starts; }, get prompts() { return prompts; }, get loadedSessions() { return loadedSessions; }, get startedInputs() { return startedInputs; }, get cancelCalls() { return cancelCalls; },
    cleanup() {
      for (const handle of intervals) clearInterval(handle);
      intervals.clear();
      finish({ state: "cancelled" });
      if (ownsRoot) rmSync(root, { recursive: true, force: true });
    }
  };
}
async function tick() { await new Promise((resolve) => setTimeout(resolve, 0)); }
function trustedInspection() { const profile = getCapabilityProfile("trusted-local"); return { executable: { path: process.execPath, digest: digest("b") }, argv: [...profile.argv], cwdPolicy: "admitted_worktree_only", environmentKeys: profile.environmentKeys, inventoryDigest: digest("c"), capabilities: structuredClone(profile.inventoryAllowlist), containment: { claimed: "trusted_host", osBoundaryVerified: false } }; }
function headlessChild({ code = 0, sessionId = "123e4567-e89b-42d3-a456-426614174000" } = {}) {
  const child = new EventEmitter(); child.pid = 4433; child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => { if (child.closed) return; child.closed = true; child.stdout.end(); child.stderr.end(); child.emit("close", 0, "SIGTERM"); };
  setImmediate(() => { if (child.closed) return; child.stdout.write(`{"type":"text","data":"implemented"}\n{"type":"end","stopReason":"end_turn","sessionId":"${sessionId}","requestId":"provider-request-1","usage":{}}\n`); child.closed = true; child.stdout.end(); child.stderr.end(); child.emit("close", code, null); });
  return child;
}
function headlessFailureChild() {
  const child = new EventEmitter(); child.pid = 4434; child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => { child.stdout.end(); child.stderr.end(); child.emit("close", 0, "SIGTERM"); };
  setImmediate(() => { child.stdout.end(); child.stderr.end(); child.emit("close", 9, null); });
  return child;
}
async function ready(h, request = submission()) { const submitted = h.service.submit(request); await tick(); h.finish(); await tick(); await tick(); return submitted; }
function collection(jobId, expectedCandidateDigest, disposition = "accepted") {
  return { contractVersion: CONTRACT_VERSIONS.collection, collectionId: "collection-001", jobId, expectedAttemptId: null, expectedCandidateDigest, disposition, validationEvidenceRef: "validation-001", validationEvidenceDigest: digest("9"), idempotencyKey: "collect-001" };
}
function envelopePath(root, jobId) { return join(root, "jobs", jobId, "service-envelope.json"); }
function candidateManifestPath(root, jobId, manifestDigest) { return join(root, "jobs", jobId, `candidate-${manifestDigest.slice(7)}.json`); }
function rewriteSeal(path, mutate) {
  const sealed = JSON.parse(readFileSync(path, "utf8"));
  mutate(sealed.envelope);
  sealed.digest = digestOf(sealed.envelope);
  writeFileSync(path, JSON.stringify(sealed));
}
function rewriteRecoveryRepairProof(store, jobId, recoveryProofDigest) {
  const { snapshot, records } = store.readVerified(jobId, { includeRecords: true });
  const record = records.find((item) => item.type === "idempotent_mutation" && item.payload?.effect?.type === "recovery_repair_requested");
  assert.ok(record, "upgrade fixture requires the original durable recovery repair request");
  record.payload.effect.payload.recoveryProofDigest = recoveryProofDigest;
  record.payload.idempotency.requestDigest = digestOf({ operation: "recovery_repair", request: record.payload.effect.payload });
  let previousDigest = null;
  for (const item of records) {
    item.previousDigest = previousDigest;
    delete item.digest;
    item.digest = digestOf(item);
    previousDigest = item.digest;
  }
  writeFileSync(store.journalPath(jobId), `${records.map((item) => JSON.stringify(item)).join("\n")}\n`);
  store.commitSnapshot(jobId, { contractVersion: snapshot.contractVersion, ...store.replayJournal(records) });
}
function replaceWithLink(path) {
  const target = `${path}.link-target`;
  writeFileSync(target, readFileSync(path));
  rmSync(path, { force: true });
  symlinkSync(target, path, "file");
}

test("job service exposes exactly the four public lifecycle operations", () => {
  const service = createJobService({
    store: {},
    profileFactory() { throw new Error("not invoked"); },
    authority() { throw new Error("not invoked"); },
    custody: {}, acpFactory() { return {}; }
  });
  assert.deepEqual(Object.keys(service).sort(), ["cancel", "collect", "status", "submit"]);
});

test("new submit is asynchronous, cursor-replays normalized events, and candidate collection is not implicit acceptance", async () => {
  const h = harness();
  try {
    const submitted = h.service.submit(submission());
    assert.equal(submitted.state, "queued");
    assert.equal(h.starts, 0, "submit returns before a fake engineer starts");
    await tick(); assert.equal(h.starts, 1); assert.equal(h.prompts, 1);
    const launch = h.startedInputs[0];
    assert.doesNotMatch(launch.prompt, /GROK_CANDIDATE/);
    assert.equal(Object.hasOwn(launch, "expectedCandidateDigest"), false);
    const before = h.service.status({ jobId: submitted.jobId, afterCursor: 0 });
    assert.equal(before.job.state, "running"); assert.equal(before.events.length, 1);
    h.finish(); await tick(); await tick();
    const ready = h.service.status({ jobId: submitted.jobId, afterCursor: 0 });
    assert.equal(ready.job.state, "candidate_ready");
    assert.equal(ready.events.at(-1).kind, "candidate_ready");
    assert.deepEqual(ready.job.nextActions, ["grok_collect", "grok_submit", "grok_cancel"], "repair uses grok_submit with mode=repair");
    assert.deepEqual(h.service.status({ jobId: submitted.jobId, afterCursor: ready.events.at(-1).cursor }).events, []);
    const candidate = h.store.readVerified(submitted.jobId).bindings.candidate;
    const request = collection(submitted.jobId, candidate.manifestDigest); request.expectedAttemptId = candidate.attemptId;
    const received = h.service.collect(request);
    assert.equal(received.state, "accepted"); assert.equal(h.store.readJob(submitted.jobId).state, "accepted");
  } finally { h.cleanup(); }
});

test("finite headless transport seals a UUID before the ambiguous spawn boundary and repairs with exact resume", async () => {
  const inspected = trustedInspection(), attestation = buildProfileAttestation(getCapabilityProfile("trusted-local"), inspected), argv = [];
  const profile = { profileId: "trusted-local", profileDigest: attestation.profileDigest, attestation, inspection: inspected };
  const h = harness({
    profileFactory: () => structuredClone(profile),
    authority: () => ({ allowed: true, grantDigest: digest("f"), receiptDigest: digest("0"), model: "grok-4.6" }),
    executionAdapterFactory: createHeadlessSessionAdapter,
    transport: { environment: process.env, inspectChild: async () => inspected, killTree: (child) => child.kill(), spawnImpl(_command, args) { argv.push(args); const flag = args.includes("--resume") ? "--resume" : "--session-id"; return headlessChild({ sessionId: args[args.indexOf(flag) + 1] }); } }
  });
  try {
    const submitted = h.service.submit(submission({ profileId: "trusted-local" }));
    await tick(); await tick(); await tick();
    const first = h.store.readVerified(submitted.jobId).bindings.candidate;
    assert.ok(first, "clean finite exit publishes the candidate");
    const runtimePath = join(h.root, "jobs", submitted.jobId, `runtime-${first.attemptId}.json`);
    const processIdentityPath = join(h.root, "jobs", submitted.jobId, `process-${first.attemptId}.json`);
    const runtimeEnvelope = JSON.parse(readFileSync(runtimePath, "utf8")).envelope;
    const processIdentityEnvelope = JSON.parse(readFileSync(processIdentityPath, "utf8")).envelope;
    assert.equal(runtimeEnvelope.childProcessIdentity, null, "the pre-spawn runtime seal remains immutable");
    assert.equal(processIdentityEnvelope.childProcessIdentity.pid, 4433);
    assert.equal(typeof processIdentityEnvelope.childProcessIdentity.startedAt, "string");
    assert.equal(processIdentityEnvelope.jobId, submitted.jobId);
    assert.equal(processIdentityEnvelope.attemptId, first.attemptId);
    assert.equal(processIdentityEnvelope.nativeSessionId, runtimeEnvelope.nativeSessionId);
    assert.equal(processIdentityEnvelope.fencingToken, runtimeEnvelope.fencingToken);
    const status = h.service.status({ jobId: submitted.jobId, afterCursor: 0 });
    assert.equal(status.events.some((event) => event.data?.type === "headless_spawn_boundary"), true);
    assert.equal(argv[0].includes("--session-id"), true);
    assert.equal(argv[0][argv[0].indexOf("-m") + 1], "grok-4.6");
    const repair = submission({ submissionId: "repair-001", idempotencyKey: "repair-001", mode: "repair", profileId: "trusted-local", continuation: { jobId: submitted.jobId, expectedAttemptId: first.attemptId, expectedCandidateDigest: first.manifestDigest }, findings: [{ code: "finding-001", message: "Repair it." }] });
    h.service.submit(repair); await tick(); await tick(); await tick();
    assert.equal(argv[1].includes("--resume"), true); assert.equal(argv[1].includes("--session-id"), false);
  } finally { h.cleanup(); }
});

test("ambiguous headless process loss is fenced as recovery and an idempotent retry does not dispatch a second prompt", async () => {
  const inspected = trustedInspection(), attestation = buildProfileAttestation(getCapabilityProfile("trusted-local"), inspected), argv = [];
  const profile = { profileId: "trusted-local", profileDigest: attestation.profileDigest, attestation, inspection: inspected };
  const h = harness({ profileFactory: () => structuredClone(profile), executionAdapterFactory: createHeadlessSessionAdapter, transport: { environment: process.env, inspectChild: async () => inspected, killTree: (child) => child.kill(), spawnImpl(_command, args) { argv.push(args); return headlessChild({ code: 9 }); } } });
  try {
    const request = submission({ profileId: "trusted-local" }), submitted = h.service.submit(request);
    await tick(); await tick(); await tick();
    assert.equal(h.service.status({ jobId: submitted.jobId }).job.state, "recovery_required");
    h.service.submit(request); await tick();
    assert.equal(argv.length, 1, "the ambiguous spawn boundary cannot be retried as prompt-not-sent");
  } finally { h.cleanup(); }
});

test("headless adapter failure permits one exact same-session recovery repair without creating attempt two", async () => {
  const inspected = trustedInspection(), attestation = buildProfileAttestation(getCapabilityProfile("trusted-local"), inspected), argv = [];
  const profile = { profileId: "trusted-local", profileDigest: attestation.profileDigest, attestation, inspection: inspected };
  const h = harness({
    profileFactory: () => structuredClone(profile),
    executionAdapterFactory: createHeadlessSessionAdapter,
    transport: { environment: process.env, inspectChild: async () => inspected, killTree: (child) => child.kill(), spawnImpl(_command, args) { argv.push(args); if (argv.length === 1) return headlessFailureChild(); const sessionId = args[args.indexOf("--resume") + 1]; return headlessChild({ sessionId }); } }
  });
  try {
    const initial = submission({ profileId: "trusted-local" }), submitted = h.service.submit(initial);
    await tick(); await tick(); await tick();
    const failed = h.service.status({ jobId: submitted.jobId, afterCursor: 0 });
    assert.equal(failed.job.state, "recovery_required");
    const attempt = h.store.readVerified(submitted.jobId).attempts.at(-1);
    const publicSessionId = failed.events.find((event) => event.data?.type === "native_session_bound")?.nativeSessionId;
    const repair = submission({
      ...initial,
      submissionId: "headless-recovery-repair-001", mode: "repair", idempotencyKey: "headless-recovery-repair-001",
      continuation: { jobId: submitted.jobId, expectedAttemptId: attempt.attemptId, expectedNativeSessionId: publicSessionId },
      findings: [{ code: "headless-recovery", message: "Resume the exact sealed headless session." }]
    });
    assert.equal(h.service.submit(repair).state, "repairing");
    await tick(); await tick(); await tick();
    const ready = h.service.status({ jobId: submitted.jobId, afterCursor: 0 });
    assert.equal(ready.job.state, "candidate_ready", JSON.stringify(ready.events));
    assert.equal(h.store.readVerified(submitted.jobId).attempts.length, 1);
    assert.equal(argv.length, 2);
    assert.equal(argv[1].includes("--resume"), true);
    assert.equal(argv[1][argv[1].indexOf("--resume") + 1], argv[0][argv[0].indexOf("--session-id") + 1]);
    assert.equal(ready.events.filter((event) => event.data?.type === "recovery_repair_prompted").length, 1);
  } finally { h.cleanup(); }
});

test("candidate custody drift rejects collection before a stale acceptance", async () => {
  const h = harness();
  try {
    const submitted = h.service.submit(submission()); await tick(); h.finish(); await tick(); await tick();
    const candidate = h.store.readVerified(submitted.jobId).bindings.candidate;
    const stale = collection(submitted.jobId, candidate.manifestDigest); stale.expectedAttemptId = candidate.attemptId;
    h.mutateInventory(); assert.throws(() => h.service.collect(stale), /inventory|candidate/i);
    assert.equal(h.store.readJob(submitted.jobId).state, "candidate_ready");
    assert.equal(h.prompts, 1);
  } finally { h.cleanup(); }
});

test("repair atomically consumes the candidate and starts the next attempt from its exact native session", async () => {
  const h = harness();
  try {
    const submitted = h.service.submit(submission()); await tick(); h.finish(); await tick(); await tick();
    const first = h.store.readVerified(submitted.jobId).bindings.candidate;
    const repair = submission({ submissionId: "repair-001", mode: "repair", idempotencyKey: "repair-001", continuation: { jobId: submitted.jobId, expectedAttemptId: first.attemptId, expectedCandidateDigest: first.manifestDigest }, findings: [{ code: "finding-001", message: "Fix the bounded defect." }] });
    const result = h.service.submit(repair);
    assert.equal(result.state, "repairing");
    assert.equal(h.store.readVerified(submitted.jobId).bindings.candidate, null, "prior candidate is invalidated atomically");
    await tick();
    assert.deepEqual(h.loadedSessions, [null, "native-001"]);
    assert.equal(h.prompts, 2);
    const [initialLaunch, repairLaunch] = h.startedInputs;
    assert.equal(Object.hasOwn(initialLaunch, "expectedCandidateDigest"), false);
    assert.equal(Object.hasOwn(repairLaunch, "expectedCandidateDigest"), false);
    assert.doesNotMatch(repairLaunch.prompt, /GROK_CANDIDATE|sha256:[a-f0-9]{64}/);
    assert.match(repairLaunch.prompt, /finding-001: Fix the bounded defect\./);
    h.service.submit(repair); await tick();
    assert.equal(h.prompts, 2, "idempotent repair retry never duplicates its prompt");
  } finally { h.cleanup(); }
});

test("pre-start cancellation journals intent, awaits truthful host acknowledgement, and replays idempotently", async () => {
  const h = harness();
  try {
    const submitted = h.service.submit(submission()); await tick(); h.finish(); await tick(); await tick();
    const request = { contractVersion: CONTRACT_VERSIONS.cancellation, cancellationId: "cancel-001", jobId: submitted.jobId, reason: "operator-requested", idempotencyKey: "cancel-001" };
    const first = await h.service.cancel(request);
    assert.equal(first.state, "cancelled");
    const replay = await h.service.cancel(request);
    assert.deepEqual(replay, first);
  } finally { h.cleanup(); }
});

test("a cancellation during ACP launch persists its running origin and waits for protocol cancellation", async () => {
  let releaseStart; let entered;
  const startGate = new Promise((resolve) => { releaseStart = resolve; });
  const enteredStart = new Promise((resolve) => { entered = resolve; });
  let hostAcknowledgements = 0, protocolCancels = 0;
  const h = harness({
    acknowledge: async () => { hostAcknowledgements += 1; return true; },
    acpFactory: (hooks) => ({
      async start() {
        // The child is already real enough to bind a native session, but ACP
        // has not returned its runtime handle to the service yet.
        await hooks.onSessionBound({ nativeSessionId: "native-launch-race" });
        entered();
        await startGate;
        return {
          done: new Promise(() => {}),
          async cancel() {
            protocolCancels += 1;
            await hooks.onCancelAcknowledged({});
            return true;
          }
        };
      }
    })
  });
  try {
    const submitted = h.service.submit(submission({ submissionId: "launch-race-001", idempotencyKey: "launch-race-001" }));
    await enteredStart;
    const request = { contractVersion: CONTRACT_VERSIONS.cancellation, cancellationId: "launch-race-cancel", jobId: submitted.jobId, reason: "operator-requested", idempotencyKey: "launch-race-cancel" };
    const pending = await h.service.cancel(request);
    const durable = h.store.readVerified(submitted.jobId);
    assert.equal(pending.state, "cancelling");
    assert.equal(durable.job.state, "cancelling");
    assert.equal(durable.cancellation.fromState, "running");
    assert.equal(hostAcknowledgements, 0, "a live-but-unreturned child cannot be host-self-certified absent");
    assert.equal(h.service.status({ jobId: submitted.jobId }).job.state, "recovery_required");
    releaseStart();
    await tick(); await tick(); await tick();
    assert.equal(protocolCancels, 1);
    assert.equal(h.store.readJob(submitted.jobId).state, "cancelled");
  } finally { h.cleanup(); }
});

test("caller process controls fail before authority or ACP start", () => {
  const h = harness(); let authorityCalls = 0;
  const service = createJobService({ store: h.store, authority: () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; }, profileFactory: () => ({ profileId: "hermetic", profileDigest: digest("b"), attestation: { profileId: "hermetic", profileDigest: digest("b"), fingerprint: digest("8") }, inspection: {} }), custody: h.custody, acpFactory: () => ({}) });
  try {
    const malicious = submission(); malicious.task = { ...malicious.task, executable: "grok" };
    assert.throws(() => service.submit(malicious), /unsupported|process-control/i); assert.equal(authorityCalls, 0);
  } finally { h.cleanup(); }
});

test("sealed envelope and candidate manifest tampering fail closed without launching another child", async () => {
  const h = harness();
  try {
    const submitted = await ready(h); const candidate = h.store.readVerified(submitted.jobId).bindings.candidate;
    const envelope = join(h.root, "jobs", submitted.jobId, "service-envelope.json");
    writeFileSync(envelope, "{");
    assert.equal(h.service.status({ jobId: submitted.jobId }).job.state, "recovery_required");
    assert.equal(h.starts, 1);
    writeFileSync(envelope, JSON.stringify({ contractVersion: "agent-platform.grok-builder-service-envelope.v1", envelope: {}, digest: digest("a") }));
    assert.equal(h.service.status({ jobId: submitted.jobId }).job.state, "recovery_required");
    assert.equal(h.starts, 1);
    assert.ok(candidate.manifestDigest);
  } finally { h.cleanup(); }
});

test("renewal preserves an active fence and a competing owner cannot rotate it", async () => {
  const h = harness();
  try {
    const submitted = h.service.submit(submission()); await tick();
    const before = h.store.readVerified(submitted.jobId).lease;
    const renewed = h.store.renewExecutionLease(submitted.jobId, { ownerId: before.ownerId, fencingToken: before.fencingToken, durationMs: 30_000 });
    assert.equal(renewed.fencingToken, before.fencingToken);
    assert.throws(() => h.store.renewExecutionLease(submitted.jobId, { ownerId: "other-owner", fencingToken: before.fencingToken, durationMs: 30_000 }), /owner|lease/i);
    h.finish();
  } finally { h.cleanup(); }
});

test("running cancellation uses the active fence and reaches terminal acknowledgement", async () => {
  const h = harness();
  try {
    const submitted = h.service.submit(submission()); await tick();
    const before = h.store.readVerified(submitted.jobId).lease.fencingToken;
    const result = await h.service.cancel({ contractVersion: CONTRACT_VERSIONS.cancellation, cancellationId: "cancel-run-001", jobId: submitted.jobId, reason: "operator-requested", idempotencyKey: "cancel-run-001" });
    assert.equal(result.state, "cancelled"); assert.equal(h.cancelCalls, 1);
    assert.equal(h.store.readVerified(submitted.jobId).lease.fencingToken, before);
  } finally { h.cleanup(); }
});

test("collection accepts, rejects, or requests repair with exact request-digest replay", async () => {
  for (const disposition of ["accepted", "rejected", "repair_requested"]) {
    const h = harness();
    try {
      const submitted = await ready(h); const candidate = h.store.readVerified(submitted.jobId).bindings.candidate;
      const request = collection(submitted.jobId, candidate.manifestDigest, disposition); request.expectedAttemptId = candidate.attemptId; request.idempotencyKey = `collect-${disposition}`; request.collectionId = `collection-${disposition}`;
      const first = h.service.collect(request), replay = h.service.collect(request);
      const expectedState = disposition === "repair_requested" ? "repairing" : disposition;
      assert.equal(first.state, expectedState); assert.deepEqual(replay, first);
      assert.throws(() => h.service.collect({ ...request, disposition: disposition === "accepted" ? "rejected" : "accepted" }), /idempotency|digest/i);
    } finally { h.cleanup(); }
  }
});

test("real ACP adapter uses injected host dependencies, child parity, custody and fence callbacks", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-real-service-")); const store = new JobStore({ stateRoot: root });
  try {
    const profile = getCapabilityProfile("trusted-local");
    const inspection = { executable: { path: process.execPath, digest: digest("b") }, argv: [...profile.argv], cwdPolicy: profile.cwdPolicy, environmentKeys: profile.environmentKeys, inventoryDigest: digest("c"), capabilities: structuredClone(profile.inventoryAllowlist), containment: { claimed: "trusted_host", osBoundaryVerified: false } };
    const attestation = buildProfileAttestation(profile, inspection, { environment: process.env }); let launches = 0, inspections = 0, classifications = 0, authorizations = 0, revalidations = 0;
    const request = submission({ profileId: "trusted-local", submissionId: "real-001", idempotencyKey: "real-001" });
    const expectedJobId = `job-${digestOf({ submissionId: request.submissionId }).slice(7, 39)}`;
    const expectedAttemptId = `attempt-${digestOf({ jobId: expectedJobId, number: 1 }).slice(7, 39)}`;
    const expectedRequestId = `request-${digestOf({ jobId: expectedJobId, attemptId: expectedAttemptId }).slice(7, 39)}`;
    const expectedAssistantOutputDigest = digestText("Implementation complete.\nTests passed.\n");
    const custody = { admit({ jobId, source, stateRoot }) { return { jobId, sourceSha: source.sourceSha, sourceCustodyDigest: digest("c"), destinationRoot: source.destinationRoot, sourceRoot: source.repositoryRoot, stateRoot }; }, reserve(x) { return x; }, create(x) { return { ...x, linkedWorktree: true, worktreeCustodyDigest: digest("d") }; }, inventory() { return { inventoryDigest: digest("e"), protectedGitMetadata: {}, entries: [] }; }, revalidate() { revalidations += 1; return { inventoryDigest: digest("e") }; } };
    const service = createJobService({ store, custody, authority: () => ({ allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }), profileFactory: () => ({ profileId: "trusted-local", profileDigest: attestation.profileDigest, attestation, inspection }), timers: { setInterval() { return null; }, clearInterval() {} }, acp: { launch: async () => { launches += 1; return fakeAcpAgent({ sessionId: "native-real", permission: true }); }, inspectChild: async () => { inspections += 1; return inspection; }, classifyPermission: async () => { classifications += 1; return { operation: "write_file" }; }, authorizePermission: async () => { authorizations += 1; return { allowed: true, optionId: "allow" }; }, environment: process.env } });
    const submitted = service.submit(request); await new Promise((resolve) => setTimeout(resolve, 400));
    assert.equal(launches, 1); assert.equal(inspections, 1); assert.equal(classifications, 1); assert.equal(authorizations, 1); assert.ok(revalidations > 0);
    const current = service.status({ jobId: submitted.jobId });
    assert.equal(current.job.state, "candidate_ready");
    assert.equal(current.candidate.providerCandidateDigest, expectedAssistantOutputDigest);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("exact new-submit replay validates its journal-bound request before protected callbacks", async () => {
  let authorityCalls = 0, profileCalls = 0, custodyCalls = 0;
  const profile = { profileId: "hermetic", profileDigest: digest("b"), attestation: { profileId: "hermetic", profileDigest: digest("b"), fingerprint: digest("8") }, inspection: {} };
  const h = harness({
    authority: () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; },
    profileFactory: () => { profileCalls += 1; return structuredClone(profile); }
  });
  const originalAdmit = h.custody.admit.bind(h.custody);
  h.custody.admit = (...args) => { custodyCalls += 1; return originalAdmit(...args); };
  try {
    const request = submission({ submissionId: "replay-new-001", idempotencyKey: "replay-new-001" });
    const first = h.service.submit(request);
    const callbackCounts = [authorityCalls, profileCalls, custodyCalls];
    assert.deepEqual(h.service.submit(structuredClone(request)), first);
    assert.deepEqual([authorityCalls, profileCalls, custodyCalls], callbackCounts, "an exact active replay cannot reconsume protected authority");
    for (const changed of [
      { task: { ...request.task, instructions: "Different bounded task." } },
      { source: { ...request.source, sourceSha: "b".repeat(40) } },
      { idempotencyKey: "replay-new-other" }
    ]) {
      assert.throws(() => h.service.submit({ ...structuredClone(request), ...changed }), /idempotency|digest|context/i);
      assert.deepEqual([authorityCalls, profileCalls, custodyCalls], callbackCounts);
    }
    await tick(); assert.equal(h.prompts, 1); h.finish(); await tick(); await tick();
  } finally { h.cleanup(); }
});

test("exact new-submit replay returns the durable receipt after native-session evidence without re-prompting", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-native-session-replay-"));
  const request = submission({ submissionId: "native-session-replay-001", idempotencyKey: "native-session-replay-001" });
  const h1 = harness({ root, ownerId: "native-session-replay-old" });
  const h2 = harness({ root, ownerId: "native-session-replay-new" });
  try {
    const submitted = h1.service.submit(request);
    await tick();
    assert.equal(h1.prompts, 1);
    assert.equal(h2.service.status({ jobId: submitted.jobId }).job.state, "recovery_required");

    const replayed = h2.service.submit(structuredClone(request));
    assert.equal(replayed.jobId, submitted.jobId);
    assert.equal(replayed.state, "queued");
    assert.deepEqual(replayed.nextActions, ["grok_status", "grok_cancel"]);
    await tick();
    assert.equal(h1.prompts, 1, "the original native session receives the only prompt");
    assert.equal(h2.prompts, 0, "an exact replay cannot launch after native-session evidence");
  } finally {
    h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true });
  }
});

test("malformed durable replay state fails before authority, profile, or custody", async () => {
  let authorityCalls = 0, profileCalls = 0, custodyCalls = 0;
  const profile = { profileId: "hermetic", profileDigest: digest("b"), attestation: { profileId: "hermetic", profileDigest: digest("b"), fingerprint: digest("8") }, inspection: {} };
  const h = harness({
    authority: () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; },
    profileFactory: () => { profileCalls += 1; return structuredClone(profile); }
  });
  const originalAdmit = h.custody.admit.bind(h.custody);
  h.custody.admit = (...args) => { custodyCalls += 1; return originalAdmit(...args); };
  try {
    const request = submission({ submissionId: "replay-corrupt-001", idempotencyKey: "replay-corrupt-001" });
    await ready(h, request);
    const prior = [authorityCalls, profileCalls, custodyCalls];
    writeFileSync(join(h.root, "jobs", `job-${digestOf({ submissionId: request.submissionId }).slice(7, 39)}`, "snapshot.json"), "{");
    assert.throws(() => h.service.submit(structuredClone(request)), /missing|malformed|journal|snapshot/i);
    assert.deepEqual([authorityCalls, profileCalls, custodyCalls], prior);
  } finally { h.cleanup(); }
});

test("authority denial and malformed ACP candidate outcomes never launch or bind a candidate", async () => {
  const denied = harness({ authority: () => ({ allowed: false, grantDigest: digest("f"), receiptDigest: digest("0") }) });
  try {
    assert.throws(() => denied.service.submit(submission({ submissionId: "denied-001", idempotencyKey: "denied-001" })), /denied/i);
    assert.equal(denied.starts, 0);
  } finally { denied.cleanup(); }

  for (const [suffix, outcome] of [
    ["state", { state: "running", assistantOutputDigest: digest("a"), terminalEvidenceDigest: digest("b") }],
    ["missing", { state: "candidate_ready" }],
    ["wrong", { state: "candidate_ready", candidateDigest: digest("a") }],
    ["digest", { state: "candidate_ready", assistantOutputDigest: "not-a-digest", terminalEvidenceDigest: digest("b") }]
  ]) {
    const h = harness();
    try {
      const submitted = h.service.submit(submission({ submissionId: `bad-outcome-${suffix}`, idempotencyKey: `bad-outcome-${suffix}` }));
      await tick(); h.finish(outcome); await tick(); await tick();
      assert.equal(h.store.readVerified(submitted.jobId).bindings.candidate, null);
      assert.equal(h.service.status({ jobId: submitted.jobId }).job.state, "recovery_required");
    } finally { h.cleanup(); }
  }
});

test("truncated, recomputed-replacement, and linked envelopes fail before ACP launch", async () => {
  const corruptions = [
    ["truncated", (path) => writeFileSync(path, "{")],
    ["recomputed", (path) => rewriteSeal(path, (envelope) => { envelope.sourceCustodyDigest = digest("z"); })],
    ["link", (path) => replaceWithLink(path)]
  ];
  for (const [suffix, corrupt] of corruptions) {
    const h = harness();
    try {
      const submitted = h.service.submit(submission({ submissionId: `envelope-${suffix}`, idempotencyKey: `envelope-${suffix}` }));
      corrupt(envelopePath(h.root, submitted.jobId));
      await tick(); await tick();
      assert.equal(h.starts, 0, `${suffix} envelope must block ACP launch`);
      assert.equal(h.service.status({ jobId: submitted.jobId }).job.state, "recovery_required");
    } finally { h.cleanup(); }
  }
});

test("truncated, replaced, and linked candidate manifests fail closed without relaunch", async () => {
  const corruptions = [
    ["truncated", (path) => writeFileSync(path, "{")],
    ["replaced", (path) => rewriteSeal(path, (manifest) => { manifest.nativeSessionId = "other-native-session"; })],
    ["link", (path) => replaceWithLink(path)]
  ];
  for (const [suffix, corrupt] of corruptions) {
    const h = harness();
    try {
      const submitted = await ready(h, submission({ submissionId: `manifest-${suffix}`, idempotencyKey: `manifest-${suffix}` }));
      const candidate = h.store.readVerified(submitted.jobId).bindings.candidate;
      corrupt(candidateManifestPath(h.root, submitted.jobId, candidate.manifestDigest));
      assert.equal(h.service.status({ jobId: submitted.jobId }).job.state, "recovery_required");
      assert.equal(h.starts, 1, `${suffix} manifest must not schedule a replacement ACP child`);
    } finally { h.cleanup(); }
  }
});

test("authority requests bind submission custody/context and repair candidate/findings evidence", async () => {
  const requests = [];
  const h = harness({ authority: (request) => { requests.push(request); return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; } });
  try {
    const submitted = await ready(h, submission({ submissionId: "authority-001", idempotencyKey: "authority-001" }));
    const initial = requests[0];
    assert.deepEqual(initial.requiredScopes, ["provider", "private_disclosure", "cost", "worktree"]);
    assert.equal(initial.submissionDigest, digestOf(submission({ submissionId: "authority-001", idempotencyKey: "authority-001" })));
    assert.equal(initial.sourceSha, sourceSha); assert.equal(initial.sourceCustodyDigest, digest("c"));
    assert.equal(initial.repositoryRoot, "C:\\source");
    assert.equal(initial.destinationRoot, "C:\\worktrees\\job-001"); assert.equal(initial.destinationDigest, digestOf("c:/worktrees/job-001"));
    assert.equal(initial.dataClass, "internal"); assert.match(initial.contextDigest, /^sha256:/);
    const candidate = h.store.readVerified(submitted.jobId).bindings.candidate;
    const findings = [{ code: "finding-authority", message: "Repair this bounded test finding." }];
    const repairSubmission = submission({ submissionId: "authority-repair", mode: "repair", idempotencyKey: "authority-repair", continuation: { jobId: submitted.jobId, expectedAttemptId: candidate.attemptId, expectedCandidateDigest: candidate.manifestDigest }, findings });
    for (const changed of [
      { ...repairSubmission, task: { ...repairSubmission.task, title: "Changed repair title" } },
      { ...repairSubmission, task: { ...repairSubmission.task, instructions: "Changed repair instructions" } },
      { ...repairSubmission, task: { ...repairSubmission.task, dataClass: "public" } },
      { ...repairSubmission, task: { ...repairSubmission.task, contextPaths: ["src/other.mjs"] } },
      { ...repairSubmission, source: { ...repairSubmission.source, sourceSha: "b".repeat(40) } },
      { ...repairSubmission, profileId: "different-profile" }
    ]) assert.throws(() => h.service.submit(changed), /repair source|task|data class|profile/i);
    assert.equal(requests.length, 1, "mutated repair prompt material fails before authority or ACP");
    h.service.submit(repairSubmission);
    const repair = requests[1];
    assert.equal(repair.mode, "repair"); assert.equal(repair.candidateDigest, candidate.manifestDigest);
    assert.equal(repair.candidateAttemptId, candidate.attemptId); assert.equal(repair.findingsDigest, digestOf(findings));
    assert.equal(repair.sourceCustodyDigest, digest("c")); assert.equal(repair.destinationDigest, digestOf("c:/worktrees/job-001"));
    assert.equal(repair.repairSubmissionDigest, digestOf(repairSubmission));
    assert.equal(repair.repairTaskDigest, digestOf(repairSubmission.task)); assert.equal(repair.repairSourceDigest, digestOf(repairSubmission.source));
  } finally { h.cleanup(); }
});

test("heartbeat renews one fence, rejects a competitor, and records recovery on renewal loss", async () => {
  let now = 10_000; const root = mkdtempSync(join(tmpdir(), "grok-heartbeat-"));
  const store = new JobStore({ stateRoot: root, now: () => now }); const heartbeats = [];
  const h = harness({ root, store, ownerId: "clock-owner", leaseDurationMs: 100, heartbeatMs: 25, timers: { setInterval(fn) { heartbeats.push(fn); return fn; }, clearInterval() {} } });
  try {
    const submitted = h.service.submit(submission({ submissionId: "heartbeat-001", idempotencyKey: "heartbeat-001" }));
    await tick();
    const first = store.readVerified(submitted.jobId).lease;
    assert.equal(heartbeats.length, 1);
    now = 10_050; heartbeats[0]();
    const renewed = store.readVerified(submitted.jobId).lease;
    assert.equal(renewed.fencingToken, first.fencingToken); assert.ok(renewed.expiresAt > first.expiresAt);
    assert.throws(() => new JobStore({ stateRoot: root, now: () => now }).acquireExecutionLease(submitted.jobId, { ownerId: "other-owner", durationMs: 100 }), /held|owner/i);
    now = renewed.expiresAt + 1; heartbeats[0]();
    assert.equal(h.service.status({ jobId: submitted.jobId }).job.state, "recovery_required");
  } finally { h.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("real Node timers renew a live execution while its provider result remains pending", async () => {
  const h = harness({ leaseDurationMs: 2_000, heartbeatMs: 100 });
  try {
    const submitted = h.service.submit(submission({ submissionId: "real-timer-heartbeat-001", idempotencyKey: "real-timer-heartbeat-001" }));
    await tick();
    const initial = h.store.readVerified(submitted.jobId).lease;
    const deadline = Date.now() + 3_000;
    let renewed = initial;
    while (renewed.expiresAt <= initial.expiresAt && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
      renewed = h.store.readVerified(submitted.jobId).lease;
    }
    assert.ok(renewed.expiresAt > initial.expiresAt, "the real interval must advance the durable lease while the result is pending");
    assert.equal(h.service.status({ jobId: submitted.jobId }).job.state, "running");
  } finally { h.cleanup(); }
});

test("default execution authority leaves a five-minute live-provider margin", async () => {
  const h = harness();
  try {
    const before = Date.now();
    const submitted = h.service.submit(submission({ submissionId: "default-lease-margin-001", idempotencyKey: "default-lease-margin-001" }));
    await tick();
    const lease = h.store.readVerified(submitted.jobId).lease;
    assert.ok(lease.expiresAt >= before + 295_000, "the default lease must tolerate a normal silent provider reasoning interval");
  } finally { h.cleanup(); }
});

test("heartbeat starts before a slow ACP launch can outlive its original lease", async () => {
  let now = 10_000; const root = mkdtempSync(join(tmpdir(), "grok-slow-start-"));
  const store = new JobStore({ stateRoot: root, now: () => now }); const heartbeats = [];
  let releaseStart; const startGate = new Promise((resolve) => { releaseStart = resolve; });
  let started; const startedGate = new Promise((resolve) => { started = resolve; });
  const h = harness({
    root, store, ownerId: "slow-start-owner", leaseDurationMs: 100, heartbeatMs: 25,
    timers: { setInterval(fn) { heartbeats.push(fn); return fn; }, clearInterval() {} },
    acpFactory: () => ({ async start() { started(); await startGate; return { done: Promise.resolve({ state: "cancelled" }), async cancel() { return true; } }; } })
  });
  try {
    const submitted = h.service.submit(submission({ submissionId: "slow-start-001", idempotencyKey: "slow-start-001" }));
    await started;
    const original = store.readVerified(submitted.jobId).lease;
    assert.equal(heartbeats.length, 1, "heartbeat is registered before adapter.start resolves");
    now = 10_075; heartbeats[0]();
    now = 10_150; heartbeats[0]();
    const renewed = store.readVerified(submitted.jobId).lease;
    assert.ok(now > original.expiresAt, "the launcher exceeded its original lease window");
    assert.ok(renewed.expiresAt > now, "the pre-start heartbeat retained the durable lease");
    releaseStart(); await tick(); await tick();
  } finally { h.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("a late ACP start is stopped and ignored after its launch heartbeat loses authority", async () => {
  let now = 20_000; const root = mkdtempSync(join(tmpdir(), "grok-start-authority-loss-"));
  const store = new JobStore({ stateRoot: root, now: () => now }); const heartbeats = [];
  let releaseStart; const startGate = new Promise((resolve) => { releaseStart = resolve; });
  let started; const startedGate = new Promise((resolve) => { started = resolve; });
  let stops = 0, resultReads = 0;
  const h = harness({
    root, store, ownerId: "lost-start-owner", leaseDurationMs: 100, heartbeatMs: 25,
    timers: { setInterval(fn) { heartbeats.push(fn); return fn; }, clearInterval() {} },
    acpFactory: () => ({ async start() {
      started(); await startGate;
      return {
        child: { stop() { stops += 1; } },
        get done() { resultReads += 1; return Promise.resolve({ state: "candidate_ready", candidateDigest: digest("a") }); },
        async cancel() { return true; }
      };
    } })
  });
  try {
    const submitted = h.service.submit(submission({ submissionId: "lost-start-001", idempotencyKey: "lost-start-001" }));
    await started;
    const lease = store.readVerified(submitted.jobId).lease;
    now = lease.expiresAt + 1; heartbeats[0]();
    assert.equal(store.readVerified(submitted.jobId).job.state, "recovery_required");
    releaseStart(); await tick(); await tick();
    const recovered = store.readVerified(submitted.jobId);
    assert.equal(stops, 1, "the late child is stopped as soon as its handle becomes available");
    assert.equal(resultReads, 0, "the candidate result is never consumed after authority loss");
    assert.equal(recovered.job.state, "recovery_required");
    assert.equal(recovered.bindings.candidate, null);
  } finally { h.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("two default service instances have distinct owners and one durable global ACP slot", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-global-slot-"));
  const h1 = harness({ root, store: new JobStore({ stateRoot: root }) });
  const h2 = harness({ root, store: new JobStore({ stateRoot: root }) });
  try {
    const one = h1.service.submit(submission({ submissionId: "slot-one-001", idempotencyKey: "slot-one-001", source: { ...submission().source, destinationRoot: "C:\\worktrees\\slot-one" } }));
    await tick(); assert.equal(h1.starts, 1);
    const two = h2.service.submit(submission({ submissionId: "slot-two-001", idempotencyKey: "slot-two-001", source: { ...submission().source, destinationRoot: "C:\\worktrees\\slot-two" } }));
    await tick(); assert.equal(h2.starts, 0, "the second service must queue behind the state-root-global slot");
    const oneLease = h1.store.readVerified(one.jobId).lease, twoLease = h2.store.readVerified(two.jobId).lease;
    assert.notEqual(oneLease.ownerId, twoLease.ownerId, "default service instances cannot impersonate a common owner");
    await assert.rejects(() => h2.service.cancel({ contractVersion: CONTRACT_VERSIONS.cancellation, cancellationId: "slot-cross-cancel", jobId: one.jobId, reason: "operator-requested", idempotencyKey: "slot-cross-cancel" }), /lease|held|owner/i);
    h1.finish(); await tick(); await tick(); await tick();
    h2.service.status({ jobId: two.jobId }); await tick(); await tick();
    assert.equal(h2.starts, 1, "polling drains a previously slot-blocked queued job after release");
    h2.finish(); await tick(); await tick();
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("restart re-drives a durable cancellation intent and terminal replay never reacquires its expired fence", async () => {
  let now = 20_000; const root = mkdtempSync(join(tmpdir(), "grok-cancel-restart-"));
  const h1 = harness({ root, store: new JobStore({ stateRoot: root, now: () => now }), ownerId: "restart-old-owner", acknowledge: async () => false, leaseDurationMs: 100, heartbeatMs: 25 });
  const h2 = harness({ root, store: new JobStore({ stateRoot: root, now: () => now }), ownerId: "restart-new-owner", acknowledge: async () => true, leaseDurationMs: 100, heartbeatMs: 25 });
  try {
    const submitted = await ready(h1, submission({ submissionId: "cancel-restart-001", idempotencyKey: "cancel-restart-001" }));
    const request = { contractVersion: CONTRACT_VERSIONS.cancellation, cancellationId: "cancel-restart", jobId: submitted.jobId, reason: "operator-requested", idempotencyKey: "cancel-restart" };
    const pending = await h1.service.cancel(request);
    assert.equal(pending.state, "cancelling");
    assert.equal(h2.service.status({ jobId: submitted.jobId }).job.state, "recovery_required");
    const stale = h1.store.readVerified(submitted.jobId).lease; now = stale.expiresAt + 1;
    const completed = await h2.service.cancel(structuredClone(request));
    assert.equal(completed.state, "cancelled");
    assert.equal(h2.store.readVerified(submitted.jobId).lease.ownerId, "restart-new-owner");
    now = 99_999_999;
    assert.deepEqual(await h2.service.cancel(structuredClone(request)), completed, "exact terminal cancellation replay returns before lease acquisition");
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("restart from a running cancellation intent waits for expiry, host proof, and releases stale global capacity", async () => {
  let now = 30_000; const root = mkdtempSync(join(tmpdir(), "grok-running-cancel-restart-"));
  let protocolCancels = 0; const hostProofs = [];
  const h1 = harness({
    root, ownerId: "running-cancel-old", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }),
    timers: { setInterval() { return null; }, clearInterval() {} },
    acpFactory: (hooks) => ({
      async start() {
        await hooks.onSessionBound({ nativeSessionId: "native-running-cancel" });
        return { done: new Promise(() => {}), async cancel() { protocolCancels += 1; return true; } };
      }
    })
  });
  const h2 = harness({
    root, ownerId: "running-cancel-new", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }),
    acknowledge: async (proof) => { hostProofs.push(proof); return true; }
  });
  try {
    const submitted = h1.service.submit(submission({ submissionId: "running-cancel-001", idempotencyKey: "running-cancel-001" }));
    await tick(); await tick();
    const request = { contractVersion: CONTRACT_VERSIONS.cancellation, cancellationId: "running-cancel-replay", jobId: submitted.jobId, reason: "operator-requested", idempotencyKey: "running-cancel-replay" };
    const pending = await h1.service.cancel(request);
    assert.equal(pending.state, "cancelling");
    assert.equal(protocolCancels, 1);
    const raw = h1.store.readVerified(submitted.jobId);
    assert.equal(raw.cancellation.fromState, "running");
    assert.equal(h2.service.status({ jobId: submitted.jobId }).job.state, "recovery_required");
    await assert.rejects(() => h2.service.cancel(structuredClone(request)), /waits for expiry|lease/i);
    assert.equal(hostProofs.length, 0, "no host absence proof is consulted while the old fence is live");
    now = raw.lease.expiresAt + 1;
    const completed = await h2.service.cancel(structuredClone(request));
    assert.equal(completed.state, "cancelled"); assert.equal(completed.cleanup, "released");
    assert.equal(hostProofs.length, 1); assert.equal(hostProofs[0].originState, "recovery_required");
    assert.equal(h2.store.readExecutionSlot(), null, "the bound expired slot is rotated and durably released");
    const next = h2.service.submit(submission({ submissionId: "after-running-cancel", idempotencyKey: "after-running-cancel", source: { ...submission().source, destinationRoot: "C:\\worktrees\\after-running-cancel" } }));
    await tick(); assert.equal(h2.starts, 1, "released capacity lets the next queued job launch");
    h2.finish(); await tick(); await tick();
    assert.equal(h2.service.status({ jobId: next.jobId }).job.state, "candidate_ready");
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("a recovery_required job permits cancellation only after expired-fence takeover and host child-absence proof", async () => {
  let now = 40_000; const root = mkdtempSync(join(tmpdir(), "grok-recovery-cancel-"));
  let childAbsent = false; const proofs = [];
  const h1 = harness({
    root, ownerId: "recovery-old", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }),
    timers: { setInterval() { return null; }, clearInterval() {} },
    acpFactory: () => ({ async start() { throw new Error("provider launch failed without a child"); } })
  });
  const h2 = harness({
    root, ownerId: "recovery-new", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }),
    acknowledge: async (proof) => { proofs.push(proof); return childAbsent; }
  });
  try {
    const submitted = h1.service.submit(submission({ submissionId: "recovery-cancel-001", idempotencyKey: "recovery-cancel-001" }));
    await tick(); await tick(); await tick();
    const raw = h1.store.readVerified(submitted.jobId);
    assert.equal(raw.job.state, "recovery_required");
    assert.deepEqual(h2.service.status({ jobId: submitted.jobId }).job.nextActions, ["grok_status", "grok_cancel"]);
    const request = { contractVersion: CONTRACT_VERSIONS.cancellation, cancellationId: "recovery-cancel", jobId: submitted.jobId, reason: "operator-requested", idempotencyKey: "recovery-cancel" };
    await assert.rejects(() => h2.service.cancel(request), /waits for expiry|lease/i);
    now = raw.lease.expiresAt + 1;
    await assert.rejects(() => h2.service.cancel(request), /child-absence/i);
    assert.equal(h2.store.readVerified(submitted.jobId).job.state, "recovery_required");
    childAbsent = true;
    const cancelled = await h2.service.cancel(request);
    assert.equal(cancelled.state, "cancelled"); assert.equal(cancelled.cleanup, "released");
    assert.equal(proofs.at(-1).originState, "recovery_required"); assert.equal(proofs.at(-1).childAbsenceRequired, true);
    assert.ok(existsSync(envelopePath(root, submitted.jobId)), "cleanup releases only the reservation claim, never the retained worktree evidence");
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("restart cancels an orphaned raw-running job only after expiry and sealed child-absence proof", async () => {
  let now = 45_000; const root = mkdtempSync(join(tmpdir(), "grok-running-orphan-cancel-"));
  let childAbsent = false; const proofs = [];
  const h1 = harness({
    root, ownerId: "running-orphan-old", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }),
    timers: { setInterval() { return null; }, clearInterval() {} },
    acpFactory: (hooks) => ({
      async start() {
        await hooks.onSessionBound({ nativeSessionId: "native-running-orphan", childProcessIdentity: { pid: 7103, startedAt: "2026-08-15T20:02:00.000Z" } });
        return { done: new Promise(() => {}), async cancel() { return true; } };
      }
    })
  });
  const h2 = harness({
    root, ownerId: "running-orphan-new", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }),
    acknowledge: async (proof) => { proofs.push(proof); return childAbsent; }
  });
  try {
    const submitted = h1.service.submit(submission({ submissionId: "running-orphan-001", idempotencyKey: "running-orphan-001" }));
    await tick(); await tick();
    const raw = h1.store.readVerified(submitted.jobId);
    assert.equal(raw.job.state, "running");
    assert.equal(h2.service.status({ jobId: submitted.jobId }).job.state, "recovery_required");
    const request = { contractVersion: CONTRACT_VERSIONS.cancellation, cancellationId: "running-orphan-cancel", jobId: submitted.jobId, reason: "operator-requested", idempotencyKey: "running-orphan-cancel" };
    await assert.rejects(() => h2.service.cancel(request), /waits for expiry|lease/i);
    assert.equal(proofs.length, 0);
    now = raw.lease.expiresAt + 1;
    await assert.rejects(() => h2.service.cancel(request), /child-absence/i);
    assert.equal(h2.store.readVerified(submitted.jobId).job.state, "running");
    childAbsent = true;
    const cancelled = await h2.service.cancel(request);
    assert.equal(cancelled.state, "cancelled"); assert.equal(cancelled.cleanup, "released");
    assert.equal(proofs.at(-1).originState, "running");
    assert.equal(proofs.at(-1).childAbsenceRequired, true);
    assert.deepEqual(proofs.at(-1).childProcessIdentity, { pid: 7103, startedAt: "2026-08-15T20:02:00.000Z" });
    assert.equal(h2.store.readExecutionSlot(), null);
    const next = h2.service.submit(submission({ submissionId: "after-running-orphan", idempotencyKey: "after-running-orphan", source: { ...submission().source, destinationRoot: "C:\\worktrees\\after-running-orphan" } }));
    await tick(); assert.equal(h2.starts, 1);
    h2.finish(); await tick(); await tick();
    assert.equal(h2.service.status({ jobId: next.jobId }).job.state, "candidate_ready");
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("an exact new-submit replay resumes only an expired, unprompted raw-running attempt after restart", async () => {
  let now = 50_000, firstLaunches = 0, authorityCalls = 0;
  const root = mkdtempSync(join(tmpdir(), "grok-pre-prompt-restart-"));
  class InterruptedPrePromptStore extends JobStore {
    transition(jobId, to, options) {
      // Simulate a process loss while it tries to persist its ACP failure:
      // the first attempt remains raw-running, with no native-session bind.
      if (to === "recovery_required") throw new Error("simulated process interruption");
      return super.transition(jobId, to, options);
    }
    releaseExecutionSlot() { throw new Error("simulated process interruption"); }
  }
  const h1 = harness({
    root, ownerId: "pre-prompt-old", leaseDurationMs: 100, heartbeatMs: 25,
    store: new InterruptedPrePromptStore({ stateRoot: root, now: () => now }),
    authority: () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; },
    acpFactory: () => ({ async start() { firstLaunches += 1; throw new Error("ACP failed before session bind"); } })
  });
  const h2 = harness({
    root, ownerId: "pre-prompt-new", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }),
    authority: () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; }
  });
  try {
    const request = submission({ submissionId: "pre-prompt-restart-001", idempotencyKey: "pre-prompt-restart-001" });
    const submitted = h1.service.submit(request);
    await tick(); await tick(); await tick();
    const interrupted = h1.store.readVerified(submitted.jobId);
    assert.equal(firstLaunches, 1);
    assert.equal(interrupted.job.state, "running", "the interrupted process left only the raw active state");
    assert.equal(interrupted.attempts.length, 1);
    assert.equal(existsSync(join(root, "jobs", submitted.jobId, `runtime-${interrupted.attempts[0].attemptId}.json`)), false, "no native session was ever bound");
    assert.equal(h2.service.status({ jobId: submitted.jobId }).job.state, "recovery_required", "status remains fail-closed before replay proof");
    const staleLease = interrupted.lease;
    const staleSlot = h2.store.readExecutionSlot();
    assert.equal(staleSlot?.jobId, submitted.jobId);
    now = staleLease.expiresAt + 1;

    const replay = h2.service.submit(structuredClone(request));
    assert.equal(replay.jobId, submitted.jobId);
    await tick(); await tick();
    const resumed = h2.store.readVerified(submitted.jobId);
    assert.equal(h1.prompts, 0, "the failed first ACP launch never reached a provider prompt");
    assert.equal(h2.prompts, 1, "the exact replay makes the only provider prompt");
    assert.equal(resumed.attempts.length, 2, "recovery is auditable as a new attempt, not a hidden retry");
    assert.equal(resumed.attempts[1].number, 2);
    assert.equal(resumed.lease.ownerId, "pre-prompt-new");
    assert.equal(resumed.lease.fencingToken, staleLease.fencingToken + 1);
    assert.equal(h2.store.readExecutionSlot()?.fencingToken, resumed.lease.fencingToken, "the matching expired slot rotated with the new fence");
    assert.equal(authorityCalls, 1, "exact replay reuses the original admitted authority");

    h2.finish(); await tick(); await tick();
    assert.equal(h2.service.status({ jobId: submitted.jobId }).job.state, "candidate_ready");
    h2.service.submit(structuredClone(request)); await tick();
    assert.equal(h2.prompts, 1, "terminal exact replay cannot start a third provider prompt");
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("a durable acp_failure before native-session binding replays after expiry without a false sealed-evidence status", async () => {
  let now = 60_000, authorityCalls = 0;
  const root = mkdtempSync(join(tmpdir(), "grok-acp-failure-replay-"));
  const h1 = harness({
    root, ownerId: "acp-failure-old", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }),
    authority: () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; },
    acpFactory: (hooks) => ({ async start() { await hooks.onFailure({ failureKind: "child_lost", childClose: { code: 19, signal: "Bearer supersecretvalue", spawnError: false, stderrBytes: 37, stderrLimitExceeded: true, rawStderr: "Bearer supersecretvalue" } }); throw new Error("ACP bootstrap failed before session bind"); } })
  });
  const h2 = harness({
    root, ownerId: "acp-failure-new", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }),
    authority: () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; }
  });
  try {
    const request = submission({ submissionId: "acp-failure-replay-001", idempotencyKey: "acp-failure-replay-001" });
    const submitted = h1.service.submit(request);
    await tick(); await tick(); await tick();
    const failed = h1.store.readVerified(submitted.jobId);
    assert.equal(failed.job.state, "recovery_required");
    assert.equal(failed.attempts.length, 1);
    assert.equal(failed.usage, null);
    assert.equal(failed.bindings.candidate, null);
    assert.equal(failed.bindings.providerCandidateDigest, null);
    assert.equal(failed.job.eventCursor, 1);
    const failureEvent = h1.store.readStatus(submitted.jobId, { afterCursor: 0 }).events[0];
    assert.equal(failureEvent.data.code, "acp_failure");
    assert.equal(failureEvent.data.failureKind, "child_lost");
    assert.deepEqual(failureEvent.data.childClose, { code: 19, signal: null, spawnError: false, stderrBytes: 37, stderrLimitExceeded: true });
    assert.doesNotMatch(JSON.stringify(failureEvent), /supersecretvalue|rawStderr/);
    assert.equal(existsSync(join(root, "jobs", submitted.jobId, `runtime-${failed.attempts[0].attemptId}.json`)), false);
    const beforeReplay = h2.service.status({ jobId: submitted.jobId });
    assert.equal(beforeReplay.job.state, "recovery_required");
    assert.notEqual(beforeReplay.job.recoveryReason, "sealed_evidence_revalidation_failed", "no candidate is expected after an ACP bootstrap failure");
    const oldLease = failed.lease; now = oldLease.expiresAt + 1;

    h2.service.submit(structuredClone(request));
    await tick(); await tick();
    const resumed = h2.store.readVerified(submitted.jobId);
    assert.equal(h2.prompts, 1, "the repaired adapter sends the first and only provider prompt");
    assert.equal(resumed.attempts.length, 2);
    assert.equal(resumed.lease.fencingToken, oldLease.fencingToken + 1);
    assert.equal(authorityCalls, 1, "exact replay reuses the original authority admission");
    h2.finish(); await tick(); await tick();
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("each expired audited pre-bind ACP failure can recover once, creating attempt N plus one", async () => {
  let now = 65_000, authorityCalls = 0;
  const root = mkdtempSync(join(tmpdir(), "grok-multi-pre-prompt-replay-"));
  const failedAcp = (hooks) => ({ async start() { await hooks.onFailure({}); throw new Error("ACP bootstrap failed before session bind"); } });
  const authority = () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; };
  const h1 = harness({ root, ownerId: "multi-pre-prompt-one", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority, acpFactory: failedAcp });
  const h2 = harness({ root, ownerId: "multi-pre-prompt-two", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority, acpFactory: failedAcp });
  const h3 = harness({ root, ownerId: "multi-pre-prompt-three", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority });
  try {
    const request = submission({ submissionId: "multi-pre-prompt-replay-001", idempotencyKey: "multi-pre-prompt-replay-001" });
    const submitted = h1.service.submit(request); await tick(); await tick(); await tick();
    const first = h1.store.readVerified(submitted.jobId); assert.equal(first.attempts.length, 1); assert.equal(first.job.state, "recovery_required");
    now = first.lease.expiresAt + 1;
    h2.service.submit(structuredClone(request)); await tick(); await tick(); await tick();
    const second = h2.store.readVerified(submitted.jobId); assert.equal(second.attempts.length, 2); assert.equal(second.job.state, "recovery_required");
    const events = h2.store.readStatus(submitted.jobId, { afterCursor: 0 }).events;
    assert.deepEqual(events.map((event) => [event.attemptId, event.kind, event.data?.code]), second.attempts.map((attempt) => [attempt.attemptId, "failure", "acp_failure"]));
    assert.ok(second.attempts.every((attempt) => !existsSync(join(root, "jobs", submitted.jobId, `runtime-${attempt.attemptId}.json`))));
    const expiredLatestLease = second.lease, expiredLatestSlot = h2.store.readExecutionSlot(); assert.ok(expiredLatestSlot === null || expiredLatestSlot.fencingToken === expiredLatestLease.fencingToken);
    now = expiredLatestLease.expiresAt + 1;
    const beforeReplay = h3.service.status({ jobId: submitted.jobId }); assert.equal(beforeReplay.job.state, "recovery_required"); assert.notEqual(beforeReplay.job.recoveryReason, "sealed_evidence_revalidation_failed");
    h3.service.submit(structuredClone(request)); await tick(); await tick();
    const resumed = h3.store.readVerified(submitted.jobId);
    assert.equal(resumed.attempts.length, 3); assert.equal(resumed.attempts.at(-1).number, 3); assert.equal(h3.prompts, 1);
    assert.equal(resumed.lease.fencingToken, expiredLatestLease.fencingToken + 1); assert.equal(h3.store.readExecutionSlot()?.fencingToken, resumed.lease.fencingToken);
    assert.equal(authorityCalls, 1, "all exact replays reuse the original admitted authority");
    h3.finish(); await tick(); await tick();
  } finally { h1.cleanup(); h2.cleanup(); h3.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("pre-prompt recovery revalidates the journal-bound linked worktree instead of re-admitting its existing destination", async () => {
  let now = 70_000;
  const root = mkdtempSync(join(tmpdir(), "grok-pre-prompt-custody-replay-"));
  const h1 = harness({
    root, ownerId: "pre-prompt-custody-old", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }),
    acpFactory: (hooks) => ({ async start() { await hooks.onFailure({}); throw new Error("ACP bootstrap failed before session bind"); } })
  });
  let replayRevalidations = 0;
  let h2;
  try {
    const request = submission({ submissionId: "pre-prompt-custody-replay-001", idempotencyKey: "pre-prompt-custody-replay-001" });
    const submitted = h1.service.submit(request);
    await tick(); await tick(); await tick();
    const failed = h1.store.readVerified(submitted.jobId);
    assert.equal(failed.job.state, "recovery_required");
    const originalRevalidate = h1.custody.revalidate.bind(h1.custody);
    h1.custody.admit = () => { throw new Error("existing destination must not be re-admitted"); };
    h1.custody.revalidate = (...args) => { replayRevalidations += 1; return originalRevalidate(...args); };
    h2 = harness({
      root, ownerId: "pre-prompt-custody-new", leaseDurationMs: 100, heartbeatMs: 25,
      store: new JobStore({ stateRoot: root, now: () => now }), custody: h1.custody
    });
    now = failed.lease.expiresAt + 1;
    assert.doesNotThrow(() => h2.service.submit(structuredClone(request)));
    await tick(); await tick();
    assert.ok(replayRevalidations >= 1, "replay must revalidate its immutable linked custody");
    assert.equal(h2.prompts, 1);
    h2.finish(); await tick(); await tick();
  } finally { h1.cleanup(); h2?.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("runtime custody journal binding regenerates a missing envelope after a bind/write fault without repeat authority, worktree, or prompt", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-runtime-replay-")); let creates = 0, authorities = 0;
  const h1 = harness({
    root, ownerId: "fault-owner", store: new JobStore({ stateRoot: root, faults: { afterServiceRuntime: true } }),
    authority: () => { authorities += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; }
  });
  const originalCreate = h1.custody.create.bind(h1.custody);
  h1.custody.create = (...args) => { creates += 1; return originalCreate(...args); };
  const h2 = harness({
    root, ownerId: "fault-owner", store: new JobStore({ stateRoot: root }), custody: h1.custody, delayed: false,
    authority: () => { authorities += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; }
  });
  try {
    const request = submission({ submissionId: "runtime-fault-001", idempotencyKey: "runtime-fault-001" });
    const first = h1.service.submit(request); await tick(); await tick();
    assert.equal(h1.service.status({ jobId: first.jobId }).job.state, "recovery_required");
    assert.equal(creates, 1); assert.equal(h1.prompts, 0);
    rmSync(envelopePath(root, first.jobId), { force: true });
    const replay = h2.service.submit(structuredClone(request));
    assert.equal(replay.jobId, first.jobId); await tick(); await tick(); await tick();
    assert.equal(h2.service.status({ jobId: first.jobId }).job.state, "candidate_ready");
    assert.equal(creates, 1, "journaled custody reuses the single created worktree");
    assert.equal(authorities, 1, "exact post-admission replay never consumes authority again");
    assert.equal(h2.prompts, 1);
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("repair replay resumes the exact native session once after restart and rejects competing findings", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-repair-restart-")); let authorityCalls = 0;
  const h1 = harness({ root, store: new JobStore({ stateRoot: root }), ownerId: "repair-owner", authority: () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; } });
  const h2 = harness({ root, store: new JobStore({ stateRoot: root }), ownerId: "repair-owner", authority: () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; } });
  try {
    const submitted = await ready(h1, submission({ submissionId: "repair-restart-001", idempotencyKey: "repair-restart-001" }));
    const candidate = h1.store.readVerified(submitted.jobId).bindings.candidate;
    const repair = submission({ submissionId: "repair-restart-request", mode: "repair", idempotencyKey: "repair-restart-request", continuation: { jobId: submitted.jobId, expectedAttemptId: candidate.attemptId, expectedCandidateDigest: candidate.manifestDigest }, findings: [{ code: "finding-restart", message: "Repair the bounded fixture." }] });
    const slot = h1.store.acquireExecutionSlot("slot-holder", { ownerId: "slot-owner", fencingToken: 1, profileDigest: digest("b"), expiresAt: Date.now() + 30_000 });
    h1.service.submit(repair);
    assert.equal(authorityCalls, 2);
    const different = { ...structuredClone(repair), submissionId: "repair-restart-other", idempotencyKey: "repair-restart-other", findings: [{ code: "finding-other", message: "Different finding set." }] };
    assert.throws(() => h1.service.submit(different), /active repair|different repair|finding/i);
    assert.equal(authorityCalls, 2, "a losing repair contender cannot consume a second grant");
    await tick(); assert.equal(h1.prompts, 1, "the held global slot leaves repair durable but unprompted");
    h1.store.releaseExecutionSlot("slot-holder", { ownerId: "slot-owner", fencingToken: 1, profileDigest: digest("b") });
    const replay = h2.service.submit(structuredClone(repair));
    assert.equal(replay.state, "repairing"); await tick();
    assert.deepEqual(h2.loadedSessions, ["native-001"]); assert.equal(h2.prompts, 1);
    assert.equal(authorityCalls, 2, "restart replay binds the original repair authority and never re-prompts twice");
    h2.finish(); await tick(); await tick();
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("runtime-bound recovery repair reloads one sealed session with a finding-bound repair authority and no second attempt", async () => {
  let now = 10_000, authorityCalls = 0, approvedRepairSubmissionDigest = null;
  const root = mkdtempSync(join(tmpdir(), "grok-runtime-recovery-repair-"));
  const h1 = harness({
    root, ownerId: "bound-owner-one", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }),
    authority: () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; },
    acpFactory: (hooks) => ({
      async start(input) {
        assert.equal(input.nativeSessionId, null);
        await hooks.onSessionBound({ nativeSessionId: "native-001" });
        await hooks.onFailure();
        throw new Error("simulated ACP interruption after sealed bind");
      }
    })
  });
  const h2 = harness({
    root, ownerId: "bound-owner-two", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }),
    authority: (request) => {
      authorityCalls += 1;
      const allowed = request.mode !== "repair" || request.repairSubmissionDigest === approvedRepairSubmissionDigest;
      return { allowed, grantDigest: allowed ? digest("1") : digest("f"), receiptDigest: allowed ? digest("2") : digest("0") };
    }
  });
  try {
    const submitted = h1.service.submit(submission({ submissionId: "runtime-repair-001", idempotencyKey: "runtime-repair-001" }));
    await tick(); await tick(); await tick();
    const failed = h1.store.readVerified(submitted.jobId);
    assert.equal(failed.job.state, "recovery_required");
    assert.equal(failed.attempts.length, 1);
    const runtime = JSON.parse(readFileSync(join(root, "jobs", submitted.jobId, `runtime-${failed.attempts[0].attemptId}.json`), "utf8")).envelope;
    assert.equal(runtime.nativeSessionId, "native-001");
    const publicSessionId = h1.service.status({ jobId: submitted.jobId, afterCursor: 0 }).events
      .find((event) => event.data?.type === "native_session_bound")?.nativeSessionId;
    assert.match(publicSessionId, /^session-[a-f0-9]{32}$/);
    assert.notEqual(publicSessionId, runtime.nativeSessionId, "the public continuation must not disclose the sealed ACP session ID");
    now = failed.lease.expiresAt + 1;
    const repair = submission({
      submissionId: "runtime-repair-resume-001", mode: "repair", idempotencyKey: "runtime-repair-resume-001",
      continuation: { jobId: submitted.jobId, expectedAttemptId: failed.attempts[0].attemptId, expectedNativeSessionId: publicSessionId },
      findings: [{ code: "runtime-bound-finding", message: "Repair the interrupted bounded task." }]
    });
    approvedRepairSubmissionDigest = digestOf(repair);
    const changedFinding = { ...structuredClone(repair), idempotencyKey: "runtime-repair-other", findings: [{ code: "other-finding", message: "Unauthorized repair finding." }] };
    assert.throws(() => h2.service.submit(changedFinding), /denied|authority/i);
    assert.equal(h2.starts, 0, "an unapproved finding cannot start an ACP repair");
    const changedIdempotency = { ...structuredClone(repair), idempotencyKey: "runtime-repair-other" };
    assert.throws(() => h2.service.submit(changedIdempotency), /denied|authority/i);
    assert.equal(h2.starts, 0, "an authority decision binds the exact repair submission idempotency key");
    const resumed = h2.service.submit(repair);
    assert.equal(resumed.state, "repairing");
    await tick(); await tick();
    assert.deepEqual(h2.loadedSessions, ["native-001"]);
    assert.equal(h2.prompts, 1);
    assert.equal(h2.store.readVerified(submitted.jobId).attempts.length, 1, "same-session recovery never creates attempt two");
    assert.equal(authorityCalls, 4, "only the initial admission and exact repair are allowed; two mutated repair envelopes are denied before ACP");
    h2.finish(); await tick(); await tick(); await tick();
    assert.equal(h2.service.status({ jobId: submitted.jobId }).job.state, "candidate_ready");
    const candidate = h2.store.readVerified(submitted.jobId).bindings.candidate;
    const manifest = JSON.parse(readFileSync(candidateManifestPath(root, submitted.jobId, candidate.manifestDigest), "utf8")).envelope;
    assert.equal(manifest.grantDigest, digest("f"), "immutable runtime retains the initial implementation admission grant");
    assert.equal(manifest.recoveryRepairAuthority.repairGrantDigest, digest("1"));
    assert.equal(manifest.recoveryRepairAuthority.repairReceiptDigest, digest("2"));
    const replay = h2.service.submit(structuredClone(repair));
    assert.equal(replay.state, "candidate_ready");
    assert.equal(h2.prompts, 1, "exact replay cannot send a second repair prompt");
    const snapshotPath = h2.store.snapshotPath(submitted.jobId), originalSnapshot = readFileSync(snapshotPath, "utf8");
    const poisoned = JSON.parse(originalSnapshot); poisoned.recoveryRepair.repairGrantDigest = digest("3"); writeFileSync(snapshotPath, JSON.stringify(poisoned));
    assert.throws(() => h2.service.status({ jobId: submitted.jobId }), /journal|snapshot|faithfully|evidence/i);
    writeFileSync(snapshotPath, originalSnapshot);
    const collectRequest = collection(submitted.jobId, candidate.manifestDigest); collectRequest.expectedAttemptId = candidate.attemptId; collectRequest.idempotencyKey = "runtime-repair-collect"; collectRequest.collectionId = "runtime-repair-collect";
    assert.equal(h2.service.collect(collectRequest).state, "accepted", "distinct repair authority evidence survives candidate validation and collection");
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("expired raw-running process loss requires host child absence and one new same-session repair authority", async () => {
  let now = 11_500, authorityCalls = 0; const absenceProofs = [], authorityRequests = [];
  const root = mkdtempSync(join(tmpdir(), "grok-raw-running-repair-"));
  const authority = (request) => { authorityCalls += 1; authorityRequests.push(structuredClone(request)); return { allowed: true, grantDigest: authorityCalls === 1 ? digest("f") : digest("1"), receiptDigest: authorityCalls === 1 ? digest("0") : digest("2") }; };
  const oldProcess = harness({
    root, ownerId: "raw-running-old", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority,
    acpFactory: (hooks) => ({ async start(input) {
      await hooks.onSessionBound({ nativeSessionId: "native-raw-running", childProcessIdentity: { pid: 7101, startedAt: "2026-08-15T20:00:00.000Z" } });
      for (let index = 0; index < 4; index += 1) await hooks.onEvent({ kind: "thought", nativeSessionId: "native-raw-running", value: { text: `history-${index}` } });
      return { done: new Promise(() => {}), async cancel() { return false; }, child: { stop() {} } };
    } })
  });
  const recovered = harness({
    root, ownerId: "raw-running-new", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority,
    runtimeAcknowledge: (proof) => { absenceProofs.push(proof); return true; }
  });
  const childPresent = harness({
    root, ownerId: "raw-running-child-present", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }), authority, runtimeAcknowledge: () => false
  });
  try {
    const submitted = oldProcess.service.submit(submission({ submissionId: "raw-running-001", idempotencyKey: "raw-running-001" }));
    await tick(); await tick();
    let state = oldProcess.store.readVerified(submitted.jobId); assert.equal(state.job.state, "running"); assert.equal(state.attempts.length, 1);
    oldProcess.store.transition(submitted.jobId, "recovery_required", { fence: state.lease.fencingToken, allowRecovery: true });
    state = oldProcess.store.readVerified(submitted.jobId); assert.equal(state.job.state, "recovery_required", "a restarted controller may durably project the raw-running job as recovery-required");
    const repair = submission({
      submissionId: "raw-running-repair", mode: "repair", idempotencyKey: "raw-running-repair",
      continuation: { jobId: submitted.jobId, expectedAttemptId: state.attempts[0].attemptId, expectedNativeSessionId: "native-raw-running" },
      findings: [{ code: "process-loss", message: "Continue from the exact native session after the invocation host was lost." }]
    });
    assert.throws(() => recovered.service.submit(structuredClone(repair)), /expiry|lease|live/i);
    assert.equal(absenceProofs.length, 0); assert.equal(authorityCalls, 1);
    now = state.lease.expiresAt + 1;
    assert.throws(() => childPresent.service.submit(structuredClone(repair)), /child-absence/i);
    assert.equal(authorityCalls, 1); state = childPresent.store.readVerified(submitted.jobId); now = state.lease.expiresAt + 1;
    recovered.service.submit(repair); await tick(); await tick(); await tick(); await tick();
    assert.equal(absenceProofs.length, 1); assert.equal(absenceProofs[0].childAbsenceRequired, true);
    assert.equal(authorityCalls, 2); assert.deepEqual(recovered.loadedSessions, ["native-raw-running"]); assert.equal(recovered.prompts, 1);
    assert.equal(authorityRequests[1].mode, "repair"); assert.equal(authorityRequests[1].findingsDigest, digestOf(repair.findings));
    assert.match(authorityRequests[1].runtimeRecoveryProofDigest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(recovered.store.readVerified(submitted.jobId).attempts.length, 1);
    recovered.service.submit(structuredClone(repair)); await tick(); assert.equal(authorityCalls, 2); assert.equal(recovered.prompts, 1);
    for (const changed of [
      { ...structuredClone(repair), findings: [{ code: "other", message: "Different finding." }] },
      { ...structuredClone(repair), idempotencyKey: "raw-running-other" },
      { ...structuredClone(repair), continuation: { ...repair.continuation, expectedNativeSessionId: "native-other" } }
    ]) assert.throws(() => recovered.service.submit(changed), /idempotency|finding|session|continuation|active repair|journal evidence/i);
    assert.equal(authorityCalls, 2); assert.equal(recovered.prompts, 1);
    recovered.finish(); await tick(); await tick(); await tick();
    assert.equal(recovered.service.status({ jobId: submitted.jobId }).job.state, "candidate_ready");
  } finally { oldProcess.cleanup(); childPresent.cleanup(); recovered.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("opaque raw-running repair authorization replays its first post-request pre-prompt failure after upgrade", async () => {
  let now = 11_700, authorityCalls = 0;
  const root = mkdtempSync(join(tmpdir(), "grok-raw-running-opaque-retry-"));
  const authority = () => {
    authorityCalls += 1;
    return { allowed: true, grantDigest: authorityCalls === 1 ? digest("f") : digest("1"), receiptDigest: authorityCalls === 1 ? digest("0") : digest("2") };
  };
  const oldProcess = harness({
    root, ownerId: "raw-opaque-old", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority,
    acpFactory: (hooks) => ({ async start() {
      await hooks.onSessionBound({ nativeSessionId: "native-raw-opaque", childProcessIdentity: { pid: 7102, startedAt: "2026-08-15T20:01:00.000Z" } });
      await hooks.onEvent({ kind: "thought", nativeSessionId: "native-raw-opaque", value: { text: "pre-repair history" } });
      return { done: new Promise(() => {}), async cancel() { return false; }, child: { stop() {} } };
    } })
  });
  const failedRepair = harness({
    root, ownerId: "raw-opaque-failed-repair", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority,
    runtimeAcknowledge: () => true,
    acpFactory: () => ({ async start() { throw new Error("pre-prompt service launch failure"); } })
  });
  const replay = harness({
    root, ownerId: "raw-opaque-replay", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority
  });
  try {
    const submitted = oldProcess.service.submit(submission({ submissionId: "raw-opaque-001", idempotencyKey: "raw-opaque-001" }));
    await tick(); await tick();
    let state = oldProcess.store.readVerified(submitted.jobId); now = state.lease.expiresAt + 1;
    const repair = submission({
      submissionId: "raw-opaque-repair", mode: "repair", idempotencyKey: "raw-opaque-repair",
      continuation: { jobId: submitted.jobId, expectedAttemptId: state.attempts[0].attemptId, expectedNativeSessionId: "native-raw-opaque" },
      findings: [{ code: "raw-opaque", message: "Resume the already-authorized raw-running repair after the controller upgrade." }]
    });
    failedRepair.service.submit(repair); await tick(); await tick(); await tick();
    state = failedRepair.store.readVerified(submitted.jobId);
    assert.equal(state.job.state, "recovery_required");
    assert.equal(authorityCalls, 2);
    const failure = failedRepair.store.readStatus(submitted.jobId, { afterCursor: 0 }).events.filter((event) => event.kind === "failure");
    assert.equal(failure.length, 1);
    assert.equal(failure[0].data.code, "service_execution_failed");
    assert.equal(failure[0].data.serviceStage, "adapter_start");
    rewriteRecoveryRepairProof(failedRepair.store, submitted.jobId, digest("7"));
    state = failedRepair.store.readVerified(submitted.jobId); now = state.lease.expiresAt + 1;
    replay.service.submit(structuredClone(repair)); await tick(); await tick();
    assert.equal(authorityCalls, 2, "the exact historical repair grant is reused");
    assert.deepEqual(replay.loadedSessions, ["native-raw-opaque"]);
    assert.equal(replay.prompts, 1);
  } finally { oldProcess.cleanup(); failedRepair.cleanup(); replay.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("raw-running recovery repair rejects terminal, candidate, usage, and cancellation evidence before host proof", async (t) => {
  for (const mode of ["terminal", "candidate", "usage", "cancel"]) await t.test(mode, async () => {
    let now = 11_800, authorityCalls = 0, absenceCalls = 0;
    const root = mkdtempSync(join(tmpdir(), `grok-raw-running-${mode}-`));
    const authority = () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; };
    const oldProcess = harness({
      root, ownerId: `raw-${mode}-old`, leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority,
      acpFactory: (hooks) => ({ async start() { await hooks.onSessionBound({ nativeSessionId: `native-${mode}` }); return { done: new Promise(() => {}), async cancel() { return false; }, child: { stop() {} } }; } })
    });
    const recovered = harness({
      root, ownerId: `raw-${mode}-new`, leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority,
      runtimeAcknowledge: () => { absenceCalls += 1; return true; }
    });
    try {
      const submitted = oldProcess.service.submit(submission({ submissionId: `raw-${mode}-001`, idempotencyKey: `raw-${mode}-001` })); await tick(); await tick();
      let state = oldProcess.store.readVerified(submitted.jobId), last = oldProcess.store.readStatus(submitted.jobId, { afterCursor: 0 }).events.at(-1);
      if (["terminal", "candidate"].includes(mode)) oldProcess.store.appendEvent(submitted.jobId, {
        contractVersion: CONTRACT_VERSIONS.event, eventId: `event-raw-${mode}`, jobId: submitted.jobId, attemptId: state.attempts[0].attemptId,
        fencingToken: state.lease.fencingToken, nativeSessionId: last.nativeSessionId, requestId: last.requestId,
        cursor: last.cursor + 1, sequence: last.sequence + 1, kind: "progress", occurredAt: new Date(now).toISOString(), data: { type: mode === "terminal" ? "native_terminal" : "provider_candidate_ready" }
      }, { fence: state.lease.fencingToken });
      if (mode === "usage") oldProcess.store.recordUsage(submitted.jobId, { usage: { contractVersion: CONTRACT_VERSIONS.usage, inputTokens: 1, outputTokens: 1, totalTokens: 2 }, fence: state.lease.fencingToken });
      if (mode === "cancel") oldProcess.store.beginCancellation(submitted.jobId, { reason: "operator-requested", idempotencyKey: `raw-${mode}-cancel`, fence: state.lease.fencingToken });
      state = oldProcess.store.readVerified(submitted.jobId); now = state.lease.expiresAt + 1;
      const repair = submission({
        submissionId: `raw-${mode}-repair`, mode: "repair", idempotencyKey: `raw-${mode}-repair`,
        continuation: { jobId: submitted.jobId, expectedAttemptId: state.attempts[0].attemptId, expectedNativeSessionId: `native-${mode}` },
        findings: [{ code: `raw-${mode}`, message: "Must fail before another prompt." }]
      });
      assert.throws(() => recovered.service.submit(repair), /preconditions|journal evidence|only recovery/i);
      assert.equal(authorityCalls, 1); assert.equal(absenceCalls, 0); assert.equal(recovered.starts, 0);
    } finally { oldProcess.cleanup(); recovered.cleanup(); rmSync(root, { recursive: true, force: true }); }
  });
});

test("exact recovery repair replay retries pre-prompt session/load failures without new authority, attempt, or duplicate prompt", async () => {
  let now = 12_000, authorityCalls = 0, failedLoads = 0;
  const root = mkdtempSync(join(tmpdir(), "grok-runtime-repair-load-retry-"));
  const authority = (request) => { authorityCalls += 1; return { allowed: true, grantDigest: request.mode === "repair" ? digest("1") : digest("f"), receiptDigest: request.mode === "repair" ? digest("2") : digest("0") }; };
  const boundFailure = (hooks) => ({ async start() { await hooks.onSessionBound({ nativeSessionId: "native-001" }); await hooks.onFailure(); throw new Error("initial bound ACP interruption"); } });
  const loadFailure = (hooks) => ({ async start(input) { assert.equal(input.nativeSessionId, "native-001"); failedLoads += 1; await hooks.onFailure(); throw new Error("session/load failed before repair prompt"); } });
  const make = (ownerId, acpFactory = null) => harness({
    root, ownerId, leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority,
    ...(acpFactory === null ? {} : { acpFactory })
  });
  const h1 = make("repair-load-initial", boundFailure), h2 = make("repair-load-retry-one", loadFailure),
    h3 = make("repair-load-retry-two", loadFailure), h4 = make("repair-load-success");
  try {
    const submitted = h1.service.submit(submission({ submissionId: "repair-load-retry-001", idempotencyKey: "repair-load-retry-001" }));
    await tick(); await tick(); await tick();
    let state = h1.store.readVerified(submitted.jobId); now = state.lease.expiresAt + 1;
    const repair = submission({
      submissionId: "repair-load-retry-request", mode: "repair", idempotencyKey: "repair-load-retry-request",
      continuation: { jobId: submitted.jobId, expectedAttemptId: state.attempts[0].attemptId, expectedNativeSessionId: "native-001" },
      findings: [{ code: "repair-load-retry", message: "Continue the exact authorized repair after bounded load recovery." }]
    });
    h2.service.submit(repair); await tick(); await tick(); await tick();
    state = h2.store.readVerified(submitted.jobId); assert.equal(state.job.state, "recovery_required"); assert.equal(authorityCalls, 2);
    const durableRepair = structuredClone(state.recoveryRepair), firstRetryFence = state.lease.fencingToken;
    now = state.lease.expiresAt + 1;
    h3.service.submit(structuredClone(repair)); await tick(); await tick(); await tick();
    state = h3.store.readVerified(submitted.jobId); assert.equal(state.job.state, "recovery_required"); assert.equal(authorityCalls, 2);
    assert.equal(state.lease.fencingToken, firstRetryFence + 1); const secondRetryFence = state.lease.fencingToken;
    assert.deepEqual(state.recoveryRepair, durableRepair, "retry evidence never rewrites the original proof or authority receipts");
    now = state.lease.expiresAt + 1;
    h4.service.submit(structuredClone(repair)); await tick(); await tick();
    assert.equal(authorityCalls, 2, "all load retries reuse the original implementation and repair grants");
    assert.equal(failedLoads, 2); assert.deepEqual(h4.loadedSessions, ["native-001"]); assert.equal(h4.prompts, 1);
    state = h4.store.readVerified(submitted.jobId);
    assert.equal(state.attempts.length, 1); assert.equal(state.lease.fencingToken, secondRetryFence + 1);
    assert.equal(h4.store.readExecutionSlot().fencingToken, state.lease.fencingToken);
    assert.deepEqual(state.recoveryRepair, durableRepair);
    h4.finish(); await tick(); await tick(); await tick();
    assert.equal(h4.service.status({ jobId: submitted.jobId }).job.state, "candidate_ready");
    const events = h4.store.readStatus(submitted.jobId, { afterCursor: 0 }).events;
    assert.equal(events.filter((event) => event.kind === "failure" && event.data?.code === "acp_failure").length, 3);
    assert.equal(events.filter((event) => event.data?.type === "recovery_repair_prompted").length, 1);
  } finally { h1.cleanup(); h2.cleanup(); h3.cleanup(); h4.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("recovery repair retry binds an opaque journal-authorized proof to current evidence after upgrade", async () => {
  let now = 12_500, authorityCalls = 0;
  const root = mkdtempSync(join(tmpdir(), "grok-runtime-repair-proof-upgrade-"));
  const authority = (request) => { authorityCalls += 1; return { allowed: true, grantDigest: request.mode === "repair" ? digest("1") : digest("f"), receiptDigest: request.mode === "repair" ? digest("2") : digest("0") }; };
  const make = (ownerId, acpFactory = null) => harness({
    root, ownerId, leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority,
    ...(acpFactory === null ? {} : { acpFactory })
  });
  const h1 = make("proof-upgrade-initial", (hooks) => ({ async start() { await hooks.onSessionBound({ nativeSessionId: "native-001" }); await hooks.onFailure(); throw new Error("initial interruption"); } }));
  const h2 = make("proof-upgrade-load", (hooks) => ({ async start() { await hooks.onFailure(); throw new Error("pre-prompt load interruption"); } }));
  const h3 = make("proof-upgrade-success");
  try {
    const submitted = h1.service.submit(submission({ submissionId: "repair-proof-upgrade-001", idempotencyKey: "repair-proof-upgrade-001" }));
    await tick(); await tick(); await tick();
    let state = h1.store.readVerified(submitted.jobId);
    const attempt = state.attempts[0];
    const opaqueHistoricalProofDigest = digest("7");
    now = state.lease.expiresAt + 1;
    const repair = submission({
      submissionId: "repair-proof-upgrade-request", mode: "repair", idempotencyKey: "repair-proof-upgrade-request",
      continuation: { jobId: submitted.jobId, expectedAttemptId: attempt.attemptId, expectedNativeSessionId: "native-001" },
      findings: [{ code: "proof-upgrade", message: "Resume the already-authorized repair after the controller upgrade." }]
    });
    h2.service.submit(repair); await tick(); await tick(); await tick();
    state = h2.store.readVerified(submitted.jobId);
    assert.notEqual(state.recoveryRepair.recoveryProofDigest, opaqueHistoricalProofDigest, "the fixture starts with the current reconstructible proof");
    rewriteRecoveryRepairProof(h2.store, submitted.jobId, opaqueHistoricalProofDigest);
    state = h2.store.readVerified(submitted.jobId); now = state.lease.expiresAt + 1;
    const durableSnapshotPath = h2.store.snapshotPath(submitted.jobId), durableSnapshot = readFileSync(durableSnapshotPath, "utf8");
    const tamperedSnapshot = JSON.parse(durableSnapshot); tamperedSnapshot.recoveryRepair.repairReceiptDigest = digest("3");
    writeFileSync(durableSnapshotPath, JSON.stringify(tamperedSnapshot));
    assert.throws(() => h3.service.submit(structuredClone(repair)), /journal|snapshot|faithfully/i);
    writeFileSync(durableSnapshotPath, durableSnapshot);
    const changedFindings = { ...structuredClone(repair), findings: [{ code: "different-upgrade-finding", message: "This was not the authorized finding." }] };
    assert.throws(() => h3.service.submit(changedFindings), /opaque authorization|finding|receipt/i);
    assert.equal(h3.starts, 0); assert.equal(authorityCalls, 2);
    h3.service.submit(structuredClone(repair)); await tick(); await tick();
    assert.equal(authorityCalls, 2, "upgrade replay reuses the exact historical repair grant and receipt");
    assert.deepEqual(h3.loadedSessions, ["native-001"]); assert.equal(h3.prompts, 1);
    assert.equal(h3.store.readVerified(submitted.jobId).recoveryRepair.recoveryProofDigest, opaqueHistoricalProofDigest);
  } finally { h1.cleanup(); h2.cleanup(); h3.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("recovery repair retry rejects an unrelated ACP failure tail before authority or another session/load", async () => {
  let now = 13_000, authorityCalls = 0;
  const root = mkdtempSync(join(tmpdir(), "grok-runtime-repair-load-poison-"));
  const authority = (request) => { authorityCalls += 1; return { allowed: true, grantDigest: request.mode === "repair" ? digest("1") : digest("f"), receiptDigest: request.mode === "repair" ? digest("2") : digest("0") }; };
  const h1 = harness({
    root, ownerId: "repair-poison-initial", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority,
    acpFactory: (hooks) => ({ async start() { await hooks.onSessionBound({ nativeSessionId: "native-001" }); await hooks.onFailure(); throw new Error("initial bound ACP interruption"); } })
  });
  const h2 = harness({
    root, ownerId: "repair-poison-load", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority,
    acpFactory: (hooks) => ({ async start() { await hooks.onFailure(); throw new Error("pre-prompt load failure"); } })
  });
  const h3 = harness({ root, ownerId: "repair-poison-replay", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority });
  try {
    const submitted = h1.service.submit(submission({ submissionId: "repair-load-poison-001", idempotencyKey: "repair-load-poison-001" }));
    await tick(); await tick(); await tick();
    let state = h1.store.readVerified(submitted.jobId); now = state.lease.expiresAt + 1;
    const repair = submission({
      submissionId: "repair-load-poison-request", mode: "repair", idempotencyKey: "repair-load-poison-request",
      continuation: { jobId: submitted.jobId, expectedAttemptId: state.attempts[0].attemptId, expectedNativeSessionId: "native-001" },
      findings: [{ code: "repair-load-poison", message: "Do not cross unexpected replay evidence." }]
    });
    h2.service.submit(repair); await tick(); await tick(); await tick();
    state = h2.store.readVerified(submitted.jobId); const events = h2.store.readStatus(submitted.jobId, { afterCursor: 0 }).events, last = events.at(-1);
    rewriteRecoveryRepairProof(h2.store, submitted.jobId, digest("7"));
    h2.store.appendEvent(submitted.jobId, {
      contractVersion: CONTRACT_VERSIONS.event, eventId: "event-intervening-retry", jobId: submitted.jobId, attemptId: state.attempts[0].attemptId,
      fencingToken: state.lease.fencingToken, nativeSessionId: last.nativeSessionId, requestId: "request-unrelated-retry",
      cursor: last.cursor + 1, sequence: last.sequence + 1, kind: "failure", occurredAt: new Date(now).toISOString(), data: { code: "acp_failure" }
    }, { fence: state.lease.fencingToken });
    state = h2.store.readVerified(submitted.jobId); now = state.lease.expiresAt + 1;
    assert.throws(() => h3.service.submit(structuredClone(repair)), /sealed request|session|fence sequence/i);
    assert.equal(authorityCalls, 2); assert.equal(h3.starts, 0); assert.equal(h3.prompts, 0);
  } finally { h1.cleanup(); h2.cleanup(); h3.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("recovery repair never retries after the durable repair-prompt boundary", async () => {
  let now = 14_000, authorityCalls = 0;
  const root = mkdtempSync(join(tmpdir(), "grok-runtime-repair-prompt-boundary-"));
  const authority = (request) => { authorityCalls += 1; return { allowed: true, grantDigest: request.mode === "repair" ? digest("1") : digest("f"), receiptDigest: request.mode === "repair" ? digest("2") : digest("0") }; };
  const h1 = harness({
    root, ownerId: "repair-prompt-initial", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority,
    acpFactory: (hooks) => ({ async start() { await hooks.onSessionBound({ nativeSessionId: "native-001" }); await hooks.onFailure(); throw new Error("initial bound ACP interruption"); } })
  });
  const h2 = harness({
    root, ownerId: "repair-prompt-crossed", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority,
    acpFactory: (hooks) => ({ async start() { await hooks.onSessionBound({ nativeSessionId: "native-001" }); await hooks.onPromptDispatch({}); await hooks.onFailure(); throw new Error("repair failed after prompt boundary"); } })
  });
  const h3 = harness({ root, ownerId: "repair-prompt-replay", leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority });
  try {
    const submitted = h1.service.submit(submission({ submissionId: "repair-prompt-boundary-001", idempotencyKey: "repair-prompt-boundary-001" }));
    await tick(); await tick(); await tick();
    let state = h1.store.readVerified(submitted.jobId); now = state.lease.expiresAt + 1;
    const repair = submission({
      submissionId: "repair-prompt-boundary-request", mode: "repair", idempotencyKey: "repair-prompt-boundary-request",
      continuation: { jobId: submitted.jobId, expectedAttemptId: state.attempts[0].attemptId, expectedNativeSessionId: "native-001" },
      findings: [{ code: "repair-prompt-boundary", message: "Never duplicate this repair prompt." }]
    });
    h2.service.submit(repair); await tick(); await tick(); await tick();
    state = h2.store.readVerified(submitted.jobId); const events = h2.store.readStatus(submitted.jobId, { afterCursor: 0 }).events;
    assert.equal(events.filter((event) => event.data?.type === "recovery_repair_prompted").length, 1);
    now = state.lease.expiresAt + 1;
    assert.throws(() => h3.service.submit(structuredClone(repair)), /journal evidence|prompt|boundary/i);
    assert.equal(authorityCalls, 2); assert.equal(h3.starts, 0); assert.equal(h3.prompts, 0);
  } finally { h1.cleanup(); h2.cleanup(); h3.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("runtime recovery binds the stable profile attestation fingerprint across restart timestamps", async () => {
  let now = 15_000, repairProfileProof = undefined;
  const root = mkdtempSync(join(tmpdir(), "grok-runtime-profile-reattestation-"));
  const profileAt = (attestedAt, fingerprint = digest("8")) => ({
    profileId: "hermetic", profileDigest: digest("b"),
    attestation: { profileId: "hermetic", profileDigest: digest("b"), fingerprint, attestedAt }, inspection: {}
  });
  const h1 = harness({
    root, ownerId: "profile-restart-one", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }), profileFactory: () => profileAt("2026-08-15T00:00:00.000Z"),
    acpFactory: (hooks) => ({ async start() { await hooks.onSessionBound({ nativeSessionId: "native-001" }); await hooks.onFailure(); throw new Error("bound ACP interruption"); } })
  });
  const h2 = harness({
    root, ownerId: "profile-restart-two", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }), profileFactory: () => profileAt("2026-08-15T00:01:00.000Z"),
    authority: (request) => {
      if (request.mode === "repair") repairProfileProof = request.legacyRecoveryProfileProofDigest;
      return { allowed: true, grantDigest: digest("1"), receiptDigest: digest("2") };
    }
  });
  try {
    const initial = submission({ submissionId: "profile-restart-001", idempotencyKey: "profile-restart-001" });
    const submitted = h1.service.submit(initial); await tick(); await tick(); await tick();
    const failed = h1.store.readVerified(submitted.jobId); now = failed.lease.expiresAt + 1;
    const repair = submission({
      submissionId: "profile-restart-repair", mode: "repair", idempotencyKey: "profile-restart-repair",
      continuation: { jobId: submitted.jobId, expectedAttemptId: failed.attempts.at(-1).attemptId, expectedNativeSessionId: "native-001" },
      findings: [{ code: "profile-restart", message: "Continue the sealed session after host restart." }]
    });
    assert.doesNotThrow(() => h2.service.submit(repair));
    assert.equal(repairProfileProof, null, "new stable-fingerprint envelopes need no legacy compatibility exception");
    await tick(); assert.deepEqual(h2.loadedSessions, ["native-001"]);
    h2.finish(); await tick(); await tick();
    assert.equal(h2.service.status({ jobId: submitted.jobId }).job.state, "candidate_ready");
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("runtime recovery binds a stable-fingerprint migration to one-use repair authority", async () => {
  let now = 16_000, authorityCalls = 0, expectedMigrationProof = null;
  const root = mkdtempSync(join(tmpdir(), "grok-runtime-profile-drift-"));
  const profile = (fingerprint) => ({ profileId: "hermetic", profileDigest: digest("b"), attestation: { profileId: "hermetic", profileDigest: digest("b"), fingerprint }, inspection: {} });
  const h1 = harness({
    root, ownerId: "profile-drift-one", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }), profileFactory: () => profile(digest("8")),
    acpFactory: (hooks) => ({ async start() { await hooks.onSessionBound({ nativeSessionId: "native-001" }); await hooks.onFailure(); throw new Error("bound ACP interruption"); } })
  });
  const h2 = harness({
    root, ownerId: "profile-drift-two", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }), profileFactory: () => profile(digest("7")),
    authority: (request) => {
      authorityCalls += 1;
      const allowed = request.mode === "repair" && request.legacyRecoveryProfileProofDigest === expectedMigrationProof;
      return { allowed, grantDigest: allowed ? digest("1") : digest("f"), receiptDigest: allowed ? digest("2") : digest("0") };
    }
  });
  try {
    const submitted = h1.service.submit(submission({ submissionId: "profile-drift-001", idempotencyKey: "profile-drift-001" }));
    await tick(); await tick(); await tick();
    const failed = h1.store.readVerified(submitted.jobId); now = failed.lease.expiresAt + 1;
    const envelope = JSON.parse(readFileSync(envelopePath(root, submitted.jobId), "utf8")).envelope;
    expectedMigrationProof = digestOf({
      contractVersion: "agent-platform.grok-builder-legacy-profile-reattestation.v1", operation: "repair_profile_reattestation_v1",
      jobId: submitted.jobId, profileId: envelope.profileId, profileDigest: envelope.profileDigest,
      oldAttestationFingerprint: digest("8"), newAttestationFingerprint: digest("7"),
      contextDigest: failed.serviceContext.contextDigest, sourceCustodyDigest: envelope.sourceCustodyDigest,
      worktreeCustodyDigest: envelope.custody.worktreeCustodyDigest
    });
    const repair = submission({
      submissionId: "profile-drift-repair", mode: "repair", idempotencyKey: "profile-drift-repair",
      continuation: { jobId: submitted.jobId, expectedAttemptId: failed.attempts.at(-1).attemptId, expectedNativeSessionId: "native-001" },
      findings: [{ code: "profile-drift", message: "This must not resume under changed attested capabilities." }]
    });
    assert.doesNotThrow(() => h2.service.submit(repair));
    assert.equal(authorityCalls, 1);
    await tick(); assert.equal(h2.starts, 1); assert.deepEqual(h2.loadedSessions, ["native-001"]);
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("model-bound headless admissions ignore volatile launcher fingerprint drift", async () => {
  let now = 16_500, repairProfileProof = undefined;
  const root = mkdtempSync(join(tmpdir(), "grok-runtime-headless-profile-continuity-"));
  const profile = (fingerprint) => ({ profileId: "hermetic", profileDigest: digest("b"), attestation: { profileId: "hermetic", profileDigest: digest("b"), fingerprint }, inspection: {} });
  const h1 = harness({
    root, ownerId: "headless-profile-one", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }), profileFactory: () => profile(digest("8")),
    authority: () => ({ allowed: true, grantDigest: digest("1"), receiptDigest: digest("2"), model: "grok-4.6" }),
    acpFactory: (hooks) => ({ async start() { await hooks.onSessionBound({ nativeSessionId: "native-001" }); await hooks.onFailure(); throw new Error("bound headless interruption"); } })
  });
  const h2 = harness({
    root, ownerId: "headless-profile-two", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }), profileFactory: () => profile(digest("7")),
    authority: (request) => {
      if (request.mode === "repair") repairProfileProof = request.legacyRecoveryProfileProofDigest;
      return { allowed: true, grantDigest: digest("1"), receiptDigest: digest("2"), model: "grok-4.6" };
    }
  });
  try {
    const submitted = h1.service.submit(submission({ submissionId: "headless-profile-001", idempotencyKey: "headless-profile-001" }));
    await tick(); await tick(); await tick();
    const failed = h1.store.readVerified(submitted.jobId); now = failed.lease.expiresAt + 1;
    const repair = submission({
      submissionId: "headless-profile-repair", mode: "repair", idempotencyKey: "headless-profile-repair",
      continuation: { jobId: submitted.jobId, expectedAttemptId: failed.attempts.at(-1).attemptId, expectedNativeSessionId: "native-001" },
      findings: [{ code: "headless-profile", message: "Resume the exact model-bound headless session." }]
    });
    assert.doesNotThrow(() => h2.service.submit(repair));
    assert.equal(repairProfileProof, null, "volatile launcher drift does not require unrelated provider authority");
    await tick(); assert.deepEqual(h2.loadedSessions, ["native-001"]);
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("legacy timestamped envelopes require an exact re-attestation proof in one-use repair authority", async () => {
  let now = 17_000, expectedLegacyProof = null, authorityCalls = 0;
  const root = mkdtempSync(join(tmpdir(), "grok-runtime-legacy-profile-"));
  const profileAt = (attestedAt) => ({
    profileId: "hermetic", profileDigest: digest("b"),
    attestation: { profileId: "hermetic", profileDigest: digest("b"), fingerprint: digest("8"), attestedAt }, inspection: {}
  });
  const h1 = harness({
    root, ownerId: "legacy-profile-one", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }), profileFactory: () => profileAt("2026-08-15T00:00:00.000Z"),
    acpFactory: (hooks) => ({ async start() { await hooks.onSessionBound({ nativeSessionId: "native-001" }); await hooks.onFailure(); throw new Error("bound ACP interruption"); } })
  });
  const h2 = harness({
    root, ownerId: "legacy-profile-two", leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now }), profileFactory: () => profileAt("2026-08-15T00:02:00.000Z"),
    authority: (request) => {
      authorityCalls += 1;
      const allowed = request.mode !== "repair" || request.legacyRecoveryProfileProofDigest === expectedLegacyProof;
      return { allowed, grantDigest: allowed ? digest("1") : digest("f"), receiptDigest: allowed ? digest("2") : digest("0") };
    }
  });
  try {
    const submitted = h1.service.submit(submission({ submissionId: "legacy-profile-001", idempotencyKey: "legacy-profile-001" }));
    await tick(); await tick(); await tick();
    const failed = h1.store.readVerified(submitted.jobId); now = failed.lease.expiresAt + 1;
    const path = envelopePath(root, submitted.jobId);
    rewriteSeal(path, (envelope) => { delete envelope.attestationBindingVersion; delete envelope.attestationFingerprint; });
    const legacyEnvelope = JSON.parse(readFileSync(path, "utf8")).envelope;
    expectedLegacyProof = digestOf({
      contractVersion: "agent-platform.grok-builder-legacy-profile-reattestation.v1", operation: "repair_profile_reattestation", jobId: submitted.jobId,
      profileId: legacyEnvelope.profileId, profileDigest: legacyEnvelope.profileDigest,
      legacyAttestationDigest: legacyEnvelope.attestationDigest, currentAttestationFingerprint: digest("8"),
      contextDigest: failed.serviceContext.contextDigest, sourceCustodyDigest: legacyEnvelope.sourceCustodyDigest,
      worktreeCustodyDigest: legacyEnvelope.custody.worktreeCustodyDigest
    });
    const repair = submission({
      submissionId: "legacy-profile-repair", mode: "repair", idempotencyKey: "legacy-profile-repair",
      continuation: { jobId: submitted.jobId, expectedAttemptId: failed.attempts.at(-1).attemptId, expectedNativeSessionId: "native-001" },
      findings: [{ code: "legacy-profile", message: "Continue only with approved current re-attestation." }]
    });
    const originalLegacyDigest = legacyEnvelope.attestationDigest;
    rewriteSeal(path, (envelope) => { envelope.attestationDigest = digest("6"); });
    assert.throws(() => h2.service.submit(structuredClone(repair)), /denied|authority/i, "a recomputed legacy digest changes the authority-bound proof");
    assert.equal(h2.starts, 0);
    rewriteSeal(path, (envelope) => { envelope.attestationDigest = originalLegacyDigest; });
    assert.doesNotThrow(() => h2.service.submit(repair));
    assert.equal(authorityCalls, 2, "tampered and exact legacy repairs each reach the one-use authority with different proofs");
    await tick(); assert.deepEqual(h2.loadedSessions, ["native-001"]);
    h2.finish(); await tick(); await tick();
    assert.equal(h2.service.status({ jobId: submitted.jobId }).job.state, "candidate_ready");
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("runtime recovery repair permits pre-bind ACP history but only resumes the final sealed attempt", async () => {
  let now = 20_000, authorities = 0;
  const root = mkdtempSync(join(tmpdir(), "grok-runtime-recovery-history-"));
  const authority = () => { authorities += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; };
  const preBindFailure = (hooks) => ({ async start() { await hooks.onFailure(); throw new Error("pre-bind ACP failure"); } });
  const boundFailure = (hooks) => ({ async start() { await hooks.onSessionBound({ nativeSessionId: "native-001" }); await hooks.onFailure(); throw new Error("bound ACP failure"); } });
  const owners = ["history-one", "history-two", "history-three", "history-four", "history-five"];
  const h1 = harness({ root, ownerId: owners[0], leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority, acpFactory: preBindFailure });
  const h2 = harness({ root, ownerId: owners[1], leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority, acpFactory: preBindFailure });
  const h3 = harness({ root, ownerId: owners[2], leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority, acpFactory: preBindFailure });
  const h4 = harness({ root, ownerId: owners[3], leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority, acpFactory: boundFailure });
  const h5 = harness({ root, ownerId: owners[4], leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }), authority });
  try {
    const initial = submission({ submissionId: "runtime-history-001", idempotencyKey: "runtime-history-001" });
    const submitted = h1.service.submit(initial); await tick(); await tick(); await tick();
    for (const prior of [h2, h3, h4]) {
      const state = prior.store.readVerified(submitted.jobId); now = state.lease.expiresAt + 1;
      prior.service.submit(structuredClone(initial)); await tick(); await tick(); await tick();
    }
    const failed = h4.store.readVerified(submitted.jobId);
    assert.equal(failed.attempts.length, 4);
    assert.ok(failed.attempts.slice(0, -1).every((attempt) => !existsSync(join(root, "jobs", submitted.jobId, `runtime-${attempt.attemptId}.json`))));
    assert.ok(existsSync(join(root, "jobs", submitted.jobId, `runtime-${failed.attempts.at(-1).attemptId}.json`)));
    now = failed.lease.expiresAt + 1;
    const repair = submission({
      submissionId: "runtime-history-repair", mode: "repair", idempotencyKey: "runtime-history-repair",
      continuation: { jobId: submitted.jobId, expectedAttemptId: failed.attempts.at(-1).attemptId, expectedNativeSessionId: "native-001" },
      findings: [{ code: "history-finding", message: "Repair the sealed final attempt." }]
    });
    const malformedPriorRuntime = join(root, "jobs", submitted.jobId, `runtime-${failed.attempts[0].attemptId}.json`);
    writeFileSync(malformedPriorRuntime, "{}");
    assert.throws(() => h5.service.submit(structuredClone(repair)), /prior attempt|runtime evidence|native session/i);
    assert.equal(h5.starts, 0, "malformed earlier attempt evidence fails before ACP");
    rmSync(malformedPriorRuntime, { force: true });
    h5.service.submit(repair); await tick(); await tick();
    assert.deepEqual(h5.loadedSessions, ["native-001"]);
    assert.equal(h5.store.readVerified(submitted.jobId).attempts.length, 4);
    assert.equal(authorities, 2, "only original admission and finding-bound repair authority are consumed");
    h5.finish(); await tick(); await tick();
  } finally { h1.cleanup(); h2.cleanup(); h3.cleanup(); h4.cleanup(); h5.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("journal-bound provider evidence recovers a manifest-to-publication interruption without another ACP prompt", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-candidate-publication-")); let authorityCalls = 0;
  const h1 = harness({
    root, ownerId: "candidate-owner", delayed: false,
    store: new JobStore({ stateRoot: root, faults: { beforeCandidatePublication: true } }),
    authority: () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; }
  });
  const h2 = harness({
    root, ownerId: "candidate-owner", store: new JobStore({ stateRoot: root }),
    authority: () => { authorityCalls += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; }
  });
  try {
    const submitted = h1.service.submit(submission({ submissionId: "candidate-publication-001", idempotencyKey: "candidate-publication-001" }));
    await tick(); await tick(); await tick();
    assert.equal(h1.store.readVerified(submitted.jobId).job.state, "recovery_required");
    const beforeRecoveryCursor = h1.store.readVerified(submitted.jobId).job.eventCursor;
    const recovered = h2.service.status({ jobId: submitted.jobId, afterCursor: beforeRecoveryCursor });
    assert.equal(recovered.job.state, "candidate_ready");
    assert.ok(recovered.candidate?.providerCandidateDigest);
    assert.equal(recovered.events.length, 1, "recovery must replay its new convenience event from the caller cursor");
    assert.equal(recovered.events[0].kind, "candidate_ready");
    assert.equal(recovered.events[0].cursor, recovered.job.eventCursor);
    assert.deepEqual(h2.service.status({ jobId: submitted.jobId, afterCursor: recovered.job.eventCursor }).events, []);
    assert.equal(h1.prompts, 1); assert.equal(h2.prompts, 0);
    assert.equal(authorityCalls, 1, "candidate publication recovery does not call protected authority");
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("a recomputed runtime seal cannot poison candidate publication or recovery", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-runtime-seal-"));
  const h1 = harness({ root, ownerId: "runtime-seal-owner", delayed: false, store: new JobStore({ stateRoot: root, faults: { beforeCandidatePublication: true } }) });
  const h2 = harness({ root, ownerId: "runtime-seal-owner", store: new JobStore({ stateRoot: root }) });
  try {
    const submitted = h1.service.submit(submission({ submissionId: "runtime-seal-001", idempotencyKey: "runtime-seal-001" }));
    await tick(); await tick(); await tick();
    const attempt = h1.store.readVerified(submitted.jobId).attempts.at(-1);
    rewriteSeal(join(root, "jobs", submitted.jobId, `runtime-${attempt.attemptId}.json`), (runtime) => {
      runtime.nativeSessionId = "poisoned-native-session";
      runtime.requestId = "request-poisoned";
      runtime.fencingToken = 99;
    });
    const status = h2.service.status({ jobId: submitted.jobId });
    assert.equal(status.job.state, "recovery_required");
    assert.equal(h2.store.readVerified(submitted.jobId).bindings.candidate, null);
    assert.equal(h2.starts, 0);
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("a published candidate also rejects recomputed native runtime evidence", async () => {
  const h = harness();
  try {
    const submitted = await ready(h, submission({ submissionId: "published-runtime-seal-001", idempotencyKey: "published-runtime-seal-001" }));
    const attempt = h.store.readVerified(submitted.jobId).attempts.at(-1);
    rewriteSeal(join(h.root, "jobs", submitted.jobId, `runtime-${attempt.attemptId}.json`), (runtime) => {
      runtime.nativeSessionId = "poisoned-published-session";
      runtime.requestId = "request-poisoned";
      runtime.fencingToken = 88;
    });
    const status = h.service.status({ jobId: submitted.jobId });
    assert.equal(status.job.state, "recovery_required");
    assert.equal(status.candidate, null);
    assert.equal(h.starts, 1, "validation failure cannot schedule another child");
  } finally { h.cleanup(); }
});

test("status failure never emits raw path-shaped custody errors", async () => {
  const h = harness(); const observed = []; const priorError = console.error;
  try {
    const submitted = await ready(h, submission({ submissionId: "redacted-status-001", idempotencyKey: "redacted-status-001" }));
    h.custody.revalidate = () => { throw new Error("C:\\private\\secret-token\\path"); };
    console.error = (...values) => observed.push(values);
    const status = h.service.status({ jobId: submitted.jobId });
    assert.equal(status.job.state, "recovery_required");
    assert.deepEqual(observed, []);
  } finally { console.error = priorError; h.cleanup(); }
});

test("provider-event-bound candidate recovery retires only its stale slot and leaves an unrelated live slot alone", async () => {
  let now = 50_000; const root = mkdtempSync(join(tmpdir(), "grok-expired-candidate-")); let authorities = 0;
  const h1 = harness({
    root, ownerId: "old-candidate-owner", delayed: false, leaseDurationMs: 100, heartbeatMs: 25,
    store: new JobStore({ stateRoot: root, now: () => now, faults: { beforeCandidatePublication: true } }),
    authority: () => { authorities += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; }
  });
  const h2 = harness({
    root, ownerId: "new-candidate-owner", store: new JobStore({ stateRoot: root, now: () => now }),
    authority: () => { authorities += 1; return { allowed: true, grantDigest: digest("f"), receiptDigest: digest("0") }; }
  });
  try {
    const submitted = h1.service.submit(submission({ submissionId: "expired-candidate-001", idempotencyKey: "expired-candidate-001" }));
    await tick(); await tick(); await tick();
    const stale = h1.store.readVerified(submitted.jobId).lease;
    // Model a process crash after the provider terminal event but before the
    // normal finally block released its global slot.
    h1.store.acquireExecutionSlot(submitted.jobId, {
      ownerId: stale.ownerId, fencingToken: stale.fencingToken, profileDigest: h1.profile.profileDigest,
      expiresAt: stale.expiresAt
    });
    now = stale.expiresAt + 1;
    const recovered = h2.service.status({ jobId: submitted.jobId });
    assert.equal(recovered.job.state, "candidate_ready");
    const live = h2.store.readVerified(submitted.jobId).lease;
    assert.equal(live.ownerId, "new-candidate-owner"); assert.ok(live.fencingToken > stale.fencingToken);
    assert.equal(h2.prompts, 0); assert.equal(authorities, 1);
    assert.equal(h2.store.readExecutionSlot(), null, "provider terminal evidence can retire only its matching stale slot");

    const next = h2.service.submit(submission({ submissionId: "after-expired-candidate", idempotencyKey: "after-expired-candidate", source: { ...submission().source, destinationRoot: "C:\\worktrees\\after-expired-candidate" } }));
    await tick(); assert.equal(h2.starts, 1, "the queued second job launches after candidate recovery frees capacity");
    const otherSlot = h2.store.readExecutionSlot(); assert.equal(otherSlot.jobId, next.jobId);
    const candidate = h2.store.readVerified(submitted.jobId).bindings.candidate;
    const accepted = collection(submitted.jobId, candidate.manifestDigest); accepted.expectedAttemptId = candidate.attemptId; accepted.idempotencyKey = "collect-expired-candidate"; accepted.collectionId = "collect-expired-candidate";
    assert.equal(h2.service.collect(accepted).state, "accepted");
    const afterCollectionSlot = h2.store.readExecutionSlot();
    assert.equal(afterCollectionSlot.jobId, next.jobId, "candidate collection must not evict another job's live capacity");
    assert.equal(afterCollectionSlot.digest, otherSlot.digest);
    h2.finish(); await tick(); await tick();
  } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test("a fresh service uses verified candidate terminal evidence for expired collect, repair, and cancel leases", async () => {
  for (const operation of ["collect", "repair", "cancel"]) {
    let now = 60_000; const root = mkdtempSync(join(tmpdir(), `grok-expired-candidate-${operation}-`));
    const h1 = harness({ root, ownerId: `candidate-${operation}-old`, leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }) });
    const h2 = harness({ root, ownerId: `candidate-${operation}-new`, leaseDurationMs: 100, heartbeatMs: 25, store: new JobStore({ stateRoot: root, now: () => now }) });
    try {
      const submitted = await ready(h1, submission({ submissionId: `expired-${operation}-001`, idempotencyKey: `expired-${operation}-001`, source: { ...submission().source, destinationRoot: `C:\\worktrees\\expired-${operation}` } }));
      const first = h1.store.readVerified(submitted.jobId).bindings.candidate;
      const stale = h1.store.readVerified(submitted.jobId).lease; now = stale.expiresAt + 1;
      if (operation === "collect") {
        const request = collection(submitted.jobId, first.manifestDigest); request.expectedAttemptId = first.attemptId; request.idempotencyKey = "expired-collect"; request.collectionId = "expired-collect";
        assert.equal(h2.service.collect(request).state, "accepted");
      } else if (operation === "repair") {
        const request = submission({ submissionId: "expired-repair-request", mode: "repair", idempotencyKey: "expired-repair-request", source: { ...submission().source, destinationRoot: `C:\\worktrees\\expired-${operation}` }, continuation: { jobId: submitted.jobId, expectedAttemptId: first.attemptId, expectedCandidateDigest: first.manifestDigest }, findings: [{ code: "expired-repair", message: "Resume from the exact verified candidate." }] });
        assert.equal(h2.service.submit(request).state, "repairing");
        await tick(); assert.deepEqual(h2.loadedSessions, ["native-001"]);
        h2.finish(); await tick(); await tick();
      } else {
        const request = { contractVersion: CONTRACT_VERSIONS.cancellation, cancellationId: "expired-candidate-cancel", jobId: submitted.jobId, reason: "operator-requested", idempotencyKey: "expired-candidate-cancel" };
        const cancelled = await h2.service.cancel(request);
        assert.equal(cancelled.state, "cancelled"); assert.equal(cancelled.cleanup, "released");
      }
      const recoveredLease = h2.store.readVerified(submitted.jobId).lease;
      assert.equal(recoveredLease.ownerId, `candidate-${operation}-new`);
      assert.ok(recoveredLease.fencingToken > stale.fencingToken);
    } finally { h1.cleanup(); h2.cleanup(); rmSync(root, { recursive: true, force: true }); }
  }
});
