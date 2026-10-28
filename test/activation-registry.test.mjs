import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { ACTIVATION_REGISTRY_VERSION, createActivationRegistryService } from "../src/activation-registry.mjs";
import { jobIdForSubmission } from "../src/job-service.mjs";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "grok-registry-"));
  const registryRoot = join(root, "registry"), activations = join(registryRoot, "activations"), routes = join(registryRoot, "routes"), acceptances = join(registryRoot, "acceptances");
  mkdirSync(activations, { recursive: true }); mkdirSync(routes); mkdirSync(acceptances);
  const repoA = join(root, "repo-a"), repoB = join(root, "repo-b"), destinations = join(root, "worktrees");
  mkdirSync(repoA); mkdirSync(repoB); mkdirSync(destinations);
  const writeActivation = (name, repositoryRoot, expiresAt = "2030-01-01T00:00:00.000Z") => {
    const path = join(activations, `${name}.json`);
    writeFileSync(path, JSON.stringify({ repositoryRoot: resolve(repositoryRoot), destinationRoot: resolve(destinations), profileId: "trusted-local", dataClasses: ["public"], expiresAt }));
    return path;
  };
  return { root, registryRoot, repoA, repoB, destinations, writeActivation, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

function submission(repositoryRoot, destinationRoot, submissionId = "submission-001") {
  return { submissionId, mode: "new", profileId: "trusted-local", continuation: null,
    source: { repositoryRoot, destinationRoot }, task: { dataClass: "public" } };
}

function proxyFactory(calls) {
  return ({ manifestPath }) => ({
    async submit(value) { calls.push(["submit", manifestPath, value]); return { jobId: value.mode === "repair" ? value.continuation.jobId : jobIdForSubmission(value.submissionId), state: "queued" }; },
    async status(value) { calls.push(["status", manifestPath, value]); return { job: { jobId: value.jobId, state: "running" }, events: [] }; },
    async collect(value) { calls.push(["collect", manifestPath, value]); return { jobId: value.jobId, state: "accepted" }; },
    async cancel(value) { calls.push(["cancel", manifestPath, value]); return { jobId: value.jobId, state: "cancelled" }; }
  });
}
const registryService = (options) => createActivationRegistryService({ ...options, manifestLoader: (path) => JSON.parse(readFileSync(path, "utf8")) });

test("registry routes exact repositories and persists job ownership across disconnected clients", async () => {
  const f = fixture(), calls = [];
  try {
    const activationA = f.writeActivation("a", f.repoA), activationB = f.writeActivation("b", f.repoB);
    writeFileSync(join(f.registryRoot, "registry.json"), JSON.stringify({ contractVersion: ACTIVATION_REGISTRY_VERSION, activations: [activationA, activationB] }));
    const first = registryService({ registryRoot: f.registryRoot, proxyFactory: proxyFactory(calls), now: new Date("2029-01-01T00:00:00Z") });
    const queued = await first.submit(submission(f.repoB, join(f.destinations, "job-b")));
    assert.equal(queued.jobId, jobIdForSubmission("submission-001"));
    assert.equal(calls[0][1], activationB);
    const route = JSON.parse(readFileSync(join(f.registryRoot, "routes", `${queued.jobId}.json`), "utf8"));
    assert.equal(route.manifestPath, activationB);
    assert.equal(route.state, "pending", "the route journal remains immutable; acceptance is a separate durable record");
    assert.equal(JSON.parse(readFileSync(join(f.registryRoot, "acceptances", `${queued.jobId}.json`), "utf8")).jobId, queued.jobId);

    const second = registryService({ registryRoot: f.registryRoot, proxyFactory: proxyFactory(calls), now: new Date("2029-01-01T00:00:01Z") });
    assert.equal((await second.status({ jobId: queued.jobId })).job.state, "running");
    assert.equal((await second.collect({ jobId: queued.jobId })).state, "accepted");
    assert.equal((await second.cancel({ jobId: queued.jobId })).state, "cancelled");
    assert.deepEqual(calls.slice(1).map(([operation, path]) => [operation, path]), [["status", activationB], ["collect", activationB], ["cancel", activationB]]);
  } finally { f.cleanup(); }
});

test("registry fails closed on zero or ambiguous active matches", async () => {
  const f = fixture();
  try {
    const a = f.writeActivation("a", f.repoA), duplicate = f.writeActivation("duplicate", f.repoA);
    writeFileSync(join(f.registryRoot, "registry.json"), JSON.stringify({ contractVersion: ACTIVATION_REGISTRY_VERSION, activations: [a] }));
    const none = registryService({ registryRoot: f.registryRoot, proxyFactory: proxyFactory([]), now: new Date("2029-01-01T00:00:00Z") });
    await assert.rejects(none.submit(submission(f.repoB, join(f.destinations, "none"))), /no active activation/i);
    writeFileSync(join(f.registryRoot, "registry.json"), JSON.stringify({ contractVersion: ACTIVATION_REGISTRY_VERSION, activations: [a, duplicate] }));
    const ambiguous = registryService({ registryRoot: f.registryRoot, proxyFactory: proxyFactory([]), now: new Date("2029-01-01T00:00:00Z") });
    await assert.rejects(ambiguous.submit(submission(f.repoA, join(f.destinations, "ambiguous"))), /multiple active activations/i);
  } finally { f.cleanup(); }
});

test("a long-lived registry service rechecks activation expiry before persisting a new route", async () => {
  const f = fixture(); let clock = new Date("2029-01-01T00:00:00Z");
  try {
    const activation = f.writeActivation("a", f.repoA, "2029-01-01T00:00:05.000Z");
    writeFileSync(join(f.registryRoot, "registry.json"), JSON.stringify({ contractVersion: ACTIVATION_REGISTRY_VERSION, activations: [activation] }));
    const service = registryService({ registryRoot: f.registryRoot, proxyFactory: proxyFactory([]), now: () => clock });
    clock = new Date("2029-01-01T00:00:10Z");
    await assert.rejects(service.submit(submission(f.repoA, join(f.destinations, "expired-after-start"))), /no active activation/i);
    assert.deepEqual(readdirSync(join(f.registryRoot, "routes")), []);
  } finally { f.cleanup(); }
});

test("expired activations reject new work but remain routable for an existing job", async () => {
  const f = fixture(), calls = [];
  try {
    const expired = f.writeActivation("expired", f.repoA, "2028-01-01T00:00:00.000Z");
    writeFileSync(join(f.registryRoot, "registry.json"), JSON.stringify({ contractVersion: ACTIVATION_REGISTRY_VERSION, activations: [expired] }));
    const service = registryService({ registryRoot: f.registryRoot, proxyFactory: proxyFactory(calls), now: new Date("2029-01-01T00:00:00Z") });
    await assert.rejects(service.submit(submission(f.repoA, join(f.destinations, "new"))), /no active activation/i);
    const manifestDigest = `sha256:${createHash("sha256").update(readFileSync(expired)).digest("hex")}`;
    const legacyRoute = { contractVersion: "agent-platform.grok-build-engineer-route.v2", jobId: "job-existing", manifestPath: expired, manifestDigest, state: "pending", submissionDigest: `sha256:${"a".repeat(64)}` };
    const legacyBytes = JSON.stringify(legacyRoute);
    writeFileSync(join(f.registryRoot, "routes", "job-existing.json"), legacyBytes);
    assert.equal((await service.status({ jobId: "job-existing" })).job.state, "submission_pending", "a historical v2 pending route stays byte-for-byte intact and is observable without inventing a host job");
    writeFileSync(join(f.registryRoot, "acceptances", "job-existing.json"), JSON.stringify({ contractVersion: "agent-platform.grok-build-engineer-route-acceptance.v1", jobId: "job-existing", submissionDigest: legacyRoute.submissionDigest, resultDigest: `sha256:${"b".repeat(64)}` }));
    assert.equal((await service.status({ jobId: "job-existing" })).job.state, "running", "a historical acceptance sidecar restores safe v2 observation");
    assert.equal(readFileSync(join(f.registryRoot, "routes", "job-existing.json"), "utf8"), legacyBytes, "legacy route evidence is never rewritten");
  } finally { f.cleanup(); }
});

test("provider-free registry health never summarizes an expired runtime as ready", async () => {
  const f = fixture();
  try {
    const expiresAt = "2028-01-01T00:00:00.000Z";
    const expired = f.writeActivation("expired", f.repoA, expiresAt);
    writeFileSync(join(f.registryRoot, "registry.json"), JSON.stringify({ contractVersion: ACTIVATION_REGISTRY_VERSION, activations: [expired] }));
    const service = registryService({ registryRoot: f.registryRoot, now: new Date("2029-01-01T00:00:00Z"), proxyFactory: () => ({
      async status() { return { kind: "runtime_health", loadedVersion: "0.3.11", bundleDigest: null, grokVersion: "unavailable", activationMatch: true, expiresAt, correctiveAction: "renew_runtime_activation" }; }
    }) });
    const health = await service.status({});
    assert.equal(health.activationMatch, false);
    assert.equal(health.correctiveAction, "renew_or_repair_runtime_activation");
    assert.equal(health.expiresAt, expiresAt);
  } finally { f.cleanup(); }
});

test("pending routes reconcile only through an exact original submission and never route lifecycle calls to an unknown job", async () => {
  const f = fixture(), calls = []; let attempts = 0;
  try {
    const activation = f.writeActivation("a", f.repoA);
    writeFileSync(join(f.registryRoot, "registry.json"), JSON.stringify({ contractVersion: ACTIVATION_REGISTRY_VERSION, activations: [activation] }));
    const service = registryService({ registryRoot: f.registryRoot, now: new Date("2029-01-01T00:00:00Z"), proxyFactory: ({ manifestPath }) => ({
      async submit(value) { calls.push(["submit", manifestPath, value]); attempts += 1; if (attempts === 1) throw new Error("connection lost after downstream admission"); return { jobId: jobIdForSubmission(value.submissionId), state: "queued" }; },
      async status(value) { calls.push(["status", manifestPath, value]); return { job: { jobId: value.jobId, state: "running" }, events: [] }; },
      async collect(value) { calls.push(["collect", manifestPath, value]); return value; }, async cancel(value) { calls.push(["cancel", manifestPath, value]); return value; }
    }) });
    const first = submission(f.repoA, join(f.destinations, "retry"));
    await assert.rejects(service.submit(first), /connection lost/);
    const jobId = jobIdForSubmission(first.submissionId);
    assert.equal((await service.status({ jobId })).job.state, "submission_pending");
    await assert.rejects(service.collect({ jobId }), /retry the exact original submission/i);
    await assert.rejects(service.cancel({ jobId }), /retry the exact original submission/i);
    assert.equal(calls.length, 1, "unresolved lifecycle calls never reach the host");
    await assert.rejects(service.submit({ ...first, idempotencyKey: "other-key" }), /another activation or submission/);
    const reconciled = await service.submit(first);
    assert.equal(reconciled.jobId, jobId);
    const route = JSON.parse(readFileSync(join(f.registryRoot, "routes", `${jobId}.json`), "utf8"));
    assert.equal(route.state, "pending"); assert.equal(route.acceptanceDigest, null);
    assert.equal(typeof JSON.parse(readFileSync(join(f.registryRoot, "acceptances", `${jobId}.json`), "utf8")).resultDigest, "string");
  } finally { f.cleanup(); }
});

test("registry rejects activation mutation after a job route is sealed", async () => {
  const f = fixture();
  try {
    const activation = f.writeActivation("a", f.repoA);
    writeFileSync(join(f.registryRoot, "registry.json"), JSON.stringify({ contractVersion: ACTIVATION_REGISTRY_VERSION, activations: [activation] }));
    const service = registryService({ registryRoot: f.registryRoot, proxyFactory: proxyFactory([]), now: new Date("2029-01-01T00:00:00Z") });
    const result = await service.submit(submission(f.repoA, join(f.destinations, "sealed")));
    writeFileSync(activation, JSON.stringify({ repositoryRoot: f.repoB, destinationRoot: f.destinations, profileId: "trusted-local", dataClasses: ["public"], expiresAt: "2030-01-01T00:00:00.000Z" }));
    await assert.rejects(service.status({ jobId: result.jobId }), /manifest was changed/i);
  } finally { f.cleanup(); }
});

test("registry refuses routing when the full activation validator rejects a manifest", async () => {
  const f = fixture();
  try {
    const activation = f.writeActivation("invalid", f.repoA);
    writeFileSync(join(f.registryRoot, "registry.json"), JSON.stringify({ contractVersion: ACTIVATION_REGISTRY_VERSION, activations: [activation] }));
    const service = createActivationRegistryService({ registryRoot: f.registryRoot, proxyFactory: proxyFactory([]), manifestLoader() { throw new Error("invalid receipts"); }, now: new Date("2029-01-01T00:00:00Z") });
    await assert.rejects(service.submit(submission(f.repoA, join(f.destinations, "invalid"))), /failed full validation/i);
  } finally { f.cleanup(); }
});

test("provider-free no-job health explains an invalid registry instead of returning a tool failure", async () => {
  const f = fixture();
  try {
    writeFileSync(join(f.registryRoot, "registry.json"), JSON.stringify({ invalid: true }));
    const service = registryService({ registryRoot: f.registryRoot, proxyFactory: proxyFactory([]), healthMetadata: { loadedVersion: "0.3.11", bundleDigest: `sha256:${"c".repeat(64)}` } });
    assert.deepEqual(await service.status({}), { kind: "registry_health", loadedVersion: "0.3.11", bundleDigest: `sha256:${"c".repeat(64)}`, grokVersion: "unavailable", activationMatch: false, expiresAt: null, correctiveAction: "repair_activation_registry", activations: [], jobs: [] });
  } finally { f.cleanup(); }
});

test("provider-free health exposes bounded durable job handles to a fresh client", async () => {
  const f = fixture(), calls = [];
  try {
    const activation = f.writeActivation("a", f.repoA);
    writeFileSync(join(f.registryRoot, "registry.json"), JSON.stringify({ contractVersion: ACTIVATION_REGISTRY_VERSION, activations: [activation] }));
    const service = registryService({ registryRoot: f.registryRoot, proxyFactory: proxyFactory(calls), now: new Date("2029-01-01T00:00:00Z") });
    const queued = await service.submit(submission(f.repoA, join(f.destinations, "discover"), "submission-discover"));
    const health = await service.status({});
    assert.deepEqual(health.jobs, [{ jobId: queued.jobId, routeState: "routed", runtimeId: null, expiresAt: "2030-01-01T00:00:00.000Z", nextActions: ["call_grok_status_with_job_id"] }]);
  } finally { f.cleanup(); }
});
