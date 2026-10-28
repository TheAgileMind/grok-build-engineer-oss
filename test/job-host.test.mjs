import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createJobHostProxy, jobHostEndpoint, jobHostRequestSecret, requestJobHost, startJobHost } from "../src/job-host.mjs";
import { IdempotencyConflictError, IntegrityError, LeaseConflictError } from "../src/job-store.mjs";

const TEST_SECRET = "a".repeat(64);

function endpoint(root, name) {
  return process.platform === "win32"
    ? `\\\\.\\pipe\\grok-build-engineer-test-${process.pid}-${name}`
    : join(root, `${name}.sock`);
}

test("a persistent host completes work after the submitting client disconnects", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-job-host-"));
  let state = "queued", candidate = null;
  const service = {
    submit(value) {
      state = "running";
      setTimeout(() => { state = "candidate_ready"; candidate = { manifestDigest: value.manifestDigest }; }, 25);
      return { jobId: value.jobId, state: "queued", cursor: 0 };
    },
    status({ jobId }) { return { job: { jobId, state }, candidate, events: [] }; },
    collect(value) { state = value.disposition === "accepted" ? "accepted" : "rejected"; return { jobId: value.jobId, state }; },
    cancel({ jobId }) { state = "cancelled"; return { jobId, state }; }
  };
  const address = endpoint(root, "disconnect");
  const host = await startJobHost({ service, endpoint: address, requestSecret: TEST_SECRET });
  try {
    const submitted = await requestJobHost({ endpoint: address, operation: "submit", args: { jobId: "job-001", manifestDigest: "candidate-001" }, requestSecret: TEST_SECRET });
    assert.equal(submitted.state, "queued");
    await new Promise((resolve) => setTimeout(resolve, 50));
    const reconnected = await requestJobHost({ endpoint: address, operation: "status", args: { jobId: "job-001" }, requestSecret: TEST_SECRET });
    assert.equal(reconnected.job.state, "candidate_ready");
    assert.deepEqual(reconnected.candidate, { manifestDigest: "candidate-001" });
    const collected = await requestJobHost({ endpoint: address, operation: "collect", args: { jobId: "job-001", disposition: "accepted" }, requestSecret: TEST_SECRET });
    assert.equal(collected.state, "accepted");
  } finally {
    await host.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("host ping reports the exact non-public execution policy without widening tool operations", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-job-host-policy-"));
  const service = {
    runtimePolicy: Object.freeze({ leaseDurationMs: 300_000, heartbeatMs: 30_000 }),
    submit: async () => ({}), status: async () => ({}), collect: async () => ({}), cancel: async () => ({})
  };
  const address = endpoint(root, "policy"), host = await startJobHost({ service, endpoint: address, requestSecret: TEST_SECRET });
  try {
    assert.deepEqual(await requestJobHost({ endpoint: address, operation: "ping", args: {}, requestSecret: TEST_SECRET }), {
      ready: true, runtimePolicy: { leaseDurationMs: 300_000, heartbeatMs: 30_000 }
    });
    await assert.rejects(requestJobHost({ endpoint: address, operation: "runtimePolicy", args: {} }), /unsupported/);
  } finally { await host.close(); rmSync(root, { recursive: true, force: true }); }
});

test("host rejects missing or wrong request secrets and rechecks activation identity before service work", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-job-host-auth-")), manifestPath = join(root, "activation.json");
  writeFileSync(manifestPath, JSON.stringify({ stateRoot: root, expiresAt: "2030-01-01T00:00:00.000Z" }));
  const environment = { GROK_BUILD_ENGINEER_ACTIVATION_MANIFEST: manifestPath }, address = endpoint(root, "auth"), calls = [];
  const host = await startJobHost({ environment, endpoint: address, service: { submit: async () => { calls.push("submit"); return {}; }, status: async () => ({}), collect: async () => ({}), cancel: async () => ({}) } });
  try {
    const secret = jobHostRequestSecret(environment);
    await assert.rejects(requestJobHost({ endpoint: address, operation: "submit", args: {}, requestSecret: "b".repeat(64) }), /malformed/);
    assert.deepEqual(calls, []);
    writeFileSync(manifestPath, JSON.stringify({ stateRoot: root, expiresAt: "2030-01-01T00:00:00.000Z", changed: true }));
    await assert.rejects(requestJobHost({ endpoint: address, operation: "submit", args: {}, requestSecret: secret }), /activation is unavailable/);
    assert.deepEqual(calls, []);
  } finally { await host.close(); rmSync(root, { recursive: true, force: true }); }
});

test("expired activation keeps existing lifecycle control while identity remains unchanged", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-job-host-expired-")), manifestPath = join(root, "activation.json"), calls = [];
  writeFileSync(manifestPath, JSON.stringify({ stateRoot: root, expiresAt: "2000-01-01T00:00:00.000Z" }));
  const environment = { GROK_BUILD_ENGINEER_ACTIVATION_MANIFEST: manifestPath }, address = endpoint(root, "expired");
  const service = Object.fromEntries(["submit", "status", "collect", "cancel"].map((operation) => [operation, async (args) => { calls.push(operation); return { operation, args }; }]));
  const host = await startJobHost({ environment, endpoint: address, service });
  try {
    const secret = jobHostRequestSecret(environment);
    for (const operation of ["status", "collect", "cancel"]) assert.equal((await requestJobHost({ endpoint: address, operation, args: { jobId: "job-existing" }, requestSecret: secret })).operation, operation);
    assert.deepEqual(calls, ["status", "collect", "cancel"]);
  } finally { await host.close(); rmSync(root, { recursive: true, force: true }); }
});

test("separate clients can repair, observe, and cancel through one host", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-job-host-"));
  const calls = [];
  const service = Object.fromEntries(["submit", "status", "collect", "cancel"].map((operation) => [operation, async (args) => {
    calls.push([operation, structuredClone(args)]);
    return { operation, args };
  }]));
  const address = endpoint(root, "operations");
  const host = await startJobHost({ service, endpoint: address, requestSecret: TEST_SECRET });
  try {
    for (const operation of ["submit", "status", "collect", "cancel"]) {
      const result = await requestJobHost({ endpoint: address, operation, args: { jobId: "job-002", operation }, requestSecret: TEST_SECRET });
      assert.equal(result.operation, operation);
    }
    assert.deepEqual(calls.map(([operation]) => operation), ["submit", "status", "collect", "cancel"]);
    await assert.rejects(requestJobHost({ endpoint: address, operation: "unknown", args: {} }), /unsupported/);
  } finally {
    await host.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("the transient proxy starts one host and reconnects without owning its lifetime", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-job-host-proxy-"));
  const manifestPath = join(root, "activation.json");
  writeFileSync(manifestPath, JSON.stringify({ stateRoot: root, expiresAt: "2030-01-01T00:00:00.000Z" }));
  const environment = { GROK_BUILD_ENGINEER_ACTIVATION_MANIFEST: manifestPath };
  const bundleDigest = `sha256:${"a".repeat(64)}`;
  const address = jobHostEndpoint(environment, process.platform, bundleDigest);
  let starts = 0, hostPromise;
  const service = {
    submit: async ({ jobId }) => ({ jobId, state: "queued" }),
    status: async ({ jobId }) => ({ job: { jobId, state: "running" }, events: [] }),
    collect: async ({ jobId }) => ({ jobId, state: "accepted" }),
    cancel: async ({ jobId }) => ({ jobId, state: "cancelled" })
  };
  const proxy = createJobHostProxy({
    environment, bundlePath: import.meta.filename, expectedBundleDigest: bundleDigest,
    spawnProcess() {
      starts += 1;
      hostPromise = startJobHost({ service, endpoint: address, environment });
      return { unref() {} };
    }
  });
  try {
    assert.equal((await proxy.submit({ jobId: "job-003" })).state, "queued");
    assert.equal((await proxy.status({ jobId: "job-003" })).job.state, "running");
    assert.equal(starts, 1);
  } finally {
    if (hostPromise) await (await hostPromise).close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("the proxy restarts a lost host and preserves safe remote error categories", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-job-host-restart-"));
  const manifestPath = join(root, "activation.json");
  writeFileSync(manifestPath, JSON.stringify({ stateRoot: root, expiresAt: "2030-01-01T00:00:00.000Z" }));
  const environment = { GROK_BUILD_ENGINEER_ACTIVATION_MANIFEST: manifestPath };
  const bundleDigest = `sha256:${"b".repeat(64)}`;
  const address = jobHostEndpoint(environment, process.platform, bundleDigest);
  const hosts = [];
  let starts = 0;
  const service = {
    submit: async () => { throw new TypeError("submission shape is invalid"); },
    status: async ({ jobId }) => { if (jobId === "stale-cursor") throw new RangeError("status cursor is stale or in the future"); return { job: { jobId, state: "running" }, events: [] }; },
    collect: async () => { throw new Error("private provider detail"); },
    cancel: async ({ jobId }) => ({ jobId, state: "cancelled" })
  };
  const proxy = createJobHostProxy({
    environment, bundlePath: import.meta.filename, expectedBundleDigest: bundleDigest,
    spawnProcess() {
      starts += 1;
      void startJobHost({ service, endpoint: address, environment }).then((host) => hosts.push(host));
      return { once() {}, removeListener() {}, unref() {} };
    }
  });
  try {
    assert.equal((await proxy.status({ jobId: "job-restart" })).job.state, "running");
    await (await requestJobHost({ endpoint: address, operation: "ping", args: {}, requestSecret: jobHostRequestSecret(environment) })).ready;
    await hosts[0].close();
    assert.equal((await proxy.status({ jobId: "job-restart" })).job.state, "running");
    assert.equal(starts, 2, "a later client call must restart a lost detached host");
    await assert.rejects(proxy.submit({}), /submission shape is invalid/);
    await assert.rejects(proxy.status({ jobId: "stale-cursor" }), (error) => error instanceof TypeError && /cursor is stale/i.test(error.message));
    await assert.rejects(proxy.collect({}), (error) => {
      assert.equal(error.remote?.code, "service_error");
      assert.doesNotMatch(error.message, /private provider detail/);
      return true;
    });
  } finally {
    for (const host of hosts.slice(1)) await host.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("the host exposes fixed lifecycle error categories without leaking controller details", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-job-host-errors-"));
  const address = endpoint(root, "errors");
  const service = {
    submit: async () => { throw new IntegrityError("sealed private evidence mismatch"); },
    status: async () => { throw new LeaseConflictError("private owner and expiry detail"); },
    collect: async () => { throw new IdempotencyConflictError("private request digest detail"); },
    cancel: async () => { throw new Error("unknown private controller detail"); }
  };
  const host = await startJobHost({ service, endpoint: address, requestSecret: TEST_SECRET });
  try {
    const expected = [
      ["submit", "integrity_error", /lifecycle transition/i],
      ["status", "lease_conflict", /not yet recoverable/i],
      ["collect", "idempotency_conflict", /idempotency key conflicts/i],
      ["cancel", "service_error", /governed job service rejected/i]
    ];
    for (const [operation, code, message] of expected) {
      await assert.rejects(requestJobHost({ endpoint: address, operation, args: {}, requestSecret: TEST_SECRET }), (error) => {
        assert.equal(error.remote?.code, code);
        assert.match(error.message, message);
        assert.doesNotMatch(error.message, /private|sealed/);
        return true;
      });
    }
  } finally { await host.close(); rmSync(root, { recursive: true, force: true }); }
});

test("production proxy fails closed when its separately supervised host is absent", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-job-host-absent-"));
  const manifestPath = join(root, "activation.json");
  writeFileSync(manifestPath, JSON.stringify({ stateRoot: root, expiresAt: "2030-01-01T00:00:00.000Z" }));
  const proxy = createJobHostProxy({
    environment: { GROK_BUILD_ENGINEER_ACTIVATION_MANIFEST: manifestPath },
    bundlePath: import.meta.filename,
    expectedBundleDigest: `sha256:${"c".repeat(64)}`
  });
  try { await assert.rejects(proxy.status({ jobId: "job-absent" }), /supervised local Grok job host is unavailable/); }
  finally { rmSync(root, { recursive: true, force: true }); }
});
