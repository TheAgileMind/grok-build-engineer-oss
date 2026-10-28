import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { ACTIVATION_REGISTRY_VERSION, createActivationRegistryService } from "../src/activation-registry.mjs";
import { ACTIVATION_ENV, ACTIVATION_VERSION, ActivationConfigError, createActivatedService, createPermissionPolicy, defaultProcessInspector, inspectGrok, inventoryProjection, loadActivationManifest } from "../src/activation-runtime.mjs";
import { CONTRACT_VERSIONS } from "../src/contracts.mjs";
import { JobStore } from "../src/job-store.mjs";
import { getCapabilityProfile, profileFingerprint } from "../src/profiles.mjs";

const digest = (value) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
function canonical(value) { if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`; if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`; return JSON.stringify(value); }
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "grok-activation-")), repositoryRoot = join(root, "repo"), destinationRoot = join(root, "worktrees"), stateRoot = join(root, "state"), executable = join(root, "grok.exe"), manifestPath = join(root, "activation.json");
  mkdirSync(repositoryRoot); mkdirSync(destinationRoot); mkdirSync(stateRoot); mkdirSync(join(stateRoot, "job-authorities")); writeFileSync(executable, "fake-grok");
  const raw = { plugins: [], skills: [], agents: [], hooks: [], mcpServers: [], marketplaces: [], configSources: [], projectTrusted: true, permissions: { loaded: true } };
  const opaque = (value) => Array.isArray(value) ? value.map(opaque) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, opaque(value[key])])) : digest(String(value));
  const section = (value) => digest(canonical(opaque(value ?? null)));
  const projection = { plugins: section(raw.plugins), skills: section(raw.skills), agents: section(raw.agents), hooks: section(raw.hooks), mcpServers: section(raw.mcpServers), marketplaces: section(raw.marketplaces), configSources: section(raw.configSources), permissions: section(raw.permissions), projectTrusted: true };
  const sourceSha = "a".repeat(40);
  const manifest = { contractVersion: ACTIVATION_VERSION, runtimeId: "runtime_test", runtimeApprovalDigest: digest("scope"), stateRoot, grokExecutable: executable, grokExecutableDigest: digest("fake-grok"), inventoryDigest: digest(canonical(projection)), profileId: "trusted-local", trustedHostAcknowledgement: "trusted_host_not_os_sandbox", repositoryRoot, destinationRoot, dataClasses: ["public"], expiresAt: "2030-01-01T00:00:00.000Z" };
  const jobAuthority = { contractVersion: CONTRACT_VERSIONS.jobAuthority, authorityId: "authority_test", runtimeId: manifest.runtimeId, sourceSha, dataClasses: ["public"], provider: "xai", model: "grok-build", disclosure: "public_only", costCeilingUsd: 10, validationCommands: ["npm test", "Assert BUILD_REPAIR_TOKEN equals same-session-confirmed."], acceptanceCriteria: ["tests_pass"], externalEffects: [], authorizationBasis: "user_approved", expiresAt: manifest.expiresAt, receiptDigest: digest("job-authority") };
  writeFileSync(manifestPath, JSON.stringify(manifest));
  writeFileSync(join(stateRoot, "job-authorities", `${jobAuthority.authorityId}.json`), JSON.stringify(jobAuthority));
  return { root, raw, manifest, sourceSha, jobAuthority, manifestPath, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}
function runner(raw, mutate = null) { return (command, args, options) => { assert.equal(options.shell, false); assert.deepEqual(args.slice(0, 2), ["--no-auto-update", "--cwd"]); const value = structuredClone(raw); mutate?.(value); return { status: 0, stdout: JSON.stringify(value) }; }; }

test("activation manifest is strict, local, expiring, and secret-free", () => {
  const f = fixture();
  try {
    const manifest = loadActivationManifest({ environment: { [ACTIVATION_ENV]: f.manifestPath }, now: new Date("2029-01-01T00:00:00Z") });
    assert.equal(manifest.profileId, "trusted-local");
    writeFileSync(f.manifestPath, JSON.stringify({ ...f.manifest, extra: true }));
    assert.throws(() => loadActivationManifest({ environment: { [ACTIVATION_ENV]: f.manifestPath }, now: new Date("2029-01-01T00:00:00Z") }), ActivationConfigError);
    writeFileSync(f.manifestPath, JSON.stringify({ ...f.manifest, runtimeApprovalDigest: `sha256:${"0".repeat(64)}` }));
    assert.throws(() => loadActivationManifest({ environment: { [ACTIVATION_ENV]: f.manifestPath }, now: new Date("2029-01-01T00:00:00Z") }), ActivationConfigError, "a candidate placeholder cannot become runtime authority");
  } finally { f.cleanup(); }
});

test("expired activation can be loaded only for existing-job lifecycle recovery", () => {
  const f = fixture();
  try {
    assert.throws(() => loadActivationManifest({ environment: { [ACTIVATION_ENV]: f.manifestPath }, now: new Date("2031-01-01T00:00:00Z") }), /expired/);
    const recovered = loadActivationManifest({ environment: { [ACTIVATION_ENV]: f.manifestPath }, now: new Date("2031-01-01T00:00:00Z"), allowExpired: true });
    assert.equal(recovered.repositoryRoot, f.manifest.repositoryRoot);
  } finally { f.cleanup(); }
});

test("inspection fixes executable, argv, cwd, output bounds, and inventory digest before launch", () => {
  const f = fixture();
  try {
    const manifest = loadActivationManifest({ environment: { [ACTIVATION_ENV]: f.manifestPath }, now: new Date("2029-01-01T00:00:00Z") });
    assert.equal(inspectGrok({ manifest, worktree: f.manifest.repositoryRoot, runner: runner(f.raw) }).evidence.inventoryDigest, f.manifest.inventoryDigest);
    assert.throws(() => inspectGrok({ manifest, worktree: f.manifest.repositoryRoot, runner: runner(f.raw, (raw) => { raw.plugins.push({ name: "drift" }); }) }), ActivationConfigError);
    assert.throws(() => inspectGrok({ manifest, worktree: f.root, runner: runner(f.raw) }), ActivationConfigError);
  } finally { f.cleanup(); }
});

test("activation composition remains provider-free until a submitted job and ignores caller permission metadata", () => {
  const f = fixture();
  try {
    const service = createActivatedService({ environment: { [ACTIVATION_ENV]: f.manifestPath, PATH: "x", GROK_HOME: "x", USERPROFILE: "x" }, now: new Date("2029-01-01T00:00:00Z"), runner: runner(f.raw) });
    assert.deepEqual(Object.keys(service).sort(), ["cancel", "collect", "status", "submit"]);
    assert.deepEqual(service.status({}), { kind: "runtime_health", loadedVersion: "0.5.0", activationVersion: ACTIVATION_VERSION, bundleDigest: null, grokVersion: "unavailable", activationMatch: true, expiresAt: f.manifest.expiresAt, correctiveAction: "ready" });
  } finally { f.cleanup(); }
});

test("a persistent activated host and registry recompute readiness after expiry", async () => {
  const f = fixture(); let current = new Date("2029-01-01T00:00:00Z");
  try {
    const activated = createActivatedService({ environment: { [ACTIVATION_ENV]: f.manifestPath, PATH: "x" }, now: current, clock: () => current, runner: runner(f.raw) });
    const registryRoot = join(f.root, "registry");
    mkdirSync(join(registryRoot, "activations"), { recursive: true }); mkdirSync(join(registryRoot, "routes")); mkdirSync(join(registryRoot, "acceptances"));
    const registeredManifest = join(registryRoot, "activations", "runtime_test.json");
    writeFileSync(registeredManifest, JSON.stringify(f.manifest));
    writeFileSync(join(registryRoot, "registry.json"), JSON.stringify({ contractVersion: ACTIVATION_REGISTRY_VERSION, activations: [registeredManifest] }));
    const registry = createActivationRegistryService({ registryRoot, now: () => current, proxyFactory: () => activated, manifestLoader: (path) => loadActivationManifest({ environment: { [ACTIVATION_ENV]: path }, now: current, allowExpired: true }) });
    assert.equal((await registry.status({})).correctiveAction, "ready");
    current = new Date("2031-01-01T00:00:00Z");
    const expired = await registry.status({});
    assert.equal(expired.activationMatch, false);
    assert.equal(expired.correctiveAction, "renew_or_repair_runtime_activation");
    assert.equal(expired.activations[0].health.correctiveAction, "renew_runtime_activation");
  } finally { f.cleanup(); }
});

test("activated authority consumes the flat custody-bound request and schedules a submit", async () => {
  const f = fixture(); let starts = 0;
  try {
    const source = { repositoryRoot: f.manifest.repositoryRoot, sourceSha: "a".repeat(40), destinationRoot: join(f.manifest.destinationRoot, "job-001"), branchPolicy: "detached" };
    const custody = {
      admit({ jobId, stateRoot }) { return { jobId, sourceSha: source.sourceSha, sourceCustodyDigest: digest("source"), destinationRoot: source.destinationRoot, sourceRoot: source.repositoryRoot, stateRoot, branchPolicy: "detached" }; },
      reserve(admission) { return admission; }, create(admission) { return { ...admission, linkedWorktree: true, worktreeCustodyDigest: digest("worktree") }; },
      inventory() { return { inventoryDigest: digest("inventory"), protectedGitMetadata: {}, entries: [] }; }, revalidate() { return { inventoryDigest: digest("inventory") }; }
    };
    const acpFactory = (hooks) => ({ async start() { starts += 1; await hooks.onSessionBound({ nativeSessionId: "native-001" }); return { done: new Promise(() => {}), cancel: async () => true }; } });
    const store = new JobStore({ stateRoot: f.manifest.stateRoot });
    const service = createActivatedService({ environment: { [ACTIVATION_ENV]: f.manifestPath, PATH: "x", GROK_HOME: "x", USERPROFILE: "x", API_TOKEN: "must-not-pass", GIT_CONFIG_GLOBAL: "must-not-pass" }, now: new Date("2029-01-01T00:00:00Z"), runner: (command, args, options) => { assert.deepEqual(Object.keys(options.env).sort(), ["GROK_HOME", "PATH", "USERPROFILE"]); assert.equal("API_TOKEN" in options.env, false); return runner(f.raw)(command, args, options); }, jobServiceOptions: { store, custody, acpFactory, timers: { setInterval() { return null; }, clearInterval() {} } } });
    const result = service.submit({ contractVersion: CONTRACT_VERSIONS.submission, submissionId: "submission-001", mode: "new", idempotencyKey: "submit-001", profileId: "trusted-local", continuation: null, source, task: { title: "Public task", instructions: "Make a local change.", dataClass: "public", contextPaths: ["src/example.mjs"] }, findings: [] });
    assert.equal(result.state, "queued"); await new Promise((resolve) => setTimeout(resolve, 0)); assert.equal(starts, 1);
    const admission = store.readVerified(result.jobId).admission;
    assert.notEqual(admission.grantDigest, f.jobAuthority.receiptDigest); assert.notEqual(admission.receiptDigest, f.jobAuthority.receiptDigest);
  } finally { f.cleanup(); }
});

test("authority rechecks injected clock expiry before a later submit", async () => {
  const f = fixture(); let current = new Date("2029-01-01T00:00:00Z");
  try {
    const capture = {}; let closeChild, processState = "absent";
    createActivatedService({ environment: { [ACTIVATION_ENV]: f.manifestPath, PATH: "x" }, now: current, clock: () => current, runner: runner(f.raw), processInspector: () => ({ state: processState }), launch: () => ({ closed: new Promise((resolve) => { closeChild = resolve; }) }), jobServiceFactory(options) { capture.authority = options.authority; capture.acp = options.acp; capture.acknowledgeRuntimeRecovery = options.acknowledgeRuntimeRecovery; capture.acknowledgePreStartCancellation = options.acknowledgePreStartCancellation; return { submit() {}, status() {}, collect() {}, cancel() {} }; } });
    const request = { operation: "grok_submit", mode: "new", sourceSha: f.sourceSha, repositoryRoot: f.manifest.repositoryRoot, destinationRoot: join(f.manifest.destinationRoot, "job-001"), dataClass: "public", profileDigest: profileFingerprint(getCapabilityProfile("trusted-local")), requiredScopes: ["provider", "private_disclosure", "cost", "worktree"] };
    assert.equal(capture.authority(request).allowed, true);
    const superseded = { ...f.jobAuthority, authorityId: "authority_superseded", runtimeId: "runtime_superseded", receiptDigest: digest("job-authority-superseded") };
    writeFileSync(join(f.manifest.stateRoot, "job-authorities", `${superseded.authorityId}.json`), JSON.stringify(superseded));
    assert.equal(capture.authority(request).allowed, true, "a valid superseded runtime authority remains audit evidence without poisoning the active runtime store");
    assert.equal(capture.authority({ ...request, sourceSha: "b".repeat(40) }).allowed, false, "a separate job authority remains bound to the approved immutable source SHA");
    const secondAuthority = { ...f.jobAuthority, authorityId: "authority_second", sourceSha: "b".repeat(40), receiptDigest: digest("job-authority-second") };
    writeFileSync(join(f.manifest.stateRoot, "job-authorities", `${secondAuthority.authorityId}.json`), JSON.stringify(secondAuthority));
    assert.equal(capture.authority({ ...request, sourceSha: secondAuthority.sourceSha }).allowed, true, "one stable runtime can admit another clean SHA only with its matching job authority");
    writeFileSync(join(f.manifest.stateRoot, "job-authorities", `${secondAuthority.authorityId}.json`), JSON.stringify({ ...secondAuthority, expiresAt: "2028-01-01T00:00:00.000Z" }));
    assert.equal(capture.authority({ ...request, sourceSha: secondAuthority.sourceSha }).allowed, false, "an expired job authority blocks only its governed prompt");
    const child = { pid: 7101, startedAt: "2026-08-15T20:00:00.000Z" };
    assert.equal(capture.acknowledgeRuntimeRecovery({ childProcessIdentity: child }), true, "a fresh activated host requires an OS-verified prior child identity");
    assert.equal(capture.acknowledgePreStartCancellation, capture.acknowledgeRuntimeRecovery, "cancellation recovery uses the same fail-closed sealed child inspector");
    capture.acp.launch({});
    assert.equal(capture.acknowledgeRuntimeRecovery({ childProcessIdentity: child }), false, "a live ACP child blocks process-loss recovery");
    closeChild(); await Promise.resolve();
    assert.equal(capture.acknowledgeRuntimeRecovery({ childProcessIdentity: child }), true, "a closed ACP child still requires OS-verified absence");
    processState = "present";
    assert.equal(capture.acknowledgeRuntimeRecovery({ childProcessIdentity: child }), false, "a surviving prior PID blocks recovery");
    processState = "mismatch";
    assert.equal(capture.acknowledgeRuntimeRecovery({ childProcessIdentity: child }), false, "PID reuse or identity mismatch blocks recovery");
    processState = "unknown";
    assert.equal(capture.acknowledgeRuntimeRecovery({ childProcessIdentity: child }), false, "an unreadable process table fails closed");
    current = new Date("2031-01-01T00:00:00Z");
    const decision = capture.authority(request);
    assert.equal(decision.allowed, false);
  } finally { f.cleanup(); }
});

test("Windows recovery inspector accepts case-insensitive host system variables outside delegated child authority", { skip: process.platform !== "win32" }, () => {
  const systemRoot = process.env.SystemRoot ?? process.env.SYSTEMROOT;
  assert.equal(typeof systemRoot, "string");
  let observed = null;
  const run = (executable, args, options) => { observed = { executable, args, options }; return { status: 3, stdout: "" }; };
  assert.deepEqual(defaultProcessInspector({ pid: 2_147_483_000 }, { SystemRoot: systemRoot }, run), { state: "absent" });
  assert.equal(observed.executable.toLowerCase(), resolve(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe").toLowerCase());
  assert.equal(observed.options.env.SYSTEMROOT, systemRoot);
});

test("profile re-attestation permit consumes one exact recovery request without pinning a job", () => {
  const f = fixture(); const profileDigest = profileFingerprint(getCapabilityProfile("trusted-local"));
  try {
    const permit = { permitId: "reattest-001", profileId: "trusted-local", profileDigest, oldAttestationFingerprint: digest("old"), oldAttestationDigest: null, newAttestationFingerprint: digest("new"), expiresAt: f.manifest.expiresAt };
    writeFileSync(f.manifestPath, JSON.stringify({ ...f.manifest, profileReattestationPermit: permit }));
    const capture = {};
    createActivatedService({ environment: { [ACTIVATION_ENV]: f.manifestPath, PATH: "x" }, now: new Date("2029-01-01T00:00:00Z"), runner: runner(f.raw), jobServiceFactory(options) { capture.authority = options.authority; return { submit() {}, status() {}, collect() {}, cancel() {} }; } });
    const proof = { contractVersion: "agent-platform.grok-builder-legacy-profile-reattestation.v1", operation: "repair_profile_reattestation_v1", jobId: "job-001", profileId: "trusted-local", profileDigest, oldAttestationFingerprint: permit.oldAttestationFingerprint, newAttestationFingerprint: permit.newAttestationFingerprint, contextDigest: digest("context"), sourceCustodyDigest: digest("source"), worktreeCustodyDigest: digest("worktree") };
    const request = { operation: "grok_submit", mode: "repair", jobId: proof.jobId, sourceSha: f.sourceSha, repositoryRoot: f.manifest.repositoryRoot, destinationRoot: join(f.manifest.destinationRoot, "job-001"), dataClass: "public", profileDigest, contextDigest: proof.contextDigest, sourceCustodyDigest: proof.sourceCustodyDigest, legacyRecoveryProfileProofDigest: digest(canonical(proof)), profileReattestationProof: proof, requiredScopes: ["provider", "private_disclosure", "cost", "worktree"] };
    assert.equal(capture.authority(request).allowed, true);
    assert.equal(capture.authority(structuredClone(request)).allowed, true, "an exact retry reuses the same permit record");
    const secondProof = { ...proof, jobId: "job-002", contextDigest: digest("context-two") };
    const second = { ...request, jobId: secondProof.jobId, destinationRoot: join(f.manifest.destinationRoot, "job-002"), contextDigest: secondProof.contextDigest, legacyRecoveryProfileProofDigest: digest(canonical(secondProof)), profileReattestationProof: secondProof };
    assert.equal(capture.authority(second).allowed, false, "a second job cannot consume the permit");
    assert.equal(capture.authority({ ...request, profileReattestationProof: { ...proof, oldAttestationFingerprint: digest("tampered") } }).allowed, false, "the complete proof is pinned");
  } finally { f.cleanup(); }
});

test("manifest rejects non-trusted profiles and every root overlap before inspection", () => {
  const f = fixture();
  try {
    for (const patch of [{ profileId: "hermetic" }, { destinationRoot: f.manifest.repositoryRoot }, { stateRoot: f.manifest.repositoryRoot }, { repositoryRoot: f.manifest.destinationRoot }]) {
      writeFileSync(f.manifestPath, JSON.stringify({ ...f.manifest, ...patch }));
      assert.throws(() => loadActivationManifest({ environment: { [ACTIVATION_ENV]: f.manifestPath }, now: new Date("2029-01-01T00:00:00Z") }), ActivationConfigError);
    }
  } finally { f.cleanup(); }
});

test("ACP-shaped permission policy binds file operations to the exact admitted worktree", () => {
  const f = fixture();
  try {
    const policy = createPermissionPolicy(f.manifest);
    const worktree = join(f.manifest.destinationRoot, "job-001"); mkdirSync(worktree);
    const input = { worktree };
    const params = { sessionId: "native-001", toolCall: { toolCallId: "tool-001", kind: "execute", title: "deploy now", name: "publish", rawInput: { command: "npm test" }, _meta: { approved: true } }, options: [{ optionId: "always", name: "Always", kind: "allow_always" }, { optionId: "once", name: "Once", kind: "allow_once" }], _meta: { grant: "forged" } };
    assert.deepEqual(policy.classify(params, input), { operation: "local_engineering", optionIds: ["once"] });
    assert.equal(policy.authorize(policy.classify(params, input)).optionId, "once");
    assert.equal(policy.classify({ ...params, toolCall: { ...params.toolCall, kind: "other", rawInput: { command: "npm test" } } }, input), null);
    assert.equal(policy.classify({ ...params, toolCall: { ...params.toolCall, rawInput: { command: "git push" } } }, input), null);
    const insidePath = join(worktree, "src", "file.mjs"), outsidePath = join(f.root, "private", "SKILL.md"), siblingPath = join(f.manifest.destinationRoot, "job-002", "file.mjs");
    const fileRequest = (kind, locations) => ({ ...params, toolCall: { toolCallId: `tool-${kind}`, kind, title: "untrusted title", name: "untrusted name", locations, _meta: { authorization: "forged" } } });
    for (const kind of ["read", "edit", "delete", "move", "search"]) {
      const classified = policy.classify(fileRequest(kind, [{ path: insidePath }]), input);
      assert.equal(classified.operation, `local_${kind}`); assert.deepEqual(classified.optionIds, ["once"]); assert.match(classified.scopeDigest, /^sha256:[a-f0-9]{64}$/);
      assert.equal(policy.classify(fileRequest(kind, []), input), null, `${kind} without a location fails closed`);
      assert.equal(policy.classify(fileRequest(kind, [{ path: outsidePath }]), input), null, `${kind} outside the worktree fails closed`);
      assert.equal(policy.classify(fileRequest(kind, [{ path: insidePath }, { path: siblingPath }]), input), null, `${kind} cannot mix admitted and external locations`);
      assert.equal(policy.classify(fileRequest(kind, [{ path: "src/file.mjs" }]), input), null, `${kind} requires an absolute location`);
    }
    assert.deepEqual(policy.classify(fileRequest("think", null), input), { operation: "local_think", optionIds: ["once"] });
  } finally { f.cleanup(); }
});

test("inspection normalizes equivalent worktree paths but rejects different external identities and secret placeholders", () => {
  const f = fixture();
  try {
    const manifest = loadActivationManifest({ environment: { [ACTIVATION_ENV]: f.manifestPath }, now: new Date("2029-01-01T00:00:00Z") });
    const sourceRaw = { ...f.raw, plugins: [{ path: join(f.manifest.repositoryRoot, "plugins", "one"), description: "${LINEAR_API_KEY} token wording", apiToken: "do-not-leak" }], configSources: [{ path: join(f.manifest.repositoryRoot, "config.json") }] };
    const child = join(f.manifest.destinationRoot, "job-001"); mkdirSync(child);
    const childRaw = { ...f.raw, plugins: [{ path: join(child, "plugins", "one"), description: "${LINEAR_API_KEY} token wording", apiToken: "a-different-secret" }], configSources: [{ path: join(child, "config.json") }] };
    const sourceProjection = inventoryProjection(sourceRaw, { worktree: f.manifest.repositoryRoot });
    const childProjection = inventoryProjection(childRaw, { worktree: child });
    assert.deepEqual(sourceProjection, childProjection);
    assert.equal(JSON.stringify(sourceProjection).includes("LINEAR_API_KEY"), false);
    assert.equal(JSON.stringify(sourceProjection).includes("do-not-leak"), false);
    const drift = inventoryProjection({ ...childRaw, plugins: [{ path: join(child, "plugins", "two"), description: "${LINEAR_API_KEY} token wording" }] }, { worktree: child });
    assert.notDeepEqual(sourceProjection, drift);
    const externalOne = inventoryProjection({ ...childRaw, configSources: [{ path: "C:\\trusted-global\\config-one.json" }] }, { worktree: child });
    const externalTwo = inventoryProjection({ ...childRaw, configSources: [{ path: "C:\\trusted-global\\config-two.json" }] }, { worktree: child });
    assert.notDeepEqual(externalOne, externalTwo);
  } finally { f.cleanup(); }
});

test("inspection inventory is stable across collection order but preserves multiplicity and content drift", () => {
  const first = {
    plugins: [{ name: "one", enabled: true }, { name: "two", enabled: false }],
    skills: [{ name: "alpha" }, { name: "beta" }],
    hooks: ["before", "after"], projectTrusted: true
  };
  const reordered = {
    ...first,
    plugins: [...first.plugins].reverse(), skills: [...first.skills].reverse(), hooks: [...first.hooks].reverse()
  };
  assert.deepEqual(inventoryProjection(first), inventoryProjection(reordered));
  assert.notDeepEqual(inventoryProjection(first), inventoryProjection({ ...first, hooks: ["before", "after", "after"] }));
  assert.notDeepEqual(inventoryProjection(first), inventoryProjection({ ...first, plugins: [{ name: "one", enabled: true }, { name: "two", enabled: true }] }));
});
