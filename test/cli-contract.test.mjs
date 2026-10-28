import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { CLI_CONTRACT_VERSION, cliErrorResponse, cliResponse, validateCliRequest } from "../src/cli-contract.mjs";
import { validateTaskPacket } from "../src/contracts.mjs";
import { createTaskPolicy, FIXED_WINDOWS_ENVIRONMENT_KEYS, packetDigest, scopedEnvironment } from "../src/task-policy.mjs";

const script = join(process.cwd(), "scripts", "grok-delegate.mjs");
function invoke(args) { const result = spawnSync(process.execPath, [script, ...args], { encoding: "utf8", windowsHide: true }); return { ...result, body: JSON.parse(result.stdout) }; }
const prepareScript = join(process.cwd(), "scripts", "prepare-task-packet.mjs");
function invokePrepare(args) { const result = spawnSync(process.execPath, [prepareScript, ...args], { encoding: "utf8", windowsHide: true }); return { ...result, body: JSON.parse(result.stdout) }; }

test("CLI help and invalid arguments always emit the versioned response", () => {
  const help = invoke(["--help"]); assert.equal(help.status, 0); assert.equal(help.body.contractVersion, CLI_CONTRACT_VERSION); assert.equal(help.body.operation, "help"); assert.match(help.body.usage.prepare, /--input/); assert.match(help.body.usage.submit, /--packet/); assert.match(help.body.usage.status, /--state-root/); assert.match(help.body.usage.repair, /--findings/); assert.match(help.body.usage.collect, /--acceptance/);
  const bad = invoke(["unknown"]); assert.notEqual(bad.status, 0); assert.equal(bad.body.contractVersion, CLI_CONTRACT_VERSION); assert.equal(bad.body.ok, false);
});
test("CLI status, submit, repair, and cancel fail closed without a provider", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-cli-")); try {
    const status = invoke(["status", "--state-root", join(root, "state"), "--task-run-id", "run-001"]); assert.notEqual(status.status, 0); assert.equal(status.body.error.code, "not_found");
    const packet = join(root, "packet.json"); writeFileSync(packet, "{}\n");
    for (const operation of ["submit", "repair"]) { const result = invoke([operation, "--packet", packet]); assert.notEqual(result.status, 0); assert.equal(result.body.contractVersion, CLI_CONTRACT_VERSION); }
    const cancel = invoke(["cancel", "--state-root", join(root, "state"), "--task-run-id", "run-001"]); assert.notEqual(cancel.status, 0); assert.equal(cancel.body.error.code, "not_found");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("CLI status returns a validated starting projection while spawn is pending", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-cli-running-")); try {
    const stateRoot = join(root, "state"); mkdirSync(join(stateRoot, "runs"), { recursive: true });
    const starting = { contractVersion: "agent-platform.grok-build-engineer-one-shot.v1", taskRunId: "run-001", requestId: "request-001", state: "starting", mode: "implementation", startedAt: new Date().toISOString(), ownerNonce: "owner", sessionId: "123e4567-e89b-12d3-a456-426614174000", pid: null, binding: { sourceSha: "0123456789abcdef0123456789abcdef01234567", repositoryRoot: root, worktree: root, custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) }, requested: { model: "grok-build", executable: process.execPath }, allowedScope: { worktree: root, paths: [], commands: [], network: "none", tools: [], environment: [] } };
    writeFileSync(join(stateRoot, "runs", "run-001.json"), `${JSON.stringify(starting)}\n`);
    const status = invoke(["status", "--state-root", stateRoot, "--task-run-id", "run-001"]); assert.equal(status.status, 0); assert.equal(status.body.contractVersion, CLI_CONTRACT_VERSION); assert.equal(status.body.receipt.state, "starting");
    const cancel = invoke(["cancel", "--state-root", stateRoot, "--task-run-id", "run-001"]); assert.equal(cancel.status, 69); assert.equal(cancel.body.error.code, "unsupported");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("CLI live status rejects malformed starting projections", () => {
  const receipt = { contractVersion: "agent-platform.grok-build-engineer-one-shot.v1", taskRunId: "run-001", requestId: "request-001", state: "starting", ownerNonce: "owner", sessionId: "123e4567-e89b-12d3-a456-426614174000", pid: "not-a-pid", binding: { sourceSha: "0123456789abcdef0123456789abcdef01234567", repositoryRoot: "C:/repo", worktree: "C:/repo", custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) } };
  assert.throws(() => cliResponse("status", receipt.taskRunId, { receipt }), /live receipt pid is invalid/);
});
test("CLI contract exposes provider-free prepare and bounded redacted errors", () => {
  assert.equal(validateCliRequest({ operation: "prepare" }).operation, "prepare");
  const response = cliErrorResponse("status", "run-001", new Error("token: sk-proj-12345678901234567890"));
  assert.equal(response.error.code, "cli_error");
  assert.doesNotMatch(response.error.message, /sk-proj-/);
  assert.ok(response.error.message.length <= 512);
});
test("unified CLI prepare emits only a policy-runnable canonical packet", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-cli-prepare-")); try {
    const inputPath = join(root, "input.json");
    const input = { contractVersion: "agent-platform.grok-build-engineer-task.v2", taskRunId: "run-001", requestId: "request-001", mode: "implementation", delivery: "artifact_only", repositoryRoot: root, worktree: root, sourceSha: "0123456789abcdef0123456789abcdef01234567", task: { title: "Prepare", instructions: "Prepare only.", contextPaths: ["src"] }, policy: { allowedPaths: ["src/**"], allowedCommands: ["node test"], allowedEnvironment: [], network: "none", tools: [], timeouts: { startMs: 1000, turnMs: 1000, idleMs: 1000, cancelMs: 1000 }, repairBudget: 0 }, provider: { executable: process.execPath, model: "grok-build" }, stateRoot: join(root, "state"), approval: { contractVersion: "agent-platform.grok-build-engineer-approval.v1", approvalId: "approval-001", packetDigest: "sha256:" + "0".repeat(64), issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(), approvedBy: "test", authorizationStatement: "Test-only explicit approval shape." }, continuation: null, findingsDigest: null };
    writeFileSync(inputPath, `${JSON.stringify(input)}\n`);
    const prepared = invoke(["prepare", "--input", inputPath]);
    assert.equal(prepared.status, 0); validateTaskPacket(prepared.body.packet);
    assert.equal(prepared.body.packet.approval.packetDigest, packetDigest(prepared.body.packet));
    input.policy.allowedCommands = ["npm test && whoami"]; writeFileSync(inputPath, `${JSON.stringify(input)}\n`);
    const rejected = invoke(["prepare", "--input", inputPath]);
    assert.notEqual(rejected.status, 0); assert.equal(rejected.body.error.code, "invalid_input");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("CLI rejects explicit state-root and task identity mismatches", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-cli-identity-")); try {
    const packet = join(root, "packet.json");
    writeFileSync(packet, JSON.stringify({ taskRunId: "run-001", stateRoot: join(root, "packet-state") }));
    const result = invoke(["status", "--packet", packet, "--state-root", join(root, "other-state"), "--task-run-id", "run-001"]);
    assert.notEqual(result.status, 0);
    assert.equal(result.body.error.code, "invalid_input");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("provider-free packet preparation fills the canonical digest without creating authority", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-prepare-")); try {
    const inputPath = join(root, "input.json"); const input = { contractVersion: "agent-platform.grok-build-engineer-task.v2", taskRunId: "run-001", requestId: "request-001", mode: "implementation", delivery: "artifact_only", repositoryRoot: root, worktree: root, sourceSha: "0123456789abcdef0123456789abcdef01234567", task: { title: "Prepare", instructions: "Prepare only.", contextPaths: ["src"] }, policy: { allowedPaths: ["src/**"], allowedCommands: ["npm test"], allowedEnvironment: [], network: "none", tools: [], timeouts: { startMs: 1000, turnMs: 1000, idleMs: 1000, cancelMs: 1000 }, repairBudget: 0 }, provider: { executable: process.execPath, model: "grok-build" }, stateRoot: join(root, "state"), approval: { contractVersion: "agent-platform.grok-build-engineer-approval.v1", approvalId: "approval-001", packetDigest: "sha256:" + "0".repeat(64), issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(), approvedBy: "test", authorizationStatement: "Test-only explicit approval shape." }, continuation: null, findingsDigest: null };
    writeFileSync(inputPath, `${JSON.stringify(input)}\n`); const result = invokePrepare([inputPath]); assert.equal(result.status, 0); validateTaskPacket(result.body); assert.equal(result.body.approval.packetDigest, packetDigest(result.body)); assert.equal(result.body.approval.approvedBy, "test"); assert.equal(result.body.contractVersion, input.contractVersion);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("current examples validate against the task policy and contain no wildcard commands", () => {
  for (const name of ["task-packet.template.json", "job-request.example.json"]) {
    const packet = JSON.parse(readFileSync(resolve(process.cwd(), "examples", name), "utf8"));
    validateTaskPacket(packet);
    createTaskPolicy(packet);
    assert.ok(packet.approval.contractVersion);
    assert.ok(packet.approval.authorizationStatement);
    assert.ok(packet.policy.allowedCommands.every((command) => !/[?*]/.test(command)));
  }
  const repairInput = resolve(process.cwd(), "examples", "repair-task-packet.template.json"); const preparedRepair = invokePrepare([repairInput]); assert.equal(preparedRepair.status, 0); validateTaskPacket(preparedRepair.body); assert.equal(preparedRepair.body.mode, "repair"); assert.equal(preparedRepair.body.policy.repairBudget, 1);
  const profiles = JSON.parse(readFileSync(resolve(process.cwd(), "examples", "capability-profiles.example.json"), "utf8"));
  assert.deepEqual(profiles.profiles.map((profile) => profile.profileId), ["hermetic", "trusted-local", "connected"]);
  assert.ok(profiles.profiles.every((profile) => profile.commandAllowlist.every((command) => !/[?*]/.test(command))));
});

test("empty caller environment allowlist still supplies fixed Windows variables without secret-shaped values", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-cli-env-")); try {
    const packet = { contractVersion: "agent-platform.grok-build-engineer-task.v2", taskRunId: "run-env-001", requestId: "request-env-001", mode: "implementation", delivery: "artifact_only", repositoryRoot: root, worktree: root, sourceSha: "0123456789abcdef0123456789abcdef01234567", task: { title: "Environment", instructions: "Test fixed environment.", contextPaths: ["src"] }, policy: { allowedPaths: ["src/**"], allowedCommands: ["npm test"], allowedEnvironment: [], network: "none", tools: [], timeouts: { startMs: 1000, turnMs: 1000, idleMs: 1000, cancelMs: 1000 }, repairBudget: 0 }, provider: { executable: process.execPath, model: "grok-build" }, stateRoot: join(root, "state"), continuation: null, findingsDigest: null, approval: { contractVersion: "agent-platform.grok-build-engineer-approval.v1", approvalId: "approval-env-001", packetDigest: "sha256:" + "0".repeat(64), issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(), approvedBy: "test", authorizationStatement: "Test-only explicit approval shape." } };
    packet.approval.packetDigest = packetDigest(packet);
    const source = Object.fromEntries([...FIXED_WINDOWS_ENVIRONMENT_KEYS, "API_TOKEN", "CUSTOM_VALUE"].map((key) => [key, `${key}-value`]));
    const child = scopedEnvironment(packet, source);
    assert.ok(FIXED_WINDOWS_ENVIRONMENT_KEYS.every((key) => child[key] === `${key}-value`));
    assert.equal(child.API_TOKEN, undefined);
    assert.equal(child.CUSTOM_VALUE, undefined);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("documentation exposes one truthful artifact-only lifecycle and disables direct-write", () => {
  const readme = readFileSync(resolve(process.cwd(), "README.md"), "utf8");
  const skill = readFileSync(resolve(process.cwd(), "skills", "grok-build-engineer", "SKILL.md"), "utf8");
  for (const text of [readme, skill]) {
    for (const operation of ["prepare", "approve", "submit", "status", "repair", "collect"]) assert.match(text, new RegExp(operation));
    assert.match(text, /trusted host is not an OS[\s\S]*sandbox/i);
    assert.match(text, /provider usage\/cost[\s\S]*not[\s\S]*hard/i);
    assert.match(text, /cross-process cancellation[\s\S]*unsupported/i);
    assert.match(text, /artifact-only[\s\S]*implemented/i);
    assert.match(text, /provider[\s-]+tools[\s\S]*disabled/i);
    assert.match(text, /controller[\s\S]*validation/i);
    assert.match(text, /direct-write[\s\S]*disabled/i);
    assert.match(text, /exact task-bound[\s\S]*(write_file|accepted operation)/i);
    assert.match(text, /(?:rejected artifact|invalid provider output)[\s\S]*(?:digest|structural shape)/i);
    assert.match(text, /no successful 0\.5\.7 live provider proof[\s\S]*claimed/i);
  }
});
