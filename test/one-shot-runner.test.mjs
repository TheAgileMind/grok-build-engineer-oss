import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { CONTRACT_VERSIONS } from "../src/contracts.mjs";
import { ARTIFACT_CONTRACT_VERSION, beginArtifactTransaction, executeArtifact, persistRejectedArtifactEvidence } from "../src/artifact-delivery.mjs";
import { buildOneShotLaunch, cancelRun, createOneShotRunner as createProductionOneShotRunner, persistAcceptanceDecision, providerErrorFramePath, receiptDigest, readRunReceipt, RunnerCancellationUnsupportedError, verifyCustody } from "../src/one-shot-runner.mjs";
import { cliResponse } from "../src/cli-contract.mjs";
import { packetDigest, createTaskPolicy, validateChangedFiles } from "../src/task-policy.mjs";

function packet(root, mode = "implementation") {
  const repositoryRoot = join(root, "synthetic-repository"), worktree = join(root, "synthetic-worktree"), stateRoot = join(root, "synthetic-state");
  mkdirSync(repositoryRoot, { recursive: true }); mkdirSync(worktree, { recursive: true });
  const value = { contractVersion: CONTRACT_VERSIONS.taskPacket, taskRunId: "run-001", requestId: "request-001", mode, delivery: "artifact_only", repositoryRoot, worktree, sourceSha: "0123456789abcdef0123456789abcdef01234567", task: { title: "Synthetic task", instructions: "Make the bounded change.", contextPaths: ["src"] }, policy: { allowedPaths: ["src/**"], allowedCommands: [], allowedEnvironment: [], network: "none", tools: [], timeouts: { startMs: 1000, turnMs: 1000, idleMs: 1000, cancelMs: 1000 }, repairBudget: mode === "repair" ? 1 : 0 }, provider: { executable: process.execPath, model: "grok-build" }, stateRoot, approval: { contractVersion: CONTRACT_VERSIONS.approvalPacket, approvalId: "approval-001", packetDigest: "sha256:" + "0".repeat(64), issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(), approvedBy: "test", authorizationStatement: "Test-only approval for the exact synthetic packet." }, continuation: mode === "repair" ? null : null, findingsDigest: null };
  value.approval.packetDigest = packetDigest(value); return value;
}
function createOneShotRunner({ artifactDelivery = {}, ...options } = {}) {
  return createProductionOneShotRunner({
    artifactDelivery: {
      buildPrompt: () => "synthetic artifact prompt",
      prepareScratch: ({ stateRoot, taskRunId, requestId }) => join(resolve(stateRoot), "provider-scratch", taskRunId, requestId),
      removeScratch: () => true,
      parseOutput: (_output, task) => ({ contractVersion: ARTIFACT_CONTRACT_VERSION, taskRunId: task.taskRunId, requestId: task.requestId, operations: [{ kind: "write_file", path: "src/result.mjs", content: "export {};\n" }] }),
      beginTransaction: () => ({ rollback: () => true, commit: () => true }),
      execute: () => ({ ok: true, decisions: [], validationEvidence: [], appliedPaths: ["src/result.mjs"] }),
      persistArtifact: () => ({}),
      persistRejectedArtifact: () => ({}),
      persistDecision: () => ({}),
      ...artifactDelivery
    },
    ...options
  });
}
function linkedGitFixture(prefix) {
  const root = mkdtempSync(join(tmpdir(), prefix)), repository = join(root, "repository"), worktree = join(root, "worktree"), stateRoot = join(root, "state");
  mkdirSync(repository); mkdirSync(stateRoot);
  const git = (cwd, args) => { const result = spawnSync("git", ["-c", "user.name=Test", "-c", "user.email=test@example.com", ...args], { cwd, encoding: "utf8", windowsHide: true }); assert.equal(result.status, 0, result.stderr); return result.stdout.trim(); };
  git(repository, ["init", "--quiet"]);
  return { root, repository, worktree, stateRoot, git: (args, cwd = repository) => git(cwd, args) };
}
class FakeChild extends EventEmitter { constructor(frames, code = 0) { super(); this.pid = 4242; this.stdout = new EventEmitter(); this.stderr = new EventEmitter(); this.exitCode = code; this.killCount = 0; setImmediate(() => { for (const frame of frames) { const normalized = frame && typeof frame === "object" && frame.type === "end" && frame.stopReason === undefined ? { ...frame, stopReason: "end_turn" } : frame; this.stdout.emit("data", `${JSON.stringify(normalized)}\n`); } this.emit("close", code); }); } kill() { this.killCount += 1; this.emit("close", 143); } }
class RawChild extends EventEmitter { constructor(raw) { super(); this.pid = 4343; this.stdout = new EventEmitter(); this.stderr = new EventEmitter(); this.killCount = 0; setImmediate(() => { this.stdout.emit("data", raw); this.emit("close", 0); }); } kill() { this.killCount += 1; this.emit("close", 143); } }
class ChunkedRawChild extends EventEmitter { constructor(chunks) { super(); this.pid = 4344; this.stdout = new EventEmitter(); this.stderr = new EventEmitter(); this.killCount = 0; setImmediate(() => { for (const chunk of chunks) this.stdout.emit("data", chunk); this.emit("close", 0); }); } kill() { this.killCount += 1; this.emit("close", 143); } }
class SplitUtf8Child extends EventEmitter { constructor(task) { super(); this.pid = 4444; this.stdout = new EventEmitter(); this.stderr = new EventEmitter(); setImmediate(() => { const line = `${JSON.stringify({ type: "text", taskRunId: task.taskRunId, requestId: task.requestId, text: "café" })}\n`; const bytes = Buffer.from(line); const split = bytes.indexOf(Buffer.from("é")) + 1; this.stdout.emit("data", bytes.subarray(0, split)); this.stdout.emit("data", bytes.subarray(split)); this.stdout.emit("data", Buffer.from(`${JSON.stringify({ type: "end", stopReason: "end_turn", taskRunId: task.taskRunId, requestId: task.requestId })}\n`)); this.emit("close", 0); }); } kill() {} }
class NonClosingChild extends EventEmitter { constructor() { super(); this.pid = 4545; this.stdout = new EventEmitter(); this.stderr = new EventEmitter(); } kill() {} }
class NonClosingRawChild extends EventEmitter { constructor(chunks) { super(); this.pid = 4546; this.stdout = new EventEmitter(); this.stderr = new EventEmitter(); this.killCount = 0; setImmediate(() => { for (const chunk of chunks) this.stdout.emit("data", chunk); }); } kill() { this.killCount += 1; } }
class DelayedOutputChild extends EventEmitter { constructor(task) { super(); this.pid = 4646; this.stdout = new EventEmitter(); this.stderr = new EventEmitter(); setTimeout(() => { this.stdout.emit("data", `${JSON.stringify({ type: "text", taskRunId: task.taskRunId, requestId: task.requestId, text: "{}" })}\n`); setTimeout(() => { this.stdout.emit("data", `${JSON.stringify({ type: "end", stopReason: "end_turn", taskRunId: task.taskRunId, requestId: task.requestId })}\n`); this.emit("close", 0); }, 30); }, 5); } kill() {} }

test("one-shot launch disables provider tools and runs only in the isolated scratch workspace", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-launch-")); try {
    const allowedRules = (args) => args.flatMap((arg, index) => arg === "--allow" ? [args[index + 1]] : []);
    const task = packet(root); task.policy.allowedCommands = ["node test", "git status"]; task.approval.packetDigest = packetDigest(task);
    const scratch = join(task.stateRoot, "provider-scratch", task.taskRunId, task.requestId);
    const launch = buildOneShotLaunch({ packet: task, promptFilePath: join(root, "prompt.txt"), providerCwd: scratch, sessionId: "123e4567-e89b-42d3-a456-426614174000" });
    for (const flag of ["--no-subagents", "--disable-web-search"]) assert.equal(launch.args.includes(flag), true, flag);
    assert.deepEqual(allowedRules(launch.args), []);
    assert.equal(launch.args[launch.args.indexOf("--tools") + 1], "");
    assert.equal(launch.cwd, scratch);
    assert.notEqual(launch.cwd, task.worktree);
    assert.throws(() => buildOneShotLaunch({ packet: task, promptFilePath: join(root, "prompt.txt"), providerCwd: task.worktree, sessionId: "123e4567-e89b-42d3-a456-426614174009" }), /exact artifact-only provider scratch/i);
    const dangerous = packet(root); dangerous.taskRunId = "run-003"; dangerous.requestId = "request-003"; dangerous.policy.allowedCommands = ["npm publish*"]; dangerous.approval.packetDigest = packetDigest(dangerous);
    assert.throws(() => buildOneShotLaunch({ packet: dangerous, promptFilePath: join(root, "prompt-dangerous.txt"), sessionId: "123e4567-e89b-42d3-a456-426614174002" }), /wildcard|denied by task policy/);
    const unsafe = packet(root); unsafe.taskRunId = "run-004"; unsafe.requestId = "request-004"; unsafe.policy.allowedCommands = ["node test && git status"]; unsafe.approval.packetDigest = packetDigest(unsafe);
    assert.throws(() => buildOneShotLaunch({ packet: unsafe, promptFilePath: join(root, "prompt-unsafe.txt"), sessionId: "123e4567-e89b-42d3-a456-426614174003" }), /safe Bash rule|unsupported shell syntax/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("artifact-only launch isolates GROK_HOME from a fixture operator home with mcp_servers", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-isolate-"));
  try {
    const operatorHome = resolve(root, "operator-grok");
    const localAppData = join(operatorHome, "AppData", "Local");
    const appData = join(operatorHome, "AppData", "Roaming");
    const pluginMerge = join(operatorHome, ".claude", "plugins");
    mkdirSync(operatorHome, { recursive: true });
    mkdirSync(pluginMerge, { recursive: true });
    writeFileSync(join(operatorHome, "config.toml"), [
      "models.default = \"grok-4.6\"",
      "models.default_reasoning_effort = \"xhigh\"",
      "ui.permission_mode = \"always-approve\"",
      "",
      "[compat.codex]",
      "mcps = false",
      "",
      "[mcp_servers.figma]",
      "command = \"npx\"",
      "",
      "[mcp_servers.gbrain]",
      "command = \"npx\"",
      "",
      "[mcp_servers.linear]",
      "command = \"npx\"",
      ""
    ].join("\n"));
    writeFileSync(join(pluginMerge, "installed.json"), JSON.stringify({
      plugins: ["episodic-memory", "exa", "supabase", "paper"]
    }));
    const task = packet(root);
    const scratch = join(task.stateRoot, "provider-scratch", task.taskRunId, task.requestId);
    const launch = buildOneShotLaunch({
      packet: task,
      promptFilePath: join(root, "prompt.txt"),
      providerCwd: scratch,
      sessionId: "123e4567-e89b-42d3-a456-426614174000",
      environment: {
        GROK_HOME: operatorHome,
        HOME: operatorHome,
        USERPROFILE: operatorHome,
        LOCALAPPDATA: localAppData,
        APPDATA: appData,
        PATH: "/bin"
      }
    });
    assert.notEqual(launch.env.GROK_HOME, operatorHome);
    assert.notEqual(launch.env.HOME, operatorHome);
    assert.notEqual(launch.env.USERPROFILE, operatorHome);
    assert.notEqual(launch.env.LOCALAPPDATA, localAppData);
    assert.notEqual(launch.env.APPDATA, appData);
    assert.equal(launch.env.GROK_HOME, join(resolve(task.stateRoot), "provider-homes", task.taskRunId, task.requestId));
    assert.equal(launch.env.USERPROFILE, launch.env.GROK_HOME);
    assert.equal(launch.env.LOCALAPPDATA, launch.env.GROK_HOME);
    assert.equal(launch.env.APPDATA, launch.env.GROK_HOME);
    assert.notEqual(launch.env.GROK_HOME, launch.cwd);
    assert.match(launch.cwd, /provider-scratch/);
    assert.equal(launch.args[launch.args.indexOf("--tools") + 1], "");
    assert.equal(launch.args.includes("MCPTool(*)") || launch.args.some((arg, index) => arg === "--deny" && launch.args[index + 1] === "MCPTool(*)"), true);
    assert.equal(launch.args.includes("--debug-file"), true);
    assert.equal(launch.args[launch.args.indexOf("--debug-file") + 1], launch.debugFile);
    assert.match(launch.debugFile, /provider-debug/);
    assert.notEqual(launch.debugFile, launch.cwd);
    assert.equal(launch.args.includes("--sandbox"), false);
    const visible = [launch.env.GROK_HOME, launch.env.HOME, launch.env.USERPROFILE, launch.env.LOCALAPPDATA, launch.env.APPDATA, launch.cwd, launch.debugFile, ...launch.args].join("\0");
    assert.equal(visible.includes(operatorHome), false);
    assert.equal(visible.includes("mcp_servers"), false);
    for (const name of ["figma", "gbrain", "linear", "episodic-memory", "exa", "supabase", "paper", "mcps"]) {
      assert.equal(visible.includes(name), false, name);
    }
    assert.equal(JSON.stringify(launch.env).includes("mcp_servers"), false);
    const withoutAppData = buildOneShotLaunch({
      packet: task,
      promptFilePath: join(root, "prompt.txt"),
      providerCwd: scratch,
      sessionId: "123e4567-e89b-42d3-a456-426614174001",
      environment: { GROK_HOME: operatorHome, HOME: operatorHome, USERPROFILE: operatorHome, LOCALAPPDATA: localAppData, PATH: "/bin" }
    });
    assert.equal(withoutAppData.env.APPDATA, withoutAppData.env.GROK_HOME);
    assert.equal(withoutAppData.env.USERPROFILE, withoutAppData.env.GROK_HOME);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("production one-shot runner persists secret-safe diagnostics from an authentic Grok error frame", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-error-frame-"));
  try {
    const task = packet(resolve(root));
    const token = "sk-proj-faketoken1234567890abcd";
    const frame = {
      type: "error",
      message: `Couldn't start session: Authorization: Bearer ${token}`,
      error: {
        type: "api_error",
        code: "provider_error",
        message: `Couldn't start session: Authorization: Bearer ${token}`,
        status: 401
      }
    };
    const line = JSON.stringify(frame);
    const expectedDigest = `sha256:${createHash("sha256").update(line).digest("hex")}`;
    const receipt = await createProductionOneShotRunner({
      verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }),
      artifactDelivery: {
        buildPrompt: () => "synthetic artifact prompt",
        prepareScratch: ({ stateRoot, taskRunId, requestId }) => join(resolve(stateRoot), "provider-scratch", taskRunId, requestId),
        removeScratch: () => true,
        parseOutput: () => { throw new Error("must not parse after provider error"); },
        beginTransaction: () => ({ rollback: () => true, commit: () => true }),
        execute: () => { throw new Error("must not execute after provider error"); },
        persistArtifact: () => ({}),
        persistRejectedArtifact: () => ({}),
        persistDecision: () => ({})
      },
      killTree: (child) => child.kill(),
      spawnImpl: (_command, _args, options) => {
        assert.match(options.env.GROK_HOME, /provider-homes/);
        assert.notEqual(options.env.GROK_HOME, options.cwd);
        assert.equal(existsSync(options.env.GROK_HOME), true);
        assert.deepEqual(readdirSync(options.env.GROK_HOME), []);
        assert.equal(options.env.USERPROFILE, options.env.GROK_HOME);
        assert.equal(options.env.APPDATA, options.env.GROK_HOME);
        return new FakeChild([frame], 1);
      }
    }).run(task);
    assert.equal(receipt.state, "failed");
    assert.equal(receipt.diagnostics.code, "provider_error");
    assert.equal(receipt.diagnostics.frameDigest, expectedDigest);
    assert.equal(receipt.diagnostics.status, 401);
    assert.equal(receipt.diagnostics.category, "api_error");
    assert.equal(receipt.diagnostics.message.includes(token), false);
    assert.match(receipt.diagnostics.message, /REDACTED/);
    assert.ok(receipt.diagnostics.message.length <= 512);
    const serialized = JSON.stringify(receipt);
    assert.equal(serialized.includes(token), false);
    assert.equal(serialized.includes(`Bearer ${token}`), false);
    const persisted = readRunReceipt(task.stateRoot, task.taskRunId);
    assert.equal(persisted.diagnostics.code, "provider_error");
    assert.equal(persisted.diagnostics.frameDigest, expectedDigest);
    assert.equal(JSON.stringify(persisted).includes(token), false);
    const framePath = providerErrorFramePath({ stateRoot: task.stateRoot, taskRunId: task.taskRunId, requestId: task.requestId });
    assert.equal(existsSync(framePath), true);
    const stored = JSON.parse(readFileSync(framePath, "utf8"));
    assert.equal(stored.frameDigest, expectedDigest);
    assert.equal(stored.protocolFrameType, "error");
    assert.equal(JSON.stringify(stored).includes(token), false);
    assert.match(String(stored.protocolErrorMessage ?? stored.frame?.message ?? ""), /REDACTED/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("production runner maps a code-less Grok error frame to provider_error instead of runner_failure", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-error-codeless-"));
  try {
    const task = packet(resolve(root));
    const frame = { type: "error", message: "Couldn't start session: api_key=super-secret-value" };
    const receipt = await createProductionOneShotRunner({
      verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }),
      artifactDelivery: {
        buildPrompt: () => "synthetic artifact prompt",
        prepareScratch: ({ stateRoot, taskRunId, requestId }) => join(resolve(stateRoot), "provider-scratch", taskRunId, requestId),
        removeScratch: () => true,
        parseOutput: () => { throw new Error("must not parse after provider error"); },
        beginTransaction: () => ({ rollback: () => true, commit: () => true }),
        execute: () => { throw new Error("must not execute after provider error"); },
        persistArtifact: () => ({}),
        persistRejectedArtifact: () => ({}),
        persistDecision: () => ({})
      },
      killTree: (child) => child.kill(),
      spawnImpl: () => new FakeChild([frame], 1)
    }).run(task);
    assert.equal(receipt.state, "failed");
    assert.equal(receipt.diagnostics.code, "provider_error");
    assert.notEqual(receipt.diagnostics.code, "runner_failure");
    assert.match(receipt.diagnostics.frameDigest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(receipt.diagnostics.message.includes("super-secret-value"), false);
    assert.match(receipt.diagnostics.message, /REDACTED/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("task policy derives a secret-free scoped environment and rejects path escape", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try { const policy = createTaskPolicy(packet(root)); assert.deepEqual(policy.environment, []); assert.throws(() => validateChangedFiles([{ path: "../package.json", status: "M" }], policy), /escapes|outside/); const denied = packet(root); denied.policy.tools = ["provider_exec"]; denied.approval.packetDigest = packetDigest(denied); assert.throws(() => createTaskPolicy(denied), /artifact-only|provider tools/); } finally { rmSync(root, { recursive: true, force: true }); }
});
test("implementation runner provisions the packet-bound state root and linked worktree before spawn", async () => {
  const fixture = linkedGitFixture("grok-one-shot-provision-"); const { root, repository, worktree, stateRoot, git } = fixture;
  try {
    mkdirSync(join(repository, "src"), { recursive: true }); writeFileSync(join(repository, "src", "base.mjs"), "export {};\n"); git(["add", "src/base.mjs"]); git(["commit", "--quiet", "-m", "base"]);
    const task = packet(root); task.repositoryRoot = repository; task.worktree = worktree; task.sourceSha = git(["rev-parse", "HEAD"]); task.stateRoot = stateRoot; rmSync(stateRoot, { recursive: true, force: true }); task.approval.packetDigest = packetDigest(task);
    const receipt = await createOneShotRunner({ spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }]) }).run(task);
    assert.equal(receipt.state, "candidate");
    assert.equal(existsSync(join(worktree, ".git")), true);
    assert.equal(existsSync(join(stateRoot, "runs", `${task.taskRunId}.json`)), true);
    assert.equal(git(["rev-parse", "HEAD"], worktree), task.sourceSha);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("production runner parses one provider artifact and owns every candidate effect", async () => {
  const fixture = linkedGitFixture("grok-one-shot-artifact-integration-"); const { root, repository, worktree, stateRoot, git } = fixture;
  try {
    mkdirSync(join(repository, "src"), { recursive: true }); mkdirSync(join(repository, "test"), { recursive: true });
    writeFileSync(join(repository, "src", "context.mjs"), "export const context = true;\n");
    writeFileSync(join(repository, "test", "result.test.mjs"), "import assert from 'node:assert/strict'; import test from 'node:test'; import { result } from '../src/result.mjs'; test('result', () => assert.equal(result, 42));\n");
    git(["add", "src/context.mjs", "test/result.test.mjs"]); git(["commit", "--quiet", "-m", "base"]);
    const task = packet(root); task.repositoryRoot = repository; task.worktree = worktree; task.stateRoot = stateRoot; task.sourceSha = git(["rev-parse", "HEAD"]); task.policy.allowedCommands = ["node --test"]; task.approval.packetDigest = packetDigest(task);
    const output = JSON.stringify({ contractVersion: ARTIFACT_CONTRACT_VERSION, taskRunId: task.taskRunId, requestId: task.requestId, operations: [{ kind: "write_file", path: "README.md", content: "denied\n" }, { kind: "run_command", command: "node --version" }, { kind: "write_file", path: "src/result.mjs", content: "export const result = 42;\n" }, { kind: "run_command", command: "node --test" }] });
    const receipt = await createProductionOneShotRunner({ spawnImpl: (_command, _args, options) => { assert.notEqual(options.cwd, worktree); assert.match(options.cwd, /provider-scratch/i); assert.match(options.env.GROK_HOME, /provider-homes/); assert.notEqual(options.env.GROK_HOME, options.cwd); assert.equal(existsSync(join(worktree, "src", "result.mjs")), false); return new FakeChild([{ type: "text", taskRunId: task.taskRunId, requestId: task.requestId, text: output }, { type: "end", taskRunId: task.taskRunId, requestId: task.requestId }]); } }).run(task);
    assert.equal(receipt.state, "candidate");
    assert.equal(readFileSync(join(worktree, "src", "result.mjs"), "utf8"), "export const result = 42;\n");
    assert.equal(existsSync(join(worktree, "README.md")), false);
    assert.deepEqual(receipt.validationEvidence.map(({ command, exitCode }) => ({ command, exitCode })), [{ command: "node --test", exitCode: 0 }]);
    const decisions = JSON.parse(readFileSync(join(stateRoot, "artifacts", task.taskRunId, `${task.requestId}.decision.json`), "utf8"));
    assert.deepEqual(decisions.decisions.map(({ decision }) => decision), ["deny", "deny", "allow", "allow"]);
    assert.equal(existsSync(join(stateRoot, "provider-scratch", task.taskRunId, task.requestId)), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("one-shot runner produces a candidate receipt from correlated terminal output", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try { const task = packet(resolve(root)); const runner = createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [{ path: "src/result.mjs", status: "A" }] }), spawnImpl: () => new FakeChild([{ type: "text", taskRunId: task.taskRunId, requestId: task.requestId, text: "{}" }, { type: "end", taskRunId: task.taskRunId, requestId: task.requestId, changedFiles: [] }]) }); const receipt = await runner.run(task); assert.equal(receipt.state, "candidate"); assert.deepEqual(receipt.changedFiles.map((entry) => entry.path), ["src/result.mjs"]); } finally { rmSync(root, { recursive: true, force: true }); }
});
test("one-shot runner requires one end_turn terminal and rejects max turns or post-terminal data", async () => {
  const cases = [
    [[{ type: "end", stopReason: "max_turns", taskRunId: "run-001", requestId: "request-001" }], "terminal_stop_reason_invalid"],
    [[{ type: "max_turns_reached", taskRunId: "run-001", requestId: "request-001" }], "max_turns"],
    [[{ type: "end", stopReason: "end_turn", requestId: "provider-request-001" }], "terminal_session_missing"],
    [[{ type: "end", stopReason: "end_turn", taskRunId: "run-001" }], "terminal_request_missing"],
    [[{ type: "end", stopReason: "end_turn", taskRunId: "run-001", requestId: "request-001" }, { type: "end", stopReason: "end_turn", taskRunId: "run-001", requestId: "request-001" }], "post_terminal_data"],
    [[{ type: "end", stopReason: "end_turn", taskRunId: "run-001", requestId: "request-001" }, { type: "text", taskRunId: "run-001", requestId: "request-001" }], "post_terminal_data"]
  ];
  for (const [frames, code] of cases) {
    const root = mkdtempSync(join(tmpdir(), "grok-one-shot-terminal-"));
    try { const task = packet(resolve(root)); const receipt = await createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }), spawnImpl: () => new FakeChild(frames) }).run(task); assert.equal(receipt.state, "failed"); assert.equal(receipt.diagnostics.code, code); }
    finally { rmSync(root, { recursive: true, force: true }); }
  }
});
test("provider-native request IDs remain stable without being confused with controller request IDs", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try {
    const task = packet(resolve(root));
    const frames = [
      { type: "system", requestId: "a17c0e9f-b6cd-4001-84ac-f86223a648be" },
      { type: "end", requestId: "a17c0e9f-b6cd-4001-84ac-f86223a648be" }
    ];
    const receipt = await createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }), spawnImpl: (_command, args) => { const sessionFlag = args.includes("--resume") ? "--resume" : "--session-id"; return new FakeChild(frames.map((frame) => frame.type === "end" ? { ...frame, sessionId: args[args.indexOf(sessionFlag) + 1] } : frame)); } }).run(task);
    assert.equal(receipt.state, "candidate");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("provider-native request ID drift fails closed", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try {
    const task = packet(resolve(root));
    const receipt = await createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }), killTree: (child) => child.kill(), spawnImpl: (_command, args) => new FakeChild([{ type: "system", requestId: "native-001" }, { type: "end", requestId: "native-002", sessionId: args[args.indexOf("--session-id") + 1] }]) }).run(task);
    assert.equal(receipt.state, "failed");
    assert.equal(receipt.diagnostics.message, "stream_correlation_mismatch");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("artifact-only runner rejects provider tool frames before controller execution", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try {
    const task = packet(resolve(root)); let executed = 0;
    const receipt = await createOneShotRunner({
      verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }),
      artifactDelivery: { execute: () => { executed += 1; throw new Error("must not execute"); } },
      killTree: (child) => child.kill(),
      spawnImpl: () => new FakeChild([{ type: "tool_call", taskRunId: task.taskRunId, requestId: task.requestId }, { type: "end", taskRunId: task.taskRunId, requestId: task.requestId }])
    }).run(task);
    assert.equal(receipt.state, "failed");
    assert.equal(receipt.diagnostics.code, "artifact_tool_attempted");
    assert.equal(executed, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("artifact-only runner preserves a mutated provider scratch directory as failure evidence", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try {
    const task = packet(resolve(root));
    const receipt = await createOneShotRunner({
      verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }),
      artifactDelivery: { removeScratch: () => { throw new Error("provider scratch was mutated"); } },
      spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }])
    }).run(task);
    assert.equal(receipt.state, "failed");
    assert.equal(receipt.diagnostics.code, "artifact_scratch_mutated");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("candidate receipts contain controller-owned validation evidence", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try {
    const task = packet(resolve(root));
    const validationEvidence = [{ command: "node test", exitCode: 0, outputDigest: "sha256:" + "a".repeat(64) }];
    const receipt = await createOneShotRunner({
      verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }),
      artifactDelivery: { execute: () => ({ ok: true, decisions: [], validationEvidence, appliedPaths: ["src/result.mjs"] }) },
      spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }])
    }).run(task);
    assert.equal(receipt.state, "candidate");
    assert.deepEqual(receipt.validationEvidence, validationEvidence);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("one-shot runner fails closed on malformed output and scope escape", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try { const task = packet(resolve(root)); const custody = () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) }); const malformed = createOneShotRunner({ verifyCustodyImpl: custody, killTree: (child) => child.kill(), spawnImpl: () => new FakeChild(["not-json"]) }); const failed = await malformed.run(task); assert.equal(failed.state, "failed"); assert.equal(failed.diagnostics.code, "invalid_stream_frame"); const escaped = packet(resolve(root)); escaped.taskRunId = "run-002"; escaped.requestId = "request-002"; escaped.approval = { ...escaped.approval, packetDigest: packetDigest(escaped) }; const runner = createOneShotRunner({ verifyCustodyImpl: () => ({ ...custody(), changedFiles: [{ path: "package.json", status: "M" }] }), killTree: (child) => child.kill(), spawnImpl: () => new FakeChild([{ type: "end", taskRunId: escaped.taskRunId, requestId: escaped.requestId, changedFiles: [] }]) }); const denied = await runner.run(escaped); assert.equal(denied.state, "failed"); assert.equal(denied.diagnostics.code, "scope_violation"); } finally { rmSync(root, { recursive: true, force: true }); }
});
test("candidate publication requires controller or provider-native request correlation", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try {
    const task = packet(resolve(root));
    const receipt = await createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }), spawnImpl: () => new FakeChild([{ type: "end" }]) }).run(task);
    assert.equal(receipt.state, "failed");
    assert.equal(receipt.diagnostics.code, "terminal_session_missing");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("one-shot runner bounds terminated and unterminated stdout frames and kills the child", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try {
    const task = packet(resolve(root)); const custody = () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) }); const terminated = new RawChild(`${"x".repeat(4 * 1024 * 1024 + 1)}\n`); const first = await createOneShotRunner({ verifyCustodyImpl: custody, killTree: (child) => child.kill(), spawnImpl: () => terminated }).run(task); assert.equal(first.state, "failed"); assert.equal(first.diagnostics.code, "stdout_frame_limit"); assert.equal(terminated.killCount, 1);
    const secondTask = { ...task, taskRunId: "run-002", requestId: "request-002" }; secondTask.approval = { ...secondTask.approval, packetDigest: packetDigest(secondTask) }; const unterminated = new RawChild("y".repeat(4 * 1024 * 1024 + 1)); const second = await createOneShotRunner({ verifyCustodyImpl: custody, killTree: (child) => child.kill(), spawnImpl: () => unterminated }).run(secondTask); assert.equal(second.state, "failed"); assert.equal(second.diagnostics.code, "stdout_frame_limit"); assert.equal(unterminated.killCount, 1);
    const thirdTask = { ...task, taskRunId: "run-003", requestId: "request-003" }; thirdTask.approval = { ...thirdTask.approval, packetDigest: packetDigest(thirdTask) };
    const frame = `${JSON.stringify({ type: "text", taskRunId: thirdTask.taskRunId, requestId: thirdTask.requestId, text: "z".repeat(3_500_000) })}\n`;
    const cumulative = new ChunkedRawChild(Array(5).fill(frame));
    const third = await createOneShotRunner({
      verifyCustodyImpl: custody,
      artifactDelivery: { persistRejectedArtifact: persistRejectedArtifactEvidence },
      killTree: (child) => child.kill(),
      spawnImpl: () => cumulative
    }).run(thirdTask);
    assert.equal(third.state, "failed"); assert.equal(third.diagnostics.code, "artifact_output_limit"); assert.equal(cumulative.killCount, 1);
    const rejected = JSON.parse(readFileSync(join(thirdTask.stateRoot, "artifacts", thirdTask.taskRunId, `${thirdTask.requestId}.rejected.json`), "utf8"));
    assert.equal(rejected.rejectionCode, "artifact_output_limit");
    assert.equal(rejected.outputTruncated, true);
    assert.ok(rejected.outputBytes > 4 * 1024 * 1024);
    assert.equal(rejected.structure.jsonType, "oversized");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("oversized artifact evidence survives unproven child termination", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-overflow-recovery-"));
  try {
    const task = packet(resolve(root));
    task.policy.timeouts.cancelMs = 20;
    task.approval.packetDigest = packetDigest(task);
    const frame = `${JSON.stringify({ type: "text", taskRunId: task.taskRunId, requestId: task.requestId, text: "z".repeat(3_500_000) })}\n`;
    const child = new NonClosingRawChild([frame, frame]);
    const receipt = await createOneShotRunner({
      verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) }),
      artifactDelivery: { persistRejectedArtifact: persistRejectedArtifactEvidence },
      killTree: (owned) => owned.kill(),
      spawnImpl: () => child
    }).run(task);
    assert.equal(receipt.state, "recovery_required");
    assert.equal(receipt.diagnostics.code, "child_termination_unproven");
    assert.equal(child.killCount, 1);
    const rejected = JSON.parse(readFileSync(join(task.stateRoot, "artifacts", task.taskRunId, `${task.requestId}.rejected.json`), "utf8"));
    assert.equal(rejected.rejectionCode, "artifact_output_limit");
    assert.equal(rejected.outputTruncated, true);
    assert.ok(rejected.outputBytes > 4 * 1024 * 1024);
    assert.equal(rejected.structure.jsonType, "oversized");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("streaming UTF-8 carryover preserves a multibyte frame split across chunks", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try { const task = packet(resolve(root)); const receipt = await createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) }), spawnImpl: () => new SplitUtf8Child(task) }).run(task); assert.equal(receipt.state, "candidate"); } finally { rmSync(root, { recursive: true, force: true }); }
});
test("duplicate task claims fail before a second child spawn and corrupt state is recovery-required", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try { const task = packet(resolve(root)); const stateRuns = join(task.stateRoot, "runs"); mkdirSync(stateRuns, { recursive: true }); writeFileSync(join(stateRuns, `${task.taskRunId}.lock`), JSON.stringify({ taskRunId: task.taskRunId, ownerNonce: "other-owner" })); let starts = 0; await assert.rejects(() => createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) }), spawnImpl: () => { starts += 1; return new FakeChild([]); } }).run(task), { code: "recovery_required" }); assert.equal(starts, 0); const corrupt = join(task.stateRoot, "runs", "corrupt.json"); writeFileSync(corrupt, "{broken"); assert.throws(() => readRunReceipt(task.stateRoot, "corrupt"), { code: "recovery_required" }); } finally { rmSync(root, { recursive: true, force: true }); }
});
test("implementation replay rejects receipt or competing claim before provisioning a missing worktree", async () => {
  const custody = () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) });
  const fixture = linkedGitFixture("grok-one-shot-replay-receipt-"); const { root, repository, worktree, stateRoot, git } = fixture;
  try {
    writeFileSync(join(repository, "base.mjs"), "export {}\n"); git(["add", "."]); git(["commit", "--quiet", "-m", "base"]);
    const task = packet(root); task.repositoryRoot = repository; task.worktree = worktree; task.stateRoot = stateRoot; task.sourceSha = git(["rev-parse", "HEAD"]); task.approval.packetDigest = packetDigest(task);
    const first = await createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }]) }).run(task);
    assert.equal(first.state, "candidate"); git(["worktree", "remove", "--force", worktree]); assert.equal(existsSync(worktree), false);
    let starts = 0; await assert.rejects(() => createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => { starts += 1; return new FakeChild([]); } }).run(task), { code: "recovery_required" }); assert.equal(starts, 0); assert.equal(existsSync(worktree), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
  const competing = linkedGitFixture("grok-one-shot-replay-lock-"); const { root: lockRoot, repository: lockRepo, worktree: lockWorktree, stateRoot: lockState, git: lockGit } = competing;
  try {
    writeFileSync(join(lockRepo, "base.mjs"), "export {}\n"); lockGit(["add", "."]); lockGit(["commit", "--quiet", "-m", "base"]);
    const task = packet(lockRoot); task.repositoryRoot = lockRepo; task.worktree = lockWorktree; task.stateRoot = lockState; task.sourceSha = lockGit(["rev-parse", "HEAD"]); task.approval.packetDigest = packetDigest(task);
    mkdirSync(join(lockState, "runs"), { recursive: true }); writeFileSync(join(lockState, "runs", `${task.taskRunId}.lock`), JSON.stringify({ taskRunId: task.taskRunId, ownerNonce: "other-owner" }));
    let starts = 0; await assert.rejects(() => createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => { starts += 1; return new FakeChild([]); } }).run(task), { code: "recovery_required" }); assert.equal(starts, 0); assert.equal(existsSync(lockWorktree), false);
  } finally { rmSync(lockRoot, { recursive: true, force: true }); }
});
test("implementation provisioning failure releases acquired task ownership before provider spawn", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-provision-failure-")); try {
    const task = packet(root); task.repositoryRoot = join(root, "missing-repository"); task.worktree = join(root, "candidate"); task.stateRoot = join(root, "state"); task.approval.packetDigest = packetDigest(task);
    let starts = 0;
    await assert.rejects(() => createOneShotRunner({ spawnImpl: () => { starts += 1; return new FakeChild([]); } }).run(task), /approved source repository does not exist/);
    assert.equal(starts, 0);
    assert.equal(existsSync(join(task.stateRoot, "runs", `${task.taskRunId}.lock`)), false);
    assert.equal(existsSync(task.worktree), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("invalid implementation custody is rejected before state claims or worktree provisioning", async () => {
  const fixture = linkedGitFixture("grok-one-shot-invalid-custody-"); const { root, repository, worktree, stateRoot, git } = fixture;
  try {
    writeFileSync(join(repository, "base.mjs"), "export {}\n"); git(["add", "."]); git(["commit", "--quiet", "-m", "base"]);
    const task = packet(root); task.repositoryRoot = repository; task.worktree = worktree; task.stateRoot = join(repository, ".state"); task.sourceSha = git(["rev-parse", "HEAD"]); task.approval.packetDigest = packetDigest(task);
    let starts = 0;
    await assert.rejects(() => createOneShotRunner({ spawnImpl: () => { starts += 1; return new FakeChild([]); } }).run(task), /state root must not overlap/);
    assert.equal(starts, 0); assert.equal(existsSync(join(repository, ".state")), false); assert.equal(existsSync(worktree), false); assert.equal(existsSync(stateRoot), true);
    mkdirSync(worktree); const existing = { ...task, taskRunId: "run-002", requestId: "request-002", stateRoot: join(worktree, ".state"), approval: { ...task.approval } }; existing.approval.packetDigest = packetDigest(existing);
    await assert.rejects(() => createOneShotRunner({ spawnImpl: () => { starts += 1; return new FakeChild([]); } }).run(existing), /state root must not overlap/);
    assert.equal(starts, 0); assert.equal(existsSync(existing.stateRoot), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("invalid repair custody is rejected before either state claim", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-invalid-repair-custody-")); try {
    const task = packet(root); const custody = () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] });
    const first = await createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }]) }).run(task);
    const findings = { contractVersion: CONTRACT_VERSIONS.repairFindings, taskRunId: first.taskRunId, requestId: first.requestId, priorReceiptDigest: receiptDigest(first), sourceSha: task.sourceSha, repositoryRoot: resolve(task.repositoryRoot), worktree: resolve(task.worktree), createdAt: new Date().toISOString(), findings: [{ code: "validation_failed", message: "Codex validation failed" }] };
    const repair = { ...task, mode: "repair", requestId: "request-002", stateRoot: join(task.repositoryRoot, ".state"), continuation: { priorTaskRunId: first.taskRunId, priorRequestId: first.requestId, priorSessionId: first.observed.sessionId, priorReceiptDigest: receiptDigest(first), priorSourceSha: first.binding.sourceSha, priorRepositoryRoot: first.binding.repositoryRoot, priorWorktree: first.binding.worktree, priorDiffDigest: first.binding.diffDigest }, findingsDigest: receiptDigest(findings), policy: { ...task.policy, repairBudget: 1 }, approval: { ...task.approval } }; repair.approval.packetDigest = packetDigest(repair);
    let starts = 0;
    await assert.rejects(() => createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => { starts += 1; return new FakeChild([]); } }).run(repair, { priorReceipt: first, resumeSessionId: first.observed.sessionId, repairEvidence: findings }), /state root must not overlap/);
    assert.equal(starts, 0); assert.equal(existsSync(repair.stateRoot), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("collection persists an explicit Codex decision and exact replay is idempotent", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try { const task = packet(resolve(root)); const custody = () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) }); const receipt = await createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }]) }).run(task); const decision = { contractVersion: CONTRACT_VERSIONS.acceptance, taskRunId: task.taskRunId, requestId: task.requestId, receiptDigest: receiptDigest(receipt), custodyDigest: receipt.binding.custodyDigest, disposition: "accepted", decidedAt: new Date().toISOString(), idempotencyKey: "collect-001", validationEvidenceRef: "codex-test", validationEvidenceDigest: "sha256:" + "3".repeat(64) }; assert.deepEqual(persistAcceptanceDecision(task.stateRoot, decision, receipt, { verifyCustodyImpl: custody }), decision); assert.deepEqual(persistAcceptanceDecision(task.stateRoot, decision, receipt, { verifyCustodyImpl: custody }), decision); } finally { rmSync(root, { recursive: true, force: true }); }
});
test("Git custody inventory binds controller-applied renames and untracked file contents for collection", async () => {
  const fixture = linkedGitFixture("grok-one-shot-git-"); const { root, repository, worktree, stateRoot, git } = fixture;
  try {
    mkdirSync(join(repository, "src"), { recursive: true }); writeFileSync(join(repository, "src", "base.mjs"), "export {};\n"); writeFileSync(join(repository, "src", "old.mjs"), "export const old = true;\n"); git(["add", "src/base.mjs", "src/old.mjs"]); git(["commit", "--quiet", "-m", "base"]); const sourceSha = git(["rev-parse", "HEAD"]); git(["worktree", "add", "--quiet", "--detach", worktree, sourceSha]);
    const task = packet(root); task.repositoryRoot = repository; task.worktree = worktree; task.sourceSha = sourceSha; task.stateRoot = stateRoot; task.approval.packetDigest = packetDigest(task);
    const receipt = await createOneShotRunner({ artifactDelivery: { execute: () => { renameSync(join(worktree, "src", "old.mjs"), join(worktree, "src", "renamed.mjs")); writeFileSync(join(worktree, "src", "untracked.mjs"), "export const value = 1;\n"); git(["add", "-A"], worktree); return { ok: true, decisions: [], validationEvidence: [], appliedPaths: ["src/renamed.mjs", "src/untracked.mjs"] }; } }, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }]) }).run(task); assert.equal(receipt.state, "candidate"); assert.deepEqual(receipt.changedFiles.map((entry) => entry.path), ["src/renamed.mjs", "src/untracked.mjs"]); assert.equal(receipt.changedFiles[0].previousPath, "src/old.mjs");
    const before = verifyCustody(task, { allowDirty: true }); writeFileSync(join(worktree, "src", "untracked.mjs"), "export const value = 2;\n"); const after = verifyCustody(task, { allowDirty: true }); assert.notEqual(after.diffDigest, before.diffDigest);
    const decision = { contractVersion: CONTRACT_VERSIONS.acceptance, taskRunId: task.taskRunId, requestId: task.requestId, receiptDigest: receiptDigest(receipt), custodyDigest: receipt.binding.custodyDigest, disposition: "accepted", decidedAt: new Date().toISOString(), idempotencyKey: "collect-untracked", validationEvidenceRef: "codex-test", validationEvidenceDigest: "sha256:" + "4".repeat(64) };
    assert.throws(() => persistAcceptanceDecision(stateRoot, decision, receipt), /custody changed/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("Git-authoritative custody rejects an out-of-scope edit omitted by the terminal frame", async () => {
  const fixture = linkedGitFixture("grok-one-shot-git-"); const { root, repository, worktree, stateRoot, git } = fixture;
  try {
    mkdirSync(join(repository, "src"), { recursive: true }); writeFileSync(join(repository, "src", "base.mjs"), "export {};\n"); writeFileSync(join(repository, "other.mjs"), "export const value = 1;\n"); git(["add", "."]); git(["commit", "--quiet", "-m", "base"]); const sourceSha = git(["rev-parse", "HEAD"]); git(["worktree", "add", "--quiet", "--detach", worktree, sourceSha]); const task = packet(root); task.repositoryRoot = repository; task.worktree = worktree; task.sourceSha = sourceSha; task.stateRoot = stateRoot; task.approval.packetDigest = packetDigest(task);
    const receipt = await createOneShotRunner({ artifactDelivery: { beginTransaction: beginArtifactTransaction }, spawnImpl: () => { writeFileSync(join(worktree, "other.mjs"), "export const value = 2;\n"); return new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId, changedFiles: [] }]); } }).run(task);
    assert.equal(receipt.state, "failed"); assert.equal(receipt.diagnostics.code, "scope_violation");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("Git custody rejects a primary checkout and overlapping state roots", () => {
  const fixture = linkedGitFixture("grok-one-shot-primary-"); const { root, repository, stateRoot, git } = fixture;
  try {
    writeFileSync(join(repository, "base.mjs"), "export {};\n"); git(["add", "."]); git(["commit", "--quiet", "-m", "base"]); const task = packet(root); task.repositoryRoot = repository; task.worktree = repository; task.sourceSha = git(["rev-parse", "HEAD"]); task.stateRoot = stateRoot; task.approval.packetDigest = packetDigest(task);
    assert.throws(() => verifyCustody(task), /distinct from the primary repository/);
    task.worktree = join(root, "worktree"); git(["worktree", "add", "--quiet", "--detach", task.worktree, task.sourceSha]); task.stateRoot = join(task.worktree, ".state"); task.approval.packetDigest = packetDigest(task);
    assert.throws(() => verifyCustody(task), /state root must not overlap/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("in-process cancellation never claims success without child close proof", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try { const task = packet(resolve(root)); task.policy.timeouts.cancelMs = 20; task.approval.packetDigest = packetDigest(task); const child = new NonClosingChild(); const runner = createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) }), killTree: () => {}, spawnImpl: () => child }); const runPromise = runner.run(task); await new Promise((resolveNow) => setImmediate(resolveNow)); const cancelPromise = runner.cancel(task.taskRunId); const [receipt, cancelled] = await Promise.all([runPromise, cancelPromise]); assert.equal(receipt.state, "recovery_required"); assert.equal(cancelled.state, "recovery_required"); child.emit("close", 0); await new Promise((resolveNow) => setImmediate(resolveNow)); assert.equal(readRunReceipt(task.stateRoot, task.taskRunId).state, "recovery_required"); } finally { rmSync(root, { recursive: true, force: true }); }
});
test("timeout stop paths require recovery when child termination is unproven", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try { const task = packet(resolve(root)); task.policy.timeouts.startMs = 10; task.policy.timeouts.cancelMs = 20; task.approval.packetDigest = packetDigest(task); const receipt = await createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) }), killTree: () => {}, spawnImpl: () => new NonClosingChild() }).run(task); assert.equal(receipt.state, "recovery_required"); assert.equal(receipt.diagnostics.code, "child_termination_unproven"); } finally { rmSync(root, { recursive: true, force: true }); }
});
test("first valid output clears start timeout while later terminal output remains within turn timeout", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try { const task = packet(resolve(root)); task.policy.timeouts.startMs = 20; task.policy.timeouts.turnMs = 100; task.policy.timeouts.idleMs = 100; task.approval.packetDigest = packetDigest(task); const receipt = await createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }), killTree: () => {}, spawnImpl: () => new DelayedOutputChild(task) }).run(task); assert.equal(receipt.state, "candidate"); } finally { rmSync(root, { recursive: true, force: true }); }
});
test("status contracts accept validated starting projections before a child PID exists", () => {
  const starting = { contractVersion: "agent-platform.grok-build-engineer-one-shot.v1", taskRunId: "run-001", requestId: "request-001", state: "starting", sessionId: "123e4567-e89b-12d3-a456-426614174000", ownerNonce: "owner", pid: null, binding: { sourceSha: "0123456789abcdef0123456789abcdef01234567", repositoryRoot: "C:/repo", worktree: "C:/repo", custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) } }; assert.equal(cliResponse("status", starting.taskRunId, { receipt: starting }).receipt.state, "starting");
});
test("cross-process cancellation is a stable unsupported result and writes no receipt", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-cancel-"));
  try {
    const task = packet(resolve(root)); const running = { contractVersion: "agent-platform.grok-build-engineer-one-shot.v1", taskRunId: task.taskRunId, requestId: task.requestId, state: "running", mode: task.mode, startedAt: new Date().toISOString(), ownerNonce: "owner", sessionId: "123e4567-e89b-12d3-a456-426614174000", pid: 4242, binding: { sourceSha: task.sourceSha, repositoryRoot: resolve(task.repositoryRoot), worktree: resolve(task.worktree), custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) }, requested: { model: task.provider.model, executable: task.provider.executable }, allowedScope: { worktree: resolve(task.worktree), paths: ["src/**"], commands: ["node test"], network: "none", tools: ["read_file"], environment: [] } };
    mkdirSync(join(task.stateRoot, "runs"), { recursive: true }); writeFileSync(join(task.stateRoot, "runs", `${task.taskRunId}.json`), `${JSON.stringify(running)}\n`);
    assert.throws(() => cancelRun(task.stateRoot, task.taskRunId), (error) => error instanceof RunnerCancellationUnsupportedError && error.code === "unsupported");
    assert.equal(readRunReceipt(task.stateRoot, task.taskRunId).state, "running");
    running.state = "starting"; running.pid = null; writeFileSync(join(task.stateRoot, "runs", `${task.taskRunId}.json`), `${JSON.stringify(running)}\n`);
    assert.throws(() => cancelRun(task.stateRoot, task.taskRunId), (error) => error instanceof RunnerCancellationUnsupportedError && error.code === "unsupported");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("artifact evidence persistence failure fails closed before controller execution", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-evidence-")); try {
    const task = packet(resolve(root)); let executions = 0;
    const receipt = await createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }), artifactDelivery: { persistArtifact: () => { throw new Error("artifact evidence disk full"); }, execute: () => { executions += 1; throw new Error("must not execute"); } }, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }]) }).run(task);
    assert.equal(receipt.state, "failed"); assert.equal(receipt.diagnostics.code, "artifact_evidence_failed"); assert.equal(executions, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("unsupported artifact kinds persist bounded evidence without candidate effects and remain non-repairable", async () => {
  const fixture = linkedGitFixture("grok-one-shot-rejected-artifact-"); const { root, repository, worktree, stateRoot, git } = fixture;
  try {
    mkdirSync(join(repository, "src"), { recursive: true });
    writeFileSync(join(repository, "src", "base.mjs"), "export const base = true;\n");
    git(["add", "."]); git(["commit", "--quiet", "-m", "base"]);
    const sourceSha = git(["rev-parse", "HEAD"]); git(["worktree", "add", "--quiet", "--detach", worktree, sourceSha]);
    const task = packet(root); task.repositoryRoot = repository; task.worktree = worktree; task.stateRoot = stateRoot; task.sourceSha = sourceSha; task.approval.packetDigest = packetDigest(task);
    const output = JSON.stringify({ contractVersion: ARTIFACT_CONTRACT_VERSION, taskRunId: task.taskRunId, requestId: task.requestId, operations: [{ kind: "search_replace", path: "src/result.mjs", content: "export const result = true;\n" }] });
    const receipt = await createProductionOneShotRunner({ spawnImpl: () => new FakeChild([{ type: "text", taskRunId: task.taskRunId, requestId: task.requestId, text: output }, { type: "end", taskRunId: task.taskRunId, requestId: task.requestId }]) }).run(task);
    assert.equal(receipt.state, "failed"); assert.equal(receipt.diagnostics.code, "artifact_invalid");
    assert.equal(existsSync(join(worktree, "src", "result.mjs")), false); assert.equal(git(["status", "--porcelain"], worktree), "");
    const rejectedPath = join(stateRoot, "artifacts", task.taskRunId, `${task.requestId}.rejected.json`);
    assert.equal(existsSync(rejectedPath), true); assert.equal(JSON.parse(readFileSync(rejectedPath, "utf8")).structure.operations.items[0].kind, "search_replace");
    const findings = { contractVersion: CONTRACT_VERSIONS.repairFindings, taskRunId: receipt.taskRunId, requestId: receipt.requestId, priorReceiptDigest: receiptDigest(receipt), sourceSha, repositoryRoot: resolve(repository), worktree: resolve(worktree), createdAt: new Date().toISOString(), findings: [{ code: "artifact_invalid", message: "Rejected artifact cannot be repaired." }] };
    const repair = packet(root, "repair"); repair.repositoryRoot = repository; repair.worktree = worktree; repair.stateRoot = stateRoot; repair.sourceSha = sourceSha; repair.taskRunId = task.taskRunId; repair.requestId = "request-002"; repair.continuation = { priorTaskRunId: receipt.taskRunId, priorRequestId: receipt.requestId, priorSessionId: receipt.observed.sessionId, priorReceiptDigest: receiptDigest(receipt), priorSourceSha: sourceSha, priorRepositoryRoot: resolve(repository), priorWorktree: resolve(worktree), priorDiffDigest: receipt.binding.diffDigest }; repair.findingsDigest = receiptDigest(findings); repair.approval = { ...repair.approval, packetDigest: packetDigest(repair) };
    await assert.rejects(() => createOneShotRunner().run(repair, { resumeSessionId: receipt.observed.sessionId, repairEvidence: findings, priorReceipt: receipt }), /prior candidate receipt/i);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("rejected artifact evidence persistence failure fails closed before controller execution", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-rejected-evidence-failure-")); try {
    const task = packet(resolve(root)); let executions = 0;
    const receipt = await createOneShotRunner({
      verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }),
      artifactDelivery: { parseOutput: () => { throw new TypeError("artifact operation 0 kind is unsupported"); }, persistRejectedArtifact: () => { throw new Error("rejection evidence disk full"); }, execute: () => { executions += 1; throw new Error("must not execute"); } },
      spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }])
    }).run(task);
    assert.equal(receipt.state, "failed"); assert.equal(receipt.diagnostics.code, "artifact_rejection_evidence_failed"); assert.equal(executions, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("artifact decision persistence failure restores the pre-call candidate", async () => {
  const fixture = linkedGitFixture("grok-one-shot-decision-rollback-"); const { root, repository, worktree, stateRoot, git } = fixture;
  try {
    mkdirSync(join(repository, "src"), { recursive: true });
    writeFileSync(join(repository, "src", "base.mjs"), "export const base = true;\n");
    git(["add", "."]); git(["commit", "--quiet", "-m", "base"]);
    const sourceSha = git(["rev-parse", "HEAD"]); git(["worktree", "add", "--quiet", "--detach", worktree, sourceSha]);
    const task = packet(root); task.repositoryRoot = repository; task.worktree = worktree; task.stateRoot = stateRoot; task.sourceSha = sourceSha; task.approval.packetDigest = packetDigest(task);
    const baseline = verifyCustody(task);
    const receipt = await createOneShotRunner({
      artifactDelivery: {
        beginTransaction: beginArtifactTransaction,
        execute: (options) => executeArtifact(options),
        persistDecision: () => { throw new Error("decision disk full"); }
      },
      spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }])
    }).run(task);
    assert.equal(receipt.state, "failed"); assert.equal(receipt.diagnostics.code, "artifact_evidence_failed");
    assert.equal(existsSync(join(worktree, "src", "result.mjs")), false);
    assert.equal(verifyCustody(task).diffDigest, baseline.diffDigest);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("terminal receipt persistence failure restores the pre-call candidate", async () => {
  const fixture = linkedGitFixture("grok-one-shot-terminal-rollback-"); const { root, repository, worktree, stateRoot, git } = fixture;
  try {
    mkdirSync(join(repository, "src"), { recursive: true });
    writeFileSync(join(repository, "src", "base.mjs"), "export const base = true;\n");
    git(["add", "."]); git(["commit", "--quiet", "-m", "base"]);
    const sourceSha = git(["rev-parse", "HEAD"]); git(["worktree", "add", "--quiet", "--detach", worktree, sourceSha]);
    const task = packet(root); task.repositoryRoot = repository; task.worktree = worktree; task.stateRoot = stateRoot; task.sourceSha = sourceSha; task.approval.packetDigest = packetDigest(task);
    const baseline = verifyCustody(task);
    await assert.rejects(() => createOneShotRunner({
      artifactDelivery: { beginTransaction: beginArtifactTransaction, execute: (options) => executeArtifact(options) },
      persistOwnedImpl: () => { throw new Error("terminal disk full"); },
      spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }])
    }).run(task), /terminal disk full/);
    assert.equal(existsSync(join(worktree, "src", "result.mjs")), false);
    assert.equal(verifyCustody(task).diffDigest, baseline.diffDigest);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("successful validation side effects trigger scope denial and full rollback", async () => {
  const fixture = linkedGitFixture("grok-one-shot-scope-rollback-"); const { root, repository, worktree, stateRoot, git } = fixture;
  try {
    mkdirSync(join(repository, "src"), { recursive: true });
    writeFileSync(join(repository, "src", "base.mjs"), "export const base = true;\n");
    git(["add", "."]); git(["commit", "--quiet", "-m", "base"]);
    const sourceSha = git(["rev-parse", "HEAD"]); git(["worktree", "add", "--quiet", "--detach", worktree, sourceSha]);
    const task = packet(root); task.repositoryRoot = repository; task.worktree = worktree; task.stateRoot = stateRoot; task.sourceSha = sourceSha; task.policy.allowedCommands = ["node test"]; task.approval.packetDigest = packetDigest(task);
    const baseline = verifyCustody(task);
    const receipt = await createOneShotRunner({
      artifactDelivery: {
        parseOutput: (_output, current) => ({ contractVersion: ARTIFACT_CONTRACT_VERSION, taskRunId: current.taskRunId, requestId: current.requestId, operations: [{ kind: "write_file", path: "src/result.mjs", content: "export {};\n" }, { kind: "run_command", command: "node test" }] }),
        beginTransaction: beginArtifactTransaction,
        execute: (options) => executeArtifact({ ...options, spawnSyncImpl: () => { writeFileSync(join(worktree, "validation-leak.mjs"), "export const leaked = true;\n"); return { status: 0, stdout: "pass\n", stderr: "", error: null }; } })
      },
      spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }])
    }).run(task);
    assert.equal(receipt.state, "failed"); assert.equal(receipt.diagnostics.code, "scope_violation");
    assert.equal(existsSync(join(worktree, "src", "result.mjs")), false);
    assert.equal(existsSync(join(worktree, "validation-leak.mjs")), false);
    assert.equal(verifyCustody(task).diffDigest, baseline.diffDigest);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("state persistence failures release claims only after confirmed child close", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-persist-")); try {
    const task = packet(resolve(root)); let writes = 0; const child = new NonClosingChild(); child.kill = () => { child.emit("close", 143); };
    const persistImpl = (stateRoot, taskRunId, receipt) => { writes += 1; mkdirSync(join(stateRoot, "runs"), { recursive: true }); if (writes === 2) throw new Error("disk full"); writeFileSync(join(stateRoot, "runs", `${taskRunId}.json`), `${JSON.stringify(receipt)}\n`); return receipt; };
    await assert.rejects(() => createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) }), persistImpl, killTree: (owned) => owned.kill(), spawnImpl: () => child }).run(task), { code: "recovery_required" });
    assert.equal(existsSync(join(task.stateRoot, "runs", `${task.taskRunId}.lock`)), false);
    const terminalTask = packet(resolve(root)); terminalTask.taskRunId = "run-002"; terminalTask.requestId = "request-002"; terminalTask.approval.packetDigest = packetDigest(terminalTask);
    await assert.rejects(() => createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }), persistOwnedImpl: () => { throw new Error("terminal disk full"); }, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: terminalTask.taskRunId, requestId: terminalTask.requestId }]) }).run(terminalTask), /terminal disk full/);
    assert.equal(existsSync(join(terminalTask.stateRoot, "runs", `${terminalTask.taskRunId}.lock`)), false);

    const unconfirmedTask = packet(resolve(root)); unconfirmedTask.taskRunId = "run-003"; unconfirmedTask.requestId = "request-003"; unconfirmedTask.policy.timeouts.cancelMs = 5; unconfirmedTask.approval.packetDigest = packetDigest(unconfirmedTask);
    let unconfirmedWrites = 0; const unconfirmedChild = new NonClosingChild();
    const unconfirmedPersist = (stateRoot, taskRunId, receipt) => { unconfirmedWrites += 1; mkdirSync(join(stateRoot, "runs"), { recursive: true }); if (unconfirmedWrites === 2) throw new Error("disk full"); writeFileSync(join(stateRoot, "runs", `${taskRunId}.json`), `${JSON.stringify(receipt)}\n`); return receipt; };
    const unconfirmedRunner = createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) }), persistImpl: unconfirmedPersist, killTree: (owned) => owned.kill(), spawnImpl: () => unconfirmedChild });
    await assert.rejects(() => unconfirmedRunner.run(unconfirmedTask), { code: "recovery_required" });
    assert.equal(existsSync(join(unconfirmedTask.stateRoot, "runs", `${unconfirmedTask.taskRunId}.lock`)), true, "an unconfirmed child must retain the cross-process task claim");
    assert.deepEqual(unconfirmedRunner.activeRuns(), [unconfirmedTask.taskRunId], "an unconfirmed child remains owned for recovery");
    const lateCancel = unconfirmedRunner.cancel(unconfirmedTask.taskRunId); unconfirmedChild.emit("close", 143); const lateCancellation = await lateCancel;
    assert.equal(lateCancellation.state, "recovery_required");
    assert.equal(existsSync(join(unconfirmedTask.stateRoot, "runs", `${unconfirmedTask.taskRunId}.lock`)), false, "confirmed late close releases the task claim");
    assert.deepEqual(unconfirmedRunner.activeRuns(), []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("repair binds dirty custody/findings/session, consumes one prior candidate budget, and preserves both attempt receipts", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try {
    const task = packet(resolve(root)); let currentDiff = "sha256:" + "2".repeat(64); const custody = () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: currentDiff }); const first = await createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }]) }).run(task);
    const findings = { contractVersion: CONTRACT_VERSIONS.repairFindings, taskRunId: first.taskRunId, requestId: first.requestId, priorReceiptDigest: receiptDigest(first), sourceSha: task.sourceSha, repositoryRoot: resolve(task.repositoryRoot), worktree: resolve(task.worktree), createdAt: new Date().toISOString(), findings: [{ code: "validation_failed", message: "Codex validation failed" }] };
    const repair = { ...task, mode: "repair", requestId: "request-002", continuation: { priorTaskRunId: first.taskRunId, priorRequestId: first.requestId, priorSessionId: first.observed.sessionId, priorReceiptDigest: receiptDigest(first), priorSourceSha: first.binding.sourceSha, priorRepositoryRoot: first.binding.repositoryRoot, priorWorktree: first.binding.worktree, priorDiffDigest: first.binding.diffDigest }, findingsDigest: receiptDigest(findings), policy: { ...task.policy, repairBudget: 1 }, approval: { ...task.approval } }; repair.approval.packetDigest = packetDigest(repair);
    const second = await createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: repair.taskRunId, requestId: repair.requestId }]) }).run(repair, { priorReceipt: first, resumeSessionId: first.observed.sessionId, repairEvidence: findings }); assert.equal(second.state, "candidate"); assert.equal(second.observed.sessionId, first.observed.sessionId); assert.deepEqual(JSON.parse(readFileSync(join(repair.stateRoot, "attempts", repair.taskRunId, "request-001.json"), "utf8")), first);
    const repairKey = repair.continuation.priorReceiptDigest.slice(7); const repairLock = join(repair.stateRoot, "runs", `repair-${repairKey}.lock`); const consumptionPath = join(repair.stateRoot, "repair-consumptions", `${repairKey}.json`);
    assert.equal(existsSync(repairLock), false, "successful repair must release its active claim"); assert.equal(existsSync(consumptionPath), true, "successful repair must retain immutable anti-replay evidence"); assert.deepEqual(JSON.parse(readFileSync(consumptionPath, "utf8")), { contractVersion: "agent-platform.grok-build-engineer-repair-consumption.v1", priorReceiptDigest: repair.continuation.priorReceiptDigest, taskRunId: repair.taskRunId, requestId: repair.requestId, sessionId: repair.continuation.priorSessionId, repairReceiptDigest: receiptDigest(second), consumedAt: second.finishedAt });
    const competing = { ...repair, taskRunId: "run-002", requestId: "request-003", approval: { ...repair.approval } }; competing.continuation = { ...repair.continuation }; competing.approval.packetDigest = packetDigest(competing); await assert.rejects(() => createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => new FakeChild([]) }).run(competing, { priorReceipt: first, resumeSessionId: first.observed.sessionId, repairEvidence: findings }), { code: "recovery_required" });
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("repair claim is released when execution fails before provider spawn", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-repair-preflight-")); try {
    const task = packet(resolve(root)); const custody = () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }); const first = await createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }]) }).run(task);
    const findings = { contractVersion: CONTRACT_VERSIONS.repairFindings, taskRunId: first.taskRunId, requestId: first.requestId, priorReceiptDigest: receiptDigest(first), sourceSha: task.sourceSha, repositoryRoot: resolve(task.repositoryRoot), worktree: resolve(task.worktree), createdAt: new Date().toISOString(), findings: [{ code: "validation_failed", message: "Codex validation failed" }] };
    const repair = { ...task, mode: "repair", requestId: "request-002", continuation: { priorTaskRunId: first.taskRunId, priorRequestId: first.requestId, priorSessionId: first.observed.sessionId, priorReceiptDigest: receiptDigest(first), priorSourceSha: first.binding.sourceSha, priorRepositoryRoot: first.binding.repositoryRoot, priorWorktree: first.binding.worktree, priorDiffDigest: first.binding.diffDigest }, findingsDigest: receiptDigest(findings), policy: { ...task.policy, repairBudget: 1 }, approval: { ...task.approval } }; repair.approval.packetDigest = packetDigest(repair);
    const taskLock = join(repair.stateRoot, "runs", `${repair.taskRunId}.lock`); writeFileSync(taskLock, `${JSON.stringify({ taskRunId: repair.taskRunId, ownerNonce: "other-owner" })}\n`);
    await assert.rejects(() => createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => new FakeChild([]) }).run(repair, { priorReceipt: first, resumeSessionId: first.observed.sessionId, repairEvidence: findings }), { code: "recovery_required" }); rmSync(taskLock);
    const repairLock = join(repair.stateRoot, "runs", `repair-${repair.continuation.priorReceiptDigest.slice(7)}.lock`);
    await assert.rejects(() => createOneShotRunner({ verifyCustodyImpl: () => { throw new Error("custody failed"); }, spawnImpl: () => new FakeChild([]) }).run(repair, { priorReceipt: first, resumeSessionId: first.observed.sessionId, repairEvidence: findings }), /custody failed/);
    assert.equal(existsSync(taskLock), false); assert.equal(existsSync(repairLock), false);
    const repaired = await createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: repair.taskRunId, requestId: repair.requestId }]) }).run(repair, { priorReceipt: first, resumeSessionId: first.observed.sessionId, repairEvidence: findings }); assert.equal(repaired.state, "candidate");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("repair consumption persistence failure retains the active claim and fails closed", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-repair-consumption-failure-")); try {
    const task = packet(resolve(root)); const custody = () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }); const first = await createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId }]) }).run(task);
    const findings = { contractVersion: CONTRACT_VERSIONS.repairFindings, taskRunId: first.taskRunId, requestId: first.requestId, priorReceiptDigest: receiptDigest(first), sourceSha: task.sourceSha, repositoryRoot: resolve(task.repositoryRoot), worktree: resolve(task.worktree), createdAt: new Date().toISOString(), findings: [{ code: "validation_failed", message: "Codex validation failed" }] };
    const repair = { ...task, mode: "repair", requestId: "request-002", continuation: { priorTaskRunId: first.taskRunId, priorRequestId: first.requestId, priorSessionId: first.observed.sessionId, priorReceiptDigest: receiptDigest(first), priorSourceSha: first.binding.sourceSha, priorRepositoryRoot: first.binding.repositoryRoot, priorWorktree: first.binding.worktree, priorDiffDigest: first.binding.diffDigest }, findingsDigest: receiptDigest(findings), policy: { ...task.policy, repairBudget: 1 }, approval: { ...task.approval } }; repair.approval.packetDigest = packetDigest(repair);
    await assert.rejects(() => createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: repair.taskRunId, requestId: repair.requestId }]), persistRepairConsumptionImpl: () => { throw new Error("disk full"); } }).run(repair, { priorReceipt: first, resumeSessionId: first.observed.sessionId, repairEvidence: findings }), { code: "recovery_required" });
    assert.equal(existsSync(join(repair.stateRoot, "runs", `repair-${repair.continuation.priorReceiptDigest.slice(7)}.lock`)), true, "failed consumption persistence must preserve the repair claim");
    assert.equal(existsSync(join(repair.stateRoot, "repair-consumptions", `${repair.continuation.priorReceiptDigest.slice(7)}.json`)), false, "failed consumption persistence must not invent durable anti-replay evidence");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("provider validation evidence is rejected regardless of its claimed outcome", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try { const task = packet(resolve(root)); const custody = () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64) }); const unknown = await createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId, validationEvidence: [{ command: "npm publish", exitCode: 0 }] }]) }).run(task); assert.equal(unknown.diagnostics.code, "provider_validation_claimed"); const failed = packet(resolve(root)); failed.taskRunId = "run-002"; failed.requestId = "request-002"; failed.approval = { ...failed.approval, packetDigest: packetDigest(failed) }; const result = await createOneShotRunner({ verifyCustodyImpl: custody, spawnImpl: () => new FakeChild([{ type: "end", taskRunId: failed.taskRunId, requestId: failed.requestId, validationEvidence: [{ command: "node test", exitCode: 1 }] }]) }).run(failed); assert.equal(result.diagnostics.code, "provider_validation_claimed"); } finally { rmSync(root, { recursive: true, force: true }); }
});
test("provider validation claims persist a failed receipt and release the claim", async () => {
  const root = mkdtempSync(join(tmpdir(), "grok-one-shot-")); try { const task = packet(resolve(root)); const result = await createOneShotRunner({ verifyCustodyImpl: () => ({ custodyDigest: "sha256:" + "1".repeat(64), diffDigest: "sha256:" + "2".repeat(64), changedFiles: [] }), spawnImpl: () => new FakeChild([{ type: "end", taskRunId: task.taskRunId, requestId: task.requestId, validationEvidence: [{ command: "node test", exitCode: 0, outputDigest: "not-a-digest" }] }]) }).run(task); assert.equal(result.state, "failed"); assert.equal(result.diagnostics.code, "provider_validation_claimed"); assert.equal(readRunReceipt(task.stateRoot, task.taskRunId).diagnostics.code, "provider_validation_claimed"); assert.equal(existsSync(join(task.stateRoot, "runs", `${task.taskRunId}.lock`)), false); } finally { rmSync(root, { recursive: true, force: true }); }
});
