import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { evaluatePreToolUse, PRETOOL_GUARD_VERSION } from "../src/pretool-guard.mjs";
import { assertGuardDiscovered, assertNoCompetingInputHooks, installPreToolGuard } from "../src/pretool-overlay.mjs";

function fixture(root) { return { contractVersion: PRETOOL_GUARD_VERSION, taskRunId: "run-001", requestId: "request-001", sessionId: "123e4567-e89b-42d3-a456-426614174000", worktree: resolve(root), paths: ["src/**", "test/**"], commands: ["npm test"], tools: ["read_file", "grep", "list_dir", "search_replace", "run_terminal_cmd"], network: "none" }; }
function event(policy, toolName, toolInput) { return { hookEventName: "PreToolUse", sessionId: policy.sessionId, cwd: policy.worktree, workspaceRoot: policy.worktree, toolName, toolInput }; }

test("guard allows the exact command and approved edit scope", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-guard-")); try {
    mkdirSync(join(root, "src")); const policy = fixture(root);
    assert.equal(evaluatePreToolUse(event(policy, "run_terminal_command", { command: "npm test" }), policy).decision, "allow");
    assert.equal(evaluatePreToolUse(event(policy, "search_replace", { file_path: join(root, "src", "index.mjs") }), policy).decision, "allow");
    assert.equal(evaluatePreToolUse(event(policy, "read_file", { target_file: join(root, "package.json") }), policy).decision, "allow");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("guard denies inherited commands, background work, path escapes, unknown tools, and session drift", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-guard-")); try {
    const policy = fixture(root);
    for (const denied of [
      event(policy, "Bash", { command: "cmd /c npm test" }),
      event(policy, "Bash", { command: "npm test; Get-ChildItem" }),
      event(policy, "Bash", { command: "npm test", is_background: true }),
      event(policy, "Edit", { file_path: join(root, "package.json") }),
      event(policy, "read_file", { target_file: resolve(root, "..", "secret.txt") }),
      event(policy, "read_file", { target_file: `${join(root, "src", "index.mjs")}:secret` }),
      event(policy, "WebFetch", { url: "https://example.com" }),
      { ...event(policy, "Bash", { command: "npm test" }), sessionId: "other" }
    ]) assert.equal(evaluatePreToolUse(denied, policy).decision, "deny");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("run-scoped user hook overlay is integrity-bound, discoverable, and removable", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-guard-")); try {
    const policy = fixture(root);
    const packet = { taskRunId: policy.taskRunId, requestId: policy.requestId, worktree: policy.worktree, stateRoot: join(root, "state") };
    const overlay = installPreToolGuard({ packet, policy, sessionId: policy.sessionId, hookRoot: join(root, "user-hooks") });
    assert.equal(overlay.verify(), true);
    assert.equal(assertGuardDiscovered({ hooks: [{ event: "pre_tool_use", hookType: "command", target: overlay.command, source: { type: "user", path: overlay.hooksDirectory } }] }, overlay), true);
    assert.equal(existsSync(overlay.hookPath), true);
    overlay.remove();
    assert.equal(existsSync(overlay.hookPath), false);
    assert.equal(existsSync(overlay.policyPath), false);
    assert.equal(existsSync(overlay.evidencePath), true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("hook process scopes by session when the provider does not inherit the marker variable", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-guard-")); try {
    const policy = fixture(root);
    const packet = { taskRunId: policy.taskRunId, requestId: policy.requestId, worktree: policy.worktree, stateRoot: join(root, "state") };
    const overlay = installPreToolGuard({ packet, policy, sessionId: policy.sessionId, hookRoot: join(root, "user-hooks") });
    const script = fileURLToPath(new URL("../scripts/grok-pretool-guard.mjs", import.meta.url));
    const args = [script, "--policy", overlay.policyPath, "--digest", overlay.policyDigest, "--evidence", overlay.evidencePath];
    const denied = spawnSync(process.execPath, args, { input: JSON.stringify(event(policy, "Bash", { command: "cmd /c npm test" })), encoding: "utf8", env: { ...process.env, GROK_BUILD_ENGINEER_GUARD_DIGEST: overlay.policyDigest } });
    assert.equal(denied.status, 2);
    assert.equal(JSON.parse(denied.stdout).decision, "deny");
    const inheritedMarkerAbsent = spawnSync(process.execPath, args, { input: JSON.stringify(event(policy, "Bash", { command: "cmd /c npm test" })), encoding: "utf8", env: process.env });
    assert.equal(inheritedMarkerAbsent.status, 2);
    assert.equal(JSON.parse(inheritedMarkerAbsent.stdout).decision, "deny");
    const nestedSession = event(policy, "Bash", { command: "npm test" });
    delete nestedSession.sessionId; nestedSession.params = { sessionId: policy.sessionId };
    const nestedSessionAllowed = spawnSync(process.execPath, args, { input: JSON.stringify(nestedSession), encoding: "utf8", env: process.env });
    assert.equal(nestedSessionAllowed.status, 0);
    assert.equal(nestedSessionAllowed.stdout, "");
    const unrelated = spawnSync(process.execPath, args, { input: JSON.stringify({ ...event(policy, "Bash", { command: "cmd /c npm test" }), sessionId: "other-session" }), encoding: "utf8", env: process.env });
    assert.equal(unrelated.status, 0);
    assert.equal(unrelated.stdout, "");
    assert.deepEqual(overlay.readEvidence().map((record) => record.decision), ["deny", "deny", "allow"]);
    overlay.remove();
    assert.deepEqual(overlay.readEvidence().map((record) => record.sessionId), [
      policy.sessionId,
      policy.sessionId,
      policy.sessionId,
    ]);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("guard normalizes documented snake_case envelopes and applies segment-aware scope", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-guard-")); try {
    const policy = fixture(root); mkdirSync(join(root, "src"));
    const snake = { hook_event_name: "pre_tool_use", session_id: policy.sessionId, cwd: policy.worktree, workspace_root: policy.worktree, tool_name: "search_replace", tool_input: { file_path: join(root, "src2", "main.mjs") } };
    assert.equal(evaluatePreToolUse(snake, policy).decision, "deny");
    const normalizedDecision = evaluatePreToolUse({ ...snake, tool_input: JSON.stringify({ file_path: "src/main.mjs" }) }, policy);
    assert.equal(normalizedDecision.decision, "allow");
    assert.equal(evaluatePreToolUse({ ...event(policy, "Bash", { command: "npm test" }), sessionId: undefined, params: { sessionId: policy.sessionId } }, policy).decision, "allow");
    assert.equal(evaluatePreToolUse(event(policy, "Glob", { target_directory: root }), policy).decision, "allow");
    assert.equal(evaluatePreToolUse(event({ ...policy, paths: ["**"] }, "Glob", { target_directory: root }), { ...policy, paths: ["**"] }).decision, "allow");
    assert.equal(evaluatePreToolUse({ hook_event_name: "pre_tool_use", session_id: policy.sessionId, cwd: policy.worktree, workspace_root: policy.worktree, tool_name: "search_replace", tool_input: "not-json" }, policy).decision, "deny");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("guard denies quoted/wrapped/aliased commands and non-none network policy", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-guard-")); try {
    const policy = fixture(root);
    assert.equal(evaluatePreToolUse(event(policy, "Bash", { command: 'npm "test"' }), policy).decision, "allow");
    for (const command of ["npm.cmd test", "cmd /c npm test", "npm test*"]) assert.equal(evaluatePreToolUse(event(policy, "Bash", { command }), policy).decision, "deny");
    assert.equal(evaluatePreToolUse(event(policy, "Bash", { command: "npm test" }), { ...policy, network: "public_read" }).decision, "deny");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("guard discovery fails for competing input rewriting hooks while passive hooks remain acceptable", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-guard-")); try {
    const policy = fixture(root); const packet = { taskRunId: policy.taskRunId, requestId: policy.requestId, worktree: policy.worktree, stateRoot: join(root, "state") };
    const overlay = installPreToolGuard({ packet, policy, sessionId: policy.sessionId, hookRoot: join(root, "user-hooks") });
    const controller = { event: "pre_tool_use", hookType: "command", target: overlay.command, source: { type: "user", path: overlay.hooksDirectory } };
    assert.doesNotThrow(() => assertNoCompetingInputHooks({ hooks: [controller, { event: "PreToolUse", hookType: "command", target: "other-passive-hook", source: { type: "user", path: overlay.hooksDirectory } }] }, overlay));
    assert.throws(() => assertGuardDiscovered({ hooks: [controller, { event: "pre_tool_use", hookType: "transform" }] }, overlay), /competing/);
    assert.throws(() => assertGuardDiscovered({ hooks: [] }, overlay), /did not discover/);
    overlay.remove();
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("tampered controller overlays are removed after integrity failure", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-guard-overlay-")); try {
    const worktree = join(root, "worktree"), stateRoot = join(root, "state"), hookRoot = join(root, "grok", "hooks"); mkdirSync(worktree); mkdirSync(stateRoot);
    const packet = { taskRunId: "run-001", requestId: "request-001", worktree, stateRoot };
    const policy = { paths: ["src/**"], commands: ["npm test"], tools: ["read_file"], network: "none" };
    const overlay = installPreToolGuard({ packet, policy, sessionId: "123e4567-e89b-42d3-a456-426614174000", hookRoot });
    writeFileSync(overlay.hookPath, "tampered\n");
    assert.throws(() => overlay.remove(), /integrity check failed/);
    assert.equal(existsSync(overlay.hookPath), false); assert.equal(existsSync(overlay.policyPath), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("guard denies read, list, grep, and edit through linked path components", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-guard-link-")); try {
    const outside = join(root, "outside"), worktree = join(root, "worktree"); mkdirSync(outside); mkdirSync(worktree); mkdirSync(join(worktree, "src"));
    const linked = join(worktree, "src", "linked"); symlinkSync(outside, linked, process.platform === "win32" ? "junction" : "dir"); const policy = fixture(worktree);
    for (const [tool, input] of [["read_file", { target_file: join(linked, "secret.txt") }], ["list_dir", { path: linked }], ["grep", { path: linked }], ["search_replace", { file_path: join(linked, "secret.txt") }]]) assert.equal(evaluatePreToolUse(event(policy, tool, input), policy).decision, "deny", tool);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
