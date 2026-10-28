import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { HeadlessCliError, HeadlessProtocolError, HeadlessRecoveryRequiredError, buildHeadlessLaunchPlan, buildHeadlessPermissionPolicy, createHeadlessSessionAdapter, headlessPolicyArgs } from "../src/headless-session.mjs";
import { buildProfileAttestation, getCapabilityProfile } from "../src/profiles.mjs";

const digest = `sha256:${"b".repeat(64)}`;
const defaultStateRoot = mkdtempSync(join(tmpdir(), "grok-headless-suite-"));
function inspection() { const profile = getCapabilityProfile("trusted-local"); return { executable: { path: process.execPath, digest }, argv: [...profile.argv], cwdPolicy: "admitted_worktree_only", environmentKeys: profile.environmentKeys, inventoryDigest: `sha256:${"c".repeat(64)}`, capabilities: structuredClone(profile.inventoryAllowlist), containment: { claimed: "trusted_host", osBoundaryVerified: false } }; }
function attestation() { return buildProfileAttestation(getCapabilityProfile("trusted-local"), inspection()); }
function input(overrides = {}) { return { jobId: "job-001", attemptId: "attempt-001", requestId: "request-001", fencingToken: 1, attestation: attestation(), inspection: inspection(), stateRoot: defaultStateRoot, worktree: process.cwd(), prompt: "Implement the bounded change.", ...overrides }; }
function fakeChild({ chunks = [], code = 0, signal = null, stderr = "", hold = false } = {}) {
  const child = new EventEmitter(); child.pid = 4242; child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => { if (!child.closed) { child.closed = true; child.stdout.end(); child.stderr.end(); child.emit("close", 0, "SIGTERM"); } };
  setImmediate(() => { if (stderr) child.stderr.write(stderr); for (const chunk of chunks) child.stdout.write(chunk); if (!hold) { child.stdout.end(); child.stderr.end(); child.closed = true; child.emit("close", code, signal); } });
  return child;
}
function ignoredChild() { const child = new EventEmitter(); child.pid = 4343; child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => {}; return child; }
function manualTimers() { let nextId = 1; const tasks = new Map(); return { setTimeout(fn, ms) { const handle = { id: nextId++, unref() {} }; tasks.set(handle.id, { handle, fn, ms }); return handle; }, clearTimeout(handle) { tasks.delete(handle?.id); }, fireFirst(ms) { const task = [...tasks.values()].find((entry) => entry.ms === ms); if (task) { tasks.delete(task.handle.id); task.fn(); } }, fireLast(ms) { const task = [...tasks.values()].reverse().find((entry) => entry.ms === ms); if (task) { tasks.delete(task.handle.id); task.fn(); } } }; }
function adapter(overrides = {}) { return createHeadlessSessionAdapter({ verifyCustody: async () => true, verifyFence: async () => true, inspectChild: async () => inspection(), ...overrides }); }

test("headless plan is shell-free and selects a new UUID session or exact resume", () => {
  const sessionId = "123e4567-e89b-42d3-a456-426614174000", base = { attestation: attestation(), worktree: process.cwd(), promptFilePath: join(tmpdir(), "path with spaces", "prompt.txt"), nativeSessionId: sessionId };
  const fresh = buildHeadlessLaunchPlan(base), resumed = buildHeadlessLaunchPlan({ ...base, attestation: { ...base.attestation, resumeSessionId: sessionId } });
  assert.equal(fresh.options.shell, false); assert.equal(fresh.args.includes("safe prompt"), false); assert.equal(fresh.args[fresh.args.indexOf("--prompt-file") + 1], base.promptFilePath);
  assert.equal(fresh.args[fresh.args.indexOf("--agent") + 1], "general-purpose");
  assert.equal(fresh.args.includes("--no-plan"), true);
  assert.equal(fresh.args[fresh.args.indexOf("--reasoning-effort") + 1], "high");
  assert.equal(fresh.args[fresh.args.indexOf("--max-turns") + 1], "24");
  assert.deepEqual(fresh.launchReceipt, { model: "grok-build", agent: "general-purpose", planMode: "disabled", reasoningEffort: "high", maxTurns: 24, allowedTools: ["read_file", "grep", "list_dir", "search_replace", "run_terminal_cmd"], disallowedTools: ["Agent", "web_search", "web_fetch"] });
  assert.equal(fresh.args[fresh.args.indexOf("--tools") + 1], "read_file,grep,list_dir,search_replace,run_terminal_cmd");
  assert.equal(fresh.args[fresh.args.indexOf("--disallowed-tools") + 1], "Agent,web_search,web_fetch");
  assert.equal(fresh.args.includes("Read,Grep,Edit,Write,Bash"), false);
  assert.equal(fresh.args.includes("Agent,WebSearch,WebFetch,MCP,mcp__*"), false);
  assert.deepEqual(fresh.args.slice(-2), ["--session-id", sessionId]); assert.deepEqual(resumed.args.slice(-2), ["--resume", sessionId]); assert.equal(resumed.args.includes("--session-id"), false);
  assert.equal(resumed.args[resumed.args.indexOf("--agent") + 1], "general-purpose"); assert.equal(resumed.args.includes("--no-plan"), true); assert.equal(resumed.args[resumed.args.indexOf("--reasoning-effort") + 1], "high"); assert.equal(resumed.args[resumed.args.indexOf("--max-turns") + 1], "24");
  assert.deepEqual(resumed.launchReceipt, fresh.launchReceipt);
});

test("headless capability policy emits exact command rules and fails closed for public-read networking", () => {
  const args = headlessPolicyArgs({ allowedCommands: ["npm test"] });
  assert.equal(args.includes("Bash(npm test)"), true);
  assert.throws(() => headlessPolicyArgs({ allowedCommands: ["npm test*"] }), /wildcard/);
  assert.equal(buildHeadlessPermissionPolicy().network, "none");
  assert.throws(() => buildHeadlessPermissionPolicy({ network: "public_read" }), /official-doc|unavailable/);
});

test("headless adapter requires controller state root before prompt dispatch or spawn", async () => {
  const calls = [];
  const { stateRoot, ...withoutStateRoot } = input();
  await assert.rejects(() => adapter({ spawnImpl: () => { calls.push("spawn"); return fakeChild(); }, onPromptDispatch: async () => calls.push("dispatch") }).start(withoutStateRoot), /state root/i);
  assert.deepEqual(calls, []);
});

test("headless adapter seals a new session before its explicitly ambiguous spawn boundary and completes only after clean stream exit", async () => {
  const trace = [], events = [], stateRoot = mkdtempSync(join(tmpdir(), "grok-headless-test-"));
  const runtime = await adapter({ spawnImpl(command, argv) { trace.push(["spawn", command, argv]); const sessionId = argv[argv.indexOf("--session-id") + 1]; return fakeChild({ chunks: [`{"type":"text","data":"done"}\n`, `{"type":"end","stopReason":"end_turn","sessionId":"${sessionId}","requestId":"provider-request-1","usage":{}}\n`] }); }, onSessionBound: async (value) => trace.push(["bound", value.nativeSessionId]), onPromptDispatch: async (value) => trace.push(["dispatch", value.ambiguity]), onEvent: async (value) => events.push(value) }).start(input({ stateRoot }));
  const outcome = await runtime.done;
  assert.equal(trace[0][0], "bound"); assert.equal(trace[1][0], "dispatch"); assert.equal(trace[2][0], "spawn");
  assert.match(trace[0][1], /^[0-9a-f-]{36}$/i); assert.equal(trace[1][1], "headless_spawn_is_prompt_boundary");
  assert.equal(outcome.state, "candidate_ready"); assert.equal(events.at(-1).kind, "terminal");
});

test("headless adapter rejects malformed and oversized NDJSON before terminal publication", async (t) => {
  for (const [name, chunks] of [["malformed", ["not-json\n"]], ["oversized", [`${"x".repeat(1_048_577)}\n`]]]) await t.test(name, async () => {
    const stateRoot = mkdtempSync(join(tmpdir(), `grok-headless-${name}-`));
    const runtime = await adapter({ spawnImpl: () => fakeChild({ chunks }) }).start(input({ stateRoot }));
    await assert.rejects(runtime.done, (error) => error instanceof HeadlessProtocolError || error instanceof HeadlessRecoveryRequiredError);
    assert.equal(readdirSync(join(stateRoot, "headless-prompts")).length, 0);
  });
});

test("headless CLI error frames remain failures but preserve bounded redacted startup diagnostics", async () => {
  let failure;
  const message = "Couldn't start session: api_key=super-secret-value";
  const runtime = await adapter({
    spawnImpl: () => fakeChild({ chunks: [`${JSON.stringify({ type: "error", message })}\n`], code: 1 }),
    onFailure: async (value) => { failure = value; }
  }).start(input());
  await assert.rejects(runtime.done, HeadlessCliError);
  assert.equal(failure.failureKind, "headless_cli_error");
  assert.equal(failure.diagnostics.protocolFrameType, "error");
  assert.deepEqual(failure.diagnostics.protocolFrameKeys, ["message", "type"]);
  assert.equal(failure.diagnostics.protocolErrorMessage.includes("super-secret-value"), false);
  assert.match(failure.diagnostics.protocolErrorMessage, /REDACTED/);
  assert.match(failure.diagnostics.protocolFrameDigest, /^sha256:[a-f0-9]{64}$/);
});

test("malformed stream diagnostics remain protocol-invalid without echoing frame content", async () => {
  let failure;
  const runtime = await adapter({ spawnImpl: () => fakeChild({ chunks: ["not-json-with-sensitive-content\n"] }), onFailure: async (value) => { failure = value; } }).start(input());
  await assert.rejects(runtime.done, HeadlessProtocolError);
  assert.equal(failure.failureKind, "headless_stream_invalid");
  assert.equal(failure.diagnostics.protocolFrameType, "invalid_json");
  assert.deepEqual(failure.diagnostics.protocolFrameKeys, []);
  assert.equal(Object.hasOwn(failure.diagnostics, "protocolErrorMessage"), false);
});

test("headless nonzero exit and ambiguous post-spawn loss fail closed with redacted diagnostics", async () => {
  let failure; const stateRoot = mkdtempSync(join(tmpdir(), "grok-headless-failure-"));
  const runtime = await adapter({ spawnImpl: () => fakeChild({ chunks: ["{\"type\":\"text\",\"data\":\"ok\"}\n"], code: 9, stderr: "api_key=super-secret-value" }), onFailure: async (value) => { failure = value; } }).start(input({ stateRoot }));
  await assert.rejects(runtime.done, HeadlessRecoveryRequiredError);
  assert.equal(failure.failureKind, "headless_terminal_invalid"); assert.equal(failure.diagnostics.stderrTail.includes("super-secret-value"), false);
  assert.match(failure.diagnostics.stderrTail, /REDACTED/);
  assert.equal(readdirSync(join(stateRoot, "headless-prompts")).length, 0);
});

test("headless cancellation kills the finite child and waits for close acknowledgement", async () => {
  let acknowledged = 0; const stateRoot = mkdtempSync(join(tmpdir(), "grok-headless-cancel-")); const runtime = await adapter({ spawnImpl: () => fakeChild({ hold: true }), onCancelAcknowledged: async () => { acknowledged += 1; } }).start(input({ stateRoot }));
  await runtime.cancel(); const outcome = await runtime.done;
  assert.equal(outcome.state, "cancelled"); assert.equal(acknowledged, 1);
  assert.equal(readdirSync(join(stateRoot, "headless-prompts")).length, 0);
});

test("headless initialization timeout fails closed before the first valid frame", async () => {
  const timers = manualTimers(); let failure;
  const runtime = await adapter({ timers, spawnImpl: () => ignoredChild(), onFailure: async (value) => { failure = value; } }).start(input());
  timers.fireFirst(30000);
  await assert.rejects(runtime.done, HeadlessRecoveryRequiredError);
  assert.equal(failure.failureKind, "headless_initialization_timeout");
});

test("headless idle timeout resets on stream activity and fails a silent child", async () => {
  const timers = manualTimers(); let failure;
  const runtime = await adapter({ timers, spawnImpl: (_command, argv) => { const sessionId = argv[argv.indexOf("--session-id") + 1]; return fakeChild({ chunks: [`{"type":"text","data":"progress"}\n`], hold: true, code: 0, signal: null, sessionId }); }, onFailure: async (value) => { failure = value; } }).start(input());
  await new Promise((resolve) => setImmediate(resolve));
  timers.fireFirst(300000);
  await assert.rejects(runtime.done, HeadlessRecoveryRequiredError);
  assert.equal(failure.failureKind, "headless_idle_timeout");
});

test("headless cancellation timeout recovers when a child ignores tree termination", async () => {
  const timers = manualTimers(); let failure;
  const runtime = await adapter({ timers, spawnImpl: () => ignoredChild(), killTree: () => {}, onFailure: async (value) => { failure = value; } }).start(input());
  await runtime.cancel();
  timers.fireLast(30000);
  await assert.rejects(runtime.done, HeadlessRecoveryRequiredError);
  assert.equal(failure.failureKind, "headless_cancellation_timeout");
});

test("documented streaming-json frames normalize and require one correlated end while allowing noncritical extensions", async () => {
  const stateRoot = mkdtempSync(join(tmpdir(), "grok-headless-doc-"));
  const runtime = await adapter({
    spawnImpl: (_command, argv) => {
      const sessionId = argv[argv.indexOf("--session-id") + 1];
      const frames = [
        { type: "thought", data: "Analyzing the directory structure..." },
        { type: "future_extension", sessionId, data: "ignored" },
        { type: "tool_call", toolCallId: "call_1", title: "Read", kind: null, status: null, toolName: "read_file", rawInput: { path: "src/main.rs" }, content: [], locations: [] },
        { type: "tool_call_update", toolCallId: "call_1", status: null, content: [], rawOutput: null, locations: [] },
        { type: "text", data: "Here's a summary" },
        { type: "usage", messageId: null, stopReason: null, usage: null, signature: null },
        { type: "end", stopReason: "end_turn", sessionId, requestId: "xyz789", usage: {}, num_turns: 7, modelUsage: {} }
      ];
      return fakeChild({ chunks: [frames.map((frame) => `${JSON.stringify(frame)}\n`).join("")] });
    }
  }).start(input({ stateRoot }));
  const outcome = await runtime.done;
  assert.equal(outcome.state, "candidate_ready");
  assert.equal(readdirSync(join(stateRoot, "headless-prompts")).length, 0, "prompt text is removed after close");
  assert.equal(existsSync(join(stateRoot, "headless-prompts")), true);
});

test("signed usage frames may use the full bounded provider frame allowance", async () => {
  const events = [];
  const signature = "s".repeat(20 * 1024);
  const runtime = await adapter({
    onEvent: async (event) => events.push(event),
    spawnImpl: (_command, argv) => {
      const sessionId = argv[argv.indexOf("--session-id") + 1];
      const frames = [
        { type: "text", data: "done" },
        { type: "usage", messageId: null, stopReason: "end_turn", usage: { inputTokens: 1 }, signature },
        { type: "end", stopReason: "end_turn", sessionId, requestId: "signed-usage", usage: {}, num_turns: 1, modelUsage: {} }
      ];
      return fakeChild({ chunks: [frames.map((frame) => `${JSON.stringify(frame)}\n`).join("")] });
    }
  }).start(input());
  assert.equal((await runtime.done).state, "candidate_ready");
  assert.equal(events.some((event) => JSON.stringify(event).includes(signature)), false, "opaque signatures are validated but never journaled");
});

test("token-sized text and thought frames are coalesced below the durable event-rate ceiling", async () => {
  const events = [];
  const runtime = await adapter({
    onEvent: async (event) => events.push(event),
    spawnImpl: (_command, argv) => {
      const sessionId = argv[argv.indexOf("--session-id") + 1];
      const frames = [
        ...Array.from({ length: 600 }, () => ({ type: "thought", data: "private reasoning token" })),
        ...Array.from({ length: 600 }, () => ({ type: "text", data: "visible " })),
        { type: "usage", messageId: null, stopReason: "end_turn", usage: null, signature: null },
        { type: "end", stopReason: "end_turn", sessionId, requestId: "xyz789", usage: {}, num_turns: 1, modelUsage: {} }
      ];
      return fakeChild({ chunks: [frames.map((frame) => `${JSON.stringify(frame)}\n`).join("")] });
    }
  }).start(input());
  assert.equal((await runtime.done).state, "candidate_ready");
  const textEvents = events.filter((event) => event.kind === "text");
  assert.equal(textEvents.length, 1);
  assert.equal(textEvents[0].value.text, "visible ".repeat(600));
  assert.equal(events.filter((event) => event.value?.type === "thought").length, 1);
  assert.equal(events.some((event) => JSON.stringify(event).includes("private reasoning token")), false);
});

test("critical unknown stream frames and end-before-last fail closed", async () => {
  for (const chunks of [
    [{ type: "future_extension", critical: true }],
    [{ type: "end", stopReason: "end_turn", sessionId: "123e4567-e89b-42d3-a456-426614174000", requestId: "xyz" }, { type: "text", data: "late" }]
  ]) {
    const runtime = await adapter({ spawnImpl: (_command, argv) => fakeChild({ chunks: [`${JSON.stringify(chunks[0])}\n`, ...(chunks.slice(1).map((frame) => `${JSON.stringify(frame)}\n`))] }) }).start(input());
    await assert.rejects(runtime.done, HeadlessProtocolError);
  }
});
