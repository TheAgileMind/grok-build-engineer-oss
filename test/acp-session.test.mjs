import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import * as acp from "@agentclientprotocol/sdk";
import { AcpProtocolError, AcpRecoveryRequiredError, buildLaunchPlan, createAcpSessionAdapter, createBoundedNdjsonStream, launchAcpChild } from "../src/acp-session.mjs";
import { fakeAcpAgent } from "./fake-acp-agent.mjs";
import { CONTRACT_VERSIONS } from "../src/contracts.mjs";
import { buildProfileAttestation, getCapabilityProfile } from "../src/profiles.mjs";

const digest = `sha256:${"b".repeat(64)}`;
function inspection() { const profile = getCapabilityProfile("trusted-local"); return { executable: { path: process.execPath, digest }, argv: [...profile.argv], cwdPolicy: "admitted_worktree_only", environmentKeys: profile.environmentKeys, inventoryDigest: `sha256:${"c".repeat(64)}`, capabilities: structuredClone(profile.inventoryAllowlist), containment: { claimed: "trusted_host", osBoundaryVerified: false } }; }
function attestation(environment = process.env) { return buildProfileAttestation(getCapabilityProfile("trusted-local"), inspection(), { environment }); }
function input(overrides = {}) { return { jobId: "job-1", attemptId: "attempt-1", requestId: "request-1", fencingToken: 1, attestation: attestation(), inspection: inspection(), worktree: process.cwd(), prompt: "local test", ...overrides }; }
function digestText(value) { return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`; }
function adapter(overrides = {}) { return createAcpSessionAdapter({ inspectChild: async () => inspection(), verifyCustody: async () => true, verifyFence: async () => true, ...overrides }); }
function quickTimers(target) { return { setTimeout(handler, delay) { return setTimeout(handler, delay === target ? 5 : delay); }, clearTimeout, now: Date.now }; }
function sizedAvailableCommandsUpdate(bytes, sessionId = "native-pre-bind") {
  const update = { sessionUpdate: "available_commands_update", availableCommands: [{ name: "repair", description: "" }] }, params = { sessionId, update };
  update.availableCommands[0].description = "x".repeat(bytes - Buffer.byteLength(JSON.stringify(params)));
  assert.equal(Buffer.byteLength(JSON.stringify(params)), bytes); return { update };
}
function preBindPeer({ sessionId = "native-pre-bind", updates = [], extensionNotifications = [] } = {}) {
  const calls = [], notify = async (ctx) => { for (const item of extensionNotifications) await ctx.client.notify(item.method, item.params); for (const item of updates) await ctx.client.notify(acp.methods.client.session.update, { sessionId: item.sessionId ?? sessionId, update: item.update }); };
  const app = acp.agent({ name: "pre-bind-fake-grok" })
    .onRequest(acp.methods.agent.initialize, async (ctx) => { calls.push("initialize"); return { protocolVersion: ctx.params.protocolVersion, agentCapabilities: { loadSession: true } }; })
    .onRequest(acp.methods.agent.session.new, async (ctx) => { calls.push("new"); await notify(ctx); return { sessionId }; })
    .onRequest(acp.methods.agent.session.load, async (ctx) => { calls.push(`load:${ctx.params.sessionId}`); await notify(ctx); return {}; })
    .onRequest(acp.methods.agent.session.prompt, async (ctx) => { calls.push(`prompt:${ctx.params.sessionId}`); await ctx.client.notify(acp.methods.client.session.update, { sessionId: ctx.params.sessionId, update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: "Implementation complete.\n" } } }); return { stopReason: "end_turn" }; });
  return { agent: app, calls, stop() {} };
}

test("new ACP session binds durably before prompt and produces a correlated candidate", async () => {
  const peer = fakeAcpAgent({ sessionId: "native-1" }), trace = [], events = []; let binding;
  const sessionAdapter = adapter({ launch: async () => peer, onSessionBound: async (r) => { binding = r; trace.push(`bound:${r.nativeSessionId}`); }, onEvent: async (e) => { trace.push(`event:${e.sequence}`); events.push(e); } });
  const runtime = await sessionAdapter.start(input()); const result = await runtime.done;
  assert.equal(result.state, "candidate_ready"); assert.deepEqual(peer.calls, ["initialize", "new", "prompt:native-1"]);
  assert.deepEqual(trace, ["bound:native-1", "event:1", "event:2", "event:3"]); assert.ok(events.every((event) => event.jobId === "job-1" && event.nativeSessionId === "native-1"));
  assert.deepEqual(binding.launchEvidence.argv, getCapabilityProfile("trusted-local").argv); assert.equal(binding.launchEvidence.executableDigest, digest); assert.equal(Object.hasOwn(binding, "launchPlan"), false); assert.equal(Object.hasOwn(binding.launchEvidence, "environment"), false);
});

test("ACP prelaunch failures expose only a bounded safe stage", async (t) => {
  const cases = [
    ["profile drift", "adapter_profile_drift", adapter({ launch: async () => fakeAcpAgent() }), input({ inspection: { ...inspection(), inventoryDigest: `sha256:${"d".repeat(64)}` } })],
    ["initial guard", "adapter_guard", adapter({ launch: async () => fakeAcpAgent(), verifyCustody: async () => false }), input()],
    ["child launch", "adapter_child_launch", adapter({ launch: async () => { throw new Error("raw launch diagnostic must not escape"); } }), input()],
    ["child parity", "adapter_child_parity", adapter({ launch: async () => fakeAcpAgent(), inspectChild: async () => { throw new Error("raw parity diagnostic must not escape"); } }), input()]
  ];
  for (const [name, stage, sessionAdapter, startInput] of cases) await t.test(name, async () => {
    await assert.rejects(sessionAdapter.start(startInput), (error) => error?.safeStage === stage);
  });
});

test("candidate completion derives authority from normalized assistant output, not marker text", async (t) => {
  for (const [name, narrative] of [
    ["ordinary completion", "Implementation and tests completed successfully."],
    ["digest-shaped text", `sha256:${"f".repeat(64)}`],
    ["legacy marker text", `GROK_CANDIDATE sha256:${"e".repeat(64)}`],
    ["legacy marker followed by text", `GROK_CANDIDATE sha256:${"e".repeat(64)}\npost-marker text`]
  ]) await t.test(name, async () => {
    const events = [], result = await (await adapter({ launch: async () => fakeAcpAgent({ chunks: [narrative] }), onEvent: async (event) => events.push(event) }).start(input())).done;
    assert.equal(result.assistantOutputDigest, digestText(narrative));
    assert.match(result.terminalEvidenceDigest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(events.at(-1).kind, "terminal");
  });
});

test("known lifecycle updates received before session/new returns are bound then replayed before prompt", async () => {
  const peer = preBindPeer({ updates: [
    { update: { sessionUpdate: "available_commands_update", availableCommands: [] } },
    { update: { sessionUpdate: "available_commands_update", availableCommands: [{ name: "repair" }] } }
  ] }), trace = [], events = [];
  const result = await (await adapter({ launch: async () => peer, onSessionBound: async (binding) => trace.push(`bound:${binding.nativeSessionId}`), onEvent: async (event) => { trace.push(`event:${event.kind}`); events.push(event); } }).start(input())).done;
  assert.equal(result.state, "candidate_ready"); assert.deepEqual(peer.calls, ["initialize", "new", "prompt:native-pre-bind"]);
  assert.deepEqual(trace, ["bound:native-pre-bind", "event:available_commands", "event:available_commands", "event:text", "event:terminal"]);
  assert.deepEqual(events.slice(0, 2).map((event) => ({ nativeSessionId: event.nativeSessionId, value: event.value })), [{ nativeSessionId: "native-pre-bind", value: { count: 0 } }, { nativeSessionId: "native-pre-bind", value: { count: 0 } }]);
});

test("resume quarantines updates received while rebinding the exact prior session", async () => {
  const peer = preBindPeer({ sessionId: "native-existing", updates: [{ update: { sessionUpdate: "available_commands_update", availableCommands: [] } }] }), events = [];
  const result = await (await adapter({ launch: async () => peer, onEvent: async (event) => events.push(event) }).start(input({ nativeSessionId: "native-existing", attemptId: "attempt-2" }))).done;
  assert.equal(result.state, "candidate_ready"); assert.deepEqual(peer.calls, ["initialize", "load:native-existing", "prompt:native-existing"]); assert.deepEqual(events.map((event) => event.kind), ["text", "terminal"]);
});

test("known bounded Grok UI notifications are ignored during resume", async () => {
  const peer = preBindPeer({ sessionId: "native-existing", extensionNotifications: [
    { method: "_x.ai/mcp/servers_updated", params: { mcpServers: [] } },
    { method: "_x.ai/models/update", params: { availableModels: [], currentModelId: "default" } },
    { method: "_x.ai/settings/update", params: { sharing_enabled: false } },
    { method: "_x.ai/announcements/update", params: { announcements: [], gen: 1 } },
    { method: "_x.ai/mcp/init_progress", params: { connected: 0, total: 0, sessionId: "native-existing" } },
    { method: "_x.ai/session_notification", params: { sessionId: "native-existing", update: {} } }
  ], updates: [{ update: { sessionUpdate: "available_commands_update", availableCommands: [] } }] }), events = [];
  const result = await (await adapter({ launch: async () => peer, onEvent: async (event) => events.push(event) }).start(input({ nativeSessionId: "native-existing", attemptId: "attempt-2" }))).done;
  assert.equal(result.state, "candidate_ready");
  assert.deepEqual(peer.calls, ["initialize", "load:native-existing", "prompt:native-existing"]);
  assert.deepEqual(events.map((event) => event.kind), ["text", "terminal"]);
});

test("Grok turn_completed metadata cannot interrupt an otherwise valid candidate", async () => {
  const sessionId = "native-turn-completed", calls = [], narrative = "done\nreview complete";
  const peer = acp.agent({ name: "turn-completed-fake-grok" })
    .onRequest(acp.methods.agent.initialize, async (ctx) => { calls.push("initialize"); return { protocolVersion: ctx.params.protocolVersion, agentCapabilities: { loadSession: true } }; })
    .onRequest(acp.methods.agent.session.new, async () => { calls.push("new"); return { sessionId }; })
    .onRequest(acp.methods.agent.session.prompt, async (ctx) => {
      calls.push("prompt");
      await ctx.client.notify(acp.methods.client.session.update, { sessionId, update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: narrative } } });
      await ctx.client.notify("_x.ai/session/update", { sessionId, update: { sessionUpdate: "turn_completed", prompt_id: "prompt-1", stop_reason: "end_turn", usage: { inputTokens: 3, outputTokens: 2, totalTokens: 5 } } });
      return { stopReason: "end_turn" };
    });
  const result = await (await adapter({ launch: async () => ({ agent: peer, stop() {} }) }).start(input())).done;
  assert.equal(result.state, "candidate_ready");
  assert.equal(result.assistantOutputDigest, digestText(narrative));
  assert.deepEqual(calls, ["initialize", "new", "prompt"]);
});

test("post-response assistant chunks are drained into the current turn", async () => {
  const narrative = "delayed implementation summary", sessionId = "native-delayed", peer = acp.agent({ name: "delayed-fake-grok" })
    .onRequest(acp.methods.agent.initialize, async (ctx) => ({ protocolVersion: ctx.params.protocolVersion, agentCapabilities: {} }))
    .onRequest(acp.methods.agent.session.new, async () => ({ sessionId }))
    .onRequest(acp.methods.agent.session.prompt, async (ctx) => {
      setTimeout(() => ctx.client.notify(acp.methods.client.session.update, { sessionId, update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: narrative } } }), 60);
      return { stopReason: "end_turn" };
    });
  const result = await (await adapter({ launch: async () => ({ agent: peer, stop() {} }) }).start(input())).done;
  assert.equal(result.state, "candidate_ready"); assert.equal(result.assistantOutputDigest, digestText(narrative));
});

test("a same-session frame after the completion drain invalidates terminal publication", async () => {
  const sessionId = "native-after-drain", peer = acp.agent({ name: "after-drain-fake-grok" })
    .onRequest(acp.methods.agent.initialize, async (ctx) => ({ protocolVersion: ctx.params.protocolVersion, agentCapabilities: {}, sessionCapabilities: { resume: {} } }))
    .onRequest(acp.methods.agent.session.new, async () => ({ sessionId }))
    .onRequest(acp.methods.agent.session.prompt, async (ctx) => {
      setTimeout(() => ctx.client.notify(acp.methods.client.session.update, { sessionId, update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: "late suffix" } } }), 175);
      return { stopReason: "end_turn" };
    });
  await assert.rejects((await adapter({ launch: async () => ({ agent: peer, stop() {} }), onEvent: async (event) => { if (event.kind === "terminal") await new Promise((resolve) => setTimeout(resolve, 100)); } }).start(input())).done, /recovery|correlation/i);
});

test("resume-time history cannot supply or contaminate the current repair candidate", async (t) => {
  const prior = `sha256:${"f".repeat(64)}`;
  for (const historicalMarker of [prior, `GROK_CANDIDATE ${prior}`]) await t.test(historicalMarker.startsWith("GROK") ? "legacy marker" : "digest-only marker", async () => {
    const peer = preBindPeer({ sessionId: "native-existing", updates: [
      { update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: `${historicalMarker}\nhistorical ` } } },
      { update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: "tail" } } }
    ] }), events = [];
    const result = await (await adapter({ launch: async () => peer, onEvent: async (event) => events.push(event) }).start(input({ nativeSessionId: "native-existing", attemptId: "attempt-2" }))).done;
    assert.equal(result.state, "candidate_ready"); assert.deepEqual(peer.calls, ["initialize", "load:native-existing", "prompt:native-existing"]);
    assert.equal(events.filter((event) => event.kind === "terminal").length, 1);
    assert.equal(events.some((event) => event.kind === "text" && event.value.text.includes("historical tail")), false);
  });
});

test("a realistic 29-update resume-time history is quarantined before the repair prompt", async () => {
  const textUpdate = (sessionUpdate, character) => ({ update: { sessionUpdate, content: { type: "text", text: `${character.repeat(5_000)}\n` } } });
  const updates = [
    textUpdate("user_message_chunk", "u"),
    ...Array.from({ length: 7 }, () => textUpdate("agent_thought_chunk", "t")),
    ...Array.from({ length: 4 }, () => textUpdate("agent_message_chunk", "a")),
    ...Array.from({ length: 16 }, (_, index) => ({ update: { sessionUpdate: "tool_call", toolCallId: `history-tool-${index}`, title: "x".repeat(5_000), status: "completed" } })),
    sizedAvailableCommandsUpdate(124_984, "native-existing")
  ];
  const rawBytes = updates.map((item) => Buffer.byteLength(JSON.stringify({ sessionId: "native-existing", update: item.update })));
  const aggregateBytes = rawBytes.reduce((total, bytes) => total + bytes, 0);
  assert.equal(updates.length, 29); assert.ok(aggregateBytes >= 263_000 && aggregateBytes < getCapabilityProfile("trusted-local").limits.maximumFrameBytes);
  assert.equal(Math.max(...rawBytes), 124_984);
  assert.deepEqual(Object.fromEntries([...new Set(updates.map((item) => item.update.sessionUpdate))].map((kind) => [kind, updates.filter((item) => item.update.sessionUpdate === kind).length])), {
    user_message_chunk: 1, agent_thought_chunk: 7, agent_message_chunk: 4, tool_call: 16, available_commands_update: 1
  });
  const peer = preBindPeer({ sessionId: "native-existing", updates }), bindings = [], events = [];
  const result = await (await adapter({ launch: async () => peer, onSessionBound: async (binding) => bindings.push(binding), onEvent: async (event) => events.push(event) }).start(input({ nativeSessionId: "native-existing", attemptId: "attempt-history" }))).done;
  assert.equal(result.state, "candidate_ready"); assert.deepEqual(peer.calls, ["initialize", "load:native-existing", "prompt:native-existing"]);
  assert.equal(bindings.length, 1); assert.deepEqual(events.map((event) => event.kind), ["text", "terminal"]);
});

test("two realistic pre-bind command catalogs may exceed the event limit but remain within the frame limit", async () => {
  const limits = getCapabilityProfile("trusted-local").limits, first = sizedAvailableCommandsUpdate(87_917), second = sizedAvailableCommandsUpdate(87_918);
  assert.ok(87_917 > limits.maximumEventBytes / 2); assert.ok(87_917 + 87_918 < limits.maximumFrameBytes);
  const peer = preBindPeer({ updates: [first, second] }), bindings = [], events = [];
  const result = await (await adapter({ launch: async () => peer, onSessionBound: async (binding) => bindings.push(binding), onEvent: async (event) => events.push(event) }).start(input())).done;
  assert.equal(result.state, "candidate_ready"); assert.deepEqual(peer.calls, ["initialize", "new", "prompt:native-pre-bind"]); assert.equal(bindings.length, 1); assert.deepEqual(events.slice(0, 2).map((event) => event.kind), ["available_commands", "available_commands"]);
});

test("wrong-session or overflowing pre-bind notifications fail closed without binding or prompt", async (t) => {
  const cases = [
    ["wrong session", [{ sessionId: "other-session", update: { sessionUpdate: "available_commands_update", availableCommands: [] } }]],
    ["queue count overflow", Array.from({ length: 241 }, () => ({ update: { sessionUpdate: "available_commands_update", availableCommands: [] } }))],
    ["queue frame aggregate overflow", [sizedAvailableCommandsUpdate(600_000), sizedAvailableCommandsUpdate(600_000)]]
  ];
  for (const [name, updates] of cases) await t.test(name, async () => {
    const peer = preBindPeer({ updates }), bindings = [];
    await assert.rejects((await adapter({ launch: async () => peer, onSessionBound: async (binding) => bindings.push(binding) }).start(input())).done, /recovery|correlation|failed|invalid/i);
    assert.deepEqual(bindings, []); assert.deepEqual(peer.calls, ["initialize", "new"]);
  });
});

test("repair resumes the exact prior native session without creating another", async () => {
  const peer = preBindPeer({ sessionId: "native-existing" });
  const trace = [];
  const sessionAdapter = adapter({ launch: async () => peer, onSessionBound: async () => trace.push("bound"), onPromptDispatch: async () => trace.push("dispatch") });
  const result = await (await sessionAdapter.start(input({ nativeSessionId: "native-existing", attemptId: "attempt-2" }))).done;
  assert.equal(result.state, "candidate_ready"); assert.deepEqual(peer.calls, ["initialize", "load:native-existing", "prompt:native-existing"]);
  assert.deepEqual(trace, ["bound", "dispatch"], "durable prompt dispatch is recorded only after load quarantine and immediately before the ACP prompt");
});

test("a delayed same-session load frame extends quarantine and cannot contaminate the repair prompt", async () => {
  const sessionId = "native-stale-after-resume", calls = [], peer = acp.agent({ name: "stale-after-resume-fake-grok" })
    .onRequest(acp.methods.agent.initialize, async (ctx) => ({ protocolVersion: ctx.params.protocolVersion, agentCapabilities: { loadSession: true } }))
    .onRequest(acp.methods.agent.session.load, async (ctx) => {
      calls.push(`load:${ctx.params.sessionId}`);
      setTimeout(() => ctx.client.notify(acp.methods.client.session.update, { sessionId, update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: "stale prior-turn suffix" } } }), 60);
      return {};
    })
    .onRequest(acp.methods.agent.session.prompt, async (ctx) => {
      calls.push("prompt");
      await ctx.client.notify(acp.methods.client.session.update, { sessionId, update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: "fresh repair output" } } });
      return { stopReason: "end_turn" };
    });
  const events = [], result = await (await adapter({ launch: async () => ({ agent: peer, stop() {} }), onEvent: async (event) => events.push(event) }).start(input({ nativeSessionId: sessionId, attemptId: "attempt-2" }))).done;
  assert.equal(result.state, "candidate_ready");
  assert.deepEqual(calls, [`load:${sessionId}`, "prompt"]);
  assert.equal(events.some((event) => JSON.stringify(event.value).includes("stale prior-turn suffix")), false);
  assert.equal(result.assistantOutputDigest, digestText("fresh repair output"));
});

test("advertised cached local auth is selected headlessly before session creation", async () => {
  const peer = fakeAcpAgent({ authMethods: [{ id: "cached_token", name: "Cached local login" }] }); const result = await (await adapter({ launch: async () => peer }).start(input())).done;
  assert.equal(result.state, "candidate_ready"); assert.deepEqual(peer.calls.slice(0, 3), ["initialize", "authenticate:cached_token:true", "new"]);
});

test("interactive or missing cached auth fails closed without starting a session", async () => {
  const peer = fakeAcpAgent({ authMethods: [{ id: "cached_token", name: "Interactive cached token", type: "terminal", args: ["login"] }] }); const sessionAdapter = adapter({ launch: async () => peer });
  await assert.rejects((await sessionAdapter.start(input())).done, /activation is required/i); assert.deepEqual(peer.calls, ["initialize"]);
});

test("credential-supplying cached auth variants are never selected", async () => {
  const peer = fakeAcpAgent({ authMethods: [{ id: "cached_token", name: "Forged credential input", type: "env_var", vars: [{ name: "XAI_API_KEY" }] }] });
  await assert.rejects((await adapter({ launch: async () => peer }).start(input())).done, /activation is required/i); assert.deepEqual(peer.calls, ["initialize"]);
});

test("repair refuses session load unless the peer advertises it", async () => {
  const peer = fakeAcpAgent({ loadSession: false }); await assert.rejects((await adapter({ launch: async () => peer }).start(input({ nativeSessionId: "native-existing" }))).done, /cannot load|recovery/i); assert.deepEqual(peer.calls, ["initialize"]);
});

test("two interleaved logical jobs stay in independent children and correlations", async () => {
  const peers = [fakeAcpAgent({ sessionId: "one" }), fakeAcpAgent({ sessionId: "two" })], events = [];
  const adapters = peers.map((peer) => adapter({ launch: async () => peer, onEvent: async (event) => events.push(event) }));
  const [left, right] = await Promise.all([adapters[0].start(input()), adapters[1].start(input({ jobId: "job-2", attemptId: "attempt-2", requestId: "request-2", fencingToken: 2 }))]);
  await Promise.all([left.done, right.done]); assert.deepEqual(events.map((event) => event.jobId).sort(), ["job-1", "job-1", "job-1", "job-2", "job-2", "job-2"]);
});

test("unclassifiable permission fails closed rather than trusting ACP metadata", async () => {
  const events = [], peer = fakeAcpAgent({ permission: true }), sessionAdapter = adapter({ launch: async () => peer, onEvent: async (event) => events.push(event) });
  await assert.rejects((await sessionAdapter.start(input())).done, /candidate completion|recovery|failed/i);
  assert.equal(events[0].kind, "permission_denied"); assert.deepEqual(events[0].value, { reason: "frozen_authority" }); assert.doesNotMatch(JSON.stringify(events), /forged/);
});

test("classified permission is re-fenced, audited, and limited to an offered option", async () => {
  const events = [], peer = fakeAcpAgent({ permission: true });
  const result = await (await adapter({ launch: async () => peer, classifyPermission: async () => ({ operation: "write_file" }), authorizePermission: async () => ({ allowed: true, optionId: "allow" }), onEvent: async (event) => events.push(event) }).start(input())).done;
  assert.equal(result.state, "candidate_ready"); assert.deepEqual(events[0].value, { operation: "write_file", optionId: "allow" }); assert.equal(events[0].kind, "permission_allowed");
});

test("cancellation journals intent before ACP cancel and accepts the terminal cancelled receipt", async () => {
  const peer = fakeAcpAgent({ waitForCancel: true }), trace = [];
  const sessionAdapter = adapter({ launch: async () => peer, onSessionBound: async () => trace.push("bound"), beforeCancel: async () => trace.push("before"), onCancelAcknowledged: async () => trace.push("ack") });
  const runtime = await sessionAdapter.start(input());
  while (!trace.includes("bound")) await new Promise((resolve) => setTimeout(resolve, 1));
  await runtime.cancel(); const result = await runtime.done;
  assert.equal(result.state, "cancelled"); assert.deepEqual(trace, ["bound", "before", "ack"]); assert.ok(peer.calls.includes("cancel"));
});

test("failed pre-intent cancellation is retry-safe and does not misclassify natural end_turn", async () => {
  let release, attempts = 0; const gate = new Promise((resolve) => { release = resolve; }), peer = fakeAcpAgent({ promptGate: gate });
  const runtime = await adapter({ launch: async () => peer, beforeCancel: async () => { if (++attempts === 1) throw new Error("Bearer supersecretvalue"); } }).start(input());
  while (!peer.calls.some((call) => call.startsWith("prompt:"))) await new Promise((resolve) => setTimeout(resolve, 1));
  await assert.rejects(runtime.cancel(), (error) => !error.message.includes("supersecretvalue")); release(); const result = await runtime.done; assert.equal(result.state, "candidate_ready");
});

test("failed pre-intent cancellation can be retried with one cached pending promise", async () => {
  let attempts = 0; const peer = fakeAcpAgent({ waitForCancel: true }), runtime = await adapter({ launch: async () => peer, beforeCancel: async () => { if (++attempts === 1) throw new Error("store unavailable"); } }).start(input());
  while (!peer.calls.some((call) => call.startsWith("prompt:"))) await new Promise((resolve) => setTimeout(resolve, 1)); await assert.rejects(runtime.cancel(), /not persisted/); const left = runtime.cancel(), right = runtime.cancel(); assert.equal(left, right); await left; assert.equal((await runtime.done).state, "cancelled"); assert.equal(attempts, 2);
});

test("launch plan and injected spawn preserve exact command, argv, cwd, minimal env, and shell false", () => {
  const profile = getCapabilityProfile("trusted-local"), allowedEnvironment = Object.fromEntries(profile.environmentKeys.map((key) => [key, `safe-${key}`])), environment = { ...allowedEnvironment, SECRET: "no" };
  const launchAttestation = attestation(environment), plan = buildLaunchPlan({ attestation: launchAttestation, worktree: process.cwd(), environment });
  assert.equal(plan.command, process.execPath); assert.deepEqual(plan.args, profile.argv); assert.equal(plan.options.cwd, process.cwd()); assert.equal(plan.options.shell, false); assert.deepEqual(plan.options.env, allowedEnvironment);
  let captured; const fake = new EventEmitter(); fake.stdin = new PassThrough(); fake.stdout = new PassThrough(); fake.stderr = new PassThrough(); fake.kill = () => {};
  launchAcpChild({ attestation: launchAttestation, worktree: process.cwd(), limits: profile.limits, environment, spawnImpl: (...args) => { captured = args; return fake; } });
  assert.equal(captured[0], process.execPath); assert.deepEqual(captured[1], ["--no-auto-update", "agent", "stdio"]); assert.equal(captured[2].shell, false); assert.equal(captured[2].env.SECRET, undefined);
  const delayed = new EventEmitter(); delayed.pid = 7123; delayed.stdin = new PassThrough(); delayed.stdout = new PassThrough(); delayed.stderr = new PassThrough(); delayed.kill = () => {};
  let inspections = 0;
  const identified = launchAcpChild({
    attestation: launchAttestation, worktree: process.cwd(), limits: profile.limits, environment, spawnImpl: () => delayed,
    processInspector: () => ++inspections < 3 ? { state: "unknown" } : { state: "present", identity: { pid: 7123, startedAt: "2026-08-16T21:00:00.000Z" } }
  });
  assert.equal(inspections, 3); assert.deepEqual(identified.childProcessIdentity, { pid: 7123, startedAt: "2026-08-16T21:00:00.000Z" });
  assert.throws(() => launchAcpChild({ attestation: { ...launchAttestation, argv: ["agent", "stdio"] }, worktree: process.cwd(), limits: profile.limits, environment, spawnImpl: () => delayed }), (error) => error?.safeStage === "adapter_child_launch_plan");
  assert.throws(() => launchAcpChild({ attestation: launchAttestation, worktree: process.cwd(), limits: profile.limits, environment, spawnImpl: () => { throw new Error("raw spawn diagnostic"); } }), (error) => error?.safeStage === "adapter_child_spawn");
  assert.throws(() => launchAcpChild({ attestation: launchAttestation, worktree: process.cwd(), limits: profile.limits, environment, spawnImpl: () => delayed, processInspector: () => ({ state: "unknown" }) }), (error) => error?.safeStage === "adapter_child_identity");
  const repairChild = new EventEmitter(); repairChild.pid = 7124; repairChild.stdin = new PassThrough(); repairChild.stdout = new PassThrough(); repairChild.stderr = new PassThrough(); repairChild.kill = () => {};
  const repairLaunch = launchAcpChild({ attestation: launchAttestation, worktree: process.cwd(), limits: profile.limits, environment, spawnImpl: () => repairChild, processInspector: () => ({ state: "unknown" }), input: { nativeSessionId: "native-existing" } });
  assert.equal(repairLaunch.childProcessIdentity, null, "session/load retains the original sealed process identity when replacement inspection is unavailable");
  assert.throws(() => buildLaunchPlan({ attestation: { ...launchAttestation, argv: ["agent", "stdio"] }, worktree: process.cwd(), environment }), /approved ACP launch shape/i);
  assert.throws(() => buildLaunchPlan({ attestation: launchAttestation, worktree: process.cwd(), environment: { ...environment, PATH: "drifted-path" } }), /environment|attestation/i);
});

test("production child loss resolves on close, not early exit", async () => {
  const child = new EventEmitter(); child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => {};
  const limits = { ...getCapabilityProfile("trusted-local").limits, maximumEventBytes: 4 };
  const launched = launchAcpChild({ attestation: attestation(), worktree: process.cwd(), limits, spawnImpl: () => child }); let settled = false; launched.closed.then(() => { settled = true; });
  child.stderr.write("diagnostic-only"); child.emit("exit", 0, null); await new Promise((resolve) => setImmediate(resolve)); assert.equal(settled, false); child.emit("close", 17, "SIGTERM");
  assert.deepEqual(await launched.closed, { lost: true, code: 17, signal: "SIGTERM", spawnError: false, stderrBytes: 15, stderrLimitExceeded: true });
});

test("valid final response followed by immediate child close drains before loss classification", async () => {
  let close; const peer = fakeAcpAgent({ afterPrompt: () => queueMicrotask(close) }); peer.closed = new Promise((resolve) => { close = resolve; });
  const result = await (await adapter({ launch: async () => peer }).start(input())).done; assert.equal(result.state, "candidate_ready");
});

test("bounded NDJSON rejects hostile raw frames before SDK parsing without reflecting secrets", async (t) => {
  const limits = { maximumFrameBytes: 256, maximumFrameDepth: 5, maximumFrameNodes: 30 };
  const cases = [
    ["oversized", Buffer.from("{" + "x".repeat(300))],
    ["malformed", Buffer.from('{"jsonrpc":"2.0","method":oops}\n')],
    ["truncated", Buffer.from('{"jsonrpc":"2.0","method":"Bearer supersecretvalue"}')],
    ["deep", Buffer.from('{"jsonrpc":"2.0","method":"x","params":[[[[[[0]]]]]]}\n')],
    ["duplicate key", Buffer.from('{"jsonrpc":"2.0","method":"x","method":"Bearer supersecretvalue"}\n')],
    ["escaped duplicate key", Buffer.from('{"jsonrpc":"2.0","method":"x","m\\u0065thod":"Bearer supersecretvalue"}\n')],
    ["unknown update", Buffer.from('{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"invented_update","raw":"Bearer supersecretvalue"}}}\n')],
    ["malformed optional usage", Buffer.from('{"jsonrpc":"2.0","id":1,"result":{"stopReason":"end_turn","usage":{"inputTokens":1,"outputTokens":1,"totalTokens":3}}}\n')],
    ["secret-bearing optional usage", Buffer.from('{"jsonrpc":"2.0","id":1,"result":{"usage":{"inputTokens":1,"outputTokens":1,"totalTokens":2,"apiToken":"supersecretvalue"}}}\n')],
    ["unsafe USD precision", Buffer.from('{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"usage_update","used":1,"size":2,"cost":{"amount":0.0000001,"currency":"USD"}}}}\n')],
    ["overflowing USD micros", Buffer.from('{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"usage_update","used":1,"size":2,"cost":{"amount":3000,"currency":"USD"}}}}\n')],
    ["secret-bearing cost", Buffer.from('{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"usage_update","used":1,"size":2,"cost":{"amount":1,"currency":"USD","apiToken":"supersecretvalue"}}}}\n')],
    ["fatal UTF-8", Buffer.from([0x7b, 0x22, 0x80, 0x0a])]
  ];
  for (const [name, bytes] of cases) await t.test(name, async () => {
    const stdin = new PassThrough(), stdout = new PassThrough(), stream = createBoundedNdjsonStream({ stdin, stdout, limits }); const reader = stream.readable.getReader(); stdout.end(bytes);
    await assert.rejects(reader.read(), (error) => error instanceof AcpProtocolError && !error.message.includes("supersecretvalue"));
  });
});

test("bounded NDJSON rechecks an oversized tail after consuming a valid complete frame", async () => {
  const limits = { maximumFrameBytes: 128, maximumFrameDepth: 8, maximumFrameNodes: 64 }, stdin = new PassThrough(), stdout = new PassThrough();
  const stream = createBoundedNdjsonStream({ stdin, stdout, limits }), reader = stream.readable.getReader(); stdout.write(Buffer.from('{"jsonrpc":"2.0","method":"ok"}\n'));
  assert.equal((await reader.read()).value.method, "ok"); stdout.write(Buffer.from("x".repeat(129))); await assert.rejects(reader.read(), AcpProtocolError);
});

test("production byte bounds admit a structurally large Grok tool history frame while retaining a finite node ceiling", async () => {
  const nodes = Array.from({ length: 17_500 }, (_, index) => index), frame = Buffer.from(`${JSON.stringify({ jsonrpc: "2.0", method: "session/update", params: { sessionId: "native-existing", update: { sessionUpdate: "tool_call", toolCallId: "history-tool", title: "history", status: "completed", rawOutput: nodes } } })}\n`);
  assert.ok(frame.byteLength < getCapabilityProfile("trusted-local").limits.maximumFrameBytes);
  const stdin = new PassThrough(), stdout = new PassThrough(), stream = createBoundedNdjsonStream({ stdin, stdout, limits: getCapabilityProfile("trusted-local").limits }), reader = stream.readable.getReader();
  stdout.end(frame);
  const result = await reader.read();
  assert.equal(result.value.params.update.rawOutput.length, 17_500);
});

test("chunked narrative and split secret normalize without leaking provider payloads", async () => {
  const events = [], peer = fakeAcpAgent({ chunks: ["Bearer super", "secretvalue\nImplementation ", "complete"] });
  const result = await (await adapter({ launch: async () => peer, onEvent: async (event) => events.push(event) }).start(input())).done;
  assert.match(result.assistantOutputDigest, /^sha256:[a-f0-9]{64}$/); const persisted = JSON.stringify(events); assert.doesNotMatch(persisted, /supersecretvalue/); assert.match(persisted, /REDACTED/); assert.ok(events.every((event) => !Object.hasOwn(event.value, "sessionUpdate")));
});

test("user or thought digest text cannot influence assistant output evidence", async (t) => {
  const marker = `sha256:${"d".repeat(64)}`;
  for (const sessionUpdate of ["user_message_chunk", "agent_thought_chunk"]) await t.test(sessionUpdate, async () => {
    const events = [];
    const peer = fakeAcpAgent({ chunks: ["ordinary agent text"], updates: [{ sessionUpdate, content: { type: "text", text: marker } }] });
    const result = await (await adapter({ launch: async () => peer, onEvent: async (event) => events.push(event) }).start(input())).done;
    assert.equal(result.assistantOutputDigest, digestText("ordinary agent text"));
    assert.equal(events.at(-1).kind, "terminal");
  });
});

test("official stable metadata updates normalize without retaining raw payload", async () => {
  const events = [], peer = fakeAcpAgent({ updates: [{ sessionUpdate: "current_mode_update", currentModeId: "code" }] });
  const result = await (await adapter({ launch: async () => peer, onEvent: async (event) => events.push(event) }).start(input())).done;
  assert.equal(result.state, "candidate_ready"); assert.ok(events.some((event) => event.kind === "current_mode" && event.value.currentModeId === "code")); assert.ok(events.every((event) => !Object.hasOwn(event.value, "sessionUpdate")));
});

test("valid and absent usage normalize strictly and USD cost is retained", async () => {
  const usage = { inputTokens: 3, outputTokens: 2, totalTokens: 5, thoughtTokens: 1 };
  const costUpdate = { sessionUpdate: "usage_update", used: 6, size: 100, cost: { amount: 0.02, currency: "USD" } };
  const result = await (await adapter({ launch: async () => fakeAcpAgent({ usage, updates: [costUpdate] }) }).start(input())).done;
  assert.deepEqual(result.usage, { contractVersion: CONTRACT_VERSIONS.usage, inputTokens: 3, outputTokens: 2, totalTokens: 5 }); assert.deepEqual(result.cost, { contractVersion: CONTRACT_VERSIONS.cost, currency: "USD", amountMicros: 20_000, source: "provider_reported" });
  const absent = await (await adapter({ launch: async () => fakeAcpAgent() }).start(input())).done; assert.equal(absent.usage, null); assert.equal(absent.cost, null);
});

test("malformed or secret-bearing final usage cannot be accepted", async (t) => {
  for (const usage of [{ inputTokens: 4, outputTokens: 4, totalTokens: 2 }, { inputTokens: 1, outputTokens: 1, totalTokens: 2, _meta: { apiToken: "supersecretvalue" } }]) await t.test(JSON.stringify(usage), async () => {
    const sessionAdapter = adapter({ launch: async () => fakeAcpAgent({ usage }) }); await assert.rejects((await sessionAdapter.start(input())).done, /recovery|failed|invalid/i); assert.equal(sessionAdapter.activeCount(), 0);
  });
});

test("trusted-host child parity drift fails before ACP initialization", async () => {
  const peer = fakeAcpAgent(), drifted = inspection(); drifted.capabilities.skills = ["forged"];
  const sessionAdapter = adapter({ launch: async () => peer, inspectChild: async () => drifted }); await assert.rejects(sessionAdapter.start(input()), /parity|differs/i); assert.deepEqual(peer.calls, []); assert.equal(sessionAdapter.activeCount(), 0);
});

test("active-job capacity is reserved before awaits and cannot be raced", async () => {
  const peer = fakeAcpAgent({ waitForCancel: true }), sessionAdapter = adapter({ launch: async () => peer }); const first = await sessionAdapter.start(input());
  await assert.rejects(sessionAdapter.start(input({ jobId: "job-2" })), /active-job limit/i); while (!peer.calls.some((call) => call.startsWith("prompt:"))) await new Promise((resolve) => setTimeout(resolve, 1)); await first.cancel(); await first.done; assert.equal(sessionAdapter.activeCount(), 0);
});

test("stale fence rejects the first provider event without advancing cursor", async () => {
  let current = true; const events = [], sessionAdapter = adapter({ launch: async () => fakeAcpAgent(), verifyFence: async () => current, onSessionBound: async () => { current = false; }, onEvent: async (event) => events.push(event) });
  await assert.rejects((await sessionAdapter.start(input())).done, /recovery|fence/i); assert.deepEqual(events, []); assert.equal(sessionAdapter.activeCount(), 0);
});

test("custody drift after native binding rejects the first provider event", async () => {
  let current = true; const events = [], sessionAdapter = adapter({ launch: async () => fakeAcpAgent(), verifyCustody: async () => current, onSessionBound: async () => { current = false; }, onEvent: async (event) => events.push(event) });
  await assert.rejects((await sessionAdapter.start(input())).done, /recovery|custody/i); assert.deepEqual(events, []); assert.equal(sessionAdapter.activeCount(), 0);
});

test("wrong session and forged correlation metadata are rejected before cursor persistence", async (t) => {
  const expected = { jobId: "job-1", attemptId: "attempt-1", requestId: "request-1", fencingToken: 1, nativeSessionId: "fake-session" };
  const cases = [
    ["wrong session", { sessionId: "other-session", update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: "bad\n" } } }],
    ["wrong job", { update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: "bad\n" }, _meta: { grokCorrelation: { ...expected, jobId: "other-job" } } } }],
    ["wrong attempt", { update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: "bad\n" }, _meta: { grokCorrelation: { ...expected, attemptId: "other-attempt" } } } }],
    ["wrong request", { update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: "bad\n" }, _meta: { grokCorrelation: { ...expected, requestId: "other-request" } } } }],
    ["extra correlation field", { update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: "bad\n" }, _meta: { grokCorrelation: { ...expected, extra: "forged" } } } }]
  ];
  for (const [name, notification] of cases) await t.test(name, async () => {
    const events = [], sessionAdapter = adapter({ launch: async () => fakeAcpAgent({ notifications: [notification] }), onEvent: async (event) => events.push(event) }); await assert.rejects((await sessionAdapter.start(input())).done, /recovery|correlation|failed/i); assert.deepEqual(events, []);
  });
});

test("duplicate provider sequence fails without accepting a later candidate", async (t) => {
  const sequenced = (sequence, value) => ({ sessionUpdate: "agent_message_chunk", content: { type: "text", text: `${value}\n` }, _meta: { grokSequence: sequence } });
  await t.test("duplicate sequence", async () => {
    const events = [], peer = fakeAcpAgent({ updates: [sequenced(1, "first"), sequenced(1, "second")] }), sessionAdapter = adapter({ launch: async () => peer, onEvent: async (event) => events.push(event) }); await assert.rejects((await sessionAdapter.start(input())).done, /recovery|sequence|failed/i); assert.equal(events.length, 1); assert.equal(events[0].sequence, 1);
  });
});

test("crash immediately after durable native-session binding is recovery-required", async () => {
  let lose; const peer = fakeAcpAgent({ waitForCancel: true }); peer.closed = new Promise((resolve) => { lose = resolve; }); const trace = [];
  let failure;
  const runtime = await adapter({ launch: async () => peer, onSessionBound: async () => { trace.push("bound"); lose({ code: 23, signal: "SIGKILL", spawnError: false, stderrBytes: 41, stderrLimitExceeded: false, rawStderr: "Bearer supersecretvalue" }); }, onFailure: async (value) => { failure = value; } }).start(input());
  await assert.rejects(runtime.done, (error) => error instanceof AcpRecoveryRequiredError); assert.deepEqual(trace, ["bound"]);
  assert.equal(failure.failureKind, "child_lost");
  assert.deepEqual(failure.childClose, { code: 23, signal: "SIGKILL", spawnError: false, stderrBytes: 41, stderrLimitExceeded: false });
  assert.doesNotMatch(JSON.stringify(failure), /supersecretvalue|rawStderr/);
});

test("missing cancellation terminal acknowledgement is recovery-required", async () => {
  const peer = fakeAcpAgent({ waitForCancel: true, cancelAcknowledges: false });
  const quickTimers = { setTimeout(handler, delay) { return setTimeout(handler, delay === 30_000 ? 5 : delay); }, clearTimeout };
  const sessionAdapter = adapter({ launch: async () => peer, timers: quickTimers }), runtime = await sessionAdapter.start(input()); const doneRejection = runtime.done.catch((error) => error);
  while (!peer.calls.some((call) => call.startsWith("prompt:"))) await new Promise((resolve) => setTimeout(resolve, 1));
  await assert.rejects(runtime.cancel(), (error) => error instanceof AcpRecoveryRequiredError); assert.ok((await doneRejection) instanceof AcpRecoveryRequiredError); assert.equal(sessionAdapter.activeCount(), 0);
});

test("durable callback failures remain generic and cancellation observes acknowledgement-store failure promptly", async (t) => {
  await t.test("session bind callback", async () => {
    const runtime = await adapter({ launch: async () => fakeAcpAgent(), onSessionBound: async () => { throw new Error("Bearer supersecretvalue"); } }).start(input()); await assert.rejects(runtime.done, (error) => error instanceof AcpRecoveryRequiredError && !error.message.includes("supersecretvalue"));
  });
  await t.test("failure callback", async () => {
    const runtime = await adapter({ launch: async () => fakeAcpAgent({ usage: { inputTokens: 1, outputTokens: 1, totalTokens: 3 } }), onFailure: async () => { throw new Error("Bearer supersecretvalue"); } }).start(input()); await assert.rejects(runtime.done, (error) => !error.message.includes("supersecretvalue"));
  });
  await t.test("cancel acknowledgement callback", async () => {
    const peer = fakeAcpAgent({ waitForCancel: true }), runtime = await adapter({ launch: async () => peer, onCancelAcknowledged: async () => { throw new Error("Bearer supersecretvalue"); } }).start(input()); const done = runtime.done.catch((error) => error);
    while (!peer.calls.some((call) => call.startsWith("prompt:"))) await new Promise((resolve) => setTimeout(resolve, 1)); await assert.rejects(runtime.cancel(), (error) => error instanceof AcpRecoveryRequiredError && !error.message.includes("supersecretvalue")); assert.ok((await done) instanceof AcpRecoveryRequiredError);
  });
});

test("initialization, idle, and overall profile timeouts stop the run and clean active state", async (t) => {
  const cases = [
    ["initialization", fakeAcpAgent({ stallInitialize: true }), 30_000],
    ["idle", fakeAcpAgent({ waitForCancel: true }), 300_000],
    ["overall", fakeAcpAgent({ waitForCancel: true }), 3_600_000]
  ];
  for (const [name, peer, target] of cases) await t.test(name, async () => {
    const sessionAdapter = adapter({ launch: async () => peer, timers: quickTimers(target) }), runtime = await sessionAdapter.start(input()); await assert.rejects(runtime.done, /recovery|failed/i); assert.equal(sessionAdapter.activeCount(), 0);
  });
});
