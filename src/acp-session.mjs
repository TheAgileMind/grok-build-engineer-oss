import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import * as acp from "@agentclientprotocol/sdk";

import { CONTRACT_VERSIONS, validateNormalizedCost, validateNormalizedUsage } from "./contracts.mjs";
import { getCapabilityProfile, profileFingerprint, verifyAttestedEnvironment, verifyChildAuthorityParity, verifyProfileDrift } from "./profiles.mjs";
import { redactForBoundary } from "./redaction.mjs";

export class AcpSessionError extends Error { constructor(message, cause) { super(message, { cause }); this.name = "AcpSessionError"; } }
export class AcpProtocolError extends AcpSessionError { constructor() { super("ACP peer sent an invalid bounded frame"); this.name = "AcpProtocolError"; } }
export class AcpCorrelationError extends AcpSessionError { constructor(message = "ACP correlation check failed") { super(message); this.name = "AcpCorrelationError"; } }
export class AcpRecoveryRequiredError extends AcpSessionError { constructor(message = "ACP session continuity requires recovery") { super(message); this.name = "AcpRecoveryRequiredError"; } }
export class AcpActivationRequiredError extends AcpSessionError { constructor() { super("Grok local activation is required"); this.name = "AcpActivationRequiredError"; } }

const KNOWN_UPDATES = new Set(["agent_message_chunk", "agent_thought_chunk", "user_message_chunk", "tool_call", "tool_call_update", "plan", "plan_update", "plan_removed", "available_commands_update", "current_mode_update", "config_option_update", "session_info_update", "usage_update"]);
const KNOWN_XAI_NOTIFICATIONS = Object.freeze(["_x.ai/mcp/servers_updated", "_x.ai/models/update", "_x.ai/settings/update", "_x.ai/announcements/update", "_x.ai/mcp/init_progress", "_x.ai/session_notification"]);
function boundedExtensionParams(value) { if (!value || typeof value !== "object" || Array.isArray(value)) throw new AcpProtocolError(); return value; }
function xaiTurnCompletedParams(value) {
  const params = boundedExtensionParams(value), update = params.update, usage = update?.usage;
  if (typeof params.sessionId !== "string" || !params.sessionId || !update || typeof update !== "object" || Array.isArray(update) ||
      update.sessionUpdate !== "turn_completed" || update.stop_reason !== "end_turn" || typeof update.prompt_id !== "string" || !update.prompt_id ||
      !usage || typeof usage !== "object" || Array.isArray(usage) ||
      ![usage.inputTokens, usage.outputTokens, usage.totalTokens].every((amount) => Number.isSafeInteger(amount) && amount >= 0) ||
      usage.totalTokens !== usage.inputTokens + usage.outputTokens) throw new AcpProtocolError();
  return params;
}

function text(value, label) { if (typeof value !== "string" || value.length === 0) throw new TypeError(`${label} must be non-empty text`); return value; }
function positive(value, label) { if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${label} must be a positive safe integer`); return value; }
function processIdentity(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("|") !== "pid|startedAt" ||
      !Number.isSafeInteger(value.pid) || value.pid < 1 || typeof value.startedAt !== "string" || Number.isNaN(Date.parse(value.startedAt))) {
    throw new AcpSessionError("spawned ACP child identity is unavailable");
  }
  return Object.freeze({ pid: value.pid, startedAt: new Date(value.startedAt).toISOString() });
}
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function timeout(promise, milliseconds, message, timers = globalThis) { let handle; return Promise.race([promise, new Promise((_, reject) => { handle = timers.setTimeout(() => reject(new AcpSessionError(message)), milliseconds); })]).finally(() => timers.clearTimeout(handle)); }
function safeError(error) { return error instanceof AcpRecoveryRequiredError ? error : new AcpSessionError("ACP session failed safely"); }
// Lexically scan before JSON.parse so duplicate keys and depth/node bombs are
// rejected before the official SDK receives a message.
function scanJson(source, maximumDepth = 32, maximumNodes = 65_536) {
  let at = 0, nodes = 0; const fail = () => { throw new AcpProtocolError(); }; const white = () => { while (/\s/.test(source[at] ?? "")) at += 1; };
  const stringToken = () => {
    const start = at; if (source[at++] !== '"') fail();
    while (at < source.length) { const char = source[at++]; if (char === '"') { try { return JSON.parse(source.slice(start, at)); } catch { fail(); } } if (char === "\\") { const escape = source[at++]; if (!'"\\/bfnrtu'.includes(escape ?? "")) fail(); if (escape === "u") { const hex = source.slice(at, at + 4); if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail(); at += 4; } } else if (char.charCodeAt(0) < 0x20) fail(); } fail();
  };
  const value = (depth) => {
    if (++nodes > maximumNodes || depth > maximumDepth) fail(); white(); const char = source[at];
    if (char === '"') { stringToken(); return; }
    if (char === "{") { at += 1; white(); const keys = new Set(); if (source[at] === "}") { at += 1; return; } for (;;) { white(); const key = stringToken(); if (keys.has(key)) fail(); keys.add(key); white(); if (source[at++] !== ":") fail(); value(depth + 1); white(); const next = source[at++]; if (next === "}") return; if (next !== ",") fail(); } }
    if (char === "[") { at += 1; white(); if (source[at] === "]") { at += 1; return; } for (;;) { value(depth + 1); white(); const next = source[at++]; if (next === "]") return; if (next !== ",") fail(); } }
    const tail = source.slice(at); const literal = /^(?:true|false|null)/.exec(tail)?.[0] ?? /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(tail)?.[0]; if (!literal) fail(); at += literal.length;
  };
  value(0); white(); if (at !== source.length) fail();
}

function exactOptionalKeys(value, allowed) { return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).every((key) => allowed.includes(key)); }
function strictUsageEvidence(usage) {
  if (!exactOptionalKeys(usage, ["inputTokens", "outputTokens", "totalTokens", "thoughtTokens", "cachedReadTokens", "cachedWriteTokens", "_meta"]) || usage._meta != null) throw new AcpProtocolError();
  const { inputTokens, outputTokens, totalTokens } = usage;
  if (![inputTokens, outputTokens, totalTokens].every((value) => Number.isSafeInteger(value) && value >= 0) || totalTokens !== inputTokens + outputTokens) throw new AcpProtocolError();
  for (const key of ["thoughtTokens", "cachedReadTokens", "cachedWriteTokens"]) if (usage[key] != null && (!Number.isSafeInteger(usage[key]) || usage[key] < 0)) throw new AcpProtocolError();
}
function strictCostEvidence(cost) {
  if (!exactOptionalKeys(cost, ["amount", "currency", "_meta"]) || cost._meta != null || cost.currency !== "USD" || !Number.isFinite(cost.amount) || cost.amount < 0) throw new AcpProtocolError();
  const micros = cost.amount * 1_000_000; if (!Number.isSafeInteger(micros) || micros / 1_000_000 !== cost.amount) throw new AcpProtocolError();
  try { validateNormalizedCost({ contractVersion: CONTRACT_VERSIONS.cost, currency: "USD", amountMicros: micros, source: "provider_reported" }); } catch { throw new AcpProtocolError(); }
}

function parseFrame(bytes, limits) {
  if (bytes.byteLength === 0 || bytes.byteLength > limits.maximumFrameBytes) throw new AcpProtocolError();
  let raw; try { raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { throw new AcpProtocolError(); }
  scanJson(raw, limits.maximumFrameDepth ?? 32, limits.maximumFrameNodes ?? 65_536);
  let message; try { message = JSON.parse(raw); } catch { throw new AcpProtocolError(); }
  if (!message || typeof message !== "object" || Array.isArray(message) || message.jsonrpc !== "2.0") throw new AcpProtocolError();
  if (Object.keys(message).some((key) => !["jsonrpc", "id", "method", "params", "result", "error"].includes(key))) throw new AcpProtocolError();
  const request = typeof message.method === "string", response = Object.hasOwn(message, "result") !== Object.hasOwn(message, "error");
  if (request === response || (response && !Object.hasOwn(message, "id"))) throw new AcpProtocolError();
  if (response && message.result && typeof message.result === "object" && Object.hasOwn(message.result, "usage") && message.result.usage != null) strictUsageEvidence(message.result.usage);
  if (message.method === acp.methods.client.session.update) {
    const params = message.params, update = params?.update;
    if (!params || typeof params !== "object" || typeof params.sessionId !== "string" || !update || typeof update !== "object" || !KNOWN_UPDATES.has(update.sessionUpdate)) throw new AcpProtocolError();
    if (["agent_message_chunk", "agent_thought_chunk", "user_message_chunk"].includes(update.sessionUpdate) && (update.content?.type !== "text" || typeof update.content.text !== "string")) throw new AcpProtocolError();
    if (update.sessionUpdate === "usage_update" && Object.hasOwn(update, "cost") && update.cost != null) strictCostEvidence(update.cost);
  }
  return message;
}

/** Stable ACP v1 Stream with inbound bounds applied before JSON parsing. */
export function createBoundedNdjsonStream({ stdin, stdout, limits, onFatal = () => {} }) {
  if (!stdin?.write || !stdout?.on) throw new TypeError("Node stdio streams are required");
  let pending = Buffer.alloc(0), finished = false, cleanup = () => {};
  const readable = new ReadableStream({
    start(controller) {
      const fatal = () => { if (finished) return; finished = true; onFatal(); cleanup(); controller.error(new AcpProtocolError()); };
      const data = (chunk) => { if (finished) return; pending = Buffer.concat([pending, Buffer.from(chunk)]); for (;;) { const newline = pending.indexOf(0x0a); if (newline < 0) break; let frame = pending.subarray(0, newline); pending = pending.subarray(newline + 1); if (frame.at(-1) === 0x0d) frame = frame.subarray(0, -1); try { controller.enqueue(parseFrame(frame, limits)); } catch { return fatal(); } } if (pending.byteLength > limits.maximumFrameBytes) fatal(); };
      const end = () => { if (finished) return; if (pending.byteLength) return fatal(); finished = true; cleanup(); controller.close(); }; const error = () => fatal();
      cleanup = () => { stdout.off("data", data); stdout.off("end", end); stdout.off("error", error); }; stdout.on("data", data); stdout.once("end", end); stdout.once("error", error);
    }, cancel() { finished = true; cleanup(); try { stdout.destroy(); } catch {} }
  });
  const writable = new WritableStream({ write(message) { const encoded = Buffer.from(`${JSON.stringify(message)}\n`); if (encoded.byteLength > limits.maximumFrameBytes) throw new AcpProtocolError(); return new Promise((resolve, reject) => stdin.write(encoded, (error) => error ? reject(new AcpProtocolError()) : resolve())); }, close() { stdin.end(); }, abort() { stdin.destroy(); } });
  return { readable, writable };
}

export function buildLaunchPlan({ attestation, worktree, environment = process.env }) {
  const profile = getCapabilityProfile(attestation?.profileId);
  if (!attestation?.executable?.path || !isAbsolute(attestation.executable.path) || attestation.profileDigest !== profileFingerprint(profile) || !Array.isArray(attestation.argv) || attestation.argv.some((argument) => typeof argument !== "string" || !argument) || JSON.stringify(attestation.argv) !== JSON.stringify(profile.argv) || JSON.stringify(attestation.environmentKeys) !== JSON.stringify(profile.environmentKeys)) throw new AcpSessionError("frozen attestation has no approved ACP launch shape");
  verifyAttestedEnvironment(attestation, { environment });
  if (!isAbsolute(worktree)) throw new AcpSessionError("admitted worktree must be absolute");
  const env = {}; for (const key of attestation.environmentKeys ?? []) if (typeof environment[key] === "string") env[key] = environment[key];
  return Object.freeze({ command: attestation.executable.path, args: Object.freeze([...attestation.argv]), options: Object.freeze({ cwd: worktree, env: Object.freeze(env), shell: false, stdio: Object.freeze(["pipe", "pipe", "pipe"]), windowsHide: true }) });
}

export function launchAcpChild({ attestation, worktree, limits, spawnImpl = spawn, environment = process.env, processInspector = null, input = null }) {
  let plan, child;
  try { plan = buildLaunchPlan({ attestation, worktree, environment }); }
  catch (error) { if (error && typeof error === "object") error.safeStage = "adapter_child_launch_plan"; throw error; }
  try { child = spawnImpl(plan.command, plan.args, plan.options); }
  catch (error) { if (error && typeof error === "object") error.safeStage = "adapter_child_spawn"; throw error; }
  let stopped = false, stderrBytes = 0, stderrLimitExceeded = false; const closed = deferred();
  const stop = () => { if (stopped) return; stopped = true; try { child.kill(); } catch {} };
  let childProcessIdentity = null;
  try {
    if (typeof processInspector === "function") {
      // Windows may expose the spawned PID a fraction later than spawn()
      // returns. Each inspector call is itself bounded; retry only the
      // indeterminate state and never accept absent/mismatched evidence.
      let observed = null;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        observed = processInspector({ pid: child.pid, executablePath: plan.command });
        if (observed?.state === "present") break;
      }
      if (observed?.state !== "present") {
        // A new native session needs durable PID/start evidence for later
        // process-loss recovery. A session/load repair already has that
        // immutable identity in its original runtime seal, and the repair
        // prompt boundary is journaled separately before prompt.
        if (typeof input?.nativeSessionId !== "string" || input.nativeSessionId.length === 0) throw new AcpSessionError("spawned ACP child cannot be identified");
      } else childProcessIdentity = processIdentity(observed.identity);
    }
  } catch (error) { stop(); const safe = error instanceof AcpSessionError ? error : new AcpSessionError("spawned ACP child cannot be identified"); safe.safeStage = "adapter_child_identity"; throw safe; }
  child.stderr.on("data", (chunk) => { stderrBytes += Buffer.byteLength(chunk); if (stderrBytes > limits.maximumEventBytes) { stderrLimitExceeded = true; stop(); } }); child.stderr.resume();
  child.once("error", () => closed.resolve({ lost: true, code: null, signal: null, spawnError: true, stderrBytes, stderrLimitExceeded }));
  child.once("close", (code, signal) => closed.resolve({ lost: true, code, signal, spawnError: false, stderrBytes, stderrLimitExceeded }));
  return { stream: createBoundedNdjsonStream({ stdin: child.stdin, stdout: child.stdout, limits, onFatal: stop }), stop, closed: closed.promise, launchPlan: plan, childProcessIdentity };
}

function normalizeChildCloseEvidence(value, limits) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const code = value.code === null || Number.isSafeInteger(value.code) ? (value.code ?? null) : null;
  const signal = typeof value.signal === "string" && /^[A-Z0-9_]{1,32}$/.test(value.signal) ? value.signal : null;
  const stderrBytes = Number.isSafeInteger(value.stderrBytes) && value.stderrBytes >= 0
    ? Math.min(value.stderrBytes, limits.maximumEventBytes + 1)
    : 0;
  return Object.freeze({ code, signal, spawnError: value.spawnError === true, stderrBytes, stderrLimitExceeded: value.stderrLimitExceeded === true });
}

function normalizeUsage(usage) {
  if (usage == null) return null;
  strictUsageEvidence(usage); const normalized = { contractVersion: CONTRACT_VERSIONS.usage, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, totalTokens: usage.totalTokens };
  try { return validateNormalizedUsage(normalized); } catch { throw new AcpProtocolError(); }
}
function normalizeCost(update) { if (update.cost == null) return null; strictCostEvidence(update.cost); return validateNormalizedCost({ contractVersion: CONTRACT_VERSIONS.cost, currency: "USD", amountMicros: update.cost.amount * 1_000_000, source: "provider_reported" }); }
function digestText(value) { return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`; }
function correlationMeta(update, expected, providerSequence) { const keys = ["jobId", "attemptId", "requestId", "fencingToken", "nativeSessionId"], meta = update?._meta?.grokCorrelation; if (meta != null && (!meta || typeof meta !== "object" || Array.isArray(meta) || Object.keys(meta).length !== keys.length || keys.some((key) => meta[key] !== expected[key]))) throw new AcpCorrelationError(); const next = update?._meta?.grokSequence; if (next != null) { if (!Number.isSafeInteger(next) || next !== providerSequence + 1) throw new AcpCorrelationError("ACP provider sequence is stale or out of order"); return next; } return providerSequence; }
function attestedLaunchEvidence(attestation) { return Object.freeze({ profileId: attestation.profileId, profileDigest: attestation.profileDigest, fingerprint: attestation.fingerprint, executableDigest: attestation.executable.digest, argv: Object.freeze([...attestation.argv]), cwdPolicy: attestation.cwdPolicy, environmentKeys: Object.freeze([...attestation.environmentKeys]), environmentDigest: attestation.environmentDigest }); }

export function createAcpSessionAdapter({ launch = launchAcpChild, inspectChild, verifyCustody, verifyFence, onSessionBound = async () => {}, onPromptDispatch = async () => {}, onEvent = async () => {}, onFailure = async () => {}, beforeCancel = async () => {}, onCancelAcknowledged = async () => {}, classifyPermission, authorizePermission, environment = process.env, timers = globalThis } = {}) {
  const active = new Map();
  async function start(input) {
    const jobId = text(input.jobId, "jobId"), attemptId = text(input.attemptId, "attemptId"), requestId = text(input.requestId, "requestId"); positive(input.fencingToken, "fencingToken");
    const profile = getCapabilityProfile(input.attestation?.profileId), limits = profile.limits, launchEnvironment = Object.freeze(Object.fromEntries(profile.environmentKeys.filter((key) => typeof environment[key] === "string").map((key) => [key, environment[key]])));
    if (active.has(jobId) || active.size >= limits.maximumActiveJobs) throw new AcpSessionError("immutable profile active-job limit reached");
    active.set(jobId, { pending: true });
    let child, nativeSessionId = null, terminal = false, sequence = 0, providerSequence = 0, assistantBuffer = "", assistantText = "", cost = null, cancellationPending = false, cancelPromise = null, idleHandle, overallHandle, closeHandle, bindPhase = "idle", turnPhase = "idle", preBindBytes = 0, preBindGeneration = 0, childClose = null, turnGeneration = 0; const preBindUpdates = [], textBuffers = { agent_thought_chunk: "", user_message_chunk: "" }; let eventTimes = [];
    const fatal = deferred(), cancellationReceipt = deferred(); let fatalSet = false;
    const expected = () => ({ jobId, attemptId, requestId, fencingToken: input.fencingToken, nativeSessionId });
    const fail = (error) => { if (fatalSet) return; fatalSet = true; fatal.reject(error instanceof AcpRecoveryRequiredError ? error : safeError(error)); try { child?.stop(); } catch {} };
    const fence = async () => { if (typeof verifyFence !== "function" || await verifyFence(expected()) !== true) throw new AcpCorrelationError("current execution fence is unavailable"); };
    const custody = async () => { if (typeof verifyCustody !== "function" || await verifyCustody(input) !== true) throw new AcpCorrelationError("worktree custody is unavailable"); };
    const guard = async () => {
      if (fatalSet) throw new AcpRecoveryRequiredError();
      await custody();
      await fence();
      if (fatalSet) throw new AcpRecoveryRequiredError();
    };
    const resetIdle = () => { timers.clearTimeout(idleHandle); idleHandle = timers.setTimeout(() => fail(new AcpRecoveryRequiredError("ACP idle timeout requires recovery")), limits.idleTimeoutMs); };
    const emit = async (kind, value) => { await guard(); const now = typeof timers.now === "function" ? timers.now() : Date.now(); eventTimes = eventTimes.filter((point) => now - point < 60_000); if (eventTimes.length >= limits.maximumEventsPerMinute) throw new AcpProtocolError(); resetIdle(); const event = { ...expected(), sequence: sequence + 1, cursor: `${attemptId}:${sequence + 1}`, kind, value: redactForBoundary(value) }; if (Buffer.byteLength(JSON.stringify(event.value)) > limits.maximumEventBytes) throw new AcpProtocolError(); await onEvent(event); eventTimes.push(now); sequence += 1; };
    const validatedUpdate = (params) => { if (!params || typeof params !== "object" || typeof params.sessionId !== "string" || !params.update || typeof params.update !== "object" || !KNOWN_UPDATES.has(params.update.sessionUpdate)) throw new AcpProtocolError(); return params.update; };
    const queuePreBindUpdate = (params) => {
      validatedUpdate(params); if (bindPhase !== "pending" && params.sessionId !== nativeSessionId) throw new AcpCorrelationError();
      let copy, bytes; try { copy = structuredClone({ sessionId: params.sessionId, update: params.update }); bytes = Buffer.byteLength(JSON.stringify(copy)); } catch { throw new AcpProtocolError(); }
      // Session/load history is still an event burst. Reuse the immutable
      // profile's one-minute event ceiling instead of inventing a smaller cap.
      if (preBindUpdates.length >= limits.maximumEventsPerMinute || bytes > limits.maximumFrameBytes || preBindBytes + bytes > limits.maximumFrameBytes) throw new AcpProtocolError();
      preBindUpdates.push({ params: copy, bytes }); preBindBytes += bytes; preBindGeneration += 1;
    };
    let prelaunchStage = "adapter_profile_drift";
    try {
      verifyProfileDrift(input.attestation, input.inspection, { environment: launchEnvironment });
      prelaunchStage = "adapter_guard"; await guard();
      prelaunchStage = "adapter_child_launch";
      child = await launch({ attestation: input.attestation, worktree: text(input.worktree, "worktree"), limits, environment: launchEnvironment, input }); if (!child || (!child.agent && !child.stream) || typeof child.stop !== "function") throw new AcpSessionError("launcher returned no bounded ACP peer");
      prelaunchStage = "adapter_child_parity";
      if (profile.enforcementClass !== "os_enforced") { if (typeof inspectChild !== "function") throw new AcpRecoveryRequiredError("launched child authority parity is unavailable"); verifyChildAuthorityParity(input.attestation, await inspectChild({ ...input, child }), { environment: launchEnvironment }); }
    } catch (error) { active.delete(jobId); try { child?.stop(); } catch {} if (error && typeof error === "object" && typeof error.safeStage !== "string") error.safeStage = prelaunchStage; throw error; }
    overallHandle = timers.setTimeout(() => fail(new AcpRecoveryRequiredError("ACP overall timeout requires recovery")), limits.overallTimeoutMs); if (child.closed) child.closed.then((evidence) => { childClose = normalizeChildCloseEvidence(evidence, limits); closeHandle = timers.setTimeout(() => { if (!terminal) fail(new AcpRecoveryRequiredError(cancellationPending ? "cancellation child was lost" : "ACP child was lost")); }, 250); });
    let sendCancel;
    let client = acp.client({ name: "grok-build-engineer" })
      .onRequest(acp.methods.client.session.requestPermission, async (ctx) => {
        try {
          await guard(); if (typeof classifyPermission !== "function" || typeof authorizePermission !== "function") throw new AcpProtocolError();
          const classified = await classifyPermission(ctx.params, input); if (!classified || classified.trustedMeta === true) throw new AcpProtocolError();
          const decision = await authorizePermission(classified, input); if (!decision?.allowed || typeof decision.optionId !== "string" || !ctx.params.options.some((option) => option.optionId === decision.optionId)) throw new AcpProtocolError();
          await emit("permission_allowed", { operation: typeof classified.operation === "string" ? classified.operation : "classified_operation", optionId: decision.optionId });
          return { outcome: { outcome: "selected", optionId: decision.optionId } };
        } catch {
          try { if (nativeSessionId && !fatalSet) await emit("permission_denied", { reason: "frozen_authority" }); } catch (error) { fail(error); }
          return { outcome: { outcome: "cancelled" } };
        }
      })
      .onRequest(acp.methods.client.fs.readTextFile, async () => { throw new AcpProtocolError(); }).onRequest(acp.methods.client.fs.writeTextFile, async () => { throw new AcpProtocolError(); });
    // Grok 1.0.0 emits these bounded vendor notifications while replaying a
    // session. They are UI metadata, carry no authority, and are deliberately
    // ignored rather than retained or translated into job evidence. All other
    // unregistered extension methods continue to fail closed in the ACP SDK.
    for (const method of KNOWN_XAI_NOTIFICATIONS) client = client.onNotification(method, boundedExtensionParams, async () => {});
    client = client.onNotification("_x.ai/session/update", xaiTurnCompletedParams, async (ctx) => {
      if (bindPhase === "ready" && ctx.params.sessionId !== nativeSessionId) fail(new AcpCorrelationError());
    });
    client = client.onNotification(acp.methods.client.session.update, async (ctx) => { if (fatalSet) return; try {
        if (bindPhase === "pending" || bindPhase === "settling" || bindPhase === "replaying") { queuePreBindUpdate(ctx.params); return; }
        if (bindPhase !== "ready" || turnPhase !== "prompting" || !nativeSessionId || ctx.params.sessionId !== nativeSessionId) throw new AcpCorrelationError(); const update = validatedUpdate(ctx.params); providerSequence = correlationMeta(update, expected(), providerSequence); turnGeneration += 1;
        if (["agent_message_chunk", "agent_thought_chunk", "user_message_chunk"].includes(update.sessionUpdate)) {
          if (update.content?.type !== "text" || typeof update.content.text !== "string") throw new AcpProtocolError();
          const isAgent = update.sessionUpdate === "agent_message_chunk"; let buffer = isAgent ? assistantBuffer : textBuffers[update.sessionUpdate]; buffer += update.content.text;
          for (;;) {
            const newline = buffer.indexOf("\n"); if (newline < 0) break; const line = buffer.slice(0, newline).replace(/\r$/, ""); buffer = buffer.slice(newline + 1);
            if (line) { if (isAgent) assistantText += redactForBoundary(`${line}\n`); await emit(update.sessionUpdate === "agent_thought_chunk" ? "thought" : update.sessionUpdate === "user_message_chunk" ? "user_text" : "text", { text: line }); }
          }
          if (Buffer.byteLength(buffer) > limits.maximumFrameBytes) throw new AcpProtocolError(); if (isAgent) assistantBuffer = buffer; else textBuffers[update.sessionUpdate] = buffer;
        }
        else if (update.sessionUpdate === "usage_update") { if (!Number.isSafeInteger(update.used) || update.used < 0 || !Number.isSafeInteger(update.size) || update.size < update.used) throw new AcpProtocolError(); cost = normalizeCost(update); await emit("usage", { used: update.used, size: update.size, cost }); }
        else if (update.sessionUpdate === "tool_call" || update.sessionUpdate === "tool_call_update") { if (typeof update.toolCallId !== "string" || !update.toolCallId) throw new AcpProtocolError(); await emit("tool", { toolCallId: update.toolCallId, title: typeof update.title === "string" ? update.title : null, status: typeof update.status === "string" ? update.status : null }); }
        else if (update.sessionUpdate === "plan") await emit("plan", { entries: Array.isArray(update.entries) ? update.entries.map((entry) => ({ content: String(entry.content ?? ""), status: String(entry.status ?? "") })) : [] });
        else if (update.sessionUpdate === "plan_update") await emit("plan_update", { planId: typeof update.plan?.planId === "string" ? update.plan.planId : null, type: typeof update.plan?.type === "string" ? update.plan.type : null, entryCount: Array.isArray(update.plan?.entries) ? update.plan.entries.length : null });
        else if (update.sessionUpdate === "plan_removed") await emit("plan_removed", { planId: String(update.planId) });
        else if (update.sessionUpdate === "available_commands_update") await emit("available_commands", { count: Array.isArray(update.availableCommands) ? update.availableCommands.length : 0 });
        else if (update.sessionUpdate === "current_mode_update") await emit("current_mode", { currentModeId: String(update.currentModeId) });
        else if (update.sessionUpdate === "config_option_update") await emit("config_options", { count: Array.isArray(update.configOptions) ? update.configOptions.length : 0 });
        else if (update.sessionUpdate === "session_info_update") await emit("session_info", { hasTitle: typeof update.title === "string", updatedAt: typeof update.updatedAt === "string" ? update.updatedAt : null });
      } catch (error) { fail(error); } });
    const run = client.connectWith(child.agent ?? child.stream, async (ctx) => {
      const initialized = await timeout(ctx.request(acp.methods.agent.initialize, { protocolVersion: acp.PROTOCOL_VERSION, clientCapabilities: {}, clientInfo: { name: "grok-build-engineer", version: "0.3.13" } }), limits.initializationTimeoutMs, "ACP initialization timed out", timers); if (initialized.protocolVersion !== acp.PROTOCOL_VERSION) throw new AcpProtocolError();
      if (Array.isArray(initialized.authMethods) && initialized.authMethods.length) {
        const cached = initialized.authMethods.find((method) => method?.id === "cached_token" && typeof method.name === "string" && method.name && method.type == null && !["args", "env", "vars", "link"].some((key) => Object.hasOwn(method, key))); if (!cached) throw new AcpActivationRequiredError();
        await timeout(ctx.request(acp.methods.agent.authenticate, { methodId: cached.id, _meta: { headless: true, credentialSource: "local_cache" } }), limits.initializationTimeoutMs, "Grok local activation timed out", timers);
      }
      bindPhase = "pending";
      if (input.nativeSessionId) { if (initialized.agentCapabilities?.loadSession !== true) throw new AcpRecoveryRequiredError("ACP peer cannot load the prior native session"); await timeout(ctx.request(acp.methods.agent.session.load, { sessionId: input.nativeSessionId, cwd: input.worktree, mcpServers: [] }), limits.initializationTimeoutMs, "ACP session load timed out", timers); nativeSessionId = input.nativeSessionId; } else { const created = await timeout(ctx.request(acp.methods.agent.session.new, { cwd: input.worktree, mcpServers: [] }), limits.initializationTimeoutMs, "ACP session creation timed out", timers); nativeSessionId = text(created.sessionId, "native session ID"); }
      if (fatalSet) throw new AcpRecoveryRequiredError(); bindPhase = "settling";
      if (preBindUpdates.some(({ params }) => params.sessionId !== nativeSessionId)) throw new AcpCorrelationError();
       await guard(); await onSessionBound({ ...expected(), protocolVersion: initialized.protocolVersion, launchEvidence: attestedLaunchEvidence(input.attestation), childProcessIdentity: child.childProcessIdentity ?? null }); sendCancel = () => ctx.notify(acp.methods.agent.session.cancel, { sessionId: nativeSessionId }); bindPhase = "replaying";
      // Resume is deliberately history-free. Any notification queued while the
      // resume request was binding belongs to the old stream epoch and is
      // quarantined rather than replayed into the repair turn. A peer that
      // cannot provide resume was rejected above; falling back to load would
      // silently reintroduce stale assistant output.
      if (input.nativeSessionId) { preBindUpdates.length = 0; preBindBytes = 0; }
      while (!input.nativeSessionId && preBindUpdates.length) { const { params, bytes } = preBindUpdates.shift(); preBindBytes -= bytes; const update = validatedUpdate(params); if (params.sessionId !== nativeSessionId) throw new AcpCorrelationError(); providerSequence = correlationMeta(update, expected(), providerSequence);
        if (["agent_message_chunk", "agent_thought_chunk", "user_message_chunk"].includes(update.sessionUpdate)) {
          if (update.content?.type !== "text" || typeof update.content.text !== "string") throw new AcpProtocolError(); const isAgent = update.sessionUpdate === "agent_message_chunk"; let buffer = isAgent ? assistantBuffer : textBuffers[update.sessionUpdate]; buffer += update.content.text;
          for (;;) { const newline = buffer.indexOf("\n"); if (newline < 0) break; const line = buffer.slice(0, newline).replace(/\r$/, ""); buffer = buffer.slice(newline + 1); if (line) await emit(update.sessionUpdate === "agent_thought_chunk" ? "thought" : update.sessionUpdate === "user_message_chunk" ? "user_text" : "text", { text: line }); }
          if (Buffer.byteLength(buffer) > limits.maximumFrameBytes) throw new AcpProtocolError(); if (isAgent) assistantBuffer = buffer; else textBuffers[update.sessionUpdate] = buffer;
        } else if (update.sessionUpdate === "usage_update") { if (!Number.isSafeInteger(update.used) || update.used < 0 || !Number.isSafeInteger(update.size) || update.size < update.used) throw new AcpProtocolError(); cost = normalizeCost(update); await emit("usage", { used: update.used, size: update.size, cost }); }
        else if (update.sessionUpdate === "tool_call" || update.sessionUpdate === "tool_call_update") { if (typeof update.toolCallId !== "string" || !update.toolCallId) throw new AcpProtocolError(); await emit("tool", { toolCallId: update.toolCallId, title: typeof update.title === "string" ? update.title : null, status: typeof update.status === "string" ? update.status : null }); }
        else if (update.sessionUpdate === "plan") await emit("plan", { entries: Array.isArray(update.entries) ? update.entries.map((entry) => ({ content: String(entry.content ?? ""), status: String(entry.status ?? "") })) : [] });
        else if (update.sessionUpdate === "plan_update") await emit("plan_update", { planId: typeof update.plan?.planId === "string" ? update.plan.planId : null, type: typeof update.plan?.type === "string" ? update.plan.type : null, entryCount: Array.isArray(update.plan?.entries) ? update.plan.entries.length : null });
        else if (update.sessionUpdate === "plan_removed") await emit("plan_removed", { planId: String(update.planId) });
        else if (update.sessionUpdate === "available_commands_update") await emit("available_commands", { count: Array.isArray(update.availableCommands) ? update.availableCommands.length : 0 });
        else if (update.sessionUpdate === "current_mode_update") await emit("current_mode", { currentModeId: String(update.currentModeId) });
        else if (update.sessionUpdate === "config_option_update") await emit("config_options", { count: Array.isArray(update.configOptions) ? update.configOptions.length : 0 });
        else if (update.sessionUpdate === "session_info_update") await emit("session_info", { hasTitle: typeof update.title === "string", updatedAt: typeof update.updatedAt === "string" ? update.updatedAt : null });
      }
      // Pre-bind output is session-lifecycle evidence, never current-turn
      // assistant evidence. It may be emitted for a new session, but it cannot
      // contribute to the digest that authorizes local candidate publication.
      if (assistantBuffer) { await emit("text", { text: assistantBuffer }); assistantBuffer = ""; }
      for (const [kind, buffer] of Object.entries(textBuffers)) if (buffer) { await emit(kind === "agent_thought_chunk" ? "thought" : "user_text", { text: buffer }); textBuffers[kind] = ""; }
      // session/load may finish its replay notifications shortly after the RPC
      // response. Keep the adapter in replaying state until that old stream is
      // quiet for a full boundary window; every such frame remains bounded and
      // is discarded, never translated into current-turn candidate evidence.
      if (input.nativeSessionId) {
        let observedGeneration = preBindGeneration, stableSince = Date.now();
        while (Date.now() - stableSince < 150) {
          await new Promise((resolve) => timers.setTimeout(resolve, 25)); await guard();
          if (preBindGeneration !== observedGeneration) {
            observedGeneration = preBindGeneration; stableSince = Date.now();
            preBindUpdates.length = 0; preBindBytes = 0;
          }
        }
        preBindUpdates.length = 0; preBindBytes = 0;
      }
      // Publish the turn boundary synchronously: notifications before it were
      // quarantined history; notifications after it belong to this prompt.
      turnPhase = "prompting"; bindPhase = "ready"; resetIdle(); await guard(); await onPromptDispatch(expected()); await guard();
      const response = await ctx.request(acp.methods.agent.session.prompt, { sessionId: nativeSessionId, prompt: [{ type: "text", text: text(input.prompt, "prompt") }] }); timers.clearTimeout(idleHandle); await guard();
      // xAI's ACP prompt response is completion metadata, not a guarantee that
      // the final session/update notification has been delivered. Drain until
      // the current turn's update generation is stable, bounded by the idle
      // timeout. This prevents post-response chunks from being lost or treated
      // as a later turn.
      let stableSince = Date.now(), observedGeneration = turnGeneration;
      while (Date.now() - stableSince < 150) {
        await new Promise((resolve) => timers.setTimeout(resolve, 25));
        if (turnGeneration !== observedGeneration) { observedGeneration = turnGeneration; stableSince = Date.now(); }
        if (Date.now() - stableSince >= 150) break;
      }
      turnPhase = "terminalizing";
      await guard();
      if (assistantBuffer) { assistantText += redactForBoundary(assistantBuffer); await emit("text", { text: assistantBuffer }); assistantBuffer = ""; }
      for (const [kind, buffer] of Object.entries(textBuffers)) if (buffer) { await emit(kind === "agent_thought_chunk" ? "thought" : "user_text", { text: buffer }); textBuffers[kind] = ""; }
      const usage = normalizeUsage(response.usage);
      if (cancellationPending) { if (response.stopReason !== "cancelled") throw new AcpRecoveryRequiredError("ACP cancellation acknowledgement was missing"); await onCancelAcknowledged({ ...expected(), stopReason: "cancelled" }); cancellationReceipt.resolve(true); terminal = true; return { state: "cancelled", stopReason: "cancelled", usage, cost }; }
      if (response.stopReason !== "end_turn") throw new AcpSessionError("ACP terminal completion evidence is incomplete");
      const assistantOutputDigest = digestText(assistantText);
      const terminalEvidenceDigest = digestText(JSON.stringify({ sessionId: nativeSessionId, requestId, stopReason: response.stopReason, providerSequence, eventSequence: sequence, assistantOutputDigest }));
      await emit("terminal", { stopReason: response.stopReason, providerSequence, assistantOutputDigest, terminalEvidenceDigest });
      terminal = true; return { state: "candidate_ready", assistantOutputDigest, terminalEvidenceDigest, stopReason: response.stopReason, usage, cost };
    });
    const done = Promise.race([run, fatal.promise]).catch(async (error) => {
      const recovery = error instanceof AcpActivationRequiredError ? error : nativeSessionId ? (error instanceof AcpRecoveryRequiredError ? error : new AcpRecoveryRequiredError()) : safeError(error);
      const failureKind = recovery instanceof AcpActivationRequiredError ? "activation_required" : childClose ? "child_lost" : recovery instanceof AcpRecoveryRequiredError ? "recovery_required" : "session_failure";
      try { await onFailure({ ...expected(), error: recovery.message, recoveryRequired: recovery instanceof AcpRecoveryRequiredError, failureKind, childClose }); } catch {}
      throw recovery;
    }).finally(() => { terminal = true; timers.clearTimeout(idleHandle); timers.clearTimeout(overallHandle); timers.clearTimeout(closeHandle); active.delete(jobId); try { child.stop(); } catch {} });
    const runtime = { correlation: expected, child, done, cancel() {
      if (cancelPromise) return cancelPromise;
      cancelPromise = (async () => {
        try { await guard(); await beforeCancel(expected()); }
        catch { cancelPromise = null; throw new AcpSessionError("cancellation intent was not persisted"); }
        cancellationPending = true;
        if (!sendCancel) { const error = new AcpRecoveryRequiredError("native session is not yet cancellable"); fail(error); throw error; }
        try { await sendCancel(); await timeout(Promise.race([cancellationReceipt.promise, done.then(() => { throw new AcpRecoveryRequiredError(); }, () => { throw new AcpRecoveryRequiredError(); })]), limits.cancellationTimeoutMs, "ACP cancellation acknowledgement timed out", timers); }
        catch { const error = new AcpRecoveryRequiredError("ACP cancellation acknowledgement timed out"); fail(error); throw error; }
        return true;
      })();
      return cancelPromise;
    } };
    active.set(jobId, runtime); return runtime;
  }
  return Object.freeze({ start, activeCount: () => active.size, get: (jobId) => active.get(jobId) ?? null });
}
