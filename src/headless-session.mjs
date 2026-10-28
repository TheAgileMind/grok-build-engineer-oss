import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { closeSync, fsyncSync, lstatSync, mkdirSync, openSync, unlinkSync, writeFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

import { getCapabilityProfile, verifyChildAuthorityParity, verifyProfileDrift } from "./profiles.mjs";
import { redactForBoundary } from "./redaction.mjs";
import { frameDiagnostics } from "./stream-frames.mjs";
import { exactCommandRule, FIXED_WINDOWS_ENVIRONMENT_KEYS } from "./task-policy.mjs";

export const HEADLESS_ADAPTER_VERSION = "agent-platform.grok-builder-headless.v1";
export class HeadlessSessionError extends Error { constructor(message = "Headless Grok session failed safely") { super(message); this.name = "HeadlessSessionError"; } }
export class HeadlessProtocolError extends HeadlessSessionError { constructor(message = "Headless Grok emitted an invalid bounded frame") { super(message); this.name = "HeadlessProtocolError"; } }
export class HeadlessRecoveryRequiredError extends HeadlessSessionError { constructor(message = "Headless Grok continuity requires recovery") { super(message); this.name = "HeadlessRecoveryRequiredError"; } }
export class HeadlessCliError extends HeadlessRecoveryRequiredError { constructor(message = "Headless Grok CLI reported an error") { super(message); this.name = "HeadlessCliError"; } }

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_STDERR_TAIL_BYTES = 8 * 1024;
const MAX_STREAM_BYTES = 16 * 1024 * 1024;
const MAX_ASSISTANT_BYTES = 4 * 1024 * 1024;
const MAX_PROMPT_BYTES = 8 * 1024 * 1024;
const MAX_ARRAY_ENTRIES = 10_000;
const TERMINAL_STOP_REASON = "end_turn";
const HEADLESS_AGENT = "general-purpose";
const HEADLESS_REASONING_EFFORT = "high";
const HEADLESS_MAX_TURNS = 24;
const KNOWN_TYPES = new Set(["thought", "tool_call", "tool_call_update", "text", "usage", "plan", "available_commands", "end", "error", "max_turns_reached"]);
// Headless filtering uses Grok's internal tool IDs. The capitalized names below
// are permission-rule classes and are intentionally limited to --allow/--deny.
const ALLOWED_TOOLS = Object.freeze(["read_file", "grep", "list_dir", "search_replace", "run_terminal_cmd"]);
const FIXED_ALLOW_RULES = Object.freeze(["Read", "Grep", "Edit", "Write"]);
const DISALLOWED_TOOLS = Object.freeze(["Agent", "web_search", "web_fetch"]);
const DENY_RULES = Object.freeze(["MCPTool(*)", "WebSearch", "WebFetch",
  "Bash(git push*)", "Bash(git remote*)", "Bash(gh pr*)", "Bash(gh release*)", "Bash(npm publish*)",
  "Bash(gcloud*)", "Bash(kubectl*)", "Bash(docker push*)", "Bash(curl*)", "Bash(wget*)", "Bash(Invoke-WebRequest*)",
  "Bash(ssh*)", "Bash(git credential*)", "Bash(rm*)", "Bash(del*)", "Bash(rmdir*)", "Bash(Remove-Item*)", "Bash(*--delete*)"
]);

function digest(value) { return `sha256:${createHash("sha256").update(value).digest("hex")}`; }
function text(value, label) { if (typeof value !== "string" || value.length === 0) throw new TypeError(`${label} must be non-empty text`); return value; }
function positive(value, label) { if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${label} must be a positive safe integer`); return value; }
function utc(clock) { const value = clock(); const date = value instanceof Date ? value : new Date(value); if (Number.isNaN(date.getTime())) throw new TypeError("clock returned an invalid time"); return date.toISOString(); }
function boundedText(value) { if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > MAX_ASSISTANT_BYTES) throw new HeadlessProtocolError(); return value; }
function requiredString(value, label) { if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > 16 * 1024) throw new HeadlessProtocolError(`${label} is invalid`); return value; }
function optionalString(value, label) { if (value === undefined || value === null) return null; return requiredString(value, label); }
function optionalFrameString(value, label, maximumFrameBytes) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > maximumFrameBytes) throw new HeadlessProtocolError(`${label} is invalid`);
  return value;
}
function object(value, label) { if (!value || typeof value !== "object" || Array.isArray(value)) throw new HeadlessProtocolError(`${label} must be an object`); return value; }
function array(value, label) { if (!Array.isArray(value) || value.length > MAX_ARRAY_ENTRIES) throw new HeadlessProtocolError(`${label} must be a bounded array`); return value; }
function safeJson(value, label) { object(value, label); try { if (Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_ASSISTANT_BYTES) throw new Error(); } catch { throw new HeadlessProtocolError(`${label} is too large`); } return value; }
function safeJsonValue(value, label) { try { const encoded = JSON.stringify(value); if (encoded === undefined || Buffer.byteLength(encoded, "utf8") > MAX_ASSISTANT_BYTES) throw new Error(); } catch { throw new HeadlessProtocolError(`${label} is too large`); } return value; }

function ensurePlainDirectory(path, label) {
  const target = resolve(path);
  if (!isAbsolute(path)) throw new HeadlessSessionError(`${label} must be absolute`);
  let current = target;
  for (;;) {
    try {
      const existing = lstatSync(current);
      if (existing.isSymbolicLink() || !existing.isDirectory()) throw new HeadlessSessionError(`${label} has an unsafe ancestor`);
      if (resolve(current, "..") === current) break;
      current = resolve(current, "..");
    } catch (error) {
      if (error?.code === "ENOENT") { const parent = resolve(current, ".."); if (parent === current) break; current = parent; continue; }
      throw error;
    }
  }
  mkdirSync(target, { recursive: true, mode: 0o700 });
  const details = lstatSync(target);
  if (!details.isDirectory() || details.isSymbolicLink()) throw new HeadlessSessionError(`${label} is not a plain directory`);
  return target;
}
function writePromptFile(stateRoot, prompt) {
  if (typeof prompt !== "string" || Buffer.byteLength(prompt, "utf8") > MAX_PROMPT_BYTES) throw new HeadlessSessionError("headless prompt is missing or oversized");
  if (typeof stateRoot !== "string" || !isAbsolute(stateRoot)) throw new HeadlessSessionError("headless state root is required");
  const root = ensurePlainDirectory(stateRoot, "headless state root");
  const directory = ensurePlainDirectory(join(root, "headless-prompts"), "headless prompt directory");
  const path = join(directory, `${randomUUID()}.prompt`);
  let descriptor;
  try {
    descriptor = openSync(path, "wx", 0o600);
    const bytes = Buffer.from(prompt, "utf8");
    writeFileSync(descriptor, bytes);
    try { fsyncSync(descriptor); } catch (error) { if (!["EINVAL", "ENOTSUP", "EISDIR"].includes(error?.code)) throw error; }
    return Object.freeze({ path, promptDigest: digest(bytes), promptPathDigest: digest(path) });
  } catch { try { unlinkSync(path); } catch {} throw new HeadlessSessionError("headless prompt could not be sealed"); }
  finally { if (descriptor !== undefined) closeSync(descriptor); }
}
function cleanupPromptFile(record) { if (!record?.path) return; try { const details = lstatSync(record.path); if (details.isFile() && !details.isSymbolicLink()) unlinkSync(record.path); } catch {} }

/** Deterministic, fail-closed policy for the trusted-local headless adapter. */
export function buildHeadlessPermissionPolicy({ network = "none" } = {}) {
  if (network === "public_read") throw new HeadlessSessionError("public_read is unavailable: Grok CLI cannot enforce official-doc GET destinations");
  if (network !== "none") throw new HeadlessSessionError("unsupported network policy");
  return Object.freeze({ permissionMode: "dontAsk", allowedTools: ALLOWED_TOOLS, disallowedTools: DISALLOWED_TOOLS, denyRules: DENY_RULES, network: "none", networkRead: "denied", mcpRead: "denied" });
}
export function headlessPolicyArgs({ allowedCommands = [], network = "none" } = {}) {
  if (!Array.isArray(allowedCommands)) throw new HeadlessSessionError("approved commands must be an array");
  const policy = buildHeadlessPermissionPolicy({ network });
  let allowRules;
  try { allowRules = [...FIXED_ALLOW_RULES, ...allowedCommands.map((command) => exactCommandRule(command))]; }
  catch (error) { throw new HeadlessSessionError(error?.message ?? "approved command is not exact"); }
  return Object.freeze(["--permission-mode", policy.permissionMode, "--tools", policy.allowedTools.join(","), "--disallowed-tools", policy.disallowedTools.join(","), ...allowRules.flatMap((rule) => ["--allow", rule]), ...policy.denyRules.flatMap((rule) => ["--deny", rule])]);
}
export function artifactOnlyPolicyArgs({ network = "none" } = {}) {
  buildHeadlessPermissionPolicy({ network });
  const removed = [...ALLOWED_TOOLS, ...DISALLOWED_TOOLS];
  const deny = ["Read", "Grep", "Edit", "Write", "Bash(*)", ...DENY_RULES];
  return Object.freeze(["--permission-mode", "dontAsk", "--tools", "", "--disallowed-tools", removed.join(","), ...deny.flatMap((rule) => ["--deny", rule])]);
}
function exactArgument(args, flag, expected) {
  const indexes = args.reduce((all, value, index) => value === flag ? [...all, index] : all, []);
  if (indexes.length !== 1 || args[indexes[0] + 1] !== expected) throw new HeadlessSessionError(`headless launch contract differs at ${flag}`);
}
function launchReceipt(args, model) {
  exactArgument(args, "--agent", HEADLESS_AGENT);
  if (args.filter((value) => value === "--no-plan").length !== 1) throw new HeadlessSessionError("headless launch contract differs at --no-plan");
  exactArgument(args, "--reasoning-effort", HEADLESS_REASONING_EFFORT);
  exactArgument(args, "--max-turns", String(HEADLESS_MAX_TURNS));
  exactArgument(args, "-m", model);
  exactArgument(args, "--tools", ALLOWED_TOOLS.join(","));
  exactArgument(args, "--disallowed-tools", DISALLOWED_TOOLS.join(","));
  return Object.freeze({ model, agent: HEADLESS_AGENT, planMode: "disabled", reasoningEffort: HEADLESS_REASONING_EFFORT, maxTurns: HEADLESS_MAX_TURNS, allowedTools: Object.freeze([...ALLOWED_TOOLS]), disallowedTools: Object.freeze([...DISALLOWED_TOOLS]) });
}

/** Build a shell-free, finite Grok Build headless command. */
export function buildHeadlessLaunchPlan({ attestation, worktree, promptFilePath, nativeSessionId, model = "grok-build", environment = process.env, allowedCommands = [], allowedEnvironment = [], network = "none" } = {}) {
  const profile = getCapabilityProfile(attestation?.profileId);
  if (!attestation?.executable?.path || typeof attestation.executable.path !== "string") throw new HeadlessSessionError("frozen attestation has no executable");
  if (!UUID.test(text(nativeSessionId, "nativeSessionId"))) throw new HeadlessSessionError("native session identifier must be a UUID");
  text(worktree, "worktree"); text(model, "model");
  if (typeof promptFilePath !== "string" || !isAbsolute(promptFilePath)) throw new HeadlessSessionError("headless prompt file path is required");
  if (!Array.isArray(allowedEnvironment) || allowedEnvironment.some((key) => typeof key !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key))) throw new HeadlessSessionError("approved environment keys are invalid");
  const requestedEnvironment = new Set([...FIXED_WINDOWS_ENVIRONMENT_KEYS, ...allowedEnvironment]);
  const env = Object.freeze(Object.fromEntries(profile.environmentKeys.filter((key) => requestedEnvironment.has(key) && typeof environment[key] === "string").map((key) => [key, environment[key]])));
  const base = [
    "--no-auto-update",
    "--agent", HEADLESS_AGENT,
    "--no-plan",
    "--reasoning-effort", HEADLESS_REASONING_EFFORT,
    "--max-turns", String(HEADLESS_MAX_TURNS),
    "--prompt-file", promptFilePath,
    "--cwd", worktree,
    "-m", model,
    "--output-format", "streaming-json",
    ...headlessPolicyArgs({ allowedCommands, network })
  ];
  const sessionArgs = nativeSessionId === attestation.resumeSessionId ? ["--resume", nativeSessionId] : ["--session-id", nativeSessionId];
  const args = Object.freeze([...base, ...sessionArgs]);
  return Object.freeze({ command: attestation.executable.path, args, launchReceipt: launchReceipt(args, model), options: Object.freeze({ cwd: worktree, env, shell: false, stdio: Object.freeze(["ignore", "pipe", "pipe"]), windowsHide: true, detached: process.platform !== "win32" }) });
}

function parseToolCall(frame) { requiredString(frame.toolCallId, "toolCallId"); requiredString(frame.title, "title"); optionalString(frame.kind, "kind"); optionalString(frame.status, "status"); requiredString(frame.toolName, "toolName"); safeJsonValue(frame.rawInput, "rawInput"); array(frame.content, "content"); array(frame.locations, "locations"); }
function parseToolCallUpdate(frame) { requiredString(frame.toolCallId, "toolCallId"); optionalString(frame.status, "status"); array(frame.content, "content"); array(frame.locations, "locations"); if (frame.rawOutput !== undefined) safeJsonValue(frame.rawOutput, "rawOutput"); }
function parseFrame(line, maximumFrameBytes, expectedSessionId) {
  if (Buffer.byteLength(line, "utf8") === 0 || Buffer.byteLength(line, "utf8") > maximumFrameBytes) throw new HeadlessProtocolError();
  let frame; try { frame = JSON.parse(line); } catch { throw new HeadlessProtocolError(); }
  if (!frame || typeof frame !== "object" || Array.isArray(frame) || typeof frame.type !== "string") throw new HeadlessProtocolError();
  const type = frame.type;
  if (!KNOWN_TYPES.has(type) && !type.startsWith("auto_compact_")) {
    if (frame.critical === true) throw new HeadlessProtocolError();
    if (frame.sessionId !== undefined && (typeof frame.sessionId !== "string" || frame.sessionId !== expectedSessionId)) throw new HeadlessProtocolError();
    safeJson(frame, "extension frame");
    return Object.freeze({ ignored: true }); // forward-compatible, noncritical extension frame
  }
  if (type === "error") { requiredString(frame.message, "error message"); throw new HeadlessCliError("headless CLI reported a terminal error"); }
  if (type === "text" || type === "thought") return Object.freeze({ type, text: boundedText(frame.data), progress: type === "thought" });
  if (type === "tool_call") { parseToolCall(frame); return Object.freeze({ type, progress: true, data: frame }); }
  if (type === "tool_call_update") { parseToolCallUpdate(frame); return Object.freeze({ type, progress: true, data: frame }); }
  if (type === "usage") { optionalString(frame.messageId, "usage messageId"); optionalString(frame.stopReason, "usage stopReason"); if (frame.usage !== undefined && frame.usage !== null) safeJson(frame.usage, "usage"); optionalFrameString(frame.signature, "usage signature", maximumFrameBytes); return Object.freeze({ type, progress: true, data: frame }); }
  if (type === "plan") { array(frame.entries, "plan entries"); return Object.freeze({ type, progress: true, data: frame }); }
  if (type === "available_commands") { array(frame.tools, "available tools"); array(frame.commands, "available commands"); return Object.freeze({ type, progress: true, data: frame }); }
  if (type === "max_turns_reached" || type.startsWith("auto_compact_")) return Object.freeze({ type, progress: true, data: frame });
  if (type === "end") {
    requiredString(frame.stopReason, "end stopReason"); requiredString(frame.sessionId, "end sessionId"); requiredString(frame.requestId, "end requestId");
    if (frame.sessionId !== expectedSessionId) throw new HeadlessProtocolError();
    if (frame.usage !== undefined) safeJson(frame.usage, "end usage");
    if (frame.num_turns !== undefined && !Number.isSafeInteger(frame.num_turns)) throw new HeadlessProtocolError();
    if (frame.modelUsage !== undefined) safeJson(frame.modelUsage, "modelUsage");
    return Object.freeze({ type, terminal: true, progress: true, data: frame });
  }
  throw new HeadlessProtocolError();
}

function defaultKillTree(child) { try { if (process.platform !== "win32" && Number.isSafeInteger(child.pid) && child.pid > 1) process.kill(-child.pid, "SIGTERM"); else child.kill(); } catch { try { child.kill(); } catch {} } }
function makeChildStop(child, killTree) { let stopped = false; return () => { if (stopped) return; stopped = true; try { killTree(child); } catch { try { child.kill(); } catch {} } }; }

export function createHeadlessSessionAdapter({ spawnImpl = spawn, killTree = defaultKillTree, inspectChild = null, verifyCustody, verifyFence, onSessionBound = async () => {}, onProcessStarted = async () => {}, onPromptDispatch = async () => {}, onEvent = async () => {}, onFailure = async () => {}, beforeCancel = async () => {}, onCancelAcknowledged = async () => {}, environment = process.env, clock = () => new Date(), timers = globalThis } = {}) {
  const active = new Map();
  async function start(input) {
    const jobId = text(input.jobId, "jobId"), attemptId = text(input.attemptId, "attemptId"), requestId = text(input.requestId, "requestId"); positive(input.fencingToken, "fencingToken");
    if (active.has(jobId)) throw new HeadlessSessionError("job already has a finite headless process");
    verifyProfileDrift(input.attestation, input.inspection, { environment });
    const profile = getCapabilityProfile(input.attestation.profileId), limits = profile.limits;
    const nativeSessionId = input.nativeSessionId === null || input.nativeSessionId === undefined ? randomUUID() : text(input.nativeSessionId, "nativeSessionId");
    if (!UUID.test(nativeSessionId)) throw new HeadlessSessionError("native session identifier must be a UUID");
    const expected = () => ({ jobId, attemptId, requestId, fencingToken: input.fencingToken, nativeSessionId });
    const guard = async () => { if (typeof verifyCustody !== "function" || await verifyCustody(input) !== true) throw new HeadlessRecoveryRequiredError("worktree custody is unavailable"); if (typeof verifyFence !== "function" || await verifyFence(expected()) !== true) throw new HeadlessRecoveryRequiredError("current execution fence is unavailable"); };
    const emit = async (kind, value) => { await guard(); const redacted = redactForBoundary(value); if (Buffer.byteLength(JSON.stringify(redacted), "utf8") > limits.maximumEventBytes) throw new HeadlessProtocolError(); await onEvent({ ...expected(), kind, value: redacted }); };
    let promptFile = null; let child = null, cancellation = false, failed = false, stderrBytes = 0, stderrTail = Buffer.alloc(0), stdout = Buffer.alloc(0), streamBytes = 0, providerRequestId = null, assistant = "", assistantBytes = 0, pendingAssistantText = "", thoughtReported = false, sawStreamEnd = false, terminalFrame = null, streamWork = Promise.resolve();
    let initializationTimer = null, idleTimer = null, overallTimer = null, pendingTimeout = null;
    const sessionBinding = { ...expected(), childProcessIdentity: null };
    await guard(); await onSessionBound(sessionBinding);
    promptFile = writePromptFile(input.stateRoot, input.prompt);
    let plan, argvDigest, effectiveLaunch;
    try {
      plan = buildHeadlessLaunchPlan({ attestation: { ...input.attestation, resumeSessionId: input.nativeSessionId ?? null }, worktree: input.worktree, promptFilePath: promptFile.path, nativeSessionId, model: input.model ?? "grok-build", environment });
      effectiveLaunch = plan.launchReceipt;
      argvDigest = digest(JSON.stringify([plan.command, ...plan.args]));
      await onPromptDispatch({ ...expected(), ambiguity: "headless_spawn_is_prompt_boundary", adapterVersion: HEADLESS_ADAPTER_VERSION, argvDigest, promptDigest: promptFile.promptDigest, promptPathDigest: promptFile.promptPathDigest, effectiveLaunch });
    } catch (error) { cleanupPromptFile(promptFile); throw error; }
    try { child = spawnImpl(plan.command, plan.args, plan.options); } catch { cleanupPromptFile(promptFile); const safe = new HeadlessSessionError("headless CLI could not start"); safe.safeStage = "adapter_child_spawn"; throw safe; }
    if (!child || typeof child.once !== "function" || !child.stdout?.on || !child.stderr?.on || !Number.isSafeInteger(child.pid) || child.pid < 1) { try { child?.kill?.(); } catch {} cleanupPromptFile(promptFile); const safe = new HeadlessSessionError("headless CLI child identity is unavailable"); safe.safeStage = "adapter_child_identity"; throw safe; }
    const stop = makeChildStop(child, killTree), childIdentity = { pid: child.pid, startedAt: utc(clock) }; active.set(jobId, { child, stop, nativeSessionId });
    const schedule = (milliseconds, callback) => { const timer = timers.setTimeout(callback, milliseconds); timer?.unref?.(); return timer; };
    const expireBeforeReady = (message, failureKind) => { const error = new HeadlessRecoveryRequiredError(message); if (typeof failHandler === "function") void failHandler(error, failureKind); else { pendingTimeout = { error, failureKind }; stop(); cleanupPromptFile(promptFile); } };
    initializationTimer = schedule(limits.initializationTimeoutMs, () => expireBeforeReady("headless CLI did not emit an initial frame", "headless_initialization_timeout"));
    overallTimer = schedule(limits.overallTimeoutMs, () => expireBeforeReady("headless CLI exceeded its overall timeout", "headless_overall_timeout"));
    try { await onProcessStarted({ ...expected(), childProcessIdentity: childIdentity, effectiveLaunch }); if (profile.enforcementClass !== "os_enforced") { if (typeof inspectChild !== "function") throw new HeadlessRecoveryRequiredError("launched child authority parity is unavailable"); verifyChildAuthorityParity(input.attestation, await inspectChild({ ...input, child }), { environment }); } await emit("headless_process_started", { adapterVersion: HEADLESS_ADAPTER_VERSION, argvDigest, promptPathDigest: promptFile.promptPathDigest, pid: childIdentity.pid, startedAt: childIdentity.startedAt, effectiveLaunch }); } catch (error) { stop(); cleanupPromptFile(promptFile); throw error; }
    let cancelTimer = null;
    let failHandler = null;
    const done = new Promise((resolveDone, rejectDone) => {
      const clearTimer = (timer) => { if (timer !== null) timers.clearTimeout?.(timer); };
      const clearAllTimers = () => { clearTimer(initializationTimer); clearTimer(idleTimer); clearTimer(overallTimer); clearTimer(cancelTimer); initializationTimer = null; idleTimer = null; overallTimer = null; cancelTimer = null; };
      const expire = (message, failureKind) => { if (typeof failHandler === "function") void failHandler(new HeadlessRecoveryRequiredError(message), failureKind); };
      const armIdleTimer = () => { clearTimer(idleTimer); idleTimer = schedule(limits.idleTimeoutMs, () => expire("headless CLI exceeded its idle timeout", "headless_idle_timeout")); };
      const markFirstFrame = () => { if (initializationTimer !== null) { clearTimer(initializationTimer); initializationTimer = null; } };
      const fail = async (error, failureKind = "headless_failure") => {
        if (failed) return;
        failed = true;
        clearAllTimers();
        stop();
        cleanupPromptFile(promptFile);
        try {
          await onFailure({ ...expected(), error: error instanceof HeadlessSessionError ? error.message : "headless CLI failed safely", recoveryRequired: true, failureKind, diagnostics: { adapterVersion: HEADLESS_ADAPTER_VERSION, argvDigest, promptPathDigest: promptFile.promptPathDigest, stderrBytes, stderrDigest: digest(stderrTail), stderrTail: redactForBoundary(stderrTail.toString("utf8")), ...(error?.frameDiagnostics ?? {}) } });
        } catch {}
        rejectDone(error instanceof HeadlessSessionError ? error : new HeadlessRecoveryRequiredError());
      };
      failHandler = fail;
      if (pendingTimeout !== null) { const timeout = pendingTimeout; pendingTimeout = null; void fail(timeout.error, timeout.failureKind); }
      const flushAssistantText = async () => {
        // Grok emits token-sized text frames. Persisting each token as a
        // durable job event can exceed the profile's event-rate ceiling even
        // though the provider turn itself is healthy. Coalesce text into
        // bounded UTF-16 chunks; 16K code units are at most 64 KiB in UTF-8,
        // safely below the 128 KiB event boundary.
        while (pendingAssistantText.length > 0) {
          let cut = Math.min(16_384, pendingAssistantText.length);
          if (cut < pendingAssistantText.length && /[\uD800-\uDBFF]/.test(pendingAssistantText[cut - 1])) cut -= 1;
          const chunk = pendingAssistantText.slice(0, cut);
          pendingAssistantText = pendingAssistantText.slice(cut);
          await emit("text", { text: chunk });
        }
      };
      const processStdoutChunk = async (chunk) => {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        stdout = Buffer.concat([stdout, bytes]);
        for (;;) {
          const newline = stdout.indexOf(0x0a);
          if (newline < 0) break;
          const line = stdout.subarray(0, newline).toString("utf8").replace(/\r$/, "");
          stdout = stdout.subarray(newline + 1);
          if (!line.trim()) continue;
          let frame;
          try { frame = parseFrame(line, limits.maximumFrameBytes, nativeSessionId); }
          catch (error) { if (error && typeof error === "object" && error.frameDiagnostics === undefined) error.frameDiagnostics = frameDiagnostics(line); throw error; }
          markFirstFrame();
          const frameRequestId = frame.data?.requestId;
          if (frameRequestId !== undefined) {
            if (typeof frameRequestId !== "string" || (providerRequestId !== null && providerRequestId !== frameRequestId)) throw new HeadlessProtocolError("headless stream request correlation changed");
            providerRequestId ??= frameRequestId;
          }
          if (frame.ignored) { if (terminalFrame !== null) throw new HeadlessProtocolError(); continue; }
          if (frame.terminal) { if (terminalFrame !== null) throw new HeadlessProtocolError(); terminalFrame = frame.data; }
          else if (terminalFrame !== null) throw new HeadlessProtocolError();
          if (frame.text !== undefined) {
            if (frame.progress) {
              // Reasoning is not candidate output. One bounded progress marker
              // per response is enough for observability without journaling
              // private token-by-token thought text.
              if (!thoughtReported) { await emit("progress", { type: frame.type }); thoughtReported = true; }
            } else {
              assistant += frame.text;
              pendingAssistantText += frame.text;
              assistantBytes += Buffer.byteLength(frame.text, "utf8");
              if (assistantBytes > MAX_ASSISTANT_BYTES) throw new HeadlessProtocolError();
              if (pendingAssistantText.length >= 16_384) await flushAssistantText();
            }
          } else if (frame.progress) {
            await flushAssistantText();
            if (frame.type === "usage") thoughtReported = false;
            await emit("progress", { type: frame.type });
          }
        }
        if (stdout.byteLength > limits.maximumFrameBytes) throw new HeadlessProtocolError();
      };
      const handleStdout = (chunk) => {
        armIdleTimer();
        streamWork = streamWork.then(() => processStdoutChunk(chunk)).catch((error) => void fail(error, error instanceof HeadlessCliError ? "headless_cli_error" : "headless_stream_invalid"));
      };
      const handleStderr = (chunk) => {
        armIdleTimer();
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        stderrBytes += bytes.byteLength;
        stderrTail = Buffer.concat([stderrTail, bytes]);
        if (stderrTail.byteLength > MAX_STDERR_TAIL_BYTES) stderrTail = stderrTail.subarray(stderrTail.byteLength - MAX_STDERR_TAIL_BYTES);
      };
      const handleClose = (code, signal) => {
        streamWork.then(async () => {
          clearAllTimers();
          cleanupPromptFile(promptFile);
          if (failed) return;
          const diagnostics = { adapterVersion: HEADLESS_ADAPTER_VERSION, argvDigest, promptPathDigest: promptFile.promptPathDigest, pid: childIdentity.pid, startedAt: childIdentity.startedAt, exitedAt: utc(clock), exitCode: code, signal: signal ?? null, stderrBytes, stderrDigest: digest(stderrTail), stderrTail: redactForBoundary(stderrTail.toString("utf8")) };
          if (cancellation) { await onCancelAcknowledged({ ...expected(), diagnostics }); failed = true; resolveDone({ state: "cancelled", diagnostics }); return; }
          if (stdout.byteLength !== 0 || !sawStreamEnd || code !== 0 || terminalFrame === null || terminalFrame.stopReason !== TERMINAL_STOP_REASON) throw new HeadlessRecoveryRequiredError("headless CLI exited without clean bounded terminal evidence");
          await flushAssistantText();
          const assistantOutputDigest = digest(assistant);
          const terminalEvidenceDigest = digest(JSON.stringify({ ...expected(), assistantOutputDigest, terminalFrame, diagnostics }));
          await emit("terminal", { assistantOutputDigest, terminalEvidenceDigest, diagnostics });
          failed = true;
          resolveDone({ state: "candidate_ready", assistantOutputDigest, terminalEvidenceDigest, diagnostics });
        }).catch((error) => void fail(error, "headless_terminal_invalid"));
      };
      const boundedStdout = (chunk) => { streamBytes += Buffer.byteLength(chunk); if (streamBytes > MAX_STREAM_BYTES) { void fail(new HeadlessProtocolError("headless stream exceeded its bounded byte limit"), "headless_stream_overflow"); return; } handleStdout(chunk); };
      child.stdout.on("data", boundedStdout);
      child.stdout.once("end", () => { sawStreamEnd = true; });
      child.stderr.on("data", handleStderr);
      child.once("error", () => void fail(new HeadlessRecoveryRequiredError("headless CLI process was lost"), "headless_child_lost"));
      child.once("close", handleClose);
    }).finally(() => { cleanupPromptFile(promptFile); active.delete(jobId); });
    return Object.freeze({ child: { stop, identity: childIdentity }, done, cancel: async () => { if (cancellation) return true; await guard(); await beforeCancel(expected()); cancellation = true; cancelTimer = timers.setTimeout(() => failHandler?.(new HeadlessRecoveryRequiredError("headless CLI did not acknowledge cancellation"), "headless_cancellation_timeout"), limits.cancellationTimeoutMs); cancelTimer?.unref?.(); stop(); return true; } });
  }
  return Object.freeze({ start, activeCount: () => active.size, get: (jobId) => active.get(jobId) ?? null });
}
