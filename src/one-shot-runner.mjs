import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { spawnSync } from "node:child_process";
import { closeSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { StringDecoder } from "node:string_decoder";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { TASK_DELIVERY, validateAcceptanceDecision, validateRepairFindings, validateRunReceipt, validateTaskPacket } from "./contracts.mjs";
import { redactForBoundary } from "./redaction.mjs";
import { assertApprovedPacket } from "./authority-safety.mjs";
import { createTaskPolicy, packetDigest, scopedEnvironment, validateChangedFiles } from "./task-policy.mjs";
import { artifactOnlyPolicyArgs } from "./headless-session.mjs";
import { beginArtifactTransaction, buildArtifactPrompt, executeArtifact, parseArtifactOutput, persistArtifactDecision, persistArtifactEvidence, persistRejectedArtifactEvidence, prepareArtifactScratch, removeArtifactScratch } from "./artifact-delivery.mjs";
import { providerErrorFromFrame, receiptExtrasFromFrameError } from "./stream-frames.mjs";
import { createOneShotWorktree } from "./worktree-custody.mjs";

export const ONE_SHOT_RUNNER_VERSION = "agent-platform.grok-build-engineer-one-shot.v1";
const REPAIR_CONSUMPTION_VERSION = "agent-platform.grok-build-engineer-repair-consumption.v1";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_STDOUT_FRAME_BYTES = 4 * 1024 * 1024;
const MAX_STDOUT_STREAM_BYTES = 16 * 1024 * 1024;
const MAX_ARTIFACT_OUTPUT_BYTES = 4 * 1024 * 1024;
const TASK_RUN_ID = /^[a-z][a-z0-9_-]{2,63}$/;
export class RunnerRecoveryRequiredError extends Error { constructor(message = "Runner state requires recovery") { super(message); this.name = "RunnerRecoveryRequiredError"; this.code = "recovery_required"; } }
export class RunnerCancellationUnsupportedError extends Error { constructor(message = "separate-process cancellation is unsupported") { super(message); this.name = "RunnerCancellationUnsupportedError"; this.code = "unsupported"; } }
function digest(value) { return `sha256:${createHash("sha256").update(value).digest("hex")}`; }
export function receiptDigest(value) { return digest(JSON.stringify(value)); }
function now(clock) { const value = clock(); const date = value instanceof Date ? value : new Date(value); if (Number.isNaN(date.getTime())) throw new TypeError("clock returned an invalid time"); return date.toISOString(); }
function safeStateRoot(root) { const target = resolve(root); mkdirSync(target, { recursive: true, mode: 0o700 }); mkdirSync(join(target, "runs"), { recursive: true, mode: 0o700 }); mkdirSync(join(target, "attempts"), { recursive: true, mode: 0o700 }); mkdirSync(join(target, "acceptance"), { recursive: true, mode: 0o700 }); mkdirSync(join(target, "repair-consumptions"), { recursive: true, mode: 0o700 }); return target; }
function validTaskRunId(value) { if (typeof value !== "string" || !TASK_RUN_ID.test(value)) throw new TypeError("taskRunId is invalid"); return value; }
function writeJson(path, value) { const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`; writeFileSync(temporary, `${JSON.stringify(value)}\n`, "utf8"); renameSync(temporary, path); }
function persist(root, taskRunId, receipt) { const base = safeStateRoot(root); writeJson(join(base, "runs", `${taskRunId}.json`), receipt); return receipt; }
function attemptPath(root, taskRunId, requestId) { validTaskRunId(taskRunId); if (typeof requestId !== "string" || !/^[a-z][a-z0-9_-]{2,63}$/.test(requestId)) throw new TypeError("requestId is invalid"); const directory = join(safeStateRoot(root), "attempts", taskRunId); mkdirSync(directory, { recursive: true, mode: 0o700 }); return join(directory, `${requestId}.json`); }
export function receiptPath(stateRoot, taskRunId) { validTaskRunId(taskRunId); return join(resolve(stateRoot), "runs", `${taskRunId}.json`); }
function claimPath(stateRoot, taskRunId) { validTaskRunId(taskRunId); return join(safeStateRoot(stateRoot), "runs", `${taskRunId}.lock`); }
function repairKey(priorReceiptDigest) { if (typeof priorReceiptDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(priorReceiptDigest)) throw new TypeError("prior receipt digest is invalid"); return priorReceiptDigest.slice(7); }
function repairClaimPath(stateRoot, priorReceiptDigest) { return join(resolve(stateRoot), "runs", `repair-${repairKey(priorReceiptDigest)}.lock`); }
function repairConsumptionPath(stateRoot, priorReceiptDigest) { return join(resolve(stateRoot), "repair-consumptions", `${repairKey(priorReceiptDigest)}.json`); }
function readRecord(path) { try { return JSON.parse(readFileSync(path, "utf8")); } catch { throw new RunnerRecoveryRequiredError("persisted runner state is corrupt or incomplete"); } }
function validateRunningRecord(value, taskRunId) { if (!value || typeof value !== "object" || value.contractVersion !== ONE_SHOT_RUNNER_VERSION || value.taskRunId !== taskRunId || typeof value.requestId !== "string" || !["starting", "running"].includes(value.state) || typeof value.ownerNonce !== "string" || !UUID.test(value.sessionId) || !value.binding || typeof value.binding.sourceSha !== "string" || typeof value.binding.repositoryRoot !== "string" || typeof value.binding.worktree !== "string" || typeof value.binding.custodyDigest !== "string" || typeof value.binding.diffDigest !== "string" || (value.state === "running" && (!Number.isSafeInteger(value.pid) || value.pid < 2)) || (value.state === "starting" && value.pid !== null && value.pid !== undefined)) throw new RunnerRecoveryRequiredError("persisted running state is corrupt or incomplete"); return value; }
function claimTask(stateRoot, taskRunId, ownerNonce) { const path = claimPath(stateRoot, taskRunId); try { const fd = openSync(path, "wx", 0o600); try { writeFileSync(fd, `${JSON.stringify({ taskRunId, ownerNonce, pid: process.pid })}\n`, "utf8"); } finally { closeSync(fd); } } catch (error) { if (error?.code === "EEXIST") throw new RunnerRecoveryRequiredError("task run is already claimed by another process"); throw error; } return path; }
function claimRepair(stateRoot, priorReceiptDigest, ownerNonce, priorSessionId) { const root = safeStateRoot(stateRoot); const path = repairClaimPath(root, priorReceiptDigest); const consumption = repairConsumptionPath(root, priorReceiptDigest); if (existsSync(consumption)) throw new RunnerRecoveryRequiredError("repair budget for this candidate has already been consumed"); try { const fd = openSync(path, "wx", 0o600); try { writeFileSync(fd, `${JSON.stringify({ priorReceiptDigest, ownerNonce, priorSessionId, claimedAt: new Date().toISOString() })}\n`, "utf8"); } finally { closeSync(fd); } if (existsSync(consumption)) { releaseRepair(root, priorReceiptDigest, ownerNonce); throw new RunnerRecoveryRequiredError("repair budget for this candidate has already been consumed"); } } catch (error) { if (error?.code === "EEXIST") throw new RunnerRecoveryRequiredError("repair budget for this candidate has already been consumed"); throw error; } return path; }
function releaseTask(stateRoot, taskRunId, ownerNonce) { const path = claimPath(stateRoot, taskRunId); if (!existsSync(path)) return; try { const record = readRecord(path); if (record.ownerNonce === ownerNonce) unlinkSync(path); } catch { /* preserve corrupt evidence for recovery */ } }
function releaseRepair(stateRoot, priorReceiptDigest, ownerNonce) { const path = repairClaimPath(stateRoot, priorReceiptDigest); if (!existsSync(path)) return; try { const record = readRecord(path); if (record.ownerNonce === ownerNonce) unlinkSync(path); } catch { /* preserve corrupt evidence for recovery */ } }
function persistRepairConsumption(stateRoot, priorReceiptDigest, ownerNonce, receipt) { const claim = repairClaimPath(stateRoot, priorReceiptDigest); if (!existsSync(claim)) throw new RunnerRecoveryRequiredError("active repair claim is missing before consumption persistence"); const claimRecord = readRecord(claim); if (claimRecord.ownerNonce !== ownerNonce) throw new RunnerRecoveryRequiredError("repair consumption persistence lost claim ownership"); const path = repairConsumptionPath(stateRoot, priorReceiptDigest); const record = { contractVersion: REPAIR_CONSUMPTION_VERSION, priorReceiptDigest, taskRunId: receipt.taskRunId, requestId: receipt.requestId, sessionId: claimRecord.priorSessionId, repairReceiptDigest: receiptDigest(receipt), consumedAt: receipt.finishedAt }; if (existsSync(path)) { const prior = readRecord(path); if (receiptDigest(prior) !== receiptDigest(record)) throw new RunnerRecoveryRequiredError("immutable repair consumption evidence conflicts with an existing record"); } else writeJson(path, record); try { unlinkSync(claim); } catch (error) { throw new RunnerRecoveryRequiredError(`repair consumption persisted but active claim cleanup failed: ${safeMessage(error)}`); } return record; }
function persistOwned(root, taskRunId, ownerNonce, receipt) { const path = receiptPath(root, taskRunId); if (existsSync(path)) { const current = readRecord(path); if (current.state === "cancelled") return current; if (current.ownerNonce !== ownerNonce) throw new RunnerRecoveryRequiredError("terminal persistence lost task ownership"); } if (receipt.state !== "running") { const immutable = attemptPath(root, taskRunId, receipt.requestId); if (existsSync(immutable)) { const prior = readRecord(immutable); if (receiptDigest(prior) !== receiptDigest(receipt)) throw new RunnerRecoveryRequiredError("immutable attempt evidence conflicts with an existing receipt"); } else writeJson(immutable, receipt); } return persist(root, taskRunId, receipt); }
export function readRunReceipt(stateRoot, taskRunId) { const path = receiptPath(stateRoot, taskRunId); if (!existsSync(path)) return null; const value = readRecord(path); if (value.state === "starting" || value.state === "running") return validateRunningRecord(value, taskRunId); validateRunReceipt(value); return value; }
export function persistAcceptanceDecision(stateRoot, decision, receipt, { verifyCustodyImpl = verifyCustody } = {}) { validateAcceptanceDecision(decision); validateRunReceipt(receipt); if (decision.taskRunId !== receipt.taskRunId || decision.requestId !== receipt.requestId) throw new TypeError("acceptance decision does not match receipt identity"); if (decision.receiptDigest !== receiptDigest(receipt) || decision.custodyDigest !== receipt.binding.custodyDigest) throw new TypeError("acceptance decision is not bound to the receipt custody"); if (receipt.state !== "candidate") throw new TypeError("only candidate receipts can be collected"); const currentCustody = verifyCustodyImpl({ repositoryRoot: receipt.binding.repositoryRoot, worktree: receipt.binding.worktree, sourceSha: receipt.binding.sourceSha, stateRoot }, { allowDirty: true }); if (currentCustody.custodyDigest !== receipt.binding.custodyDigest || currentCustody.diffDigest !== receipt.binding.diffDigest) throw new TypeError("candidate custody changed since validation"); const path = join(safeStateRoot(stateRoot), "acceptance", `${decision.taskRunId}-${decision.idempotencyKey}.json`); if (existsSync(path)) { const prior = readRecord(path); if (receiptDigest(prior) !== receiptDigest(decision)) throw new RunnerRecoveryRequiredError("acceptance idempotency key conflicts with existing evidence"); return prior; } writeJson(path, decision); return decision; }
export function cancelRun(stateRoot, taskRunId) { validTaskRunId(taskRunId); const path = receiptPath(stateRoot, taskRunId); if (!existsSync(path)) throw new RunnerRecoveryRequiredError("no persisted task run exists"); validateRunningRecord(readRecord(path), taskRunId); throw new RunnerCancellationUnsupportedError(); }
function allowedScope(packet, policy) {
  return { worktree: resolve(packet.worktree), paths: [...policy.paths], commands: [...policy.commands], network: policy.network, tools: [...policy.tools], environment: [...policy.environment] };
}
export function artifactOnlyGrokHomePath({ stateRoot, taskRunId, requestId }) {
  validTaskRunId(taskRunId);
  if (typeof requestId !== "string" || !/^[a-z][a-z0-9_-]{2,63}$/.test(requestId)) throw new TypeError("requestId is invalid");
  if (typeof stateRoot !== "string" || !isAbsolute(stateRoot)) throw new TypeError("stateRoot must be absolute");
  return join(resolve(stateRoot), "provider-homes", taskRunId, requestId);
}
export function isolateArtifactOnlyLaunchEnvironment(sourceEnv, { grokHome }) {
  if (typeof grokHome !== "string" || !isAbsolute(grokHome)) throw new TypeError("isolated GROK_HOME must be absolute");
  const env = { ...(sourceEnv ?? {}) };
  // scopedEnvironment copies operator HOME/USERPROFILE/GROK_HOME/LOCALAPPDATA.
  // Empty --tools, --deny MCPTool(*), and [compat.codex] mcps=false do not stop
  // Grok from treating those values as its config root or merging Claude plugins.
  // Always replace the profile roots; do not leave the operator USERPROFILE in place.
  env.GROK_HOME = grokHome;
  env.HOME = grokHome;
  env.USERPROFILE = grokHome;
  env.LOCALAPPDATA = grokHome;
  env.APPDATA = grokHome;
  return Object.freeze(env);
}
export function artifactOnlyDebugFilePath({ stateRoot, taskRunId, requestId }) {
  validTaskRunId(taskRunId);
  if (typeof requestId !== "string" || !/^[a-z][a-z0-9_-]{2,63}$/.test(requestId)) throw new TypeError("requestId is invalid");
  if (typeof stateRoot !== "string" || !isAbsolute(stateRoot)) throw new TypeError("stateRoot must be absolute");
  return join(resolve(stateRoot), "provider-debug", taskRunId, `${requestId}.log`);
}
export function providerErrorFramePath({ stateRoot, taskRunId, requestId }) {
  validTaskRunId(taskRunId);
  if (typeof requestId !== "string" || !/^[a-z][a-z0-9_-]{2,63}$/.test(requestId)) throw new TypeError("requestId is invalid");
  if (typeof stateRoot !== "string" || !isAbsolute(stateRoot)) throw new TypeError("stateRoot must be absolute");
  return join(resolve(stateRoot), "provider-frames", taskRunId, `${requestId}.error.json`);
}
function prepareArtifactOnlyGrokHome(grokHome) {
  mkdirSync(grokHome, { recursive: true, mode: 0o700 });
  return grokHome;
}
function persistProviderErrorFrame({ stateRoot, taskRunId, requestId, line, diagnostics }) {
  if (!diagnostics || typeof diagnostics !== "object" || typeof diagnostics.protocolFrameDigest !== "string") return null;
  const path = providerErrorFramePath({ stateRoot, taskRunId, requestId });
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  let frame = null;
  try { frame = JSON.parse(typeof line === "string" ? line : ""); } catch { frame = null; }
  const redacted = frame && typeof frame === "object" && !Array.isArray(frame) ? redactForBoundary(frame) : null;
  const record = {
    contractVersion: "agent-platform.grok-build-engineer-provider-frame.v1",
    taskRunId,
    requestId,
    frameDigest: diagnostics.protocolFrameDigest,
    protocolFrameType: typeof diagnostics.protocolFrameType === "string" ? diagnostics.protocolFrameType : "error",
    protocolFrameKeys: Array.isArray(diagnostics.protocolFrameKeys) ? diagnostics.protocolFrameKeys.filter((key) => typeof key === "string").slice(0, 64) : [],
    protocolErrorMessage: typeof diagnostics.protocolErrorMessage === "string" ? diagnostics.protocolErrorMessage.slice(0, 1024) : null,
    ...(typeof diagnostics.category === "string" ? { category: diagnostics.category } : {}),
    ...(diagnostics.status !== undefined && diagnostics.status !== null ? { status: diagnostics.status } : {}),
    frame: redacted
  };
  if (Buffer.byteLength(JSON.stringify(record), "utf8") > 16_384) record.frame = null;
  if (existsSync(path)) {
    try {
      const prior = JSON.parse(readFileSync(path, "utf8"));
      if (digest(JSON.stringify(prior)) !== digest(JSON.stringify(record))) throw new RunnerRecoveryRequiredError("provider error-frame evidence conflicts with an existing record");
      return prior;
    } catch (error) {
      if (error instanceof RunnerRecoveryRequiredError) throw error;
      throw new RunnerRecoveryRequiredError("persisted provider error-frame evidence is corrupt or incomplete");
    }
  }
  writeJson(path, record);
  return record;
}
function buildLaunchFromPolicy({ packet, policy, promptFilePath, providerCwd, sessionId, resume = false, environment = process.env }) {
  if (!UUID.test(sessionId)) throw new TypeError("sessionId must be a UUID");
  const pathKey = (value) => (process.platform === "win32" ? resolve(value).toLowerCase() : resolve(value));
  const expectedCwd = join(resolve(packet.stateRoot), "provider-scratch", packet.taskRunId, packet.requestId);
  if (policy.delivery !== TASK_DELIVERY.ARTIFACT_ONLY || typeof providerCwd !== "string" || !isAbsolute(providerCwd) || pathKey(providerCwd) !== pathKey(expectedCwd)) throw new TypeError("exact artifact-only provider scratch workspace is required");
  const grokHome = artifactOnlyGrokHomePath({ stateRoot: packet.stateRoot, taskRunId: packet.taskRunId, requestId: packet.requestId });
  const debugFile = artifactOnlyDebugFilePath({ stateRoot: packet.stateRoot, taskRunId: packet.taskRunId, requestId: packet.requestId });
  if (pathKey(grokHome) === pathKey(expectedCwd) || pathKey(grokHome) === pathKey(providerCwd)) throw new TypeError("isolated Grok home must be distinct from the provider scratch workspace");
  if (pathKey(debugFile) === pathKey(expectedCwd) || pathKey(dirname(debugFile)) === pathKey(expectedCwd)) throw new TypeError("debug file must be distinct from the provider scratch workspace");
  const policyArgs = [...artifactOnlyPolicyArgs({ network: policy.network })];
  const args = ["--no-auto-update", "--no-subagents", "--disable-web-search", "--agent", "general-purpose", "--no-plan", "--reasoning-effort", "high", "--max-turns", "24", "--prompt-file", promptFilePath, "--cwd", providerCwd, "-m", packet.provider.model, "--output-format", "streaming-json", "--debug-file", debugFile, ...policyArgs, ...(resume ? ["--resume", sessionId] : ["--session-id", sessionId])];
  const env = isolateArtifactOnlyLaunchEnvironment(scopedEnvironment(policy, environment), { grokHome });
  return Object.freeze({ command: packet.provider.executable, args: Object.freeze(args), cwd: providerCwd, env, grokHome, debugFile, model: packet.provider.model, sessionId, resume, delivery: TASK_DELIVERY.ARTIFACT_ONLY });
}
export function buildOneShotLaunch({ packet, promptFilePath, providerCwd, sessionId, resume = false, environment = process.env }) {
  validateTaskPacket(packet);
  return buildLaunchFromPolicy({ packet, policy: createTaskPolicy(packet), promptFilePath, providerCwd, sessionId, resume, environment });
}
function defaultKillTree(child) { const pid = child?.pid; if (!Number.isSafeInteger(pid) || pid < 2) throw new RunnerRecoveryRequiredError("child identity is unavailable for safe termination"); if (process.platform === "win32") { const result = spawnSync("taskkill.exe", ["/PID", String(pid), "/T", "/F"], { shell: false, windowsHide: true, encoding: "utf8", timeout: 10_000 }); if (result.status !== 0 && result.status !== 128) throw new RunnerRecoveryRequiredError("Windows process-tree termination was not acknowledged"); return; } try { process.kill(-pid, "SIGTERM"); } catch (error) { if (error?.code !== "ESRCH") throw error; } }
function promptFile(root, prompt) { const directory = join(safeStateRoot(root), "prompts"); mkdirSync(directory, { recursive: true, mode: 0o700 }); const path = join(directory, `${randomUUID()}.txt`); const fd = openSync(path, "wx", 0o600); try { writeFileSync(fd, prompt, "utf8"); } finally { closeSync(fd); } return path; }
function failCode(error) { const code = error?.code; return typeof code === "string" && /^[a-z][a-z0-9_-]{0,63}$/.test(code) ? code : "runner_failure"; }
function boundedStreamError() { const error = new Error("stdout_frame_limit"); error.code = "stdout_frame_limit"; return error; }
function safeMessage(error) { return redactForBoundary(String(error?.message ?? error ?? "runner failed safely")).slice(0, 512); }
export function verifyCustody(packet, { allowDirty = false, expectedDiffDigest = null } = {}) {
  const { worktree, repositoryRoot, stateRoot } = custodyPaths(packet);
  const pathKey = (value) => (process.platform === "win32" ? resolve(value).toLowerCase() : resolve(value));
  const marker = join(worktree, ".git");
  if (!existsSync(marker) || !lstatSync(marker).isFile() || lstatSync(marker).isSymbolicLink()) throw new TypeError("candidate worktree must be a linked Git worktree");
  const gitAt = (cwd, args) => {
    const result = spawnSync("git", ["-c", "core.hooksPath=NUL", "-c", "core.fsmonitor=false", ...args], { cwd, shell: false, windowsHide: true, encoding: "utf8" });
    if (result.status !== 0) throw new TypeError("Git custody inspection failed");
    return result.stdout ?? "";
  };
  const git = (args) => gitAt(worktree, args);
  const sameExistingPath = (left, right) => {
    if (pathKey(left) === pathKey(right)) return true;
    try {
      const leftDetails = lstatSync(left), rightDetails = lstatSync(right);
      return String(leftDetails.dev) === String(rightDetails.dev) && String(leftDetails.ino) === String(rightDetails.ino);
    } catch { return false; }
  };
  const worktreeTop = resolve(git(["rev-parse", "--show-toplevel"]).trim());
  const sourceTop = resolve(gitAt(repositoryRoot, ["rev-parse", "--show-toplevel"]).trim());
  const worktreeCommon = resolve(worktree, git(["rev-parse", "--git-common-dir"]).trim());
  const sourceCommon = resolve(repositoryRoot, gitAt(repositoryRoot, ["rev-parse", "--git-common-dir"]).trim());
  if (!sameExistingPath(worktreeTop, worktree) || !sameExistingPath(sourceTop, repositoryRoot) || !sameExistingPath(worktreeCommon, sourceCommon)) throw new TypeError("candidate linked worktree is not registered to the approved source repository");
  const head = git(["rev-parse", "HEAD"]).trim();
  if (head !== packet.sourceSha) throw new TypeError("candidate worktree baseline revision differs from the approved source SHA");
  const diff = git(["diff", "--binary", "HEAD"]);
  const tracked = git(["diff", "--name-status", "-M", "-z", "HEAD"]).split("\0").filter(Boolean);
  const untracked = git(["ls-files", "--others", "--exclude-standard", "-z"]).split("\0").filter(Boolean);
  const inventory = [];
  const addTracked = (status, path, previousPath = undefined) => inventory.push({ status: status.replace(/\d+$/, "").toUpperCase(), path: path.replaceAll("\\", "/"), ...(previousPath === undefined ? {} : { previousPath: previousPath.replaceAll("\\", "/") }) });
  for (let index = 0; index < tracked.length;) {
    const status = tracked[index++];
    if (/^[RC]\d*$/.test(status)) { const previousPath = tracked[index++]; const nextPath = tracked[index++]; addTracked(status, nextPath, previousPath); }
    else addTracked(status, tracked[index++]);
  }
  for (const path of untracked) addTracked("U", path);
  const manifest = [];
  const addManifest = (path, status) => {
    const target = resolve(worktree, path);
    if (relative(worktree, target).split(sep).includes("..")) throw new TypeError("Git custody path escapes the worktree");
    let contentDigest = digest(`deleted:${path}`);
    if (existsSync(target)) {
      const stat = lstatSync(target);
      if (stat.isSymbolicLink()) throw new TypeError("Git custody does not allow symlinked changed files");
      if (!stat.isFile()) throw new TypeError("Git custody changed path is not a regular file");
      contentDigest = digest(readFileSync(target));
    }
    manifest.push({ status, path: path.replaceAll("\\", "/"), contentDigest });
  };
  for (const entry of inventory) { addManifest(entry.path, entry.status); if (entry.previousPath !== undefined) addManifest(entry.previousPath, "D"); }
  manifest.sort((a, b) => a.path.localeCompare(b.path) || a.status.localeCompare(b.status));
  const changedFiles = [...inventory].sort((a, b) => a.path.localeCompare(b.path) || a.status.localeCompare(b.status));
  const diffDigest = digest(`${tracked.join("\0")}\0${untracked.join("\0")}\0${diff}\0${JSON.stringify(manifest)}`);
  if (!allowDirty && inventory.length > 0) throw new TypeError("candidate worktree must be clean before spawn");
  if (expectedDiffDigest !== null && diffDigest !== expectedDiffDigest) throw new TypeError("repair worktree diff differs from the bound prior candidate");
  return Object.freeze({ custodyDigest: digest(JSON.stringify({ sourceSha: packet.sourceSha, repositoryRoot: resolve(packet.repositoryRoot), worktree, head })), diffDigest, changedFiles });
}

function custodyPaths(packet) {
  const worktree = resolve(packet.worktree), repositoryRoot = resolve(packet.repositoryRoot), stateRoot = resolve(packet.stateRoot);
  const pathKey = (value) => (process.platform === "win32" ? resolve(value).toLowerCase() : resolve(value));
  const within = (parent, child) => { const rest = relative(pathKey(parent), pathKey(child)); return rest === "" || (!rest.startsWith("..") && !isAbsolute(rest)); };
  if (within(repositoryRoot, worktree) || within(worktree, repositoryRoot)) throw new TypeError("candidate worktree must be distinct from the primary repository");
  if (within(stateRoot, worktree) || within(worktree, stateRoot) || within(stateRoot, repositoryRoot) || within(repositoryRoot, stateRoot)) throw new TypeError("state root must not overlap repository custody paths");
  return { worktree, repositoryRoot, stateRoot };
}

function provisionImplementationWorktree(packet) {
  if (packet.mode !== "implementation") return;
  const requestedWorktree = resolve(packet.worktree);
  try { lstatSync(requestedWorktree); return; } catch (error) { if (error?.code !== "ENOENT") throw error; }
  const { worktree, repositoryRoot, stateRoot } = custodyPaths(packet);
  if (!existsSync(repositoryRoot)) throw new TypeError("approved source repository does not exist");
  safeStateRoot(stateRoot);
  createOneShotWorktree({ taskRunId: packet.taskRunId, repositoryRoot, sourceSha: packet.sourceSha, worktree, stateRoot });
}

const DEFAULT_ARTIFACT_DELIVERY = Object.freeze({
  buildPrompt: buildArtifactPrompt,
  prepareScratch: prepareArtifactScratch,
  removeScratch: removeArtifactScratch,
  parseOutput: parseArtifactOutput,
  beginTransaction: beginArtifactTransaction,
  execute: executeArtifact,
  persistArtifact: persistArtifactEvidence,
  persistRejectedArtifact: persistRejectedArtifactEvidence,
  persistDecision: persistArtifactDecision
});

export function createOneShotRunner({
  spawnImpl = spawn,
  killTree = defaultKillTree,
  clock = () => new Date(),
  timers = globalThis,
  environment = process.env,
  verifyCustodyImpl = verifyCustody,
  artifactDelivery = null,
  persistImpl = persist,
  persistOwnedImpl = persistOwned,
  persistRepairConsumptionImpl = persistRepairConsumption
} = {}) {
  if (artifactDelivery !== null && (!artifactDelivery || typeof artifactDelivery !== "object" || Array.isArray(artifactDelivery))) throw new TypeError("artifact delivery overrides must be an object");
  for (const name of Object.keys(artifactDelivery ?? {})) if (!Object.hasOwn(DEFAULT_ARTIFACT_DELIVERY, name)) throw new TypeError(`artifact delivery override is unsupported: ${name}`);
  const artifactOps = Object.freeze({ ...DEFAULT_ARTIFACT_DELIVERY, ...(artifactDelivery ?? {}) });
  for (const [name, operation] of Object.entries(artifactOps)) if (typeof operation !== "function") throw new TypeError(`artifact delivery ${name} must be a function`);
  const active = new Map();
  async function run(packet, { approval = null, resumeSessionId = null, repairEvidence = null, priorReceipt = null } = {}) {
    validateTaskPacket(packet);
    const packetApproval = approval ?? packet.approval;
    assertApprovedPacket({ packet, approval: packetApproval, digest: packetDigest(packet) });
    if (packet.mode === "repair" && (!resumeSessionId || !UUID.test(resumeSessionId) || !repairEvidence || !priorReceipt)) throw new TypeError("repair requires an eligible candidate receipt and explicit failed acceptance evidence");
    const policy = createTaskPolicy(packet);
    if (packet.mode === "repair") {
      validateRunReceipt(priorReceipt); validateRepairFindings(repairEvidence);
      if (priorReceipt.state !== "candidate") throw new TypeError("repair requires a prior candidate receipt");
      const continuation = packet.continuation;
      if (packet.sourceSha !== continuation.priorSourceSha || resolve(packet.repositoryRoot) !== resolve(continuation.priorRepositoryRoot) || resolve(packet.worktree) !== resolve(continuation.priorWorktree)) throw new TypeError("repair packet custody does not match the prior candidate");
      if (priorReceipt.taskRunId !== continuation.priorTaskRunId || priorReceipt.requestId !== continuation.priorRequestId || priorReceipt.observed.sessionId !== continuation.priorSessionId || receiptDigest(priorReceipt) !== continuation.priorReceiptDigest || priorReceipt.binding.sourceSha !== continuation.priorSourceSha || priorReceipt.binding.repositoryRoot !== resolve(continuation.priorRepositoryRoot) || priorReceipt.binding.worktree !== resolve(continuation.priorWorktree) || priorReceipt.binding.diffDigest !== continuation.priorDiffDigest) throw new TypeError("prior candidate receipt does not match the repair binding");
      if (repairEvidence.taskRunId !== continuation.priorTaskRunId || repairEvidence.requestId !== continuation.priorRequestId || repairEvidence.priorReceiptDigest !== continuation.priorReceiptDigest || repairEvidence.sourceSha !== continuation.priorSourceSha || resolve(repairEvidence.repositoryRoot) !== resolve(continuation.priorRepositoryRoot) || resolve(repairEvidence.worktree) !== resolve(continuation.priorWorktree)) throw new TypeError("repair findings do not match the bound prior task");
      if (packet.findingsDigest !== receiptDigest(repairEvidence)) throw new TypeError("repair findings digest does not match the task packet");
    }
    // Validate the complete custody topology before any claim can create state
    // inside the repository or candidate worktree.
    custodyPaths(packet);
    const sessionId = resumeSessionId ?? randomUUID();
    const startedAt = now(clock), runKey = packet.taskRunId;
    if (active.has(runKey)) throw new Error("task run is already active");
    const ownerNonce = randomUUID();
    const existing = existsSync(receiptPath(packet.stateRoot, runKey)) ? readRunReceipt(packet.stateRoot, runKey) : null;
    if (existing && !(packet.mode === "repair" && priorReceipt && receiptDigest(existing) === receiptDigest(priorReceipt))) throw new RunnerRecoveryRequiredError("task run already has persisted evidence");
    let repairClaimed = false, providerStarted = false;
    if (packet.mode === "repair") { claimRepair(packet.stateRoot, packet.continuation.priorReceiptDigest, ownerNonce, packet.continuation.priorSessionId); repairClaimed = true; }
    try { claimTask(packet.stateRoot, runKey, ownerNonce); } catch (error) { if (repairClaimed) releaseRepair(packet.stateRoot, packet.continuation.priorReceiptDigest, ownerNonce); throw error; }
    let custody;
    try {
      provisionImplementationWorktree(packet);
      custody = verifyCustodyImpl(packet, { allowDirty: packet.mode === "repair", expectedDiffDigest: packet.mode === "repair" ? packet.continuation.priorDiffDigest : null });
    } catch (error) {
      releaseTask(packet.stateRoot, runKey, ownerNonce);
      if (repairClaimed) releaseRepair(packet.stateRoot, packet.continuation.priorReceiptDigest, ownerNonce);
      throw error;
    }
    const running = { contractVersion: ONE_SHOT_RUNNER_VERSION, taskRunId: packet.taskRunId, requestId: packet.requestId, state: "starting", mode: packet.mode, startedAt, ownerNonce, sessionId, pid: null, binding: { sourceSha: packet.sourceSha, repositoryRoot: resolve(packet.repositoryRoot), worktree: resolve(packet.worktree), custodyDigest: custody.custodyDigest, diffDigest: custody.diffDigest }, requested: { model: packet.provider.model, executable: packet.provider.executable }, allowedScope: allowedScope(packet, policy) };
    try { persistImpl(packet.stateRoot, runKey, running); } catch (error) { releaseTask(packet.stateRoot, runKey, ownerNonce); if (repairClaimed) releaseRepair(packet.stateRoot, packet.continuation.priorReceiptDigest, ownerNonce); throw error; }
    let providerScratch = null, scratchRemoved = false, promptPath = null, launch, artifactTransaction = null, transactionCommitted = false;
    try {
      providerScratch = artifactOps.prepareScratch({ stateRoot: packet.stateRoot, taskRunId: packet.taskRunId, requestId: packet.requestId });
      const prompt = artifactOps.buildPrompt({ packet, repairEvidence });
      promptPath = promptFile(packet.stateRoot, prompt);
      launch = buildLaunchFromPolicy({ packet, policy, promptFilePath: promptPath, providerCwd: providerScratch, sessionId, resume: packet.mode === "repair", environment });
      prepareArtifactOnlyGrokHome(launch.grokHome);
      mkdirSync(dirname(launch.debugFile), { recursive: true, mode: 0o700 });
      artifactTransaction = artifactOps.beginTransaction({ packet, custody });
      if (!artifactTransaction || typeof artifactTransaction.rollback !== "function" || typeof artifactTransaction.commit !== "function") throw new TypeError("controller artifact transaction is invalid");
    } catch (error) {
      if (providerScratch !== null) try { artifactOps.removeScratch(providerScratch); } catch {}
      if (promptPath !== null) try { unlinkSync(promptPath); } catch {}
      releaseTask(packet.stateRoot, runKey, ownerNonce);
      if (repairClaimed) releaseRepair(packet.stateRoot, packet.continuation.priorReceiptDigest, ownerNonce);
      throw error;
    }
    let child, stderr = "", artifactOutput = "", terminal = null, finished = false, childClosed = false, terminationError = null, rejectionEvidenceError = null, rejectionEvidenceAttempted = false, rejectionOutputTruncated = false, startTimer = null, turnTimer = null, idleTimer = null;
    const childEnvironment = { ...launch.env };
    const removeScratch = () => { if (scratchRemoved) return; artifactOps.removeScratch(providerScratch); scratchRemoved = true; };
    const stop = () => { if (finished || childClosed) return true; try { killTree(child); return childClosed; } catch (error) { terminationError ??= error; throw error; } };
    const finish = (state, code, message, extra = {}) => ({ contractVersion: "agent-platform.grok-build-engineer-receipt.v1", taskRunId: packet.taskRunId, requestId: packet.requestId, mode: packet.mode, state, startedAt, finishedAt: now(clock), ownerNonce, binding: { sourceSha: packet.sourceSha, repositoryRoot: resolve(packet.repositoryRoot), worktree: resolve(packet.worktree), custodyDigest: custody.custodyDigest, diffDigest: extra.diffDigest ?? custody.diffDigest }, requested: { model: packet.provider.model, executable: packet.provider.executable }, observed: { model: typeof terminal?.model === "string" && terminal.model.length <= 512 ? redactForBoundary(terminal.model).slice(0, 512) : packet.provider.model, sessionId, exitCode: Number.isInteger(code) ? code : null }, allowedScope: allowedScope(packet, policy), changedFiles: extra.changedFiles ?? [], validationEvidence: extra.validationEvidence ?? [], diagnostics: { code: typeof extra.code === "string" ? extra.code : String(code ?? "runner_failure"), message: String(message).slice(0, 512), stderrDigest: stderr ? digest(stderr) : null, ...receiptExtrasFromFrameError(extra.protocolError) } });
    const settle = (receipt) => { let safeReceipt = receipt; try { removeScratch(); } catch (error) { safeReceipt = finish("failed", null, safeMessage(error), { changedFiles: [], validationEvidence: [], code: "artifact_scratch_mutated" }); } try { validateRunReceipt(safeReceipt); } catch { safeReceipt = finish("failed", null, "runner receipt validation failed", { changedFiles: [], validationEvidence: [], code: "runner_failure" }); validateRunReceipt(safeReceipt); } finished = true; for (const timer of [startTimer, turnTimer, idleTimer]) if (timer !== null) timers.clearTimeout?.(timer); const entry = active.get(runKey); if (entry && entry.cancelTimer !== null) timers.clearTimeout?.(entry.cancelTimer); active.delete(runKey); try { unlinkSync(promptPath); } catch {} let saved; try { try { saved = persistOwnedImpl(packet.stateRoot, runKey, ownerNonce, safeReceipt); } catch (error) { const rollbackError = rollbackArtifactTransaction(); if (rollbackError !== null) throw new RunnerRecoveryRequiredError(`terminal persistence failed and artifact rollback failed: ${safeMessage(rollbackError)}`); throw error; } if (repairClaimed && providerStarted) { try { persistRepairConsumptionImpl(packet.stateRoot, packet.continuation.priorReceiptDigest, ownerNonce, saved); } catch (error) { if (error instanceof RunnerRecoveryRequiredError) throw error; throw new RunnerRecoveryRequiredError(`repair consumption evidence could not be persisted: ${safeMessage(error)}`); } } } finally { releaseTask(packet.stateRoot, runKey, ownerNonce); if (repairClaimed && !providerStarted) releaseRepair(packet.stateRoot, packet.continuation.priorReceiptDigest, ownerNonce); } if (safeReceipt.state === "cancelled") entry?.cancelResolve?.(saved); return saved; };
    const rollbackArtifactTransaction = () => {
      if (artifactTransaction === null || transactionCommitted) return null;
      try {
        artifactTransaction.rollback();
        verifyCustodyImpl(packet, { allowDirty: packet.mode === "repair", expectedDiffDigest: custody.diffDigest });
        return null;
      } catch (error) { return error; }
    };
    const persistFrameEvidence = (error) => {
      if (!error?.frameDiagnostics) return;
      try {
        persistProviderErrorFrame({ stateRoot: packet.stateRoot, taskRunId: packet.taskRunId, requestId: packet.requestId, line: error.protocolFrameLine, diagnostics: error.frameDiagnostics });
      } catch { /* receipt diagnostics remain the bounded evidence if disk persist fails */ }
    };
    const fail = (failureCode, message, state = "failed", protocolError = null) => {
      persistFrameEvidence(protocolError);
      const rollbackError = rollbackArtifactTransaction();
      if (rollbackError !== null) return settle(finish("recovery_required", child?.exitCode ?? null, safeMessage(rollbackError), { changedFiles: [], validationEvidence: [], code: "artifact_rollback_failed" }));
      return settle(finish(state, child?.exitCode ?? null, message, { changedFiles: [], validationEvidence: [], code: failureCode, protocolError }));
    };
    const persistRejection = (error) => {
      if (rejectionEvidenceAttempted) return rejectionEvidenceError;
      rejectionEvidenceAttempted = true;
      try {
        artifactOps.persistRejectedArtifact({ stateRoot: packet.stateRoot, packet, output: artifactOutput, error, outputTruncated: rejectionOutputTruncated });
      } catch (evidenceError) {
        rejectionEvidenceError = evidenceError;
      }
      return rejectionEvidenceError;
    };
    const persistRejectionOrFail = (error) => {
      const evidenceError = persistRejection(error);
      return evidenceError === null ? null : fail("artifact_rejection_evidence_failed", safeMessage(evidenceError));
    };
    try { child = spawnImpl(launch.command, launch.args, { cwd: launch.cwd, env: Object.freeze(childEnvironment), shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] }); } catch (error) { try { unlinkSync(promptPath); } catch {} return settle(finish("failed", null, safeMessage(error), { code: "spawn_failed" })); }
    if (!child || !child.stdout?.on || !child.stderr?.on || !Number.isSafeInteger(child.pid) || child.pid < 1) return settle(finish("failed", null, "child identity is unavailable", { code: "child_identity_invalid" }));
    providerStarted = true;
    let cancelResolve = null; const cancelPromise = new Promise((resolveCancel) => { cancelResolve = resolveCancel; }); let resolveOutcomeRef = null; let entry; const requestCancel = () => { if (entry.cancelRequested) return entry.cancelPromise; entry.cancelRequested = true; try { entry.stop(); } catch { /* the grace timer records unconfirmed cancellation */ } entry.cancelTimer = timers.setTimeout(() => { if (active.get(runKey) === entry) { try { entry.cancelledReceipt = settle(finish("recovery_required", null, terminationError ? "runner child-tree termination was not proven" : "runner cancellation was not acknowledged", { code: terminationError ? "cancellation_termination_unproven" : "cancellation_unacknowledged" })); } catch (error) { entry.cancelError = error; } entry.cancelResolve?.(entry.cancelledReceipt); resolveOutcomeRef?.({ code: null, protocolError: null, forcedReceipt: entry.cancelledReceipt }); } }, entry.cancelMs); return entry.cancelPromise; }; entry = { child, stop, sessionId, cancelRequested: false, cancelPromise, cancelResolve, cancelTimer: null, cancelMs: policy.timeouts.cancelMs, requestCancel, cancelledReceipt: null, cancelError: null }; active.set(runKey, entry);
    running.state = "running"; running.pid = child.pid;
    try { persistImpl(packet.stateRoot, runKey, running); } catch (error) {
      let closeTimer = null;
      const closed = await new Promise((resolveClose) => {
        let resolved = false;
        const resolveOnce = (value) => { if (resolved) return; resolved = true; resolveClose(value); };
        child.once("close", () => {
          childClosed = true;
          if (closeTimer !== null) timers.clearTimeout?.(closeTimer);
          if (entry.cancelTimer !== null) timers.clearTimeout?.(entry.cancelTimer);
          if (active.get(runKey) === entry) active.delete(runKey);
          try { removeScratch(); } catch {}
          try { unlinkSync(promptPath); } catch {}
          releaseTask(packet.stateRoot, runKey, ownerNonce);
          if (entry.cancelRequested && entry.cancelledReceipt === null) {
            entry.cancelledReceipt = finish("recovery_required", child.exitCode ?? null, "running state could not be persisted before confirmed child termination", { code: "running_state_persistence_failed" });
            entry.cancelResolve?.(entry.cancelledReceipt);
          }
          resolveOnce(true);
        });
        child.once?.("error", () => {});
        closeTimer = timers.setTimeout(() => resolveOnce(false), policy.timeouts.cancelMs);
        try { stop(); } catch {}
      });
      throw new RunnerRecoveryRequiredError(closed ? "running state could not be persisted after confirmed child termination" : "running state could not be persisted and child termination was not proven");
    }
    let nativeRequestId = null, controllerCorrelated = false, terminalSeen = false;
    const parse = (line) => {
      let frame;
      try { frame = JSON.parse(line); } catch { throw Object.assign(new Error("invalid_stream_frame"), { code: "invalid_stream_frame" }); }
      if (!frame || typeof frame !== "object" || Array.isArray(frame) || typeof frame.type !== "string" || frame.type.length === 0) throw Object.assign(new Error("invalid_stream_frame"), { code: "invalid_stream_frame" });
      // taskRunId is controller-owned correlation metadata used by synthetic
      // fixtures. Grok's top-level requestId is provider-native and must not
      // be compared with the controller packet requestId.
      if (frame.taskRunId !== undefined) {
        if (frame.taskRunId !== packet.taskRunId) throw new Error("stream_correlation_mismatch");
        controllerCorrelated = true;
      }
      if (frame.requestId !== undefined) {
        if (typeof frame.requestId !== "string" || !frame.requestId) throw new Error("stream_correlation_mismatch");
        if (nativeRequestId === null) nativeRequestId = frame.requestId;
        else if (nativeRequestId !== frame.requestId) throw new Error("stream_correlation_mismatch");
      }
      const observedSessionId = frame.sessionId ?? frame.params?.sessionId;
      if (observedSessionId !== undefined && observedSessionId !== sessionId) throw new Error("stream_session_mismatch");
      if (terminalSeen) throw Object.assign(new Error("post_terminal_data"), { code: "post_terminal_data" });
      if (frame.type === "max_turns_reached") throw Object.assign(new Error("max_turns"), { code: "max_turns" });
      if (frame.type === "end") {
        if (frame.stopReason !== "end_turn") throw Object.assign(new Error("terminal_stop_reason_invalid"), { code: "terminal_stop_reason_invalid" });
        // Synthetic fixtures may carry controller correlation instead. Native
        // provider output must prove the exact session and request on `end`.
        if (observedSessionId === undefined && frame.taskRunId === undefined) throw Object.assign(new Error("terminal_session_missing"), { code: "terminal_session_missing" });
        if (frame.requestId === undefined) throw Object.assign(new Error("terminal_request_missing"), { code: "terminal_request_missing" });
        terminalSeen = true; terminal = frame; return;
      }
      if (["terminal", "completed"].includes(frame.type)) throw Object.assign(new Error("terminal_frame_type_invalid"), { code: "terminal_frame_type_invalid" });
      if (frame.type === "error" || frame.error) throw providerErrorFromFrame(line, frame);
      if (["tool_call", "tool_call_update"].includes(frame.type)) throw Object.assign(new Error("provider attempted a direct tool call during artifact-only delivery"), { code: "artifact_tool_attempted" });
      if (frame.type === "text") {
        const text = typeof frame.data === "string" ? frame.data : frame.text;
        if (typeof text !== "string") throw Object.assign(new Error("artifact text frame is invalid"), { code: "artifact_output_invalid" });
        artifactOutput += text;
        if (Buffer.byteLength(artifactOutput, "utf8") > MAX_ARTIFACT_OUTPUT_BYTES) throw Object.assign(new Error("artifact output exceeds the bounded limit"), { code: "artifact_output_limit" });
      }
    };
    let forcedReceipt = null, protocolError = null;
    const stopWithGrace = (error) => { if (!entry || finished) return; if (!protocolError) protocolError = error; persistFrameEvidence(protocolError); if (error?.code === "artifact_output_limit") { rejectionOutputTruncated = true; persistRejection(error); } try { entry.stop(); } catch (killError) { protocolError = protocolError ?? killError; } if (entry.cancelTimer === null) entry.cancelTimer = timers.setTimeout(() => { if (active.get(runKey) === entry) { const message = rejectionEvidenceError === null ? "runner child-tree termination was not proven" : `runner child-tree termination was not proven; rejected artifact evidence could not be persisted: ${safeMessage(rejectionEvidenceError)}`; try { forcedReceipt = settle(finish("recovery_required", null, message, { code: "child_termination_unproven" })); } catch (settleError) { entry.cancelError = settleError; } resolveOutcomeRef?.({ code: null, protocolError, forcedReceipt }); } }, entry.cancelMs); };
    const outcome = await new Promise((resolveOutcome) => {
      resolveOutcomeRef = resolveOutcome;
      let buffer = "", streamBytes = 0, closed = false;
      const decoder = new StringDecoder("utf8");
      const resolveOnce = (value) => { if (closed) return; closed = true; resolveOutcome(value); };
      const armIdle = () => {
        if (idleTimer !== null) timers.clearTimeout?.(idleTimer);
        idleTimer = timers.setTimeout(() => stopWithGrace(Object.assign(new Error("idle_timeout"), { code: "idle_timeout" })), policy.timeouts.idleMs);
      };
      const consume = (text) => {
        buffer += text; armIdle();
        for (;;) {
          const index = buffer.indexOf("\n");
          if (index < 0) { if (Buffer.byteLength(buffer, "utf8") > MAX_STDOUT_FRAME_BYTES) throw boundedStreamError(); break; }
          const raw = buffer.slice(0, index).replace(/\r$/, ""); buffer = buffer.slice(index + 1);
          if (Buffer.byteLength(raw, "utf8") > MAX_STDOUT_FRAME_BYTES) throw boundedStreamError();
          if (raw.trim()) parse(raw.trim());
        }
      };
      startTimer = timers.setTimeout(() => stopWithGrace(Object.assign(new Error("start_timeout"), { code: "start_timeout" })), policy.timeouts.startMs);
      turnTimer = timers.setTimeout(() => stopWithGrace(Object.assign(new Error("turn_timeout"), { code: "turn_timeout" })), policy.timeouts.turnMs);
      armIdle();
      child.stdout.on("data", (chunk) => {
        if (protocolError) return;
        streamBytes += Buffer.byteLength(chunk);
        if (streamBytes > MAX_STDOUT_STREAM_BYTES) { stopWithGrace(boundedStreamError()); return; }
        if (startTimer !== null) { timers.clearTimeout?.(startTimer); startTimer = null; }
        try { consume(decoder.write(Buffer.from(chunk))); } catch (error) { stopWithGrace(error); }
      });
      child.stderr.on("data", (chunk) => { stderr = (stderr + Buffer.from(chunk).toString("utf8")).slice(-8192); });
      child.once("error", (error) => stopWithGrace(error));
      child.once("close", (code) => {
        childClosed = true;
        if (!protocolError) {
          try { consume(decoder.end()); if (buffer.trim()) { if (Buffer.byteLength(buffer, "utf8") > MAX_STDOUT_FRAME_BYTES) throw boundedStreamError(); parse(buffer.trim()); } }
          catch (error) { protocolError = error; }
        }
        resolveOnce({ code, protocolError, forcedReceipt });
      });
    });
    const currentEntry = active.get(runKey);
    let result = forcedReceipt ?? outcome.forcedReceipt ?? currentEntry?.cancelledReceipt;
    if (result === null || result === undefined) {
      if (currentEntry?.cancelRequested) result = terminationError ? settle(finish("recovery_required", outcome.code, "runner child-tree termination was not proven", { code: "cancellation_termination_unproven" })) : settle(finish("cancelled", outcome.code, "runner cancellation requested", { code: "cancelled" }));
      else if (outcome.protocolError) {
        if (outcome.protocolError.code === "artifact_output_limit") result = persistRejectionOrFail(outcome.protocolError);
        if (result === null || result === undefined) result = fail(failCode(outcome.protocolError), safeMessage(outcome.protocolError), "failed", outcome.protocolError);
      }
      else if (!terminal) result = fail("terminal_missing", "stream ended before terminal frame");
      else if (terminal.status === "failed" || terminal.status === "error") result = fail("provider_failure", "provider reported a failed terminal outcome");
      else if (outcome.code !== 0) result = fail("child_exit_nonzero", `child exited with code ${outcome.code}`);
      else if (!controllerCorrelated && nativeRequestId === null) result = fail("stream_correlation_missing", "provider stream did not contain bounded request correlation");
      else if (Array.isArray(terminal.validationEvidence) && terminal.validationEvidence.length > 0) result = fail("provider_validation_claimed", "artifact-only delivery rejects provider-reported validation evidence");
      else {
        try { removeScratch(); } catch (error) { result = fail("artifact_scratch_mutated", safeMessage(error)); }
        if (result === null || result === undefined) {
          let artifact, artifactEvidence;
          try { artifact = artifactOps.parseOutput(artifactOutput, packet); }
          catch (error) {
            result = persistRejectionOrFail(error);
            if (result === null || result === undefined) result = fail("artifact_invalid", safeMessage(error));
          }
          if ((result === null || result === undefined) && artifact) {
            try { artifactEvidence = artifactOps.persistArtifact({ stateRoot: packet.stateRoot, artifact }); }
            catch (error) { result = fail("artifact_evidence_failed", safeMessage(error)); }
          }
          if ((result === null || result === undefined) && artifact) {
            let execution;
            const rollbackOrRecover = () => {
              const error = rollbackArtifactTransaction();
              return error === null ? null : settle(finish("recovery_required", child?.exitCode ?? null, safeMessage(error), { changedFiles: [], validationEvidence: [], code: "artifact_rollback_failed" }));
            };
            if (result === null || result === undefined) {
              try { execution = artifactOps.execute({ artifact, packet, policy, transaction: artifactTransaction, environment }); }
              catch (error) { result = rollbackOrRecover() ?? fail("artifact_execution_failed", safeMessage(error)); }
            }
            if ((result === null || result === undefined) && (!execution || typeof execution.ok !== "boolean" || !Array.isArray(execution.decisions) || !Array.isArray(execution.validationEvidence) || !Array.isArray(execution.appliedPaths))) result = rollbackOrRecover() ?? fail("artifact_execution_failed", "controller artifact execution returned invalid evidence");
            if ((result === null || result === undefined) && !execution.ok) {
              result = rollbackOrRecover();
              if (result === null) {
                try { artifactOps.persistDecision({ stateRoot: packet.stateRoot, artifact, artifactEvidence, execution }); }
                catch (error) { result = fail("artifact_evidence_failed", safeMessage(error)); }
              }
              if (result === null || result === undefined) result = fail("validation_failed", "controller-owned validation failed and candidate custody was restored");
            }
            if (result === null || result === undefined) {
              let afterCustody, scopeError = null;
              try {
                afterCustody = verifyCustodyImpl(packet, { allowDirty: true });
                validateChangedFiles(afterCustody.changedFiles ?? [], policy);
                const baselinePaths = new Set((custody.changedFiles ?? []).map((entry) => entry.path));
                const appliedPaths = new Set(execution.appliedPaths);
                const unexpected = (afterCustody.changedFiles ?? []).filter((entry) => !baselinePaths.has(entry.path) && !appliedPaths.has(entry.path));
                if (unexpected.length > 0) throw new TypeError("controller custody contains changes outside the applied artifact");
              } catch (error) { scopeError = error; }
              if (scopeError !== null) {
                result = rollbackOrRecover();
                if (result === null) {
                  const deniedExecution = Object.freeze({ ...execution, ok: false, appliedPaths: Object.freeze([]) });
                  try { artifactOps.persistDecision({ stateRoot: packet.stateRoot, artifact, artifactEvidence, execution: deniedExecution }); }
                  catch (error) { result = fail("artifact_evidence_failed", safeMessage(error)); }
                }
                if (result === null || result === undefined) result = fail("scope_violation", safeMessage(scopeError));
              } else {
                try { artifactOps.persistDecision({ stateRoot: packet.stateRoot, artifact, artifactEvidence, execution }); }
                catch (error) { result = rollbackOrRecover() ?? fail("artifact_evidence_failed", safeMessage(error)); }
                if (result === null || result === undefined) {
                  result = settle(finish("candidate", outcome.code, "candidate ready", { changedFiles: afterCustody.changedFiles ?? [], validationEvidence: execution.validationEvidence, diffDigest: afterCustody.diffDigest }));
                  artifactTransaction.commit();
                  transactionCommitted = true;
                }
              }
            }
          }
        }
      }
    }
    return result;
  }
  async function cancel(taskRunId) { validTaskRunId(taskRunId); const entry = active.get(taskRunId); if (!entry) throw new RunnerRecoveryRequiredError("task run is not owned by this runner process"); return entry.requestCancel(); }
  return Object.freeze({ run, cancel, activeRuns: () => [...active.keys()] });
}
export async function runOneShotTask(packet, options = {}) { return createOneShotRunner(options).run(packet, options); }
