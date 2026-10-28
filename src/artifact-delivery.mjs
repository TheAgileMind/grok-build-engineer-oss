import { createHash, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  rmdirSync,
  unlinkSync,
  writeFileSync
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { containsCredentialValue, redactForBoundary } from "./redaction.mjs";
import { APPROVED_TASK_TOOLS, assertCommandAllowed, commandTokens, pathInScope, scopedEnvironment } from "./task-policy.mjs";

export const ARTIFACT_CONTRACT_VERSION = "agent-platform.grok-build-engineer-change-artifact.v1";
export const ARTIFACT_DECISION_VERSION = "agent-platform.grok-build-engineer-artifact-decision.v1";
export const ARTIFACT_REJECTION_VERSION = "agent-platform.grok-build-engineer-artifact-rejection.v1";

const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;
const MAX_CONTEXT_BYTES = 8 * 1024 * 1024;
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 256;
const MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_TRANSACTION_BYTES = 512 * 1024 * 1024;
const MAX_TRANSACTION_ENTRIES = 10_000;
const MAX_REJECTED_OPERATION_SHAPES = 32;
const IDENTIFIER = /^[a-z][a-z0-9_-]{2,63}$/;
const ARTIFACT_OPERATION_KINDS = Object.freeze(["write_file", "delete_file", "run_command"]);
const FORBIDDEN_PROVIDER_OPERATION_KINDS = Object.freeze([...APPROVED_TASK_TOOLS, "tool_call"]);
const DISCLOSED_OPERATION_KINDS = new Set([...ARTIFACT_OPERATION_KINDS, ...FORBIDDEN_PROVIDER_OPERATION_KINDS]);
const REJECTED_ARTIFACT_FIELDS = Object.freeze(["contractVersion", "taskRunId", "requestId", "operations"]);
const REJECTION_CODES = new Set(["unsupported_operation_kind", "invalid_json", "secret_shaped_data", "identity_mismatch", "output_bounds_invalid", "artifact_output_limit", "artifact_schema_invalid"]);

function fail(message, code = null) { const error = new TypeError(message); if (code !== null) error.code = code; throw error; }
function digest(value) { return `sha256:${createHash("sha256").update(value).digest("hex")}`; }
function exact(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) fail(`${label} has unexpected fields`);
  return value;
}
function safeIdentifier(value, label) { if (typeof value !== "string" || !IDENTIFIER.test(value)) fail(`${label} is invalid`); return value; }
function lstatOrNull(path) {
  try { return lstatSync(path); }
  catch (error) { if (error?.code === "ENOENT") return null; throw error; }
}
function safeRelative(value, label) {
  if (typeof value !== "string" || !value || isAbsolute(value)) fail(`${label} must be repository-relative`);
  const normalized = value.replaceAll("\\", "/");
  if (normalized === ".git" || normalized.startsWith(".git/") || normalized === "node_modules" || normalized.startsWith("node_modules/") || normalized.split("/").some((part) => !part || part === "." || part === "..")) fail(`${label} escapes the worktree`);
  return normalized;
}
function within(root, target) {
  const rest = relative(resolve(root), resolve(target));
  return rest === "" || (!isAbsolute(rest) && !rest.split(sep).includes(".."));
}
function assertPlainAncestors(root, target) {
  const base = resolve(root), destination = resolve(target);
  if (!within(base, destination) || destination === base) fail("artifact path escapes the worktree");
  let current = destination;
  while (within(base, current) && current !== base) {
    const details = lstatOrNull(current);
    if (details !== null) {
      if (details.isSymbolicLink()) fail("artifact path contains a symbolic link");
      if (current !== destination && !details.isDirectory()) fail("artifact path has a non-directory ancestor");
    }
    current = dirname(current);
  }
  const rootDetails = lstatSync(base);
  if (!rootDetails.isDirectory() || rootDetails.isSymbolicLink()) fail("artifact worktree is not a plain directory");
  return destination;
}
function utf8(bytes, label) {
  const value = bytes.toString("utf8");
  if (!Buffer.from(value, "utf8").equals(bytes)) fail(`${label} is not UTF-8 text`);
  return value;
}

function contextFiles(worktree, contextPaths) {
  const root = resolve(worktree), files = new Map();
  let totalBytes = 0;
  const addFile = (relativePath) => {
    const normalized = safeRelative(relativePath, "context path");
    if (files.has(normalized)) return;
    const target = assertPlainAncestors(root, join(root, ...normalized.split("/")));
    const details = lstatSync(target);
    if (!details.isFile()) fail("context entry is not a regular file");
    if (details.size > MAX_FILE_BYTES) fail(`context file is too large: ${normalized}`);
    const bytes = readFileSync(target); totalBytes += bytes.length;
    if (files.size >= MAX_FILES || totalBytes > MAX_CONTEXT_BYTES) fail("artifact context exceeds its bounded allowance");
    const content = utf8(bytes, `context file ${normalized}`);
    if (containsCredentialValue(content)) fail(`context file contains secret-shaped data: ${normalized}`);
    files.set(normalized, content);
  };
  const visit = (relativePath) => {
    const normalized = safeRelative(relativePath, "context path");
    const target = assertPlainAncestors(root, join(root, ...normalized.split("/")));
    const details = lstatOrNull(target);
    if (details === null) fail(`context path does not exist: ${normalized}`);
    if (details.isFile()) { addFile(normalized); return; }
    if (!details.isDirectory()) fail(`context path is not a plain file or directory: ${normalized}`);
    for (const entry of readdirSync(target, { withFileTypes: true })) {
      if ([".git", "node_modules"].includes(entry.name)) continue;
      const child = `${normalized}/${entry.name}`;
      if (entry.isSymbolicLink()) fail(`context path contains a symbolic link: ${child}`);
      if (entry.isDirectory()) visit(child);
      else if (entry.isFile()) addFile(child);
      else fail(`context path contains a special entry: ${child}`);
    }
  };
  for (const entry of contextPaths) visit(entry);
  return [...files].sort(([left], [right]) => left.localeCompare(right)).map(([path, content]) => ({ path, content }));
}

export function buildArtifactPrompt({ packet, repairEvidence = null }) {
  const context = contextFiles(packet.worktree, packet.task.contextPaths);
  const repair = repairEvidence === null ? null : redactForBoundary(repairEvidence);
  const example = {
    contractVersion: ARTIFACT_CONTRACT_VERSION,
    taskRunId: packet.taskRunId,
    requestId: packet.requestId,
    operations: [
      { kind: "write_file", path: "<repository-relative allowed path>", content: "<complete UTF-8 file content>" },
      { kind: "delete_file", path: "<repository-relative allowed path>" },
      { kind: "run_command", command: "<exact allowlisted validation command>" }
    ]
  };
  return [
    packet.task.title,
    "",
    packet.task.instructions,
    "",
    "Artifact-only execution contract:",
    "- You have no filesystem, command, network, MCP, or subagent tools.",
    "- Do not claim that you changed files or ran commands.",
    "- Return exactly one JSON object and no markdown fences or commentary.",
    `- contractVersion must be ${ARTIFACT_CONTRACT_VERSION}.`,
    `- taskRunId must be ${packet.taskRunId}; requestId must be ${packet.requestId}.`,
    `- operations is an ordered array. operation.kind must be exactly one of: ${ARTIFACT_OPERATION_KINDS.map((kind) => JSON.stringify(kind)).join(", ")}.`,
    "- write_file objects must contain exactly kind, path, and content; delete_file exactly kind and path; run_command exactly kind and command.",
    `- Never emit provider-tool or legacy operation kinds, including ${FORBIDDEN_PROVIDER_OPERATION_KINDS.join(", ")}.`,
    "- Encode each requested prohibited-path denial probe as a write_file or delete_file operation and each requested prohibited-command denial probe as a run_command operation; do not invent another kind. The trusted controller will deny those operations before effect and continue with allowed operations.",
    "- Include each required validation command as a run_command operation; only the trusted controller may execute it.",
    "- Use only the operation objects the task needs. Replace every angle-bracket placeholder; do not copy placeholder values literally.",
    "Exact task-bound JSON artifact example:",
    JSON.stringify(example),
    "",
    `Context JSON:\n${JSON.stringify(context)}`,
    repair === null ? "" : `\nFailed acceptance evidence JSON:\n${JSON.stringify(repair)}`
  ].join("\n");
}

export function parseArtifactOutput(output, packet) {
  if (typeof output !== "string" || !output.trim() || Buffer.byteLength(output, "utf8") > MAX_ARTIFACT_BYTES) fail("artifact output is missing or oversized", "output_bounds_invalid");
  let value;
  try { value = JSON.parse(output.trim()); } catch { fail("artifact output must be exactly one JSON object", "invalid_json"); }
  if (containsCredentialValue(JSON.stringify(value))) fail("artifact output contains secret-shaped data", "secret_shaped_data");
  exact(value, ["contractVersion", "taskRunId", "requestId", "operations"], "artifact");
  if (value.contractVersion !== ARTIFACT_CONTRACT_VERSION) fail("artifact contractVersion is unsupported");
  if (value.taskRunId !== packet.taskRunId || value.requestId !== packet.requestId) fail("artifact identity does not match the task packet", "identity_mismatch");
  if (!Array.isArray(value.operations) || value.operations.length < 1 || value.operations.length > MAX_FILES) fail("artifact operations must be a bounded non-empty array");
  const filePaths = new Set(), commands = new Set();
  let contentBytes = 0;
  const operations = value.operations.map((operation, index) => {
    if (!operation || typeof operation !== "object" || Array.isArray(operation)) fail(`artifact operation ${index} is invalid`);
    if (operation.kind === "write_file") {
      exact(operation, ["kind", "path", "content"], `artifact operation ${index}`);
      const path = safeRelative(operation.path, `artifact operation ${index} path`);
      if (typeof operation.content !== "string") fail(`artifact operation ${index} content must be text`);
      const bytes = Buffer.byteLength(operation.content, "utf8"); contentBytes += bytes;
      if (bytes > MAX_FILE_BYTES || contentBytes > MAX_ARTIFACT_BYTES) fail("artifact file content exceeds its bounded allowance");
      if (filePaths.has(path)) fail(`artifact contains duplicate file path: ${path}`);
      filePaths.add(path); return Object.freeze({ kind: operation.kind, path, content: operation.content });
    }
    if (operation.kind === "delete_file") {
      exact(operation, ["kind", "path"], `artifact operation ${index}`);
      const path = safeRelative(operation.path, `artifact operation ${index} path`);
      if (filePaths.has(path)) fail(`artifact contains duplicate file path: ${path}`);
      filePaths.add(path); return Object.freeze({ kind: operation.kind, path });
    }
    if (operation.kind === "run_command") {
      exact(operation, ["kind", "command"], `artifact operation ${index}`);
      if (typeof operation.command !== "string" || !operation.command.trim() || Buffer.byteLength(operation.command, "utf8") > 512) fail(`artifact operation ${index} command is invalid`);
      if (commands.has(operation.command)) fail(`artifact contains duplicate command: ${operation.command}`);
      commands.add(operation.command); return Object.freeze({ kind: operation.kind, command: operation.command });
    }
    fail(`artifact operation ${index} kind is unsupported`, "unsupported_operation_kind");
  });
  return Object.freeze({ contractVersion: value.contractVersion, taskRunId: value.taskRunId, requestId: value.requestId, operations: Object.freeze(operations) });
}

function operationDigest(operation) { return digest(JSON.stringify(operation)); }
function decision(operation, index, result, reason, extra = {}) {
  const target = operation.kind === "run_command" ? operation.command : operation.path;
  return Object.freeze({ index, kind: operation.kind, target, operationDigest: operationDigest(operation), decision: result, reason, ...extra });
}
function commandInvocation(command, environment, platform = process.platform) {
  const tokens = commandTokens(command);
  if (platform === "win32") return { command: environment.COMSPEC ?? process.env.COMSPEC ?? "C:\\Windows\\System32\\cmd.exe", args: ["/d", "/s", "/c", command] };
  return { command: tokens[0], args: tokens.slice(1) };
}

function transactionError(cause) {
  const error = new Error("artifact rollback failed");
  error.code = "artifact_rollback_failed";
  error.cause = cause;
  return error;
}
function dependencyPath(path) { return path.split("/").includes("node_modules"); }
function fixedGitEnvironment() {
  const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";
  const environment = {
    PATH: process.env.PATH ?? "",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: nullDevice,
    GIT_TERMINAL_PROMPT: "0",
    GCM_INTERACTIVE: "Never",
    GIT_ASKPASS: "",
    SSH_ASKPASS: "",
    GIT_OPTIONAL_LOCKS: "0"
  };
  for (const key of ["SystemRoot", "SystemDrive", "ComSpec", "TEMP", "TMP"]) if (process.env[key]) environment[key] = process.env[key];
  return environment;
}
function fixedGit(root, args, { binary = false } = {}) {
  const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";
  const result = spawnSync("git", ["-c", `core.hooksPath=${nullDevice}`, "-c", "core.fsmonitor=false", ...args], {
    cwd: root,
    env: fixedGitEnvironment(),
    shell: false,
    windowsHide: true,
    encoding: binary ? null : "utf8",
    timeout: 30_000,
    maxBuffer: MAX_TRANSACTION_BYTES
  });
  if (result.error || result.status !== 0) fail("artifact transaction Git inspection failed");
  return result.stdout ?? (binary ? Buffer.alloc(0) : "");
}
function controlPath(root, name) {
  const value = String(fixedGit(root, ["rev-parse", "--git-path", name])).trim();
  if (!value) fail(`artifact transaction ${name} path is unavailable`);
  return isAbsolute(value) ? resolve(value) : resolve(root, value);
}
function plainFileSnapshot(path, label, budget = null) {
  const details = lstatOrNull(path);
  if (details === null) return Object.freeze({ existed: false, mode: null, bytes: null, contentDigest: digest(`missing:${label}`) });
  if (!details.isFile() || details.isSymbolicLink()) fail(`${label} is not a plain file`);
  if (budget !== null) {
    budget.entries += 1;
    budget.bytes += details.size;
    if (budget.entries > MAX_TRANSACTION_ENTRIES || budget.bytes > MAX_TRANSACTION_BYTES) fail("artifact transaction baseline exceeds its bounded allowance");
  }
  const bytes = readFileSync(path);
  return Object.freeze({ existed: true, mode: details.mode & 0o777, bytes, contentDigest: digest(bytes) });
}
function restorePlainFile(path, snapshot) {
  const current = lstatOrNull(path);
  if (!snapshot.existed) {
    if (current !== null) rmSync(path, { recursive: current.isDirectory() && !current.isSymbolicLink(), force: true });
    return;
  }
  if (current !== null && current.isFile() && !current.isSymbolicLink() && readFileSync(path).equals(snapshot.bytes)) {
    if ((current.mode & 0o777) !== snapshot.mode) chmodSync(path, snapshot.mode);
    return;
  }
  if (current !== null && (!current.isFile() || current.isSymbolicLink())) rmSync(path, { recursive: current.isDirectory() && !current.isSymbolicLink(), force: true });
  mkdirSync(dirname(path), { recursive: true });
  if (current !== null) chmodSync(path, 0o600);
  writeFileSync(path, snapshot.bytes);
  chmodSync(path, snapshot.mode);
}
function normalizedTransactionPath(value, label) {
  const path = safeRelative(value, label);
  return dependencyPath(path) ? null : path;
}
function nulList(value, label) {
  if (typeof value !== "string") fail(`${label} is invalid`);
  return value.split("\0").filter(Boolean);
}
function mutablePaths(root, sourceSha) {
  const values = new Set();
  const add = (value, label) => {
    const path = normalizedTransactionPath(value.replaceAll("\\", "/"), label);
    if (path !== null) values.add(path);
  };
  const tracked = nulList(String(fixedGit(root, ["diff", "--no-ext-diff", "--no-textconv", "--name-status", "-M", "-z", sourceSha])), "tracked transaction inventory");
  for (let index = 0; index < tracked.length;) {
    const status = tracked[index++];
    if (/^[RC]\d*$/.test(status)) {
      if (index + 1 >= tracked.length) fail("tracked transaction inventory contains an incomplete rename");
      add(tracked[index++], "tracked transaction path");
      add(tracked[index++], "tracked transaction path");
    } else {
      if (index >= tracked.length) fail("tracked transaction inventory contains an incomplete entry");
      add(tracked[index++], "tracked transaction path");
    }
  }
  for (const path of nulList(String(fixedGit(root, ["ls-files", "--others", "--exclude-standard", "-z"])), "untracked transaction inventory")) add(path, "untracked transaction path");
  for (const path of nulList(String(fixedGit(root, ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"])), "ignored transaction inventory")) add(path, "ignored transaction path");
  if (values.size > MAX_TRANSACTION_ENTRIES) fail("artifact transaction inventory exceeds its bounded allowance");
  return [...values].sort((left, right) => left.localeCompare(right));
}
function treeShape(root, { allowSpecial = false } = {}) {
  const directories = new Map(), specials = new Set();
  let entries = 0;
  const visit = (directory, prefix = "") => {
    const entriesInDirectory = readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entriesInDirectory) {
      if ([".git", "node_modules"].includes(entry.name)) continue;
      if (++entries > MAX_TRANSACTION_ENTRIES) fail("artifact transaction tree exceeds its bounded allowance");
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      const target = join(directory, entry.name);
      const details = lstatSync(target);
      if (details.isSymbolicLink() || (!details.isDirectory() && !details.isFile())) {
        if (!allowSpecial) fail("artifact transaction baseline contains a linked or special entry");
        specials.add(path);
        continue;
      }
      if (details.isDirectory()) {
        directories.set(path, details.mode & 0o777);
        visit(target, path);
      }
    }
  };
  visit(root);
  return { directories, specials };
}
function sourceFile(root, sourceSha, path) {
  const listing = String(fixedGit(root, ["ls-tree", "-z", sourceSha, "--", `:(literal)${path}`]));
  if (!listing) return null;
  const records = listing.split("\0").filter(Boolean);
  if (records.length !== 1) fail("artifact rollback source path is ambiguous");
  const separator = records[0].indexOf("\t");
  const metadata = separator < 0 ? [] : records[0].slice(0, separator).split(" ");
  const listedPath = separator < 0 ? "" : records[0].slice(separator + 1).replaceAll("\\", "/");
  if (metadata.length !== 3 || !["100644", "100755"].includes(metadata[0]) || metadata[1] !== "blob" || !/^[a-f0-9]{40,64}$/.test(metadata[2]) || listedPath !== path) fail("artifact rollback source path is not a regular file");
  return Object.freeze({ existed: true, mode: metadata[0] === "100755" ? 0o755 : 0o644, bytes: Buffer.from(fixedGit(root, ["cat-file", "blob", metadata[2]], { binary: true })) });
}
function stateFingerprint({ root, sourceSha, control, includeBytes }) {
  const budget = includeBytes ? { entries: 0, bytes: 0 } : null;
  const paths = mutablePaths(root, sourceSha);
  const files = new Map();
  for (const path of paths) {
    const target = assertPlainAncestors(root, join(root, ...path.split("/")));
    const snapshot = plainFileSnapshot(target, `artifact transaction path ${path}`, budget);
    files.set(path, includeBytes ? snapshot : Object.freeze({ ...snapshot, bytes: null }));
  }
  const shape = treeShape(root);
  const metadata = {
    marker: plainFileSnapshot(control.marker, "candidate Git marker"),
    head: plainFileSnapshot(control.head, "candidate Git HEAD"),
    index: plainFileSnapshot(control.index, "candidate Git index")
  };
  const stable = {
    head: String(fixedGit(root, ["rev-parse", "HEAD"])).trim(),
    files: [...files].map(([path, value]) => ({ path, existed: value.existed, mode: value.mode, contentDigest: value.contentDigest })),
    directories: [...shape.directories].sort(([left], [right]) => left.localeCompare(right)).map(([path, mode]) => ({ path, mode })),
    metadata: Object.fromEntries(Object.entries(metadata).map(([name, value]) => [name, { existed: value.existed, mode: value.mode, contentDigest: value.contentDigest }]))
  };
  return { files, directories: shape.directories, metadata, fingerprint: digest(JSON.stringify(stable)) };
}

export function beginArtifactTransaction({ packet }) {
  const root = resolve(packet.worktree);
  const marker = join(root, ".git");
  const markerDetails = lstatOrNull(marker);
  if (markerDetails === null || !markerDetails.isFile() || markerDetails.isSymbolicLink()) fail("artifact transaction requires a linked Git worktree");
  const head = controlPath(root, "HEAD"), index = controlPath(root, "index"), indexLock = `${index}.lock`;
  if (existsSync(indexLock)) fail("artifact transaction cannot start while the Git index is locked");
  if (String(fixedGit(root, ["rev-parse", "HEAD"])).trim() !== packet.sourceSha) fail("artifact transaction source revision differs from the approved packet");
  const control = { marker, head, index, indexLock };
  const baseline = stateFingerprint({ root, sourceSha: packet.sourceSha, control, includeBytes: true });
  let active = true;
  const rollback = () => {
    if (!active) return true;
    try {
      restorePlainFile(control.marker, baseline.metadata.marker);
      if (existsSync(control.indexLock)) unlinkSync(control.indexLock);
      restorePlainFile(control.head, baseline.metadata.head);
      restorePlainFile(control.index, baseline.metadata.index);

      const currentShape = treeShape(root, { allowSpecial: true });
      for (const path of [...currentShape.specials].sort((left, right) => right.split("/").length - left.split("/").length)) {
        const target = resolve(root, ...path.split("/"));
        if (!within(root, target)) fail("artifact rollback special path escapes the worktree");
        rmSync(target, { recursive: false, force: true });
      }
      for (const path of [...currentShape.directories.keys()].filter((path) => !baseline.directories.has(path)).sort((left, right) => right.split("/").length - left.split("/").length)) {
        const target = resolve(root, ...path.split("/"));
        if (!within(root, target)) fail("artifact rollback directory escapes the worktree");
        rmSync(target, { recursive: true, force: true });
      }

      const currentPaths = mutablePaths(root, packet.sourceSha);
      const restorePaths = new Set([...currentPaths, ...baseline.files.keys()]);
      for (const path of [...restorePaths].sort((left, right) => left.localeCompare(right))) {
        const target = resolve(root, ...path.split("/"));
        if (!within(root, target)) fail("artifact rollback path escapes the worktree");
        const desired = baseline.files.get(path) ?? sourceFile(root, packet.sourceSha, path) ?? Object.freeze({ existed: false, mode: null, bytes: null });
        restorePlainFile(target, desired);
      }
      for (const [path, mode] of [...baseline.directories].sort(([left], [right]) => left.split("/").length - right.split("/").length)) {
        const target = resolve(root, ...path.split("/"));
        const details = lstatOrNull(target);
        if (details !== null && (!details.isDirectory() || details.isSymbolicLink())) rmSync(target, { recursive: details.isDirectory() && !details.isSymbolicLink(), force: true });
        mkdirSync(target, { recursive: true });
        chmodSync(target, mode);
      }
      restorePlainFile(control.head, baseline.metadata.head);
      restorePlainFile(control.index, baseline.metadata.index);
      const restored = stateFingerprint({ root, sourceSha: packet.sourceSha, control, includeBytes: false });
      if (restored.fingerprint !== baseline.fingerprint) fail("artifact rollback did not restore the exact baseline");
      active = false;
      return true;
    } catch (error) { throw transactionError(error); }
  };
  return Object.freeze({ rollback, commit: () => { active = false; return true; } });
}

function ensureParent(root, target) {
  const missing = [];
  let current = dirname(target);
  while (current !== root && lstatOrNull(current) === null) { missing.push(current); current = dirname(current); }
  assertPlainAncestors(root, current);
  for (const directory of missing.reverse()) mkdirSync(directory);
}

export function executeArtifact({ artifact, packet, policy, transaction, environment = process.env, spawnSyncImpl = spawnSync }) {
  if (!transaction || typeof transaction.rollback !== "function" || typeof transaction.commit !== "function") fail("artifact execution requires a controller-owned transaction");
  const worktree = resolve(packet.worktree), decisions = [], allowedFiles = [], allowedCommands = [];
  let validationStarted = false;
  for (const [index, operation] of artifact.operations.entries()) {
    if (operation.kind === "run_command") {
      try { assertCommandAllowed(operation.command, policy.commands); validationStarted = true; allowedCommands.push({ index, operation }); decisions.push(decision(operation, index, "allow", "command matches the exact controller allowlist")); }
      catch { decisions.push(decision(operation, index, "deny", "command is outside the exact controller allowlist")); }
      continue;
    }
    if (!pathInScope(operation.path, policy.paths)) { decisions.push(decision(operation, index, "deny", "path is outside the controller write allowlist")); continue; }
    if (validationStarted) fail("allowed file operations must precede controller validation commands");
    const target = assertPlainAncestors(worktree, join(worktree, ...operation.path.split("/")));
    allowedFiles.push({ index, operation, target }); decisions.push(decision(operation, index, "allow", "path matches the controller write allowlist"));
  }
  if (allowedFiles.length === 0) fail("artifact contains no allowed file operation");
  for (const required of policy.commands) if (!allowedCommands.some(({ operation }) => operation.command === required)) fail(`artifact omitted required validation command: ${required}`);

  for (const { operation, target } of allowedFiles) {
    const details = lstatOrNull(target);
    if (details !== null && (!details.isFile() || details.isSymbolicLink())) fail("artifact target is not a plain file");
    ensureParent(worktree, target);
    if (operation.kind === "write_file") writeFileSync(target, operation.content, "utf8");
    else {
      if (!existsSync(target)) fail(`artifact delete target does not exist: ${operation.path}`);
      unlinkSync(target);
    }
  }

  const validationEvidence = [];
  const childEnvironment = { ...scopedEnvironment(policy, environment) };
  for (const { index, operation } of allowedCommands) {
    const launch = commandInvocation(operation.command, childEnvironment);
    const result = spawnSyncImpl(launch.command, launch.args, { cwd: worktree, env: childEnvironment, shell: false, windowsHide: true, encoding: "utf8", timeout: policy.timeouts.turnMs, maxBuffer: MAX_COMMAND_OUTPUT_BYTES });
    const stdout = typeof result?.stdout === "string" ? result.stdout : "";
    const stderr = typeof result?.stderr === "string" ? result.stderr : "";
    const exitCode = Number.isInteger(result?.status) ? result.status : null;
    const outputDigest = digest(`${stdout}\0${stderr}`);
    validationEvidence.push(Object.freeze({ command: operation.command, exitCode: exitCode ?? 1, outputDigest }));
    const existing = decisions.findIndex((entry) => entry.index === index);
    decisions[existing] = decision(operation, index, "allow", exitCode === 0 && !result?.error ? "controller validation passed" : "controller validation failed", { exitCode: exitCode ?? null, outputDigest });
    if (exitCode !== 0 || result?.error) {
      return Object.freeze({ ok: false, decisions: Object.freeze(decisions), validationEvidence: Object.freeze(validationEvidence), appliedPaths: Object.freeze([]) });
    }
  }
  return Object.freeze({ ok: true, decisions: Object.freeze(decisions), validationEvidence: Object.freeze(validationEvidence), appliedPaths: Object.freeze(allowedFiles.map(({ operation }) => operation.path)) });
}

function evidenceDirectory(stateRoot, taskRunId) {
  safeIdentifier(taskRunId, "taskRunId");
  const root = resolve(stateRoot), directory = join(root, "artifacts", taskRunId);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  assertPlainAncestors(root, directory);
  return directory;
}
function atomicJson(path, value) {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`, descriptor = openSync(temporary, "wx", 0o600);
  try { writeFileSync(descriptor, `${JSON.stringify(value)}\n`, "utf8"); } finally { closeSync(descriptor); }
  renameSync(temporary, path);
}
function existingJson(path, label) {
  const details = lstatOrNull(path);
  if (details === null) return null;
  if (!details.isFile() || details.isSymbolicLink()) fail(`${label} is not a plain file`);
  try { return JSON.parse(readFileSync(path, "utf8")); }
  catch { fail(`${label} is malformed`); }
}
function rejectedArtifactCode(error) {
  return REJECTION_CODES.has(error?.code) ? error.code : "artifact_schema_invalid";
}
function valueType(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value === "object" ? "object" : typeof value;
}
function rejectedOperationShape(operation, index) {
  if (!operation || typeof operation !== "object" || Array.isArray(operation)) return Object.freeze({ index, valueType: valueType(operation) });
  const knownFields = ["kind", "path", "content", "command"];
  const kind = operation.kind;
  return Object.freeze({
    index,
    valueType: "object",
    fields: Object.freeze(Object.fromEntries(knownFields.map((field) => [field, Object.hasOwn(operation, field)]))),
    unknownFieldCount: Object.keys(operation).filter((field) => !knownFields.includes(field)).length,
    kind: typeof kind === "string" && DISCLOSED_OPERATION_KINDS.has(kind) ? kind : null,
    kindDigest: typeof kind === "string" ? digest(kind) : null,
    kindBytes: typeof kind === "string" ? Buffer.byteLength(kind, "utf8") : null
  });
}
function emptyRejectedArtifactStructure(jsonType) {
  return Object.freeze({
    jsonType,
    fields: Object.freeze(Object.fromEntries(REJECTED_ARTIFACT_FIELDS.map((field) => [field, false]))),
    unknownFieldCount: null,
    contractVersionMatches: null,
    taskRunIdMatches: null,
    requestIdMatches: null,
    operations: Object.freeze({ valueType: "missing", count: null, truncated: false, items: Object.freeze([]) })
  });
}
function rejectedArtifactStructure(output, packet, outputBytes) {
  if (outputBytes > MAX_ARTIFACT_BYTES) return emptyRejectedArtifactStructure("oversized");
  let value;
  try { value = JSON.parse(output.trim()); }
  catch { return emptyRejectedArtifactStructure("invalid_json"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) return emptyRejectedArtifactStructure(valueType(value));
  const operations = value.operations;
  const items = Array.isArray(operations) ? operations.slice(0, MAX_REJECTED_OPERATION_SHAPES).map(rejectedOperationShape) : [];
  return Object.freeze({
    jsonType: "object",
    fields: Object.freeze(Object.fromEntries(REJECTED_ARTIFACT_FIELDS.map((field) => [field, Object.hasOwn(value, field)]))),
    unknownFieldCount: Object.keys(value).filter((field) => !REJECTED_ARTIFACT_FIELDS.includes(field)).length,
    contractVersionMatches: typeof value.contractVersion === "string" ? value.contractVersion === ARTIFACT_CONTRACT_VERSION : null,
    taskRunIdMatches: typeof value.taskRunId === "string" ? value.taskRunId === packet.taskRunId : null,
    requestIdMatches: typeof value.requestId === "string" ? value.requestId === packet.requestId : null,
    operations: Object.freeze({ valueType: valueType(operations), count: Array.isArray(operations) ? operations.length : null, truncated: Array.isArray(operations) && operations.length > MAX_REJECTED_OPERATION_SHAPES, items: Object.freeze(items) })
  });
}
export function persistRejectedArtifactEvidence({ stateRoot, packet, output, error, outputTruncated = false, recordedAt = new Date().toISOString() }) {
  if (typeof output !== "string") fail("rejected artifact output must be text");
  if (typeof outputTruncated !== "boolean") fail("rejected artifact outputTruncated must be boolean");
  safeIdentifier(packet.taskRunId, "taskRunId"); safeIdentifier(packet.requestId, "requestId");
  const directory = evidenceDirectory(stateRoot, packet.taskRunId);
  const rejectedArtifactPath = join(directory, `${packet.requestId}.rejected.json`);
  const errorMessage = error instanceof Error ? error.message : String(error ?? "");
  const outputBytes = Buffer.byteLength(output, "utf8");
  const outputDigest = digest(output);
  const record = { contractVersion: ARTIFACT_REJECTION_VERSION, taskRunId: packet.taskRunId, requestId: packet.requestId, recordedAt, outputDigest, outputBytes, outputTruncated, rejectionCode: rejectedArtifactCode(error), errorDigest: digest(errorMessage), structure: rejectedArtifactStructure(output, packet, outputBytes) };
  const prior = existingJson(rejectedArtifactPath, "rejected artifact evidence");
  if (prior !== null) {
    const { recordedAt: _priorRecordedAt, ...priorStable } = prior;
    const { recordedAt: _recordedAt, ...recordStable } = record;
    if (digest(JSON.stringify(priorStable)) !== digest(JSON.stringify(recordStable))) fail("rejected artifact evidence conflicts with an existing record");
  } else atomicJson(rejectedArtifactPath, record);
  return Object.freeze({ rejectedArtifactPath, outputDigest });
}
export function persistArtifactEvidence({ stateRoot, artifact }) {
  safeIdentifier(artifact.requestId, "requestId");
  const directory = evidenceDirectory(stateRoot, artifact.taskRunId);
  const artifactPath = join(directory, `${artifact.requestId}.artifact.json`);
  const decisionPath = join(directory, `${artifact.requestId}.decision.json`);
  const artifactDigest = digest(JSON.stringify(artifact));
  const prior = existingJson(artifactPath, "artifact evidence");
  if (prior !== null) {
    if (digest(JSON.stringify(prior)) !== artifactDigest) fail("artifact evidence conflicts with an existing record");
  } else atomicJson(artifactPath, artifact);
  return Object.freeze({ artifactPath, decisionPath, artifactDigest });
}
export function persistArtifactDecision({ stateRoot, artifact, artifactEvidence, execution, recordedAt = new Date().toISOString() }) {
  exact(artifactEvidence, ["artifactPath", "decisionPath", "artifactDigest"], "artifact evidence receipt");
  const directory = evidenceDirectory(stateRoot, artifact.taskRunId);
  const artifactPath = join(directory, `${artifact.requestId}.artifact.json`), decisionPath = join(directory, `${artifact.requestId}.decision.json`);
  if (artifactEvidence.artifactPath !== artifactPath || artifactEvidence.decisionPath !== decisionPath || !/^sha256:[a-f0-9]{64}$/.test(artifactEvidence.artifactDigest)) fail("artifact evidence receipt does not match the task");
  const record = { contractVersion: ARTIFACT_DECISION_VERSION, taskRunId: artifact.taskRunId, requestId: artifact.requestId, artifactDigest: artifactEvidence.artifactDigest, recordedAt, ok: execution.ok, decisions: execution.decisions, validationEvidence: execution.validationEvidence, appliedPaths: execution.appliedPaths };
  const prior = existingJson(decisionPath, "artifact decision evidence");
  if (prior !== null) {
    const { recordedAt: _priorRecordedAt, ...priorStable } = prior;
    const { recordedAt: _recordedAt, ...recordStable } = record;
    if (digest(JSON.stringify(priorStable)) !== digest(JSON.stringify(recordStable))) fail("artifact decision evidence conflicts with an existing record");
  } else atomicJson(decisionPath, record);
  return Object.freeze({ decisionPath, artifactDigest: artifactEvidence.artifactDigest });
}

export function prepareArtifactScratch({ stateRoot, taskRunId, requestId }) {
  safeIdentifier(taskRunId, "taskRunId"); safeIdentifier(requestId, "requestId");
  const root = resolve(stateRoot), parent = join(root, "provider-scratch", taskRunId), target = join(parent, requestId);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  assertPlainAncestors(root, parent);
  try { mkdirSync(target, { mode: 0o700 }); }
  catch (error) { if (error?.code === "EEXIST") fail("provider scratch already exists"); throw error; }
  assertPlainAncestors(root, target);
  const details = lstatSync(target);
  if (!details.isDirectory()) fail("provider scratch is not a plain directory");
  return target;
}

export function removeArtifactScratch(path) {
  const target = resolve(path);
  const details = lstatSync(target);
  if (!details.isDirectory() || details.isSymbolicLink()) fail("provider scratch is not a plain directory");
  if (readdirSync(target).length !== 0) fail("provider scratch was mutated");
  rmdirSync(target);
  return true;
}
