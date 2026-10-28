import { createHash } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { secretFreeAuthorityRecord } from "./authority-safety.mjs";
import { CONTRACT_VERSIONS, validateTaskPacket } from "./contracts.mjs";

export const TASK_POLICY_VERSION = CONTRACT_VERSIONS.runPolicy;
export const APPROVED_TASK_TOOLS = Object.freeze(["read_file", "grep", "list_dir", "search_replace", "run_terminal_cmd"]);
// These are the minimum variables needed by Grok and the approved local
// validation commands on Windows. They are copied only when present; no
// caller environment is inherited implicitly. Artifact-only launches must
// then replace GROK_HOME, HOME, USERPROFILE, LOCALAPPDATA, and APPDATA with
// a dedicated empty config root. Forwarding the operator values is the
// isolation leak: empty --tools, --deny MCPTool(*), and [compat.codex]
// mcps=false do not stop MCP init or Claude plugin merge.
export const FIXED_WINDOWS_ENVIRONMENT_KEYS = Object.freeze([
  "COMSPEC", "GROK_HOME", "HOME", "LANG", "LOCALAPPDATA", "PATH",
  "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE"
]);
const SECRET_NAME = /(?:^|_)(?:api[_-]?key|access[_-]?key|token|secret|credential|password|authorization|cookie|private[_-]?key)(?:$|_)/i;
const SHELL_SYNTAX = /[\u0000-\u001f\u007f();`|&<>$%^!]/;
const WRAPPER_TOKENS = new Set(["cmd", "cmd.exe", "command", "powershell", "powershell.exe", "pwsh", "pwsh.exe", "sh", "sh.exe", "bash", "bash.exe", "start", "call"]);
const DENIED_EXECUTABLES = new Set([
  "curl", "wget", "ssh", "scp", "gcloud", "kubectl", "invoke-webrequest",
  "rm", "del", "rmdir", "remove-item"
]);
// These commands have a positional subcommand, but also accept global
// options before it. Only options known to consume a following value are
// skipped; unknown options remain positional so a denied subcommand cannot be
// hidden behind an option-shaped token.
const SUBCOMMAND_POLICIES = Object.freeze({
  git: Object.freeze({ denied: new Set(["push", "remote"]), valueOptions: new Set(["-c", "--config", "--exec-path", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "-C"]) }),
  gh: Object.freeze({ denied: new Set(["pr", "release"]), valueOptions: new Set(["--repo", "-R", "--hostname", "--org", "--app", "--jq", "--template", "--json", "--limit", "--state", "--search"]) }),
  npm: Object.freeze({ denied: new Set(["publish"]), valueOptions: new Set(["--workspace", "-w", "--prefix", "--userconfig", "--registry", "--cache", "--tag", "--otp", "--scope"]) }),
  pnpm: Object.freeze({ denied: new Set(["publish"]), valueOptions: new Set(["--dir", "-C", "--filter", "-F", "--workspace-root"]) }),
  yarn: Object.freeze({ denied: new Set(["publish"]), valueOptions: new Set(["--cwd", "--cache-folder", "--registry"]) }),
  docker: Object.freeze({ denied: new Set(["push"]), valueOptions: new Set(["--config", "-c", "--context", "-H", "--host", "--log-level", "--tlscacert", "--tlscert", "--tlskey", "--cert-dir"]) })
});

function fail(message) { throw new TypeError(message); }
function digest(value) { return `sha256:${createHash("sha256").update(value).digest("hex")}`; }
function canonical(value) { if (value === null || typeof value !== "object") return JSON.stringify(value); if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`; return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`; }
export function packetDigest(packet) { if (!packet || typeof packet !== "object") fail("task packet is required"); const copy = structuredClone(packet); if (copy.approval) copy.approval = { ...copy.approval, packetDigest: null }; return digest(canonical(copy)); }
function safeRelative(value, label) { if (typeof value !== "string" || !value.trim() || isAbsolute(value)) fail(`${label} must be repository-relative`); const normalized = value.replaceAll("\\", "/"); if (normalized.split("/").some((part) => !part || part === "." || part === "..") || normalized === ".git" || normalized.startsWith(".git/")) fail(`${label} escapes the worktree`); return normalized; }

/** Match repository paths by whole segments; `/**` is the only recursive form. */
export function pathMatchesPattern(pattern, candidate) {
  if (typeof pattern !== "string" || typeof candidate !== "string") return false;
  const p = pattern.replaceAll("\\", "/"), c = candidate.replaceAll("\\", "/");
  if (!p || p.startsWith("/") || c.startsWith("/")) return false;
  if (c === "") return p === "**";
  const ps = p.split("/"), cs = c.split("/");
  if (ps.some((part) => !part || part === "." || part === "..") || cs.some((part) => !part || part === "." || part === "..")) return false;
  if (ps.at(-1) === "**") return cs.length >= ps.length - 1 && ps.slice(0, -1).every((part, i) => part === "*" || part === cs[i]);
  if (ps.length !== cs.length) return false;
  return ps.every((part, i) => part === "*" || part === cs[i]);
}
export function pathInScope(path, allowedPaths) { return Array.isArray(allowedPaths) && allowedPaths.some((pattern) => pathMatchesPattern(pattern, path)); }

/** Parse one command without invoking a shell. Quoting groups a token only. */
export function commandTokens(command) {
  if (typeof command !== "string" || !command.trim() || SHELL_SYNTAX.test(command)) fail("command contains unsupported shell syntax");
  const tokens = []; let token = ""; let quote = null;
  for (const char of command.trim()) {
    if (quote) { if (char === quote) quote = null; else token += char; continue; }
    if (char === "'" || char === '"') { quote = char; continue; }
    if (/\s/.test(char)) { if (token) { tokens.push(token); token = ""; } continue; }
    token += char;
  }
  if (quote || !token && tokens.length === 0) fail("command contains malformed quoting");
  if (token) tokens.push(token);
  if (tokens.some((value) => value.includes("*") || value.includes("?"))) fail("wildcard command tokens are not permitted");
  return Object.freeze(tokens);
}
function firstSubcommand(tokens, policy) {
  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith("-")) return token.toLowerCase();
    if (token.includes("=")) continue;
    if (policy.valueOptions.has(token)) index += 1;
  }
  return null;
}
function deniedCommand(tokens) {
  const executable = tokens[0]?.toLowerCase();
  const baseExecutable = executable?.replace(/\.(?:cmd|exe)$/i, "");
  if (!executable || WRAPPER_TOKENS.has(executable) || WRAPPER_TOKENS.has(baseExecutable) || executable.includes("/" ) || executable.includes("\\")) return true;
  if (DENIED_EXECUTABLES.has(executable) || DENIED_EXECUTABLES.has(baseExecutable)) return true;
  const policy = SUBCOMMAND_POLICIES[executable] ?? SUBCOMMAND_POLICIES[baseExecutable];
  return policy ? policy.denied.has(firstSubcommand(tokens, policy)) : false;
}
export function commandsMatch(command, approved) {
  try { return JSON.stringify(commandTokens(command)) === JSON.stringify(commandTokens(approved)); } catch { return false; }
}
export function exactCommandRule(command) { const tokens = commandTokens(command); if (deniedCommand(tokens)) fail("command is denied by task policy"); return `Bash(${tokens.map((token) => token.includes(" ") ? JSON.stringify(token) : token).join(" ")})`; }
export function assertCommandAllowed(command, allowedCommands) {
  const tokens = commandTokens(command); if (deniedCommand(tokens)) fail("command is denied by task policy");
  if (!Array.isArray(allowedCommands) || !allowedCommands.some((approved) => commandsMatch(command, approved))) fail("command is outside the approved task policy");
  return command;
}
export function createTaskPolicy(packet) { validateTaskPacket(packet); if (!secretFreeAuthorityRecord(packet)) fail("task packet contains secret-shaped authority data"); if (Date.parse(packet.approval.expiresAt) <= Date.now()) fail("task approval is expired"); if (packet.approval.packetDigest !== packetDigest(packet)) fail("task approval packet digest does not match the canonical task packet"); const allowedTools = new Set(APPROVED_TASK_TOOLS); if (packet.policy.tools.some((tool) => !allowedTools.has(tool))) fail("task policy requests an unapproved tool"); for (const key of packet.policy.allowedEnvironment) if (SECRET_NAME.test(key)) fail(`secret-shaped environment key is not allowed: ${key}`); if (packet.policy.network === "public_read") fail("public_read network policy is unavailable: Grok CLI cannot enforce official-doc destination allowlists"); for (const command of packet.policy.allowedCommands) exactCommandRule(command); return Object.freeze({ contractVersion: TASK_POLICY_VERSION, taskRunId: packet.taskRunId, requestId: packet.requestId, delivery: packet.delivery, worktree: resolve(packet.worktree), paths: Object.freeze([...packet.policy.allowedPaths]), commands: Object.freeze([...packet.policy.allowedCommands]), environment: Object.freeze([...packet.policy.allowedEnvironment]), network: packet.policy.network, tools: Object.freeze([...packet.policy.tools]), timeouts: Object.freeze({ ...packet.policy.timeouts }), repairBudget: packet.policy.repairBudget }); }
export function scopedEnvironment(packetOrPolicy, source = process.env) { const policy = packetOrPolicy.contractVersion === TASK_POLICY_VERSION ? packetOrPolicy : createTaskPolicy(packetOrPolicy); const result = {}; const keys = new Set([...FIXED_WINDOWS_ENVIRONMENT_KEYS, ...policy.environment]); for (const key of keys) { if (SECRET_NAME.test(key)) continue; if (typeof source[key] === "string") result[key] = source[key]; } return Object.freeze(result); }
export function assertWorktreePath(worktree, candidate) { const root = resolve(worktree), target = resolve(candidate); const rest = relative(root, target); if (rest === "" || rest.split(sep).some((part) => part === "..")) fail("candidate path escapes the approved worktree"); return target; }
function assertScopedPath(path, allowedPaths) { const normalized = safeRelative(path, "changed path"); if (!pathInScope(normalized, allowedPaths)) fail(`changed path is outside the approved scope: ${normalized}`); return normalized; }
export function validateChangedFiles(entries, policy) { if (!Array.isArray(entries)) fail("changed-file inventory must be an array"); return entries.map((entry) => { if (!entry || typeof entry.path !== "string") fail("changed-file inventory entry is malformed"); const status = String(entry.status ?? "M").toUpperCase().replace(/\d+$/, ""); if (!["A", "M", "D", "R", "C", "U"].includes(status)) fail(`changed-file status is unsupported: ${status}`); const normalized = { ...entry, status, path: assertScopedPath(entry.path, policy.paths) }; if (entry.previousPath !== undefined) normalized.previousPath = assertScopedPath(entry.previousPath, policy.paths); return normalized; }); }
export function validatePolicyCommand(command, policy) { return assertCommandAllowed(command, policy.commands); }
