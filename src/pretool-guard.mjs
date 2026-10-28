import { existsSync, lstatSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { assertCommandAllowed, pathInScope } from "./task-policy.mjs";

export const PRETOOL_GUARD_VERSION = "agent-platform.grok-pretool-guard.v1";

const TOOL_ALIASES = Object.freeze({
  Bash: "run_terminal_cmd",
  run_terminal_cmd: "run_terminal_cmd",
  run_terminal_command: "run_terminal_cmd",
  Read: "read_file",
  read_file: "read_file",
  Grep: "grep",
  grep: "grep",
  Glob: "list_dir",
  list_dir: "list_dir",
  Edit: "search_replace",
  MultiEdit: "search_replace",
  search_replace: "search_replace"
});

function deny(reason) { return Object.freeze({ decision: "deny", reason }); }
function safePath(root, candidate) {
  if (typeof candidate !== "string" || candidate.includes("\0") || candidate.startsWith("\\\\?\\") || candidate.startsWith("\\\\.\\")) return null;
  const target = resolve(root, candidate);
  const rest = relative(resolve(root), target);
  if (!(rest === "" || (!isAbsolute(rest) && !rest.split(sep).includes("..")))) return null;
  const withoutDrive = /^[A-Za-z]:[\\/]/.test(target) ? target.slice(2) : target;
  if (withoutDrive.includes(":")) return null;
  const canonicalRoot = realpathSync.native(resolve(root));
  let current = resolve(root);
  const parts = rest === "" ? [] : rest.split(sep);
  for (const part of parts) {
    current = resolve(current, part);
    if (!existsSync(current)) break;
    const details = lstatSync(current);
    if (details.isSymbolicLink()) return null;
    const canonical = realpathSync.native(current);
    const canonicalRest = relative(canonicalRoot, canonical);
    if (canonicalRest !== "" && (isAbsolute(canonicalRest) || canonicalRest.split(sep).includes(".."))) return null;
  }
  return target;
}
function relativePath(root, candidate) { return relative(resolve(root), resolve(root, candidate)).replaceAll("\\", "/"); }
function inputPath(tool, input, root) {
  if (tool === "read_file") return input.target_file ?? input.path ?? input.file_path;
  if (tool === "list_dir") return input.target_directory ?? input.directory ?? input.path ?? root;
  if (tool === "grep") return input.path ?? input.directory ?? root;
  if (tool === "search_replace") return input.file_path ?? input.path ?? input.target_file;
  return undefined;
}
function normalizeEventName(value) { return typeof value === "string" && ["pre_tool_use", "pretooluse"].includes(value.toLowerCase().replaceAll("-", "_")) ? "PreToolUse" : null; }
/** Normalize Grok's documented snake_case hook envelope and legacy aliases. */
export function normalizePreToolUseEvent(event) {
  if (!event || typeof event !== "object" || Array.isArray(event)) return null;
  const hookEventName = normalizeEventName(event.hookEventName ?? event.hook_event_name ?? event.event);
  let toolInput = event.toolInput ?? event.tool_input ?? event.input ?? event.arguments;
  if (typeof toolInput === "string") { try { toolInput = JSON.parse(toolInput); } catch { return null; } }
  if (!hookEventName || !toolInput || typeof toolInput !== "object" || Array.isArray(toolInput)) return null;
  return Object.freeze({
    hookEventName,
    sessionId: event.sessionId ?? event.session_id ?? event.params?.sessionId ?? event.params?.session_id,
    cwd: event.cwd ?? event.working_directory ?? event.workingDirectory,
    workspaceRoot: event.workspaceRoot ?? event.workspace_root ?? event.workspace,
    toolName: event.toolName ?? event.tool_name ?? event.tool,
    toolInput
  });
}
function validPolicy(policy) {
  return policy && policy.contractVersion === PRETOOL_GUARD_VERSION && typeof policy.worktree === "string" && isAbsolute(policy.worktree) && typeof policy.sessionId === "string" && Array.isArray(policy.paths) && Array.isArray(policy.commands) && Array.isArray(policy.tools) && ["none"].includes(policy.network);
}

export function evaluatePreToolUse(event, policy) {
  if (!validPolicy(policy)) return deny("Grok Build Engineer guard policy is invalid");
  const normalizedEvent = normalizePreToolUseEvent(event);
  if (!normalizedEvent || typeof normalizedEvent.toolName !== "string") return deny("Malformed PreToolUse event");
  event = normalizedEvent;
  if (event.sessionId !== policy.sessionId) return deny("Tool call session is outside the approved Grok session");
  if (typeof event.workspaceRoot !== "string" || typeof event.cwd !== "string" || safePath(policy.worktree, event.workspaceRoot) === null || safePath(policy.worktree, event.cwd) === null) return deny("Tool call working directory is outside the approved worktree");
  const tool = TOOL_ALIASES[event.toolName];
  if (!tool || !policy.tools.includes(tool)) return deny(`Tool is outside the approved policy: ${event.toolName}`);
  if (tool === "run_terminal_cmd") {
    if (event.toolInput.is_background === true || event.toolInput.isBackground === true) return deny("Background commands are not authorized");
    if (typeof event.toolInput.command !== "string" || /[\u0000-\u001f\u007f();`|&<>$%^!]/.test(event.toolInput.command) || /^(?:cmd(?:\.exe)?\s+\/(?:c|k)|powershell(?:\.exe)?\s+(?:-|\/)|pwsh(?:\.exe)?\s+-|start\b|call\b)/i.test(event.toolInput.command.trim())) return deny("Command contains unsupported shell syntax");
    try { assertCommandAllowed(event.toolInput.command, policy.commands); }
    catch { return deny("Command is outside the approved task policy"); }
    return Object.freeze({ decision: "allow" });
  }
  const candidate = inputPath(tool, event.toolInput, policy.worktree);
  const admittedPath = safePath(policy.worktree, candidate);
  if (admittedPath === null) return deny("Tool path is outside the approved worktree");
  const path = relativePath(policy.worktree, admittedPath);
  // The admitted, secret-filtered snapshot is the read boundary. allowedPaths
  // is the narrower mutation boundary and is independently rechecked from Git.
  if (tool === "search_replace" && !pathInScope(path, policy.paths)) return deny(`Edit path is outside the approved scope: ${path}`);
  return Object.freeze({ decision: "allow" });
}
