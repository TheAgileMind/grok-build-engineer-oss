import { createHash } from "node:crypto";

import { isAbsolutePath, validateGrant } from "./contracts.mjs";
import { redactForBoundary } from "./redaction.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const ENFORCEMENT = new Set(["provider_enforced", "os_enforced", "trusted_host"]);
const EFFECT_CAPABILITIES = new Set(["network_read", "network_mutation", "native_push", "deployment", "publication", "credential_helper", "dependency_lifecycle", "connected_mcp_mutation"]);
const CALLER_APPROVAL_FIELDS = new Set(["approval", "approved", "signature", "signed", "issuer", "receipt", "receiptDigest", "grant", "authorization"]);

export class CapabilityDeniedError extends Error { constructor(message) { super(message); this.name = "CapabilityDeniedError"; } }
export class ProfileDriftError extends Error { constructor(message) { super(message); this.name = "ProfileDriftError"; } }
export class ChildAuthorityMismatchError extends Error { constructor(message) { super(message); this.name = "ChildAuthorityMismatchError"; } }

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
function digest(value) { return `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`; }
function clone(value) { return structuredClone(value); }
function freeze(value) { Object.freeze(value); Object.values(value).filter((entry) => entry && typeof entry === "object" && !Object.isFrozen(entry)).forEach(freeze); return value; }
function deny(capability, reason) { throw new CapabilityDeniedError(`${capability} denied: ${reason}`); }
function validDigest(value, label) { if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError(`${label} must be a sha256 digest`); return value; }
function sameSet(left, right) { return left.length === right.length && left.every((entry, index) => entry === right[index]); }
function sortedStrings(value, label) {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string" || !entry)) throw new TypeError(`${label} must be a string array`);
  const result = [...new Set(value)].sort();
  if (result.length !== value.length) throw new TypeError(`${label} must not contain duplicates`);
  return result;
}
function safeEnvironmentKeys(value, label) {
  const keys = sortedStrings(value, label);
  if (keys.some((key) => /(?:^|_)(?:api_?key|access_?key|token|secret|credential|password|auth(?:entication|orization)?)(?:$|_)/i.test(key) || key === "NODE_OPTIONS" || /^(?:GIT|SSH)_/i.test(key) || /(?:^|_)PROXY(?:$|_)/i.test(key))) {
    throw new TypeError(`${label} must not admit credentials, API keys, process injection, Git/SSH, or proxy variables`);
  }
  return keys;
}
function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  const actual = Object.keys(value).sort(), expected = [...keys].sort();
  if (!sameSet(actual, expected)) throw new TypeError(`${label} has unsupported or missing fields`);
}
function matrix(capability, decision, enforcementClass, disclosureScope, proof, interceptionPoint = "profile_matrix") {
  return { capability, decision, interceptionPoint, denialResponse: "deny_before_prompt_and_emit_redacted_capability_denied", enforcementClass, disclosureScope, providerFreeProof: proof };
}
const SHARED_LIMITS = freeze({ initializationTimeoutMs: 30_000, idleTimeoutMs: 300_000, overallTimeoutMs: 3_600_000, cancellationTimeoutMs: 30_000, maximumFrameBytes: 1_048_576, maximumEventBytes: 131_072, maximumEventsPerMinute: 240, maximumActiveJobs: 1 });
const MATRIX = freeze({
  hermetic: [
    matrix("native_engineering", "allow", "os_enforced", "worktree_only", "fake hermetic child completes a local edit"),
    matrix("builtin_tools", "allow", "os_enforced", "worktree_only", "fake hermetic child inventory matches"),
    matrix("skills_plugins", "deny", "os_enforced", "none", "attempt is rejected before launch"),
    matrix("mcp_read", "deny", "os_enforced", "none", "attempt is rejected before launch"),
    matrix("dependency_lifecycle", "deny", "os_enforced", "none", "lifecycle hook request is rejected"),
    matrix("network_read", "deny", "os_enforced", "none", "network request is rejected"),
    matrix("network_mutation", "deny", "os_enforced", "none", "network mutation is rejected"),
    matrix("credential_helper", "deny", "os_enforced", "none", "credential helper is rejected"),
    matrix("native_push", "deny", "os_enforced", "none", "push request is rejected"),
    matrix("deployment", "deny", "os_enforced", "none", "deployment request is rejected"),
    matrix("publication", "deny", "os_enforced", "none", "publication request is rejected"),
    matrix("connected_mcp_mutation", "deny", "os_enforced", "none", "connected MCP mutation is rejected")
  ],
  "trusted-local": [
    matrix("native_engineering", "allow", "trusted_host", "admitted_worktree_only", "fake inspection freezes fixed executable, argv, cwd, and command allowlist"),
    matrix("builtin_tools", "allow", "trusted_host", "admitted_worktree_only", "fake child parity inventory matches"),
    matrix("skills_plugins", "allow", "trusted_host", "public_or_worktree_only", "fake child parity inventory matches skills, plugins, hooks, subagents, memory, and config discovery"),
    matrix("mcp_read", "allow", "trusted_host", "local_approved_readonly_only", "exact child MCP inventory contains only locally approved read-only MCPs"),
    matrix("local_dependency_lifecycle", "allow", "trusted_host", "admitted_worktree_offline_only", "exact child inventory permits only governed offline dependency lifecycle commands"),
    matrix("dependency_lifecycle", "deny", "trusted_host", "none", "lifecycle hook request is rejected"),
    matrix("network_read", "grant_required", "trusted_host", "exact_public_disclosure_grant", "one-use local-policy grant fixture is bound and consumed"),
    matrix("network_mutation", "deny", "trusted_host", "none", "network mutation request is rejected"),
    matrix("credential_helper", "deny", "trusted_host", "none", "credential helper request is rejected"),
    matrix("native_push", "deny", "trusted_host", "none", "push request is rejected"),
    matrix("deployment", "deny", "trusted_host", "none", "deployment request is rejected"),
    matrix("publication", "deny", "trusted_host", "none", "publication request is rejected"),
    matrix("connected_mcp_mutation", "deny", "trusted_host", "none", "connected MCP mutation request is rejected")
  ],
  connected: [
    matrix("native_engineering", "unavailable", "trusted_host", "none", "not provider-free provable"),
    matrix("builtin_tools", "unavailable", "trusted_host", "none", "not provider-free provable"),
    matrix("skills_plugins", "unavailable", "trusted_host", "none", "not provider-free provable"),
    matrix("mcp_read", "unavailable", "trusted_host", "none", "not provider-free provable"),
    matrix("dependency_lifecycle", "unavailable", "trusted_host", "none", "not provider-free provable"),
    matrix("network_read", "unavailable", "trusted_host", "none", "protected grant source not live-proven"),
    matrix("network_mutation", "unavailable", "trusted_host", "none", "protected grant source not live-proven"),
    matrix("credential_helper", "unavailable", "trusted_host", "none", "credential boundary not live-proven"),
    matrix("native_push", "unavailable", "trusted_host", "none", "external-effect boundary not live-proven"),
    matrix("deployment", "unavailable", "trusted_host", "none", "external-effect boundary not live-proven"),
    matrix("publication", "unavailable", "trusted_host", "none", "external-effect boundary not live-proven"),
    matrix("connected_mcp_mutation", "unavailable", "trusted_host", "none", "MCP mutation boundary not live-proven")
  ]
});
const INVENTORY_ALLOWLIST = freeze({
  hermetic: { nativeCommands: ["git_status", "npm_test"], builtIns: ["read_file", "write_file"], skills: [], plugins: [], hooks: [], subagents: [], memory: [], config: [], mcps: [], network: [], credentialHelpers: [] },
  "trusted-local": { nativeCommands: ["git_diff", "git_status", "npm_ci_offline", "npm_install_offline", "npm_run_build", "npm_run_test", "npm_run_verify", "npm_test"], builtIns: ["read_file", "write_file"], skills: ["native_skills"], plugins: ["native_plugins"], hooks: ["native_hooks"], subagents: ["native_subagents"], memory: ["native_memory"], config: ["grok_home_or_userprofile"], mcps: ["local_readonly_approved"], network: ["public_read_via_protected_grant"], credentialHelpers: [] },
  connected: { nativeCommands: [], builtIns: [], skills: [], plugins: [], hooks: [], subagents: [], memory: [], config: [], mcps: [], network: [], credentialHelpers: [] }
});
const PROFILES = freeze({
  hermetic: { profileId: "hermetic", name: "Hermetic regression", status: "approved", enforcementClass: "os_enforced", limits: SHARED_LIMITS, argv: ["--no-auto-update", "agent", "stdio"], cwdPolicy: "admitted_worktree_only", environmentKeys: ["LANG", "PATH"], commandAllowlist: ["git_status", "npm_test"], matrix: MATRIX.hermetic, inventoryAllowlist: INVENTORY_ALLOWLIST.hermetic },
  "trusted-local": { profileId: "trusted-local", name: "Trusted local engineer", status: "approved", enforcementClass: "trusted_host", limits: SHARED_LIMITS, argv: ["--no-auto-update", "agent", "stdio"], cwdPolicy: "admitted_worktree_only", environmentKeys: ["COMSPEC", "GROK_HOME", "HOME", "LANG", "LOCALAPPDATA", "PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE"], commandAllowlist: INVENTORY_ALLOWLIST["trusted-local"].nativeCommands, matrix: MATRIX["trusted-local"], inventoryAllowlist: INVENTORY_ALLOWLIST["trusted-local"] },
  connected: { profileId: "connected", name: "Connected engineer", status: "unavailable_pending_live_proof", enforcementClass: "trusted_host", limits: SHARED_LIMITS, argv: ["--no-auto-update", "agent", "stdio"], cwdPolicy: "admitted_worktree_only", environmentKeys: ["COMSPEC", "GROK_HOME", "HOME", "LANG", "LOCALAPPDATA", "PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE"], commandAllowlist: [], matrix: MATRIX.connected, inventoryAllowlist: INVENTORY_ALLOWLIST.connected }
});

function validateProfile(profile) {
  if (!profile || typeof profile !== "object" || !PROFILES[profile.profileId]) throw new TypeError("profile must be a named immutable profile");
  if (canonical(profile) !== canonical(PROFILES[profile.profileId])) throw new CapabilityDeniedError("profile differs from the immutable named profile");
  if (!ENFORCEMENT.has(profile.enforcementClass)) throw new TypeError("profile has an invalid enforcement class");
  if (!profile.matrix.length || profile.matrix.some((entry) => !ENFORCEMENT.has(entry.enforcementClass) || !entry.interceptionPoint || !entry.denialResponse || !entry.providerFreeProof)) throw new TypeError("profile capability matrix is incomplete");
  safeEnvironmentKeys(profile.environmentKeys, "profile environment keys");
  if (profile.profileId === "trusted-local" && !["GROK_HOME", "USERPROFILE"].every((key) => profile.environmentKeys.includes(key))) throw new TypeError("trusted-local must support safe Windows Grok config discovery");
  for (const value of Object.values(profile.limits)) if (!Number.isInteger(value) || value < 1) throw new TypeError("profile limits must be finite positive integers");
  return profile;
}

export function getCapabilityProfile(profileId) {
  if (typeof profileId !== "string" || !PROFILES[profileId]) throw new CapabilityDeniedError("unknown capability profile");
  return clone(validateProfile(PROFILES[profileId]));
}

export function profileFingerprint(profile) {
  const selected = validateProfile(profile);
  return digest({ profileId: selected.profileId, status: selected.status, enforcementClass: selected.enforcementClass, limits: selected.limits, argv: selected.argv, cwdPolicy: selected.cwdPolicy, environmentKeys: [...selected.environmentKeys].sort(), commandAllowlist: [...selected.commandAllowlist].sort(), matrix: selected.matrix, inventoryAllowlist: selected.inventoryAllowlist });
}

function sanitizeInspection(evidence) {
  return redactForBoundary({ executable: { digest: evidence.executable.digest }, argv: evidence.argv, cwdPolicy: evidence.cwdPolicy, environmentKeys: evidence.environmentKeys, inventoryDigest: evidence.inventoryDigest, capabilities: evidence.capabilities, containment: { claimed: evidence.containment.claimed, osBoundaryVerified: evidence.containment.osBoundaryVerified === true } });
}
function environmentBindingDigest(profile, environment) {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) throw new TypeError("environment must be an object");
  const sanitized = safeProfileEnvironment(profile, environment);
  const states = Object.fromEntries(profile.environmentKeys.map((key) => {
    const present = Object.hasOwn(sanitized, key);
    const value = sanitized[key];
    return [key, present ? { present: true, value } : { present: false }];
  }));
  return digest({ environmentKeys: profile.environmentKeys, states });
}
// Codex prepends one per-invocation shim directory to PATH. Nested Codex
// launches retain older shims, so more than one exact shim may be present.
// Remove every exact match under the attested user's actual Codex root before
// both attestation and child launch. Ignored invocation noise therefore cannot
// shadow a command in the delegated engineering process.
function stripEphemeralCodexArg0Path(value, environment) {
  const userProfile = typeof environment.USERPROFILE === "string" && environment.USERPROFILE.length > 0
    ? environment.USERPROFILE.replace(/[\\/]+$/, "").replaceAll("/", "\\")
    : null;
  if (userProfile === null) return value;
  const segments = value.split(";");
  const expectedRoot = `${userProfile}\\.codex\\tmp\\arg0\\`.toLowerCase();
  return segments.filter((segment) => {
    if (!/(?:^|[\\/])\.codex[\\/]tmp[\\/]arg0[\\/]codex-arg0[a-z0-9]{6}$/i.test(segment)) return true;
    return !segment.replaceAll("/", "\\").toLowerCase().startsWith(expectedRoot);
  }).join(";");
}
export function safeProfileEnvironment(profile, environment = process.env) {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) throw new TypeError("environment must be an object");
  return Object.freeze(Object.fromEntries(profile.environmentKeys
    .filter((key) => Object.hasOwn(environment, key) && environment[key] !== undefined)
    .map((key) => {
      if (typeof environment[key] !== "string") throw new TypeError(`environment.${key} must be a string when present`);
      return [key, key.toUpperCase() === "PATH" ? stripEphemeralCodexArg0Path(environment[key], environment) : environment[key]];
    })));
}
function validateEvidence(profile, evidence) {
  exactKeys(evidence, ["executable", "argv", "cwdPolicy", "environmentKeys", "inventoryDigest", "capabilities", "containment"], "inspection evidence");
  exactKeys(evidence.executable, ["path", "digest"], "inspection executable");
  if (!evidence.executable || typeof evidence.executable.path !== "string" || !isAbsolutePath(evidence.executable.path)) throw new TypeError("inspection executable path must be absolute");
  validDigest(evidence.executable.digest, "inspection executable digest");
  validDigest(evidence.inventoryDigest, "inspection inventory digest");
  const argv = sortedStrings(evidence.argv, "inspection argv"), profileArgv = sortedStrings(profile.argv, "profile argv");
  if (!sameSet(argv, profileArgv) || evidence.argv.join("\u0000") !== profile.argv.join("\u0000")) throw new ProfileDriftError("fixed argv differs from profile");
  if (evidence.cwdPolicy !== profile.cwdPolicy) throw new ProfileDriftError("cwd policy differs from profile");
  if (!sameSet(safeEnvironmentKeys(evidence.environmentKeys, "inspection environment keys"), [...profile.environmentKeys].sort())) throw new ProfileDriftError("minimal environment differs from profile");
  exactKeys(evidence.capabilities, ["nativeCommands", "builtIns", "skills", "plugins", "hooks", "subagents", "memory", "config", "mcps", "network", "credentialHelpers"], "inspection capabilities");
  for (const [category, allowed] of Object.entries(profile.inventoryAllowlist)) {
    const observed = sortedStrings(evidence.capabilities[category], `inspection capabilities.${category}`);
    if (!sameSet(observed, [...allowed].sort())) throw new ProfileDriftError(`${category} differs from the frozen authority inventory`);
  }
  exactKeys(evidence.containment, ["claimed", "osBoundaryVerified"], "containment evidence");
  if (!evidence.containment || typeof evidence.containment.claimed !== "string" || typeof evidence.containment.osBoundaryVerified !== "boolean") throw new TypeError("containment evidence is malformed");
  if (!["os_sandboxed", "trusted_host"].includes(evidence.containment.claimed)) throw new ProfileDriftError("containment claim is unsupported");
  if (evidence.containment.claimed === "os_sandboxed" && evidence.containment.osBoundaryVerified !== true) throw new ProfileDriftError("false enforced-sandbox claim");
  if (profile.enforcementClass === "os_enforced" && (evidence.containment.claimed !== "os_sandboxed" || evidence.containment.osBoundaryVerified !== true)) throw new ProfileDriftError("profile requires a verified OS enforcement boundary");
  if (profile.enforcementClass === "trusted_host" && (evidence.containment.claimed !== "trusted_host" || evidence.containment.osBoundaryVerified !== false)) throw new ProfileDriftError("trusted-host profile must not claim an enforced sandbox");
}

export function buildProfileAttestation(profile, inspectionEvidence, { now = new Date().toISOString(), environment = process.env } = {}) {
  const selected = validateProfile(profile);
  if (selected.status !== "approved") throw new CapabilityDeniedError(`profile ${selected.profileId} is unavailable pending live proof`);
  validateEvidence(selected, inspectionEvidence);
  const profileDigest = profileFingerprint(selected);
  const inspection = sanitizeInspection(inspectionEvidence);
  const environmentDigest = environmentBindingDigest(selected, environment);
  return freeze({ profileId: selected.profileId, profileDigest, fingerprint: digest({ profile: profileDigest, inspection, environmentDigest }), attestedAt: now, enforcementClass: selected.enforcementClass, executable: { path: inspectionEvidence.executable.path, digest: inspectionEvidence.executable.digest }, argv: [...selected.argv], cwdPolicy: selected.cwdPolicy, environmentKeys: [...selected.environmentKeys], environmentDigest, commandAllowlist: [...selected.commandAllowlist], matrix: clone(selected.matrix), inspection });
}

export function verifyAttestedEnvironment(attestation, { environment = process.env } = {}) {
  if (!attestation || typeof attestation !== "object") throw new TypeError("attestation is required");
  const profile = getCapabilityProfile(attestation.profileId);
  if (attestation.profileDigest !== profileFingerprint(profile) || attestation.environmentDigest !== environmentBindingDigest(profile, environment)) throw new ProfileDriftError("frozen launch environment drift detected");
  return { ok: true, environmentDigest: attestation.environmentDigest };
}

export function verifyProfileDrift(attestation, inspectionEvidence, { environment = process.env } = {}) {
  if (!attestation || typeof attestation !== "object") throw new TypeError("attestation is required");
  const profile = getCapabilityProfile(attestation.profileId);
  if (attestation.profileDigest !== profileFingerprint(profile)) throw new ProfileDriftError("frozen profile digest differs from named profile");
  validateEvidence(profile, inspectionEvidence);
  const nowInspection = sanitizeInspection(inspectionEvidence);
  verifyAttestedEnvironment(attestation, { environment });
  if (attestation.executable.digest !== inspectionEvidence.executable.digest || attestation.executable.path !== inspectionEvidence.executable.path || canonical(attestation.inspection) !== canonical(nowInspection)) throw new ProfileDriftError("capability inspection drift detected");
  return { ok: true, fingerprint: attestation.fingerprint, enforcementClass: attestation.enforcementClass };
}

export function verifyChildAuthorityParity(attestation, childInspectionEvidence, { environment = process.env } = {}) {
  try { verifyProfileDrift(attestation, childInspectionEvidence, { environment }); }
  catch (error) { throw new ChildAuthorityMismatchError(`child authority parity failed: ${error.message}`); }
  return { ok: true, profileDigest: attestation.profileDigest, enforcementClass: attestation.enforcementClass };
}

function assertNoCallerApproval(request) {
  if (!request || typeof request !== "object" || Array.isArray(request)) throw new TypeError("external-effect request must be an object");
  if (Object.keys(request).some((key) => CALLER_APPROVAL_FIELDS.has(key))) throw new TypeError("caller-supplied approval material is forbidden");
}
function assertContext(context) {
  exactKeys(context, ["jobId", "worktreeCustodyDigest", "profileDigest", "worktreeClass", "disclosureMode"], "external-effect context");
  if (!Object.values(context).every((value) => typeof value === "string" && value)) throw new TypeError("external-effect context must contain non-empty strings");
}
function assertExternalRequest(request) {
  assertNoCallerApproval(request);
  exactKeys(request, ["operation", "service", "direction", "dataClass", "sourcePath", "recipient", "endpoint", "payloadBoundary"], "external-effect request");
  if (!Object.values(request).every((value) => typeof value === "string" && value)) throw new TypeError("external-effect request must contain non-empty strings");
}
function publicSourcePath(path) { return path === "docs/public.md" || path.startsWith("docs/public/"); }
function publicEndpoint(endpoint) {
  try { const parsed = new URL(endpoint); return parsed.protocol === "https:" && !parsed.username && !parsed.password && !parsed.search && !parsed.hash; }
  catch { return false; }
}
function assertLocalPolicyCeiling(grant) {
  if (grant.operation !== "network_read" || grant.service !== "public_web" || grant.direction !== "egress" ||
      !sameSet([...grant.dataClasses].sort(), ["public_source"]) || !grant.sourcePaths.every(publicSourcePath) ||
      !sameSet([...grant.recipients].sort(), ["public_web"]) || !grant.endpoints.every(publicEndpoint) ||
      grant.payloadBoundary !== "host_mediated_public_only") throw new CapabilityDeniedError("local-policy fixtures only permit public-source read-only research");
}
function match(value, allowed, label) { if (!allowed.includes(value)) deny("protected_grant", `${label} is outside disclosure scope`); }
function grantBindingMatches(grant, context, request) {
  if (grant.jobId !== context.jobId || grant.worktreeCustodyDigest !== context.worktreeCustodyDigest || grant.profileDigest !== context.profileDigest) deny("protected_grant", "job, worktree, or profile binding differs");
  if (grant.operation !== request.operation || grant.service !== request.service || grant.direction !== request.direction) deny("protected_grant", "operation, service, or direction differs");
  match(request.dataClass, grant.dataClasses, "data class"); match(request.sourcePath, grant.sourcePaths, "source path"); match(request.recipient, grant.recipients, "recipient"); match(request.endpoint, grant.endpoints, "endpoint");
  if (grant.payloadBoundary !== request.payloadBoundary) deny("protected_grant", "payload boundary differs");
}

export function createLocalPolicyGrantAuthority(records) {
  if (!Array.isArray(records)) throw new TypeError("local-policy grant fixtures must be an array");
  const entries = new Map();
  const nonces = new Set();
  for (const input of records) {
    const grant = validateGrant(clone(input));
    if (grant.authorityClass !== "local_policy" || grant.issuer !== "local_policy") throw new TypeError("only provider-free local-policy fixtures may be loaded");
    assertLocalPolicyCeiling(grant);
    if (entries.has(grant.grantId)) throw new TypeError("grant fixtures must have unique grant IDs");
    if (nonces.has(grant.nonce)) throw new TypeError("grant fixtures must have unique one-use nonces");
    nonces.add(grant.nonce);
    entries.set(grant.grantId, { grant, consumed: false });
  }
  return freeze({
    kind: "local_policy_fixture",
    read(grantId) { const entry = entries.get(grantId); if (!entry) deny("protected_grant", "unknown protected grant"); return clone(entry); },
    consume(grantId, nonce) { const entry = entries.get(grantId); if (!entry || entry.grant.nonce !== nonce) deny("protected_grant", "grant nonce differs"); if (entry.consumed) deny("protected_grant", "grant was already consumed"); entry.consumed = true; }
  });
}

export function evaluateExternalEffect({ attestation, capability, request, context, grantId = null, grantAuthority = null, now = new Date().toISOString() }) {
  assertExternalRequest(request); assertContext(context);
  if (!attestation || !Array.isArray(attestation.matrix)) throw new TypeError("frozen attestation is required");
  const entry = attestation.matrix.find((candidate) => candidate.capability === capability);
  if (!entry) deny(capability, "capability is not in the frozen matrix");
  if (entry.decision === "deny" || entry.decision === "unavailable") deny(capability, entry.decision === "unavailable" ? "profile is unavailable pending live proof" : "frozen profile matrix");
  if (entry.decision === "allow" && !EFFECT_CAPABILITIES.has(capability)) return { allowed: true, capability, enforcementClass: entry.enforcementClass, profileDigest: attestation.profileDigest };
  if (entry.decision !== "grant_required") deny(capability, "external effects require an exact protected grant");
  if (!grantAuthority || grantAuthority.kind !== "local_policy_fixture") deny(capability, "human-enforced grants are unavailable without an activated broker");
  if (typeof grantId !== "string") deny(capability, "protected grant reference is required");
  const record = grantAuthority.read(grantId), grant = record.grant;
  if (Date.parse(grant.expiresAt) <= Date.parse(now)) deny(capability, "protected grant is expired");
  if (grant.authorityClass !== "local_policy" || grant.issuer !== "local_policy") deny(capability, "unverifiable authority class");
  if (context.worktreeClass !== "public_worktree" || context.disclosureMode !== "public_source_readonly") deny(capability, "local-policy research requires an explicit public worktree disclosure mode");
  assertLocalPolicyCeiling(grant);
  if (!publicSourcePath(request.sourcePath) || !publicEndpoint(request.endpoint) || request.operation !== "network_read" || request.service !== "public_web" || request.direction !== "egress" || request.dataClass !== "public_source" || request.recipient !== "public_web" || request.payloadBoundary !== "host_mediated_public_only") deny(capability, "request exceeds the public-source read-only ceiling");
  grantBindingMatches(grant, context, request);
  grantAuthority.consume(grantId, grant.nonce);
  return { allowed: true, capability, enforcementClass: entry.enforcementClass, profileDigest: attestation.profileDigest, grantDigest: digest(grant), disclosureScope: entry.disclosureScope };
}

export function redactProfileDiagnostic(value) {
  const strip = (entry) => {
    if (Array.isArray(entry)) return entry.map(strip);
    if (typeof entry === "string") return entry.replace(/https?:\/\/[^\s"']+/gi, "[REDACTED_URL]");
    if (!entry || typeof entry !== "object") return entry;
    return Object.fromEntries(Object.entries(entry)
      .filter(([key]) => !/(?:^|_)(?:url|uri|endpoint|env|environment|permission|authorization)(?:$|_)/i.test(key))
      .map(([key, child]) => [key, strip(child)]));
  };
  return redactForBoundary(strip(value));
}
