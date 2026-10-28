import { createHash } from "node:crypto";
import { closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";

import { createJobService } from "./job-service.mjs";
import { launchAcpChild } from "./acp-session.mjs";
import { createHeadlessSessionAdapter } from "./headless-session.mjs";
import { buildProfileAttestation, getCapabilityProfile, profileFingerprint, safeProfileEnvironment, verifyChildAuthorityParity } from "./profiles.mjs";
import { CONTRACT_VERSIONS, validateJobAuthority } from "./contracts.mjs";
import { secretFreeAuthorityRecord } from "./authority-safety.mjs";

export const ACTIVATION_ENV = "GROK_BUILD_ENGINEER_ACTIVATION_MANIFEST";
export const ACTIVATION_VERSION = "agent-platform.grok-build-engineer-activation.v3";
const LEGACY_ACTIVATION_VERSION = "agent-platform.grok-build-engineer-activation.v2";
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const MAX_MANIFEST_BYTES = 32 * 1024;
const MAX_INSPECT_BYTES = 2 * 1024 * 1024;
const SECRET = /(?:api[_-]?key|access[_-]?key|token|secret|credential|password|authorization|cookie|private[_-]?key)/i;
const MANIFEST_KEYS = ["contractVersion", "runtimeId", "runtimeApprovalDigest", "stateRoot", "grokExecutable", "grokExecutableDigest", "inventoryDigest", "profileId", "trustedHostAcknowledgement", "repositoryRoot", "destinationRoot", "dataClasses", "expiresAt"];
const LEGACY_MANIFEST_KEYS = ["contractVersion", "authorityId", "approvalScopeDigest", "sourceSha", "stateRoot", "grokExecutable", "grokExecutableDigest", "inventoryDigest", "profileId", "trustedHostAcknowledgement", "repositoryRoot", "destinationRoot", "dataClasses", "expiresAt", "receiptDigests"];
const RECEIPT_KEYS = ["provider", "privateDisclosure", "cost", "externalEffect"];
const PROFILE_REATTESTATION_PERMIT_KEYS = ["permitId", "profileId", "profileDigest", "oldAttestationFingerprint", "oldAttestationDigest", "newAttestationFingerprint", "expiresAt"];
const PROFILE_COMMANDS = Object.freeze({
  git_diff: "git diff", git_status: "git status", npm_ci_offline: "npm ci --offline",
  npm_install_offline: "npm install --offline", npm_run_build: "npm run build",
  npm_run_test: "npm run test", npm_run_verify: "npm run verify", npm_test: "npm test"
});

export class ActivationConfigError extends Error { constructor(message = "Local activation is unavailable") { super(message); this.name = "ActivationConfigError"; } }
export class ActivationAuthorityError extends Error {
  constructor(category, evidenceDigest = null, diagnostics = null) {
    super("Protected host authority denied the request");
    this.name = "ActivationAuthorityError";
    this.category = category;
    this.evidenceDigest = evidenceDigest;
    this.diagnostics = diagnostics;
  }
}
function exact(value, keys, label) { if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("|") !== [...keys].sort().join("|")) throw new ActivationConfigError(`${label} is invalid`); return value; }
function shaFile(path) { return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`; }
function canonical(value) { if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`; if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`; return JSON.stringify(value); }
function digest(value) { return `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`; }
function plainFile(path, label, maximum = MAX_MANIFEST_BYTES) { try { const details = lstatSync(path); if (!details.isFile() || details.isSymbolicLink() || details.size < 2 || details.size > maximum) throw new Error(); return details; } catch { throw new ActivationConfigError(`${label} is unavailable`); } }
function plainDirectory(path, label) { try { const details = lstatSync(path); if (!details.isDirectory() || details.isSymbolicLink()) throw new Error(); return resolve(path); } catch { throw new ActivationConfigError(`${label} is unavailable`); } }
function plainExistingAncestor(path, label) { let current = resolve(path); for (;;) { try { const details = lstatSync(current); if (details.isSymbolicLink() || !details.isDirectory()) throw new Error(); return current; } catch (error) { if (error?.code !== "ENOENT") throw new ActivationConfigError(`${label} is unavailable`); const parent = resolve(current, ".."); if (parent === current) throw new ActivationConfigError(`${label} is unavailable`); current = parent; } } }
function assertAbsolute(path, label) { if (typeof path !== "string" || !isAbsolute(path)) throw new ActivationConfigError(`${label} is invalid`); return resolve(path); }
function inside(child, parent) { const relation = relative(resolve(parent), resolve(child)); return relation === "" || (!relation.startsWith("..") && !isAbsolute(relation)); }
function safeDigest(value, label) { if (typeof value !== "string" || !DIGEST.test(value) || value === `sha256:${"0".repeat(64)}`) throw new ActivationConfigError(`${label} is invalid`); return value; }
function identifier(value, label) { if (typeof value !== "string" || !/^[a-z][a-z0-9_-]{2,63}$/.test(value)) throw new ActivationConfigError(`${label} is invalid`); return value; }
function jobAuthorityDirectory(manifest) { return join(manifest.stateRoot, "job-authorities"); }
function loadJobAuthorities(manifest) {
  const directory = jobAuthorityDirectory(manifest);
  try {
    const details = lstatSync(directory);
    if (!details.isDirectory() || details.isSymbolicLink()) throw new Error();
    const entries = readdirSync(directory, { withFileTypes: true });
    const authorities = entries.filter((entry) => entry.isFile() && /^[a-z][a-z0-9_-]{2,63}\.json$/.test(entry.name)).map((entry) => {
      const path = join(directory, entry.name); plainFile(path, "job authority");
      const value = JSON.parse(readFileSync(path, "utf8")); validateJobAuthority(value);
      if (value.runtimeId !== manifest.runtimeId) return null;
      if (!secretFreeAuthorityRecord(value) || value.receiptDigest === `sha256:${"0".repeat(64)}`) throw new Error();
      return Object.freeze(value);
    }).filter(Boolean);
    if (entries.some((entry) => !entry.isFile() || !/^[a-z][a-z0-9_-]{2,63}\.json$/.test(entry.name))) throw new Error();
    return authorities;
  } catch { throw new ActivationConfigError("job authority store is invalid"); }
}
function matchingJobAuthority(manifest, request, now) {
  const matches = loadJobAuthorities(manifest).filter((entry) => entry.sourceSha === request.sourceSha && entry.dataClasses.includes(request.dataClass) && Date.parse(entry.expiresAt) > now.getTime());
  return matches.length === 1 ? matches[0] : null;
}
function validateReattestationPermit(value, manifestExpiry) {
  exact(value, PROFILE_REATTESTATION_PERMIT_KEYS, "profile re-attestation permit");
  identifier(value.permitId, "profile re-attestation permitId");
  if (value.profileId !== "trusted-local") throw new ActivationConfigError("profile re-attestation permit is invalid");
  safeDigest(value.profileDigest, "profile re-attestation profileDigest");
  safeDigest(value.newAttestationFingerprint, "profile re-attestation new fingerprint");
  const oldFingerprint = value.oldAttestationFingerprint, oldDigest = value.oldAttestationDigest;
  if ((oldFingerprint === null) === (oldDigest === null)) throw new ActivationConfigError("profile re-attestation prior identity is invalid");
  if (oldFingerprint !== null) safeDigest(oldFingerprint, "profile re-attestation old fingerprint");
  if (oldDigest !== null) safeDigest(oldDigest, "profile re-attestation old digest");
  const expiry = Date.parse(value.expiresAt);
  if (!Number.isFinite(expiry) || expiry > manifestExpiry) throw new ActivationConfigError("profile re-attestation expiry is invalid");
  return Object.freeze(structuredClone(value));
}

function windowsEnvironmentValue(environment, key) {
  if (typeof environment?.[key] === "string") return environment[key];
  const matched = Object.keys(environment ?? {}).find((candidate) => candidate.toUpperCase() === key);
  return matched && typeof environment[matched] === "string" ? environment[matched] : undefined;
}

function killHeadlessProcessTree(child, environment = process.env) {
  if (!child || !Number.isSafeInteger(child.pid) || child.pid < 1) { try { child?.kill?.(); } catch {} return; }
  if (process.platform !== "win32") {
    try { process.kill(-child.pid, "SIGTERM"); return; } catch { try { child.kill(); } catch {} return; }
  }
  const systemRoot = windowsEnvironmentValue(environment, "SYSTEMROOT");
  try {
    if (typeof systemRoot === "string" && isAbsolute(systemRoot)) {
      const taskkill = resolve(systemRoot, "System32", "taskkill.exe");
      plainFile(taskkill, "process-tree cancellation executable", 16 * 1024 * 1024);
      spawnSync(taskkill, ["/pid", String(child.pid), "/t", "/f"], { shell: false, windowsHide: true, stdio: "ignore", timeout: 5_000, env: Object.fromEntries(["COMSPEC", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE"].map((key) => [key, windowsEnvironmentValue(environment, key)]).filter(([, value]) => typeof value === "string")) });
      return;
    }
  } catch { /* child.kill below remains the bounded fallback. */ }
  try { child.kill(); } catch {}
}

export function defaultProcessInspector({ pid }, environment = process.env, run = spawnSync) {
  const systemRoot = windowsEnvironmentValue(environment, "SYSTEMROOT");
  if (process.platform !== "win32" || !Number.isSafeInteger(pid) || pid < 1 || typeof systemRoot !== "string" || !isAbsolute(systemRoot)) return { state: "unknown" };
  const powershell = resolve(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const script = `$p=Get-Process -Id ${pid} -ErrorAction SilentlyContinue; if($null -eq $p){exit 3}; [pscustomobject]@{pid=[int]$p.Id;startedAt=$p.StartTime.ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress`;
  try {
    plainFile(powershell, "process inspector executable", 16 * 1024 * 1024);
    const result = run(powershell, ["-NoProfile", "-NonInteractive", "-Command", script], { shell: false, windowsHide: true, timeout: 5_000, maxBuffer: 8 * 1024, encoding: "utf8", env: Object.fromEntries(["COMSPEC", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE"].map((key) => [key, windowsEnvironmentValue(environment, key)]).filter(([, value]) => typeof value === "string")) });
    if (result?.status === 3) return { state: "absent" };
    if (result?.status !== 0 || typeof result.stdout !== "string") return { state: "unknown" };
    const identity = JSON.parse(result.stdout);
    if (!identity || identity.pid !== pid || typeof identity.startedAt !== "string" || Number.isNaN(Date.parse(identity.startedAt))) return { state: "unknown" };
    return { state: "present", identity: { pid, startedAt: new Date(identity.startedAt).toISOString() } };
  } catch { return { state: "unknown" }; }
}
function reattestationProofMatchesPermit(proof, request, permit) {
  if (!proof || typeof proof !== "object" || Array.isArray(proof) || proof.contractVersion !== "agent-platform.grok-builder-legacy-profile-reattestation.v1" ||
      proof.jobId !== request.jobId || proof.profileId !== permit.profileId || proof.profileDigest !== permit.profileDigest ||
      proof.contextDigest !== request.contextDigest || proof.sourceCustodyDigest !== request.sourceCustodyDigest ||
      typeof proof.worktreeCustodyDigest !== "string" && proof.worktreeCustodyDigest !== null) return false;
  if (proof.worktreeCustodyDigest !== null && !DIGEST.test(proof.worktreeCustodyDigest)) return false;
  if (proof.operation === "repair_profile_reattestation_v1") {
    if (Object.keys(proof).sort().join("|") !== ["contractVersion", "operation", "jobId", "profileId", "profileDigest", "oldAttestationFingerprint", "newAttestationFingerprint", "contextDigest", "sourceCustodyDigest", "worktreeCustodyDigest"].sort().join("|")) return false;
    return proof.oldAttestationFingerprint === permit.oldAttestationFingerprint && permit.oldAttestationDigest === null && proof.newAttestationFingerprint === permit.newAttestationFingerprint;
  }
  if (proof.operation === "repair_profile_reattestation") {
    if (Object.keys(proof).sort().join("|") !== ["contractVersion", "operation", "jobId", "profileId", "profileDigest", "legacyAttestationDigest", "currentAttestationFingerprint", "contextDigest", "sourceCustodyDigest", "worktreeCustodyDigest"].sort().join("|")) return false;
    return proof.legacyAttestationDigest === permit.oldAttestationDigest && permit.oldAttestationFingerprint === null && proof.currentAttestationFingerprint === permit.newAttestationFingerprint;
  }
  return false;
}

/** Loads a reviewable, non-secret local authority record. It cannot select this path from MCP arguments. */
export function loadActivationManifest({ environment = process.env, now = new Date(), allowExpired = false } = {}) {
  const supplied = environment[ACTIVATION_ENV];
  if (typeof supplied !== "string" || !isAbsolute(supplied)) throw new ActivationConfigError();
  const path = resolve(supplied); plainFile(path, "activation manifest");
  let manifest; try { manifest = JSON.parse(readFileSync(path, "utf8")); } catch { throw new ActivationConfigError("activation manifest is unavailable"); }
  const legacy = manifest?.contractVersion === LEGACY_ACTIVATION_VERSION;
  exact(manifest, [...(legacy ? LEGACY_MANIFEST_KEYS : MANIFEST_KEYS), ...(Object.hasOwn(manifest, "profileReattestationPermit") ? ["profileReattestationPermit"] : [])], "activation manifest");
  if (!secretFreeAuthorityRecord(manifest) || ![ACTIVATION_VERSION, LEGACY_ACTIVATION_VERSION].includes(manifest.contractVersion) || manifest.trustedHostAcknowledgement !== "trusted_host_not_os_sandbox") throw new ActivationConfigError("activation manifest is invalid");
  if (legacy) {
    identifier(manifest.authorityId, "authorityId"); safeDigest(manifest.approvalScopeDigest, "approval scope digest");
    if (typeof manifest.sourceSha !== "string" || !/^[a-f0-9]{40}$/.test(manifest.sourceSha)) throw new ActivationConfigError("activation source SHA is invalid");
    exact(manifest.receiptDigests, RECEIPT_KEYS, "activation receipts"); for (const value of Object.values(manifest.receiptDigests)) safeDigest(value, "receipt digest");
    manifest.runtimeId = manifest.authorityId;
  } else { identifier(manifest.runtimeId, "runtimeId"); safeDigest(manifest.runtimeApprovalDigest, "runtime approval digest"); }
  for (const key of ["stateRoot", "grokExecutable", "repositoryRoot", "destinationRoot"]) manifest[key] = assertAbsolute(manifest[key], key);
  if (manifest.profileId !== "trusted-local" || [manifest.repositoryRoot, manifest.destinationRoot, manifest.stateRoot].some((root, index, all) => all.some((other, otherIndex) => index !== otherIndex && inside(root, other)))) throw new ActivationConfigError("activation roots or profile are invalid");
  plainDirectory(manifest.repositoryRoot, "repository root"); plainDirectory(manifest.destinationRoot, "destination root"); plainExistingAncestor(manifest.stateRoot, "state root");
  safeDigest(manifest.grokExecutableDigest, "executable digest"); safeDigest(manifest.inventoryDigest, "inventory digest");
  if (!Array.isArray(manifest.dataClasses) || !manifest.dataClasses.length || manifest.dataClasses.some((entry) => typeof entry !== "string" || !/^[a-z][a-z0-9_-]{2,63}$/.test(entry))) throw new ActivationConfigError("data classes are invalid");
  const expiry = Date.parse(manifest.expiresAt); if (!Number.isFinite(expiry) || (!allowExpired && expiry <= now.getTime())) throw new ActivationConfigError("activation authority expired");
  if (Object.hasOwn(manifest, "profileReattestationPermit")) manifest.profileReattestationPermit = validateReattestationPermit(manifest.profileReattestationPermit, expiry);
  // This also rejects unknown and pending profiles before a child is launched.
  getCapabilityProfile(manifest.profileId);
  plainFile(manifest.grokExecutable, "Grok executable", 256 * 1024 * 1024);
  if (shaFile(manifest.grokExecutable) !== manifest.grokExecutableDigest) throw new ActivationConfigError("Grok executable differs from activation authority");
  return Object.freeze(manifest);
}

function worktreeRelative(value, worktree) {
  if (typeof value !== "string" || !worktree) return value;
  try { return inside(value, worktree) ? `<WORKTREE>/${relative(resolve(worktree), resolve(value)).replaceAll("\\\\", "/")}` : value; } catch { return value; }
}
export function inventoryProjection(raw, { worktree = null } = {}) {
  // Preserve exactness without persisting or emitting paths, names, URLs, or
  // plugin/MCP configuration: every scalar is one-way hashed in memory.
  const opaque = (value) => {
    // `grok inspect --json` does not guarantee inventory collection order.
    // Treat arrays as multisets: canonical sorting removes presentation-order
    // drift while retaining duplicates and every opaque element value.
    if (Array.isArray(value)) return value.map(opaque).sort((left, right) => canonical(left).localeCompare(canonical(right)));
    if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, SECRET.test(key) ? "<SECRET_PRESENT>" : opaque(value[key])]));
    return `sha256:${createHash("sha256").update(String(worktreeRelative(value, worktree))).digest("hex")}`;
  };
  const section = (value) => digest(opaque(value ?? null));
  return { plugins: section(raw.plugins), skills: section(raw.skills), agents: section(raw.agents), hooks: section(raw.hooks), mcpServers: section(raw.mcpServers), marketplaces: section(raw.marketplaces), configSources: section(raw.configSources), permissions: section(raw.permissions), projectTrusted: raw.projectTrusted === true };
}
export function inventoryDigestFor(raw, { worktree = null } = {}) { return digest(inventoryProjection(raw, { worktree })); }
function evidenceFor(profile, manifest, raw, worktree) {
  const profileInventory = profile.inventoryAllowlist;
  return {
    executable: { path: manifest.grokExecutable, digest: manifest.grokExecutableDigest }, argv: [...profile.argv], cwdPolicy: profile.cwdPolicy,
    environmentKeys: [...profile.environmentKeys], inventoryDigest: inventoryDigestFor(raw, { worktree }),
    capabilities: structuredClone(profileInventory), containment: { claimed: "trusted_host", osBoundaryVerified: false }
  };
}

/** Runs the only permitted inspection form. The runner is injectable solely for provider-free tests. */
export function inspectGrok({ manifest, worktree, environment = process.env, runner = spawnSync } = {}) {
  if (!manifest || (resolve(worktree) !== manifest.repositoryRoot && !inside(worktree, manifest.destinationRoot))) throw new ActivationConfigError("worktree is not admitted");
  const result = runner(manifest.grokExecutable, ["--no-auto-update", "--cwd", resolve(worktree), "inspect", "--json"], { shell: false, windowsHide: true, timeout: 30_000, maxBuffer: MAX_INSPECT_BYTES, encoding: "utf8", env: environment });
  if (!result || result.error || result.status !== 0 || typeof result.stdout !== "string" || Buffer.byteLength(result.stdout) > MAX_INSPECT_BYTES) throw new ActivationConfigError("Grok inspection failed");
  let raw; try { raw = JSON.parse(result.stdout); } catch { throw new ActivationConfigError("Grok inspection failed"); }
  const profile = getCapabilityProfile(manifest.profileId), evidence = evidenceFor(profile, manifest, raw, resolve(worktree));
  if (evidence.inventoryDigest !== manifest.inventoryDigest) throw new ActivationConfigError("Grok inventory differs from activation authority");
  const grokVersion = typeof raw.version === "string" && raw.version.length <= 256 && !SECRET.test(raw.version) ? raw.version : "unavailable";
  return Object.freeze({ evidence, projection: inventoryProjection(raw, { worktree: resolve(worktree) }), grokVersion });
}

export { safeProfileEnvironment };
export function createPermissionPolicy(manifest, profile = getCapabilityProfile(manifest.profileId)) {
  const commands = new Set(profile.commandAllowlist.map((capability) => PROFILE_COMMANDS[capability]).filter(Boolean));
  return Object.freeze({
    classify(params, input = null) {
      if (!params || typeof params !== "object" || Array.isArray(params) || !Array.isArray(params.options) || !params.options.every((option) => option && typeof option.optionId === "string")) return null;
      const tool = params.toolCall?.kind;
      const optionIds = params.options.filter((option) => option.kind === "allow_once").map((option) => option.optionId);
      if (!optionIds.length || typeof tool !== "string") return null;
      if (tool === "think") return { operation: "local_think", optionIds };
      if (["read", "edit", "delete", "move", "search"].includes(tool)) {
        const worktree = input?.worktree, locations = params.toolCall?.locations;
        if (typeof worktree !== "string" || !isAbsolute(worktree) || !inside(worktree, manifest.destinationRoot) || !Array.isArray(locations) || locations.length === 0) return null;
        const root = resolve(worktree), paths = [];
        for (const location of locations) {
          if (!location || typeof location !== "object" || Array.isArray(location) || typeof location.path !== "string" || !isAbsolute(location.path) || !inside(location.path, root)) return null;
          paths.push(process.platform === "win32" ? resolve(location.path).toLowerCase() : resolve(location.path));
        }
        return { operation: `local_${tool}`, optionIds, scopeDigest: digest({ worktree: process.platform === "win32" ? root.toLowerCase() : root, paths: [...new Set(paths)].sort() }) };
      }
      if (tool === "execute" && params.toolCall?.rawInput && typeof params.toolCall.rawInput === "object" && !Array.isArray(params.toolCall.rawInput) && Object.keys(params.toolCall.rawInput).sort().join("|") === "command" && typeof params.toolCall.rawInput.command === "string" && commands.has(params.toolCall.rawInput.command)) return { operation: "local_engineering", optionIds };
      // External effects belong to an exact job authority.  This runtime-wide
      // permission adapter has no job identity, so it must not infer a fetch
      // authorization from a stable activation.
      if (tool === "fetch") return null;
      return null;
    },
    authorize(classified) { return classified && classified.optionIds.length ? { allowed: true, optionId: classified.optionIds[0] } : { allowed: false }; }
  });
}

export function createActivatedService({ environment = process.env, now = null, clock = () => new Date(), runner = spawnSync, launch = launchAcpChild, headlessSpawn = spawn, processInspector = defaultProcessInspector, jobServiceFactory = createJobService, jobServiceOptions = {}, onAuthorityDiagnostic = null, allowExpiredActivation = false } = {}) {
  const current = () => { const value = clock(); const date = value instanceof Date ? value : new Date(value); if (Number.isNaN(date.getTime())) throw new ActivationConfigError("activation clock is invalid"); return date; };
  const initialNow = now ?? current();
  const manifest = loadActivationManifest({ environment, now: initialNow, allowExpired: allowExpiredActivation });
  const profile = getCapabilityProfile(manifest.profileId);
  const localEnvironment = safeProfileEnvironment(profile, environment);
  // This binds project-local Grok instructions/config as well as the trusted
  // host inventory. Each activation record admits one exact repository.
  const inspected = inspectGrok({ manifest, worktree: manifest.repositoryRoot, environment: localEnvironment, runner });
  const attestation = buildProfileAttestation(profile, inspected.evidence, { now: initialNow.toISOString(), environment: localEnvironment });
  const permissions = createPermissionPolicy(manifest, profile);
  const activeChildren = new Set();
  // Recovery inspection is a host-control operation, not delegated child
  // authority. Use only the inspector's fixed OS-variable allowlist from the
  // raw host environment so a frozen Grok profile that attested SYSTEMROOT as
  // absent cannot make Windows process-loss recovery permanently impossible.
  const inspectRuntimeProcess = processInspector === defaultProcessInspector
    ? (identity) => defaultProcessInspector(identity, environment)
    : processInspector;
  const profileFactory = (profileId) => {
    if (profileId !== manifest.profileId) throw new ActivationConfigError("profile is not admitted");
    // Preflight before every submission catches executable and extension drift before prompt.
    const fresh = inspectGrok({ manifest, worktree: manifest.repositoryRoot, environment: localEnvironment, runner });
    const refreshed = buildProfileAttestation(profile, fresh.evidence, { now: current().toISOString(), environment: localEnvironment });
    if (refreshed.fingerprint !== attestation.fingerprint) throw new ActivationConfigError("Grok inspection drifted");
    return { profileId, profileDigest: profileFingerprint(profile), attestation, inspection: fresh.evidence };
  };
  const consumeReattestationPermit = (request) => {
    const permit = manifest.profileReattestationPermit, proof = request?.profileReattestationProof;
    if (!permit || !proof || request.legacyRecoveryProfileProofDigest !== digest(proof) || !reattestationProofMatchesPermit(proof, request, permit) || Date.parse(permit.expiresAt) <= current().getTime()) return false;
    const requestDigest = digest(request), proofDigest = digest(proof), directory = resolve(manifest.stateRoot, "profile-reattestation-permits"), path = join(directory, `${permit.permitId}.json`);
    try {
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      const details = lstatSync(directory); if (!details.isDirectory() || details.isSymbolicLink()) return false;
      const record = { contractVersion: "agent-platform.grok-builder-profile-reattestation-use.v1", permitId: permit.permitId, requestDigest, proofDigest };
      let descriptor;
      try {
        descriptor = openSync(path, "wx", 0o600); writeFileSync(descriptor, `${JSON.stringify(record)}\n`, "utf8"); fsyncSync(descriptor);
        return true;
      } catch (error) {
        if (error?.code !== "EEXIST") return false;
        const existingDetails = lstatSync(path); if (!existingDetails.isFile() || existingDetails.isSymbolicLink() || existingDetails.size > 8 * 1024) return false;
        const existing = JSON.parse(readFileSync(path, "utf8"));
        return canonical(existing) === canonical(record);
      } finally { if (descriptor !== undefined) closeSync(descriptor); }
    } catch { return false; }
  };
  const authority = (request) => {
    const exactScopes = ["provider", "private_disclosure", "cost", "worktree"];
    const denied = (category) => {
      const evidenceDigest = category === "profile_reattestation" ? request?.profileReattestationProof?.newAttestationFingerprint ?? null : null;
      if (typeof onAuthorityDiagnostic === "function") {
        onAuthorityDiagnostic(Object.freeze({ code: "authority_denied", category }));
        const diagnostics = category === "profile_reattestation" ? Object.freeze({
          environmentDigest: attestation.environmentDigest,
          inventoryDigest: inspected.evidence.inventoryDigest,
          environmentStates: Object.freeze(Object.fromEntries(profile.environmentKeys.map((key) => [
            key, Object.hasOwn(localEnvironment, key) ? digest(localEnvironment[key]) : null
          ])))
        }) : null;
        throw new ActivationAuthorityError(category, evidenceDigest, diagnostics);
      }
      return { allowed: false, grantDigest: digest({ purpose: "denied", runtimeId: manifest.runtimeId }), receiptDigest: digest({ purpose: "denied_receipt", runtimeId: manifest.runtimeId }) };
    };
    if (!request || request.operation !== "grok_submit" || !["new", "repair"].includes(request.mode) || resolve(request.repositoryRoot ?? "") !== manifest.repositoryRoot || !inside(request.destinationRoot ?? "", manifest.destinationRoot) || !manifest.dataClasses.includes(request.dataClass) || request.profileDigest !== profileFingerprint(profile) || JSON.stringify(request.requiredScopes) !== JSON.stringify(exactScopes) || current().getTime() >= Date.parse(manifest.expiresAt)) return denied("runtime_scope");
    let jobAuthority;
    try { jobAuthority = matchingJobAuthority(manifest, request, current()); } catch { return denied("job_authority"); }
    if (!jobAuthority) return denied("job_authority");
    if (request.profileReattestationProof != null && (request.mode !== "repair" || !consumeReattestationPermit(request))) return denied("profile_reattestation");
    if (request.profileReattestationProof == null && request.legacyRecoveryProfileProofDigest != null) return denied("profile_binding");
    const bound = { runtimeId: manifest.runtimeId, jobAuthority: structuredClone(jobAuthority), request: structuredClone(request), dataClass: request.dataClass };
    return { allowed: true, grantDigest: digest({ purpose: "authority_grant", bound }), receiptDigest: digest({ purpose: "authority_receipt", bound }), model: jobAuthority.model };
  };
  const acp = {
    environment: localEnvironment,
    launch: (input) => {
      const child = launch({ ...input, environment: localEnvironment, processInspector: inspectRuntimeProcess });
      activeChildren.add(child);
      void Promise.resolve(child.closed).then(
        () => activeChildren.delete(child),
        () => activeChildren.delete(child)
      );
      return child;
    },
    inspectChild: async (input) => {
      const fresh = inspectGrok({ manifest, worktree: input.worktree, environment: localEnvironment, runner });
      verifyChildAuthorityParity(attestation, fresh.evidence, { environment: localEnvironment });
      return fresh.evidence;
    },
    classifyPermission: async (params) => permissions.classify(params),
    authorizePermission: async (classified) => permissions.authorize(classified)
  };
  // ACP remains injectable for compatibility tests and experimental adapters.
  // The governed 0.4 candidate uses one finite headless process per turn.
  const headlessTransport = {
    environment: localEnvironment,
    spawnImpl: headlessSpawn,
    killTree: (child) => killHeadlessProcessTree(child, environment),
    inspectChild: async (input) => {
      const fresh = inspectGrok({ manifest, worktree: input.worktree, environment: localEnvironment, runner });
      verifyChildAuthorityParity(attestation, fresh.evidence, { environment: localEnvironment });
      return fresh.evidence;
    }
  };
  const acknowledgeRuntimeRecovery = (request) => {
    if (activeChildren.size !== 0 || !request?.childProcessIdentity) return false;
    try { return inspectRuntimeProcess(request.childProcessIdentity)?.state === "absent"; } catch { return false; }
  };
  const jobService = jobServiceFactory({
    ...jobServiceOptions,
    stateRoot: manifest.stateRoot,
    authority,
    profileFactory,
    acp,
    // An explicitly injected ACP factory is compatibility/test-only. Normal
    // activated execution selects the finite headless adapter.
    executionAdapterFactory: jobServiceOptions.executionAdapterFactory ?? (jobServiceOptions.acpFactory ? jobServiceOptions.acpFactory : createHeadlessSessionAdapter),
    transport: jobServiceOptions.transport ?? headlessTransport,
    acknowledgeRuntimeRecovery,
    acknowledgePreStartCancellation: acknowledgeRuntimeRecovery
  });
  const health = () => Object.freeze({ kind: "runtime_health", loadedVersion: "0.5.0", activationVersion: manifest.contractVersion, bundleDigest: typeof environment.GROK_BUILD_ENGINEER_BUNDLE_DIGEST === "string" && DIGEST.test(environment.GROK_BUILD_ENGINEER_BUNDLE_DIGEST) ? environment.GROK_BUILD_ENGINEER_BUNDLE_DIGEST : null, grokVersion: inspected.grokVersion, activationMatch: true, expiresAt: manifest.expiresAt, correctiveAction: current().getTime() >= Date.parse(manifest.expiresAt) ? "renew_runtime_activation" : "ready" });
  return Object.freeze({ ...jobService, status(request = {}) { return (!request || request.jobId === undefined) ? health() : jobService.status(request); } });
}

export function activationUnavailableService() { const unavailable = () => { throw new ActivationConfigError(); }; return Object.freeze({ submit: unavailable, status: unavailable, collect: unavailable, cancel: unavailable }); }
