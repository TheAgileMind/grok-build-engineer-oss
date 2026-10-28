import assert from "node:assert/strict";
import test from "node:test";

import {
  CapabilityDeniedError,
  ChildAuthorityMismatchError,
  ProfileDriftError,
  buildProfileAttestation,
  createLocalPolicyGrantAuthority,
  evaluateExternalEffect,
  getCapabilityProfile,
  profileFingerprint,
  redactProfileDiagnostic,
  safeProfileEnvironment,
  verifyChildAuthorityParity,
  verifyProfileDrift
} from "../src/profiles.mjs";
import { CONTRACT_VERSIONS } from "../src/contracts.mjs";

const DIGEST = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;
const NOW = "2026-08-14T12:00:00.000Z";
const LATER = "2026-08-14T13:00:00.000Z";
const SAFE_ENVIRONMENT = Object.freeze({ COMSPEC: "C:\\Windows\\System32\\cmd.exe", GROK_HOME: "C:\\attested\\.grok", HOME: "C:\\attested", LANG: "en_US.UTF-8", LOCALAPPDATA: "C:\\attested\\AppData\\Local", PATH: "C:\\attested\\bin", PATHEXT: ".COM;.EXE;.BAT;.CMD", SYSTEMROOT: "C:\\Windows", TEMP: "C:\\attested\\Temp", TMP: "C:\\attested\\Tmp", USERPROFILE: "C:\\attested" });

function environment(overrides = {}) {
  const result = { ...SAFE_ENVIRONMENT, ...overrides };
  for (const [key, value] of Object.entries(result)) if (value === undefined) delete result[key];
  return result;
}

function evidence(overrides = {}) {
  return {
    executable: { path: "C:\\Tools\\grok.exe", digest: DIGEST },
    argv: ["--no-auto-update", "agent", "stdio"], cwdPolicy: "admitted_worktree_only",
    environmentKeys: ["COMSPEC", "GROK_HOME", "HOME", "LANG", "LOCALAPPDATA", "PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE"],
    inventoryDigest: DIGEST_B,
    capabilities: {
      nativeCommands: ["git_diff", "git_status", "npm_ci_offline", "npm_install_offline", "npm_run_build", "npm_run_test", "npm_run_verify", "npm_test"], builtIns: ["read_file", "write_file"],
      skills: ["native_skills"], plugins: ["native_plugins"], hooks: ["native_hooks"], subagents: ["native_subagents"], memory: ["native_memory"], config: ["grok_home_or_userprofile"],
      mcps: ["local_readonly_approved"], network: ["public_read_via_protected_grant"], credentialHelpers: []
    },
    containment: { claimed: "trusted_host", osBoundaryVerified: false },
    ...overrides
  };
}

function hermeticEvidence(overrides = {}) {
  return evidence({
    argv: ["--no-auto-update", "agent", "stdio"], environmentKeys: ["LANG", "PATH"],
    capabilities: { nativeCommands: ["git_status", "npm_test"], builtIns: ["read_file", "write_file"], skills: [], plugins: [], hooks: [], subagents: [], memory: [], config: [], mcps: [], network: [], credentialHelpers: [] },
    containment: { claimed: "os_sandboxed", osBoundaryVerified: true },
    ...overrides
  });
}

function context(overrides = {}) {
  return {
    jobId: "job-001", worktreeCustodyDigest: DIGEST_B,
    profileDigest: profileFingerprint(getCapabilityProfile("trusted-local")), worktreeClass: "public_worktree", disclosureMode: "public_source_readonly", ...overrides
  };
}

function grant(overrides = {}) {
  return {
    contractVersion: CONTRACT_VERSIONS.grant,
    grantId: "grant-001", jobId: "job-001", worktreeCustodyDigest: DIGEST_B,
    profileDigest: profileFingerprint(getCapabilityProfile("trusted-local")),
    operation: "network_read", service: "public_web", direction: "egress",
    dataClasses: ["public_source"], sourcePaths: ["docs/public.md"], recipients: ["public_web"],
    endpoints: ["https://docs.example.test"], payloadBoundary: "host_mediated_public_only",
    expiresAt: LATER, nonce: "nonce-001", authorityClass: "local_policy", issuer: "local_policy", receiptDigest: null,
    ...overrides
  };
}

test("exports capability-profile lookup", () => {
  assert.equal(typeof getCapabilityProfile, "function");
});

test("attests exact trusted-local capability inventory and rejects drift or false sandbox claims", () => {
  const profile = getCapabilityProfile("trusted-local");
  const attestation = buildProfileAttestation(profile, evidence(), { now: NOW, environment: environment() });
  assert.equal(attestation.enforcementClass, "trusted_host");
  assert.equal(attestation.executable.digest, DIGEST);
  assert.equal(attestation.inspection.inventoryDigest, DIGEST_B);
  assert.deepEqual(attestation.argv, ["--no-auto-update", "agent", "stdio"]);
  assert.deepEqual(attestation.environmentKeys, ["COMSPEC", "GROK_HOME", "HOME", "LANG", "LOCALAPPDATA", "PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE"]);
  assert.ok(attestation.fingerprint.startsWith("sha256:"));
  assert.equal(verifyProfileDrift(attestation, evidence(), { environment: environment() }).ok, true);
  assert.throws(() => verifyProfileDrift(attestation, evidence({ inventoryDigest: DIGEST }), { environment: environment() }), ProfileDriftError);
  assert.throws(() => verifyProfileDrift(attestation, evidence({ executable: { path: "C:\\Tools\\grok.exe", digest: DIGEST_B } })), ProfileDriftError);
  assert.throws(() => buildProfileAttestation(profile, evidence({ capabilities: { ...evidence().capabilities, nativeCommands: evidence().capabilities.nativeCommands.slice(1) } }), { now: NOW }), /frozen authority inventory/);
  assert.throws(() => buildProfileAttestation(profile, evidence({ capabilities: { ...evidence().capabilities, mcps: ["surprise_mcp"] } }), { now: NOW }), /frozen authority inventory/);
  for (const category of ["skills", "plugins", "hooks", "subagents", "memory", "config"]) {
    assert.throws(() => buildProfileAttestation(profile, evidence({ capabilities: { ...evidence().capabilities, [category]: [] } }), { now: NOW }), /frozen authority inventory/, category);
  }
  for (const unsafeKey of ["GROK_API_KEY", "XAI_API_KEY", "GROK_TOKEN", "NODE_OPTIONS", "GIT_CONFIG_GLOBAL", "SSH_AUTH_SOCK", "HTTPS_PROXY"]) {
    assert.throws(() => buildProfileAttestation(profile, evidence({ environmentKeys: [...evidence().environmentKeys, unsafeKey] }), { now: NOW }), /must not admit/, unsafeKey);
  }
  assert.throws(() => buildProfileAttestation(profile, evidence({ containment: { claimed: "os_sandboxed", osBoundaryVerified: false } }), { now: NOW }), /false enforced-sandbox claim/);
  assert.throws(() => buildProfileAttestation(profile, evidence({ containment: { claimed: "something_else", osBoundaryVerified: false } }), { now: NOW }), /unsupported/);
  assert.throws(() => buildProfileAttestation(profile, evidence({ executable: { path: "C:\\Tools\\grok.exe", digest: DIGEST, extra: true } }), { now: NOW }), /unsupported or missing/);
  assert.equal(attestation.inspection.environmentKeys.includes("PATH"), true);
  assert.equal("path" in attestation.inspection.executable, false);
  assert.doesNotMatch(JSON.stringify(attestation.inspection), /C:\\Tools|https?:\/\//);
  assert.equal(getCapabilityProfile("trusted-local").limits.maximumActiveJobs, 1);
  assert.equal(buildProfileAttestation(getCapabilityProfile("hermetic"), hermeticEvidence(), { now: NOW, environment: environment() }).enforcementClass, "os_enforced");
  assert.throws(() => buildProfileAttestation(getCapabilityProfile("hermetic"), hermeticEvidence({ containment: { claimed: "trusted_host", osBoundaryVerified: false } }), { now: NOW }), /verified OS/);
  assert.throws(() => buildProfileAttestation(profile, evidence({ containment: { claimed: "trusted_host", osBoundaryVerified: false, extra: true } }), { now: NOW }), /unsupported or missing/);
});

test("attestation binds allowlisted environment value and presence state without retaining raw values", () => {
  const profile = getCapabilityProfile("trusted-local"), attestation = buildProfileAttestation(profile, evidence(), { now: NOW, environment: environment() });
  assert.match(attestation.environmentDigest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(verifyProfileDrift(attestation, evidence(), { environment: environment() }).ok, true);
  assert.throws(() => verifyProfileDrift(attestation, evidence(), { environment: environment({ PATH: "C:\\changed\\bin" }) }), /environment drift/);
  assert.throws(() => verifyProfileDrift(attestation, evidence(), { environment: environment({ GROK_HOME: undefined }) }), /environment drift/);
  assert.equal(verifyProfileDrift(attestation, evidence(), { environment: environment({ GROK_API_KEY: "unallowlisted-secret" }) }).ok, true);
  assert.doesNotMatch(JSON.stringify({ environmentDigest: attestation.environmentDigest, inspection: attestation.inspection }), /attested|unallowlisted-secret|C:\\Windows/i);
  const absentAtAttestation = buildProfileAttestation(profile, evidence(), { now: NOW, environment: environment({ GROK_HOME: undefined }) });
  assert.throws(() => verifyProfileDrift(absentAtAttestation, evidence(), { environment: environment() }), /environment drift/);
  assert.throws(() => verifyChildAuthorityParity(attestation, evidence(), { environment: environment({ GROK_HOME: "C:\\changed\\.grok" }) }), ChildAuthorityMismatchError);
});

test("attestation keeps Codex ephemeral arg0 PATH shims stable without masking real PATH drift", () => {
  const profile = getCapabilityProfile("trusted-local");
  const first = environment({ PATH: "C:\\attested\\.codex\\tmp\\arg0\\codex-arg0Ab12Cd;C:\\attested\\bin;C:\\Windows\\System32" });
  const second = environment({ PATH: "C:\\attested\\.codex\\tmp\\arg0\\codex-arg0Ef34Gh;C:\\attested\\bin;C:\\Windows\\System32" });
  const attestation = buildProfileAttestation(profile, evidence(), { now: NOW, environment: first });
  assert.equal(verifyProfileDrift(attestation, evidence(), { environment: second }).ok, true);
  assert.equal(safeProfileEnvironment(profile, second).PATH, "C:\\attested\\bin;C:\\Windows\\System32", "the ignored shim is also removed from the child environment");
  assert.throws(() => verifyProfileDrift(attestation, evidence(), { environment: environment({ PATH: "C:\\attested\\.codex\\tmp\\arg0\\codex-arg0Ef34Gh;C:\\changed\\bin;C:\\Windows\\System32" }) }), /environment drift/);
  assert.throws(() => verifyProfileDrift(attestation, evidence(), { environment: environment({ PATH: "C:\\evil\\.codex\\tmp\\arg0\\codex-arg0Ef34Gh;C:\\attested\\bin;C:\\Windows\\System32" }) }), /environment drift/);
  const nested = environment({ PATH: "C:\\attested\\bin;C:\\attested\\.codex\\tmp\\arg0\\codex-arg0Ef34Gh;C:\\attested\\.codex\\tmp\\arg0\\codex-arg0Ij56Kl;C:\\Windows\\System32" });
  assert.equal(verifyProfileDrift(attestation, evidence(), { environment: nested }).ok, true);
  assert.equal(safeProfileEnvironment(profile, nested).PATH, "C:\\attested\\bin;C:\\Windows\\System32", "all exact nested shims are removed from child authority");
  assert.throws(() => verifyProfileDrift(attestation, evidence(), { environment: environment({ PATH: "C:\\attested\\.codex\\tmp\\arg0\\codex-arg0TOOLONG;C:\\attested\\bin;C:\\Windows\\System32" }) }), /environment drift/);
});

test("trusted-local keeps local engineering and public web useful but denies every ungranted external effect", () => {
  const profile = getCapabilityProfile("trusted-local");
  const attestation = buildProfileAttestation(profile, evidence(), { now: NOW });
  const request = { operation: "network_read", service: "public_web", direction: "egress", dataClass: "public_source", sourcePath: "docs/public.md", recipient: "public_web", endpoint: "https://docs.example.test", payloadBoundary: "host_mediated_public_only" };
  const authority = createLocalPolicyGrantAuthority([grant()]);
  const allowed = evaluateExternalEffect({ attestation, capability: "network_read", request, context: context(), grantId: "grant-001", grantAuthority: authority, now: NOW });
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.enforcementClass, "trusted_host");
  assert.equal(evaluateExternalEffect({ attestation, capability: "mcp_read", request, context: context(), now: NOW }).allowed, true);
  assert.equal(evaluateExternalEffect({ attestation, capability: "local_dependency_lifecycle", request, context: context(), now: NOW }).allowed, true);
  assert.throws(() => evaluateExternalEffect({ attestation, capability: "native_push", request, context: context(), now: NOW }), CapabilityDeniedError);
  for (const capability of ["deployment", "publication", "credential_helper", "dependency_lifecycle", "network_mutation", "connected_mcp_mutation"]) {
    assert.throws(() => evaluateExternalEffect({ attestation, capability, request, context: context(), now: NOW }), CapabilityDeniedError, capability);
  }
});

test("one-use protected grants bind every egress dimension and reject fake approval", () => {
  const attestation = buildProfileAttestation(getCapabilityProfile("trusted-local"), evidence(), { now: NOW });
  const request = { operation: "network_read", service: "public_web", direction: "egress", dataClass: "public_source", sourcePath: "docs/public.md", recipient: "public_web", endpoint: "https://docs.example.test", payloadBoundary: "host_mediated_public_only" };
  const variants = [
    [{ jobId: "job-002" }, request], [{ worktreeCustodyDigest: DIGEST }, request],
    [{ profileDigest: DIGEST_B }, request], [{ operation: "other" }, request], [{ service: "other" }, request],
    [{ direction: "ingress" }, request], [{ dataClasses: ["private_code"] }, request], [{ sourcePaths: ["src/private.mjs"] }, request],
    [{ recipients: ["other"] }, request], [{ endpoints: ["https://other.test"] }, request], [{ payloadBoundary: "other" }, request],
    [{ expiresAt: NOW }, request]
  ];
  for (const [changes, attempted] of variants) {
    assert.throws(() => {
      const authority = createLocalPolicyGrantAuthority([grant(changes)]);
      evaluateExternalEffect({ attestation, capability: "network_read", request: attempted, context: context(), grantId: "grant-001", grantAuthority: authority, now: NOW });
    }, CapabilityDeniedError);
  }
  const authority = createLocalPolicyGrantAuthority([grant()]);
  assert.throws(() => createLocalPolicyGrantAuthority([
    grant(),
    grant({ grantId: "grant-002" })
  ]), /unique one-use nonces/);
  assert.throws(() => evaluateExternalEffect({ attestation, capability: "network_read", request: { ...request, approval: "human-approved" }, context: context(), grantId: "grant-001", grantAuthority: authority, now: NOW }), /caller-supplied approval/);
  evaluateExternalEffect({ attestation, capability: "network_read", request, context: context(), grantId: "grant-001", grantAuthority: authority, now: NOW });
  assert.throws(() => evaluateExternalEffect({ attestation, capability: "network_read", request, context: context(), grantId: "grant-001", grantAuthority: authority, now: NOW }), /consumed/);
  assert.throws(() => evaluateExternalEffect({ attestation, capability: "network_read", request: { ...request, executable: "anything" }, context: context(), grantId: "grant-001", grantAuthority: createLocalPolicyGrantAuthority([grant()]), now: NOW }), /unsupported or missing/);
  assert.throws(() => evaluateExternalEffect({ attestation, capability: "network_read", request: { ...request, endpoint: 7 }, context: context(), grantId: "grant-001", grantAuthority: createLocalPolicyGrantAuthority([grant()]), now: NOW }), /non-empty strings/);
});

test("provider-free grants cannot authorize private egress, credential URLs, or a private worktree", () => {
  const attestation = buildProfileAttestation(getCapabilityProfile("trusted-local"), evidence(), { now: NOW });
  const publicRequest = { operation: "network_read", service: "public_web", direction: "egress", dataClass: "public_source", sourcePath: "docs/public.md", recipient: "public_web", endpoint: "https://docs.example.test", payloadBoundary: "host_mediated_public_only" };
  for (const dataClass of ["private_code", "private_diff", "private_prompt", "private_tool_output"]) {
    const privateRequest = { ...publicRequest, dataClass, sourcePath: "src/private.mjs" };
    assert.throws(() => {
      const authority = createLocalPolicyGrantAuthority([grant({ dataClasses: [dataClass], sourcePaths: ["src/private.mjs"] })]);
      evaluateExternalEffect({ attestation, capability: "network_read", request: privateRequest, context: context(), grantId: "grant-001", grantAuthority: authority, now: NOW });
    }, /public-source read-only/);
  }
  assert.throws(() => {
    const authority = createLocalPolicyGrantAuthority([grant({ endpoints: ["https://user:password@docs.example.test"] })]);
    evaluateExternalEffect({ attestation, capability: "network_read", request: { ...publicRequest, endpoint: "https://user:password@docs.example.test" }, context: context(), grantId: "grant-001", grantAuthority: authority, now: NOW });
  }, /public-source read-only/);
  assert.throws(() => evaluateExternalEffect({ attestation, capability: "network_read", request: publicRequest, context: context({ worktreeClass: "private_worktree" }), grantId: "grant-001", grantAuthority: createLocalPolicyGrantAuthority([grant()]), now: NOW }), /public worktree disclosure mode/);
  assert.throws(() => evaluateExternalEffect({ attestation, capability: "network_read", request: { ...publicRequest, dataClass: "private_code", sourcePath: "src/private.mjs" }, context: context(), grantId: "grant-001", grantAuthority: createLocalPolicyGrantAuthority([grant()]), now: NOW }), CapabilityDeniedError);
});

test("connected remains unavailable and child authority parity fails closed", () => {
  const connected = getCapabilityProfile("connected");
  assert.equal(connected.status, "unavailable_pending_live_proof");
  assert.throws(() => buildProfileAttestation(connected, evidence(), { now: NOW }), /unavailable/);
  const trusted = getCapabilityProfile("trusted-local");
  const attestation = buildProfileAttestation(trusted, evidence(), { now: NOW });
  assert.equal(verifyChildAuthorityParity(attestation, evidence()).ok, true);
  assert.throws(() => verifyChildAuthorityParity(attestation, evidence({ capabilities: { ...evidence().capabilities, nativeCommands: evidence().capabilities.nativeCommands.slice(1) } })), ChildAuthorityMismatchError);
  assert.throws(() => verifyChildAuthorityParity(attestation, evidence({ capabilities: { ...evidence().capabilities, mcps: ["surprise_mcp"] } })), ChildAuthorityMismatchError);
});

test("rejects caller-modified named profiles and sanitizes profile diagnostics", () => {
  const trusted = getCapabilityProfile("trusted-local");
  trusted.matrix[0].decision = "allow";
  trusted.commandAllowlist.push("git_push");
  assert.throws(() => buildProfileAttestation(trusted, evidence(), { now: NOW }), /immutable named profile/);
  const safe = redactProfileDiagnostic({ endpoint: "https://private.example.test", permission: "Bearer secret", environment: { TOKEN: "secret" }, message: "failed https://private.example.test/path" });
  assert.deepEqual(safe, { message: "failed [REDACTED_URL]" });
});
