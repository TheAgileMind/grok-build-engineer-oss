import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const digest = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

test("finalizer binds explicit authority to one candidate and registers an immutable activation", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-finalize-"));
  try {
    const candidatePath = join(root, "candidate.json"), authorityPath = join(root, "authority.json"), registryRoot = join(root, "registry");
    const jobAuthorityCandidate = { contractVersion: "agent-platform.grok-build-engineer-scope.v1", authorityId: "REPLACE_WITH_JOB_AUTHORITY_ID", runtimeId: "REPLACE_WITH_RUNTIME_ID", sourceSha: "a".repeat(40), provider: "xai", model: "grok-build", dataClasses: ["public"], disclosure: "public synthetic only", costCeilingUsd: 10, validationCommands: ["npm test", "Assert BUILD_REPAIR_TOKEN equals same-session-confirmed."], acceptanceCriteria: ["tests pass"], externalEffects: [], authorizationBasis: "user approved", expiresAt: "REPLACE_WITH_REVIEWED_UTC_EXPIRY", receiptDigest: "REPLACE_WITH_JOB_AUTHORITY_RECEIPT" };
    const candidate = { runtimeCandidate: { contractVersion: "agent-platform.grok-build-engineer-activation.v3", runtimeId: "REPLACE_WITH_RUNTIME_ID", runtimeApprovalDigest: "REPLACE_WITH_RUNTIME_APPROVAL_DIGEST", stateRoot: resolve(root, "state"), grokExecutable: resolve(root, "grok.exe"), grokExecutableDigest: digest("exe"), inventoryDigest: digest("inventory"), profileId: "trusted-local", trustedHostAcknowledgement: "trusted_host_not_os_sandbox", repositoryRoot: resolve(root, "repo"), destinationRoot: resolve(root, "worktrees"), dataClasses: ["public"], expiresAt: "REPLACE_WITH_REVIEWED_UTC_EXPIRY" }, jobAuthorityCandidate };
    writeFileSync(candidatePath, JSON.stringify(candidate));
    const candidateBytes = readFileSync(candidatePath);
    const authority = { contractVersion: "agent-platform.grok-build-engineer-authority.v1", candidateDigest: digest(candidateBytes), authorizationId: "authority_test", approvedAt: new Date(Date.now() - 1_000).toISOString(), expiresAt: new Date(Date.now() + 3_600_000).toISOString(), approvedBy: "user", approvalStatement: "Approved this exact public synthetic packet." };
    writeFileSync(authorityPath, JSON.stringify(authority));
    const unsafeAuthorityPath = join(root, "unsafe-authority.json");
    writeFileSync(unsafeAuthorityPath, JSON.stringify({ ...authority, authorizationId: "authorization_test" }));
    const unsafe = spawnSync(process.execPath, [resolve("scripts/finalize-activation.mjs"), candidatePath, unsafeAuthorityPath, registryRoot], { encoding: "utf8", shell: false });
    assert.notEqual(unsafe.status, 0, "an identifier rejected by runtime secret filtering must fail before activation writes");
    assert.equal(existsSync(registryRoot), false, "unsafe authority identity cannot leave a partial registry");
    const secretCandidatePath = join(root, "secret-candidate.json");
    writeFileSync(secretCandidatePath, JSON.stringify({ ...candidate, jobAuthorityCandidate: { ...jobAuthorityCandidate, disclosure: "api_key=synthetic-do-not-write" } }));
    const secretAuthorityPath = join(root, "secret-authority.json");
    writeFileSync(secretAuthorityPath, JSON.stringify({ ...authority, candidateDigest: digest(readFileSync(secretCandidatePath)) }));
    const secret = spawnSync(process.execPath, [resolve("scripts/finalize-activation.mjs"), secretCandidatePath, secretAuthorityPath, registryRoot], { encoding: "utf8", shell: false });
    assert.notEqual(secret.status, 0, "a labeled secret value fails before activation writes");
    assert.equal(existsSync(registryRoot), false, "secret material cannot leave a partial registry");
    const result = spawnSync(process.execPath, [resolve("scripts/finalize-activation.mjs"), candidatePath, authorityPath, registryRoot], { encoding: "utf8", shell: false });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout), activation = JSON.parse(readFileSync(output.activationPath, "utf8")), jobAuthority = JSON.parse(readFileSync(output.jobAuthorityPath, "utf8")), registry = JSON.parse(readFileSync(join(registryRoot, "registry.json"), "utf8"));
    assert.equal(activation.expiresAt, authority.expiresAt);
    assert.equal("sourceSha" in activation, false);
    assert.equal(jobAuthority.sourceSha, jobAuthorityCandidate.sourceSha);
    assert.notEqual(jobAuthority.receiptDigest, "REPLACE_WITH_JOB_AUTHORITY_RECEIPT");
    assert.deepEqual(registry.activations, [output.activationPath]);
    const authority2Path = join(root, "authority-2.json");
    writeFileSync(authority2Path, JSON.stringify({ ...authority, authorizationId: "authority_second", approvalStatement: "Approved the second exact packet." }));
    const second = spawnSync(process.execPath, [resolve("scripts/finalize-activation.mjs"), candidatePath, authority2Path, registryRoot], { encoding: "utf8", shell: false });
    assert.equal(second.status, 0, second.stderr);
    const refreshed = JSON.parse(readFileSync(join(registryRoot, "registry.json"), "utf8"));
    assert.deepEqual(refreshed.activations, [JSON.parse(second.stdout).activationPath], "Windows index replacement supersedes the old route without deleting its evidence");
    const replay = spawnSync(process.execPath, [resolve("scripts/finalize-activation.mjs"), candidatePath, authorityPath, registryRoot], { encoding: "utf8", shell: false });
    assert.notEqual(replay.status, 0, "an authority identifier cannot be replayed");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
