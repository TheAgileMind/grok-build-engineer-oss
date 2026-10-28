#!/usr/bin/env node
// Converts one explicitly user-approved, provider-free candidate into an
// immutable activation. This command does not contact Grok or establish user
// approval; the authority file must be created only after the exact packet was
// shown to and approved by the user.
import { createHash } from "node:crypto";
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import { ACTIVATION_REGISTRY_VERSION } from "../src/activation-registry.mjs";
import { ACTIVATION_VERSION } from "../src/activation-runtime.mjs";
import { CONTRACT_VERSIONS, validateJobAuthority } from "../src/contracts.mjs";
import { secretFreeAuthorityRecord, secretishIdentifier } from "../src/authority-safety.mjs";

const [candidateInput, authorityInput, registryInput] = process.argv.slice(2);
if (![candidateInput, authorityInput, registryInput].every((value) => typeof value === "string" && isAbsolute(value))) {
  process.stderr.write("usage: finalize-activation.mjs <absolute-candidate.json> <absolute-authority.json> <absolute-registry-root>\n"); process.exitCode = 64;
} else {
  const readPlain = (path, label) => { const resolved = resolve(path), details = lstatSync(resolved); if (!details.isFile() || details.isSymbolicLink() || details.size < 2 || details.size > 64 * 1024) throw new Error(`${label} is unavailable`); return readFileSync(resolved); };
  const digest = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  const candidateBytes = readPlain(candidateInput, "candidate"), authorityBytes = readPlain(authorityInput, "authority");
  const packet = JSON.parse(candidateBytes), authority = JSON.parse(authorityBytes);
  const authorityKeys = ["contractVersion", "candidateDigest", "authorizationId", "approvedAt", "expiresAt", "approvedBy", "approvalStatement"];
  if (!authority || Object.keys(authority).sort().join("|") !== authorityKeys.sort().join("|") || authority.contractVersion !== "agent-platform.grok-build-engineer-authority.v1" || authority.candidateDigest !== digest(candidateBytes) || authority.approvedBy !== "user" || typeof authority.approvalStatement !== "string" || !authority.approvalStatement.trim()) throw new Error("authority does not bind the reviewed candidate");
  if (!/^[a-z][a-z0-9_-]{2,63}$/.test(authority.authorizationId) || secretishIdentifier(authority.authorizationId) || !Number.isFinite(Date.parse(authority.approvedAt)) || !Number.isFinite(Date.parse(authority.expiresAt)) || Date.parse(authority.expiresAt) <= Date.now() || Date.parse(authority.approvedAt) > Date.now() || Date.parse(authority.expiresAt) <= Date.parse(authority.approvedAt)) throw new Error("authority timing or identity is invalid");
  const template = packet?.runtimeCandidate, jobTemplate = packet?.jobAuthorityCandidate;
  const runtimeKeys = ["contractVersion", "runtimeId", "runtimeApprovalDigest", "stateRoot", "grokExecutable", "grokExecutableDigest", "inventoryDigest", "profileId", "trustedHostAcknowledgement", "repositoryRoot", "destinationRoot", "dataClasses", "expiresAt"];
  const scopeKeys = ["contractVersion", "sourceSha", "provider", "model", "dataClasses", "disclosure", "costCeilingUsd", "validationCommands", "acceptanceCriteria", "externalEffects", "authorizationBasis", "authorityId", "runtimeId", "expiresAt", "receiptDigest"];
  if (!template || Object.keys(template).sort().join("|") !== runtimeKeys.sort().join("|") || template.contractVersion !== ACTIVATION_VERSION || template.runtimeId !== "REPLACE_WITH_RUNTIME_ID" || template.runtimeApprovalDigest !== "REPLACE_WITH_RUNTIME_APPROVAL_DIGEST" || template.expiresAt !== "REPLACE_WITH_REVIEWED_UTC_EXPIRY" || !jobTemplate || Object.keys(jobTemplate).sort().join("|") !== scopeKeys.sort().join("|") || jobTemplate.contractVersion !== CONTRACT_VERSIONS.activationScope || jobTemplate.authorityId !== "REPLACE_WITH_JOB_AUTHORITY_ID" || jobTemplate.runtimeId !== "REPLACE_WITH_RUNTIME_ID" || jobTemplate.expiresAt !== "REPLACE_WITH_REVIEWED_UTC_EXPIRY" || jobTemplate.receiptDigest !== "REPLACE_WITH_JOB_AUTHORITY_RECEIPT" || !/^[a-f0-9]{40}$/.test(jobTemplate.sourceSha) || !Array.isArray(jobTemplate.dataClasses) || jobTemplate.dataClasses.some((value) => !/^[a-z][a-z0-9_-]{2,63}$/.test(value))) throw new Error("candidate is not an unactivated review packet");
  const receipt = (kind) => `sha256:${createHash("sha256").update(authorityBytes).update("\0").update(kind).digest("hex")}`;
  const expiresAt = new Date(authority.expiresAt).toISOString();
  const activation = { ...template, runtimeId: authority.authorizationId, runtimeApprovalDigest: digest(candidateBytes), expiresAt };
  const jobAuthority = { contractVersion: CONTRACT_VERSIONS.jobAuthority, authorityId: authority.authorizationId, runtimeId: authority.authorizationId, sourceSha: jobTemplate.sourceSha, dataClasses: jobTemplate.dataClasses, provider: jobTemplate.provider, model: jobTemplate.model, disclosure: jobTemplate.disclosure, costCeilingUsd: jobTemplate.costCeilingUsd, validationCommands: jobTemplate.validationCommands, acceptanceCriteria: jobTemplate.acceptanceCriteria, externalEffects: jobTemplate.externalEffects, authorizationBasis: jobTemplate.authorizationBasis, expiresAt, receiptDigest: receipt("job_authority") };
  try { validateJobAuthority(jobAuthority); } catch { throw new Error("candidate job authority is invalid"); }
  if (!secretFreeAuthorityRecord(activation) || !secretFreeAuthorityRecord(jobAuthority)) throw new Error("candidate authority contains secret material");
  const root = resolve(registryInput), activations = join(root, "activations"), routes = join(root, "routes"), acceptances = join(root, "acceptances"), authorities = join(root, "authorities"), candidates = join(root, "candidates");
  for (const directory of [root, activations, routes, acceptances, authorities, candidates]) { mkdirSync(directory, { recursive: true, mode: 0o700 }); const details = lstatSync(directory); if (!details.isDirectory() || details.isSymbolicLink()) throw new Error("registry directory is unsafe"); }
  const writeExclusive = (path, bytes) => { let descriptor; try { descriptor = openSync(path, "wx", 0o600); writeFileSync(descriptor, bytes); fsyncSync(descriptor); } finally { if (descriptor !== undefined) closeSync(descriptor); } };
  const authorityPath = join(authorities, `${authority.authorizationId}.json`), candidatePath = join(candidates, `${authority.authorizationId}.json`), activationPath = join(activations, `${authority.authorizationId}.json`), jobAuthorities = join(activation.stateRoot, "job-authorities"), jobAuthorityPath = join(jobAuthorities, `${authority.authorizationId}.json`);
  const activationBytes = Buffer.from(`${JSON.stringify(activation)}\n`, "utf8");
  mkdirSync(jobAuthorities, { recursive: true, mode: 0o700 }); const jobAuthorityDetails = lstatSync(jobAuthorities); if (!jobAuthorityDetails.isDirectory() || jobAuthorityDetails.isSymbolicLink()) throw new Error("job authority directory is unsafe");
  writeExclusive(authorityPath, authorityBytes); writeExclusive(candidatePath, candidateBytes); writeExclusive(activationPath, activationBytes);
  writeExclusive(jobAuthorityPath, `${JSON.stringify(jobAuthority)}\n`);
  const registryPath = join(root, "registry.json");
  let activationsList = [];
  if (existsSync(registryPath)) {
    const registry = JSON.parse(readFileSync(registryPath, "utf8"));
    if (registry.contractVersion !== ACTIVATION_REGISTRY_VERSION || !Array.isArray(registry.activations)) throw new Error("registry index is invalid");
    const inside = (path) => { const relation = relative(activations, resolve(path)); return relation !== "" && !relation.startsWith("..") && !isAbsolute(relation); };
    activationsList = registry.activations.filter((path) => {
      if (typeof path !== "string" || !isAbsolute(path) || !inside(path)) throw new Error("registry activation path is unsafe");
      const existing = JSON.parse(readPlain(path, "registered activation"));
      const sameRoute = existing.repositoryRoot === activation.repositoryRoot && existing.destinationRoot === activation.destinationRoot && existing.profileId === activation.profileId && existing.dataClasses.some((value) => activation.dataClasses.includes(value));
      return !sameRoute;
    });
  }
  if (!activationsList.includes(activationPath)) activationsList.push(activationPath);
  const temporary = join(root, `.registry-${process.pid}.tmp`);
  writeExclusive(temporary, `${JSON.stringify({ contractVersion: ACTIVATION_REGISTRY_VERSION, activations: activationsList })}\n`); renameSync(temporary, registryPath);
  process.stdout.write(`${JSON.stringify({ activationPath, authorityPath, candidatePath, jobAuthorityPath, registryRoot: root, activationDigest: digest(activationBytes) })}\n`);
}
