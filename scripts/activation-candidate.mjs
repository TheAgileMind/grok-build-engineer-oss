#!/usr/bin/env node
// Review aid only. This command neither starts ACP nor grants provider, cost,
// disclosure, or external-effect authority.
import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { ACTIVATION_VERSION, inventoryDigestFor, inventoryProjection, safeProfileEnvironment } from "../src/activation-runtime.mjs";
import { CONTRACT_VERSIONS } from "../src/contracts.mjs";
import { getCapabilityProfile } from "../src/profiles.mjs";

const [executable, worktree, stateRoot, repositoryRoot, destinationRoot, scopePath] = process.argv.slice(2);
if (![executable, worktree, stateRoot, repositoryRoot, destinationRoot, scopePath].every((value) => typeof value === "string" && isAbsolute(value))) {
  process.stderr.write("usage: activation-candidate.mjs <absolute-grok> <absolute-worktree> <absolute-state-root> <absolute-repository-root> <absolute-destination-root> <absolute-scope.json>\n"); process.exitCode = 64;
} else {
  const exe = resolve(executable); const details = lstatSync(exe); if (!details.isFile() || details.isSymbolicLink()) throw new Error("Grok executable must be a regular file");
  const environment = safeProfileEnvironment(getCapabilityProfile("trusted-local"), process.env);
  const result = spawnSync(exe, ["--no-auto-update", "--cwd", resolve(worktree), "inspect", "--json"], { shell: false, windowsHide: true, timeout: 30_000, maxBuffer: 2 * 1024 * 1024, encoding: "utf8", env: environment });
  if (result.error || result.status !== 0 || typeof result.stdout !== "string") throw new Error("provider-free Grok inspection failed");
  const raw = JSON.parse(result.stdout);
  const scopeBytes = readFileSync(resolve(scopePath)); if (scopeBytes.length > 32 * 1024) throw new Error("activation scope is too large");
  const scope = JSON.parse(scopeBytes);
  const scopeKeys = ["contractVersion", "sourceSha", "provider", "model", "dataClasses", "disclosure", "costCeilingUsd", "validationCommands", "acceptanceCriteria", "externalEffects", "authorizationBasis"];
  const boundedText = (value) => typeof value === "string" && value.trim().length > 0 && value.length <= 8_192 && !/(?:Bearer\s+|sk-[A-Za-z0-9]|xai-[A-Za-z0-9])/i.test(value);
  const boundedList = (value) => Array.isArray(value) && value.length <= 128 && value.every(boundedText);
  if (!scope || Object.keys(scope).sort().join("|") !== scopeKeys.sort().join("|") || scope.contractVersion !== CONTRACT_VERSIONS.activationScope || !/^[a-f0-9]{40}$/.test(scope.sourceSha) || !Array.isArray(scope.dataClasses) || scope.dataClasses.length === 0 || scope.dataClasses.some((value) => !/^[a-z][a-z0-9_-]{2,63}$/.test(value)) || !Number.isFinite(scope.costCeilingUsd) || scope.costCeilingUsd < 0 || scope.costCeilingUsd > 10_000 || ![scope.provider, scope.model, scope.disclosure, scope.authorizationBasis].every(boundedText) || ![scope.validationCommands, scope.acceptanceCriteria, scope.externalEffects].every(boundedList)) throw new Error("activation scope is invalid");
  const git = (args) => spawnSync("git", ["-C", resolve(repositoryRoot), ...args], { shell: false, windowsHide: true, timeout: 10_000, maxBuffer: 256 * 1024, encoding: "utf8", env: environment });
  const head = git(["rev-parse", "HEAD"]), status = git(["status", "--porcelain"]);
  if (head.status !== 0 || head.stdout.trim() !== scope.sourceSha || status.status !== 0 || status.stdout.trim() !== "") throw new Error("repository is not the approved clean source SHA");
  const digest = (value) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
  const projection = inventoryProjection(raw, { worktree: resolve(worktree) });
  const runtimeCandidate = { contractVersion: ACTIVATION_VERSION, runtimeId: "REPLACE_WITH_RUNTIME_ID", runtimeApprovalDigest: "REPLACE_WITH_RUNTIME_APPROVAL_DIGEST", stateRoot: resolve(stateRoot), grokExecutable: exe, grokExecutableDigest: digest(readFileSync(exe)), inventoryDigest: inventoryDigestFor(raw, { worktree: resolve(worktree) }), profileId: "trusted-local", trustedHostAcknowledgement: "trusted_host_not_os_sandbox", repositoryRoot: resolve(repositoryRoot), destinationRoot: resolve(destinationRoot), dataClasses: scope.dataClasses, expiresAt: "REPLACE_WITH_REVIEWED_UTC_EXPIRY" };
  const jobAuthorityCandidate = { ...scope, authorityId: "REPLACE_WITH_JOB_AUTHORITY_ID", runtimeId: "REPLACE_WITH_RUNTIME_ID", expiresAt: "REPLACE_WITH_REVIEWED_UTC_EXPIRY", receiptDigest: "REPLACE_WITH_JOB_AUTHORITY_RECEIPT" };
  process.stdout.write(`${JSON.stringify({ runtimeCandidate, jobAuthorityCandidate, inventoryProjection: projection, reviewRequired: ["Approve this exact runtime packet, job authority, and expiry before creating immutable records.", "The runtime record does not authorize a source SHA, provider/model, cost, validation, disclosure, or external effects.", "This is trusted-host/provider enforcement, not OS sandbox containment.", "The cost ceiling is acknowledged but not hard-enforced by ACP provider telemetry." ] }, null, 2)}\n`);
}
