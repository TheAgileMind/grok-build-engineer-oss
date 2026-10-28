import { createHash } from "node:crypto";
import {
  closeSync, existsSync, lstatSync, openSync, readFileSync, readSync, readdirSync, realpathSync
} from "node:fs";
import { basename, dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";

const CUSTODY_VERSION = "agent-platform.grok-builder-worktree-custody.v1";
const INVENTORY_VERSION = "agent-platform.grok-builder-worktree-inventory.v1";
const SHA = /^[a-f0-9]{40}$/;
const JOB_ID = /^[a-z][a-z0-9_-]{2,63}$/;
const MAX_INVENTORY_ENTRIES = 10_000;
const MAX_INVENTORY_BYTES = 512 * 1024 * 1024;
const MAX_PATH_BYTES = 4_096;
const MAX_PROTECTED_METADATA_BYTES = 4 * 1024 * 1024;
const MAX_PACKAGE_METADATA_BYTES = 4 * 1024 * 1024;
const TERMINAL_STATES = new Set(["accepted", "rejected", "cancelled", "failed"]);
const NULL_HOOKS_PATH = process.platform === "win32" ? "NUL" : "/dev/null";

export class WorktreeCustodyError extends Error { constructor(message) { super(message); this.name = "WorktreeCustodyError"; } }

function fail(message) { throw new WorktreeCustodyError(message); }
function hash(value) { return `sha256:${createHash("sha256").update(value).digest("hex")}`; }
function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
export function digestOf(value) { return hash(canonical(value)); }
function normalizedCase(path, platform) { return platform === "win32" ? path.replaceAll("\\", "/").toLowerCase() : path.replaceAll("\\", "/"); }
function samePath(left, right, platform) {
  if (normalizedCase(resolve(left), platform) === normalizedCase(resolve(right), platform)) return true;
  try {
    const leftDetails = lstatSync(left), rightDetails = lstatSync(right);
    return String(leftDetails.dev) === String(rightDetails.dev) && String(leftDetails.ino) === String(rightDetails.ino);
  } catch { return false; }
}
function isWithin(parent, child, platform) {
  const left = normalizedCase(resolve(parent), platform).replace(/\/$/, "");
  const right = normalizedCase(resolve(child), platform).replace(/\/$/, "");
  return right === left || right.startsWith(`${left}/`);
}
function overlaps(left, right, platform) { return isWithin(left, right, platform) || isWithin(right, left, platform); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value)); }
function requireAbsolute(value, label) { if (typeof value !== "string" || !value || !isAbsolute(value)) fail(`${label} must be an absolute path`); return value; }
function requireJob(value) { if (typeof value !== "string" || !JOB_ID.test(value)) fail("jobId must be a valid identifier"); return value; }
function requireSha(value) { if (typeof value !== "string" || !SHA.test(value)) fail("sourceSha must be a full lowercase 40-hex SHA"); return value; }

function isLinkOrReparse(pathOrDetails) {
  const details = typeof pathOrDetails === "string" ? lstatSync(pathOrDetails) : pathOrDetails;
  // Node reports Windows junctions as symbolic links. The mode check also catches
  // platforms that expose a reparse link only through the POSIX file-type bits.
  return details.isSymbolicLink() || (details.mode & 0o170000) === 0o120000;
}

function assertExistingPlainPath(path, label) {
  const absolute = resolve(requireAbsolute(path, label));
  if (!existsSync(absolute)) fail(`${label} does not exist`);
  const chain = [];
  for (let cursor = absolute;; cursor = dirname(cursor)) {
    chain.push(cursor);
    if (dirname(cursor) === cursor) break;
  }
  for (const component of chain) {
    if (isLinkOrReparse(component)) fail(`${label} traverses a symlink, junction, or reparse point`);
  }
  return realpathSync(absolute);
}

function pathIdentity(path) {
  const details = lstatSync(path);
  return { path, dev: String(details.dev), ino: String(details.ino), mode: details.mode, birthtimeMs: details.birthtimeMs };
}

function assertNewDestination(path, platform) {
  const literal = requireAbsolute(path, "destinationRoot");
  const normalized = normalize(literal);
  if (normalized !== literal) fail("destinationRoot must be canonical without dot segments");
  if (platform !== "win32") {
    const slashForm = literal.replaceAll("\\", "/");
    if (normalize(slashForm) !== slashForm) fail("destinationRoot must be canonical without dot segments");
  }
  try {
    lstatSync(literal);
    fail("destinationRoot must not already exist");
  } catch (error) {
    if (error instanceof WorktreeCustodyError) throw error;
    if (error?.code !== "ENOENT") throw error;
  }
  const parent = assertExistingPlainPath(dirname(literal), "destination parent");
  assertOutsideExistingGitCheckout(parent);
  const destination = resolve(parent, basename(literal));
  if (samePath(destination, parent, platform)) fail("destinationRoot must name a child of its admitted parent");
  return { destination, parent };
}

function assertOutsideExistingGitCheckout(destinationParent) {
  for (let cursor = destinationParent;; cursor = dirname(cursor)) {
    const marker = join(cursor, ".git");
    let details = null;
    try { details = lstatSync(marker); }
    catch (error) { if (error?.code !== "ENOENT") fail("destination Git ancestry could not be inspected safely"); }
    if (details) {
      if (details.isSymbolicLink() || (details.mode & 0o170000) === 0o120000) fail("destination parent ancestry contains a linked Git control marker");
      if (details.isFile() || details.isDirectory()) fail("destination parent is inside an existing Git checkout");
      fail("destination parent ancestry contains a special Git control marker");
    }
    if (dirname(cursor) === cursor) break;
  }
}

function gitEnvironment() {
  const environment = {
    PATH: process.env.PATH ?? "", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
    GIT_TERMINAL_PROMPT: "0", GCM_INTERACTIVE: "Never", GIT_ASKPASS: "", SSH_ASKPASS: "", GIT_OPTIONAL_LOCKS: "0",
    GIT_CONFIG_COUNT: "2", GIT_CONFIG_KEY_0: "core.hooksPath", GIT_CONFIG_VALUE_0: NULL_HOOKS_PATH,
    GIT_CONFIG_KEY_1: "core.fsmonitor", GIT_CONFIG_VALUE_1: "false"
  };
  if (process.platform === "win32") {
    // Global Git configuration is deliberately disabled above. Preserve the
    // platform capability needed to check out valid repository paths that
    // exceed the legacy Win32 MAX_PATH limit without trusting user config.
    environment.GIT_CONFIG_COUNT = "3";
    environment.GIT_CONFIG_KEY_2 = "core.longpaths";
    environment.GIT_CONFIG_VALUE_2 = "true";
  }
  for (const key of ["SystemRoot", "SystemDrive", "ComSpec", "TEMP", "TMP"]) if (process.env[key]) environment[key] = process.env[key];
  return environment;
}

function fixedRun(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd, encoding: "utf8", shell: false, windowsHide: true,
    env: options.env ?? gitEnvironment(), timeout: options.timeoutMs ?? 30_000
  });
  if (result.error) throw result.error;
  return { status: result.status ?? -1, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function git(run, cwd, args) {
  const fixedArgs = ["-c", `core.hooksPath=${NULL_HOOKS_PATH}`, "-c", "core.fsmonitor=false",
    ...args];
  const result = run("git", fixedArgs, { cwd, shell: false, env: gitEnvironment(), timeoutMs: 30_000 });
  if (!result || typeof result.status !== "number") fail("Git runner returned an invalid result");
  if (result.status !== 0) fail(`fixed Git command failed: git ${args.join(" ")}`);
  return String(result.stdout ?? "");
}

function gitOptional(run, cwd, args) {
  const fixedArgs = ["-c", `core.hooksPath=${NULL_HOOKS_PATH}`, "-c", "core.fsmonitor=false",
    ...args];
  const result = run("git", fixedArgs, { cwd, shell: false, env: gitEnvironment(), timeoutMs: 30_000 });
  if (!result || typeof result.status !== "number") fail("Git runner returned an invalid result");
  if (result.status > 1) fail(`fixed Git command failed: git ${args.join(" ")}`);
  return { found: result.status === 0, stdout: String(result.stdout ?? "") };
}

function assertNoExternalGitProcesses(run, repositoryRoot) {
  const filters = gitOptional(run, repositoryRoot, ["config", "--local", "--get-regexp", "^filter\\..+\\.(clean|smudge|process)$"]);
  if (filters.found && filters.stdout.trim() !== "") fail("repository-local external Git filter configuration is unavailable");
  const fsmonitor = gitOptional(run, repositoryRoot, ["config", "--local", "--get", "core.fsmonitor"]);
  if (fsmonitor.found && fsmonitor.stdout.trim().toLowerCase() !== "false") fail("repository-local fsmonitor configuration is unavailable");
}

function nulPaths(value, label) {
  if (typeof value !== "string") fail(`${label} returned non-text output`);
  const paths = value.split("\0").filter(Boolean);
  if (paths.some((entry) => Buffer.byteLength(entry, "utf8") > MAX_PATH_BYTES)) fail(`${label} returned an oversized path`);
  return paths;
}

function sourceControlRoot(run, repositoryRoot) {
  const common = git(run, repositoryRoot, ["rev-parse", "--git-common-dir"]).trim();
  return assertExistingPlainPath(isAbsolute(common) ? common : resolve(repositoryRoot, common), "source Git control root");
}

function sourceCustody({ sourceRoot, sourceSha, sourceControlRoot: controlRoot, branchPolicy, destinationRoot, identities }) {
  return {
    contractVersion: CUSTODY_VERSION,
    sourceRoot, sourceSha, sourceControlRoot: controlRoot, branchPolicy, destinationRoot,
    identities,
    sourceCustodyDigest: digestOf({ contractVersion: CUSTODY_VERSION, sourceRoot, sourceSha, sourceControlRoot: controlRoot, branchPolicy, destinationRoot, identities })
  };
}

/**
 * Validate immutable source and destination authority. This function deliberately
 * accepts no command, branch name, cwd, environment, or executable from callers.
 * A JobStore reservation may be passed in; it is verified rather than recreated.
 */
export function admitWorktree({ jobId, source, stateRoot, reservation = null, run = fixedRun, platform = process.platform } = {}) {
  requireJob(jobId);
  if (!plainObject(source)) fail("source must be an object");
  const allowed = ["repositoryRoot", "sourceSha", "destinationRoot", "branchPolicy"];
  if (Object.keys(source).some((key) => !allowed.includes(key))) fail("source has unsupported fields");
  const sourceSha = requireSha(source.sourceSha);
  if (!["detached", "unique_mission_branch"].includes(source.branchPolicy)) fail("branchPolicy must be detached or unique_mission_branch");
  const sourceRoot = assertExistingPlainPath(source.repositoryRoot, "source repositoryRoot");
  const admittedStateRoot = assertExistingPlainPath(stateRoot, "stateRoot");
  const topLevel = assertExistingPlainPath(git(run, sourceRoot, ["rev-parse", "--show-toplevel"]).trim(), "source Git top level");
  if (!samePath(topLevel, sourceRoot, platform)) fail("source repositoryRoot is not the canonical Git worktree root");
  assertNoExternalGitProcesses(run, sourceRoot);
  const resolvedSha = git(run, sourceRoot, ["rev-parse", "--verify", `${sourceSha}^{commit}`]).trim().toLowerCase();
  if (resolvedSha !== sourceSha) fail("sourceSha is not an immutable admitted commit");
  const controlRoot = sourceControlRoot(run, sourceRoot);
  const { destination, parent } = assertNewDestination(source.destinationRoot, platform);
  for (const [leftName, left, rightName, right] of [
    ["source repository", sourceRoot, "destination", destination],
    ["source control root", controlRoot, "destination", destination],
    ["stateRoot", admittedStateRoot, "source repository", sourceRoot],
    ["stateRoot", admittedStateRoot, "destination", destination],
    ["stateRoot", admittedStateRoot, "source control root", controlRoot]
  ]) if (overlaps(left, right, platform)) fail(`${leftName} overlaps ${rightName}`);
  const identities = Object.freeze({ sourceRoot: pathIdentity(sourceRoot), sourceControlRoot: pathIdentity(controlRoot), destinationParent: pathIdentity(parent), stateRoot: pathIdentity(admittedStateRoot) });
  const custody = sourceCustody({ sourceRoot, sourceSha, sourceControlRoot: controlRoot, branchPolicy: source.branchPolicy, destinationRoot: destination, identities });
  // JobStore canonicalizes reservation keys case-insensitively on every host so
  // a record remains conservative if its state root is later moved to Windows.
  const destinationDigest = hash(normalizedCase(destination, "win32"));
  if (reservation !== null) {
    if (!plainObject(reservation) || reservation.jobId !== jobId || reservation.destinationDigest !== destinationDigest) {
      fail("JobStore destination reservation does not bind this job and canonical destination");
    }
  }
  return Object.freeze({ ...custody, jobId, stateRoot: admittedStateRoot, destinationParent: parent, destinationDigest, reservation: reservation ? structuredClone(reservation) : null });
}

export function reserveAdmittedDestination(admission, store) {
  if (!admission || !store || typeof store.reserve !== "function") fail("a JobStore reservation authority is required");
  const reservation = store.reserve(normalizedCase(admission.destinationRoot, "win32"), admission.jobId);
  return admitWorktree({ jobId: admission.jobId, source: {
    repositoryRoot: admission.sourceRoot, sourceSha: admission.sourceSha, destinationRoot: admission.destinationRoot, branchPolicy: admission.branchPolicy
  }, stateRoot: admission.stateRoot, reservation });
}

function boundedFileDigest(path, label, maximumBytes, details = lstatSync(path)) {
  if (isLinkOrReparse(details) || !details.isFile()) fail(`${label} must be a plain regular file`);
  if (details.size > maximumBytes) fail(`${label} exceeds its bounded byte allowance`);
  const descriptor = openSync(path, "r");
  const digest = createHash("sha256"), chunk = Buffer.allocUnsafe(64 * 1024);
  let total = 0;
  try {
    for (;;) {
      const bytes = readSync(descriptor, chunk, 0, chunk.length, null);
      if (bytes === 0) break;
      total += bytes;
      if (total > maximumBytes) fail(`${label} exceeded its bounded byte allowance while reading`);
      digest.update(chunk.subarray(0, bytes));
    }
  } finally { closeSync(descriptor); }
  return { bytes: total, digest: `sha256:${digest.digest("hex")}`, mode: details.mode };
}

function protectedMetadata(path, label) {
  if (!existsSync(path)) return { kind: "missing" };
  return { kind: "file", ...boundedFileDigest(path, label, MAX_PROTECTED_METADATA_BYTES) };
}

function semanticIndexProof(run, worktreeRoot) {
  const staged = git(run, worktreeRoot, ["ls-files", "--stage", "-z"]);
  const flags = git(run, worktreeRoot, ["ls-files", "-v", "-z"]);
  if (Buffer.byteLength(staged, "utf8") > MAX_PROTECTED_METADATA_BYTES || Buffer.byteLength(flags, "utf8") > MAX_PROTECTED_METADATA_BYTES) {
    fail("linked Git semantic index proof exceeds its bounded allowance");
  }
  const stagePaths = staged.split("\0").filter(Boolean).map((record) => {
    const match = /^(?:100644|100755|120000|160000) [a-f0-9]{40} [0-3]\t([\s\S]+)$/.exec(record);
    if (!match || Buffer.byteLength(match[1], "utf8") > MAX_PATH_BYTES) fail("linked Git staged index entry is malformed");
    return match[1];
  });
  const flagPaths = flags.split("\0").filter(Boolean).map((record) => {
    if (!record.startsWith("H ")) fail("linked Git index contains an unsafe path visibility flag");
    const path = record.slice(2);
    if (!path || Buffer.byteLength(path, "utf8") > MAX_PATH_BYTES) fail("linked Git index flag entry is malformed");
    return path;
  });
  if (canonical(stagePaths) !== canonical(flagPaths) || new Set(stagePaths).size !== stagePaths.length) {
    fail("linked Git semantic index entries differ");
  }
  return digestOf({ staged, flags });
}

function protectedIndexMetadata(path, run, worktreeRoot) {
  if (!existsSync(path)) fail("linked Git index does not exist");
  const details = lstatSync(path), bounded = boundedFileDigest(path, "linked Git index", MAX_PROTECTED_METADATA_BYTES, details);
  return {
    kind: "file", bytes: bounded.bytes, mode: bounded.mode,
    identity: { dev: String(details.dev), ino: String(details.ino), birthtimeMs: details.birthtimeMs },
    semanticDigest: semanticIndexProof(run, worktreeRoot)
  };
}

function metadataMatches(current, recorded) {
  if (!plainObject(current) || !plainObject(recorded)) return false;
  const { gitDirIndex: currentIndex, ...currentRest } = current, { gitDirIndex: recordedIndex, ...recordedRest } = recorded;
  if (canonical(currentRest) !== canonical(recordedRest)) return false;
  // Git may atomically replace its index during an ordinary read-only status
  // refresh, changing both raw stat-cache bytes and filesystem identity. The
  // commands in requiredLinkedMetadata validate the meaningful boundary:
  // the index parses, still matches HEAD, and contains no staged changes.
  // Retain only the bounded regular-file shape here; never confuse an inode
  // refresh with staging or index corruption.
  const shaped = [currentIndex, recordedIndex].every((index) => plainObject(index) && index.kind === "file" &&
    Number.isSafeInteger(index.bytes) && index.bytes > 0 && index.bytes <= MAX_PROTECTED_METADATA_BYTES &&
    Number.isSafeInteger(index.mode));
  if (!shaped) return false;
  // New records bind the complete HEAD-equivalent semantic index. Older
  // records predate this field; requiredLinkedMetadata still proves their
  // current index is clean and rejects every visibility flag before this
  // compatibility comparison is reached.
  return typeof recordedIndex.semanticDigest === "string" ? currentIndex.semanticDigest === recordedIndex.semanticDigest : true;
}

function inventoryMatches(current, expected) {
  if (!plainObject(current) || !plainObject(expected)) return false;
  const { inventoryDigest: _currentDigest, protectedGitMetadata: currentMetadata, ...currentRest } = current;
  const { inventoryDigest: _expectedDigest, protectedGitMetadata: expectedMetadata, ...expectedRest } = expected;
  return canonical(currentRest) === canonical(expectedRest) && metadataMatches(currentMetadata, expectedMetadata);
}

function assertIndexMatchesHead(run, worktreeRoot) {
  if (!gitOptional(run, worktreeRoot, ["diff", "--cached", "--quiet", "--exit-code"]).found) {
    fail("staging is prohibited while candidate custody is active");
  }
}

function hasStagedChange(status) {
  return status.split("\0").filter(Boolean).some((record) => record.length >= 2 && record[0] !== " " && record[0] !== "?");
}

function requiredLinkedMetadata(run, worktreeRoot, expectedSha, platform, { requireClean = true } = {}) {
  const topLevel = assertExistingPlainPath(git(run, worktreeRoot, ["rev-parse", "--show-toplevel"]).trim(), "linked Git top level");
  if (!samePath(topLevel, worktreeRoot, platform)) fail("linked worktree top level drifted");
  const head = git(run, worktreeRoot, ["rev-parse", "HEAD"]).trim().toLowerCase();
  if (head !== expectedSha) fail("linked worktree HEAD does not match immutable source SHA");
  const dotGit = join(worktreeRoot, ".git");
  if (!existsSync(dotGit) || !lstatSync(dotGit).isFile() || isLinkOrReparse(dotGit)) fail("linked worktree .git must be a plain indirection file");
  if (lstatSync(dotGit).size > 64 * 1024) fail("linked worktree .git indirection exceeds its bounded size");
  const pointer = readFileSync(dotGit, "utf8");
  if (!/^gitdir: .+\r?\n?$/.test(pointer)) fail("linked worktree .git indirection is malformed");
  const gitDirValue = pointer.slice("gitdir: ".length).trim();
  const gitDir = assertExistingPlainPath(isAbsolute(gitDirValue) ? gitDirValue : resolve(worktreeRoot, gitDirValue), "linked Git directory");
  const commonRaw = git(run, worktreeRoot, ["rev-parse", "--git-common-dir"]).trim();
  const commonDir = assertExistingPlainPath(isAbsolute(commonRaw) ? commonRaw : resolve(worktreeRoot, commonRaw), "linked Git common directory");
  if (!isWithin(commonDir, gitDir, platform)) fail("linked Git directory is outside its common Git directory");
  const index = protectedIndexMetadata(join(gitDir, "index"), run, worktreeRoot);
  assertIndexMatchesHead(run, worktreeRoot);
  const status = git(run, worktreeRoot, ["status", "--porcelain=v1", "-z", "--untracked-files=all"]);
  if (requireClean && status !== "") fail("new linked worktree baseline is dirty");
  // Candidate collection intentionally permits only unstaged working-tree edits.
  // This keeps the index a protected immutable baseline and makes staged/index
  // swaps fail custody rather than silently changing the candidate meaning.
  if (!requireClean && hasStagedChange(status)) fail("staging is prohibited while candidate custody is active");
  const listed = git(run, worktreeRoot, ["worktree", "list", "--porcelain"]);
  const registered = listed.split(/\r?\n/).filter((line) => line.startsWith("worktree "))
    .map((line) => line.slice("worktree ".length)).some((path) => samePath(path, worktreeRoot, platform));
  if (!registered) fail("linked worktree is not registered by Git");
  return {
    dotGitDigest: hash(pointer), gitDir: normalizedCase(gitDir, platform), commonDir: normalizedCase(commonDir, platform),
    head, topLevel: normalizedCase(topLevel, platform),
    gitDirHead: protectedMetadata(join(gitDir, "HEAD"), "linked Git HEAD"),
    gitDirIndex: index,
    gitDirCommonDir: protectedMetadata(join(gitDir, "commondir"), "linked Git commondir"),
    gitDirWorktreeConfig: protectedMetadata(join(gitDir, "config.worktree"), "linked Git worktree config"),
    commonConfig: protectedMetadata(join(commonDir, "config"), "common Git config")
  };
}

function materializeAdmittedWorktree(admission, { run = fixedRun, platform = process.platform, requiresReservation = true } = {}) {
  if (!admission || admission.contractVersion !== CUSTODY_VERSION) fail("admission is not a worktree custody record");
  if (requiresReservation && !admission.reservation) fail("a verified JobStore destination reservation is required before worktree creation");
  // Re-admit immediately before side effects so a parent swap or link insertion
  // cannot turn a previously safe object into a target of the fixed Git command.
  const fresh = admitWorktree({ jobId: admission.jobId, source: {
    repositoryRoot: admission.sourceRoot, sourceSha: admission.sourceSha, destinationRoot: admission.destinationRoot, branchPolicy: admission.branchPolicy
  }, stateRoot: admission.stateRoot, reservation: admission.reservation, run, platform });
  if (fresh.sourceCustodyDigest !== admission.sourceCustodyDigest ||
      !samePath(fresh.destinationParent, admission.destinationParent, platform) ||
      !samePath(fresh.destinationRoot, admission.destinationRoot, platform) ||
      !samePath(fresh.sourceControlRoot, admission.sourceControlRoot, platform) ||
      !samePath(fresh.stateRoot, admission.stateRoot, platform) ||
      canonical(fresh.identities) !== canonical(admission.identities)) {
    fail("source, destination parent, control root, or state-root custody drifted before worktree creation");
  }
  const args = fresh.branchPolicy === "detached"
    ? ["worktree", "add", "--detach", fresh.destinationRoot, fresh.sourceSha]
    : ["worktree", "add", "-b", `grok-job-${fresh.jobId}`, fresh.destinationRoot, fresh.sourceSha];
  git(run, fresh.sourceRoot, args);
  const destination = assertExistingPlainPath(fresh.destinationRoot, "created linked worktree");
  if (!samePath(destination, fresh.destinationRoot, platform)) fail("created worktree canonical path drifted");
  const metadata = requiredLinkedMetadata(run, destination, fresh.sourceSha, platform);
  const branch = git(run, destination, ["branch", "--show-current"]).trim();
  if (fresh.branchPolicy === "detached" ? branch !== "" : branch !== `grok-job-${fresh.jobId}`) fail("linked worktree branch policy was not realized");
  const custody = {
    ...fresh, destinationRoot: destination, linkedWorktree: true, branch,
    metadata, worktreeCustodyDigest: digestOf({ contractVersion: CUSTODY_VERSION, sourceCustodyDigest: fresh.sourceCustodyDigest, jobId: fresh.jobId, destinationRoot: normalizedCase(destination, platform), branch, metadata })
  };
  return Object.freeze(custody);
}

export function createAdmittedWorktree(admission, options = {}) {
  return materializeAdmittedWorktree(admission, { ...options, requiresReservation: true });
}

/**
 * Materialize the packet-owned, detached worktree used by a one-shot task.
 * One-shot runs persist their own immutable attempts and receipt claims, so
 * they deliberately do not create or depend on the retired JobStore lifecycle.
 */
export function createOneShotWorktree({ taskRunId, repositoryRoot, sourceSha, worktree, stateRoot } = {}, { run = fixedRun, platform = process.platform } = {}) {
  const admission = admitWorktree({
    jobId: taskRunId,
    source: { repositoryRoot, sourceSha, destinationRoot: worktree, branchPolicy: "detached" },
    stateRoot,
    run,
    platform
  });
  return materializeAdmittedWorktree(admission, { run, platform, requiresReservation: false });
}

function metadataForPath(root, relativePath, budget, platform) {
  const absolute = join(root, relativePath);
  assertContainedPlainPath(root, absolute, `inventory path ${relativePath}`, platform);
  let details;
  try { details = lstatSync(absolute); }
  catch (error) {
    if (error?.code === "ENOENT") return { path: relativePath, kind: "missing" };
    throw error;
  }
  if (details.isDirectory()) return { path: relativePath, kind: "directory", mode: details.mode };
  if (!details.isFile()) fail(`inventory path ${relativePath} is not a regular file`);
  if (details.size > budget.remaining) fail("worktree inventory exceeds maximum byte count");
  const hashed = boundedFileDigest(absolute, `inventory path ${relativePath}`, budget.remaining, details);
  budget.remaining -= hashed.bytes;
  return { path: relativePath, kind: "file", mode: hashed.mode, bytes: hashed.bytes, digest: hashed.digest };
}

function assertContainedPlainPath(root, target, label, platform) {
  if (!isWithin(root, target, platform)) fail(`${label} escapes the worktree`);
  const pathFromRoot = relative(root, target);
  let cursor = root;
  for (const part of pathFromRoot.split(sep).filter(Boolean)) {
    cursor = join(cursor, part);
    if (existsSync(cursor) && isLinkOrReparse(cursor)) fail(`${label} traverses a symlink, junction, or reparse point`);
  }
}

function immutablePackageJson(run, root, sourceSha, relativePath) {
  const absolute = join(root, relativePath);
  let details;
  try { details = lstatSync(absolute); } catch { fail("installed local dependencies require immutable package metadata"); }
  if (isLinkOrReparse(details) || !details.isFile() || details.size > MAX_PACKAGE_METADATA_BYTES) fail("installed local dependency package metadata is unsafe");
  const expectedBlob = git(run, root, ["rev-parse", `${sourceSha}:${relativePath}`]).trim();
  const currentBlob = git(run, root, ["hash-object", "--no-filters", "--", relativePath]).trim();
  if (!/^[a-f0-9]{40}$/.test(expectedBlob) || currentBlob !== expectedBlob) fail("installed local dependency package metadata drifted");
  let parsed;
  try { parsed = JSON.parse(readFileSync(absolute, "utf8")); } catch { fail("installed local dependency package metadata is malformed"); }
  if (!plainObject(parsed)) fail("installed local dependency package metadata is malformed");
  return parsed;
}

function safePackageRelative(value) {
  if (typeof value !== "string" || value.length === 0 || isAbsolute(value)) return null;
  const normalized = value.replaceAll("\\", "/").replace(/^\.\//, "").replace(/\/$/, "");
  if (!normalized || normalized.split("/").some((part) => ["", ".", ".."].includes(part)) || normalized === "node_modules" || normalized.startsWith("node_modules/")) return null;
  return normalized;
}

function allowedLocalDependencyLinks(run, root, custody, platform) {
  const modulesRoot = join(root, "node_modules");
  if (!existsSync(modulesRoot)) return new Map();
  const modulesDetails = lstatSync(modulesRoot);
  if (isLinkOrReparse(modulesDetails) || !modulesDetails.isDirectory()) fail("node_modules must be a plain directory");
  if (nulPaths(git(run, root, ["ls-files", "-z", "--", "node_modules"]), "tracked dependency inventory").length !== 0) {
    fail("node_modules must not contain tracked or staged paths");
  }
  const manifest = immutablePackageJson(run, root, custody.sourceSha, "package.json");
  const lock = immutablePackageJson(run, root, custody.sourceSha, "package-lock.json");
  if (![2, 3].includes(lock.lockfileVersion) || !plainObject(lock.packages)) fail("installed local dependency lockfile is unsupported");
  const declarations = { ...(plainObject(manifest.dependencies) ? manifest.dependencies : {}), ...(plainObject(manifest.devDependencies) ? manifest.devDependencies : {}), ...(plainObject(manifest.optionalDependencies) ? manifest.optionalDependencies : {}) };
  const lockRoot = lock.packages[""];
  const lockedDeclarations = plainObject(lockRoot) ? { ...(plainObject(lockRoot.dependencies) ? lockRoot.dependencies : {}), ...(plainObject(lockRoot.devDependencies) ? lockRoot.devDependencies : {}), ...(plainObject(lockRoot.optionalDependencies) ? lockRoot.optionalDependencies : {}) } : {};
  const allowed = new Map();
  for (const [name, specification] of Object.entries(declarations)) {
    if (typeof specification !== "string" || !specification.startsWith("file:")) continue;
    if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(name)) fail("installed local dependency name is unsafe");
    const targetRelative = safePackageRelative(specification.slice("file:".length));
    if (targetRelative === null) fail("installed local dependency target is unsafe");
    const linkRelative = `node_modules/${name}`;
    const locked = lock.packages[linkRelative];
    const lockedTarget = plainObject(locked) && locked.link === true ? safePackageRelative(String(locked.resolved ?? "")) : null;
    const lockedTargetPackage = lock.packages[targetRelative];
    if (lockedDeclarations[name] !== specification || lockedTarget !== targetRelative || !plainObject(lockedTargetPackage) || lockedTargetPackage.name !== name) fail("installed local dependency mapping differs from the immutable lockfile");
    const link = join(root, ...linkRelative.split("/")), target = join(root, ...targetRelative.split("/"));
    if (!existsSync(link)) continue;
    if (!isLinkOrReparse(link) || !existsSync(target) || isLinkOrReparse(target) || !lstatSync(target).isDirectory() ||
        !isWithin(root, target, platform) || !samePath(realpathSync(link), realpathSync(target), platform)) {
      fail("installed local dependency link target differs from its immutable mapping");
    }
    allowed.set(normalizedCase(link, platform), normalizedCase(realpathSync(target), platform));
  }
  return allowed;
}

function assertTreePlain(root, limit = { entries: 0 }, allowedLinks = new Map(), platform = process.platform) {
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.name === ".git") continue;
    const child = join(root, entry.name);
    if (++limit.entries > MAX_INVENTORY_ENTRIES) fail("worktree inventory exceeds maximum entry count");
    if (isLinkOrReparse(child)) {
      const expectedTarget = allowedLinks.get(normalizedCase(child, platform));
      if (expectedTarget === undefined || normalizedCase(realpathSync(child), platform) !== expectedTarget) fail("worktree contains an unapproved symlink, junction, or reparse point");
      continue;
    }
    if (!entry.isDirectory() && !entry.isFile()) fail("worktree contains a special filesystem entry");
    if (entry.isDirectory()) assertTreePlain(child, limit, allowedLinks, platform);
  }
  return limit.entries;
}

function changedTracked(run, root) {
  const raw = git(run, root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"]);
  const records = raw.split("\0").filter(Boolean);
  const entries = [];
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (record.length < 4) fail("Git status emitted a malformed entry");
    const status = record.slice(0, 2);
    const path = record.slice(3).replaceAll("\\", "/");
    if (!path || path.startsWith("/") || path.split("/").some((part) => ["", ".", ".."].includes(part))) fail("Git status emitted an unsafe path");
    entries.push({ status, path });
    if (status.includes("R") || status.includes("C")) {
      const prior = records[++index];
      if (!prior) fail("Git status emitted an incomplete rename entry");
      entries.push({ status: `${status}:prior`, path: prior.replaceAll("\\", "/") });
    }
  }
  return entries;
}

export function inventoryWorktreeCandidate(custody, { run = fixedRun, platform = process.platform } = {}) {
  if (!custody?.linkedWorktree || !custody.worktreeCustodyDigest) fail("linked worktree custody is required");
  const root = assertExistingPlainPath(custody.destinationRoot, "candidate worktree");
  if (!samePath(root, custody.destinationRoot, platform)) fail("candidate worktree path drifted");
  // Re-check all three roots at the collection boundary. A forged or stale
  // custody object must not turn a primary checkout, state directory, or an
  // overlapping path alias into an apparently valid linked candidate.
  const sourceRoot = assertExistingPlainPath(custody.sourceRoot, "source repository");
  const stateRoot = assertExistingPlainPath(custody.stateRoot, "stateRoot");
  if (overlaps(sourceRoot, root, platform)) fail("source repository overlaps candidate worktree");
  if (overlaps(stateRoot, root, platform)) fail("stateRoot overlaps candidate worktree");
  if (overlaps(stateRoot, sourceRoot, platform)) fail("stateRoot overlaps source repository");
  // Do this before status/list-files: a post-creation local config could point
  // Git at a filter process, and candidate revalidation must never invoke it.
  assertNoExternalGitProcesses(run, root);
  const currentMetadata = requiredLinkedMetadata(run, root, custody.sourceSha, platform, { requireClean: false });
  if (!metadataMatches(currentMetadata, custody.metadata)) fail("protected linked Git metadata drifted");
  const allowedDependencyLinks = allowedLocalDependencyLinks(run, root, custody, platform);
  assertTreePlain(root, { entries: 0 }, allowedDependencyLinks, platform);
  const candidates = [
    ...changedTracked(run, root),
    ...nulPaths(git(run, root, ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"]), "ignored inventory")
      .map((path) => ({ status: "ignored", path: path.replaceAll("\\", "/") }))
  ].filter(({ path }) => path !== "node_modules" && !path.startsWith("node_modules/"))
    .sort((left, right) => canonical(left).localeCompare(canonical(right)));
  if (candidates.length > MAX_INVENTORY_ENTRIES) fail("worktree inventory exceeds maximum entry count");
  const budget = { remaining: MAX_INVENTORY_BYTES };
  const all = candidates.map(({ status, path }) => ({ status, ...metadataForPath(root, path, budget, platform) }));
  const bytes = all.reduce((total, entry) => total + (entry.bytes ?? 0), 0);
  const inventory = {
    contractVersion: INVENTORY_VERSION, sourceSha: custody.sourceSha, worktreeCustodyDigest: custody.worktreeCustodyDigest,
    protectedGitMetadata: currentMetadata, entries: all, totalEntries: all.length, totalBytes: bytes
  };
  return Object.freeze({ ...inventory, inventoryDigest: digestOf(inventory) });
}

export function revalidateWorktreeCustody(custody, expectedInventory = null, options = {}) {
  const inventory = inventoryWorktreeCandidate(custody, options);
  if (expectedInventory !== null && !inventoryMatches(inventory, expectedInventory)) {
    fail("candidate inventory or custody digest no longer matches the collected candidate");
  }
  return inventory;
}

// The durable JobStore owns the reservation record and any eventual release.
// This guard deliberately has no filesystem side effect: it never removes a
// worktree and keeps reservation release impossible during review, repair,
// cancellation uncertainty, or recovery.
export function mayReleaseWorktreeReservation(state) { return TERMINAL_STATES.has(state); }
export function assertReservationReleaseEligible(state) {
  if (!mayReleaseWorktreeReservation(state)) fail("worktree reservation may be released only from a terminal job state");
  return true;
}
