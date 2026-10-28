import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { JobStore } from "../src/job-store.mjs";
import { CONTRACT_VERSIONS } from "../src/contracts.mjs";
import {
  WorktreeCustodyError, admitWorktree, createAdmittedWorktree, createOneShotWorktree, inventoryWorktreeCandidate,
  revalidateWorktreeCustody, reserveAdmittedDestination, assertReservationReleaseEligible, mayReleaseWorktreeReservation
} from "../src/worktree-custody.mjs";

const evidenceDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: options.cwd, env: options.env ?? process.env, encoding: "utf8", shell: false, windowsHide: true });
  if (result.error) throw result.error;
  return { status: result.status ?? -1, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}
function git(root, ...args) {
  const result = run("git", args, { cwd: root });
  assert.equal(result.status, 0, `git ${args.join(" ")}: ${result.stderr}`);
  return result.stdout.trim();
}
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "grok-worktree-custody-"));
  const repository = join(root, "source");
  const stateRoot = join(root, "state");
  mkdirSync(repository); mkdirSync(stateRoot); mkdirSync(join(root, "worktrees"));
  git(repository, "init"); git(repository, "config", "user.email", "fixture@example.test"); git(repository, "config", "user.name", "Fixture");
  writeFileSync(join(repository, ".gitignore"), "build/\nnode_modules/\n");
  writeFileSync(join(repository, "tracked.txt"), "base\n");
  writeFileSync(join(repository, "delete.txt"), "delete\n");
  git(repository, "add", "."); git(repository, "commit", "-m", "base");
  return { root, repository, stateRoot, sha: git(repository, "rev-parse", "HEAD") };
}
function cleanup(root) { rmSync(root, { recursive: true, force: true, maxRetries: 3 }); }
function source(fixtureRoot, destination, policy = "detached") {
  return { repositoryRoot: fixtureRoot.repository, sourceSha: fixtureRoot.sha, destinationRoot: destination, branchPolicy: policy };
}
function reserve(fixtureRoot, destination, jobId = "job-001", policy = "detached") {
  const store = new JobStore({ stateRoot: fixtureRoot.stateRoot });
  const admitted = admitWorktree({ jobId, source: source(fixtureRoot, destination, policy), stateRoot: fixtureRoot.stateRoot });
  return reserveAdmittedDestination(admitted, store);
}
function create(fixtureRoot, destination, jobId = "job-001", policy = "detached", options = {}) {
  return createAdmittedWorktree(reserve(fixtureRoot, destination, jobId, policy), options);
}
function linkedIndexPath(custody) {
  const pointer = readFileSync(join(custody.destinationRoot, ".git"), "utf8").slice("gitdir: ".length).trim();
  return resolve(custody.destinationRoot, pointer, "index");
}
function addLocalFileDependency(f) {
  mkdirSync(join(f.repository, "vendor", "path-rules"), { recursive: true });
  writeFileSync(join(f.repository, "vendor", "path-rules", "package.json"), JSON.stringify({ name: "@synthetic/path-rules", version: "1.0.0" }));
  writeFileSync(join(f.repository, "vendor", "path-rules", "index.js"), "export const fixture = true;\n");
  writeFileSync(join(f.repository, "package.json"), JSON.stringify({ name: "synthetic-fixture", version: "1.0.0", dependencies: { "@synthetic/path-rules": "file:vendor/path-rules" } }));
  writeFileSync(join(f.repository, "package-lock.json"), JSON.stringify({ name: "synthetic-fixture", version: "1.0.0", lockfileVersion: 3, packages: {
    "": { name: "synthetic-fixture", version: "1.0.0", dependencies: { "@synthetic/path-rules": "file:vendor/path-rules" } },
    "node_modules/@synthetic/path-rules": { resolved: "vendor/path-rules", link: true },
    "vendor/path-rules": { name: "@synthetic/path-rules", version: "1.0.0" }
  } }));
  git(f.repository, "add", "."); git(f.repository, "commit", "-m", "local dependency fixture");
  f.sha = git(f.repository, "rev-parse", "HEAD");
}

test("creates a clean immutable detached worktree without copying dirty primary changes", () => {
  const f = fixture();
  try {
    writeFileSync(join(f.repository, "primary-only.txt"), "unrelated primary dirt\n");
    const custody = create(f, join(f.root, "worktrees", "job-001"));
    assert.equal(custody.branch, "");
    assert.equal(git(custody.destinationRoot, "rev-parse", "HEAD"), f.sha);
    assert.equal(existsSync(join(custody.destinationRoot, "primary-only.txt")), false);
    assert.match(readFileSync(join(custody.destinationRoot, ".git"), "utf8"), /^gitdir: /);
    assert.match(git(f.repository, "status", "--porcelain"), /\?\? primary-only\.txt/);
    assert.equal(git(custody.destinationRoot, "status", "--porcelain"), "");
    assert.equal(custody.metadata.head, f.sha);
  } finally { cleanup(f.root); }
});

test("one-shot packet worktree creation needs no retired JobStore reservation", () => {
  const f = fixture();
  try {
    writeFileSync(join(f.repository, "primary-only.txt"), "unrelated primary dirt\n");
    const destination = join(f.root, "worktrees", "run-001");
    const custody = createOneShotWorktree({ taskRunId: "run-001", repositoryRoot: f.repository, sourceSha: f.sha, worktree: destination, stateRoot: f.stateRoot });
    assert.equal(custody.branch, "");
    assert.equal(git(custody.destinationRoot, "rev-parse", "HEAD"), f.sha);
    assert.equal(existsSync(join(custody.destinationRoot, "primary-only.txt")), false);
    assert.throws(() => createOneShotWorktree({ taskRunId: "run-001", repositoryRoot: f.repository, sourceSha: f.sha, worktree: destination, stateRoot: f.stateRoot }), /must not already exist/);
  } finally { cleanup(f.root); }
});

test("requires Git-authoritative linked-worktree custody and rejects primary or drifted roots", () => {
  const f = fixture();
  try {
    const custody = create(f, join(f.root, "worktrees", "job-001"));
    assert.throws(() => inventoryWorktreeCandidate({ ...custody, linkedWorktree: false }), /linked worktree custody is required/);
    assert.throws(() => inventoryWorktreeCandidate({ ...custody, destinationRoot: f.repository }), /overlaps|candidate worktree path drifted|plain indirection|linked Git/);
    assert.throws(() => inventoryWorktreeCandidate({ ...custody, sourceSha: "b".repeat(40) }), /HEAD does not match immutable source SHA/);
    assert.doesNotThrow(() => inventoryWorktreeCandidate(custody));
  } finally { cleanup(f.root); }
});

test("realizes only the fixed unique mission branch name", () => {
  const f = fixture();
  try {
    const custody = create(f, join(f.root, "worktrees", "job-branch"), "job-branch", "unique_mission_branch");
    assert.equal(custody.branch, "grok-job-job-branch");
    assert.equal(git(custody.destinationRoot, "branch", "--show-current"), "grok-job-job-branch");
  } finally { cleanup(f.root); }
});

test("rejects moving refs, arbitrary fields, existing destinations, nesting, overlaps, and state-root escapes", () => {
  const f = fixture();
  try {
    assert.throws(() => admitWorktree({ jobId: "job-001", source: { ...source(f, join(f.root, "dest")), sourceSha: "HEAD" }, stateRoot: f.stateRoot }), WorktreeCustodyError);
    assert.throws(() => admitWorktree({ jobId: "job-001", source: { ...source(f, join(f.root, "dest")), command: ["worktree", "add"] }, stateRoot: f.stateRoot }), /unsupported/);
    mkdirSync(join(f.root, "already"));
    assert.throws(() => admitWorktree({ jobId: "job-001", source: source(f, join(f.root, "already")), stateRoot: f.stateRoot }), /must not already exist/);
    assert.throws(() => admitWorktree({ jobId: "job-001", source: source(f, join(f.repository, "nested")), stateRoot: f.stateRoot }), /overlaps|inside an existing Git checkout/);
    assert.throws(() => admitWorktree({ jobId: "job-001", source: source(f, join(f.stateRoot, "nested")), stateRoot: f.stateRoot }), /overlaps/);
    assert.throws(() => admitWorktree({ jobId: "job-001", source: source(f, `${join(f.root, "worktrees")}\\..\\not-canonical`), stateRoot: f.stateRoot }), /canonical/);
    if (process.platform !== "win32") mkdirSync(join(f.root, "SOURCE"));
    assert.throws(() => admitWorktree({ jobId: "job-001", source: source(f, join(f.root, "SOURCE", "case-alias")), stateRoot: f.stateRoot, platform: "win32" }), /overlaps|inside an existing Git checkout/);
  } finally { cleanup(f.root); }
});

test("consumes the JobStore's durable canonical destination reservation without recreating it", () => {
  const f = fixture();
  try {
    const destination = join(f.root, "worktrees", "job-001");
    const store = new JobStore({ stateRoot: f.stateRoot });
    const admitted = admitWorktree({ jobId: "job-001", source: source(f, destination), stateRoot: f.stateRoot });
    const reserved = reserveAdmittedDestination(admitted, store);
    assert.equal(reserved.reservation.jobId, "job-001");
    assert.throws(() => admitWorktree({ jobId: "job-002", source: source(f, destination), stateRoot: f.stateRoot, reservation: reserved.reservation }), /does not bind/);
    assert.throws(() => store.reserve(destination.replaceAll("\\", "/").toLowerCase(), "job-002"), /reservation/);
  } finally { cleanup(f.root); }
});

test("refuses worktree creation until the exact JobStore reservation is bound", () => {
  const f = fixture();
  try {
    const destination = join(f.root, "worktrees", "job-001");
    const admitted = admitWorktree({ jobId: "job-001", source: source(f, destination), stateRoot: f.stateRoot });
    assert.throws(() => createAdmittedWorktree(admitted), /reservation is required/);
    assert.equal(existsSync(destination), false);
  } finally { cleanup(f.root); }
});

test("fails closed when the admitted destination parent is replaced before Git worktree creation", () => {
  const f = fixture();
  try {
    const destination = join(f.root, "worktrees", "job-001");
    const admitted = reserve(f, destination);
    renameSync(join(f.root, "worktrees"), join(f.root, "worktrees-original"));
    mkdirSync(join(f.root, "worktrees"));
    assert.throws(() => createAdmittedWorktree(admitted), /custody drifted/);
  } finally { cleanup(f.root); }
});

test("suppresses repository hooks, strips credential-shaped environment, and rejects local external filters", () => {
  const f = fixture();
  const sentinel = join(f.root, "hook-sentinel.txt").replaceAll("\\", "/");
  const hook = join(f.repository, ".git", "hooks", "post-checkout");
  const oldSecret = process.env.FIXTURE_CREDENTIAL;
  try {
    writeFileSync(hook, `#!/bin/sh\nprintf '%s' "${"${FIXTURE_CREDENTIAL-unset}"}" > '${sentinel}'\n`);
    chmodSync(hook, 0o755);
    process.env.FIXTURE_CREDENTIAL = "credential-shaped-fixture-secret";
    const calls = [];
    const custody = create(f, join(f.root, "worktrees", "job-001"), "job-001", "detached", {
      run(command, args, options) { calls.push({ command, args, env: options.env }); return run(command, args, options); }
    });
    assert.equal(custody.linkedWorktree, true);
    assert.equal(existsSync(sentinel), false, "post-checkout hook must not execute");
    assert.ok(calls.length > 0);
    assert.ok(calls.every((call) => call.command === "git" && !Object.hasOwn(call.env, "FIXTURE_CREDENTIAL")));
    assert.ok(calls.every((call) => call.env.GIT_OPTIONAL_LOCKS === "0"));
    if (process.platform === "win32") {
      assert.ok(calls.every((call) => call.env.GIT_CONFIG_KEY_2 === "core.longpaths"));
      assert.ok(calls.every((call) => call.env.GIT_CONFIG_VALUE_2 === "true"));
      assert.ok(calls.every((call) => !call.args.includes("core.longpaths=true")));
    }
    git(f.repository, "config", "filter.evil.smudge", `printf hook > '${sentinel}'`);
    assert.throws(() => admitWorktree({ jobId: "job-002", source: source(f, join(f.root, "worktrees", "job-002")), stateRoot: f.stateRoot }), /external Git filter/);
  } finally {
    if (oldSecret === undefined) delete process.env.FIXTURE_CREDENTIAL;
    else process.env.FIXTURE_CREDENTIAL = oldSecret;
    cleanup(f.root);
  }
});

test("rejects source and destination link escapes where the host supports a local symlink or junction", (t) => {
  const f = fixture();
  try {
    const parent = join(f.root, "link-parent");
    try { symlinkSync(f.root, parent, process.platform === "win32" ? "junction" : "dir"); }
    catch (error) { t.skip(`local ${process.platform === "win32" ? "junction" : "symlink"} fixture unavailable: ${error.code ?? "unknown"}`); return; }
    assert.throws(() => admitWorktree({ jobId: "job-001", source: source(f, join(parent, "worktrees", "job-001")), stateRoot: f.stateRoot }), /symlink|junction|reparse/);
  } finally { cleanup(f.root); }
});

test("inventories tracked modifications, deletion, untracked and ignored paths without persisting raw content", () => {
  const f = fixture();
  try {
    const custody = create(f, join(f.root, "worktrees", "job-001"));
    writeFileSync(join(custody.destinationRoot, "tracked.txt"), "secret-like candidate content\n");
    rmSync(join(custody.destinationRoot, "delete.txt"));
    writeFileSync(join(custody.destinationRoot, "untracked.txt"), "untracked\n");
    mkdirSync(join(custody.destinationRoot, "build")); writeFileSync(join(custody.destinationRoot, "build", "artifact.bin"), "ignored\n");
    const inventory = inventoryWorktreeCandidate(custody);
    const paths = inventory.entries.map((entry) => `${entry.status}:${entry.path}`).sort();
    assert.deepEqual(paths, [" D:delete.txt", " M:tracked.txt", "??:untracked.txt", "ignored:build/artifact.bin"]);
    assert.doesNotMatch(JSON.stringify(inventory), /secret-like candidate content|untracked\\n/);
    assert.match(inventory.inventoryDigest, /^sha256:/);
    assert.equal(revalidateWorktreeCustody(custody, inventory).inventoryDigest, inventory.inventoryDigest);
  } finally { cleanup(f.root); }
});

test("admits the exact immutable local-file dependency link and excludes node_modules from candidate content", (t) => {
  const f = fixture();
  try {
    addLocalFileDependency(f);
    const custody = create(f, join(f.root, "worktrees", "job-local-dependency"), "job-local-dependency");
    const scope = join(custody.destinationRoot, "node_modules", "@synthetic"); mkdirSync(scope, { recursive: true });
    const link = join(scope, "path-rules"), target = join(custody.destinationRoot, "vendor", "path-rules");
    try { symlinkSync(target, link, process.platform === "win32" ? "junction" : "dir"); }
    catch (error) { t.skip(`local dependency link fixture unavailable: ${error.code ?? "unknown"}`); return; }
    const inventory = inventoryWorktreeCandidate(custody);
    assert.equal(inventory.entries.some((entry) => entry.path === "node_modules" || entry.path.startsWith("node_modules/")), false);
    assert.equal(revalidateWorktreeCustody(custody, inventory).inventoryDigest, inventory.inventoryDigest);
    rmSync(link, { recursive: true, force: true }); mkdirSync(join(custody.destinationRoot, "vendor", "other"));
    symlinkSync(join(custody.destinationRoot, "vendor", "other"), link, process.platform === "win32" ? "junction" : "dir");
    assert.throws(() => inventoryWorktreeCandidate(custody), /target differs|immutable mapping|unapproved/i);
  } finally { cleanup(f.root); }
});

test("rejects unlisted, external, nested, staged, and lock-drifted dependency links", (t) => {
  for (const scenario of ["unlisted", "external", "nested", "staged", "lock-drift"]) {
    const f = fixture();
    try {
      addLocalFileDependency(f);
      const custody = create(f, join(f.root, "worktrees", `job-${scenario}`), `job-${scenario}`);
      const scope = join(custody.destinationRoot, "node_modules", "@synthetic"); mkdirSync(scope, { recursive: true });
      const link = join(scope, "path-rules"), target = join(custody.destinationRoot, "vendor", "path-rules");
      try { symlinkSync(target, link, process.platform === "win32" ? "junction" : "dir"); }
      catch (error) { t.skip(`dependency link fixture unavailable: ${error.code ?? "unknown"}`); return; }
      if (scenario === "unlisted") symlinkSync(target, join(scope, "unlisted"), process.platform === "win32" ? "junction" : "dir");
      if (scenario === "external") { rmSync(link, { recursive: true, force: true }); symlinkSync(f.root, link, process.platform === "win32" ? "junction" : "dir"); }
      if (scenario === "nested") {
        const nestedTarget = join(custody.destinationRoot, "vendor", "nested-target"); mkdirSync(nestedTarget);
        try { symlinkSync(nestedTarget, join(target, "nested-link"), process.platform === "win32" ? "junction" : "dir"); }
        catch (error) { if (process.platform === "win32") { t.diagnostic(`nested symlink unavailable: ${error.code ?? "unknown"}`); continue; } throw error; }
      }
      if (scenario === "staged") git(custody.destinationRoot, "add", "-f", "node_modules/@synthetic/path-rules");
      if (scenario === "lock-drift") writeFileSync(join(custody.destinationRoot, "package-lock.json"), "{}\n");
      assert.throws(() => inventoryWorktreeCandidate(custody), /symlink|junction|reparse|target|metadata|staged|staging|lockfile|package metadata|tracked/i, scenario);
    } finally { cleanup(f.root); }
  }
});

test("fails candidate revalidation after path or protected metadata mutation", () => {
  const f = fixture();
  try {
    const custody = create(f, join(f.root, "worktrees", "job-001"));
    const inventory = inventoryWorktreeCandidate(custody);
    writeFileSync(join(custody.destinationRoot, "untracked.txt"), "changed after collection\n");
    assert.throws(() => revalidateWorktreeCustody(custody, inventory), /inventory|custody/);
    rmSync(join(custody.destinationRoot, "untracked.txt"));
    rmSync(join(custody.destinationRoot, ".git"), { force: true });
    writeFileSync(join(custody.destinationRoot, ".git"), "gitdir: nowhere\n");
    assert.throws(() => inventoryWorktreeCandidate(custody), /fixed Git command failed|linked Git directory|metadata|does not exist/);
  } finally { cleanup(f.root); }
});

test("semantic index custody accepts stat-cache and atomic identity refreshes but rejects malformed or staged indexes", () => {
  const f = fixture();
  try {
    const custody = create(f, join(f.root, "worktrees", "job-001"));
    const legacyIndex = { kind: "file", bytes: custody.metadata.gitDirIndex.bytes, mode: custody.metadata.gitDirIndex.mode, digest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" };
    const legacy = structuredClone(custody); legacy.metadata.gitDirIndex = legacyIndex;
    const legacyInventory = structuredClone(inventoryWorktreeCandidate(custody)); legacyInventory.protectedGitMetadata.gitDirIndex = legacyIndex;
    git(custody.destinationRoot, "status", "--porcelain=v1", "--untracked-files=all");
    assert.doesNotThrow(() => revalidateWorktreeCustody(legacy, legacyInventory), "legacy raw index-byte digest must not reject a semantic no-staging revalidation");
    const index = linkedIndexPath(custody), preserved = `${index}.preserved`, contents = readFileSync(index);
    renameSync(index, preserved); writeFileSync(index, contents);
    assert.doesNotThrow(() => inventoryWorktreeCandidate(custody), "an atomic same-semantic index replacement is a normal Git refresh");
    writeFileSync(index, "not a Git index");
    assert.throws(() => inventoryWorktreeCandidate(custody), /fixed Git command failed|index|metadata/);
  } finally { cleanup(f.root); }
});

test("semantic index custody rejects assume-unchanged and skip-worktree visibility bypasses", () => {
  const f = fixture();
  try {
    const custody = create(f, join(f.root, "worktrees", "job-001"));
    writeFileSync(join(custody.destinationRoot, "tracked.txt"), "hidden candidate\n");
    git(custody.destinationRoot, "update-index", "--assume-unchanged", "tracked.txt");
    assert.throws(() => inventoryWorktreeCandidate(custody), /unsafe path visibility flag/);

    git(custody.destinationRoot, "update-index", "--no-assume-unchanged", "tracked.txt");
    writeFileSync(join(custody.destinationRoot, "tracked.txt"), "base\n");
    git(custody.destinationRoot, "update-index", "--skip-worktree", "tracked.txt");
    writeFileSync(join(custody.destinationRoot, "tracked.txt"), "hidden candidate\n");
    assert.throws(() => inventoryWorktreeCandidate(custody), /unsafe path visibility flag/);
  } finally { cleanup(f.root); }
});

test("semantic index custody preserves valid tracked newline filenames", () => {
  const f = fixture();
  try {
    const newlineRun = (command, args, options) => {
      if (args.includes("ls-files") && args.includes("--stage")) {
        return { status: 0, stdout: `100644 ${"a".repeat(40)} 0\ttracked\nnewline.txt\0`, stderr: "" };
      }
      if (args.includes("ls-files") && args.includes("-v")) {
        return { status: 0, stdout: "H tracked\nnewline.txt\0", stderr: "" };
      }
      return run(command, args, options);
    };
    const custody = create(f, join(f.root, "worktrees", "job-001"), "job-001", "detached", { run: newlineRun });
    assert.doesNotThrow(() => inventoryWorktreeCandidate(custody, { run: newlineRun }));
  } finally { cleanup(f.root); }
});

test("makes staging an explicit prohibited custody mutation and only permits reservation release after terminal state", () => {
  const f = fixture();
  try {
    const custody = create(f, join(f.root, "worktrees", "job-001"));
    writeFileSync(join(custody.destinationRoot, "tracked.txt"), "staged candidate\n");
    git(custody.destinationRoot, "add", "tracked.txt");
    assert.throws(() => inventoryWorktreeCandidate(custody), /staging is prohibited/);
    assert.equal(mayReleaseWorktreeReservation("candidate_ready"), false);
    assert.equal(mayReleaseWorktreeReservation("accepted"), true);
    assert.throws(() => assertReservationReleaseEligible("repairing"), /terminal/);
    assert.equal(assertReservationReleaseEligible("cancelled"), true);
    assert.equal(existsSync(custody.destinationRoot), true, "release guard never deletes a worktree");
  } finally { cleanup(f.root); }
});

test("retained terminal worktrees remain non-nestable after JobStore retires their active claim", () => {
  const f = fixture();
  try {
    const destination = join(f.root, "worktrees", "job-001");
    const store = new JobStore({ stateRoot: f.stateRoot });
    const preliminary = admitWorktree({ jobId: "job-001", source: source(f, destination), stateRoot: f.stateRoot });
    store.submit({
      job: {
        contractVersion: CONTRACT_VERSIONS.job, jobId: "job-001", submissionId: "submission-001",
        state: "queued", profileDigest: evidenceDigest, sourceCustodyDigest: preliminary.sourceCustodyDigest, eventCursor: 0
      },
      admission: {
        destinationRoot: destination, grantDigest: evidenceDigest, receiptDigest: evidenceDigest,
        sourceCustodyDigest: preliminary.sourceCustodyDigest, profileDigest: evidenceDigest
      },
      idempotencyKey: "submit-001"
    });
    const custody = createAdmittedWorktree(reserveAdmittedDestination(preliminary, store));
    const lease = store.acquireExecutionLease("job-001", { ownerId: "owner-001", durationMs: 1_000 });
    const intent = store.cancel("job-001", { reason: "operator_requested", idempotencyKey: "cancel-001", fence: lease.fencingToken });
    store.acknowledgeCancellation("job-001", {
      expectedCancellationDigest: intent.cancellationDigest, idempotencyKey: "cancel-ack-001", fence: lease.fencingToken
    });
    assert.equal(store.releaseReservation("job-001").status, "released");
    assert.equal(existsSync(custody.destinationRoot), true, "terminal release retains the linked worktree");

    assert.throws(() => admitWorktree({
      jobId: "job-002", source: source(f, join(custody.destinationRoot, "nested-job")), stateRoot: f.stateRoot
    }), /inside an existing Git checkout/);
    const sibling = admitWorktree({
      jobId: "job-002", source: source(f, join(f.root, "worktrees", "job-002")), stateRoot: f.stateRoot
    });
    assert.equal(sibling.destinationRoot, resolve(f.root, "worktrees", "job-002"));
  } finally { cleanup(f.root); }
});

test("rejects post-creation local filter configuration before candidate status or file listing", () => {
  const f = fixture();
  try {
    const custody = create(f, join(f.root, "worktrees", "job-001"));
    git(custody.destinationRoot, "config", "filter.evil.smudge", "printf unsafe-filter");
    const calls = [];
    assert.throws(() => inventoryWorktreeCandidate(custody, {
      run(command, args, options) { calls.push({ command, args }); return run(command, args, options); }
    }), /external Git filter/);
    assert.ok(calls.length > 0);
    assert.ok(calls.every((call) => !call.args.includes("status") && !call.args.includes("ls-files")),
      "candidate custody must fail during config preflight before status/list can reach a filter");
  } finally { cleanup(f.root); }
});
