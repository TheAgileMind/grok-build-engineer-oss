import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  ARTIFACT_CONTRACT_VERSION,
  beginArtifactTransaction,
  buildArtifactPrompt,
  executeArtifact,
  parseArtifactOutput,
  persistArtifactDecision,
  persistArtifactEvidence,
  persistRejectedArtifactEvidence,
  prepareArtifactScratch,
  removeArtifactScratch
} from "../src/artifact-delivery.mjs";
import { artifactOnlyPolicyArgs } from "../src/headless-session.mjs";
import { createTaskPolicy, packetDigest } from "../src/task-policy.mjs";
import { CONTRACT_VERSIONS } from "../src/contracts.mjs";

function packet(root) {
  const repositoryRoot = join(root, "source");
  const worktree = join(root, "candidate");
  const stateRoot = join(root, "state");
  mkdirSync(join(worktree, "src"), { recursive: true });
  mkdirSync(join(worktree, "test"), { recursive: true });
  mkdirSync(repositoryRoot, { recursive: true });
  writeFileSync(join(worktree, "README.md"), "public fixture\n");
  writeFileSync(join(worktree, "src", "value.mjs"), "export const value = 1;\n");
  writeFileSync(join(worktree, "test", "value.test.mjs"), "// test\n");
  const value = {
    contractVersion: CONTRACT_VERSIONS.taskPacket,
    taskRunId: "run-artifact-001",
    requestId: "request-artifact-001",
    mode: "implementation",
    delivery: "artifact_only",
    repositoryRoot,
    worktree,
    sourceSha: "0123456789abcdef0123456789abcdef01234567",
    task: {
      title: "Artifact-only change",
      instructions: "Request both denial probes, update src/value.mjs, and validate.",
      contextPaths: ["README.md", "src", "test"]
    },
    policy: {
      allowedPaths: ["src/**", "test/**"],
      allowedCommands: ["node test"],
      allowedEnvironment: [],
      network: "none",
      tools: [],
      timeouts: { startMs: 1000, turnMs: 1000, idleMs: 1000, cancelMs: 1000 },
      repairBudget: 1
    },
    provider: { executable: join(root, "grok.exe"), model: "grok-4.6" },
    stateRoot,
    continuation: null,
    findingsDigest: null,
    approval: {
      contractVersion: CONTRACT_VERSIONS.approvalPacket,
      approvalId: "approval-artifact-001",
      packetDigest: "sha256:" + "0".repeat(64),
      issuedAt: new Date(Date.now() - 1000).toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      approvedBy: "test",
      authorizationStatement: "Test-only artifact authorization."
    }
  };
  value.approval.packetDigest = packetDigest(value);
  return value;
}

function artifact(task) {
  return {
    contractVersion: ARTIFACT_CONTRACT_VERSION,
    taskRunId: task.taskRunId,
    requestId: task.requestId,
    operations: [
      { kind: "write_file", path: "README.md", content: "DENIAL_PROBE\n" },
      { kind: "run_command", command: "node --version" },
      { kind: "write_file", path: "src/value.mjs", content: "export const value = 2;\n" },
      { kind: "run_command", command: "node test" }
    ]
  };
}

function inertTransaction() { return { rollback: () => true, commit: () => true }; }
function linkedPacket(root) {
  const task = packet(root);
  rmSync(task.worktree, { recursive: true, force: true });
  mkdirSync(join(task.repositoryRoot, "src"), { recursive: true });
  mkdirSync(join(task.repositoryRoot, "test"), { recursive: true });
  writeFileSync(join(task.repositoryRoot, "README.md"), "public fixture\n");
  writeFileSync(join(task.repositoryRoot, "src", "value.mjs"), "export const value = 1;\n");
  writeFileSync(join(task.repositoryRoot, "test", "value.test.mjs"), "// test\n");
  const git = (cwd, args) => {
    const result = spawnSync("git", ["-c", "user.name=Test", "-c", "user.email=test@example.com", ...args], { cwd, encoding: "utf8", windowsHide: true });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };
  git(task.repositoryRoot, ["init", "--quiet"]);
  git(task.repositoryRoot, ["add", "."]);
  git(task.repositoryRoot, ["commit", "--quiet", "-m", "base"]);
  task.sourceSha = git(task.repositoryRoot, ["rev-parse", "HEAD"]);
  git(task.repositoryRoot, ["worktree", "add", "--quiet", "--detach", task.worktree, task.sourceSha]);
  task.approval.packetDigest = packetDigest(task);
  return task;
}

test("artifact-only prompt embeds bounded relative context and exposes no host paths", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-artifact-prompt-"));
  try {
    const task = packet(root);
    const prompt = buildArtifactPrompt({ packet: task });
    assert.match(prompt, /artifact-only/i);
    assert.match(prompt, /src\/value\.mjs/);
    assert.match(prompt, /export const value = 1/);
    assert.doesNotMatch(prompt, new RegExp(root.replaceAll("\\", "\\\\"), "i"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("artifact-only prompt gives an exact task-bound schema and forbids provider tool kinds", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-artifact-schema-prompt-"));
  try {
    const task = packet(root);
    const prompt = buildArtifactPrompt({ packet: task });
    assert.match(prompt, /kind must be exactly one of: "write_file", "delete_file", "run_command"/i);
    for (const legacyKind of ["search_replace", "read_file", "grep", "list_dir", "run_terminal_cmd", "tool_call"]) assert.match(prompt, new RegExp(`\\b${legacyKind}\\b`));
    assert.match(prompt, /prohibited-path denial probe as a write_file or delete_file operation.*prohibited-command denial probe as a run_command operation.*do not invent another kind/i);
    const marker = "Exact task-bound JSON artifact example:\n";
    const exampleLine = prompt.slice(prompt.indexOf(marker) + marker.length).split("\n", 1)[0];
    const example = JSON.parse(exampleLine);
    assert.equal(example.contractVersion, ARTIFACT_CONTRACT_VERSION);
    assert.equal(example.taskRunId, task.taskRunId);
    assert.equal(example.requestId, task.requestId);
    assert.deepEqual(example.operations.map(({ kind }) => kind), ["write_file", "delete_file", "run_command"]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("artifact prompt and returned artifact fail closed on secret-shaped data", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-artifact-secret-"));
  try {
    const task = packet(root);
    writeFileSync(join(task.worktree, "src", "secret.txt"), "api_key=sk-proj-12345678901234567890\n");
    assert.throws(() => buildArtifactPrompt({ packet: task }), /secret-shaped/i);
    rmSync(join(task.worktree, "src", "secret.txt"));
    const returned = artifact(task);
    returned.operations[2].content = "token: sk-proj-12345678901234567890\n";
    assert.throws(() => parseArtifactOutput(JSON.stringify(returned), task), /secret-shaped/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("artifact boundary permits ordinary credential identifiers but rejects credential values", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-artifact-credential-shapes-"));
  try {
    const task = packet(root);
    writeFileSync(join(task.worktree, "src", "auth.mjs"), "export function header(token) { return `Bearer ${token}`; }\n");
    assert.match(buildArtifactPrompt({ packet: task }), /function header\(token\)/);
    writeFileSync(join(task.worktree, "src", "auth.mjs"), "Authorization: Bearer abcdefghijklmnop\n");
    assert.throws(() => buildArtifactPrompt({ packet: task }), /secret-shaped/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("controller denies prohibited requests, applies allowed files, and runs only allowlisted validation", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-artifact-execute-"));
  try {
    const task = packet(root);
    const parsed = parseArtifactOutput(JSON.stringify(artifact(task)), task);
    const calls = [];
    const result = executeArtifact({
      artifact: parsed,
      packet: task,
      policy: createTaskPolicy(task),
      transaction: inertTransaction(),
      environment: {},
      spawnSyncImpl(command, args, options) {
        calls.push({ command, args, cwd: options.cwd });
        return { status: 0, stdout: "pass\n", stderr: "", error: null };
      }
    });
    assert.equal(result.ok, true);
    assert.deepEqual(result.decisions.map(({ decision }) => decision), ["deny", "deny", "allow", "allow"]);
    assert.equal(readFileSync(join(task.worktree, "README.md"), "utf8"), "public fixture\n");
    assert.equal(readFileSync(join(task.worktree, "src", "value.mjs"), "utf8"), "export const value = 2;\n");
    assert.equal(calls.length, 1);
    assert.deepEqual(result.validationEvidence.map(({ command, exitCode }) => ({ command, exitCode })), [{ command: "node test", exitCode: 0 }]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("failed controller validation rolls back every allowed file effect", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-artifact-rollback-"));
  try {
    const task = linkedPacket(root);
    const attempted = artifact(task);
    attempted.operations.splice(-1, 0, { kind: "write_file", path: "src/new/nested.mjs", content: "export {};\n" });
    const initialReadme = readFileSync(join(task.worktree, "README.md"), "utf8");
    const initialValue = readFileSync(join(task.worktree, "src", "value.mjs"), "utf8");
    const transaction = beginArtifactTransaction({ packet: task });
    const result = executeArtifact({
      artifact: parseArtifactOutput(JSON.stringify(attempted), task),
      packet: task,
      policy: createTaskPolicy(task),
      transaction,
      environment: {},
      spawnSyncImpl: () => {
        writeFileSync(join(task.worktree, "src", "validation-side-effect.mjs"), "export const leaked = true;\n");
        return { status: 1, stdout: "", stderr: "failed\n", error: null };
      }
    });
    assert.equal(result.ok, false);
    transaction.rollback();
    assert.equal(readFileSync(join(task.worktree, "README.md"), "utf8"), initialReadme);
    assert.equal(readFileSync(join(task.worktree, "src", "value.mjs"), "utf8"), initialValue);
    assert.equal(existsSync(join(task.worktree, "src", "new")), false);
    assert.equal(existsSync(join(task.worktree, "src", "validation-side-effect.mjs")), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("artifact transaction preserves an existing dirty repair baseline exactly", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-artifact-repair-baseline-"));
  try {
    const task = linkedPacket(root);
    const valuePath = join(task.worktree, "src", "value.mjs");
    const priorPath = join(task.worktree, "src", "prior.mjs");
    writeFileSync(valuePath, "export const value = 'prior candidate';\n");
    writeFileSync(priorPath, "export const prior = true;\n");
    const transaction = beginArtifactTransaction({ packet: task });
    writeFileSync(valuePath, "export const value = 'failed repair';\n");
    rmSync(priorPath);
    writeFileSync(join(task.worktree, "src", "repair-leak.mjs"), "export const leaked = true;\n");
    transaction.rollback();
    assert.equal(readFileSync(valuePath, "utf8"), "export const value = 'prior candidate';\n");
    assert.equal(readFileSync(priorPath, "utf8"), "export const prior = true;\n");
    assert.equal(existsSync(join(task.worktree, "src", "repair-leak.mjs")), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("allowed file operations cannot appear after controller validation begins", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-artifact-order-"));
  try {
    const task = packet(root);
    const reordered = artifact(task);
    reordered.operations = [reordered.operations[2], reordered.operations[3], { kind: "write_file", path: "src/late.mjs", content: "export {};\n" }];
    assert.throws(() => executeArtifact({ artifact: parseArtifactOutput(JSON.stringify(reordered), task), packet: task, policy: createTaskPolicy(task), transaction: inertTransaction(), environment: {}, spawnSyncImpl: () => ({ status: 0, stdout: "", stderr: "" }) }), /must precede/i);
    assert.equal(existsSync(join(task.worktree, "src", "late.mjs")), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("artifact parser rejects malformed or duplicate operations before effects", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-artifact-invalid-"));
  try {
    const task = packet(root);
    const duplicate = artifact(task);
    duplicate.operations.push({ kind: "delete_file", path: "src/value.mjs" });
    assert.throws(() => parseArtifactOutput(JSON.stringify(duplicate), task), /duplicate/i);
    assert.throws(() => parseArtifactOutput("```json\n{}\n```", task), /JSON|artifact/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("artifact-only provider arguments expose no local tools or allow rules", () => {
  const args = artifactOnlyPolicyArgs();
  assert.equal(args[args.indexOf("--tools") + 1], "");
  assert.equal(args.includes("--allow"), false);
  for (const tool of ["read_file", "grep", "list_dir", "search_replace", "run_terminal_cmd", "Agent", "web_search", "web_fetch"]) {
    assert.match(args[args.indexOf("--disallowed-tools") + 1], new RegExp(`(?:^|,)${tool}(?:,|$)`));
  }
});

test("artifact and decision evidence are immutable and independently persisted", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-artifact-evidence-"));
  try {
    const task = packet(root), parsed = parseArtifactOutput(JSON.stringify(artifact(task)), task);
    const evidence = persistArtifactEvidence({ stateRoot: task.stateRoot, artifact: parsed });
    assert.deepEqual(persistArtifactEvidence({ stateRoot: task.stateRoot, artifact: parsed }), evidence);
    const execution = { ok: true, decisions: [], validationEvidence: [], appliedPaths: ["src/value.mjs"] };
    const first = persistArtifactDecision({ stateRoot: task.stateRoot, artifact: parsed, artifactEvidence: evidence, execution, recordedAt: "2026-08-30T00:00:00.000Z" });
    assert.deepEqual(persistArtifactDecision({ stateRoot: task.stateRoot, artifact: parsed, artifactEvidence: evidence, execution, recordedAt: "2026-08-30T00:01:00.000Z" }), first);
    assert.throws(() => persistArtifactDecision({ stateRoot: task.stateRoot, artifact: parsed, artifactEvidence: evidence, execution: { ...execution, ok: false } }), /conflicts/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejected artifact evidence is bounded, secret-safe, and immutable", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-artifact-rejected-evidence-"));
  try {
    const task = packet(root);
    const output = JSON.stringify({
      contractVersion: ARTIFACT_CONTRACT_VERSION,
      taskRunId: task.taskRunId,
      requestId: task.requestId,
      operations: [
        { kind: "search_replace", path: "src/private-plan.mjs", content: "PRIVATE_SENTINEL_42" },
        ...Array.from({ length: 39 }, (_, index) => ({ kind: `custom_op_${index}`, content: `PRIVATE_${index}` }))
      ]
    });
    let parseError;
    assert.throws(() => parseArtifactOutput(output, task), (error) => { parseError = error; return error.code === "unsupported_operation_kind"; });
    const first = persistRejectedArtifactEvidence({ stateRoot: task.stateRoot, packet: task, output, error: parseError, recordedAt: "2026-08-31T12:00:00.000Z" });
    assert.deepEqual(persistRejectedArtifactEvidence({ stateRoot: task.stateRoot, packet: task, output, error: parseError, recordedAt: "2026-08-31T12:01:00.000Z" }), first);
    const serialized = readFileSync(first.rejectedArtifactPath, "utf8");
    const record = JSON.parse(serialized);
    assert.equal(record.outputDigest, `sha256:${createHash("sha256").update(output).digest("hex")}`);
    assert.equal(record.outputBytes, Buffer.byteLength(output, "utf8"));
    assert.equal(record.rejectionCode, "unsupported_operation_kind");
    assert.equal(record.outputTruncated, false);
    assert.equal(record.structure.operations.count, 40);
    assert.equal(record.structure.operations.items.length, 32);
    assert.equal(record.structure.operations.truncated, true);
    assert.equal(record.structure.operations.items[0].kind, "search_replace");
    assert.equal(record.structure.operations.items[0].fields.path, true);
    assert.equal(record.structure.operations.items[0].fields.content, true);
    assert.doesNotMatch(serialized, /PRIVATE_SENTINEL_42|private-plan\.mjs/);
    assert.throws(() => persistRejectedArtifactEvidence({ stateRoot: task.stateRoot, packet: task, output: `${output}\n`, error: parseError }), /conflicts/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejected artifact evidence preserves every stable rejection class", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-artifact-rejection-codes-"));
  try {
    const cases = [
      ["invalid-json", "invalid_json", () => "{"],
      ["secret-data", "secret_shaped_data", (task) => {
        const value = artifact(task);
        value.operations[0].content = "api_key=sk-proj-12345678901234567890\n";
        return JSON.stringify(value);
      }],
      ["identity", "identity_mismatch", (task) => JSON.stringify({ ...artifact(task), requestId: "different-request" })],
      ["oversized", "output_bounds_invalid", () => "x".repeat(4 * 1024 * 1024 + 1)],
      ["schema", "artifact_schema_invalid", (task) => JSON.stringify({ ...artifact(task), unexpected: true })]
    ];
    for (const [name, expectedCode, outputFor] of cases) {
      const task = packet(root);
      task.taskRunId = "run-rejection-codes";
      task.requestId = `request-${name}`;
      const output = outputFor(task);
      let parseError;
      assert.throws(() => parseArtifactOutput(output, task), (error) => { parseError = error; return true; });
      const { rejectedArtifactPath } = persistRejectedArtifactEvidence({ stateRoot: task.stateRoot, packet: task, output, error: parseError });
      const serialized = readFileSync(rejectedArtifactPath, "utf8");
      assert.equal(JSON.parse(serialized).rejectionCode, expectedCode);
      assert.doesNotMatch(serialized, /sk-proj-12345678901234567890/);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("provider scratch must remain empty before controller cleanup", () => {
  const root = mkdtempSync(join(tmpdir(), "grok-artifact-scratch-"));
  try {
    const scratch = prepareArtifactScratch({ stateRoot: root, taskRunId: "run-artifact-001", requestId: "request-artifact-001" });
    assert.equal(existsSync(scratch), true);
    assert.throws(() => prepareArtifactScratch({ stateRoot: root, taskRunId: "run-artifact-001", requestId: "request-artifact-001" }), /already exists/i);
    assert.equal(removeArtifactScratch(scratch), true);
    assert.equal(existsSync(scratch), false);
    const mutated = prepareArtifactScratch({ stateRoot: root, taskRunId: "run-artifact-002", requestId: "request-artifact-002" });
    writeFileSync(join(mutated, "unexpected.txt"), "effect\n");
    assert.throws(() => removeArtifactScratch(mutated), /mutated/i);
    assert.equal(existsSync(join(mutated, "unexpected.txt")), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
