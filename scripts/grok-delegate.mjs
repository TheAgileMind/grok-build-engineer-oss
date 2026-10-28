#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { cancelRun, createOneShotRunner, persistAcceptanceDecision, readRunReceipt } from "../src/one-shot-runner.mjs";
import { cliErrorResponse, cliHelpResponse, cliResponse, validateCliRequest, CLI_EXIT_CODES } from "../src/cli-contract.mjs";
import { createTaskPolicy, packetDigest } from "../src/task-policy.mjs";
import { redactForBoundary } from "../src/redaction.mjs";

function json(path, label) { try { return JSON.parse(readFileSync(path, "utf8")); } catch { const error = new Error(`${label} is missing or malformed`); error.code = "invalid_input"; throw error; } }
function parse(argv) { if (argv.length === 0 || argv.includes("--help") || argv.includes("-h")) return { operation: "help" }; const result = { operation: argv[0] }; for (let i = 1; i < argv.length; i += 1) { if (!argv[i].startsWith("--") || argv[i + 1] === undefined || argv[i + 1].startsWith("--")) { const error = new Error("arguments must use --name value"); error.code = "invalid_input"; throw error; } result[argv[i].slice(2)] = argv[++i]; } return result; }
function output(value) { process.stdout.write(`${JSON.stringify(value)}\n`); }
function classify(error) { if (error?.code) return error; const wrapped = new Error(String(redactForBoundary(error?.message ?? error)).slice(0, 512)); wrapped.code = /no persisted|no terminal|not found/i.test(wrapped.message) ? "not_found" : "invalid_input"; return wrapped; }
const context = { operation: null, taskRunId: null };

const main = async () => {
  const input = parse(process.argv.slice(2));
  context.operation = input.operation;
  if (input.operation === "help") { output(cliHelpResponse()); return; }
  if (input.operation === "prepare") {
    if (!input.input) throw new Error("--input is required");
    const prepared = json(input.input, "input packet");
    if (!prepared || typeof prepared !== "object" || Array.isArray(prepared) || !prepared.approval || typeof prepared.approval !== "object") throw new Error("input packet must contain an approval object");
    prepared.approval = { ...prepared.approval, packetDigest: null };
    prepared.approval.packetDigest = packetDigest(prepared);
    createTaskPolicy(prepared);
    context.taskRunId = prepared.taskRunId;
    output(cliResponse("prepare", prepared.taskRunId, { packet: prepared }));
    return;
  }
  const packet = input.packet ? json(input.packet, "task packet") : null;
  const stateRoot = input["state-root"] ?? packet?.stateRoot;
  const taskRunId = input["task-run-id"] ?? packet?.taskRunId;
  context.taskRunId = taskRunId ?? null;
  validateCliRequest({ operation: input.operation, taskRunId });
  if (input.packet && (!packet || typeof packet.stateRoot !== "string" || typeof packet.taskRunId !== "string")) throw new Error("task packet identity is incomplete");
  if (packet && input["state-root"] !== undefined && packet.stateRoot !== undefined && input["state-root"] !== packet.stateRoot) throw new Error("state root does not match task packet identity");
  if (packet && input["task-run-id"] !== undefined && packet.taskRunId !== undefined && input["task-run-id"] !== packet.taskRunId) throw new Error("task identity does not match task packet identity");
  if (!stateRoot) throw new Error("--packet (or --state-root) is required");
  if (input.operation === "status") { const receipt = readRunReceipt(stateRoot, taskRunId); if (!receipt) { const error = new Error("no persisted task run exists"); error.code = "not_found"; throw error; } output(cliResponse("status", taskRunId, { receipt })); return; }
  if (input.operation === "submit" || input.operation === "repair") {
    if (!packet) throw new Error("--packet is required");
    if ((input.operation === "repair") !== (packet.mode === "repair")) throw new Error(`${input.operation} requires a matching task packet mode`);
    const approval = input.approval ? json(input.approval, "approval packet") : packet.approval;
    let options = { approval };
    if (input.operation === "repair") {
      if (!input.findings) throw new Error("repair requires --findings with explicit versioned failed-acceptance evidence");
      const findings = json(input.findings, "repair findings");
      const prior = readRunReceipt(stateRoot, packet.continuation.priorTaskRunId);
      if (!prior || prior.state !== "candidate") { const error = new Error("repair requires the prior candidate receipt"); error.code = "rejected"; throw error; }
      options = { ...options, resumeSessionId: packet.continuation.priorSessionId, repairEvidence: findings, priorReceipt: prior };
    }
    const receipt = await createOneShotRunner().run(packet, options);
    if (receipt.state !== "candidate") { const error = new Error(`task ended in ${receipt.state}`); error.code = receipt.state === "recovery_required" ? "recovery_required" : "rejected"; error.receipt = receipt; throw error; }
    output(cliResponse(input.operation, taskRunId, { receipt })); return;
  }
  const receipt = readRunReceipt(stateRoot, taskRunId);
  if (!receipt) { const error = new Error("no persisted terminal receipt exists"); error.code = "not_found"; throw error; }
  if (input.operation === "collect") {
    if (!input.acceptance) throw new Error("collect requires --acceptance with explicit Codex validation evidence");
    const decision = json(input.acceptance, "acceptance decision");
    const saved = persistAcceptanceDecision(stateRoot, decision, receipt);
    output(cliResponse("collect", taskRunId, { receipt, acceptance: saved })); return;
  }
  if (input.operation === "cancel") {
    if (!["starting", "running"].includes(receipt.state)) { output(cliResponse("cancel", taskRunId, { receipt })); return; }
    const cancelled = cancelRun(stateRoot, taskRunId); output(cliResponse("cancel", taskRunId, { receipt: cancelled })); return;
  }
};

main().catch((error) => { const normalized = classify(error); const base = cliErrorResponse(context.operation, context.taskRunId, normalized); const response = normalized.receipt ? { ...base, receipt: normalized.receipt } : base; output(response); process.exitCode = CLI_EXIT_CODES[normalized.code] ?? response.exitCode ?? 64; });
