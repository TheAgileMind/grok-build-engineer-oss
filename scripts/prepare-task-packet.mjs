#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { createTaskPolicy, packetDigest } from "../src/task-policy.mjs";
import { redactForBoundary } from "../src/redaction.mjs";

// Compatibility façade for the established raw-packet redirect. Keep the
// same digest and policy validation as grok-delegate.mjs prepare; this helper
// does not own a second lifecycle or provider path.
const PREPARE_CONTRACT_VERSION = "agent-platform.grok-build-engineer-prepare.v1";
function output(value) { process.stdout.write(`${JSON.stringify(value)}\n`); }
function fail(message) { const error = new Error(String(message).slice(0, 512)); error.code = "invalid_input"; throw error; }

try {
  if (process.argv.length !== 3) fail("usage: prepare-task-packet.mjs <input.json>");
  let input;
  try { input = JSON.parse(readFileSync(process.argv[2], "utf8")); } catch { fail("input packet is missing or malformed"); }
  if (!input || typeof input !== "object" || Array.isArray(input) || !input.approval || typeof input.approval !== "object") fail("input packet must contain an approval object");
  const prepared = structuredClone(input);
  prepared.approval = { ...prepared.approval, packetDigest: null };
  prepared.approval.packetDigest = packetDigest(prepared);
  createTaskPolicy(prepared);
  output(prepared);
} catch (error) {
  output({ contractVersion: PREPARE_CONTRACT_VERSION, ok: false, error: { code: error?.code ?? "invalid_input", message: String(redactForBoundary(error?.message ?? error)).slice(0, 512) } });
  process.exitCode = 64;
}
