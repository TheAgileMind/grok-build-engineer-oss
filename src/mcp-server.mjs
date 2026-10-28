import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import { redactForBoundary } from "./redaction.mjs";

/** MCP is a migration-only compatibility artifact; the implementation route is the CLI. */
export const MCP_COMPAT_VERSION = "0.5.7";
const MAX_BOUNDARY_BYTES = 16_384;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const LEGACY_TOOL_NAMES = new Set(["grok_submit", "grok_repair", "grok_status", "grok_collect", "grok_cancel"]);
const CLI_ROUTE = "scripts/grok-delegate.mjs";

export class ActivationUnavailableError extends Error {
  constructor(message = "The MCP compatibility bundle is unavailable.") {
    super(message);
    this.name = "ActivationUnavailableError";
  }
}

export class MigrationRequiredError extends Error {
  constructor(message = "The MCP lifecycle was retired; use the local grok-delegate CLI.") {
    super(message);
    this.name = "MigrationRequiredError";
    this.code = "migration_required";
  }
}

const compatibilitySchema = Object.freeze({ type: "object", additionalProperties: false, properties: {} });

/** The only MCP tool intentionally discoverable by a fresh host. */
export const MCP_TOOL_INPUT_SCHEMAS = Object.freeze({ grok_build_engineer_guidance: compatibilitySchema });
const TOOL_DEFINITIONS = Object.freeze([{
  name: "grok_build_engineer_guidance",
  description: "Retired compatibility guidance only; does not execute or advertise engineering jobs. Use the local CLI.",
  inputSchema: compatibilitySchema
}]);

function bounded(value) {
  const safe = redactForBoundary(value);
  if (Buffer.byteLength(JSON.stringify(safe), "utf8") <= MAX_BOUNDARY_BYTES) return safe;
  return { kind: "cli_migration_guidance", code: "migration_required", message: `Use ${CLI_ROUTE}.` };
}

export function migrationGuidance(tool = null) {
  return Object.freeze({
    kind: "cli_migration_guidance",
    code: "migration_required",
    version: MCP_COMPAT_VERSION,
    tool,
    message: `MCP lifecycle calls are retired in ${MCP_COMPAT_VERSION}; use ${CLI_ROUTE} for prepare, submit, status, repair, collect, and cancel.`,
    implementationRoute: "cli",
    executesJobs: false,
    createsState: false,
    createsSessions: false,
    createsCandidates: false
  });
}

function response(tool, result) {
  return {
    content: [{ type: "text", text: `${tool}: compatibility guidance` }],
    structuredContent: bounded({ ok: true, tool, result })
  };
}

function failure(tool, error) {
  const code = error?.code === "migration_required" ? "migration_required" : "invalid_input";
  const message = code === "migration_required" ? error.message : error?.message ?? "The compatibility request was invalid.";
  return {
    isError: true,
    content: [{ type: "text", text: `${tool}: ${code}` }],
    structuredContent: bounded({ ok: false, tool, error: { code, message } })
  };
}

/** Default service is deterministic guidance with no provider or state authority. */
export function createProductionService() {
  const guidance = (tool) => migrationGuidance(tool);
  return Object.freeze({
    mcpMutationsDisabled: true,
    submit: () => guidance("grok_submit"),
    status: () => guidance("grok_status"),
    collect: () => guidance("grok_collect"),
    cancel: () => guidance("grok_cancel")
  });
}

export function createMcpServer({ version = MCP_COMPAT_VERSION } = {}) {
  const server = new Server({ name: "grok-build-engineer-compatibility", version }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOL_DEFINITIONS }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    try {
      if (name === "grok_build_engineer_guidance") return response(name, migrationGuidance(name));
      if (LEGACY_TOOL_NAMES.has(name)) return response(name, migrationGuidance(name));
      throw new TypeError("unknown compatibility tool");
    } catch (error) {
      return failure(name, error);
    }
  });
  return server;
}

export function bundleDigest(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

export function verifyBundleDigest({ path = process.argv[1], expected } = {}) {
  if (typeof expected !== "string" || !DIGEST.test(expected)) throw new TypeError("a sha256 bundle digest is required");
  if (bundleDigest(resolve(path)) !== expected) throw new ActivationUnavailableError("The MCP bundle digest does not match its discovery trust anchor.");
  return true;
}

export async function startStdioServer({ expectedBundleDigest = null } = {}) {
  if (expectedBundleDigest !== null) verifyBundleDigest({ expected: expectedBundleDigest });
  const server = createMcpServer();
  await server.connect(new StdioServerTransport());
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [flag, expectedBundleDigest, ...unexpected] = process.argv.slice(2);
  if (flag !== "--bundle-sha256" || unexpected.length !== 0) {
    process.stderr.write("grok-build-engineer compatibility MCP requires --bundle-sha256 sha256:<digest>\n");
    process.exitCode = 64;
  } else {
    startStdioServer({ expectedBundleDigest }).catch((error) => {
      process.stderr.write(`grok-build-engineer MCP startup failed: ${error?.code === "migration_required" ? "migration_required" : "activation_unavailable"}\n`);
      process.exitCode = 1;
    });
  }
}
