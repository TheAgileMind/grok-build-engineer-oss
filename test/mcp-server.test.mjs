import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import * as esbuild from "esbuild";

import {
  bundleDigest,
  createMcpServer,
  createProductionService,
  MCP_COMPAT_VERSION,
  migrationGuidance
} from "../src/mcp-server.mjs";

const pluginRoot = resolve(import.meta.dirname, "..");
const digest = (letter = "a") => `sha256:${letter.repeat(64)}`;

async function connectedClient() {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createMcpServer();
  await server.connect(serverTransport);
  const client = new Client({ name: "mcp-compatibility-test", version: "1.0.0" });
  await client.connect(clientTransport);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

test("default MCP discovery exposes guidance only and legacy calls never reach a service", async () => {
  const calls = [];
  const service = { submit: () => calls.push("submit"), status: () => calls.push("status"), collect: () => calls.push("collect"), cancel: () => calls.push("cancel") };
  const { client, close } = await connectedClient();
  try {
    const listed = await client.listTools();
    assert.deepEqual(listed.tools.map((tool) => tool.name), ["grok_build_engineer_guidance"]);
    assert.match(listed.tools[0].description, /does not execute/);
    const guidance = await client.callTool({ name: "grok_build_engineer_guidance", arguments: {} });
    assert.equal(guidance.structuredContent.result.code, "migration_required");
    assert.equal(guidance.structuredContent.result.version, MCP_COMPAT_VERSION);
    for (const name of ["grok_submit", "grok_repair", "grok_status", "grok_collect", "grok_cancel"]) {
      const result = await client.callTool({ name, arguments: { arbitrary: "ignored" } });
      assert.equal(result.structuredContent.result.kind, "cli_migration_guidance", name);
      assert.equal(result.structuredContent.result.createsState, false, name);
    }
    assert.deepEqual(calls, []);
  } finally { await close(); }
});

test("compatibility guidance is deterministic and explicitly denies stateful effects", () => {
  assert.deepEqual(migrationGuidance("grok_submit"), {
    kind: "cli_migration_guidance",
    code: "migration_required",
    version: "0.5.7",
    tool: "grok_submit",
    message: "MCP lifecycle calls are retired in 0.5.7; use scripts/grok-delegate.mjs for prepare, submit, status, repair, collect, and cancel.",
    implementationRoute: "cli",
    executesJobs: false,
    createsState: false,
    createsSessions: false,
    createsCandidates: false
  });
  const service = createProductionService();
  assert.deepEqual(service.status({ jobId: "job-001" }), migrationGuidance("grok_status"));
});

test("compatibility server has no injectable lifecycle proxy and rejects unknown tools", async () => {
  assert.equal(createMcpServer.length, 0);
  const { client, close } = await connectedClient();
  try {
    const listed = await client.listTools();
    assert.deepEqual(listed.tools.map((tool) => tool.name), ["grok_build_engineer_guidance"]);
    const result = await client.callTool({ name: "not_a_grok_tool", arguments: {} });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.error.code, "invalid_input");
  } finally { await close(); }
});

test("committed digest anchors a fresh source build and copied compatibility bundle", async () => {
  const discovery = JSON.parse(readFileSync(resolve(pluginRoot, ".mcp.json"), "utf8"));
  const [entry, flag, expected] = discovery.mcpServers["grok-build-engineer-compatibility"].args;
  assert.equal(flag, "--bundle-sha256");
  assert.equal(bundleDigest(resolve(pluginRoot, entry)), expected);
  const copiedRoot = mkdtempSync(join(tmpdir(), "grok-plugin-compat-copy-"));
  const rebuiltBundle = join(copiedRoot, "rebuilt-server.mjs");
  await esbuild.build({ entryPoints: [resolve(pluginRoot, "src", "mcp-server.mjs")], outfile: rebuiltBundle, bundle: true, platform: "node", format: "esm", target: "node20", legalComments: "none" });
  assert.equal(bundleDigest(rebuiltBundle), expected);
  rmSync(rebuiltBundle, { force: true });
  cpSync(pluginRoot, copiedRoot, { recursive: true, filter: (path) => !path.includes(`${sep}node_modules`) });
  try {
    const transport = new StdioClientTransport({ command: process.execPath, args: [entry, flag, expected], cwd: copiedRoot, stderr: "pipe" });
    const client = new Client({ name: "copy-smoke-client", version: "1.0.0" });
    await client.connect(transport);
    assert.deepEqual((await client.listTools()).tools.map((tool) => tool.name), ["grok_build_engineer_guidance"]);
    for (const name of ["grok_submit", "grok_repair", "grok_status", "grok_collect", "grok_cancel"]) {
      const result = await client.callTool({ name, arguments: {} });
      assert.equal(result.structuredContent.result.code, "migration_required", name);
      assert.equal(result.structuredContent.result.createsCandidates, false, name);
    }
    await client.close();
  } finally { rmSync(copiedRoot, { recursive: true, force: true }); }
});

test("digest mismatch fails before compatibility MCP emits protocol stdout", () => {
  const result = spawnSync(process.execPath, ["mcp/server.mjs", "--bundle-sha256", digest("0")], { cwd: pluginRoot, encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /startup failed: activation_unavailable/);
});
