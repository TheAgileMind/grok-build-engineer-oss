import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const [installedRoot, toolName, argumentsPath] = process.argv.slice(2);
if (!installedRoot || !toolName || !argumentsPath) {
  throw new Error("usage: node scripts/call-installed-mcp.mjs <installed-root> <tool-name> <arguments-json>");
}

const root = resolve(installedRoot);
const discovery = JSON.parse(readFileSync(resolve(root, ".mcp.json"), "utf8"));
const server = discovery.mcpServers?.["grok-build-engineer-compatibility"];
if (!server || server.command !== "node" || !Array.isArray(server.args)) throw new Error("installed MCP discovery is invalid");

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [resolve(root, server.args[0]), ...server.args.slice(1)],
  cwd: root,
  stderr: "pipe",
});
const client = new Client({ name: "grok-build-engineer-live-proof", version: "1.0.0" });

try {
  await client.connect(transport);
  const args = JSON.parse(readFileSync(resolve(argumentsPath), "utf8"));
  const result = await client.callTool({ name: toolName, arguments: args });
  process.stdout.write(`${JSON.stringify(result.structuredContent ?? result, null, 2)}\n`);
} finally {
  await client.close().catch(() => {});
}
