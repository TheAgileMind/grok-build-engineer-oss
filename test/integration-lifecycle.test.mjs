import assert from "node:assert/strict";
import test from "node:test";

// This is retained as legacy compatibility evidence. Stateful MCP execution
// was retired in 0.5.1, so compatibility must guide callers to the CLI without
// invoking an injected lifecycle service or creating durable state.
export const TEST_SUITE = "legacy-compatibility";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { createMcpServer } from "../src/mcp-server.mjs";

async function connectedClient(injectedService) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createMcpServer({ service: injectedService });
  await server.connect(serverTransport);
  const client = new Client({ name: "legacy-lifecycle-migration", version: "1.0.0" });
  await client.connect(clientTransport);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

test("retired MCP lifecycle returns deterministic CLI migration guidance without stateful effects", async () => {
  const calls = [];
  const injectedService = Object.freeze({
    submit: () => calls.push("submit"),
    status: () => calls.push("status"),
    collect: () => calls.push("collect"),
    cancel: () => calls.push("cancel")
  });
  const { client, close } = await connectedClient(injectedService);
  try {
    for (const name of ["grok_submit", "grok_repair", "grok_status", "grok_collect", "grok_cancel"]) {
      const response = await client.callTool({ name, arguments: { legacy: true } });
      const guidance = response.structuredContent.result;
      assert.equal(guidance.code, "migration_required", name);
      assert.equal(guidance.implementationRoute, "cli", name);
      assert.equal(guidance.executesJobs, false, name);
      assert.equal(guidance.createsState, false, name);
      assert.equal(guidance.createsSessions, false, name);
      assert.equal(guidance.createsCandidates, false, name);
    }
    assert.deepEqual(calls, [], "compatibility MCP must ignore injected stateful services");
  } finally {
    await close();
  }
});
