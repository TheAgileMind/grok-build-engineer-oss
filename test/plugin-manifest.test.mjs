import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

const pluginRoot = resolve(import.meta.dirname, "..");
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));

test("declares a CLI-first 0.5.7 plugin and isolated compatibility discovery contract", () => {
  const manifest = readJson(resolve(pluginRoot, ".codex-plugin", "plugin.json"));
  const mcp = readJson(resolve(pluginRoot, ".mcp.json"));
  const packageJson = readJson(resolve(pluginRoot, "package.json"));
  const packageLock = readJson(resolve(pluginRoot, "package-lock.json"));
  assert.equal(manifest.name, "grok-build-engineer");
  assert.equal(manifest.version, "0.5.7");
  assert.equal(packageJson.version, manifest.version);
  assert.equal(packageLock.version, manifest.version);
  assert.equal(packageLock.packages[""].version, manifest.version);
  assert.deepEqual(manifest.interface.defaultPrompt, ["Help me prepare a governed local Grok Build Engineer CLI submission."]);
  assert.equal(Object.hasOwn(manifest, "mcpServers"), false, "MCP is not the default plugin lifecycle route");
  assert.deepEqual(Object.keys(mcp.mcpServers), ["grok-build-engineer-compatibility"]);
  const compatibility = mcp.mcpServers["grok-build-engineer-compatibility"];
  assert.equal(compatibility.command, "node");
  assert.deepEqual(compatibility.args.slice(0, 2), ["./mcp/server.mjs", "--bundle-sha256"]);
  assert.match(compatibility.args[2], /^sha256:[a-f0-9]{64}$/);
  assert.equal(compatibility.cwd, ".");
  assert.equal(Object.hasOwn(compatibility, "env_vars"), false, "compatibility server forwards no activation environment");
  const agentMetadata = readFileSync(resolve(pluginRoot, "skills", "grok-build-engineer", "agents", "openai.yaml"), "utf8");
  assert.match(agentMetadata, /governed CLI/i); assert.doesNotMatch(agentMetadata, /through governed MCP tools/i);
  const installedCaller = readFileSync(resolve(pluginRoot, "scripts", "call-installed-mcp.mjs"), "utf8"); assert.match(installedCaller, /grok-build-engineer-compatibility/);
  const retiredHost = readFileSync(resolve(pluginRoot, "scripts", "start-job-host.ps1"), "utf8"); assert.match(retiredHost, /migration_required/); assert.doesNotMatch(retiredHost, /--job-host/);
  assert.equal(packageJson.private, true);
  assert.equal(packageJson.dependencies["@agentclientprotocol/sdk"], "1.3.0");
  assert.equal(packageJson.dependencies["@modelcontextprotocol/sdk"], "1.30.0");
  assert.equal(Object.keys(packageJson.scripts).some((name) => /install/i.test(name)), false);
  assert.equal(existsSync(resolve(pluginRoot, "mcp", "server.mjs")), true,
    "U7 owns the committed portable bundled entrypoint");
  const attributes = readFileSync(resolve(pluginRoot, ".gitattributes"), "utf8");
  assert.match(attributes, /^mcp\/server\.mjs -text$/m,
    "the byte-attested MCP bundle must not be rewritten by Windows checkout EOL conversion");
});

test("standalone marketplace source resolves from the repository root", () => {
  const repositoryRoot = pluginRoot;
  const marketplace = readJson(resolve(repositoryRoot, ".agents", "plugins", "marketplace.json"));
  const entry = marketplace.plugins.find((plugin) => plugin.name === "grok-build-engineer");
  assert.equal(entry.source.source, "local");
  assert.equal(entry.source.path, "./");
  assert.equal(existsSync(resolve(repositoryRoot, entry.source.path, ".codex-plugin", "plugin.json")), true);
});
