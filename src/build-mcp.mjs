import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import * as esbuild from "esbuild";

const pluginRoot = resolve(import.meta.dirname, "..");
const output = resolve(pluginRoot, "mcp", "server.mjs");
const discoveryPath = resolve(pluginRoot, ".mcp.json");

await esbuild.build({ entryPoints: [resolve(pluginRoot, "src", "mcp-server.mjs")], outfile: output, bundle: true, platform: "node", format: "esm", target: "node20", legalComments: "none" });
const digest = `sha256:${createHash("sha256").update(readFileSync(output)).digest("hex")}`;
const discovery = JSON.parse(readFileSync(discoveryPath, "utf8"));
const compatibilityServer = discovery.mcpServers?.["grok-build-engineer-compatibility"];
if (!compatibilityServer) throw new Error(".mcp.json must retain only the isolated compatibility server");
compatibilityServer.args = ["./mcp/server.mjs", "--bundle-sha256", digest];
writeFileSync(discoveryPath, `${JSON.stringify(discovery, null, 2)}\n`, "utf8");
