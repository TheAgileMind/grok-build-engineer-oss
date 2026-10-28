#!/usr/bin/env node
import { isAbsolute, resolve } from "node:path";
import { activationRegistryAvailable, defaultActivationRegistryRoot, findActiveActivations } from "../src/activation-registry.mjs";

const [repositoryRoot, destinationRoot, profileId = "trusted-local", dataClass = "public"] = process.argv.slice(2);
if (![repositoryRoot, destinationRoot].every((value) => typeof value === "string" && isAbsolute(value))) {
  process.stderr.write("usage: registry-status.mjs <absolute-repository-root> <absolute-destination-root> [profile-id] [data-class]\n"); process.exitCode = 64;
} else {
  const registryRoot = defaultActivationRegistryRoot(process.env);
  if (!registryRoot) throw new Error("activation registry root is unavailable");
  if (!activationRegistryAvailable(registryRoot)) { process.stdout.write(`${JSON.stringify({ registryRoot, matchCount: 0, matches: [], state: "registry_not_initialized" })}\n`); process.exitCode = 2; }
  else {
  const matches = findActiveActivations({ registryRoot, repositoryRoot: resolve(repositoryRoot), destinationRoot: resolve(destinationRoot), profileId, dataClass });
  process.stdout.write(`${JSON.stringify({ registryRoot, matchCount: matches.length, matches })}\n`);
  if (matches.length !== 1) process.exitCode = 2;
  }
}
