import assert from "node:assert/strict";
import test from "node:test";
import { assertCommandAllowed, commandsMatch, commandTokens, exactCommandRule, FIXED_WINDOWS_ENVIRONMENT_KEYS, pathInScope, pathMatchesPattern, scopedEnvironment, TASK_POLICY_VERSION } from "../src/task-policy.mjs";

test("path policy matches complete segments and is separator-normalized but case-sensitive", () => {
  assert.equal(pathMatchesPattern("src/**", "src\\lib\\main.mjs"), true);
  assert.equal(pathMatchesPattern("src/**", "src2/lib/main.mjs"), false);
  assert.equal(pathMatchesPattern("src/**", "Src/lib/main.mjs"), false);
  assert.equal(pathMatchesPattern("src/*", "src/lib/main.mjs"), false);
  assert.equal(pathInScope("test/unit/a.mjs", ["src/**", "test/**"]), true);
  assert.equal(pathInScope("", ["src/**", "test/**"]), false);
  assert.equal(pathInScope("", ["**"]), true);
});

test("command policy compares exact tokens and rejects wildcard expansion, wrappers, aliases, and shell syntax", () => {
  assert.deepEqual([...commandTokens('npm "test"')], ["npm", "test"]);
  assert.equal(commandsMatch('npm "test"', "npm test"), true);
  assert.doesNotThrow(() => assertCommandAllowed("npm test", ["npm test"]));
  for (const command of ["npm test extra", "npm.cmd test", "cmd /c npm test", "npm test; git status", "npm test*"]) {
    assert.throws(() => assertCommandAllowed(command, ["npm test"]));
  }
  assert.throws(() => exactCommandRule("npm run test*"), /wildcard/);
});

test("command policy finds denied subcommands after executable-specific global options", () => {
  for (const command of [
    "npm --foo publish",
    "npm.cmd --foo publish",
    "gh --repo owner/repo pr create",
    "docker --config C:/docker push image:tag",
    "git --work-tree C:/repo remote -v"
  ]) {
    assert.throws(() => assertCommandAllowed(command, [command]), /denied/);
  }
  for (const command of [
    "npm --foo test",
    "gh --repo owner/repo issue list",
    "docker --config C:/docker build .",
    "git --work-tree C:/repo status"
  ]) {
    assert.doesNotThrow(() => assertCommandAllowed(command, [command]), command);
  }
});

test("empty caller environment still gets fixed Windows launch variables without secret-shaped keys", () => {
  const policy = { contractVersion: TASK_POLICY_VERSION, environment: [] };
  const source = { PATH: "safe-path", TEMP: "safe-temp", USERPROFILE: "safe-user", API_KEY: "secret", CUSTOM: "not-approved" };
  const scoped = scopedEnvironment(policy, source);
  assert.equal(scoped.PATH, "safe-path");
  assert.equal(scoped.TEMP, "safe-temp");
  assert.equal(scoped.API_KEY, undefined);
  assert.equal(scoped.CUSTOM, undefined);
  assert.deepEqual(Object.keys(scoped).filter((key) => FIXED_WINDOWS_ENVIRONMENT_KEYS.includes(key)), Object.keys(scoped));
});
