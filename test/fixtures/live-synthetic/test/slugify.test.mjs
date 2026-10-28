import assert from "node:assert/strict";
import test from "node:test";

import { slugify } from "../src/slugify.mjs";

test("slugify creates stable lowercase URL segments", () => {
  assert.equal(slugify("  Grok Build Engineer  "), "grok-build-engineer");
  assert.equal(slugify("Codex___Delegation"), "codex-delegation");
  assert.equal(slugify("Already-clean"), "already-clean");
});

test("slugify rejects non-string values", () => {
  assert.throws(() => slugify(null), TypeError);
  assert.throws(() => slugify(42), TypeError);
});
