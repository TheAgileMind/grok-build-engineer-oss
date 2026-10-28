import assert from "node:assert/strict";
import test from "node:test";

process.env.GROK_RELEASE_GATE_IMPORT = "1";
const {
  CURRENT_CLI_SUITES,
  LEGACY_COMPATIBILITY_SUITES,
  LIVE_GATE_STAGES,
  classifyTests,
  evaluateReleaseGate
} = await import("../scripts/run-tests.mjs");
const OUTPUT_DIGEST = `sha256:${"f".repeat(64)}`;

test("release classification keeps current CLI evidence separate from retired compatibility coverage", () => {
  const classified = classifyTests([...CURRENT_CLI_SUITES, ...LEGACY_COMPATIBILITY_SUITES]);
  assert.deepEqual(classified.current, [...CURRENT_CLI_SUITES]);
  assert.deepEqual(classified.compatibility, [...LEGACY_COMPATIBILITY_SUITES]);
  assert.deepEqual(classified.unknown, []);
  const legacyOnly = evaluateReleaseGate({ currentStatus: 0, currentSuites: [], currentOutputDigest: OUTPUT_DIGEST, compatibilityStatus: 0, compatibilitySuites: LEGACY_COMPATIBILITY_SUITES });
  assert.equal(legacyOnly.providerFree.status, "fail");
  assert.equal(legacyOnly.decision, "artifact_only_held");
});

test("provider-free current suites prove the artifact boundary but hold release without live proof", () => {
  const report = evaluateReleaseGate({ currentStatus: 0, currentSuites: CURRENT_CLI_SUITES, currentOutputDigest: OUTPUT_DIGEST, compatibilityStatus: 0, compatibilitySuites: LEGACY_COMPATIBILITY_SUITES });
  assert.equal(report.version, "0.5.7");
  assert.equal(report.providerFree.status, "pass");
  assert.deepEqual(report.providerFree.evidence.map((entry) => entry.kind), ["contract", "policy", "artifact_boundary", "lifecycle", "restart", "cleanup", "receipt", "manifest"]);
  assert.equal(report.claims.providerFreeVerified, true);
  assert.equal(report.claims.liveProviderProof, false);
  assert.equal(report.claims.artifactOnlyImplemented, true);
  assert.equal(report.claims.directWriteEnabled, false);
  assert.equal(report.claims.privateProjectUse, false);
  assert.equal(report.decision, "artifact_only_held");
  assert.equal(report.fallback, "direct_write_disabled");
  assert.deepEqual(report.live.missing, [...LIVE_GATE_STAGES]);
});

test("stale, incomplete, or contradictory live evidence remains a release hold", () => {
  const now = Date.parse("2026-08-26T12:00:00.000Z");
  const evidence = LIVE_GATE_STAGES.map((stage) => ({ stage, status: "pass", observedAt: "2026-08-26T11:00:00.000Z", expiresAt: "2026-08-26T11:30:00.000Z", digest: `sha256:${"a".repeat(64)}` }));
  evidence.push({ ...evidence[0], digest: `sha256:${"b".repeat(64)}` });
  const report = evaluateReleaseGate({ currentStatus: 0, currentSuites: CURRENT_CLI_SUITES, currentOutputDigest: OUTPUT_DIGEST, liveEvidence: evidence, now });
  assert.equal(report.live.status, "held");
  assert.deepEqual(report.live.staleOrIncomplete, [...LIVE_GATE_STAGES]);
  assert.deepEqual(report.live.contradictory, [LIVE_GATE_STAGES[0]]);
  assert.equal(report.decision, "artifact_only_held");
});

test("structurally complete live records remain held without artifact verification", () => {
  const now = Date.parse("2026-08-26T12:00:00.000Z"), digest = `sha256:${"a".repeat(64)}`;
  const liveEvidence = LIVE_GATE_STAGES.map((stage, index) => ({ approvalDigest: digest, digest: `sha256:${String(index + 1).padStart(64, "0")}`, expiresAt: "2026-08-26T13:00:00.000Z", fixtureSha: "a".repeat(40), observedAt: "2026-08-26T11:00:00.000Z", receiptDigest: digest, requestId: `request-live-${index}`, stage, status: "pass", taskRunId: "run-live-001", validationDigest: digest }));
  const report = evaluateReleaseGate({ currentStatus: 0, currentSuites: CURRENT_CLI_SUITES, currentOutputDigest: OUTPUT_DIGEST, liveEvidence, now });
  assert.equal(report.live.structurallyComplete, true);
  assert.equal(report.live.verifierStatus, "not_implemented");
  assert.equal(report.live.status, "held");
  assert.equal(report.claims.liveProviderProof, false);
  assert.equal(report.decision, "artifact_only_held");
  assert.ok(report.reasons.includes("live_evidence_artifact_verifier_not_implemented"));
  assert.equal(report.claims.directWriteEnabled, false);
  assert.equal(report.claims.privateProjectUse, false);
});
