# Grok Build Engineer 0.5.1 release gate

This document records the provider-free release decision for the CLI-first
surface. It does not claim a live Grok run, private-project readiness, or
publication authority.

## Provider-free command

Run `npm run verify` on Windows Node.js 20 and 22. The command builds the
source and runs the explicit current CLI suites. Legacy ACP/job/MCP lifecycle
suites run separately as compatibility evidence; they are labeled in the
output and cannot satisfy the release gate by themselves.

The runner records these provider-free evidence kinds in its versioned report:

`contract`, `policy`, `lifecycle`, `restart`, `cleanup`, `receipt`, and
`manifest`.

Use `node scripts/run-tests.mjs --release --json` when a machine-readable
report is needed. A compatibility-only invocation is rejected as an invalid
release gate, including when all of its mocked-child tests pass.

## Separately approved live gate

After a separate packet, provider, and public-fixture approval, one immutable
evidence bundle must prove all of the following in the same governed workflow:

1. allowed fixture edit;
2. prohibited path denial;
3. prohibited command denial;
4. one exact same-session repair;
5. independent validation;
6. collection;
7. temporary-hook and state cleanup; and
8. fresh-session adversarial review with no unresolved Critical or High
   blocker.

The live stages are represented as `allowed_edit`, `denied_path`,
`denied_command`, `same_session_repair`, `validation`, `collection`,
`cleanup`, and `fresh_session_adversarial_review`. Each record must be a
successful, digest-bound, current receipt. Duplicate contradictory records,
stale or incomplete records, and missing records fail closed.

Each stage inventory record has exactly these fields: `approvalDigest`, `digest`,
`expiresAt`, `fixtureSha`, `observedAt`, `receiptDigest`, `requestId`, `stage`,
`status`, `taskRunId`, and `validationDigest`. All records must bind the same
fixture SHA, task ID, and approval digest; each digest is lowercase SHA-256,
the fixture revision is a full Git SHA, `status` is `pass`, and the evidence
has not expired. Structural completeness is not provider proof: 0.5.1 does not
yet resolve and re-hash the underlying approval, receipt, validation,
collection, cleanup, and review artifacts. Therefore even a structurally
complete inventory remains `direct_write_held` with
`live_evidence_artifact_verifier_not_implemented`. A later artifact verifier
must bind those source artifacts before the gate may yield
`direct_write_eligible_pending_separate_authorization`; that decision would
still never grant private-project authority by itself.

No unattended CI job runs this live gate. No provider call is made by
`npm run verify`.

## Decision and fallback

Until every provider-free condition and every separately approved live stage
is current and complete, the machine decision is `direct_write_held`.
The required fallback is `artifact_only_patch_delegation`; the fallback is a
design trigger, not an implementation or an authorization to publish,
deploy, push, merge, disclose a private project, or use customer data.
