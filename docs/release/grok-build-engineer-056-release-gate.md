# Grok Build Engineer 0.5.6 release gate

This release replaces direct provider writes with artifact-only delivery.
Provider-free verification can prove the local contract and controller, but it
cannot prove how the real Grok CLI behaves. Installation and live use therefore
remain held until a separately authorized public-fixture run succeeds.

## Provider-free gate

Run `npm run verify`. The current CLI suites must prove the versioned packet,
empty provider-tool policy, bounded context prompt, isolated provider scratch,
strict artifact parser, controller path and command decisions, allowed edit,
harmless prohibited-path and prohibited-command denials, validation rollback,
Git custody, receipts, cleanup behavior, and plugin manifest parity. Legacy
ACP/job/MCP suites remain compatibility evidence only.

Rollback covers candidate-custodied source and protected Git state.
`node_modules` remains a non-candidate dependency cache: it is neither collected
nor reset, while tracked or staged module content is rejected.

The machine-readable decision is `artifact_only_held` until verified live
evidence exists. `direct_write_disabled` is an invariant, not a fallback mode.

## Separately authorized live U18 gate

One fresh, digest-bound public-fixture workflow must prove:

1. an allowed artifact edit applied only by the controller;
2. a prohibited path request was recorded and caused no effect;
3. a prohibited command request was recorded and did not run;
4. one exact same-session repair;
5. independent validation;
6. collection; and
7. cleanup of transient scratch, locks, and orphans while immutable evidence is retained.

All stage records must bind the same fixture SHA, task ID, and approval digest.
Structural records are inventory, not provider proof, until the release verifier
resolves and re-hashes their source approval, artifact, decision, receipt,
validation, collection, and cleanup evidence.

No provider call is made by `npm run verify`. U18 submission, repair, private
source access, installation, publication, push, merge, and deployment each
remain separate human approval gates.
