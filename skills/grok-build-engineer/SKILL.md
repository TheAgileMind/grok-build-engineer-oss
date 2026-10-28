---
name: grok-build-engineer
description: Run a finite one-shot local CLI implementation or repair with Codex-owned custody, validation, acceptance, and cancellation.
---

# Grok Build Engineer

Use one finite CLI lifecycle: prepare, human approve, submit, status, optional
same-session repair, and collect. Codex remains the custody, review,
validation, repair, and acceptance owner. The trusted host is not an OS
sandbox; provider authorization, credentials, and external effects remain
separate gates.

## Prepare and approve

Create a secret-free input with the exact repository/worktree, clean source
SHA, task/context, executable/model, state root, `delivery: "artifact_only"`,
exact allowlisted paths and commands, an empty provider-tools list, environment
names, finite timeouts, and repair budget. Resolve
`<plugin-root>` from this absolute SKILL.md path by walking up through
`skills\grok-build-engineer` to the directory containing `skills`.

```powershell
$pluginRoot = "<plugin-root>"
node "$pluginRoot\scripts\prepare-task-packet.mjs" input.json > task.json
```

The compatibility helper follows the unified CLI's `prepare` contract. It
computes the canonical `approval.packetDigest` and validates the task policy
only; it does not write authority, alter global config, or call a provider. A human must
approve the exact digest and scope. The approval object must match the packet
and include `contractVersion`, `approvalId`, `packetDigest`, `issuedAt`,
`expiresAt`, `approvedBy`, and `authorizationStatement`. Self-authored
`approvedBy` metadata is not human authority.

## Submit, status, repair, collect

```powershell
node "$pluginRoot\scripts\grok-delegate.mjs" submit --packet task.json --approval approval.json
node "$pluginRoot\scripts\grok-delegate.mjs" status --state-root <state-root> --task-run-id <task-run-id>
node "$pluginRoot\scripts\prepare-task-packet.mjs" repair-input.json > repair.json
node "$pluginRoot\scripts\grok-delegate.mjs" repair --packet repair.json --findings findings.json
node "$pluginRoot\scripts\grok-delegate.mjs" collect --state-root <state-root> --task-run-id <task-run-id> --acceptance acceptance.json
node "$pluginRoot\scripts\grok-delegate.mjs" cancel --state-root <state-root> --task-run-id <task-run-id>
```

Only a candidate receipt is collectable. Independently inspect Git-authoritative
changed files, custody, diff, and validation evidence before collection. Repair
is exactly one continuation of the accepted candidate's native session and
retains the immutable implementation receipt. Collection never authorizes
deployment or publication. Use no retired MCP lifecycle operation.

Create `repair-input.json` from
`examples\repair-task-packet.template.json`. Bind every `continuation` field to
the persisted candidate receipt, retain its `taskRunId`, use a new `requestId`,
bind `findingsDigest` to the versioned `findings.json`, and set `repairBudget`
to one. Prepare the repair packet and obtain approval for its exact new digest;
never reconstruct continuation state from conversation memory.

The child launch runs in an empty state-root scratch directory with all provider
tools disabled. Only explicitly named, bounded text context is embedded in the
prompt. Grok must return one versioned JSON artifact. The prompt provides the
exact task-bound envelope, exact per-operation fields, and the only three
supported kinds: `write_file`, `delete_file`, and `run_command`. The controller
evaluates each requested file operation and command, records allow/deny decisions, applies
allowed edits, and runs validation itself. Direct-write is disabled. Exact
command tokens, paths, environment names, network mode, and timeouts remain
packet-bound. Wildcards are not permitted in command tokens.
The fixed Windows launch variables are supplied even with an empty caller
environment allowlist; secret-shaped variables are never forwarded. Artifact-only
child launches then isolate `GROK_HOME`/`HOME`/`USERPROFILE`/`LOCALAPPDATA`/
`APPDATA` to a dedicated empty directory under the state root so the operator
`USERPROFILE` is not Grok's config root. Empty `--tools` and `--deny MCPTool(*)`
do not prevent MCP init; `[compat.codex] mcps=false` did not prevent a Claude
plugin merge. Windows `--sandbox` is non-enforcing (`sandbox_profile=off`) and
is not the network boundary. Packet `network: none` is a policy deny, not an OS
block — leftover spawn still used cached OIDC and fetched models/remote settings.
A provider streaming-json error frame persists a stable provider-safe code, a
redacted bounded message, a frame digest, and a redacted copy under
`stateRoot\provider-frames`; `--debug-file` is under `stateRoot\provider-debug`
because leftover `unified.jsonl` can report startup `outcome=ok` with no
warn/error lines and a null `stderrDigest`.
On Windows Codex, `submit` needs an escalated git spawn for `verifyCustody` or
the first attempt can die with `EPERM` (exit 64) before any receipt.
Provider usage/cost is evidence when available, not hard enforcement.

Policy, artifact parsing, controller-owned application, process custody, and
Git verification are authoritative. For an
implementation packet, a missing candidate path is provisioned only after
approval and after task ownership is acquired as one exact, clean, detached
linked worktree. Provisioning or initial custody failure releases the acquired
claim. Artifact and decision records are retained under
`stateRoot\artifacts`. Invalid provider output retains a digest, byte count,
fixed rejection class, and bounded structural shape without persisting raw
paths, commands, or content. A provider scratch mutation fails closed and is
preserved for investigation. The older hook implementation is compatibility
test surface only; it is not the active implementation boundary.
Failure rollback restores candidate-custodied source and protected Git state.
`node_modules` is an explicitly non-candidate dependency cache and is neither
collected nor reset; tracked or staged module content remains prohibited.
The owning process can terminate its attested child tree; cross-process cancellation
is `unsupported` in 0.5.7, not eventual.

## Limits and release posture

The exact effects are bounded local artifact/decision/state/receipt writes, the
approved child invocation in an isolated scratch directory, and
controller-applied worktree edits and validation. Push, remote mutation, publication,
deployment, credentials, customer data, and connected MCP mutation are denied
or separately gated.

The public synthetic fixture is required live evidence for artifact-only
release: allowed work, controller denial of a prohibited path and command, one
exact repair, independent validation, collection, and scratch/state cleanup.
Artifact-only delivery is implemented and provider-free verified, but remains
held for installed use until that freshly authorized proof succeeds.
Direct-write is disabled. Adversarial review, private pilots, installation,
publication, push, merge, and deployment are separately authorized work.
No successful 0.5.7 live provider proof is claimed by this skill. The retired
0.5.6 unsupported-kind attempt is failure evidence and cannot authorize a retry.

For any failure preserve versioned JSON, stable exit code, and redacted receipt
evidence. Report plugin version, operation, task and request IDs, expected and
observed result, provider-free reproduction, and validation evidence. Never
send secrets, credentials, customer data, or unrelated private files to a
provider. Run `npm run verify` after changes; it does not call Grok or prove
live provider behavior.
