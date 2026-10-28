# Grok Build Engineer

A Node.js plugin for OpenAI Codex that lets Codex hand bounded coding tasks to
the Grok Build CLI under strict human-approval and custody rules. Codex keeps
ownership of the source tree, validation, and acceptance. Grok only returns a
versioned JSON change artifact, and a trusted controller decides which file
operations and validation commands actually run.

What it demonstrates:

- **Agent-to-agent delegation with guardrails.** Each job is prepared as a
  secret-free task packet with a digest. A human approves that exact digest
  before submission, and there is at most one repair attempt.
- **Least-privilege execution.** Provider tools are disabled, the run happens
  in an isolated empty state directory, and a pre-tool guard plus allowlisted
  validation commands control what the provider can do.
- **Evidence and redaction.** Receipts, stream frames, and job state are
  persisted with secret redaction, and Git-based worktree custody makes
  changes auditable.
- **Contracts and tests.** Versioned JSON contracts, an MCP compatibility
  server, and about 210 provider-free `node:test` tests.

## Requirements

- Windows host (the custody and path rules are Windows-specific; CI runs on
  `windows-latest`)
- Node.js 20 or 22
- The Grok Build CLI, only for live runs. Tests never call a provider.

## Install and test

```bash
npm ci --ignore-scripts
npm test              # provider-free unit and integration tests
npm run verify        # build + syntax checks + release gate
```

`npm run build` regenerates the bundled MCP server in `mcp/server.mjs` with
esbuild and rewrites its SHA-256 pin in `.mcp.json`. The bundle contains
third-party code; see `THIRD_PARTY_NOTICES.md`.

## Usage

```bash
node scripts/grok-delegate.mjs --help
```

The examples in `examples/` show task packets, job requests, and capability
profiles. The lifecycle and trust model are described below.

## Design notes

### 0.5.7: exact artifact contracts and rejected-output evidence

This plugin is a finite, one-shot CLI runner on a trusted Windows host. Codex
owns source custody, independent validation, acceptance, repair authority, and
collection. A trusted host is not an OS sandbox. The plugin does not authorize
provider access, credentials, deployment, publication, push, merge, or customer
action.

The 0.5.7 successor keeps the provider outside the candidate worktree. It
embeds only explicitly named, bounded text context in the prompt, runs Grok in
an empty state-root scratch directory with provider tools disabled, and accepts
only one versioned JSON change artifact. The prompt supplies an exact task-bound
JSON envelope, exact operation fields, and the only three accepted operation
kinds. The trusted controller—not Grok—then
decides every requested path and command, applies allowed file operations, and
runs the exact allowlisted validation commands. Direct-write delivery is
disabled.

The only implementation lifecycle is:

1. **Prepare** a secret-free packet. Preparation computes the canonical digest
   and validates policy; it does not create authority or call a provider.
2. **Approve** the exact digest and scope through a human decision. The approval
   object must include its contract version, approver, issue/expiry times,
   authorization statement, and packet digest. Self-authored JSON is not human
   approval.
3. **Submit** the approved packet through the finite CLI.
4. **Status** the exact state root and task identity; inspect the receipt and
   Git-authoritative custody independently.
5. **Repair** at most once, only from a Codex rejection with versioned findings,
   the prior receipt, and the exact native session continuation.
6. **Collect** only after Codex accepts the candidate with versioned validation
   evidence. Collection never means publication or deployment.

Resolve `<plugin-root>` from this repository's absolute
`skills\grok-build-engineer\SKILL.md` path by walking up to the directory that
contains `skills`. Do not assume a cache-version directory. The packet's
`worktree` is an absolute candidate location distinct from the source repository,
not the plugin directory. For an implementation packet it may be absent at
prepare time: after approval, the runner re-admits the packet custody and creates
one clean, detached linked worktree at that exact path before it can spawn a
provider process. A pre-existing path is never replaced or repurposed.

```powershell
$pluginRoot = "<plugin-root>"
node "$pluginRoot\scripts\prepare-task-packet.mjs" input.json > task.json
# A human reviews and approves task.json's exact approval.packetDigest and scope.
node "$pluginRoot\scripts\grok-delegate.mjs" submit --packet task.json --approval approval.json
node "$pluginRoot\scripts\grok-delegate.mjs" status --state-root C:\path\state --task-run-id run-001
# After Codex rejects with bounded findings, populate the repair template from
# the exact candidate receipt and findings, then prepare and approve its digest:
node "$pluginRoot\scripts\prepare-task-packet.mjs" repair-input.json > repair.json
node "$pluginRoot\scripts\grok-delegate.mjs" repair --packet repair.json --findings findings.json
node "$pluginRoot\scripts\grok-delegate.mjs" collect --state-root C:\path\state --task-run-id run-001 --acceptance acceptance.json
node "$pluginRoot\scripts\grok-delegate.mjs" cancel --state-root C:\path\state --task-run-id run-001
```

`prepare-task-packet.mjs` is only a compatibility façade: it uses the same
canonical digest and policy validation as the unified
`grok-delegate.mjs prepare` operation and emits the validated packet for the
established redirect
format. It does not implement a second lifecycle.

Every CLI response is versioned JSON with a stable exit code. Do not use the
retired MCP lifecycle for implementation, repair, collection, or cancellation.

## What this boundary proves—and does not prove

- The executable, arguments, worktree, state root, exact command tokens, paths,
  environment names, network mode, artifact-only delivery mode, and finite
  timeouts are frozen by the packet policy. Provider tools must be empty and
  wildcard command patterns cannot widen authority.
- An empty caller environment allowlist still copies the fixed Windows launch
  variables when present (`PATH`, `COMSPEC`, `SYSTEMROOT`, `TEMP`, and the
  documented Grok/config variables); secret-shaped names are excluded.
  Artifact-only child launches then override `GROK_HOME`, `HOME`,
  `USERPROFILE`, `LOCALAPPDATA`, and `APPDATA` to a dedicated empty directory
  under the state root (`stateRoot\\provider-homes\\<taskRunId>\\<requestId>`)
  so the provider cannot treat the operator `USERPROFILE` as Grok's config
  root. Empty `--tools` and `--deny MCPTool(*)` do not prevent MCP process
  init. A leftover 0.5.7 live run started figma/gbrain/linear from
  `~/.grok/config.toml` plus episodic-memory/exa/supabase/paper from a Claude
  plugin merge; `[compat.codex] mcps=false` did not prevent that merge. The
  operator home is not mutated. Windows `--sandbox` is non-enforcing
  (`sandbox_profile=off`) and is not used as a network or MCP boundary.
  Packet `network: none` is a policy deny, not an OS block: after spawn the
  leftover child authenticated via cached OIDC (`auth_mode=personal`) and
  fetched models plus remote settings.
- A provider streaming-json `type:"error"` frame (or a frame with `error`)
  persists a stable provider-safe diagnostic code, a redacted bounded message,
  a digest of the complete frame, and any non-secret category/status. The
  redacted frame is also written under
  `stateRoot\\provider-frames\\<taskRunId>\\<requestId>.error.json`. The child
  is launched with `--debug-file` under `stateRoot\\provider-debug` because
  leftover Grok `unified.jsonl` can be info-only (`startup complete
  outcome=ok`) with no warn/error lines, then silent until exit 1, while the
  receipt `stderrDigest` is null. CLI logs will not save the stdout error
  frame. Tokens, Authorization material, cookies, and raw prompt/source are
  never stored. `failCode()` uses that provider code instead of collapsing
  to `runner_failure`.
- Policy, artifact parsing, controller-owned application, process custody, and
  Git checks are the active boundaries. The provider receives no local tool
  authority and never uses the candidate worktree as its current directory.
  Every allowed or denied artifact operation is recorded under
  `stateRoot\artifacts`. A rejected artifact records only its exact output
  digest, byte count, fixed rejection class, and bounded structural shape—never
  raw paths, commands, or content. Any provider scratch mutation fails closed and is
  preserved for investigation. The older hook code remains compatibility test
  surface only and is not the implementation boundary.
- The controller transaction restores candidate-custodied source and protected
  Git state after validation, scope, or decision-evidence failure. `node_modules`
  remains an explicitly non-candidate dependency cache: it is not collected or
  reset by this transaction, and tracked or staged module content is rejected.
- Provider usage/cost is bounded evidence when the provider reports it, not a
  hard cost-enforcement guarantee. Operators must not claim zero cost.
- The owning process may enforce its timeout and terminate its attested child
  tree. Cross-process cancellation is unsupported in 0.5.7: a different CLI
  process returns stable `unsupported` rather than recording a false
  cancellation.
- On Windows Codex, `submit` runs `verifyCustody` via `spawnSync("git")`
  before any receipt exists. An unelevated Codex session can die with git
  `EPERM` (CLI exit 64) and never reach the provider. Escalate the git
  spawn or the Codex session if that happens; this is a host permission
  issue, not a packet or provider failure.
- Exact effects are local packet/state writes, an approved child invocation in
  an isolated scratch directory, bounded artifact/decision/receipt writes, and
  controller-applied worktree edits and validation. Push, remote
  changes, publication, deployment, credential access, customer data access,
  and connected MCP mutation remain denied or separately gated.

## Repair, acceptance, and failure evidence

Repair findings (`findings.json`) are the bounded, versioned rejection evidence:

```json
{
  "contractVersion": "agent-platform.grok-build-engineer-repair-findings.v1",
  "taskRunId": "run-001",
  "requestId": "request-001",
  "priorReceiptDigest": "sha256:<64 lowercase hex>",
  "sourceSha": "<40 lowercase hex Git SHA>",
  "repositoryRoot": "C:\\repo",
  "worktree": "C:\\repo\\.worktrees\\mission",
  "createdAt": "2026-08-25T00:00:00.000Z",
  "findings": [{ "code": "validation_failed", "message": "Codex validation failed." }]
}
```

Start `repair-input.json` from
`examples\repair-task-packet.template.json`. Keep the prior candidate's
`taskRunId`, source SHA, repository, worktree, native session ID, receipt
digest, and diff digest exact; use a new `requestId`; set `findingsDigest` to
the canonical digest of `findings.json`; and set `repairBudget` to one. Run the
same prepare command used above, then obtain human approval for the resulting
repair packet digest before invoking `repair`. Do not infer continuation fields
from chat history.

Acceptance (`acceptance.json`) is the durable Codex decision and must carry the
receipt, custody, and validation evidence digests. Preserve the complete
versioned response, stable exit code, and redacted receipt for every failure;
never include secrets or raw private content.

## Synthetic fixture and release hold

The secret-free fixture in `test\fixtures\live-synthetic` is the only planned
public-fixture gate. A fresh session must read this README and the skill,
prepare a packet with a fresh isolated candidate path, verify that submit
provisions its linked worktree, and retain evidence for the allowed edit, one
exact same-session repair, prohibited path and command denials recorded by the
controller, independent validation, collection, and scratch/state cleanup. The
fixture README defines the evidence bundle and fresh-session checklist.

No successful 0.5.7 live provider proof is claimed by this repository. The
retired 0.5.6 attempt failed closed on an unsupported provider operation kind;
it is failure evidence, not reusable authorization or 0.5.7 proof.
Artifact-only delivery is implemented and provider-free verified, but release
for installed use remains held until a freshly authorized public-fixture run
proves the real provider emits the contract and the controller proves the
allowed edit plus both harmless denials. Direct-write remains disabled. Any
private-project review, publication, deployment, push, merge, or installation
remains separately planned and separately authorized.

Run `npm run verify` for syntax, generated compatibility parity, and the
provider-free test suite. These checks do not call Grok or establish live
provider behavior.


## License

MIT. See `LICENSE`. Bundled dependencies keep their own licenses
(`THIRD_PARTY_NOTICES.md`).
