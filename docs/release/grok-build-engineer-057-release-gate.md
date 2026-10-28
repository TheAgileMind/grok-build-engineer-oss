# Grok Build Engineer 0.5.7 release gate

This successor hardens the artifact-only boundary after the separately
authorized 0.5.6 public-fixture attempt failed closed on an unsupported
provider operation kind. That attempt and its digest authorization are retired;
they are not 0.5.7 live evidence and must not be retried.

## Provider-free gate

Run `npm run verify`. The current CLI suites must prove:

1. the provider prompt includes an exact task-bound JSON envelope, exact object
   fields, and the `write_file`, `delete_file`, and `run_command` kind enum;
2. provider-tool and legacy operation kinds are explicitly forbidden;
3. unsupported kinds fail before controller execution or candidate effects;
4. rejected output persists only an exact digest, byte count, fixed rejection
   class, and bounded secret-safe structural shape;
5. rejected-artifact evidence is immutable and persistence failure fails closed;
6. a failed receipt cannot be collected or used as a repair candidate; and
7. all existing custody, rollback, receipt, cleanup, policy, and manifest gates
   continue to pass;
8. a production one-shot runner error-frame fixture persists a provider-safe
   diagnostic code, redacted bounded message, frame digest, and a redacted
   state-root error-frame file with secrets removed;
9. artifact-only launch construction isolates `GROK_HOME`/`HOME`/`USERPROFILE`/
   `LOCALAPPDATA`/`APPDATA` from a fixture operator home that contains
   `mcp_servers` plus `[compat.codex] mcps=false` and a Claude plugin-merge
   fixture, and passes `--debug-file` under the state root (not `--sandbox`).

No provider call is made by `npm run verify`. These two successor checks are
provider-free reproductions of the 2026-09-01 RED-205 receipt collapse and
global-home isolation failures.

The machine-readable decision remains `artifact_only_held`.
`direct_write_disabled` remains an invariant. This successor does not claim
live provider proof and does not call api.x.ai.

## Separately authorized live U18 gate

Provider-free verification does not prove Grok emits the exact artifact. A new
packet must be generated from the merged and installed 0.5.7 artifact, then
authorized by its exact digest. One fresh public-fixture session must prove the
allowed edit, harmless prohibited-path and prohibited-command denials,
independent validation, one separately authorized exact same-session repair,
collection, and cleanup.

No provider call is made by `npm run verify`. Installation, U18 submission,
repair, cleanup, private-source access, publication, push, merge, and deployment
remain separate human approval gates.
