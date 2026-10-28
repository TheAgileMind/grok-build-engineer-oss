const TERMINAL = new Set(["cancelled", "accepted", "rejected", "failed", "integrity_failed"]);

const TRANSITIONS = Object.freeze({
  queued: ["preflighting", "cancelling", "failed"],
  preflighting: ["starting", "cancelling", "failed"],
  starting: ["running", "cancelling", "failed"],
  running: ["awaiting_codex_input", "candidate_ready", "cancelling", "failed"],
  awaiting_codex_input: ["running", "cancelling", "failed"],
  candidate_ready: ["repairing", "accepted", "rejected", "cancelling"],
  repairing: ["preflighting", "cancelling", "failed"],
  cancelling: ["cancelled", "failed"],
  cancelled: [], accepted: [], rejected: [], failed: [], integrity_failed: [],
  // Recovery may resume execution only through the explicit preflight path,
  // or be terminally cancelled after the service has proven child absence and
  // acquired a replacement fence.
  recovery_required: ["preflighting", "cancelling"]
});

export const LIFECYCLE_STATES = Object.freeze(Object.keys(TRANSITIONS));

export function isLifecycleState(state) { return LIFECYCLE_STATES.includes(state); }
export function isTerminal(state) { return TERMINAL.has(state); }
export function canTransition(from, to) { return isLifecycleState(from) && TRANSITIONS[from].includes(to); }
export function assertTransition(from, to) {
  if (!canTransition(from, to)) throw new RangeError(`lifecycle transition ${from} -> ${to} is not allowed`);
}
