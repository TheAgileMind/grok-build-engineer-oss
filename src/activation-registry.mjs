import { createHash, randomBytes } from "node:crypto";
import { closeSync, fsyncSync, linkSync, lstatSync, openSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import { jobIdForSubmission } from "./job-service.mjs";
import { ACTIVATION_ENV, loadActivationManifest } from "./activation-runtime.mjs";

export const ACTIVATION_REGISTRY_VERSION = "agent-platform.grok-build-engineer-registry.v1";
export const ACTIVATION_ROUTE_VERSION = "agent-platform.grok-build-engineer-route.v3";
const LEGACY_ACTIVATION_ROUTE_VERSION = "agent-platform.grok-build-engineer-route.v2";
export const ACTIVATION_REGISTRY_ENV = "GROK_BUILD_ENGINEER_ACTIVATION_REGISTRY";
const MAX_FILE_BYTES = 64 * 1024;
const MAX_DISCOVERABLE_JOBS = 128;
const JOB_ID = /^job-[a-z0-9_-]{3,96}$/;

export class ActivationRegistryError extends Error {
  constructor(message) { super(message); this.name = "ActivationRegistryError"; }
}

function exact(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("|") !== [...keys].sort().join("|")) throw new ActivationRegistryError(`${label} is invalid`);
  return value;
}
function plainFile(path, label) {
  try { const details = lstatSync(path); if (!details.isFile() || details.isSymbolicLink() || details.size < 2 || details.size > MAX_FILE_BYTES) throw new Error(); }
  catch { throw new ActivationRegistryError(`${label} is unavailable`); }
}
function plainDirectory(path, label) {
  try { const details = lstatSync(path); if (!details.isDirectory() || details.isSymbolicLink()) throw new Error(); return resolve(path); }
  catch { throw new ActivationRegistryError(`${label} is unavailable`); }
}
function inside(child, parent) { const value = relative(resolve(parent), resolve(child)); return value === "" || (!value.startsWith("..") && !isAbsolute(value)); }
function fileDigest(path) { return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`; }
function readJson(path, label) { plainFile(path, label); try { return JSON.parse(readFileSync(path, "utf8")); } catch { throw new ActivationRegistryError(`${label} is malformed`); } }
function absolute(value, label) { if (typeof value !== "string" || !isAbsolute(value)) throw new ActivationRegistryError(`${label} is invalid`); return resolve(value); }
function registryLayout(registryRoot) {
  const root = plainDirectory(absolute(registryRoot, "activation registry root"), "activation registry root");
  return { root, activations: plainDirectory(join(root, "activations"), "activation directory"), routes: plainDirectory(join(root, "routes"), "activation route directory"), acceptances: plainDirectory(join(root, "acceptances"), "activation acceptance directory") };
}
function activationSummary(path, layout, manifestLoader) {
  const manifestPath = absolute(path, "activation manifest path");
  if (!inside(manifestPath, layout.activations)) throw new ActivationRegistryError("activation manifest escapes the registry");
  plainFile(manifestPath, "activation manifest");
  let value; try { value = manifestLoader(manifestPath); } catch { throw new ActivationRegistryError("activation manifest failed full validation"); }
  const repositoryRoot = absolute(value.repositoryRoot, "activation repository root");
  const destinationRoot = absolute(value.destinationRoot, "activation destination root");
  if (typeof value.profileId !== "string" || !Array.isArray(value.dataClasses) || value.dataClasses.some((entry) => typeof entry !== "string") || !Number.isFinite(Date.parse(value.expiresAt))) throw new ActivationRegistryError("activation routing fields are invalid");
  return Object.freeze({ manifestPath, manifestDigest: fileDigest(manifestPath), repositoryRoot, destinationRoot, profileId: value.profileId, dataClasses: [...value.dataClasses], expiresAt: value.expiresAt, runtimeId: value.runtimeId ?? value.authorityId ?? null });
}
function loadRegistry(layout, manifestLoader) {
  const value = exact(readJson(join(layout.root, "registry.json"), "activation registry"), ["contractVersion", "activations"], "activation registry");
  if (value.contractVersion !== ACTIVATION_REGISTRY_VERSION || !Array.isArray(value.activations) || new Set(value.activations).size !== value.activations.length) throw new ActivationRegistryError("activation registry is invalid");
  return value.activations.map((path) => activationSummary(path, layout, manifestLoader));
}
function routePath(layout, jobId) { if (typeof jobId !== "string" || !JOB_ID.test(jobId)) throw new TypeError("jobId is invalid"); return join(layout.routes, `${jobId}.json`); }
function acceptancePath(layout, jobId) { return join(layout.acceptances, `${jobId}.json`); }
function readAcceptance(layout, route) {
  const path = acceptancePath(layout, route.jobId);
  try { lstatSync(path); } catch (error) { if (error?.code === "ENOENT") return null; throw new ActivationRegistryError("activation route acceptance is unavailable"); }
  const value = exact(readJson(path, "activation route acceptance"), ["contractVersion", "jobId", "submissionDigest", "resultDigest"], "activation route acceptance");
  if (value.contractVersion !== "agent-platform.grok-build-engineer-route-acceptance.v1" || value.jobId !== route.jobId || value.submissionDigest !== route.submissionDigest || typeof value.resultDigest !== "string") throw new ActivationRegistryError("activation route acceptance differs");
  return value;
}
function readRoute(layout, jobId, manifestLoader) {
  const value = readJson(routePath(layout, jobId), "activation route");
  const legacy = value?.contractVersion === LEGACY_ACTIVATION_ROUTE_VERSION;
  exact(value, legacy ? ["contractVersion", "jobId", "manifestPath", "manifestDigest", "state", "submissionDigest"] : ["contractVersion", "jobId", "manifestPath", "manifestDigest", "state", "submissionDigest", "acceptanceDigest"], "activation route");
  if (![ACTIVATION_ROUTE_VERSION, LEGACY_ACTIVATION_ROUTE_VERSION].includes(value.contractVersion) || value.jobId !== jobId || !["pending", "accepted"].includes(value.state) || (legacy && value.state !== "pending") || typeof value.submissionDigest !== "string" || (!legacy && (value.state === "pending" ? value.acceptanceDigest !== null : typeof value.acceptanceDigest !== "string"))) throw new ActivationRegistryError("activation route identity differs");
  const activation = activationSummary(value.manifestPath, layout, manifestLoader);
  if (activation.manifestDigest !== value.manifestDigest) throw new ActivationRegistryError("activation route manifest was changed");
  const acceptance = readAcceptance(layout, value);
  if (value.state === "accepted" && (!acceptance || acceptance.resultDigest !== value.acceptanceDigest)) throw new ActivationRegistryError("activation route acceptance differs");
  const projected = acceptance ? { ...value, state: "accepted", ...(legacy ? {} : { acceptanceDigest: acceptance.resultDigest }) } : value;
  return Object.freeze({ activation, record: Object.freeze(projected), legacy, acceptance: acceptance ? Object.freeze(acceptance) : null });
}
function publishNoClobber(path, record, failureLabel) {
  const temporary = `${path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  let descriptor;
  try {
    descriptor = openSync(temporary, "wx", 0o600); writeFileSync(descriptor, `${JSON.stringify(record)}\n`, "utf8"); fsyncSync(descriptor); closeSync(descriptor); descriptor = undefined;
    try { linkSync(temporary, path); return true; }
    catch (error) { if (error?.code === "EEXIST") return false; throw error; }
  } catch (error) { if (error instanceof ActivationRegistryError) throw error; throw new ActivationRegistryError(`${failureLabel} could not be persisted`); }
  finally { if (descriptor !== undefined) closeSync(descriptor); try { unlinkSync(temporary); } catch (error) { if (error?.code !== "ENOENT") throw new ActivationRegistryError(`${failureLabel} cleanup failed`); } }
}
function persistRoute(layout, jobId, activation, manifestLoader, submissionDigest) {
  const path = routePath(layout, jobId);
  const record = { contractVersion: ACTIVATION_ROUTE_VERSION, jobId, manifestPath: activation.manifestPath, manifestDigest: activation.manifestDigest, state: "pending", submissionDigest, acceptanceDigest: null };
  if (!publishNoClobber(path, record, "activation route")) {
    const existing = readRoute(layout, jobId, manifestLoader);
    if (existing.activation.manifestPath !== activation.manifestPath || existing.activation.manifestDigest !== activation.manifestDigest || existing.record.submissionDigest !== submissionDigest) throw new ActivationRegistryError("job already belongs to another activation or submission");
  }
  return readRoute(layout, jobId, manifestLoader);
}
function persistAcceptance(layout, jobId, submissionDigest, result) {
  const path = acceptancePath(layout, jobId), resultDigest = `sha256:${createHash("sha256").update(JSON.stringify(result)).digest("hex")}`;
  const record = { contractVersion: "agent-platform.grok-build-engineer-route-acceptance.v1", jobId, submissionDigest, resultDigest };
  if (!publishNoClobber(path, record, "activation route acceptance")) {
    const existing = readJson(path, "activation route acceptance");
    if (JSON.stringify(existing) !== JSON.stringify(record)) throw new ActivationRegistryError("activation route acceptance differs");
  }
  return resultDigest;
}
function assertAccepted(layout, route, acceptanceDigest) {
  const acceptance = readAcceptance(layout, route.record);
  if (!acceptance || acceptance.resultDigest !== acceptanceDigest) throw new ActivationRegistryError("activation route could not be finalized");
}
function unresolvedRoute(route) {
  return Object.freeze({ job: { jobId: route.record.jobId, state: "submission_pending", nextActions: ["retry_exact_submission"] }, candidate: null, events: [], diagnostic: "The initial submission route is durable but no matching host receipt has been observed. Retry the exact original submission; do not collect, cancel, or repair this route yet." });
}
function exactMatch(submission, activation, now) {
  return Date.parse(activation.expiresAt) > now.getTime() &&
    resolve(submission.source.repositoryRoot) === activation.repositoryRoot &&
    inside(submission.source.destinationRoot, activation.destinationRoot) &&
    submission.profileId === activation.profileId && activation.dataClasses.includes(submission.task.dataClass);
}

export function findActiveActivations({ registryRoot, repositoryRoot, destinationRoot, profileId, dataClass, now = new Date() } = {}) {
  const layout = registryLayout(registryRoot), clock = now instanceof Date ? now : new Date(now);
  const submission = { source: { repositoryRoot: absolute(repositoryRoot, "repository root"), destinationRoot: absolute(destinationRoot, "destination root") }, profileId, task: { dataClass } };
  const manifestLoader = (path) => loadActivationManifest({ environment: { ...process.env, [ACTIVATION_ENV]: path }, now: clock, allowExpired: true });
  return loadRegistry(layout, manifestLoader).filter((entry) => exactMatch(submission, entry, clock)).map((entry) => Object.freeze({ manifestPath: entry.manifestPath, manifestDigest: entry.manifestDigest, repositoryRoot: entry.repositoryRoot, destinationRoot: entry.destinationRoot, profileId: entry.profileId, dataClasses: entry.dataClasses, expiresAt: entry.expiresAt, runtimeId: entry.runtimeId }));
}

export function defaultActivationRegistryRoot(environment = process.env) {
  if (typeof environment[ACTIVATION_REGISTRY_ENV] === "string" && isAbsolute(environment[ACTIVATION_REGISTRY_ENV])) return resolve(environment[ACTIVATION_REGISTRY_ENV]);
  if (typeof environment.LOCALAPPDATA !== "string" || !isAbsolute(environment.LOCALAPPDATA)) return null;
  return resolve(environment.LOCALAPPDATA, "AgentPlatformDevHub", "grok-build-engineer", "registry");
}

export function activationRegistryAvailable(registryRoot) {
  if (typeof registryRoot !== "string" || !isAbsolute(registryRoot)) return false;
  // Presence selects registry mode even when its structure is unsafe or
  // malformed. The service then fails closed instead of falling back to a
  // stale legacy manifest merely because validation failed.
  try { lstatSync(join(resolve(registryRoot), "registry.json")); return true; } catch (error) { if (error?.code === "ENOENT") return false; throw error; }
}

export function createActivationRegistryService({ registryRoot, proxyFactory, now = () => new Date(), manifestLoader = null, healthMetadata = {} } = {}) {
  if (typeof proxyFactory !== "function") throw new TypeError("activation proxy factory is required");
  const layout = registryLayout(registryRoot);
  const current = () => { const value = now instanceof Date ? new Date(now) : new Date(typeof now === "function" ? now() : now); if (Number.isNaN(value.getTime())) throw new TypeError("activation registry clock is invalid"); return value; };
  current();
  const loadManifest = manifestLoader ?? ((path) => loadActivationManifest({ environment: { ...process.env, [ACTIVATION_ENV]: path }, now: current(), allowExpired: true }));
  const proxies = new Map();
  const proxy = (activation) => {
    let value = proxies.get(activation.manifestDigest);
    if (!value) { value = proxyFactory(activation); proxies.set(activation.manifestDigest, value); }
    return value;
  };
  const routed = (operation) => async (args) => {
    const route = readRoute(layout, args?.jobId, loadManifest);
    if (route.record.state === "pending") {
      if (operation === "status") return unresolvedRoute(route);
      throw new ActivationRegistryError("activation route is unresolved; retry the exact original submission before lifecycle actions");
    }
    return proxy(route.activation)[operation](args);
  };
  const discoverJobs = () => {
    const entries = readdirSync(layout.routes, { withFileTypes: true });
    if (entries.length > MAX_DISCOVERABLE_JOBS) throw new ActivationRegistryError("activation route inventory exceeds the bounded health projection");
    return entries.map((entry) => {
      if (!entry.isFile() || entry.isSymbolicLink() || !entry.name.endsWith(".json")) throw new ActivationRegistryError("activation route inventory is invalid");
      const jobId = basename(entry.name, ".json"), route = readRoute(layout, jobId, loadManifest), pending = route.record.state === "pending";
      return Object.freeze({ jobId, routeState: pending ? "submission_pending" : "routed", runtimeId: route.activation.runtimeId, expiresAt: route.activation.expiresAt, nextActions: pending ? ["retry_exact_submission"] : ["call_grok_status_with_job_id"] });
    }).sort((left, right) => left.jobId.localeCompare(right.jobId));
  };
  const healthBase = Object.freeze({ loadedVersion: healthMetadata.loadedVersion ?? "0.3.13", bundleDigest: healthMetadata.bundleDigest ?? null, grokVersion: "unavailable", activationMatch: false });
  const unavailableRuntimeHealth = (expiresAt, correctiveAction) => ({ kind: "runtime_health", ...healthBase, expiresAt, correctiveAction });
  const health = async () => {
    let activations, jobs;
    try { activations = loadRegistry(layout, loadManifest); jobs = discoverJobs(); }
    catch { return Object.freeze({ kind: "registry_health", ...healthBase, expiresAt: null, correctiveAction: "repair_activation_registry", activations: [], jobs: [] }); }
    const reports = await Promise.all(activations.map(async (activation) => {
      try { return { runtimeId: activation.runtimeId, expiresAt: activation.expiresAt, health: await proxy(activation).status({}) }; }
      catch { return { runtimeId: activation.runtimeId, expiresAt: activation.expiresAt, health: unavailableRuntimeHealth(activation.expiresAt, "renew_or_repair_runtime_activation") }; }
    }));
    const ready = reports.filter((entry) => entry.health?.activationMatch === true && entry.health?.correctiveAction === "ready");
    const grokVersions = [...new Set(ready.map((entry) => entry.health.grokVersion).filter((value) => typeof value === "string"))];
    return Object.freeze({ kind: "registry_health", ...healthBase, grokVersion: grokVersions.length === 1 ? grokVersions[0] : "unavailable", activationMatch: ready.length > 0, expiresAt: ready.length === 1 ? ready[0].expiresAt : reports.length === 1 ? reports[0].expiresAt : null, correctiveAction: ready.length > 0 ? "ready" : reports.length ? "renew_or_repair_runtime_activation" : "create_runtime_activation", activations: reports, jobs });
  };
  return Object.freeze({
    async submit(submission) {
      let activation;
      let route = null;
      if (submission?.mode === "repair") {
        route = readRoute(layout, submission?.continuation?.jobId, loadManifest);
        if (route.record.state === "pending") throw new ActivationRegistryError("activation route is unresolved; retry the exact original submission first");
        activation = route.activation;
      }
      else {
        const clock = current(), matches = loadRegistry(layout, loadManifest).filter((entry) => exactMatch(submission, entry, clock));
        if (matches.length === 0) throw new ActivationRegistryError("no active activation matches this submission");
        if (matches.length !== 1) throw new ActivationRegistryError("multiple active activations match this submission");
        [activation] = matches;
      }
      const expectedJobId = submission.mode === "repair" ? submission.continuation.jobId : jobIdForSubmission(submission.submissionId);
      const submissionDigest = `sha256:${createHash("sha256").update(JSON.stringify(submission)).digest("hex")}`;
      if (submission.mode === "new") route = persistRoute(layout, expectedJobId, activation, loadManifest, submissionDigest);
      const result = await proxy(activation).submit(submission);
      if (!result || result.jobId !== expectedJobId) throw new ActivationRegistryError("activated host returned a different job identity");
      if (submission.mode === "new") assertAccepted(layout, route, persistAcceptance(layout, expectedJobId, submissionDigest, result));
      return result;
    },
    status: async (args = {}) => args?.jobId === undefined ? health() : routed("status")(args), collect: routed("collect"), cancel: routed("cancel")
  });
}
