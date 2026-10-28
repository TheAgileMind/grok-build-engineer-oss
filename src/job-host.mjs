import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { closeSync, chmodSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import net from "node:net";
import { isAbsolute, join, resolve } from "node:path";

export const JOB_HOST_PROTOCOL = "agent-platform.grok-build-engineer-host.v1";
const MAX_MESSAGE_BYTES = 2 * 1024 * 1024;
const SERVICE_OPERATIONS = new Set(["submit", "status", "collect", "cancel"]);
const OPERATIONS = new Set(["ping", ...SERVICE_OPERATIONS]);
const SECRET_PATTERN = /^[a-f0-9]{64}$/;

export class JobHostRemoteError extends Error {
  constructor(remote) {
    super(remote?.message ?? "The persistent Grok job host rejected the request.");
    this.name = "JobHostRemoteError";
    this.remote = Object.freeze({
      code: typeof remote?.code === "string" ? remote.code : "service_error",
      message: typeof remote?.message === "string" ? remote.message : "The governed job service rejected the request.",
      ...(typeof remote?.category === "string" ? { category: remote.category } : {}),
      ...(typeof remote?.evidenceDigest === "string" ? { evidenceDigest: remote.evidenceDigest } : {})
    });
  }
}

export class JobHostUnavailableError extends Error {
  constructor() {
    super("The supervised local Grok job host is unavailable.");
    this.name = "JobHostUnavailableError";
  }
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function activationPath(environment) {
  const value = environment.GROK_BUILD_ENGINEER_ACTIVATION_MANIFEST;
  if (typeof value !== "string" || !isAbsolute(value)) throw new Error("activation manifest is unavailable");
  return resolve(value);
}

function activationIdentity(environment) {
  const path = activationPath(environment), bytes = readFileSync(path);
  let manifest; try { manifest = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("activation manifest is unavailable"); }
  if (!manifest || typeof manifest.stateRoot !== "string" || !isAbsolute(manifest.stateRoot) || !Number.isFinite(Date.parse(manifest.expiresAt))) throw new Error("activation manifest is unavailable");
  return { path, bytes, manifest, digest: digest(bytes) };
}

function secureDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const details = lstatSync(path); if (!details.isDirectory() || details.isSymbolicLink()) throw new Error("job host state directory is unsafe");
  if (process.platform !== "win32") chmodSync(path, 0o700);
  return path;
}

/** Trusted single-desktop-user IPC only; this does not claim protection from a same-user process. */
export function jobHostRequestSecret(environment = process.env) {
  const activation = activationIdentity(environment), directory = secureDirectory(resolve(activation.manifest.stateRoot, "job-host-auth"));
  const path = join(directory, `${activation.digest}.json`);
  const read = () => {
    const details = lstatSync(path); if (!details.isFile() || details.isSymbolicLink() || details.size > 1024) throw new Error("job host credential is unsafe");
    if (process.platform !== "win32") chmodSync(path, 0o600);
    const record = JSON.parse(readFileSync(path, "utf8"));
    if (!record || record.contractVersion !== "agent-platform.grok-build-engineer-host-secret.v1" || record.activationDigest !== activation.digest || !SECRET_PATTERN.test(record.secret)) throw new Error("job host credential is invalid");
    return record.secret;
  };
  try { return read(); }
  catch (error) {
    if (error?.code !== "ENOENT") throw error;
    const record = { contractVersion: "agent-platform.grok-build-engineer-host-secret.v1", activationDigest: activation.digest, secret: randomBytes(32).toString("hex") };
    const temporary = `${path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
    let descriptor;
    try {
      descriptor = openSync(temporary, "wx", 0o600); writeFileSync(descriptor, `${JSON.stringify(record)}\n`); fsyncSync(descriptor); closeSync(descriptor); descriptor = undefined;
      try { linkSync(temporary, path); } catch (writeError) { if (writeError?.code !== "EEXIST") throw writeError; }
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
      try { unlinkSync(temporary); } catch (cleanupError) { if (cleanupError?.code !== "ENOENT") throw cleanupError; }
    }
    return read();
  }
}

function activationValidator(environment, initial = null) {
  if (typeof environment?.GROK_BUILD_ENGINEER_ACTIVATION_MANIFEST !== "string") return null;
  const expected = initial ?? activationIdentity(environment).digest;
  return () => {
    const current = activationIdentity(environment);
    if (current.digest !== expected) throw Object.assign(new Error("activation runtime is no longer current"), { name: "ActivationConfigError" });
  };
}

export function jobHostEndpoint(environment = process.env, platform = process.platform, bundleIdentity = "") {
  const manifestPath = activationPath(environment);
  const identity = digest(`${platform}\0${bundleIdentity}\0${platform === "win32" ? manifestPath.toLowerCase() : manifestPath}\0${readFileSync(manifestPath)}`);
  if (platform === "win32") return `\\\\.\\pipe\\grok-build-engineer-${identity}`;
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (!manifest || typeof manifest.stateRoot !== "string" || !isAbsolute(manifest.stateRoot)) throw new Error("activation state root is unavailable");
  return join(resolve(manifest.stateRoot), `.grok-build-engineer-${identity}.sock`);
}

function safeRemoteError(error) {
  if (error instanceof TypeError || error instanceof RangeError) return { code: "invalid_input", message: error.message };
  if (error?.name === "ActivationConfigError" || error?.name === "ActivationUnavailableError") return { code: "activation_unavailable", message: "Local Grok activation is unavailable." };
  if (error?.name === "ActivationAuthorityError") return { code: "authority_denied", message: "Protected host authority denied the request.", category: error.category, evidenceDigest: error.evidenceDigest };
  if (error?.name === "IntegrityError") return { code: "integrity_error", message: "Durable job evidence did not satisfy the requested lifecycle transition." };
  if (error?.name === "LeaseConflictError") return { code: "lease_conflict", message: "The governed job lease is held or not yet recoverable." };
  if (error?.name === "IdempotencyConflictError") return { code: "idempotency_conflict", message: "The idempotency key conflicts with durable job evidence." };
  return { code: "service_error", message: "The governed job service rejected the request." };
}

function encode(value) {
  const encoded = `${JSON.stringify(value)}\n`;
  if (Buffer.byteLength(encoded) > MAX_MESSAGE_BYTES) throw new Error("job host message exceeds boundary");
  return encoded;
}

async function readMessage(socket, timeoutMs) {
  return new Promise((resolveMessage, rejectMessage) => {
    let buffer = "", bytes = 0;
    const timer = setTimeout(() => { socket.destroy(); rejectMessage(new Error("job host request timed out")); }, timeoutMs);
    const done = (callback, value) => { clearTimeout(timer); socket.removeAllListeners(); callback(value); };
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > MAX_MESSAGE_BYTES) return done(rejectMessage, new Error("job host response exceeds boundary"));
      buffer += chunk;
      const newline = buffer.indexOf("\n");
      if (newline < 0) return;
      try { done(resolveMessage, JSON.parse(buffer.slice(0, newline))); }
      catch { done(rejectMessage, new Error("job host response is malformed")); }
    });
    socket.on("error", (error) => done(rejectMessage, error));
    socket.on("end", () => { if (!buffer.includes("\n")) done(rejectMessage, new Error("job host response was truncated")); });
  });
}

export async function requestJobHost({ endpoint, operation, args, requestSecret, timeoutMs = 30_000 }) {
  if (!OPERATIONS.has(operation)) throw new TypeError("job host operation is unsupported");
  if (typeof requestSecret !== "string" || !SECRET_PATTERN.test(requestSecret)) throw new TypeError("job host request secret is required");
  const requestId = `request-${randomBytes(16).toString("hex")}`;
  const socket = net.createConnection(endpoint);
  await new Promise((resolveConnection, rejectConnection) => {
    const timer = setTimeout(() => {
      socket.destroy();
      rejectConnection(new Error("job host connection timed out"));
    }, Math.min(timeoutMs, 5_000));
    const finish = (callback, value) => {
      clearTimeout(timer);
      socket.removeListener("connect", connected);
      socket.removeListener("error", failed);
      callback(value);
    };
    const connected = () => finish(resolveConnection);
    const failed = (error) => finish(rejectConnection, error);
    socket.once("connect", connected);
    socket.once("error", failed);
  });
  socket.write(encode({ contractVersion: JOB_HOST_PROTOCOL, requestId, operation, args, requestSecret }));
  const response = await readMessage(socket, timeoutMs);
  socket.end();
  if (!response || response.contractVersion !== JOB_HOST_PROTOCOL || response.requestId !== requestId || typeof response.ok !== "boolean") throw new Error("job host response identity differs");
  if (!response.ok) {
    if (response.error?.code === "invalid_input") throw new TypeError(response.error.message);
    throw new JobHostRemoteError(response.error);
  }
  return response.result;
}

export async function startJobHost({ service, environment = process.env, endpoint = jobHostEndpoint(environment), requestSecret = null, validateRuntime = null } = {}) {
  if (!service || [...SERVICE_OPERATIONS].some((operation) => typeof service[operation] !== "function")) throw new TypeError("job host service is incomplete");
  const hostSecret = requestSecret ?? jobHostRequestSecret(environment);
  if (!SECRET_PATTERN.test(hostSecret)) throw new TypeError("job host request secret is required");
  const runtimeValidator = validateRuntime ?? (requestSecret === null ? activationValidator(environment) : null);
  const server = net.createServer((socket) => {
    void (async () => {
      let requestId = "unknown";
      try {
        const request = await readMessage(socket, 30_000);
        if (!request || request.contractVersion !== JOB_HOST_PROTOCOL || typeof request.requestId !== "string" || !OPERATIONS.has(request.operation) || !request.args || typeof request.args !== "object" || Array.isArray(request.args)) throw new TypeError("job host request is malformed");
        requestId = request.requestId;
        if (typeof request.requestSecret !== "string" || !SECRET_PATTERN.test(request.requestSecret) ||
            !timingSafeEqual(Buffer.from(request.requestSecret, "hex"), Buffer.from(hostSecret, "hex"))) throw new TypeError("job host request is malformed");
        runtimeValidator?.();
        const result = request.operation === "ping" ? {
          ready: true,
          ...(service.runtimePolicy ? { runtimePolicy: service.runtimePolicy } : {})
        } : await service[request.operation](request.args);
        socket.end(encode({ contractVersion: JOB_HOST_PROTOCOL, requestId, ok: true, result }));
      } catch (error) {
        try { socket.end(encode({ contractVersion: JOB_HOST_PROTOCOL, requestId, ok: false, error: safeRemoteError(error) })); }
        catch { socket.destroy(); }
      }
    })();
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(endpoint, resolveListen);
  });
  // POSIX socket files can be owner-restricted with Node. Windows named-pipe
  // ACLs are not configurable through this API; the supported boundary there
  // remains one trusted desktop user, not protection from same-user code.
  if (process.platform !== "win32") {
    try { chmodSync(endpoint, 0o600); }
    catch { await new Promise((resolveClose) => server.close(resolveClose)); throw new Error("job host endpoint permissions are unavailable"); }
  }
  return Object.freeze({ endpoint, close: () => new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose())) });
}

async function waitForHost(endpoint, requestSecret, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try { return await requestJobHost({ endpoint, operation: "ping", args: {}, requestSecret, timeoutMs: 1_000 }); }
    catch (error) {
      lastError = error;
      if (!/connect|pipe|not found|rejected|unknown job|job does not exist/i.test(error.message)) throw error;
      await new Promise((resolveWait) => setTimeout(resolveWait, 50));
    }
  }
  throw lastError ?? new Error("persistent Grok job host did not start");
}

export function createJobHostProxy({ environment = process.env, bundlePath = process.argv[1], expectedBundleDigest, spawnProcess = null, startTimeoutMs = 15_000 } = {}) {
  const endpoint = jobHostEndpoint(environment, process.platform, expectedBundleDigest);
  const requestSecret = jobHostRequestSecret(environment);
  let startPromise = null;
  const ensure = async () => {
    try {
      await requestJobHost({ endpoint, operation: "ping", args: {}, requestSecret, timeoutMs: 500 });
      return;
    } catch (error) {
      if (!/connect|pipe|not found|rejected|unknown job|job does not exist/i.test(error.message)) throw error;
    }
    if (typeof spawnProcess !== "function") throw new JobHostUnavailableError();
    if (!startPromise) {
      const pending = (async () => {
        const child = spawnProcess(process.execPath, [resolve(bundlePath), "--bundle-sha256", expectedBundleDigest, "--job-host"], {
          detached: true, windowsHide: true, shell: false, stdio: "ignore", env: { ...environment }
        });
        child.unref?.();
        let rejectSpawn;
        const spawnFailure = new Promise((_, reject) => { rejectSpawn = reject; });
        const failed = () => rejectSpawn(new Error("persistent Grok job host failed to launch"));
        child.once?.("error", failed);
        try { await Promise.race([waitForHost(endpoint, requestSecret, startTimeoutMs), spawnFailure]); }
        finally { child.removeListener?.("error", failed); }
      })();
      startPromise = pending;
      void pending.finally(() => { if (startPromise === pending) startPromise = null; }).catch(() => {});
    }
    await startPromise;
  };
  const call = (operation) => async (args) => { await ensure(); return requestJobHost({ endpoint, operation, args, requestSecret }); };
  return Object.freeze({ submit: call("submit"), status: call("status"), collect: call("collect"), cancel: call("cancel") });
}
