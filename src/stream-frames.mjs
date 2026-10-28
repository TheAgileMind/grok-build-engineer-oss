import { createHash } from "node:crypto";
import { containsCredentialValue, redactForBoundary } from "./redaction.mjs";

const PROVIDER_CODE = /^[a-z][a-z0-9_-]{0,63}$/;
const DEFAULT_PROVIDER_CODE = "provider_error";

function digestLine(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function tryParseFrame(line) {
  try {
    const frame = JSON.parse(line);
    if (!frame || typeof frame !== "object" || Array.isArray(frame)) return null;
    return frame;
  } catch {
    return null;
  }
}

function errorObject(frame) {
  return frame?.error && typeof frame.error === "object" && !Array.isArray(frame.error) ? frame.error : null;
}

/** Best-effort provider error text from a Grok streaming-json frame. */
export function errorMessageFromFrame(frame) {
  if (!frame || typeof frame !== "object" || Array.isArray(frame)) return null;
  if (typeof frame.message === "string" && frame.message.length > 0) return frame.message;
  const nested = errorObject(frame);
  if (typeof nested?.message === "string" && nested.message.length > 0) return nested.message;
  if (typeof frame.error === "string" && frame.error.length > 0) return frame.error;
  return null;
}

function safeDiagnosticToken(value) {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 2_147_483_647) return value;
  if (typeof value !== "string" || value.length === 0 || value.length > 64) return null;
  if (containsCredentialValue(value)) return null;
  const normalized = value.trim().toLowerCase();
  if (!PROVIDER_CODE.test(normalized)) return null;
  return normalized;
}

function candidateCodes(frame) {
  if (!frame || typeof frame !== "object" || Array.isArray(frame)) return [];
  const nested = errorObject(frame);
  return [frame.code, nested?.code];
}

/** Stable failCode-safe identifier for a provider error frame. */
export function providerErrorCode(frame) {
  for (const candidate of candidateCodes(frame)) {
    if (typeof candidate !== "string") continue;
    const normalized = candidate.trim().toLowerCase().replace(/[^a-z0-9_-]/g, "_").slice(0, 64);
    if (PROVIDER_CODE.test(normalized) && normalized !== "runner_failure") return normalized;
  }
  return DEFAULT_PROVIDER_CODE;
}

/**
 * Bounded, secret-safe view of one streaming-json line.
 * Shared by the headless adapter and the production one-shot runner.
 */
export function frameDiagnostics(line) {
  const text = typeof line === "string" ? line : "";
  const base = { protocolFrameBytes: Buffer.byteLength(text, "utf8"), protocolFrameDigest: digestLine(text) };
  const frame = tryParseFrame(text);
  if (!frame) {
    const protocolFrameType = text.length === 0 ? "invalid_json" : (() => {
      try { JSON.parse(text); return "invalid_shape"; } catch { return "invalid_json"; }
    })();
    return Object.freeze({ ...base, protocolFrameType, protocolFrameKeys: [] });
  }
  const keys = Object.keys(frame).filter((key) => typeof key === "string" && key.length <= 128).sort().slice(0, 64);
  const protocolFrameType = typeof frame.type === "string" && frame.type.length <= 128 ? frame.type : "invalid_type";
  const rawMessage = protocolFrameType === "error" || frame.error !== undefined ? errorMessageFromFrame(frame) : null;
  const protocolErrorMessage = typeof rawMessage === "string" ? redactForBoundary(rawMessage).slice(0, 1024) : null;
  const nested = errorObject(frame);
  const category = safeDiagnosticToken(frame.category ?? nested?.category ?? nested?.type);
  const status = safeDiagnosticToken(frame.status ?? nested?.status);
  return Object.freeze({
    ...base,
    protocolFrameType,
    protocolFrameKeys: keys,
    ...(protocolErrorMessage ? { protocolErrorMessage } : {}),
    ...(category !== null ? { category } : {}),
    ...(status !== null ? { status } : {})
  });
}

/** Throw-ready Error whose `code` is usable by failCode() and whose diagnostics are receipt-safe. */
export function providerErrorFromFrame(line, frame = null) {
  const parsed = frame && typeof frame === "object" && !Array.isArray(frame) ? frame : tryParseFrame(line);
  const diagnostics = frameDiagnostics(typeof line === "string" ? line : "");
  const code = providerErrorCode(parsed);
  const raw = errorMessageFromFrame(parsed) ?? code;
  const message = redactForBoundary(String(raw)).slice(0, 512);
  const error = new Error(message);
  error.code = code;
  error.frameDiagnostics = diagnostics;
  error.protocolFrameLine = typeof line === "string" ? line : "";
  return error;
}

/** Optional receipt fields derived from a thrown provider-frame error. */
export function receiptExtrasFromFrameError(error) {
  const diagnostics = error?.frameDiagnostics;
  if (!diagnostics || typeof diagnostics !== "object" || Array.isArray(diagnostics)) return {};
  const extras = {};
  if (typeof diagnostics.protocolFrameDigest === "string" && /^sha256:[a-f0-9]{64}$/.test(diagnostics.protocolFrameDigest)) {
    extras.frameDigest = diagnostics.protocolFrameDigest;
  }
  if (typeof diagnostics.category === "string" && PROVIDER_CODE.test(diagnostics.category)) extras.category = diagnostics.category;
  if (typeof diagnostics.status === "number" && Number.isSafeInteger(diagnostics.status) && diagnostics.status >= 0) extras.status = diagnostics.status;
  else if (typeof diagnostics.status === "string" && PROVIDER_CODE.test(diagnostics.status)) extras.status = diagnostics.status;
  return extras;
}
