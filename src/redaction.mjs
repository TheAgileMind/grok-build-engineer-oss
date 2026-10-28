const SECRET_KEY = /(?:access|refresh)?(?:token|secret)|password|passwd|authorization|credential|api[-_]?key|private[-_]?key|session[-_]?key|cookie/i;
const CREDENTIAL_URL = /(?:https?|git|ssh):\/\/[^\s/@:]+:[^\s/@]+@[^\s/]+[^\s]*/gi;
const BEARER_OR_BASIC = /\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{8,}\b/gi;
const OAUTH_TOKEN = /\b(?:oauth\s+)?(?:access|refresh)[_-]?token\s*(?:=|:)\s*[^\s,;]+/gi;
// These formats include an issuer or a multi-part cryptographic structure.
// Deliberately avoid generic long-hex matching so digests remain auditable.
// Keep one canonical, non-global source for provider/JWT detection. Redaction
// uses global instances so every occurrence is replaced; authority filtering
// uses the non-global detector so repeated `.test` calls remain stable.
const JWT_FORMAT = /\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b/;
const PROVIDER_TOKEN_FORMAT = /\b(?:sk-(?:proj-)?|gh[pousr]_)[A-Za-z0-9_-]{16,}|\bgithub_pat_[A-Za-z0-9_]{22,}|\bxox[baprs]-[A-Za-z0-9-]{10,}|\bAIza[A-Za-z0-9_-]{20,}|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/;
const JWT = new RegExp(JWT_FORMAT.source, "g");
const PROVIDER_TOKEN = new RegExp(PROVIDER_TOKEN_FORMAT.source, "g");
const SECRET_VALUE_FORMAT = new RegExp(`${JWT_FORMAT.source}|${PROVIDER_TOKEN_FORMAT.source}`);
const CREDENTIAL_URL_FORMAT = /(?:https?|git|ssh):\/\/[^\s\/@:]+:[^\s\/@]+@[^\s\/]+[^\s]*/i;
const BEARER_OR_BASIC_FORMAT = /\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{8,}\b/i;
const LABELED_SECRET = /\b((?:api[-_ ]?key|token|secret|password|passwd|session[-_ ]?key)\s*(?:=|:)\s*)[^\s,;]+/gi;
const REDACTED = "[REDACTED]";

/** Return whether a string contains a provider credential or JWT shape. */
export function containsSecretValue(value) {
  return typeof value === "string" && SECRET_VALUE_FORMAT.test(value);
}

/** Return whether a string contains an actual credential-shaped value. */
export function containsCredentialValue(value) {
  return typeof value === "string" && (
    containsSecretValue(value) || CREDENTIAL_URL_FORMAT.test(value) || BEARER_OR_BASIC_FORMAT.test(value)
  );
}

function exceptionLike(value) {
  return value instanceof Error || (value !== null && typeof value === "object" && !Array.isArray(value)
    && typeof value.stack === "string" && typeof value.message === "string");
}

function redactString(value) {
  return value.replace(CREDENTIAL_URL, "[REDACTED_CREDENTIAL_URL]")
    .replace(BEARER_OR_BASIC, REDACTED).replace(OAUTH_TOKEN, REDACTED)
    .replace(JWT, REDACTED).replace(PROVIDER_TOKEN, REDACTED)
    .replace(LABELED_SECRET, `$1${REDACTED}`);
}

function redact(value, seen) {
  if (typeof value === "string") return redactString(value);
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (value === undefined) return null;
  if (typeof value !== "object" || exceptionLike(value)) return "[REDACTED_EXCEPTION]";
  if (seen.has(value)) return "[REDACTED_CYCLE]";
  seen.add(value);
  if (Array.isArray(value)) {
    if (value.every((entry) => typeof entry === "string")) {
      const joined = value.join("");
      if (redactString(joined) !== joined) return [REDACTED];
    }
    return value.map((entry) => redact(entry, seen));
  }
  const result = {};
  for (const [key, entry] of Object.entries(value)) if (!SECRET_KEY.test(key)) result[key] = redact(entry, seen);
  return result;
}

export function redactForBoundary(value) {
  return redact(value, new WeakSet());
}

export function redactAndSerialize(value) {
  return JSON.stringify(redactForBoundary(value));
}
