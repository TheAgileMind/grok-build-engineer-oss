import { createHash } from "node:crypto";
import { validateApprovalPacket } from "./contracts.mjs";
import { containsSecretValue } from "./redaction.mjs";

const SECRET_KEY = /(?:^|_)(?:api_?key|access_?key|token|secret|credential|password|authorization|cookie|private_?key)(?:$|_)/i;
const SECRET_VALUE = /\$\{[^}]*?(?:api_?key|access_?key|token|secret|credential|password|authorization|cookie|private_?key)[^}]*\}|\b(?:bearer|basic)\s+[a-z0-9._~+\/-]+=*|\b(?:api[-_ ]?key|access[-_ ]?key|token|secret|credential|password|authorization|cookie|private[-_ ]?key)\s*(?:=|:)\s*\S+|:\/\/[^\s\/:]+:[^\s@\/]+@/i;
const SECRETISH_ID = /(?:api[_-]?key|access[_-]?key|token|secret|credential|password|authorization|cookie|private[_-]?key)/i;

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function digest(value) {
  // Use the same canonical JSON shape as the task-policy packet digest, while
  // keeping authority validation independent from the policy implementation.
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function secretishIdentifier(value) {
  return typeof value !== "string" || SECRETISH_ID.test(value);
}

export function secretFreeAuthorityRecord(value) {
  if (typeof value === "string") return !SECRET_VALUE.test(value) && !containsSecretValue(value);
  if (Array.isArray(value)) return value.every(secretFreeAuthorityRecord);
  if (value && typeof value === "object") {
    return Object.entries(value).every(([key, entry]) =>
      (key === "authorizationBasis" || !SECRET_KEY.test(key)) && secretFreeAuthorityRecord(entry));
  }
  return value === null || ["boolean", "number"].includes(typeof value);
}

export function approvalIsCurrent(approval, { now = new Date() } = {}) {
  if (!approval || typeof approval !== "object") return false;
  const issued = Date.parse(approval.issuedAt), expires = Date.parse(approval.expiresAt), current = now instanceof Date ? now.getTime() : Date.parse(now);
  return Number.isFinite(issued) && Number.isFinite(expires) && Number.isFinite(current) && issued <= current && current < expires;
}

/**
 * Return the stable, key-order-independent representation used for authority
 * comparisons. This is deliberately a canonical JSON representation, not a
 * cryptographic-human-signature claim; the trusted host remains the authority
 * that supplied and verified the approval file.
 */
export function canonicalAuthorityRecord(value) {
  if (value === null || typeof value !== "object") return canonical(value);
  return canonical(structuredClone(value));
}

/** Compute the approval binding over every packet field except its self-digest. */
export function canonicalTaskPacketDigest(packet) {
  if (!packet || typeof packet !== "object" || Array.isArray(packet)) throw new TypeError("task packet is required");
  const copy = structuredClone(packet);
  if (!copy.approval || typeof copy.approval !== "object" || Array.isArray(copy.approval)) throw new TypeError("task packet approval is required");
  copy.approval = { ...copy.approval, packetDigest: null };
  return digest(canonical(copy));
}

export function assertApprovedPacket({ packet, approval, digest: suppliedDigest, now = new Date() }) {
  if (!secretFreeAuthorityRecord(packet) || !secretFreeAuthorityRecord(approval)) throw new TypeError("approval packet contains secret-shaped data");
  validateApprovalPacket(approval);
  validateApprovalPacket(packet?.approval);
  if (!approvalIsCurrent(approval, { now })) throw new TypeError("approval packet is missing or expired");
  if (!packet?.approval || canonicalAuthorityRecord(approval) !== canonicalAuthorityRecord(packet.approval)) throw new TypeError("complete approval object does not match the task packet");
  const expectedDigest = canonicalTaskPacketDigest(packet);
  if (typeof suppliedDigest !== "string" || suppliedDigest !== expectedDigest || approval.packetDigest !== expectedDigest) throw new TypeError("approval packet digest does not match canonical task scope");
  return true;
}
