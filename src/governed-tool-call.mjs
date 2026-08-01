import { createHash } from "node:crypto";
import { TrustGraduation, normalizeActionClass } from "@trust-graduation/core";

const ALLOWED_ACTION_CLASSES = new Set([
  "external.write",
  "github.issue.create",
  "github.issue.comment",
  "notification.send"
]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])])
    );
  }
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === null) {
    return value;
  }
  throw new TypeError("action values must be JSON-compatible");
}

export function normalizeRequestedAction({ actionClass, tool, target, input }) {
  const normalizedClass = normalizeActionClass(actionClass);
  if (!ALLOWED_ACTION_CLASSES.has(normalizedClass)) {
    throw new Error(`unknown action class: ${normalizedClass || "missing"}`);
  }
  if (typeof tool !== "string" || tool.trim() === "") throw new Error("tool is required");
  if (typeof target !== "string" || target.trim() === "") throw new Error("target is required");
  if (!isRecord(input)) throw new Error("input must be an object");
  return canonicalize({
    actionClass: normalizedClass,
    tool: tool.trim(),
    target: target.trim(),
    input
  });
}

export function actionFingerprint(action) {
  return createHash("sha256").update(JSON.stringify(canonicalize(action))).digest("hex");
}

function assertAuthorityContext(context) {
  for (const field of ["principal", "requestedBy", "scope"]) {
    if (typeof context?.[field] !== "string" || context[field].trim() === "") {
      throw new Error(`missing authority field: ${field}`);
    }
  }
}

/**
 * Host-owned lifecycle around one consequential provider call.
 * The provider is never reached during prepare, and every approval is bound
 * to the exact normalized action fingerprint and consumed before execution.
 */
export class GovernedToolCall {
  #provider;
  #trust;
  #pending = new Map();
  #receipts = [];

  constructor({ provider, workspace = "claude-builders-bounty", evidence = [] } = {}) {
    if (typeof provider !== "function") throw new TypeError("provider must be a function");
    this.#provider = provider;
    this.#trust = new TrustGraduation({ workspace, evidence });
  }

  prepare({ actionClass, tool, target, input, authority } = {}) {
    assertAuthorityContext(authority);
    const action = normalizeRequestedAction({ actionClass, tool, target, input });
    const fingerprint = actionFingerprint(action);
    const decision = this.#trust.canExecute({
      actionClass: action.actionClass,
      context: {
        ...authority,
        requestedAction: action,
        target: action.target
      }
    });
    if (!decision.needsApproval) throw new Error("provider action was not approval-gated");
    this.#pending.set(fingerprint, { action, authority, decision, approved: false, consumed: false });
    return { fingerprint, decision, packet: decision.packet };
  }

  approve(fingerprint) {
    const pending = this.#pending.get(fingerprint);
    if (!pending || pending.consumed) throw new Error("approval target is missing or already consumed");
    pending.approved = true;
    return { fingerprint, action: pending.action, decisionId: pending.decision.decisionId };
  }

  async execute(fingerprint, proposedAction = undefined) {
    const pending = this.#pending.get(fingerprint);
    if (!pending || pending.consumed) throw new Error("approval replay rejected");
    if (!pending.approved) throw new Error("explicit approval is required");
    if (proposedAction && actionFingerprint(proposedAction) !== fingerprint) {
      throw new Error("approved action fingerprint mismatch");
    }

    const decision = this.#trust.canExecute({
      actionClass: pending.action.actionClass,
      context: { ...pending.authority, requestedAction: pending.action, target: pending.action.target },
      approval: { state: "approved" }
    });
    if (!decision.allowed) throw new Error("approval did not authorize this action");
    pending.consumed = true;

    const startedAt = new Date().toISOString();
    try {
      const result = await this.#provider(pending.action);
      const receipt = this.#recordReceipt({ pending, decision, startedAt, ok: true, result });
      return { result, receipt };
    } catch (error) {
      const receipt = this.#recordReceipt({ pending, decision, startedAt, ok: false, error });
      error.receipt = receipt;
      throw error;
    }
  }

  receipts() {
    return this.#receipts.map((receipt) => ({ ...receipt }));
  }

  #recordReceipt({ pending, decision, startedAt, ok, result, error }) {
    const receipt = {
      protocol: "trust-graduation",
      type: "execution_receipt",
      receiptId: `tgr_${this.#receipts.length + 1}`,
      decisionId: decision.decisionId,
      actionClass: pending.action.actionClass,
      fingerprint: actionFingerprint(pending.action),
      tool: pending.action.tool,
      target: pending.action.target,
      startedAt,
      finishedAt: new Date().toISOString(),
      outcome: ok ? "success" : "failure",
      ...(ok ? { result: result ?? null } : { error: String(error?.message || error) })
    };
    this.#receipts.push(receipt);
    return receipt;
  }
}

