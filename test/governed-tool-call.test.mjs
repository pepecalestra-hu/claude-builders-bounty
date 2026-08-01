import assert from "node:assert/strict";
import test from "node:test";
import { GovernedToolCall } from "../src/governed-tool-call.mjs";

const authority = { principal: "repo-owner", requestedBy: "agent", scope: "sandbox" };
const request = {
  actionClass: "external.write",
  tool: "sandbox-ticket",
  target: "ticket:42",
  input: { title: "bounded write", labels: ["bounty"] }
};

test("provider does not run before explicit approval", async () => {
  let calls = 0;
  const gate = new GovernedToolCall({ provider: async () => { calls += 1; } });
  const prepared = gate.prepare({ ...request, authority });
  assert.equal(calls, 0);
  assert.equal(prepared.decision.needsApproval, true);
  assert.equal(prepared.packet.requestedAction.target, "ticket:42");
});

test("the exact approved action runs once and emits a correlated receipt", async () => {
  const calls = [];
  const gate = new GovernedToolCall({ provider: async (action) => { calls.push(action); return { id: "sandbox-1" }; } });
  const prepared = gate.prepare({ ...request, authority });
  gate.approve(prepared.fingerprint);
  const execution = await gate.execute(prepared.fingerprint, prepared.packet.requestedAction);
  assert.equal(calls.length, 1);
  assert.equal(execution.receipt.fingerprint, prepared.fingerprint);
  assert.equal(execution.receipt.outcome, "success");
});

test("changed input is rejected without a provider call", async () => {
  let calls = 0;
  const gate = new GovernedToolCall({ provider: async () => { calls += 1; } });
  const prepared = gate.prepare({ ...request, authority });
  gate.approve(prepared.fingerprint);
  await assert.rejects(() => gate.execute(prepared.fingerprint, { ...prepared.packet.requestedAction, input: { title: "changed" } }), /fingerprint mismatch/);
  assert.equal(calls, 0);
});

test("replay is rejected without a second provider call", async () => {
  let calls = 0;
  const gate = new GovernedToolCall({ provider: async () => { calls += 1; } });
  const prepared = gate.prepare({ ...request, authority });
  gate.approve(prepared.fingerprint);
  await gate.execute(prepared.fingerprint);
  await assert.rejects(() => gate.execute(prepared.fingerprint), /replay rejected/);
  assert.equal(calls, 1);
});

test("missing and unknown authority fields fail closed", () => {
  const gate = new GovernedToolCall({ provider: async () => undefined });
  assert.throws(() => gate.prepare({ ...request, authority: { principal: "repo-owner", scope: "sandbox" } }), /requestedBy/);
  assert.throws(() => gate.prepare({ ...request, actionClass: "unknown.authority", authority }), /unknown action class/);
});

