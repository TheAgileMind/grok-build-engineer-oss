import * as acp from "@agentclientprotocol/sdk";

/** In-process provider-free ACP peer used by U5 tests. */
export function fakeAcpAgent({ sessionId = "fake-session", candidateDigest = `sha256:${"a".repeat(64)}`, stopReason = "end_turn", permission = false, waitForCancel = false, promptGate = null, stallInitialize = false, chunks = null, usage = undefined, updates = [], notifications = [], cancelAcknowledges = true, authMethods = null, loadSession = true, afterPrompt = null } = {}) {
  const calls = [];
  let releaseCancel; const cancelled = new Promise((resolve) => { releaseCancel = resolve; });
  const app = acp.agent({ name: "fake-grok" })
    .onRequest(acp.methods.agent.initialize, async (ctx) => { calls.push("initialize"); if (stallInitialize) await new Promise(() => {}); return { protocolVersion: ctx.params.protocolVersion, agentCapabilities: { loadSession }, ...(authMethods === null ? {} : { authMethods }) }; })
    .onRequest(acp.methods.agent.authenticate, async (ctx) => { calls.push(`authenticate:${ctx.params.methodId}:${ctx.params._meta?.headless === true}`); return {}; })
    .onRequest(acp.methods.agent.session.new, async () => { calls.push("new"); return { sessionId }; })
    .onRequest(acp.methods.agent.session.load, async (ctx) => { calls.push(`load:${ctx.params.sessionId}`); return {}; })
    .onRequest(acp.methods.agent.session.load, async (ctx) => { calls.push(`load:${ctx.params.sessionId}`); return {}; })
    .onRequest(acp.methods.agent.session.prompt, async (ctx) => {
      calls.push(`prompt:${ctx.params.sessionId}`);
      if (permission) {
        const permissionResult = await ctx.client.request(acp.methods.client.session.requestPermission, { sessionId: ctx.params.sessionId, toolCall: { toolCallId: "permission", title: "forged", kind: "execute", status: "pending", rawInput: {} }, options: [{ optionId: "allow", name: "allow", kind: "allow_once" }] });
        if (permissionResult.outcome.outcome !== "selected") return { stopReason: "cancelled" };
      }
      if (waitForCancel) { await cancelled; return { stopReason: "cancelled" }; }
      if (promptGate) await promptGate;
      for (const notification of notifications) await ctx.client.notify(acp.methods.client.session.update, { sessionId: notification.sessionId ?? ctx.params.sessionId, update: notification.update });
      for (const update of updates) await ctx.client.notify(acp.methods.client.session.update, { sessionId: ctx.params.sessionId, update });
      for (const text of chunks ?? ["Implementation complete.\nTests passed.\n"]) await ctx.client.notify(acp.methods.client.session.update, { sessionId: ctx.params.sessionId, update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text } } });
      if (afterPrompt) afterPrompt(); return { stopReason, ...(usage === undefined ? {} : { usage }) };
    })
    .onNotification(acp.methods.agent.session.cancel, async () => { calls.push("cancel"); if (cancelAcknowledges) releaseCancel(); });
  return { agent: app, calls, stop() {} };
}
