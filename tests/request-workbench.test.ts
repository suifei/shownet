import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  captureRuleActionFromDraft, captureRuleDraftFromRule, captureRuleDraftValidationError, changeRuleDraftOperationTarget, changeRuleDraftStage,
  createEmptyRuleDraft, isCaptureRuleDraftValid, prefillMirrorDraftFromRequest,
} from "../src/captureRuleDraft.ts";
import { compareRequestRecords, draftToCurl, parseCurl, redactSecrets, resolveTemplate, sanitizeReplayHeaders } from "../src/requestWorkbench.ts";
import { generateRequestCode } from "../src/requestCode.ts";
import type { CaptureRule, RequestRecord } from "../src/types.ts";

const variables = {
  active: [{ name: "host", value: "active.example", secret: false, source: "active" as const }],
  global: [
    { name: "host", value: "global.example", secret: false, source: "global" as const },
    { name: "token", value: "top-secret", secret: true, source: "global" as const },
  ],
};

function record(overrides: Partial<RequestRecord> = {}): RequestRecord {
  return {
    id: "request-a", order: 1, time: "12:00", method: "POST", host: "api.example.com", path: "/v1/items", status: 200,
    type: "fetch", size: "1 KB", duration: 20, source: "browser", protocol: "h2", tls: "TLS 1.3", risk: "none",
    requestHeaders: [{ name: "Content-Type", value: "application/json" }], responseHeaders: [], requestBody: '{"id":1}',
    responseBody: '{"ok":true}', cryptoSnippetCount: 0, ...overrides,
  };
}

describe("request workbench", () => {
  it("resolves variables by active, global, builtin priority and masks secrets", () => {
    const resolved = resolveTemplate("https://{{host}}/items?token={{token}}&missing={{none}}", variables.active, variables.global);
    assert.equal(resolved.value, "https://active.example/items?token=top-secret&missing={{none}}");
    assert.equal(resolved.maskedValue, "https://active.example/items?token=••••••••&missing={{none}}");
    assert.deepEqual(resolved.unresolved, ["none"]);
    assert.equal(redactSecrets("Bearer top-secret", variables.global), "Bearer ••••••••");
  });

  it("removes hop-by-hop headers, honors credential switches and recalculates content length", () => {
    const headers = sanitizeReplayHeaders([
      { name: "Connection", value: "keep-alive, X-Internal" },
      { name: "X-Internal", value: "remove" },
      { name: "Cookie", value: "sid=secret" },
      { name: "Authorization", value: "Bearer secret" },
      { name: "Content-Length", value: "999" },
      { name: "Accept", value: "application/json" },
    ], { includeCookie: false, includeAuthorization: false, bodyByteLength: 4 });
    assert.deepEqual(headers, [{ name: "Accept", value: "application/json" }, { name: "Content-Length", value: "4" }]);
  });

  it("imports and exports complete cURL values", () => {
    const parsed = parseCurl("curl -X POST 'https://api.example.com/v1' -H 'Authorization: Bearer abc' -H 'X-Test: yes' --data-raw '{\"ok\":true}'");
    assert.equal(parsed.method, "POST");
    assert.equal(parsed.headers.length, 2);
    const exported = draftToCurl(parsed);
    assert.match(exported, /Bearer abc/);
    assert.match(exported, /X-Test: yes/);
  });

  it("generates Python, Java and other code without removing runtime credentials", () => {
    const input = {
      method: "POST",
      url: "https://api.example.com/v1/items?key=secret-key",
      headers: [
        { name: "Authorization", value: "Bearer secret-token" },
        { name: "Cookie", value: "sid=secret-cookie" },
        { name: "X-Trace", value: "trace-value" },
      ],
      body: '{"token":"body-secret"}',
    };
    for (const template of ["curl", "httpie", "python", "java", "fetch", "axios", "go"] as const) {
      const code = generateRequestCode(input, template);
      assert.match(code, /secret-token/, `missing authorization in ${template}`);
      assert.match(code, /secret-cookie/, `missing cookie in ${template}`);
      assert.match(code, /body-secret/, `missing body in ${template}`);
    }
    assert.match(generateRequestCode(input, "java"), /HttpClient/);
    assert.match(generateRequestCode(input, "python"), /import requests/);
  });

  it("creates key-aware JSON, header and transport differences with ignore paths", () => {
    const differences = compareRequestRecords(
      record(),
      record({ id: "request-b", status: 401, duration: 35, requestBody: '{"id":2,"nonce":"dynamic"}', requestHeaders: [{ name: "content-type", value: "application/json" }, { name: "X-Request-Id", value: "b" }] }),
      ["body.nonce", "headers.x-request-id"],
    );
    assert.ok(differences.some((entry) => entry.path === "body.id"));
    assert.ok(differences.some((entry) => entry.path === "status"));
    assert.ok(differences.some((entry) => entry.path === "durationMs"));
    assert.ok(!differences.some((entry) => entry.path.includes("nonce") || entry.path.includes("x-request-id")));
  });

  it("preserves repeated query values when comparing requests", () => {
    const differences = compareRequestRecords(
      record({ query: "tag=one&tag=two&stable=yes" }),
      record({ id: "request-b", query: "tag=one&tag=three&stable=yes" }),
    );
    const query = differences.find((entry) => entry.path === "query.tag");
    assert.equal(query?.before, '["one","two"]');
    assert.equal(query?.after, '["one","three"]');
    assert.ok(!differences.some((entry) => entry.path === "query.stable"));
  });

  it("round trips response rewrites with status, headers and body operations", () => {
    const rule: CaptureRule = {
      id: "rule-response", name: "调整测试响应", enabled: false, priority: 80, stage: "response",
      matcher: { kind: "predicate", field: "status", operator: "gte", value: 400 },
      action: { kind: "rewrite", operations: [
        { target: "response.status", op: "set", value: 200 },
        { target: "response.header", op: "set", name: "X-Debug", value: "yes" },
        { target: "response.body", op: "replace", pattern: "secret-[0-9]+", value: "masked" },
      ] },
      createdBy: "user", revision: 3, hitCount: 2, createdAt: 1, updatedAt: 2,
    };
    const draft = captureRuleDraftFromRule(rule);
    assert.ok(draft);
    assert.equal(draft.stage, "response");
    assert.equal(draft.operations.length, 3);
    assert.equal(captureRuleDraftValidationError(draft), undefined);
    assert.deepEqual(captureRuleActionFromDraft(draft), rule.action);
  });

  it("round trips request body rewrites and prefills safe selected text", () => {
    const base = createEmptyRuleDraft();
    const prefilled = changeRuleDraftOperationTarget(base, base.operations[0].id, "request.body", {
      host: "api.example.com",
      requestBody: '{"token":"before"}',
    });
    assert.equal(prefilled.name, "api.example.com 请求正文改写");
    assert.equal(prefilled.matchValue, "api.example.com");
    assert.equal(prefilled.operations[0].value, '{"token":"before"}');
    prefilled.operations[0].operation = "replace";
    prefilled.operations[0].pattern = "before";
    prefilled.operations[0].value = "after";
    assert.equal(captureRuleDraftValidationError(prefilled), undefined);

    const action = captureRuleActionFromDraft(prefilled);
    assert.deepEqual(action, { kind: "rewrite", operations: [
      { target: "request.body", op: "replace", pattern: "before", value: "after" },
    ] });
    const restored = captureRuleDraftFromRule({
      id: "request-body-rule", name: prefilled.name, enabled: false, priority: prefilled.priority, stage: "request",
      matcher: { kind: "predicate", field: "host", operator: "contains", value: "api.example.com" },
      action, createdBy: "user", revision: 1, hitCount: 0, createdAt: 1, updatedAt: 1,
    });
    assert.equal(restored?.operations[0].target, "request.body");
    assert.deepEqual(restored && captureRuleActionFromDraft(restored), action);

    const binary = changeRuleDraftOperationTarget(base, base.operations[0].id, "request.body", {
      host: "api.example.com",
      requestBody: "base64:AAEC",
    });
    assert.equal(binary.operations[0].value, "");
  });

  it("round trips safe Map Remote settings and preserves URL values", () => {
    const rule: CaptureRule = {
      id: "rule-map-remote", name: "转发到测试环境", enabled: false, priority: 15, stage: "request",
      matcher: { kind: "predicate", field: "host", operator: "equals", value: "api.example.com" },
      action: {
        kind: "redirect",
        targetTemplate: "https://stage.example.com/api/*?api_token=private-target&view=full",
        excludePattern: "https://api.example.com/health*?auth=private-exclude&keep=yes",
        preserveHost: true,
        preserveCredentials: true,
        allowInsecureDowngrade: true,
      },
      createdBy: "user", revision: 2, hitCount: 0, createdAt: 1, updatedAt: 2,
    };
    const draft = captureRuleDraftFromRule(rule);
    assert.ok(draft);
    assert.equal(captureRuleDraftValidationError(draft), undefined);
    assert.equal(draft.redirectExcludePattern, rule.action.excludePattern);
    assert.equal(draft.redirectPreserveHost, true);
    assert.equal(draft.redirectPreserveCredentials, true);
    assert.equal(draft.redirectAllowInsecureDowngrade, true);
    assert.deepEqual(captureRuleActionFromDraft(draft), rule.action);

    for (const targetTemplate of [
      "ftp://stage.example.com/file",
      "https://user:pass@stage.example.com/",
      "https://stage.example.com/#fragment",
      "https:\\stage.example.com\\api",
    ]) {
      assert.match(captureRuleDraftValidationError({ ...draft, targetTemplate }) ?? "", /HTTP\(S\)|凭据|片段/);
    }

    assert.equal(rule.action.targetTemplate, "https://stage.example.com/api/*?api_token=private-target&view=full");
  });

  it("round trips weak network settings and rejects ineffective or invalid limits", () => {
    const rule: CaptureRule = {
      id: "rule-network", name: "移动弱网", enabled: false, priority: 90, stage: "request",
      matcher: { kind: "predicate", field: "host", operator: "contains", value: "api.example.com" },
      action: { kind: "throttle", latencyMs: 180, jitterMs: 70, uploadKbps: 64, downloadKbps: 128, packetLossPercent: 2.5 },
      createdBy: "user", revision: 1, hitCount: 0, createdAt: 1, updatedAt: 1,
    };
    const draft = captureRuleDraftFromRule(rule);
    assert.ok(draft);
    assert.equal(captureRuleDraftValidationError(draft), undefined);
    assert.deepEqual(captureRuleActionFromDraft(draft), rule.action);

    const ineffective = { ...draft, latencyMs: 0, jitterMs: 0, uploadKbps: 0, downloadKbps: 0, packetLossPercent: 0 };
    assert.match(captureRuleDraftValidationError(ineffective) ?? "", /至少需要一项/);
    assert.match(captureRuleDraftValidationError({ ...draft, uploadKbps: 7 }) ?? "", /必须为 0 或 8/);
  });

  it("round trips request and response breakpoints with bounded timeout policies", () => {
    const rule: CaptureRule = {
      id: "rule-breakpoint", name: "登录人工断点", enabled: false, priority: 20, stage: "response",
      matcher: { kind: "predicate", field: "status", operator: "gte", value: 400 },
      action: { kind: "breakpoint", timeoutMs: 45_000, onTimeout: "abort" },
      createdBy: "user", revision: 1, hitCount: 0, createdAt: 1, updatedAt: 1,
    };
    const draft = captureRuleDraftFromRule(rule);
    assert.ok(draft);
    assert.equal(draft.actionKind, "breakpoint");
    assert.equal(draft.breakpointTimeoutSeconds, 45);
    assert.equal(captureRuleDraftValidationError(draft), undefined);
    assert.deepEqual(captureRuleActionFromDraft(draft), rule.action);
    assert.match(captureRuleDraftValidationError({ ...draft, breakpointTimeoutSeconds: 4 }) ?? "", /5 到 300 秒/);

    const normalized = captureRuleDraftFromRule({
      ...rule,
      action: { kind: "breakpoint", timeoutMs: 45_600, onTimeout: "continue" },
    });
    assert.equal(normalized?.breakpointTimeoutSeconds, 46);
    const clamped = captureRuleDraftFromRule({
      ...rule,
      action: { kind: "breakpoint", timeoutMs: 600, onTimeout: "continue" },
    });
    assert.equal(clamped?.breakpointTimeoutSeconds, 5);

    const requestDraft = changeRuleDraftStage(draft, "request");
    assert.equal(requestDraft.actionKind, "breakpoint");
  });

  it("round trips mirror presets and keeps connection rules narrowly scoped", () => {
    const rule: CaptureRule = {
      id: "rule-mirror", name: "生产域名转测试环境", enabled: false, priority: 10, stage: "connection",
      matcher: { kind: "predicate", field: "host", operator: "wildcard", value: "*.example.com" },
      action: { kind: "mirror", targetHost: "staging.example.test", targetPort: 8443, identity: "target" },
      createdBy: "user", revision: 2, hitCount: 0, createdAt: 1, updatedAt: 1,
    };
    const draft = captureRuleDraftFromRule(rule);
    assert.ok(draft);
    assert.equal(draft.stage, "connection");
    assert.equal(draft.actionKind, "mirror");
    assert.equal(draft.mirrorIdentity, "target");
    assert.equal(captureRuleDraftValidationError(draft), undefined);
    assert.deepEqual(captureRuleActionFromDraft(draft), rule.action);
    assert.match(captureRuleDraftValidationError({ ...draft, mirrorTargetHost: "https://staging.example.test" }) ?? "", /只填写有效主机/);
    assert.match(captureRuleDraftValidationError({ ...draft, mirrorTargetPort: "65536" }) ?? "", /1 到 65535/);

    const connectionDraft = changeRuleDraftStage(createEmptyRuleDraft(), "connection");
    assert.equal(connectionDraft.field, "host");
    assert.equal(connectionDraft.operator, "wildcard");
    assert.equal(connectionDraft.actionKind, "mirror");
    assert.equal(changeRuleDraftStage(connectionDraft, "request").actionKind, "rewrite");

    const contextual = prefillMirrorDraftFromRequest(connectionDraft, { host: "api.example.com" });
    assert.equal(contextual.name, "api.example.com 镜像");
    assert.equal(contextual.matchValue, "api.example.com");
    const customized = prefillMirrorDraftFromRequest({ ...connectionDraft, name: "自定义规则", matchValue: "*.example.com" }, { host: "api.example.com" });
    assert.equal(customized.name, "自定义规则");
    assert.equal(customized.matchValue, "*.example.com");
    assert.ok([...prefillMirrorDraftFromRequest(connectionDraft, { host: "a".repeat(253) }).name].length <= 120);
  });

  it("resets response-only matcher state when returning to the request stage", () => {
    const responseDraft = { ...createEmptyRuleDraft(), stage: "response" as const, field: "status", operator: "gte", matchValue: "400" };
    const requestDraft = changeRuleDraftStage(responseDraft, "request");
    assert.equal(requestDraft.field, "host");
    assert.equal(requestDraft.operator, "equals");
    assert.equal(requestDraft.operations[0]?.target, "request.header");
  });

  it("matches backend safety limits", () => {
    const draft = createEmptyRuleDraft();
    draft.name = "受控请求头";
    draft.matchValue = "api.example.com";
    assert.equal(isCaptureRuleDraftValid(draft), true);
    draft.operations[0].name = "Content-Length";
    assert.match(captureRuleDraftValidationError(draft) ?? "", /代理自动维护/);

    const regexDraft = createEmptyRuleDraft();
    regexDraft.name = "多字节正文正则";
    regexDraft.matchValue = "api.example.com";
    regexDraft.operations[0] = { ...regexDraft.operations[0], target: "request.body", operation: "replace", pattern: "中".repeat(86), value: "masked" };
    assert.match(captureRuleDraftValidationError(regexDraft) ?? "", /256 字节/);

  });
});
