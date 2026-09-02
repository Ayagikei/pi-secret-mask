import assert from "node:assert/strict";
import test from "node:test";
import {
  assertShellSafeHandles,
  containsSecretHandle,
  planToolSecretResolution,
  SecretResolutionError,
} from "../src/tool-secret-resolver.ts";

function lookup(entries = { __SECRET_TOKEN__: "real-token", __SECRET_PASSWORD__: "p@ss\\\"word" }) {
  return {
    placeholders: () => Object.keys(entries),
    secretFor: (handle) => entries[handle],
  };
}

test("write.content resolves an explicit known handle", () => {
  const input = { path: ".env", content: "TOKEN=__SECRET_TOKEN__" };
  const plan = planToolSecretResolution("write", input, lookup());
  assert.ok(plan);
  assert.equal(input.content, "TOKEN=__SECRET_TOKEN__");
  plan.apply();
  assert.equal(input.content, "TOKEN=real-token");
});

test("a handle in an unapproved path is blocked", () => {
  const input = { path: "__SECRET_TOKEN__", content: "safe" };
  assert.throws(
    () => planToolSecretResolution("write", input, lookup()),
    (error) => error instanceof SecretResolutionError && error.code === "UNAUTHORIZED_PATH",
  );
});

test("an invented handle fails closed", () => {
  assert.throws(
    () => planToolSecretResolution("write", { content: "__SECRET_MADE_UP__" }, lookup()),
    (error) => error instanceof SecretResolutionError && error.code === "UNKNOWN_HANDLE",
  );
});

test("custom browser rule resolves only the configured value field", () => {
  const input = { selector: "#password", value: "__SECRET_TOKEN__" };
  const plan = planToolSecretResolution("browser_fill", input, lookup(), {
    rules: [{ tool: "browser_fill", paths: ["value"] }],
  });
  assert.ok(plan);
  plan.apply();
  assert.equal(input.value, "real-token");
  assert.equal(input.selector, "#password");
});

test("tool-name globs work", () => {
  const input = { password: "__SECRET_TOKEN__" };
  const plan = planToolSecretResolution("mcp__cloudflare__login", input, lookup(), {
    includeDefaults: false,
    rules: [{ tool: "mcp__*__login", paths: ["password"] }],
  });
  assert.ok(plan);
  plan.apply();
  assert.equal(input.password, "real-token");
});

test("array wildcard paths work", () => {
  const input = { fields: [{ name: "user", value: "plain" }, { name: "password", value: "__SECRET_TOKEN__" }] };
  const plan = planToolSecretResolution("browser_fill_form", input, lookup(), {
    includeDefaults: false,
    rules: [{ tool: "browser_fill_form", paths: ["fields.*.value"] }],
  });
  assert.ok(plan);
  plan.apply();
  assert.equal(input.fields[1].value, "real-token");
});

test("recursive ** paths work", () => {
  const input = { body: { credentials: { nested: { token: "__SECRET_TOKEN__" } } } };
  const plan = planToolSecretResolution("trusted_http", input, lookup(), {
    includeDefaults: false,
    rules: [{ tool: "trusted_http", paths: ["body.credentials.**"] }],
  });
  assert.ok(plan);
  plan.apply();
  assert.equal(input.body.credentials.nested.token, "real-token");
});

test("pi-mcp-adapter object args resolve while metadata stays untouched", () => {
  const input = {
    server: "cloudflare",
    tool: "login",
    args: { username: "demian", password: "__SECRET_TOKEN__" },
  };
  const plan = planToolSecretResolution("mcp", input, lookup());
  assert.ok(plan);
  plan.apply();
  assert.equal(input.args.password, "real-token");
  assert.equal(input.server, "cloudflare");
  assert.equal(input.tool, "login");
});

test("pi-mcp-adapter JSON-string args are parsed and reserialized", () => {
  const input = { server: "cloudflare", tool: "login", args: '{"password":"__SECRET_TOKEN__"}' };
  const plan = planToolSecretResolution("mcp", input, lookup());
  assert.ok(plan);
  plan.apply();
  assert.deepEqual(JSON.parse(input.args), { password: "real-token" });
});

test("JSON adapter safely escapes quotes and backslashes in a secret", () => {
  const input = { server: "x", tool: "login", args: '{"password":"__SECRET_PASSWORD__"}' };
  const plan = planToolSecretResolution("mcp", input, lookup());
  assert.ok(plan);
  plan.apply();
  assert.equal(JSON.parse(input.args).password, 'p@ss\\"word');
});

test("invalid JSON containing a handle is blocked", () => {
  const input = { server: "x", tool: "login", args: '{password:"__SECRET_TOKEN__"}' };
  assert.throws(
    () => planToolSecretResolution("mcp", input, lookup()),
    (error) => error instanceof SecretResolutionError && error.code === "INVALID_JSON",
  );
});

test("MCP server metadata cannot carry a secret", () => {
  const input = { server: "__SECRET_TOKEN__", tool: "login", args: {} };
  assert.throws(
    () => planToolSecretResolution("mcp", input, lookup()),
    (error) => error instanceof SecretResolutionError && error.code === "UNAUTHORIZED_PATH",
  );
});

test("handles in object keys are blocked", () => {
  const input = { content: { __SECRET_TOKEN__: "value" } };
  assert.throws(
    () => planToolSecretResolution("write", input, lookup()),
    (error) => error instanceof SecretResolutionError && error.code === "UNAUTHORIZED_PATH",
  );
});

test("shell-safe values may be resolved", () => {
  const input = { command: 'curl -H "Authorization: Bearer __SECRET_TOKEN__" https://example.test' };
  const plan = planToolSecretResolution("bash", input, lookup());
  assert.ok(plan);
  assert.doesNotThrow(() => assertShellSafeHandles(plan, lookup()));
  plan.apply();
  assert.match(input.command, /real-token/);
});

test("shell metacharacters fail closed because quote context is unknown", () => {
  const input = { command: "login --password __SECRET_PASSWORD__" };
  const plan = planToolSecretResolution("bash", input, lookup());
  assert.ok(plan);
  assert.throws(
    () => assertShellSafeHandles(plan, lookup()),
    (error) => error instanceof SecretResolutionError,
  );
});

test("a call without a handle produces no plan", () => {
  assert.equal(planToolSecretResolution("write", { content: "plain" }, lookup()), null);
  assert.equal(containsSecretHandle({ content: "plain" }), false);
  assert.equal(containsSecretHandle({ content: "__SECRET_TOKEN__" }), true);
});

test("JSON-string adapter rejects handle-bearing keys before resolution", () => {
  const input = { args: '{"__" "SECRET_TOKEN__":"value"}' };
  // Build valid JSON without placing a handle literal in this test source.
  input.args = JSON.stringify({ ["__" + "SECRET_TOKEN__"]: "value" });
  assert.throws(
    () => planToolSecretResolution("mcp", input, lookup()),
    (error) => error instanceof SecretResolutionError && error.code === "UNAUTHORIZED_PATH",
  );
});

test("current edit.edits paths resolve without mutating before apply", () => {
  const input = { edits: [{ oldText: "__" + "SECRET_TOKEN__", newText: "value=__" + "SECRET_TOKEN__" }] };
  const plan = planToolSecretResolution("edit", input, lookup());
  assert.ok(plan);
  assert.notEqual(input.edits[0].oldText, "real-token");
  plan.apply();
  assert.equal(input.edits[0].oldText, "real-token");
  assert.equal(input.edits[0].newText, "value=real-token");
});

test("unknownHandle ignore cannot weaken fail-closed resolution", () => {
  assert.throws(
    () => planToolSecretResolution("write", { content: "__" + "SECRET_INVENTED__" }, lookup(), { unknownHandle: "ignore" }),
    (error) => error instanceof SecretResolutionError && error.code === "UNKNOWN_HANDLE",
  );
});

test("JSON adapter preserves an own __proto__ key without changing the clone prototype", () => {
  const args = JSON.parse('{"__proto__":{"x":1},"password":"placeholder"}');
  args.password = "__" + "SECRET_TOKEN__";
  const input = { args };
  const plan = planToolSecretResolution("mcp", input, lookup());
  assert.ok(plan);
  plan.apply();
  assert.equal(Object.getPrototypeOf(input.args), Object.prototype);
  assert.equal(Object.hasOwn(input.args, "__proto__"), true);
  assert.deepEqual(input.args.__proto__, { x: 1 });
  assert.equal(input.args.password, "real-token");
});

test("text resolution safely replaces an own __proto__ argument", () => {
  const input = JSON.parse('{"__proto__":"placeholder"}');
  input.__proto__ = "__" + "SECRET_TOKEN__";
  const plan = planToolSecretResolution("custom", input, lookup(), {
    includeDefaults: false,
    rules: [{ tool: "custom", paths: ["__proto__"] }],
  });
  assert.ok(plan);
  plan.apply();
  assert.equal(Object.getPrototypeOf(input), Object.prototype);
  assert.equal(Object.hasOwn(input, "__proto__"), true);
  assert.equal(input.__proto__, "real-token");
});
