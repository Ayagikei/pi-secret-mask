import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";

const home = mkdtempSync(join(tmpdir(), "pi-secret-session-"));
process.env.HOME = home;
after(() => rmSync(home, { recursive: true, force: true }));
const dir = join(home, ".pi/agent/extensions/pi-secret-mask");
mkdirSync(dir, { recursive: true });
const { default: registerExtension } = await import("../extensions/pi-secret-mask.ts");
const A = "__SECRET_APP_TOKEN__";
const B = "__SECRET_OTHER_TOKEN__";
const ONCE = "Allow once";
const SESSION = "Allow for this session";

function fixture(config = {}) {
  writeFileSync(join(dir, "config.json"), JSON.stringify({ mode: "ask", dotenv: { enabled: false }, ...config }));
  writeFileSync(join(dir, "secrets.json"), JSON.stringify([
    { name: "APP_TOKEN", value: "app-secret-123456" },
    { name: "OTHER_TOKEN", value: "other-secret-654321" },
    { name: "UNSAFE", value: "pass word;$()" },
  ]));
  const pi = { handlers: new Map(), tools: new Map(), commands: new Map(),
    on(name, fn) { this.handlers.set(name, fn); },
    registerTool(tool) { this.tools.set(tool.name, tool); },
    registerCommand(name, command) { this.commands.set(name, command); },
  };
  registerExtension(pi);
  let id = "session-a";
  const choices = [];
  const prompts = [];
  const notifications = [];
  const ctx = {
    mode: "tui", hasUI: true, cwd: home,
    sessionManager: { getSessionId: () => id },
    ui: {
      select: async (title, options) => { prompts.push({ title, options }); return choices.shift() ?? "Deny"; },
      confirm: async (title, message) => { prompts.push({ title, message }); return choices.shift() === ONCE; },
      notify: (...args) => notifications.push(args),
      custom: async () => { throw new Error("Saved credentials must not request plaintext input"); },
    },
  };
  pi.handlers.get("session_start")({ reason: "startup" }, ctx);
  return {
    pi, ctx, choices, prompts, notifications,
    setId(next) { id = next; },
    reuse(name = "APP_TOKEN", context = ctx, signal) {
      return pi.tools.get("request_secret").execute("request", { name }, signal, undefined, context);
    },
    async use(toolName = "write", input = { content: A }, context = ctx) {
      const original = structuredClone(input);
      const result = await pi.handlers.get("tool_call")({ toolName, input }, context);
      if (result?.block) assert.deepEqual(input, original, "blocked arguments must remain untouched");
      return { input, result };
    },
    revoke() { return pi.commands.get("mask-secret-revoke").handler("", ctx); },
  };
}

async function grant(f) {
  f.choices.push(SESSION);
  assert.equal((await f.reuse()).details.handle, A);
}

function assertNoHandle(result) {
  assert.equal(result.details?.handle, undefined);
  assert.doesNotMatch(JSON.stringify(result), /app-secret-123456|__SECRET_APP_TOKEN__/);
}

test("session reuse approval covers repeated requests and authorized tools without leaking values", async () => {
  const f = fixture();
  const saved = readFileSync(join(dir, "secrets.json"), "utf8");
  await grant(f);
  assert.equal((await f.reuse()).details.handle, A);
  for (const [tool, input] of [
    ["bash", { command: `login --token ${A}` }],
    ["powershell", { command: `login --token ${A}` }],
    ["write", { path: "config", content: A }],
    ["edit", { path: "config", edits: [{ oldText: A, newText: `value=${A}` }] }],
    ["mcp", { tool: "login", args: JSON.stringify({ password: A }) }],
    ["mcp", { tool: "login", args: { password: A } }],
  ]) {
    const used = await f.use(tool, input);
    assert.equal(used.result, undefined);
    assert.match(JSON.stringify(used.input), /app-secret-123456/);
  }
  assert.equal(f.prompts.length, 1);
  assert.deepEqual(f.prompts[0].options, [ONCE, SESSION, "Deny"]);
  assert.match(f.prompts[0].title, /ANY configured tool path/);
  assert.match(f.prompts[0].title, /mask-secret-revoke/);
  assert.doesNotMatch(JSON.stringify(f.prompts), /app-secret-123456/);
  assert.equal(readFileSync(join(dir, "secrets.json"), "utf8"), saved, "grants must not be persisted");

  const output = { content: [{ type: "text", text: "value=app-secret-123456" }], details: { key: "app-secret-123456" } };
  f.pi.handlers.get("tool_result")(output, f.ctx);
  assert.doesNotMatch(JSON.stringify(output), /app-secret-123456/);
  assert.match(JSON.stringify(output), /__SECRET_APP_TOKEN__/);
  const payload = { messages: [{ role: "user", content: "value=app-secret-123456" }] };
  f.pi.handlers.get("before_provider_request")({ payload }, f.ctx);
  assert.equal(payload.messages[0].content, `value=${A}`);
});

test("granting during tool use also authorizes subsequent request_secret reuse", async () => {
  const f = fixture();
  f.choices.push(SESSION);
  assert.equal((await f.use()).input.content, "app-secret-123456");
  assert.equal((await f.reuse()).details.handle, A);
  assert.equal((await f.use()).result, undefined);
  assert.equal(f.prompts.length, 1);
  assert.match(f.prompts[0].title, /Tool: write/);
  assert.match(f.prompts[0].title, /Authorized argument paths: content/);
});

test("one-shot reuse and tool confirmation never become session grants", async () => {
  const f = fixture();
  f.choices.push(ONCE, ONCE, ONCE, ONCE);
  assert.equal((await f.reuse()).details.handle, A);
  assert.equal((await f.reuse()).details.handle, A);
  assert.equal((await f.use()).result, undefined);
  assert.equal((await f.use()).result, undefined);
  assert.equal(f.prompts.length, 4);
  assert.equal((await f.use()).result.block, true);
});

for (const choice of ["Deny", undefined, "unexpected", true]) {
  test(`declined/cancelled/invalid selection ${String(choice)} grants nothing`, async () => {
    const f = fixture();
    f.ctx.ui.select = async () => choice;
    assertNoHandle(await f.reuse());
    assert.equal((await f.use()).result.block, true);
    f.ctx.ui.select = async () => "Deny";
    assertNoHandle(await f.reuse());
  });
}

test("multiple credentials require approval for all, without granting unrelated handles", async () => {
  const f = fixture();
  await grant(f);
  assert.equal((await f.use("write", { content: `${A} ${B}` })).result.block, true);
  assert.equal((await f.reuse("OTHER_TOKEN")).details?.handle, undefined);
  f.choices.push(ONCE);
  assert.equal((await f.use("write", { content: `${A} ${B}` })).result, undefined);
  assert.equal((await f.use("write", { content: B })).result.block, true);
  f.choices.push(SESSION);
  assert.equal((await f.use("write", { content: `${A} ${B}` })).result, undefined);
  const count = f.prompts.length;
  assert.equal((await f.reuse("OTHER_TOKEN")).details.handle, B);
  assert.equal((await f.use("write", { content: B })).result, undefined);
  assert.equal(f.prompts.length, count);
});

test("cached grants do not bypass path, unknown-handle, JSON, key, or shell safety checks", async () => {
  const f = fixture();
  await grant(f);
  f.choices.push(SESSION);
  assert.equal((await f.reuse("UNSAFE")).details.handle, "__SECRET_UNSAFE__");
  const count = f.prompts.length;
  for (const [tool, input] of [
    ["read", { path: A }],
    ["write", { path: A, content: "safe" }],
    ["write", { content: `${A} __SECRET_INVENTED__` }],
    ["mcp", { args: `{broken ${A}` }],
    ["mcp", { args: { [A]: "value" } }],
    ["browser_fill", { value: A }],
    ["bash", { command: "login __SECRET_UNSAFE__" }],
    ["powershell", { command: "login __SECRET_UNSAFE__" }],
  ]) assert.equal((await f.use(tool, input)).result.block, true);
  assert.equal(f.prompts.length, count, "validation must precede even cached approval");
});

test("session approval honors configured paths but not disabled resolution", async () => {
  let f = fixture({ toolResolution: { includeDefaults: false, rules: [{ tool: "browser_fill", paths: ["value"] }] } });
  await grant(f);
  assert.equal((await f.use("browser_fill", { value: A })).input.value, "app-secret-123456");
  assert.equal((await f.use()).result.block, true);
  f = fixture({ toolResolution: { enabled: false } });
  await grant(f);
  assert.equal((await f.use()).result.block, true);
});

for (const reason of ["startup", "new", "resume", "fork", "reload"]) {
  test(`session_start ${reason} clears approvals even if the session ID stays the same`, async () => {
    const f = fixture();
    await grant(f);
    f.pi.handlers.get("session_start")({ reason }, f.ctx);
    assertNoHandle(await f.reuse());
    assert.equal((await f.use()).result.block, true);
  });
}

test("shutdown invalidates grants and blocks stale calls until a new session starts", async () => {
  const f = fixture();
  await grant(f);
  f.pi.handlers.get("session_shutdown")({ reason: "quit" }, f.ctx);
  f.choices.push(SESSION);
  assertNoHandle(await f.reuse());
  assert.equal((await f.use()).result.block, true);
  assert.equal(f.prompts.length, 1, "no prompts from a closed runtime");
});

test("changed session IDs fail closed without relying solely on lifecycle hooks", async () => {
  const f = fixture();
  await grant(f);
  f.setId("session-b");
  assertNoHandle(await f.reuse());
  f.setId("session-a");
  assert.equal((await f.use()).result.block, true, "switching back must not revive grants");
});

test("a fresh extension instance never inherits remembered approvals", async () => {
  const f = fixture();
  await grant(f);
  const fresh = fixture();
  assertNoHandle(await fresh.reuse());
  assert.equal((await fresh.use()).result.block, true);
});

test("compaction, turns, and same-session tree navigation keep approvals", async () => {
  const f = fixture();
  await grant(f);
  for (const event of ["session_compact", "session_tree", "turn_start", "agent_end"]) {
    await f.pi.handlers.get(event)?.({}, f.ctx);
  }
  assert.equal((await f.reuse()).details.handle, A);
  assert.equal((await f.use()).result, undefined);
  assert.equal(f.prompts.length, 1);
});

test("revoke clears reuse and execution approvals without deleting saved credentials", async () => {
  const f = fixture();
  await grant(f);
  const saved = readFileSync(join(dir, "secrets.json"), "utf8");
  await f.revoke();
  assertNoHandle(await f.reuse());
  assert.equal((await f.use()).result.block, true);
  assert.equal(readFileSync(join(dir, "secrets.json"), "utf8"), saved);
  await grant(f);
  assert.equal((await f.use()).result, undefined);
});

test("credential rotation revokes the old grant even when its old value remains masked", async () => {
  const f = fixture({ extraSecrets: [{ name: "APP_TOKEN", value: "app-secret-123456" }] });
  await grant(f);
  await f.pi.commands.get("mask-secret").handler("APP_TOKEN rotated-secret-123456", f.ctx);
  assertNoHandle(await f.reuse());
  assert.equal((await f.use()).result.block, true, "retained old handles lose authorization too");
  f.choices.push(SESSION);
  const newHandle = (await f.reuse()).details.handle;
  assert.ok(newHandle);
  assert.equal((await f.use("write", { content: newHandle })).input.content, "rotated-secret-123456");
});

for (const mode of ["rpc", "print", "json"]) {
  test(`${mode} cannot consume or create TUI session grants`, async () => {
    const f = fixture();
    await grant(f);
    const ctx = { ...f.ctx, mode, hasUI: mode === "rpc" };
    assertNoHandle(await f.reuse("APP_TOKEN", ctx));
    assert.equal((await f.use("write", { content: A }, ctx)).result.block, true);
    if (mode === "rpc") {
      f.choices.push(ONCE);
      assert.equal((await f.use("write", { content: A }, ctx)).result, undefined, "RPC keeps one-shot confirmation");
      assert.equal((await f.use("write", { content: A }, ctx)).result.block, true);
    }
  });
}

test("missing/stale session identity only permits explicit one-shot approval", async () => {
  for (const manager of [undefined, { getSessionId: () => undefined }, { getSessionId() { throw new Error("stale"); } }]) {
    const f = fixture();
    f.ctx.sessionManager = manager;
    f.choices.push(SESSION);
    assertNoHandle(await f.reuse()); // Even a fabricated UI return must not create a grant.
    assert.deepEqual(f.prompts[0].options, [ONCE, "Deny"]);
    f.choices.push(ONCE);
    assert.equal((await f.reuse()).details.handle, A);
    assert.equal((await f.use()).result.block, true);
  }
});

test("confirm-only hosts retain one-shot behavior without implicit session grants", async () => {
  const f = fixture();
  delete f.ctx.ui.select;
  f.choices.push(ONCE, ONCE);
  assert.equal((await f.reuse()).details.handle, A);
  assert.equal((await f.use()).result, undefined);
  assertNoHandle(await f.reuse());
  assert.equal(f.prompts.length, 3);
});

test("explicit hasUI false blocks cached grants and dialogs in ask mode", async () => {
  const f = fixture();
  await grant(f);
  f.ctx.hasUI = false;
  assertNoHandle(await f.reuse());
  assert.equal((await f.use()).result.block, true);
  assert.equal(f.prompts.length, 1);
});

test("auto and allowCommands keep their existing scope and are not changed by revocation", async () => {
  const f = fixture({ mode: "auto" });
  assert.equal((await f.use()).result, undefined);
  assertNoHandle(await f.reuse(), "auto does not authorize returning stored credentials");
  await grant(f);
  await f.revoke();
  assertNoHandle(await f.reuse());
  assert.equal((await f.use()).result, undefined);
  const g = fixture({ allowCommands: ["login "] });
  assert.equal((await g.use("bash", { command: `login ${A}` })).result, undefined);
  assert.equal((await g.use()).result.block, true);
  assertNoHandle(await g.reuse());
});

for (const invalidate of ["revoke", "shutdown", "reload", "session-id", "rotate", "abort"]) {
  for (const kind of ["reuse", "tool"]) {
    test(`pending ${kind} approval cannot survive ${invalidate}`, async () => {
      const f = fixture();
      const controller = new AbortController();
      f.ctx.signal = controller.signal;
      let reply;
      f.ctx.ui.select = () => new Promise((resolve) => { reply = resolve; });
      const pending = kind === "reuse" ? f.reuse() : f.use();
      assert.equal(typeof reply, "function");
      if (invalidate === "revoke") await f.revoke();
      if (invalidate === "shutdown") f.pi.handlers.get("session_shutdown")({}, f.ctx);
      if (invalidate === "reload") f.pi.handlers.get("session_start")({ reason: "reload" }, f.ctx);
      if (invalidate === "session-id") f.setId("session-b");
      if (invalidate === "rotate") await f.pi.commands.get("mask-secret").handler("APP_TOKEN new-secret-123456", f.ctx);
      if (invalidate === "abort") controller.abort();
      reply(SESSION);
      const result = await pending;
      if (kind === "reuse") assertNoHandle(result);
      else assert.equal(result.result.block, true);
      f.ctx.signal = undefined;
      f.ctx.ui.select = async () => "Deny";
      assertNoHandle(await f.reuse());
      assert.equal((await f.use()).result.block, true);
    });
  }
}

test("request abort signal is honored independently of ctx.signal", async () => {
  const f = fixture();
  const controller = new AbortController();
  f.ctx.ui.select = async () => { controller.abort(); return SESSION; };
  assertNoHandle(await f.reuse("APP_TOKEN", f.ctx, controller.signal));
  f.ctx.ui.select = async () => "Deny";
  assertNoHandle(await f.reuse());
});

for (const method of ["select", "confirm"]) {
  test(`a rejected ${method} dialog neither mutates arguments nor grants later reuse`, async () => {
    const f = fixture();
    if (method === "confirm") delete f.ctx.ui.select;
    f.ctx.ui[method] = async () => { throw new Error("UI torn down"); };
    const input = { content: A };
    // Pi 0.84.2 treats tool_call exceptions as blocking, and execute exceptions as errors.
    await assert.rejects(f.pi.handlers.get("tool_call")({ toolName: "write", input }, f.ctx), /UI torn down/);
    assert.deepEqual(input, { content: A });
    await assert.rejects(f.reuse(), /UI torn down/);
    f.ctx.ui[method] = async () => method === "confirm" ? false : "Deny";
    assertNoHandle(await f.reuse());
    assert.equal((await f.use()).result.block, true);
  });
}

test("late masked input after shutdown is not registered or persisted", async () => {
  const f = fixture();
  const saved = readFileSync(join(dir, "secrets.json"), "utf8");
  let finish;
  f.ctx.ui.custom = () => new Promise((resolve) => { finish = resolve; });
  const pending = f.reuse("NEW_PASSWORD");
  f.pi.handlers.get("session_shutdown")({}, f.ctx);
  finish("late-password-123456");
  assert.equal((await pending).details?.handle, undefined);
  assert.equal(readFileSync(join(dir, "secrets.json"), "utf8"), saved);
});

test("fresh masked capture does not implicitly grant session use", async () => {
  const f = fixture();
  f.ctx.ui.custom = async (factory) => {
    let result;
    const component = factory({ requestRender() {} }, { fg: (_style, text) => text }, {}, (value) => { result = value; });
    component.handleInput("new-password-123456");
    component.handleInput("\r");
    return result;
  };
  const result = await f.reuse("NEW_PASSWORD");
  assert.equal(result.details.handle, "__SECRET_NEW_PASSWORD__");
  assert.equal(f.prompts.length, 0, "capture alone should not add another dialog");
  f.choices.push(SESSION);
  assert.equal((await f.use("write", { content: result.details.handle })).result, undefined);
  assert.equal((await f.reuse("NEW_PASSWORD")).details.handle, result.details.handle);
  assert.equal(f.prompts.length, 1);
  assert.equal(f.pi.tools.get("request_secret").executionMode, "sequential");
});
