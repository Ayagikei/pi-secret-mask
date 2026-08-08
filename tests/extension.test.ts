/**
 * Minimal extension integration tests: load the real extension with a mock
 * pi API and exercise the hooks against synthetic provider payloads.
 * Run with node --test (no pi runtime needed — the extension only uses
 * node built-ins plus typebox, which we stub here).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, existsSync, readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";

// typebox is a peerDependency injected by pi; stub it minimally for tests.
const require = createRequire(import.meta.url);
try {
  require.resolve("typebox");
} catch {
  // Provided below via module resolution fallback if not installed.
}

function makeMockPi() {
  const handlers = new Map();
  const commands = new Map();
  const tools = new Map();
  return {
    handlers,
    commands,
    tools,
    on: (ev, fn) => {
      if (!handlers.has(ev)) handlers.set(ev, []);
      handlers.get(ev).push(fn);
    },
    registerCommand: (name, def) => commands.set(name, def),
    registerTool: (def) => tools.set(def.name, def),
  };
}

async function loadExtension(tmp: string, config?: object) {
  // Hermetic: point $HOME at a temp dir so USER_CONFIG_FILE and
  // USER_SECRETS_FILE resolve inside the test sandbox, never the real
  // ~/.pi/agent. The extension reads homedir() at load time.
  const home = mkdtempSync(join(tmpdir(), "psm-home-"));
  const cfgDir = join(home, ".pi", "agent", "extensions", "pi-secret-mask");
  mkdirSync(cfgDir, { recursive: true });
  if (config !== undefined) {
    writeFileSync(join(cfgDir, "config.json"), JSON.stringify(config));
  }
  const prevHome = process.env.HOME;
  process.env.HOME = home;
  try {
    // Bust the module cache: each loadExtension gets a fresh extension state.
    const mod = await import(`../extensions/pi-secret-mask.ts?t=${Date.now()}-${Math.random()}`);
    const pi = makeMockPi();
    mod.default(pi);
    return { pi, home };
  } finally {
    process.env.HOME = prevHome;
  }
}

test("extension: before_provider_request masks messages + system + tools and returns payload", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "OPENAI_API_KEY=sk-ext-test-key-1234567890abcd\n");

  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const handlers = pi.handlers.get("before_provider_request");
  assert.ok(handlers?.length, "before_provider_request handler registered");

  const payload = {
    model: "x",
    system: "sk-ext-test-key-1234567890abcd in system",
    messages: [
      { role: "user", content: [{ type: "text", text: "my sk-ext-test-key-1234567890abcd here" }] },
      { role: "assistant", content: "plain string with sk-ext-test-key-1234567890abcd" },
    ],
    tools: [{ type: "function", function: { name: "f", description: "uses sk-ext-test-key-1234567890abcd" } }],
  };
  const ctx = { cwd: tmp };
  let returned: unknown;
  for (const h of handlers) {
    const r = await h({ type: "before_provider_request", payload }, ctx);
    if (r !== undefined) returned = r;
  }
  const text = JSON.stringify(returned ?? payload);
  assert.equal(text.includes("sk-ext-test-key-1234567890abcd"), false, "no real secret in payload");
  assert.ok(text.includes("__SECRET_OPENAI_API_KEY__"), "placeholder present");
  assert.equal((payload.messages[0] as any).role, "user", "structural role untouched");
  assert.equal((payload.messages[1] as any).role, "assistant", "structural role untouched");
  assert.equal((payload.tools[0] as any).type, "function", "structural type untouched");
});

test("extension: Gemini contents[].parts[].text and config.systemInstruction are masked", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "GKEY=AIzaSyExtTestKey1234567890abcdefghijklmnopqrstuvwxyz\n");

  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const handlers = pi.handlers.get("before_provider_request");
  const payload: any = {
    model: "gemini-x",
    config: { systemInstruction: { parts: [{ text: "sys AIzaSyExtTestKey1234567890abcdefghijklmnopqrstuvwxyz end" }] } },
    contents: [
      { role: "user", parts: [{ text: "hello AIzaSyExtTestKey1234567890abcdefghijklmnopqrstuvwxyz" }, { inlineData: { mimeType: "image/png", data: "AIzaSyExtTestKey1234567890abcdefghijklmnopqrstuvwxyz" } }] },
    ],
  };
  let returned: unknown;
  for (const h of handlers) {
    const r = await h({ type: "before_provider_request", payload }, { cwd: tmp });
    if (r !== undefined) returned = r;
  }
  const text = JSON.stringify(returned ?? payload);
  // Image data intentionally keeps the real bytes; text parts must be masked.
  assert.equal(payload.config.systemInstruction.parts[0].text.includes("AIzaSyExtTestKey1234567890abcdefghijklmnopqrstuvwxyz"), false, "no real secret in system text");
  assert.equal(payload.contents[0].parts[0].text.includes("AIzaSyExtTestKey1234567890abcdefghijklmnopqrstuvwxyz"), false, "no real secret in user text");
  assert.equal(payload.config.systemInstruction.parts[0].text, "sys __SECRET_GKEY__ end", "system text masked");
  assert.equal(payload.contents[0].parts[0].text, "hello __SECRET_GKEY__", "user text masked");
  // inlineData image bytes must be untouched (it is an image node)
  assert.equal(payload.contents[0].parts[1].inlineData.data, "AIzaSyExtTestKey1234567890abcdefghijklmnopqrstuvwxyz");
  assert.equal(payload.contents[0].role, "user", "structural role untouched");
});

test("extension: tool_call unmask bash + write, block dangerous shell values", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "SAFE=abc12345\nBAD=abc 123\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  // Prime the map: refreshDotenv runs on before_provider_request.
  for (const h of pi.handlers.get("before_provider_request") ?? []) {
    await h({ type: "before_provider_request", payload: { model: "x", messages: [] } }, { cwd: tmp });
  }
  const toolHandlers = pi.handlers.get("tool_call");
  assert.ok(toolHandlers?.length);

  // bash unmask
  let ev = { toolName: "bash", input: { command: "echo __SECRET_SAFE__" } };
  for (const h of toolHandlers) await h(ev, {});
  assert.equal(ev.input.command, "echo abc12345");

  // write unmask
  ev = { toolName: "write", input: { path: "/tmp/x", content: "v=__SECRET_SAFE__" } };
  for (const h of toolHandlers) await h(ev, {});
  assert.equal(ev.input.content, "v=abc12345");

  // dangerous value (space) must block bash
  const ev2 = { toolName: "bash", input: { command: "echo __SECRET_BAD__" } };
  let blocked: unknown;
  for (const h of toolHandlers) {
    const r = await h(ev2, {});
    if (r && (r as any).block) blocked = r;
  }
  assert.ok(blocked, "dangerous secret should be blocked");
});

test("extension: config validation — null extraSecrets element does not crash", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  const { pi } = await loadExtension(tmp, { extraSecrets: [null as any] });
  assert.ok(pi.handlers.has("before_provider_request"));
});

test("extension: .env rotation keeps masking history (seen source)", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "OLD=oldsecretvalue123456\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const handlers = pi.handlers.get("before_provider_request")!;

  // First request: OLD appears in history and gets masked (gets "seen").
  const p1: any = { model: "x", messages: [{ role: "user", content: "oldsecretvalue123456" }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p1 }, { cwd: tmp });
  assert.ok(JSON.stringify(p1).includes("__SECRET_OLD__"), "first request masked");

  // Rotate .env: OLD removed, NEW added.
  writeFileSync(join(tmp, ".env"), "NEW=brandnewsecretvalue789\n");
  // Sleep so mtime changes (some filesystems have coarse timestamps).
  await new Promise((r) => setTimeout(r, 20));
  const p2: any = { model: "x", messages: [{ role: "user", content: "oldsecretvalue123456" }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p2 }, { cwd: tmp });
  const t2 = JSON.stringify(p2);
  assert.equal(t2.includes("oldsecretvalue123456"), false, "rotated-away secret still masked in history");
  assert.ok(t2.includes("__SECRET_OLD__"), "old placeholder retained");
});

test("extension: structural fields survive when .env value collides with role", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  // .env value "user" would collide with the message role field.
  writeFileSync(join(tmp, ".env"), "ROLE=user\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const handlers = pi.handlers.get("before_provider_request")!;
  const payload: any = { model: "x", messages: [{ role: "user", content: "hello user" }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload }, { cwd: tmp });
  assert.equal(payload.messages[0].role, "user", "role field untouched");
  assert.equal(payload.messages[0].content, "hello __SECRET_ROLE__", "text content masked");
});

test("extension: provider free-text paths masked (tool_result/function_call_output)", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "K=freetextsecretvalue123\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const handlers = pi.handlers.get("before_provider_request")!;

  // Anthropic: tool_result with content string
  const p1: any = { model: "x", messages: [{ role: "user", content: [{ type: "tool_result", content: "freetextsecretvalue123" }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p1 }, { cwd: tmp });
  assert.ok(JSON.stringify(p1).includes("__SECRET_K__"), "tool_result content masked");

  // OpenAI Responses: function_call_output.output
  const p2: any = { model: "x", input: [{ type: "function_call_output", call_id: "1", output: "freetextsecretvalue123" }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p2 }, { cwd: tmp });
  assert.ok(JSON.stringify(p2).includes("__SECRET_K__"), "function_call_output masked");
  assert.equal(p2.input[0].call_id, "1", "structural call_id untouched");
});

test("extension: fail-closed aborts on masking error", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "K=somevalue123456789\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const handlers = pi.handlers.get("before_provider_request")!;
  let aborted = 0;
  const ctx = {
    cwd: tmp,
    abort: () => { aborted++; },
  };
  // Force an error inside the handler: a payload with a getter that throws.
  const evil: any = {};
  Object.defineProperty(evil, "messages", {
    enumerable: true,
    get() { throw new Error("boom"); },
  });
  for (const h of handlers) await h({ type: "before_provider_request", payload: evil }, ctx);
  assert.equal(aborted, 1, "abort called on masking failure");
});
