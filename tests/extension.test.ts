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
  // Hermetic: point $HOME at a sandbox inside tmp (which every test already
  // cleans up), so USER_CONFIG_FILE/USER_SECRETS_FILE never touch the real
  // ~/.pi/agent. The extension reads homedir() at load time.
  const home = join(tmp, "home");
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

test("extension: explains masked views, editing, and when to request secrets", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));

  const { pi } = await loadExtension(tmp);
  const beforeAgentStart = pi.handlers.get("before_agent_start");
  assert.ok(beforeAgentStart?.length, "before_agent_start handler registered");
  const result = await beforeAgentStart![0]({ systemPrompt: "base prompt" }, {});
  assert.match(result.systemPrompt, /redacted alias/);
  assert.match(result.systemPrompt, /file-editing tool input \(write, edit, replace, insert\)/);
  assert.match(result.systemPrompt, /only when the task genuinely needs a secret/);
  assert.match(result.systemPrompt, /absence of secrets\.json does not prove/);

  const requestSecret = pi.tools.get("request_secret");
  assert.ok(requestSecret, "request_secret tool registered");
  assert.match(requestSecret.description, /do not request one again for a placeholder already present/);
  assert.match(requestSecret.description, /file-editing tool input \(write, edit, replace, insert\)/);
});

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

test("extension: Cursor SDK top-level text is masked without touching images", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "CURSOR_TOKEN=cursorsecretvalue123\n");

  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const handlers = pi.handlers.get("before_provider_request");
  const payload = {
    text: "use cursorsecretvalue123",
    images: [{ data: "cursorsecretvalue123", mimeType: "image/png" }],
  };

  let returned: unknown;
  for (const h of handlers) {
    const result = await h({ type: "before_provider_request", payload }, { cwd: tmp });
    if (result !== undefined) returned = result;
  }

  assert.strictEqual(returned, payload);
  const result = returned as typeof payload;
  assert.equal(result.text, "use __SECRET_CURSOR_TOKEN__");
  assert.deepEqual(result.images, [{ data: "cursorsecretvalue123", mimeType: "image/png" }]);
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

  // Rotate .env: OLD removed, NEW added. Force a distinct mtime so the
  // refresh definitely triggers (no reliance on coarse FS timestamps).
  const envPath = join(tmp, ".env");
  writeFileSync(envPath, "NEW=brandnewsecretvalue789\n");
  const now = new Date();
  now.setSeconds(now.getSeconds() + 2);
  const { utimesSync } = await import("node:fs");
  utimesSync(envPath, now, now);
  const p2: any = { model: "x", messages: [{ role: "user", content: "oldsecretvalue123456 brandnewsecretvalue789" }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p2 }, { cwd: tmp });
  const t2 = JSON.stringify(p2);
  assert.equal(t2.includes("oldsecretvalue123456"), false, "rotated-away secret still masked in history");
  assert.ok(t2.includes("__SECRET_OLD__"), "old placeholder retained");
  assert.ok(t2.includes("__SECRET_NEW__"), "new secret loaded and masked");
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


test("extension: provider variants — instructions, Gemini functionResponse, multimodal output, Bedrock toolResult", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "K=varsecretvalue123456\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const handlers = pi.handlers.get("before_provider_request")!;
  const secret = "varsecretvalue123456";

  // Codex Responses: top-level instructions (P0-10)
  const p1: any = { model: "x", instructions: `sys ${secret}`, input: [{ role: "user", content: [{ type: "input_text", text: `hi ${secret}` }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p1 }, { cwd: tmp });
  assert.ok(JSON.stringify(p1).includes("__SECRET_K__"), "instructions + input_text masked");
  assert.equal(JSON.stringify(p1).includes(secret), false, "no plaintext in instructions payload");

  // Gemini functionResponse (P0-9): part.functionResponse.response.output
  const p2: any = { model: "gemini-x", contents: [{ role: "user", parts: [{ functionResponse: { name: "f", response: { output: secret } } }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p2 }, { cwd: tmp });
  assert.equal(p2.contents[0].parts[0].functionResponse.response.output, "__SECRET_K__", "gemini functionResponse.output masked");
  assert.equal(p2.contents[0].parts[0].functionResponse.name, "f", "structural name untouched");

  // OpenAI Responses multimodal output array (P0-9)
  const p3: any = { model: "x", input: [{ type: "function_call_output", call_id: "1", output: [{ type: "input_text", text: secret }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p3 }, { cwd: tmp });
  assert.equal(p3.input[0].output[0].text, "__SECRET_K__", "multimodal output array masked");
  assert.equal(p3.input[0].call_id, "1", "structural call_id untouched");

  // Bedrock Converse: content[].toolResult.content[].text (P0-11)
  const p4: any = { model: "x", messages: [{ role: "user", content: [{ toolResult: { toolUseId: "t1", content: [{ text: secret }] } }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p4 }, { cwd: tmp });
  assert.equal(p4.messages[0].content[0].toolResult.content[0].text, "__SECRET_K__", "bedrock toolResult text masked");
  assert.equal(p4.messages[0].content[0].toolResult.toolUseId, "t1", "structural toolUseId untouched");
});

test("extension: custom_tool_call_output and instructions array masked", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "K=ctco_secret_value123456\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const handlers = pi.handlers.get("before_provider_request")!;
  const secret = "ctco_secret_value123456";

  // Grammar-tool path: custom_tool_call_output (P0-N4)
  const p1: any = { model: "x", input: [{ type: "custom_tool_call_output", call_id: "c1", output: secret }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p1 }, { cwd: tmp });
  assert.equal(p1.input[0].output, "__SECRET_K__", "custom_tool_call_output masked");
  assert.equal(p1.input[0].call_id, "c1", "structural call_id untouched");

  // instructions as string array (P0-10)
  const p2: any = { model: "x", instructions: [`sys ${secret}`, "other"] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p2 }, { cwd: tmp });
  assert.equal(p2.instructions[0], "sys __SECRET_K__", "instructions array element masked");
  assert.equal(p2.instructions[1], "other", "unrelated instruction untouched");
});

test("extension: tree hook masks custom_message and customInstructions", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "K=tree_secret_value123456\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const treeHandlers = pi.handlers.get("session_before_tree")!;
  const secret = "tree_secret_value123456";

  const event: any = {
    type: "session_before_tree",
    preparation: {
      entriesToSummarize: [
        { type: "message", id: "m1", message: { role: "user", content: `msg ${secret}` } },
        // Real Pi structure: custom_message carries top-level content (P0-N5).
        { type: "custom_message", id: "c1", customType: "test", display: true, content: `custom ${secret}` },
      ],
      customInstructions: `instr ${secret}`,
    },
    signal: undefined,
  };
  let result: any;
  for (const h of treeHandlers) {
    const r = await h(event, { cwd: tmp });
    if (r !== undefined) result = r;
  }
  assert.equal(event.preparation.entriesToSummarize[0].message.content, "msg __SECRET_K__", "message entry masked");
  assert.equal(event.preparation.entriesToSummarize[1].content, "custom __SECRET_K__", "custom_message top-level content masked");
  // Pi only honors the returned override (P0-N6).
  assert.equal(result?.customInstructions, "instr __SECRET_K__", "customInstructions returned as override");
});

test("extension: .env vanishing between scan and read aborts refresh (TOCTOU)", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "OLD=oldvaluetooctou12345\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const handlers = pi.handlers.get("before_provider_request")!;

  // Prime with OLD actually appearing in history (gets the "seen" source,
  // which is what keeps history masked after rotation).
  const p0: any = { model: "x", messages: [{ role: "user", content: "oldvaluetooctou12345" }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p0 }, { cwd: tmp });
  assert.ok(JSON.stringify(p0).includes("__SECRET_OLD__"), "primed request masked");

  // Delete the file: next refresh sees it as disappeared (changed). The
  // refresh must not throw, must not leak the old value in history, and the
  // seen source keeps the mapping alive.
  rmSync(join(tmp, ".env"));
  const p1: any = { model: "x", messages: [{ role: "user", content: "oldvaluetooctou12345" }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p1 }, { cwd: tmp });
  assert.equal(JSON.stringify(p1).includes("oldvaluetooctou12345"), false, "old value stays masked after file removal");
});


test("extension: compact hook cancels when customInstructions contain secrets", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "K=compact_instr_secret12345\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const compactHandlers = pi.handlers.get("session_before_compact")!;
  const secret = "compact_instr_secret12345";

  // Prime the map.
  const bpHandlers = pi.handlers.get("before_provider_request")!;
  const p0: any = { model: "x", messages: [] };
  for (const h of bpHandlers) await h({ type: "before_provider_request", payload: p0 }, { cwd: tmp });

  // Safe instructions: no secret -> no cancel.
  let event: any = { type: "session_before_compact", preparation: { messagesToSummarize: [], turnPrefixMessages: [] }, customInstructions: "safe focus" };
  let result: any;
  for (const h of compactHandlers) {
    const r = await h(event, { cwd: tmp });
    if (r !== undefined) result = r;
  }
  assert.equal(result?.cancel, undefined, "safe instructions do not cancel");

  // Instructions containing a secret -> cancel (fail closed, P0-N6).
  event = { type: "session_before_compact", preparation: { messagesToSummarize: [], turnPrefixMessages: [] }, customInstructions: `focus on ${secret}` };
  result = undefined;
  for (const h of compactHandlers) {
    const r = await h(event, { cwd: tmp });
    if (r !== undefined) result = r;
  }
  assert.equal(result?.cancel, true, "secret-bearing instructions cancel compaction");
});

test("extension: compact masks previousSummary and message variants; fresh pattern cancels", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "K=compactvar_secret123456\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const compactHandlers = pi.handlers.get("session_before_compact")!;
  const bpHandlers = pi.handlers.get("before_provider_request")!;
  const secret = "compactvar_secret123456";
  // Prime the map.
  await bpHandlers[0]({ type: "before_provider_request", payload: { model: "x", messages: [] } }, { cwd: tmp });

  const event: any = {
    type: "session_before_compact",
    preparation: {
      messagesToSummarize: [
        { role: "bashExecution", command: `echo ${secret}`, output: secret, exitCode: 0, cancelled: false, truncated: false, timestamp: 1 },
        { role: "branchSummary", summary: `branch ${secret}`, fromId: "b1", timestamp: 1 },
        { role: "compactionSummary", summary: `comp ${secret}`, tokensBefore: 1, timestamp: 1 },
      ],
      turnPrefixMessages: [],
      previousSummary: `prev ${secret}`,
    },
    customInstructions: "safe",
  };
  let result: any;
  for (const h of compactHandlers) {
    const r = await h(event, { cwd: tmp });
    if (r !== undefined) result = r;
  }
  const prep = event.preparation;
  assert.equal(prep.messagesToSummarize[0].command, `echo __SECRET_K__`, "bashExecution.command masked");
  assert.equal(prep.messagesToSummarize[0].output, "__SECRET_K__", "bashExecution.output masked");
  assert.equal(prep.messagesToSummarize[1].summary, `branch __SECRET_K__`, "branchSummary.summary masked");
  assert.equal(prep.messagesToSummarize[2].summary, `comp __SECRET_K__`, "compactionSummary.summary masked");
  assert.equal(prep.previousSummary, `prev __SECRET_K__`, "previousSummary masked");
  assert.equal(result?.cancel, undefined, "safe instructions do not cancel");

  // Fresh pattern (sk-...) in customInstructions must cancel (P0-N6 via maskText).
  const ev2: any = { type: "session_before_compact", preparation: { messagesToSummarize: [], turnPrefixMessages: [] }, customInstructions: "focus sk-freshpattern1234567890abcd" };
  result = undefined;
  for (const h of compactHandlers) {
    const r = await h(ev2, { cwd: tmp });
    if (r !== undefined) result = r;
  }
  assert.equal(result?.cancel, true, "fresh-pattern instructions cancel");
});

test("extension: tree masks branch_summary and compaction entry summaries", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "K=treeentry_secret123456\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const treeHandlers = pi.handlers.get("session_before_tree")!;
  const secret = "treeentry_secret123456";
  // Prime the map.
  const bpHandlers = pi.handlers.get("before_provider_request")!;
  await bpHandlers[0]({ type: "before_provider_request", payload: { model: "x", messages: [] } }, { cwd: tmp });

  const event: any = {
    type: "session_before_tree",
    preparation: {
      entriesToSummarize: [
        { type: "branch_summary", id: "b1", fromId: "x", summary: `branch ${secret}` },
        { type: "compaction", id: "c1", summary: `comp ${secret}`, firstKeptEntryId: "k", tokensBefore: 1 },
        { type: "message", id: "m1", message: { role: "bashExecution", command: `echo ${secret}`, output: secret, exitCode: 0, cancelled: false, truncated: false, timestamp: 1 } },
      ],
    },
    signal: undefined,
  };
  for (const h of treeHandlers) await h(event, { cwd: tmp });
  assert.equal(event.preparation.entriesToSummarize[0].summary, `branch __SECRET_K__`, "branch_summary.summary masked");
  assert.equal(event.preparation.entriesToSummarize[1].summary, `comp __SECRET_K__`, "compaction.summary masked");
  assert.equal(event.preparation.entriesToSummarize[2].message.command, `echo __SECRET_K__`, "message bashExecution.command masked");
  assert.equal(event.preparation.entriesToSummarize[2].message.output, "__SECRET_K__", "message bashExecution.output masked");
});

test("extension: tool-call arguments and reasoning fields masked", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "K=toolreason_secret123456\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const handlers = pi.handlers.get("before_provider_request")!;
  const secret = "toolreason_secret123456";
  // Prime the map.
  await handlers[0]({ type: "before_provider_request", payload: { model: "x", messages: [] } }, { cwd: tmp });

  // OpenAI Chat / Mistral: tool_calls[].function.arguments (P0-8/9)
  const p1: any = { model: "x", messages: [{ role: "assistant", content: null, tool_calls: [{ id: "t1", type: "function", function: { name: "f", arguments: `{"key":"${secret}"}` } }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p1 }, { cwd: tmp });
  assert.ok(JSON.stringify(p1).includes("__SECRET_K__"), "tool_calls arguments masked");
  assert.equal(JSON.stringify(p1).includes(secret), false, "no plaintext in tool_calls arguments");

  // Anthropic: tool_use.input (P0-10)
  const p2: any = { model: "x", messages: [{ role: "assistant", content: [{ type: "tool_use", id: "t2", name: "f", input: { key: secret } }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p2 }, { cwd: tmp });
  assert.equal(p2.messages[0].content[0].input.key, "__SECRET_K__", "tool_use.input masked");
  assert.equal(p2.messages[0].content[0].id, "t2", "structural id untouched");

  // Gemini: functionCall.args (P0-11)
  const p3: any = { model: "x", contents: [{ role: "model", parts: [{ functionCall: { name: "f", args: { key: secret } } }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p3 }, { cwd: tmp });
  assert.equal(p3.contents[0].parts[0].functionCall.args.key, "__SECRET_K__", "functionCall.args masked");

  // Bedrock: toolUse.input (P0-12)
  const p4: any = { model: "x", messages: [{ role: "assistant", content: [{ toolUse: { toolUseId: "t4", name: "f", input: { key: secret } } }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p4 }, { cwd: tmp });
  assert.equal(p4.messages[0].content[0].toolUse.input.key, "__SECRET_K__", "toolUse.input masked");

  // OpenAI Responses: custom_tool_call.input + reasoning item (P0-13/17)
  const p5: any = { model: "x", input: [{ type: "custom_tool_call", id: "c5", input: secret }, { type: "reasoning", id: "r5", summary: [{ type: "summary_text", text: secret }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p5 }, { cwd: tmp });
  assert.equal(p5.input[0].input, "__SECRET_K__", "custom_tool_call.input masked");
  assert.equal(p5.input[1].summary[0].text, "__SECRET_K__", "reasoning summary text masked");

  // OpenAI Chat reasoning_content (P0-14)
  const p6: any = { model: "x", messages: [{ role: "assistant", content: "ok", reasoning_content: `think ${secret}` }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p6 }, { cwd: tmp });
  assert.equal(p6.messages[0].reasoning_content, "think __SECRET_K__", "reasoning_content masked");

  // Anthropic thinking block + Bedrock reasoningText (P0-15/16)
  const p7: any = { model: "x", messages: [{ role: "assistant", content: [{ type: "thinking", thinking: `think ${secret}`, signature: "sig" }, { type: "text", text: "ok" }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p7 }, { cwd: tmp });
  assert.equal(p7.messages[0].content[0].thinking, "think __SECRET_K__", "anthropic thinking masked");
  assert.equal(p7.messages[0].content[0].signature, "sig", "signature untouched (documented tradeoff)");

  const p8: any = { model: "x", messages: [{ role: "assistant", content: [{ reasoningContent: { reasoningText: { text: `think ${secret}` } }, text: "ok" }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p8 }, { cwd: tmp });
  assert.equal(p8.messages[0].content[0].reasoningContent.reasoningText.text, "think __SECRET_K__", "bedrock reasoningText masked");
});

test("extension: Mistral camelCase toolCalls, chat custom.input, image-like freeform JSON", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "K=mistral_secret_value1234\n");
  const { pi } = await loadExtension(tmp, { mode: "auto" });
  const handlers = pi.handlers.get("before_provider_request")!;
  const secret = "mistral_secret_value1234";
  await handlers[0]({ type: "before_provider_request", payload: { model: "x", messages: [] } }, { cwd: tmp });

  // Mistral: camelCase toolCalls[].function.arguments (P0-9)
  const p1: any = { model: "x", messages: [{ role: "assistant", content: "", toolCalls: [{ id: "t1", type: "function", function: { name: "f", arguments: `{"k":"${secret}"}` } }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p1 }, { cwd: tmp });
  assert.ok(JSON.stringify(p1).includes("__SECRET_K__"), "mistral toolCalls masked");
  assert.equal(JSON.stringify(p1).includes(secret), false, "no plaintext in mistral toolCalls");

  // OpenAI Chat custom tool call (P0-18)
  const p2: any = { model: "x", messages: [{ role: "assistant", content: null, tool_calls: [{ id: "t2", type: "custom", custom: { name: "f", input: secret } }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p2 }, { cwd: tmp });
  assert.equal(p2.messages[0].tool_calls[0].custom.input, "__SECRET_K__", "custom.input masked");

  // Anthropic tool_use.input with image-like nested object must NOT skip (P0-10)
  const p3: any = { model: "x", messages: [{ role: "assistant", content: [{ type: "tool_use", id: "t3", name: "f", input: { source: { type: "url", url: "https://x" }, key: secret } }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p3 }, { cwd: tmp });
  assert.equal(p3.messages[0].content[0].input.key, "__SECRET_K__", "tool_use.input masked even with image-like sibling");
  assert.equal(p3.messages[0].content[0].input.source.url, "https://x", "url field untouched");

  // Mistral thinking array (P0-19)
  const p4: any = { model: "x", messages: [{ role: "assistant", content: [{ type: "thinking", thinking: [{ text: `think ${secret}` }] }, { type: "text", text: "ok" }] }] };
  for (const h of handlers) await h({ type: "before_provider_request", payload: p4 }, { cwd: tmp });
  assert.equal(p4.messages[0].content[0].thinking[0].text, "think __SECRET_K__", "mistral thinking array text masked");
});

// Regressions for ordinary Hub settings being treated as secret capabilities.
test("extension: public dotenv settings stay readable and do not request confirmation", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), [
    "PAPER_HUB_PORT=8123", "CODEXBAR_BIN=usage-cli", "PROVIDERS=alpha,beta",
    "TODOS_PATH=tasks.md", "CACHE_DIR=/tmp/hub-cache", "PAPER_CACHE_TTL=60",
    "PAPER_TOKEN=actual-token-value", "UNCLASSIFIED=unknown-value",
  ].join("\n"));
  const { pi } = await loadExtension(tmp, { mode: "ask" });
  const payload = { text: "8123 usage-cli alpha,beta tasks.md /tmp/hub-cache 60 actual-token-value unknown-value" };
  await pi.handlers.get("before_provider_request")![0]({ payload }, { cwd: tmp });
  assert.equal(payload.text, "8123 usage-cli alpha,beta tasks.md /tmp/hub-cache 60 __SECRET_PAPER_TOKEN__ __SECRET_UNCLASSIFIED__");
  let confirmations = 0;
  const ctx = { hasUI: true, ui: { confirm: async () => { confirmations++; return true; } } };
  const event = { toolName: "write", input: { path: "/tmp/config", content: payload.text.split(" __SECRET_PAPER_TOKEN__")[0] } };
  await pi.handlers.get("tool_call")![0](event, ctx);
  assert.equal(confirmations, 0);
});

test("extension: sensitive names and key-shaped values override public dotenv types", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  const key = "sk-" + "a".repeat(30);
  writeFileSync(join(tmp, ".env"), [
    "API_KEY_PATH=/private/key-file", "TOKEN_PORT=8124", `TOOL_BIN=${key}`,
    "CUSTOM_BIN=custom-credential", "SERVICE_PORT=not-a-port",
  ].join("\n"));
  const { pi } = await loadExtension(tmp, {
    mode: "ask", customPatterns: [{ name: "CUSTOM", pattern: "custom-credential" }],
  });
  const payload = { text: `/private/key-file 8124 ${key} custom-credential not-a-port` };
  await pi.handlers.get("before_provider_request")![0]({ payload }, { cwd: tmp });
  assert.equal(payload.text, "__SECRET_API_KEY_PATH__ __SECRET_TOKEN_PORT__ __SECRET_TOOL_BIN__ __SECRET_CUSTOM_BIN__ __SECRET_SERVICE_PORT__");
});

test("extension: explicit registration still protects public-looking dotenv values", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "APP_PORT=8125\n");
  const { pi } = await loadExtension(tmp, { mode: "ask", extraSecrets: [{ name: "PIN", value: "8125" }] });
  const payload = { text: "8125" };
  await pi.handlers.get("before_provider_request")![0]({ payload }, { cwd: tmp });
  assert.equal(payload.text, "__SECRET_PIN__");
  const event = { toolName: "bash", input: { command: "use __SECRET_PIN__" } };
  const result = await pi.handlers.get("tool_call")![0](event, { hasUI: false });
  assert.equal(result?.block, true, "real registered secrets still require approval");
  assert.equal(event.input.command, "use __SECRET_PIN__", "denied inputs remain masked");
});

test("extension: ask only confirms placeholders that will actually be restored", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  const { pi } = await loadExtension(tmp, {
    mode: "ask", extraSecrets: [{ name: "SAFE_CAP", value: "safe-value" }, { name: "UNSAFE_CAP", value: "unsafe value" }],
  });
  let confirmations = 0;
  const ctx = { hasUI: true, ui: { confirm: async () => { confirmations++; return true; } } };
  const call = pi.handlers.get("tool_call")![0];
  for (const command of ["echo __SECRET_SAFE_CAP__suffix", "echo prefix__SECRET_UNSAFE_CAP__", "echo __SECRET_UNKNOWN__"]) {
    const event = { toolName: "bash", input: { command } };
    assert.equal(await call(event, ctx), undefined);
    assert.equal(event.input.command, command);
  }
  for (const toolName of ["write", "edit"]) {
    const event = { toolName, input: { path: "/tmp/x", content: "prefix__SECRET_SAFE_CAP__suffix" } };
    assert.equal(await call(event, ctx), undefined);
    assert.equal(event.input.content, "prefix__SECRET_SAFE_CAP__suffix");
  }
  assert.equal(confirmations, 0, "no confirmation when no full token is restored");

  const mixed = { toolName: "bash", input: { command: "use __SECRET_SAFE_CAP__ prefix__SECRET_UNSAFE_CAP__" } };
  assert.equal(await call(mixed, ctx), undefined);
  assert.equal(mixed.input.command, "use safe-value prefix__SECRET_UNSAFE_CAP__");
  assert.equal(confirmations, 1, "confirm the real use, not the embedded unsafe name");

  const unsafe = { toolName: "bash", input: { command: "use __SECRET_UNSAFE_CAP__" } };
  assert.equal((await call(unsafe, ctx))?.block, true, "full unsafe token remains blocked");
});

test("extension: write/edit real placeholders still require approval and preserve input when denied", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  const { pi } = await loadExtension(tmp, { mode: "ask", extraSecrets: [{ name: "CAP", value: "protected-value" }] });
  const call = pi.handlers.get("tool_call")![0];
  for (const toolName of ["write", "edit"]) {
    const input = toolName === "write"
      ? { path: "/tmp/x", content: "value=__SECRET_CAP__" }
      : { path: "/tmp/x", oldText: "__SECRET_CAP__", newText: "__SECRET_CAP__ updated" };
    const event = { toolName, input: { ...input } };
    assert.equal((await call(event, { hasUI: false }))?.block, true);
    assert.deepEqual(event.input, input);
    let confirmations = 0;
    const result = await call(event, { hasUI: true, ui: { confirm: async () => { confirmations++; return true; } } });
    assert.equal(result, undefined);
    assert.equal(confirmations, 1);
    assert.equal(JSON.stringify(event.input).includes("protected-value"), true);
    assert.equal(JSON.stringify(event.input).includes("__SECRET_CAP__"), false);
  }
});

test("extension: hashline replace/insert restore placeholders (only for file-editing tools)", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  writeFileSync(join(tmp, ".env"), "AUTHKEY=real-auth-key-value\n");
  const { pi } = await loadExtension(tmp, { mode: "auto", writeTools: ["custom_writer"] });
  for (const h of pi.handlers.get("before_provider_request") ?? []) {
    await h({ type: "before_provider_request", payload: { model: "x", text: "" } }, { cwd: tmp });
  }
  const call = pi.handlers.get("tool_call")![0];

  // hashline `insert`: `text` is written into the file, so it must be unmasked.
  const insert = { toolName: "insert", input: { anchor: "AAaa", direction: "after", text: '"key": "__SECRET_AUTHKEY__"' } };
  assert.equal(await call(insert, {}), undefined);
  assert.equal(insert.input.text, '"key": "real-auth-key-value"', "insert text restored");

  // hashline `replace`: same, and anchors must stay untouched.
  const replace = { toolName: "replace", input: { remove_from: "AAaa", remove_to: "BBbb", text: '__SECRET_AUTHKEY__' } };
  assert.equal(await call(replace, {}), undefined);
  assert.equal(replace.input.text, "real-auth-key-value");
  assert.equal(replace.input.remove_from, "AAaa");

  // Config-registered extra write tools behave the same.
  const custom = { toolName: "custom_writer", input: { path: "/tmp/x", body: "__SECRET_AUTHKEY__" } };
  assert.equal(await call(custom, {}), undefined);
  assert.equal(custom.input.body, "real-auth-key-value");

  // Tools that are not file editors keep the placeholder: no accidental restore.
  const other = { toolName: "remote_send", input: { body: "__SECRET_AUTHKEY__" } };
  assert.equal(await call(other, {}), undefined);
  assert.equal(other.input.body, "__SECRET_AUTHKEY__");
});

test("extension: ask dialog offers once / session / permanent allow and deny", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  const { pi } = await loadExtension(tmp, { mode: "ask", extraSecrets: [{ name: "CAP", value: "protected-value" }] });
  const call = pi.handlers.get("tool_call")![0];

  // "Allow once" approves this call only: the next call asks again.
  let asks = 0;
  const once = { hasUI: true, ui: { select: async () => { asks++; return "Allow once"; } } };
  let ev = { toolName: "bash", input: { command: "echo __SECRET_CAP__" } };
  assert.equal(await call(ev, once), undefined);
  assert.equal(ev.input.command, "echo protected-value");
  ev = { toolName: "bash", input: { command: "echo __SECRET_CAP__" } };
  assert.equal(await call(ev, once), undefined);
  assert.equal(asks, 2, "once does not grant a session");

  // Deny blocks and keeps the masked input.
  const deny = { hasUI: true, ui: { select: async () => "Deny" } };
  const denied = { toolName: "write", input: { path: "/tmp/x", content: "__SECRET_CAP__" } };
  assert.equal((await call(denied, deny))?.block, true);
  assert.equal(denied.input.content, "__SECRET_CAP__");

  // "Allow for this session" stops asking for later calls, in any tool.
  let sessionAsks = 0;
  const session = { hasUI: true, ui: { select: async () => { sessionAsks++; return "Allow for this session (until Pi restarts)"; }, notify: () => {} } };
  ev = { toolName: "bash", input: { command: "echo __SECRET_CAP__" } };
  assert.equal(await call(ev, session), undefined);
  assert.equal(ev.input.command, "echo protected-value");
  const insert = { toolName: "insert", input: { anchor: "AAaa", direction: "after", text: "__SECRET_CAP__" } };
  assert.equal(await call(insert, { hasUI: false }), undefined, "session grant needs no UI");
  assert.equal(insert.input.text, "protected-value");
  assert.equal(sessionAsks, 1);
});

test("extension: permanent allow persists mode=auto and keeps other config", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "psm-ext-"));
  t.after(() => rmSync(tmp, { recursive: true, force: true }));
  const { pi, home } = await loadExtension(tmp, {
    mode: "ask",
    allowCommands: ["^ls"],
    extraSecrets: [{ name: "CAP", value: "protected-value" }],
  });
  const call = pi.handlers.get("tool_call")![0];
  const notified: string[] = [];
  const ctx = {
    hasUI: true,
    ui: { select: async () => "Always allow (save mode=auto to config)", notify: (message: string) => notified.push(message) },
  };
  const ev = { toolName: "write", input: { path: "/tmp/x", content: "__SECRET_CAP__" } };
  assert.equal(await call(ev, ctx), undefined);
  assert.equal(ev.input.content, "protected-value");

  const saved = JSON.parse(readFileSync(join(home, ".pi", "agent", "extensions", "pi-secret-mask", "config.json"), "utf-8"));
  assert.equal(saved.mode, "auto", "mode persisted for future sessions");
  assert.deepEqual(saved.allowCommands, ["^ls"], "unrelated settings survive the rewrite");
  assert.equal(saved.extraSecrets[0].name, "CAP");
  assert.match(notified[0] ?? "", /mode=auto/);

  // No further prompts, even in a non-UI context.
  const next = { toolName: "bash", input: { command: "echo __SECRET_CAP__" } };
  assert.equal(await call(next, { hasUI: false }), undefined);
  assert.equal(next.input.command, "echo protected-value");
});
