import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";

const tempHome = await mkdtemp(join(tmpdir(), "pi-secret-mask-integration-"));
process.env.HOME = tempHome;
after(async () => rm(tempHome, { recursive: true, force: true }));
const userDir = join(tempHome, ".pi", "agent", "extensions", "pi-secret-mask");
await mkdir(userDir, { recursive: true });
await writeFile(
  join(userDir, "config.json"),
  JSON.stringify({
    mode: "auto",
    dotenv: { enabled: false },
    toolResolution: {
      enabled: true,
      includeDefaults: true,
      unknownHandle: "block",
      rules: [{ tool: "browser_fill", paths: ["value"] }],
    },
  }),
);

const { default: registerExtension } = await import("../extensions/pi-secret-mask.ts");

function createMockPi() {
  const handlers = new Map();
  const tools = new Map();
  const commands = new Map();
  return {
    handlers,
    tools,
    commands,
    on(name, handler) {
      handlers.set(name, handler);
    },
    registerTool(tool) {
      tools.set(tool.name, tool);
    },
    registerCommand(name, command) {
      commands.set(name, command);
    },
  };
}

function secureUi(value) {
  return {
    mode: "tui",
    hasUI: true,
    ui: {
      custom: async (factory) => {
        let result;
        const component = factory(
          { requestRender() {} },
          { fg: (_style, text) => text },
          {},
          (captured) => {
            result = captured;
          },
        );
        component.focused = true;
        component.handleInput(value);
        component.handleInput("\r");
        return result;
      },
      confirm: async () => true,
      notify() {},
    },
  };
}

test("request_secret -> explicit handle -> configured tool -> result redaction", async () => {
  const pi = createMockPi();
  registerExtension(pi);

  const request = pi.tools.get("request_secret");
  assert.ok(request);
  const result = await request.execute(
    "call-1",
    { name: "CLOUDFLARE_PASSWORD", purpose: "Cloudflare login" },
    undefined,
    undefined,
    secureUi("actual-password-123"),
  );
  const message = result.content[0].text;
  assert.match(message, /__SECRET_CLOUDFLARE_PASSWORD__/);
  assert.doesNotMatch(message, /actual-password-123/);

  const toolEvent = {
    toolName: "browser_fill",
    input: { selector: "#password", value: "__SECRET_CLOUDFLARE_PASSWORD__" },
  };
  const blocked = await pi.handlers.get("tool_call")(toolEvent, secureUi("unused"));
  assert.equal(blocked, undefined);
  assert.equal(toolEvent.input.value, "actual-password-123");

  const toolResult = { content: [{ type: "text", text: "submitted actual-password-123" }] };
  pi.handlers.get("tool_result")(toolResult);
  assert.equal(toolResult.content[0].text, "submitted __SECRET_CLOUDFLARE_PASSWORD__");

  const providerEvent = {
    payload: { messages: [{ role: "user", content: "value=actual-password-123" }] },
  };
  const providerCtx = { cwd: process.cwd(), abort() { throw new Error("unexpected abort"); } };
  pi.handlers.get("before_provider_request")(providerEvent, providerCtx);
  assert.equal(providerEvent.payload.messages[0].content, "value=__SECRET_CLOUDFLARE_PASSWORD__");
});

test("unconfigured tool paths fail closed", async () => {
  const pi = createMockPi();
  registerExtension(pi);
  const request = pi.tools.get("request_secret");
  await request.execute("call-2", { name: "SECOND_TOKEN" }, undefined, undefined, secureUi("second-token-456"));

  const event = { toolName: "browser_fill", input: { selector: "__SECRET_SECOND_TOKEN__", value: "plain" } };
  const result = await pi.handlers.get("tool_call")(event, secureUi("unused"));
  assert.equal(result.block, true);
  assert.match(result.reason, /not authorized/);
});

test.after(async () => {
  await rm(tempHome, { recursive: true, force: true });
});

test("placeholder-shaped captured input receives a new handle and persisted reuse confirms", async () => {
  const pi = createMockPi();
  registerExtension(pi);
  const request = pi.tools.get("request_secret");
  const raw = "__" + "SECRET_LITERAL__";
  const first = await request.execute("call-raw", { name: "RAW_LITERAL" }, undefined, undefined, secureUi(raw));
  const handle = first.details.handle;
  assert.notEqual(handle, raw);

  let confirms = 0;
  const reused = await request.execute("call-reuse", { name: "RAW_LITERAL" }, undefined, undefined, {
    mode: "tui",
    hasUI: true,
    ui: {
      confirm: async () => { confirms++; return true; },
      custom: async () => { throw new Error("existing credential must not prompt for plaintext"); },
    },
  });
  assert.equal(confirms, 1);
  assert.equal(reused.details.handle, handle);
});

test("tool-result details redact ordinary data fields without touching image payloads", async () => {
  const pi = createMockPi();
  registerExtension(pi);
  const request = pi.tools.get("request_secret");
  await request.execute("call-details", { name: "DETAIL_TOKEN" }, undefined, undefined, secureUi("detail-secret-789"));
  const event = {
    content: { text: "detail-secret-789" },
    details: {
      data: "detail-secret-789",
      nested: { message: "detail-secret-789" },
      image: { type: "image", data: "detail-secret-789" },
    },
  };
  pi.handlers.get("tool_result")(event);
  assert.equal(event.content.text, "__" + "SECRET_DETAIL_TOKEN__");
  assert.equal(event.details.data, "__" + "SECRET_DETAIL_TOKEN__");
  assert.equal(event.details.nested.message, "__" + "SECRET_DETAIL_TOKEN__");
  assert.equal(event.details.image.data, "detail-secret-789");
});

test("provider string input and free-form object keys are redacted", async () => {
  const pi = createMockPi();
  registerExtension(pi);
  const request = pi.tools.get("request_secret");
  await request.execute("call-provider-keys", { name: "PROVIDER_TOKEN" }, undefined, undefined, secureUi("provider-secret-123"));
  const handle = "__" + "SECRET_PROVIDER_TOKEN__";

  const providerEvent = { payload: { input: "value=provider-secret-123" } };
  pi.handlers.get("before_provider_request")(providerEvent, { cwd: process.cwd() });
  assert.equal(providerEvent.payload.input, `value=${handle}`);

  const toolInputEvent = {
    payload: {
      messages: [{
        role: "user",
        content: [{ type: "tool_use", input: { ["provider-secret-123"]: "ok" } }],
      }],
    },
  };
  pi.handlers.get("before_provider_request")(toolInputEvent, { cwd: process.cwd() });
  const toolInput = toolInputEvent.payload.messages[0].content[0].input;
  assert.equal(Object.hasOwn(toolInput, "provider-secret-123"), false);
  assert.equal(toolInput[handle], "ok");
});

test("tool-result content and details redact free-form object keys", async () => {
  const pi = createMockPi();
  registerExtension(pi);
  const request = pi.tools.get("request_secret");
  await request.execute("call-result-keys", { name: "RESULT_TOKEN" }, undefined, undefined, secureUi("result-secret-456"));
  const handle = "__" + "SECRET_RESULT_TOKEN__";

  const event = {
    content: { ["result-secret-456"]: "content" },
    details: { ["result-secret-456"]: "details" },
  };
  pi.handlers.get("tool_result")(event);
  assert.equal(Object.hasOwn(event.content, "result-secret-456"), false);
  assert.equal(event.content[handle], "content");
  assert.equal(Object.hasOwn(event.details, "result-secret-456"), false);
  assert.equal(event.details[handle], "details");
});

test("tool-result content arrays redact arbitrary keys without rewriting block structure", async () => {
  const pi = createMockPi();
  registerExtension(pi);
  const request = pi.tools.get("request_secret");
  await request.execute("call-result-array", { name: "ARRAY_TOKEN" }, undefined, undefined, secureUi("array-secret-456"));
  const handle = "__" + "SECRET_ARRAY_TOKEN__";

  const event = {
    content: [{ type: "text", text: "safe", ["array-secret-456"]: "value" }],
  };
  pi.handlers.get("tool_result")(event);
  assert.equal(event.content[0].type, "text");
  assert.equal(Object.hasOwn(event.content[0], "array-secret-456"), false);
  assert.equal(event.content[0][handle], "value");
});

test("Gemini function responses redact arbitrary nested JSON and keys", async () => {
  const pi = createMockPi();
  registerExtension(pi);
  const request = pi.tools.get("request_secret");
  await request.execute("call-gemini-response", { name: "GEMINI_TOKEN" }, undefined, undefined, secureUi("gemini-secret-456"));
  const handle = "__" + "SECRET_GEMINI_TOKEN__";
  const event = {
    payload: {
      contents: [{
        role: "user",
        parts: [{
          functionResponse: {
            name: "lookup",
            response: {
              nested: { token: "gemini-secret-456" },
              ["gemini-secret-456"]: "key-value",
            },
          },
        }],
      }],
    },
  };

  pi.handlers.get("before_provider_request")(event, { cwd: process.cwd() });
  const response = event.payload.contents[0].parts[0].functionResponse.response;
  assert.equal(event.payload.contents[0].parts[0].functionResponse.name, "lookup");
  assert.equal(response.nested.token, handle);
  assert.equal(Object.hasOwn(response, "gemini-secret-456"), false);
  assert.equal(response[handle], "key-value");
  assert.equal(JSON.stringify(event.payload).includes("gemini-secret-456"), false);
});
