/**
 * pi-secret-mask extension entry point.
 *
 * Prevents secrets from leaking to LLM providers:
 * - before_provider_request: real values -> placeholders across model-facing text payloads
 * - tool_call: bash command placeholders -> real values (auto/ask policy)
 * - tool_result: real values in tool output -> placeholders (prevents reflow)
 * - session_before_compact / session_before_tree: summary messages masked too
 * - /mask-secret: register a secret from user input; agent only sees placeholder
 * - request_secret tool: agent-initiated secret request; agent only sees placeholder
 *
 * Config: ~/.pi/agent/extensions/pi-secret-mask/config.json takes precedence,
 * falling back to a config.json next to this file.
 */
import { existsSync, readFileSync, statSync, writeFileSync, mkdirSync, chmodSync, renameSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { Type } from "typebox";
import { homedir } from "os";
import {
  DEFAULT_MASK_OPTIONS,
  MaskMap,
  collectSecretsFromText,
  loadDotenvPaths,
  maskDeepFreeform,
  maskDeepFreeformKeys,
  registerSources,
  type MaskOptions,
} from "../src/mask-engine.ts";
import { MaskedSecretInput } from "../src/masked-secret-input.ts";
import {
  assertShellSafeHandles,
  containsSecretHandle,
  planToolSecretResolution,
  SecretResolutionError,
  type ToolResolutionConfig,
  type ToolResolutionRule,
} from "../src/tool-secret-resolver.ts";

interface Config {
  mode?: "auto" | "ask";
  allowCommands?: string[];
  dotenv?: Partial<MaskOptions["dotenv"]>;
  patterns?: Partial<MaskOptions["patterns"]>;
  extraSecrets?: { name: string; value: string }[];
  customPatterns?: { name: string; pattern: string; flags?: string }[];
  base64MinLength?: number;
  toolResolution?: ToolResolutionConfig;
}

const CONFIG_FILE = join(dirname(fileURLToPath(import.meta.url)), "config.json");
/** User config dir takes precedence after npm install (survives pi update). */
const USER_CONFIG_FILE = join(homedir(), ".pi/agent/extensions/pi-secret-mask/config.json");
/** Secrets registered via /mask-secret, persisted in the user config dir. */
const USER_SECRETS_FILE = join(homedir(), ".pi/agent/extensions/pi-secret-mask/secrets.json");

const AGENT_GUIDANCE = `Secret-mask agent rules:
- A __SECRET_*__ token shown in a tool result or returned by request_secret is a redacted alias, not proof that the literal token is on disk. The underlying value may come from .env, automatic detection, or persisted registration; absence of secrets.json does not prove it is unavailable.
- If secret-mask produced a placeholder in this session, use it directly in bash commands and write/edit inputs. The extension restores the real value immediately before those local tools execute, and masks it again in tool output. A file read showing __SECRET_*__ is therefore a redacted view; do not replace the real value with the literal placeholder or conclude the config is invalid.
- Never print, echo, or otherwise expose a real secret, and do not invent placeholder names. Validate an existing credential through the intended local operation using its placeholder.
- Call request_secret only when the task genuinely needs a secret and no usable placeholder or existing local credential is available. Do not call it again for a placeholder already present. Ask only for the minimum secret name and purpose; after it returns, use the placeholder, never the real value.
- If a placeholder is unknown or an operation reports invalid credentials, report that result or request a new secret; do not infer from masked output or search for secrets.json.`;

// These names carry content-block structure rather than user data. Key-only
// fallback masking preserves them after schema-aware block fields are handled.
const CONTENT_BLOCK_STRUCTURAL_KEYS = new Set([
  "type", "role", "name", "id", "call_id", "tool_call_id", "tool_use_id",
  "status", "signature", "mimeType", "media_type",
]);

function loadConfig(): Config {
  for (const path of [USER_CONFIG_FILE, CONFIG_FILE]) {
    try {
      if (existsSync(path)) {
        return JSON.parse(readFileSync(path, "utf-8")) as Config;
      }
    } catch {
      // Corrupt config: try the next candidate.
    }
  }
  return {};
}

/** Validate config shape; invalid security-relevant fields fall back to safe defaults. */
function validateConfig(raw: unknown): Config {
  const cfg = (raw && typeof raw === "object" ? raw : {}) as Config;
  const out: Config = {};
  if (cfg.mode === "auto" || cfg.mode === "ask") out.mode = cfg.mode;
  else out.mode = "ask"; // invalid mode -> safe default
  if (Array.isArray(cfg.allowCommands)) out.allowCommands = cfg.allowCommands.filter((x) => typeof x === "string");
  else out.allowCommands = [];
  if (cfg.dotenv && typeof cfg.dotenv === "object") {
    const d = cfg.dotenv;
    const nd: NonNullable<Config["dotenv"]> = {};
    if (typeof d.enabled === "boolean") nd.enabled = d.enabled;
    if (Array.isArray(d.files)) nd.files = d.files.filter((x) => typeof x === "string");
    if (Array.isArray(d.exclude)) nd.exclude = d.exclude.filter((x) => typeof x === "string");
    if (Object.keys(nd).length > 0) out.dotenv = nd;
  }
  if (cfg.patterns && typeof cfg.patterns === "object") {
    const p = cfg.patterns as Record<string, unknown>;
    const np: NonNullable<Config["patterns"]> = {};
    for (const key of ["openai", "github", "google", "aws", "jwt", "pem", "base64"] as const) {
      if (typeof p[key] === "boolean") np[key] = p[key];
    }
    if (Object.keys(np).length > 0) out.patterns = np;
  }
  if (Array.isArray(cfg.extraSecrets)) {
    out.extraSecrets = cfg.extraSecrets.filter(
      (e): e is { name: string; value: string } =>
        !!e && typeof e === "object" && typeof (e as { name?: unknown }).name === "string" && typeof (e as { value?: unknown }).value === "string",
    );
  }
  if (Array.isArray(cfg.customPatterns)) {
    out.customPatterns = cfg.customPatterns.filter(
      (c): c is { name: string; pattern: string; flags?: string } =>
        !!c && typeof c === "object" && typeof (c as { name?: unknown }).name === "string" && typeof (c as { pattern?: unknown }).pattern === "string" &&
        ((c as { flags?: unknown }).flags === undefined || typeof (c as { flags?: unknown }).flags === "string"),
    );
  }
  if (typeof cfg.base64MinLength === "number" && Number.isFinite(cfg.base64MinLength) && cfg.base64MinLength > 0) {
    out.base64MinLength = cfg.base64MinLength;
  }
  if (cfg.toolResolution && typeof cfg.toolResolution === "object") {
    const resolution = cfg.toolResolution as Record<string, unknown>;
    const rules: ToolResolutionRule[] = [];
    if (Array.isArray(resolution.rules)) {
      for (const candidate of resolution.rules) {
        if (!candidate || typeof candidate !== "object") continue;
        const rule = candidate as Record<string, unknown>;
        if (typeof rule.tool !== "string" || !Array.isArray(rule.paths)) continue;
        const paths = rule.paths.filter((path): path is string => typeof path === "string" && path.length > 0);
        if (paths.length === 0 || (rule.adapter !== undefined && rule.adapter !== "text" && rule.adapter !== "json")) continue;
        rules.push({ tool: rule.tool, paths, adapter: rule.adapter as ToolResolutionRule["adapter"] });
      }
    }
    out.toolResolution = {
      enabled: typeof resolution.enabled === "boolean" ? resolution.enabled : true,
      includeDefaults: typeof resolution.includeDefaults === "boolean" ? resolution.includeDefaults : true,
      // Unknown handles remain blocked even if an old config requested ignore.
      unknownHandle: "block",
      rules,
    };
  }
  return out;
}

function mergeOptions(config: Config): MaskOptions {
  return {
    ...DEFAULT_MASK_OPTIONS,
    extraSecrets: config.extraSecrets ?? DEFAULT_MASK_OPTIONS.extraSecrets,
    customPatterns: config.customPatterns ?? DEFAULT_MASK_OPTIONS.customPatterns,
    base64MinLength: config.base64MinLength ?? DEFAULT_MASK_OPTIONS.base64MinLength,
    dotenv: { ...DEFAULT_MASK_OPTIONS.dotenv, ...(config.dotenv ?? {}) },
    patterns: { ...DEFAULT_MASK_OPTIONS.patterns, ...(config.patterns ?? {}) },
  };
}

export default function (pi: any) {
  const config = validateConfig(loadConfig());
  const options = mergeOptions(config);
  const mode = config.mode ?? "ask";
  const allowCommands = config.allowCommands ?? [];
  const resolutionConfig: ToolResolutionConfig = {
    enabled: config.toolResolution?.enabled ?? true,
    includeDefaults: config.toolResolution?.includeDefaults ?? true,
    unknownHandle: "block",
    rules: config.toolResolution?.rules ?? [],
  };

  const map = new MaskMap();
  let dotenvMtimes = new Map<string, number>();
  /** Tracks every source that contributed each secret: "dotenv" | "user" | "extra" | "regex:<name>". */
  const secretSources = new Map<string, Set<string>>();
  // Secrets registered via /mask-secret (only these are persisted).
  const userSecrets = new Map<string, string>(); // name -> value

  // Extra secrets from config.
  for (const { name, value } of options.extraSecrets) {
    if (value) {
      map.add(value, name);
      addSource(value, "extra");
    }
  }

  // Load persisted user secrets.
  function loadUserSecrets(): void {
    try {
      if (existsSync(USER_SECRETS_FILE)) {
        const data = JSON.parse(readFileSync(USER_SECRETS_FILE, "utf-8")) as { name: string; value: string }[];
        for (const { name, value } of data) {
          if (value) {
            userSecrets.set(name, value);
            map.addRaw(value, name);
            addSource(value, `user:${name}`);
          }
        }
      }
    } catch {
      // Ignore corrupt secrets.json.
    }
  }
  loadUserSecrets();

  function saveUserSecrets(): void {
    try {
      const dir = dirname(USER_SECRETS_FILE);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      const data = [...userSecrets.entries()].map(([name, value]) => ({ name, value }));
      // Atomic write: temp file + rename + explicit chmod (P1-7).
      const tmp = USER_SECRETS_FILE + ".tmp" + process.pid;
      writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
      chmodSync(tmp, 0o600);
      renameSync(tmp, USER_SECRETS_FILE);
    } catch {
      // Persistence failure must not block the session.
    }
  }

  /** Record that a secret comes from an additional source. */
  function addSource(secret: string, source: string): void {
    let set = secretSources.get(secret);
    if (!set) {
      set = new Set();
      secretSources.set(secret, set);
    }
    set.add(source);
  }

  /** Drop one source; remove the secret from the map when no sources remain. */
  function dropSource(secret: string, source: string): void {
    const set = secretSources.get(secret);
    if (!set) return;
    set.delete(source);
    if (set.size === 0) {
      secretSources.delete(secret);
      map.remove(secret);
    }
  }

  /** Register a user secret under a name; re-registering the same name drops the old value's user source (P1-10). */
  function registerUserSecret(name: string, value: string): string {
    const prev = userSecrets.get(name);
    if (prev !== undefined && prev !== value) {
      // Old value keeps other sources (dotenv/extra/regex/seen) but loses "user".
      dropSource(prev, `user:${name}`);
    }
    userSecrets.set(name, value);
    const ph = map.addRaw(value, name);
    addSource(value, `user:${name}`);
    saveUserSecrets();
    return ph;
  }

  function refreshDotenv(baseDir: string): void {
    if (!options.dotenv.enabled) return;
    const files = options.dotenv.files.filter((f) => !options.dotenv.exclude.includes(f));
    const seen = new Set<string>();
    const scanned = new Map<string, number>(); // path -> mtime observed this pass
    for (const file of files) {
      const path = join(baseDir, file);
      if (!existsSync(path)) continue;
      seen.add(path);
      let mtime: number;
      try {
        mtime = statSync(path).mtimeMs;
      } catch {
        continue;
      }
      scanned.set(path, mtime);
    }
    // A file that disappeared is a change; detect it, but do NOT commit
    // anything yet — commit only after a successful read (P0-3).
    let changed = false;
    for (const [path, mtime] of dotenvMtimes) {
      if (!seen.has(path)) changed = true;
    }
    for (const [path, mtime] of scanned) {
      if (dotenvMtimes.get(path) !== mtime) changed = true;
    }
    if (!changed) return;
    let entries: Map<string, string>;
    try {
      // Read exactly the paths seen during scanning, unconditionally:
      // a vanished file throws and aborts the whole refresh (P0-3 TOCTOU).
      entries = loadDotenvPaths({ readFileSync }, [...scanned.keys()], options.dotenv);
    } catch {
      // .env changed but is unreadable: keep the old mapping (do NOT commit
      // mtime, so we retry next request; never abort the provider hook).
      return;
    }
    // All reads succeeded: commit the observed state in one shot.
    for (const [path, mtime] of dotenvMtimes) {
      if (!seen.has(path)) dotenvMtimes.delete(path);
    }
    for (const [path, mtime] of scanned) {
      dotenvMtimes.set(path, mtime);
    }
    // Add new .env secrets; drop .env source from secrets that are no longer
    // provided. Secrets with other remaining sources (user/extra/regex/seen) stay.
    for (const [key, value] of entries) {
      if (!map.has(value)) {
        map.add(value, key);
        addSource(value, "dotenv");
      } else {
        addSource(value, "dotenv");
      }
    }
    // Remove the dotenv source from secrets that are no longer in .env.
    const entryValues = new Set(entries.values());
    for (const [secret, sources] of [...secretSources]) {
      if (sources.has("dotenv") && !entryValues.has(secret)) {
        dropSource(secret, "dotenv");
      }
    }
  }

  function maskMessages(messages: any[]): void {
    for (const m of messages) {
      if (!m) continue;
      if (typeof m.content === "string") {
        // Some providers use plain-string content (P0-2).
        m.content = maskText(m.content);
      } else if (Array.isArray(m.content)) {
        maskBlocks(m.content);
      } else if (m.content && typeof m.content === "object" && Array.isArray(m.content.parts)) {
        maskBlocks(m.content.parts);
      } else if (Array.isArray(m.parts)) {
        // Gemini contents[]: { role, parts: [...] }.
        maskBlocks(m.parts);
      } else if (m.type === "function_call_output" || m.type === "custom_tool_call_output") {
        // OpenAI Responses input blocks (P0-9/P0-N4): output may be a string
        // or an input_text array. Grammar-tool paths use custom_tool_call_output.
        if (typeof m.output === "string") {
          m.output = maskText(m.output);
        } else if (Array.isArray(m.output)) {
          for (let i = 0; i < m.output.length; i++) {
            const item = m.output[i];
            if (item && typeof item === "object" && typeof item.text === "string") item.text = maskText(item.text);
            else if (typeof item === "string") m.output[i] = maskText(item);
          }
        }
      } else if (m.type === "function_call" && typeof m.arguments === "string") {
        // Function arguments are JSON text that may embed secrets.
        m.arguments = maskText(m.arguments);
      } else if (m.type === "message" && Array.isArray(m.content)) {
        maskBlocks(m.content);
      }
      // Coding-agent message variants stored in sessions (P0-3/4/7):
      // bashExecution.command/output, branchSummary.summary,
      // compactionSummary.summary.
      if (m.role === "bashExecution") {
        if (typeof m.command === "string") m.command = maskText(m.command);
        if (typeof m.output === "string") m.output = maskText(m.output);
        if (typeof m.fullOutputPath === "string") m.fullOutputPath = maskText(m.fullOutputPath);
      } else if (m.role === "branchSummary" || m.role === "compactionSummary") {
        if (typeof m.summary === "string") m.summary = maskText(m.summary);
      }
      // Provider tool-call arguments (P0-8/9/13): OpenAI Chat / Mistral
      // messages[].tool_calls[].function.arguments, Responses custom_tool_call.input.
      if (Array.isArray(m.tool_calls)) {
        for (const tc of m.tool_calls) {
          if (tc?.function && typeof tc.function.arguments === "string") {
            tc.function.arguments = maskText(tc.function.arguments);
          }
          // OpenAI Chat custom tool call (P0-18).
          if (tc?.custom && typeof tc.custom.input === "string") {
            tc.custom.input = maskText(tc.custom.input);
          }
        }
      }
      // Mistral Conversations uses camelCase toolCalls (P0-9).
      if (Array.isArray(m.toolCalls)) {
        for (const tc of m.toolCalls) {
          if (tc?.function && typeof tc.function.arguments === "string") {
            tc.function.arguments = maskText(tc.function.arguments);
          }
        }
      }
      if (m.type === "custom_tool_call" && typeof m.input === "string") {
        m.input = maskText(m.input);
      }
      // Reasoning fields (P0-14/17): OpenAI Chat reasoning_content/reasoning,
      // Responses reasoning item summary[].text / content[].text.
      if (typeof m.reasoning_content === "string") m.reasoning_content = maskText(m.reasoning_content);
      if (typeof m.reasoning === "string") m.reasoning = maskText(m.reasoning);
      if (typeof m.reasoning_text === "string") m.reasoning_text = maskText(m.reasoning_text);
      if (m.type === "reasoning") {
        if (Array.isArray(m.summary)) {
          for (const s of m.summary) {
            if (s && typeof s === "object" && typeof s.text === "string") s.text = maskText(s.text);
            else if (typeof s === "string") m.summary[m.summary.indexOf(s)] = maskText(s);
          }
        }
        if (Array.isArray(m.content)) {
          for (const c of m.content) {
            if (c && typeof c === "object" && typeof c.text === "string") c.text = maskText(c.text);
          }
        }
      }
    }
  }

  function maskText(text: string): string {
    // Collect new patterns first (keys pasted in prompts, runtime-generated),
    // then mask. Every hit also records a "regex:<name>" source so .env
    // pruning never drops it mid-session.
    const sources = collectSecretsFromText(text, options);
    registerSources(map, sources);
    for (const src of sources) {
      for (const value of src.values) {
        if (map.has(value)) addSource(value, `regex:${src.name}`);
      }
    }
    const masked = map.mask(text);
    // P0-8: any secret that actually matched gets a session-level "seen"
    // source, so history containing it stays masked even if .env rotates.
    if (masked !== text) {
      for (const secret of map.placeholders().map((ph) => map.secretFor(ph)!)) {
        if (secret && text.includes(secret)) addSource(secret, "seen");
      }
    }
    return masked;
  }

  /**
   * Mask known provider text paths (`text`, messages/input/contents/system, and
   * string content). Sweeping the whole payload would corrupt structural fields
   * (role/type/name) when a short .env value collides with them (P1-N1).
   */
  function maskPayload(payload: any): void {
    if (payload == null) return;
    if (typeof payload.text === "string") payload.text = maskText(payload.text);
    // System prompt can be a string (Anthropic/Bedrock), a block array, or
    // Gemini's config.systemInstruction; Codex Responses uses top-level
    // instructions (P0-10).
    if (typeof payload.system === "string") {
      payload.system = maskText(payload.system);
    } else if (Array.isArray(payload.system)) {
      maskBlocks(payload.system);
    }
    if (typeof payload.instructions === "string") {
      payload.instructions = maskText(payload.instructions);
    } else if (Array.isArray(payload.instructions)) {
      for (let i = 0; i < payload.instructions.length; i++) {
        const item = payload.instructions[i];
        if (typeof item === "string") payload.instructions[i] = maskText(item);
        else if (item && typeof item === "object") maskBlocks([item]);
      }
    }
    const si = payload.config?.systemInstruction;
    if (typeof si === "string") {
      payload.config.systemInstruction = maskText(si);
    } else if (si && typeof si === "object" && Array.isArray(si.parts)) {
      maskBlocks(si.parts);
    }
    // OpenAI Responses accepts either a string or an array for input.
    if (typeof payload.input === "string") payload.input = maskText(payload.input);
    for (const key of ["messages", "input", "contents"]) {
      const list = payload[key];
      if (Array.isArray(list)) maskMessages(list);
    }
    // Tool definitions carry descriptions that may embed secrets.
    // OpenAI Chat: tool.function.description; Anthropic/OpenAI Responses: tool.description.
    if (Array.isArray(payload.tools)) {
      for (const tool of payload.tools) {
        if (typeof tool?.description === "string") tool.description = maskText(tool.description);
        if (typeof tool?.function?.description === "string") tool.function.description = maskText(tool.function.description);
      }
    }
  }

  /** Mask text content blocks; only known free-text fields are touched, structural fields stay. */
  function maskBlocks(blocks: any[]): void {
    for (const block of blocks) {
      if (!block || typeof block !== "object") continue;
      if (typeof block.text === "string") {
        block.text = maskText(block.text);
      }
      // Known provider free-text paths (P0-9/P0-11):
      // - OpenAI Responses function_call_output.output (string OR input_text array)
      // - Gemini functionResponse.response.output
      // - Anthropic tool_result.content (string or nested blocks)
      // - Bedrock toolResult.content[].text
      if (typeof block.output === "string") {
        block.output = maskText(block.output);
      } else if (Array.isArray(block.output)) {
        for (let i = 0; i < block.output.length; i++) {
          const item = block.output[i];
          if (item && typeof item === "object" && typeof item.text === "string") {
            item.text = maskText(item.text);
          } else if (typeof item === "string") {
            block.output[i] = maskText(item);
          }
        }
      }
      if (block.functionResponse && typeof block.functionResponse === "object") {
        const fr = block.functionResponse;
        if (typeof fr.response === "object" && fr.response !== null) {
          // Gemini function responses are arbitrary JSON, not only
          // response.output/response.error.
          maskDeepFreeform(fr.response, maskText);
        }
      }
      if (block.response && typeof block.response === "object" && typeof block.response.output === "string") {
        block.response.output = maskText(block.response.output);
      }
      if (typeof block.content === "string") {
        block.content = maskText(block.content);
      } else if (Array.isArray(block.content)) {
        maskBlocks(block.content);
      }
      if (block.toolResult && typeof block.toolResult === "object" && Array.isArray(block.toolResult.content)) {
        maskBlocks(block.toolResult.content);
      }
      // Tool-use input payloads are free-form JSON that may embed secrets
      // (P0-10/11/12): Anthropic tool_use.input, Gemini functionCall.args,
      // Bedrock toolUse.input.
      if (block.type === "tool_use" && block.input && typeof block.input === "object") {
        maskDeepFreeform(block.input, (s) => maskText(s));
      }
      if (block.functionCall && typeof block.functionCall === "object" && block.functionCall.args && typeof block.functionCall.args === "object") {
        maskDeepFreeform(block.functionCall.args, (s) => maskText(s));
      }
      if (block.toolUse && typeof block.toolUse === "object" && block.toolUse.input && typeof block.toolUse.input === "object") {
        maskDeepFreeform(block.toolUse.input, (s) => maskText(s));
      }
      // Mistral Conversations thinking is content[].thinking[].text (P0-19).
      if (Array.isArray(block.thinking)) {
        for (const t of block.thinking) {
          if (t && typeof t === "object" && typeof t.text === "string") t.text = maskText(t.text);
        }
      }
      // Reasoning content (P0-15/16): Anthropic thinking, Bedrock reasoningText.
      if (block.type === "thinking" && typeof block.thinking === "string") {
        block.thinking = maskText(block.thinking);
      }
      if (block.reasoningContent && typeof block.reasoningContent === "object") {
        const rt = block.reasoningContent.reasoningText;
        if (rt && typeof rt === "object" && typeof rt.text === "string") rt.text = maskText(rt.text);
      }
      // Other block types are skipped: their string fields are structural.
    }
  }

  /** Capture only through Pi's TUI custom component; print/json modes fail closed. */
  async function secureInput(ctx: any, name: string, purpose?: string): Promise<string | undefined> {
    if (ctx?.mode !== "tui" || typeof ctx?.ui?.custom !== "function") return undefined;
    return await ctx.ui.custom(
      (tui: any, theme: any, _keybindings: any, done: (value: string | undefined) => void) =>
        new MaskedSecretInput(name, purpose, tui, theme, done),
    );
  }

  // Keep the placeholder contract in the agent's system context. Tool results are
  // intentionally redacted, so the agent otherwise cannot tell a masked file view
  // from a literal placeholder stored on disk.
  pi.on("before_agent_start", (event: any) => ({
    systemPrompt: `${event.systemPrompt}\n\n${AGENT_GUIDANCE}`,
  }));

  pi.on("before_provider_request", (event: any, ctx: any) => {
    try {
      refreshDotenv(ctx?.cwd ?? process.cwd());
      const payload = event.payload as any;
      maskPayload(payload);
      return payload;
    } catch (err) {
      // Fail-closed: abort the request rather than letting unmasked secrets
      // go out. (before_provider_request cannot "reject" — any non-undefined
      // return replaces the payload, so abort the whole turn.)
      ctx?.abort?.();
      return undefined;
    }
  });

  pi.on("tool_call", async (event: any, ctx: any) => {
    if (!containsSecretHandle(event.input)) return;
    if (resolutionConfig.enabled === false) {
      return { block: true, reason: "Blocked by secret-mask: secret-handle resolution is disabled" };
    }

    let plan;
    try {
      plan = planToolSecretResolution(event.toolName, event.input ?? {}, map, resolutionConfig);
      if (!plan) return;
      assertShellSafeHandles(plan, map);
    } catch (error) {
      const message = error instanceof SecretResolutionError ? error.message : "Secret-handle resolution failed";
      ctx?.ui?.notify?.(message, "warning");
      return { block: true, reason: `Blocked by secret-mask: ${message}` };
    }

    let approved = mode === "auto";
    if (!approved && event.toolName === "bash") {
      const command = String(event.input?.command ?? "");
      approved = allowCommands.some((pattern) => {
        try { return command.startsWith(pattern) || new RegExp(pattern).test(command); } catch { return false; }
      });
    }
    if (!approved) {
      const hasUI = ctx?.hasUI ?? Boolean(ctx?.ui?.confirm);
      approved = hasUI && typeof ctx?.ui?.confirm === "function"
        ? await ctx.ui.confirm(
          "Use protected secret?",
          `Tool: ${event.toolName}\nHandles: ${plan.handles.join(", ")}\nAuthorized argument paths: ${plan.paths.join(", ")}\n\nOnly handles are displayed; real values are not rendered.`,
        )
        : false;
    }
    if (!approved) return { block: true, reason: "Blocked by secret-mask: user declined secret-handle use" };
    plan.apply();
  });

  pi.on("tool_result", (event: any) => {
    try {
      // Preserve provider block handling, then cover arbitrary structured
      // details and scalar textual fields without touching image/binary nodes.
      if (typeof event.content === "string") event.content = maskText(event.content);
      else if (Array.isArray(event.content)) {
        maskBlocks(event.content);
        // Content arrays have schema-bearing block fields, so mask arbitrary
        // keys separately without rewriting structural string values.
        maskDeepFreeformKeys(event.content, maskText, CONTENT_BLOCK_STRUCTURAL_KEYS);
      } else if (event.content && typeof event.content === "object") maskDeepFreeform(event.content, maskText);
      if (typeof event.details === "string") event.details = maskText(event.details);
      else if (event.details && typeof event.details === "object") maskDeepFreeform(event.details, maskText);
    } catch {
      // Never let masking break tool results.
    }
  });

  pi.on("session_before_compact", (event: any, ctx: any) => {
    const prep = event?.preparation;
    if (!prep) return;
    try {
      refreshDotenv(ctx?.cwd ?? process.cwd());
      if (Array.isArray(prep.messagesToSummarize)) maskMessages(prep.messagesToSummarize);
      if (Array.isArray(prep.turnPrefixMessages)) maskMessages(prep.turnPrefixMessages);
      // P0-2: previous summary is fed straight into the summarizer request.
      if (typeof prep.previousSummary === "string") {
        prep.previousSummary = maskText(prep.previousSummary);
      }
      // Provider-bound custom instructions may embed secrets (P0-N6). Pi
      // passes them at event level and the compaction result type offers no
      // instructions override, so if instructions contain a secret we must
      // fail closed by cancelling compaction rather than leak them.
      // Use maskText so fresh patterns are collected and "seen" is recorded.
      if (typeof event.customInstructions === "string") {
        const masked = maskText(event.customInstructions);
        if (masked !== event.customInstructions) {
          return { cancel: true };
        }
      }
    } catch {
      // Never abort compaction.
    }
  });

  pi.on("session_before_tree", (event: any, ctx: any) => {
    const prep = event?.preparation;
    if (!prep) return;
    try {
      refreshDotenv(ctx?.cwd ?? process.cwd());
      if (Array.isArray(prep.entriesToSummarize)) {
        for (const entry of prep.entriesToSummarize) {
          if (!entry) continue;
          // Real Pi structures (P0-N5): message entries carry .message.content;
          // custom_message entries carry top-level .content; branch_summary and
          // compaction entries carry .summary (P0-5/P0-6).
          if (entry.type === "custom_message") {
            if (typeof entry.content === "string") entry.content = maskText(entry.content);
            else if (Array.isArray(entry.content)) maskBlocks(entry.content);
          } else if (entry.type === "branch_summary" || entry.type === "compaction") {
            if (typeof entry.summary === "string") entry.summary = maskText(entry.summary);
          } else {
            const msg = entry.message;
            if (msg?.content) {
              if (typeof msg.content === "string") {
                msg.content = maskText(msg.content);
              } else if (Array.isArray(msg.content)) {
                maskBlocks(msg.content);
              } else if (Array.isArray(msg.content?.parts)) {
                maskBlocks(msg.content.parts);
              }
            }
            // bashExecution/branchSummary message variants inside entries.
            if (msg && typeof msg === "object") {
              if (msg.role === "bashExecution") {
                if (typeof msg.command === "string") msg.command = maskText(msg.command);
                if (typeof msg.output === "string") msg.output = maskText(msg.output);
                if (typeof msg.fullOutputPath === "string") msg.fullOutputPath = maskText(msg.fullOutputPath);
              } else if ((msg.role === "branchSummary" || msg.role === "compactionSummary") && typeof msg.summary === "string") {
                msg.summary = maskText(msg.summary);
              }
            }
          }
        }
      }
      // P0-N6: Pi only honors the returned override, not preparation mutation.
      if (typeof prep.customInstructions === "string") {
        const masked = maskText(prep.customInstructions);
        if (masked !== prep.customInstructions) {
          return { customInstructions: masked };
        }
      }
    } catch {
      // Never abort tree navigation.
    }
  });

  const safeCredentialName = (value: string | undefined): string => {
    const clean = [...(value ?? "")]
      .filter((char) => {
        const code = char.codePointAt(0)!;
        return code >= 0x20 && code !== 0x7f && (code < 0x80 || code > 0x9f);
      })
      .slice(0, 80)
      .join("")
      .trim();
    return clean || "USER";
  };

  // Upstream-compatible command forms: one argument is the plaintext value
  // under USER; NAME VALUE remains supported. No-argument capture is TUI-only.
  pi.registerCommand("mask-secret", {
    description: "Register a secret locally (masked TUI input or plaintext arguments, persisted)",
    handler: async (args: string, ctx: any) => {
      const parts = (args ?? "").trim().split(/\s+/).filter(Boolean);
      let name = "USER";
      let value: string | undefined;
      if (parts.length >= 2) {
        name = parts[0];
        value = parts.slice(1).join(" ");
        ctx?.ui?.notify?.("The secret was supplied in command text; masked input is safer.", "warning");
      } else if (parts.length === 1) {
        // Preserve the upstream /mask-secret VALUE contract.
        value = parts[0];
        ctx?.ui?.notify?.("The secret was supplied in command text; masked input is safer.", "warning");
      } else {
        value = await secureInput(ctx, name, "Register a local secret for later use");
      }
      if (!value) {
        ctx?.ui?.notify?.("No secret provided, cancelled", "warning");
        return;
      }
      const ph = registerUserSecret(name, value);
      ctx?.ui?.notify?.(`Registered ${safeCredentialName(name)} → ${ph} (agent sees placeholder only)`, "info");
    },
  });

  pi.registerTool({
    name: "request_secret",
    label: "Request Secret",
    description: `Request an API key, token, username, or password through a local masked TUI prompt.
The real value never appears in the tool result or conversation; this tool returns an opaque __SECRET_*__ handle.
Use this only when the task needs a credential; do not request one again for a placeholder already present.
Use that returned handle explicitly only in an authorized tool argument. Built-in authorization covers bash.command, powershell.command, write.content, edit old/new text (including edits arrays), and Pi MCP Adapter mcp.args object or JSON containers. Browser, direct MCP, and custom tools require configured toolResolution rules.
${AGENT_GUIDANCE}`,
    parameters: Type.Object({
      name: Type.String({ description: "Credential name, e.g. OPENAI_API_KEY or GITHUB_TOKEN" }),
      purpose: Type.Optional(Type.String({ description: "Short reason shown in the local prompt" })),
    }),
    execute: async (
      _id: string,
      params: { name: string; purpose?: string },
      _signal: unknown,
      _onUpdate: unknown,
      ctx: any,
    ) => {
      const name = safeCredentialName(params.name);
      const existing = userSecrets.get(name);
      if (existing !== undefined) {
        // Reusing a persisted local credential is a capability grant too.
        if (ctx?.mode !== "tui" || typeof ctx?.ui?.confirm !== "function") {
          return { content: [{ type: "text" as const, text: "A local credential may exist, but secure confirmation is unavailable in this mode." }] };
        }
        const approved = await ctx.ui.confirm(
          "Reuse protected credential?",
          `Reuse the locally registered credential ${name}? Only its handle will be returned.`,
        );
        if (!approved) return { content: [{ type: "text" as const, text: `User declined reuse of ${name}.` }] };
        const handle = map.placeholderFor(existing);
        if (!handle) return { content: [{ type: "text" as const, text: `Credential ${name} is unavailable.` }] };
        return {
          content: [{ type: "text" as const, text: `Credential ${name} is available. Reuse handle ${handle}.` }],
          details: { name, handle, reused: true },
        };
      }

      const value = await secureInput(ctx, name, params.purpose);
      if (value === undefined) {
        return {
          content: [{ type: "text" as const, text: ctx?.mode === "tui" ? `User declined to provide ${name}.` : "Secure masked input is unavailable outside TUI mode." }],
          details: { name, declined: true },
        };
      }
      const ph = registerUserSecret(name, value);
      return {
        content: [{ type: "text" as const, text: `Registered ${name}. Use handle ${ph} explicitly in an authorized tool argument. The real value was not exposed.` }],
        details: { name, handle: ph },
      };
    },
  });
}
