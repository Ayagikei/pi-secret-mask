/**
 * pi-secret-mask extension entry point.
 *
 * Prevents secrets from leaking to LLM providers:
 * - before_provider_request: real values -> placeholders across all messages
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
  loadDotenvFiles,
  maskDeep,
  registerSources,
  type MaskOptions,
} from "../src/mask-engine.ts";

interface Config {
  mode?: "auto" | "ask";
  allowCommands?: string[];
  dotenv?: Partial<MaskOptions["dotenv"]>;
  patterns?: Partial<MaskOptions["patterns"]>;
  extraSecrets?: { name: string; value: string }[];
  customPatterns?: { name: string; pattern: string; flags?: string }[];
  base64MinLength?: number;
}

const CONFIG_FILE = join(dirname(fileURLToPath(import.meta.url)), "config.json");
/** User config dir takes precedence after npm install (survives pi update). */
const USER_CONFIG_FILE = join(homedir(), ".pi/agent/extensions/pi-secret-mask/config.json");
/** Secrets registered via /mask-secret, persisted in the user config dir. */
const USER_SECRETS_FILE = join(homedir(), ".pi/agent/extensions/pi-secret-mask/secrets.json");

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

  const map = new MaskMap();
  let dotenvMtimes = new Map<string, number>();
  // Secrets whose source is .env (only these are pruned when .env changes).
  const dotenvSourced = new Set<string>();
  // Secrets registered via /mask-secret (only these are persisted).
  const userSecrets = new Map<string, string>(); // name -> value

  // Extra secrets from config.
  for (const { name, value } of options.extraSecrets) {
    if (value) map.add(value, name);
  }

  // Load persisted user secrets.
  function loadUserSecrets(): void {
    try {
      if (existsSync(USER_SECRETS_FILE)) {
        const data = JSON.parse(readFileSync(USER_SECRETS_FILE, "utf-8")) as { name: string; value: string }[];
        for (const { name, value } of data) {
          if (value) {
            userSecrets.set(name, value);
            map.add(value, name);
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

  function refreshDotenv(baseDir: string): void {
    if (!options.dotenv.enabled) return;
    const files = options.dotenv.files.filter((f) => !options.dotenv.exclude.includes(f));
    const seen = new Set<string>();
    const changedFiles: string[] = [];
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
      if (dotenvMtimes.get(path) !== mtime) changedFiles.push(path);
    }
    // Drop records for files that disappeared.
    for (const [path] of dotenvMtimes) {
      if (!seen.has(path)) {
        dotenvMtimes.delete(path);
      }
    }
    if (changedFiles.length === 0) return;
    let entries: Map<string, string>;
    try {
      entries = loadDotenvFiles({ existsSync, readFileSync }, baseDir, options.dotenv);
    } catch {
      // .env changed but is unreadable: keep the old mapping (do NOT commit
      // mtime, so we retry next request; never abort the provider hook).
      return;
    }
    // Commit mtimes only after a successful read (P0-3).
    for (const path of changedFiles) {
      const mtime = statSync(path, { throwIfNoEntry: false })?.mtimeMs;
      if (mtime !== undefined) dotenvMtimes.set(path, mtime);
    }
    // Source-aware prune (P0-4): only remove secrets that came from .env
    // and are no longer provided; secrets also present in user/extra survive.
    const protectedValues = new Set<string>();
    for (const v of userSecrets.values()) protectedValues.add(v);
    for (const { value } of options.extraSecrets) if (value) protectedValues.add(value);
    const dotenvOwned = new Map<string, string>(); // value -> key
    for (const [key, value] of entries) {
      dotenvOwned.set(value, key);
    }
    for (const [secret, key] of dotenvOwned) {
      if (!map.has(secret)) map.add(secret, key);
    }
    // Remove .env secrets that are no longer present, unless still needed
    // by another source (user / extraSecrets).
    for (const ph of map.placeholders()) {
      const secret = map.secretFor(ph);
      if (secret && !dotenvOwned.has(secret) && dotenvSourced.has(secret) && !protectedValues.has(secret)) {
        map.remove(secret);
        dotenvSourced.delete(secret);
      }
    }
    for (const [key, value] of entries) {
      if (map.has(value)) dotenvSourced.add(value);
    }
  }

  function maskMessages(messages: any[]): void {
    for (const m of messages) {
      if (!m?.content) continue;
      if (typeof m.content === "string") {
        // Some providers use plain-string content (P0-2).
        m.content = maskText(m.content);
      } else {
        maskDeep(m.content, (s) => maskText(s));
      }
    }
  }

  function maskText(text: string): string {
    // Collect new patterns first (keys pasted in prompts, runtime-generated),
    // then mask.
    const sources = collectSecretsFromText(text, options);
    registerSources(map, sources);
    return map.mask(text);
  }

  /**
   * Mask any provider payload shape (messages/input/contents/system + string
   * content). Only known text paths are scanned: sweeping the whole payload
   * would corrupt structural fields (role/type/name) when a short .env value
   * collides with them (P1-N1).
   */
  function maskPayload(payload: any): void {
    if (payload == null) return;
    // System prompt can be a string (Anthropic/Bedrock) or an array of blocks.
    if (typeof payload.system === "string") {
      payload.system = maskText(payload.system);
    } else if (Array.isArray(payload.system)) {
      maskBlocks(payload.system);
    }
    for (const key of ["messages", "input", "contents"]) {
      const list = payload[key];
      if (Array.isArray(list)) maskMessages(list);
    }
    // Tool definitions carry descriptions that may embed secrets.
    if (Array.isArray(payload.tools)) {
      for (const tool of payload.tools) {
        if (tool?.function?.description) tool.function.description = maskText(tool.function.description);
      }
    }
  }

  /** Mask Anthropic-style content blocks (text only; images skipped by maskDeep). */
  function maskBlocks(blocks: any[]): void {
    for (const block of blocks) {
      if (block && typeof block === "object" && typeof block.text === "string") {
        block.text = maskText(block.text);
      } else if (block && typeof block === "object") {
        maskDeep(block, (s) => maskText(s));
      }
    }
  }

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
    // Bail early if no placeholder anywhere (bash command / write / edit).
    const inputStr = JSON.stringify(event.input ?? {});
    if (!map.placeholders().some((ph) => inputStr.includes(ph))) return;

    if (event.toolName === "bash") {
      const command: string = event.input?.command ?? "";
      // P0-6: refuse secrets whose real value contains any shell metacharacter.
      // Strict whitelist: alnum + a few safe punctuation. Anything else
      // (quotes, whitespace, $, backticks, ;, |, &, >, <, (, ), #, ...) is
      // rejected rather than inlined into shell syntax.
      const SAFE_SECRET_RE = /^[A-Za-z0-9._:\/@+=%-]+$/;
      for (const ph of map.placeholders()) {
        if (!command.includes(ph)) continue;
        const secret = map.secretFor(ph) ?? "";
        if (!SAFE_SECRET_RE.test(secret)) {
          ctx?.ui?.notify?.(`Blocked: secret ${ph} contains shell-special characters that would change command semantics`, "warning");
          return { block: true, reason: "Blocked by secret-mask: secret value is not safe to inline into a shell command" };
        }
      }
      const unmasked = map.unmask(command);
      if (mode === "ask") {
        const allowed = allowCommands.some((pat) => command.startsWith(pat) || new RegExp(pat).test(command));
        if (!allowed) {
          const hasUI = ctx?.hasUI ?? Boolean(ctx?.ui?.confirm);
          const ok = hasUI
            ? await ctx.ui.confirm("Secret mask", `Command contains secret placeholders. Run with real values?\n\n${command}\n\n(The dialog only shows placeholders, never real values)`)
            : false;
          if (!ok) {
            ctx?.ui?.notify?.(`Blocked command containing secret placeholders: ${command.slice(0, 120)}`, "warning");
            return { block: true, reason: "Blocked by secret-mask: requires real secret to run" };
          }
        }
      }
      event.input.command = unmasked;
      return;
    }

    // write/edit: swap placeholders back to real values so files store
    // real values even though the agent only saw placeholders. In ask mode
    // confirm too (P1-3) — placeholder usage is a secret capability.
    if (event.toolName === "write" || event.toolName === "edit") {
      if (mode === "ask") {
        const hasUI = ctx?.hasUI ?? Boolean(ctx?.ui?.confirm);
        const ok = hasUI
          ? await ctx.ui.confirm("Secret mask", `Writing content that contains secret placeholders. Write real values?`)
          : false;
        if (!ok) {
          ctx?.ui?.notify?.(`Blocked write/edit containing secret placeholders`, "warning");
          return { block: true, reason: "Blocked by secret-mask: write/edit with secret placeholders requires confirmation" };
        }
      }
      maskDeep(event.input, (s) => map.unmask(s));
    }
  });

  pi.on("tool_result", (event: any) => {
    if (!event.content) return;
    try {
      // Output may contain runtime-generated secrets (e.g. aws sts output);
      // collect them first, then mask.
      maskDeep(event.content, (s) => maskText(s));
    } catch {
      // Never let masking break tool results.
    }
  });

  pi.on("session_before_compact", (event: any, ctx: any) => {
    const prep = event.preparation;
    if (!prep) return;
    try {
      refreshDotenv(ctx?.cwd ?? process.cwd());
      if (Array.isArray(prep.messagesToSummarize)) maskMessages(prep.messagesToSummarize);
      if (Array.isArray(prep.turnPrefixMessages)) maskMessages(prep.turnPrefixMessages);
    } catch {
      // Never abort compaction.
    }
  });

  pi.on("session_before_tree", (event: any, ctx: any) => {
    const prep = event.preparation;
    if (!prep) return;
    try {
      refreshDotenv(ctx?.cwd ?? process.cwd());
      if (Array.isArray(prep.entriesToSummarize)) {
        for (const entry of prep.entriesToSummarize) {
          if (entry?.message?.content) {
            if (typeof entry.message.content === "string") {
              entry.message.content = maskText(entry.message.content);
            } else {
              maskDeep(entry.message.content, (s) => maskText(s));
            }
          }
        }
      }
    } catch {
      // Never abort tree navigation.
    }
  });

  // /mask-secret <name> <value>: register a secret from user input
  // (interactive or args). Persisted; agent never sees the real value.
  pi.registerCommand("mask-secret", {
    description: "Register a secret to be masked (interactive input or args, persisted)",
    handler: async (args: string, ctx: any) => {
      const parts = (args ?? "").trim().split(/\s+/).filter(Boolean);
      let name = "USER";
      let value = "";
      if (parts.length >= 2) {
        name = parts[0];
        value = parts.slice(1).join(" ");
      } else if (parts.length === 1) {
        // Single arg is treated as the value; name defaults to USER.
        value = parts[0];
      } else {
        value = (await ctx.ui.input("Secret value to mask (agent will not see it):", "")) ?? "";
      }
      value = value.trim();
      if (!value) {
        ctx.ui.notify("No secret provided, cancelled", "warning");
        return;
      }
      const ph = map.add(value, name);
      userSecrets.set(name, value);
      saveUserSecrets();
      ctx.ui.notify(`Registered ${name} → ${ph} (agent sees placeholder only)`, "info");
    },
  });

  // request_secret: agent-initiated secret request. The user's input is
  // masked immediately; the agent only receives the placeholder.
  pi.registerTool({
    name: "request_secret",
    label: "Request Secret",
    description: `Request a secret (API key/token/password) from the user and register it in the masking system.
The value the user enters is masked into a placeholder; you (the agent) only see the placeholder and never touch the real value.
Use the placeholder in bash commands or file writes and the extension substitutes the real value automatically.
Use case: tasks that require a secret from the user to continue.`,
    parameters: Type.Object({
      name: Type.String({ description: "Secret name, e.g. OPENAI_API_KEY, GITHUB_TOKEN" }),
      purpose: Type.Optional(Type.String({ description: "Purpose shown to the user" })),
    }),
    execute: async (
      _id: string,
      params: { name: string; purpose?: string },
      _signal: unknown,
      _onUpdate: unknown,
      ctx: any,
    ) => {
      const name = params.name?.trim() || "USER";
      const purpose = params.purpose?.trim();
      if (!ctx?.ui?.input) {
        return {
          content: [{ type: "text" as const, text: "No interactive UI in this mode (print/json); cannot request a secret. Ask the user to register it via /mask-secret first." }],
        };
      }
      const value = (await ctx.ui.input(
        purpose ? `Enter ${name} (purpose: ${purpose}; the agent will not see it):` : `Enter ${name} (the agent will not see it):`,
        "",
      )) ?? "";
      if (!value.trim()) {
        return {
          content: [{ type: "text" as const, text: `User cancelled input for ${name}` }],
        };
      }
      const ph = map.add(value.trim(), name);
      userSecrets.set(name, value.trim());
      saveUserSecrets();
      return {
        content: [{ type: "text" as const, text: `Registered ${name}. Use placeholder ${ph} instead of the real value (bash/write substitute automatically). The real value is never exposed to you.` }],
      };
    },
  });
}
