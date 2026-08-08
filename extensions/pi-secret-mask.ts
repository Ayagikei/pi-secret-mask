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
import { existsSync, readFileSync, statSync, writeFileSync, mkdirSync } from "fs";
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
  pruneSecrets,
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
  const config = loadConfig();
  const options = mergeOptions(config);
  const mode = config.mode ?? "ask";
  const allowCommands = config.allowCommands ?? [];

  const map = new MaskMap();
  let dotenvMtimes = new Map<string, number>();
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
      writeFileSync(USER_SECRETS_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });
    } catch {
      // Persistence failure must not block the session.
    }
  }

  function refreshDotenv(baseDir: string): void {
    if (!options.dotenv.enabled) return;
    let changed = false;
    const files = options.dotenv.files.filter((f) => !options.dotenv.exclude.includes(f));
    const seen = new Set<string>();
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
      if (dotenvMtimes.get(path) === mtime) continue;
      dotenvMtimes.set(path, mtime);
      changed = true;
    }
    // Drop records for files that disappeared.
    for (const [path] of dotenvMtimes) {
      if (!seen.has(path)) {
        dotenvMtimes.delete(path);
        changed = true;
      }
    }
    if (!changed) return;
    const entries = loadDotenvFiles({ existsSync, readFileSync }, baseDir, options.dotenv);
    const active = new Set<string>();
    for (const [key, value] of entries) {
      active.add(value);
      if (!map.has(value)) map.add(value, key);
    }
    // User-registered (/mask-secret) and extraSecrets must survive .env changes.
    for (const v of userSecrets.values()) active.add(v);
    for (const { value } of options.extraSecrets) if (value) active.add(value);
    pruneSecrets(map, active);
  }

  function maskMessages(messages: any[]): void {
    for (const m of messages) {
      if (m?.content) maskDeep(m.content, (s) => maskText(s));
    }
  }

  function maskText(text: string): string {
    // Collect new patterns first (keys pasted in prompts, runtime-generated),
    // then mask.
    const sources = collectSecretsFromText(text, options);
    registerSources(map, sources);
    return map.mask(text);
  }

  pi.on("before_provider_request", (event: any) => {
    refreshDotenv(process.cwd());
    const payload = event.payload as any;
    const messages = payload?.messages;
    if (Array.isArray(messages)) {
      maskMessages(messages);
      return payload;
    }
  });

  pi.on("tool_call", async (event: any, ctx: any) => {
    // Bail early if no placeholder anywhere (bash command / write / edit).
    const inputStr = JSON.stringify(event.input ?? {});
    if (!map.placeholders().some((ph) => inputStr.includes(ph))) return;

    if (event.toolName === "bash") {
      const command: string = event.input?.command ?? "";
      if (mode === "ask") {
        const allowed = allowCommands.some((pat) => command.startsWith(pat) || new RegExp(pat).test(command));
        if (!allowed) {
          const ok = ctx?.ui?.confirm
            ? await ctx.ui.confirm("Secret mask", `Command contains secret placeholders. Run with real values?\n\n${command}\n\n(The dialog only shows placeholders, never real values)`)
            : false;
          if (!ok) {
            ctx?.ui?.notify?.(`Blocked command containing secret placeholders: ${command.slice(0, 120)}`, "warning");
            return { block: true, reason: "Blocked by secret-mask: requires real secret to run" };
          }
        }
      }
      event.input.command = map.unmask(command);
      return;
    }

    // write/edit: swap placeholders back to real values so files store
    // real values even though the agent only saw placeholders.
    if (event.toolName === "write" || event.toolName === "edit") {
      maskDeep(event.input, (s) => map.unmask(s));
    }
  });

  pi.on("tool_result", (event: any) => {
    if (!event.content) return;
    // Output may contain runtime-generated secrets (e.g. aws sts output);
    // collect them first, then mask.
    maskDeep(event.content, (s) => maskText(s));
  });

  pi.on("session_before_compact", (event: any) => {
    const prep = event.preparation;
    if (!prep) return;
    refreshDotenv(process.cwd());
    if (Array.isArray(prep.messagesToSummarize)) maskMessages(prep.messagesToSummarize);
    if (Array.isArray(prep.turnPrefixMessages)) maskMessages(prep.turnPrefixMessages);
  });

  pi.on("session_before_tree", (event: any) => {
    const prep = event.preparation;
    if (!prep) return;
    refreshDotenv(process.cwd());
    if (Array.isArray(prep.entriesToSummarize)) {
      for (const entry of prep.entriesToSummarize) {
        if (entry?.message?.content) maskDeep(entry.message.content, (s) => map.mask(s));
      }
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
