/**
 * pi-secret-mask 扩展入口
 *
 * 防 secret 泄露给 LLM provider：
 * - before_provider_request：全消息真实值 → 占位符
 * - tool_call：bash 命令占位符 → 真实值（auto/ask 放行）
 * - tool_result：工具输出真实值 → 占位符（防回流）
 * - session_before_compact / session_before_tree：摘要消息同样掩码
 * - /mask-secret：用户输入密钥注册，agent 只见占位符（持久化到用户目录）
 *
 * 配置：优先 ~/.pi/agent/extensions/pi-secret-mask/config.json，其次扩展同目录。
 */
import { existsSync, readFileSync, statSync, writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
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
/** npm 安装后优先读用户配置目录（pi update 不会覆盖） */
const USER_CONFIG_FILE = join(homedir(), ".pi/agent/extensions/pi-secret-mask/config.json");
/** 用户通过 /mask-secret 注册的 secret，持久化到用户目录 */
const USER_SECRETS_FILE = join(homedir(), ".pi/agent/extensions/pi-secret-mask/secrets.json");

function loadConfig(): Config {
  for (const path of [USER_CONFIG_FILE, CONFIG_FILE]) {
    try {
      if (existsSync(path)) {
        return JSON.parse(readFileSync(path, "utf-8")) as Config;
      }
    } catch {
      // 配置损坏时尝试下一个
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
  // 用户通过 /mask-secret 注册的 secret（只持久化这些）
  const userSecrets = new Map<string, string>(); // name -> value

  // 手动补充 secret
  for (const { name, value } of options.extraSecrets) {
    if (value) map.add(value, name);
  }

  // 加载用户 /mask-secret 注册的持久化 secret
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
      // 忽略损坏的 secrets.json
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
      // 持久化失败不阻塞
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
    // 删除已消失的文件记录
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
    // 用户注册（/mask-secret）和 extraSecrets 的 secret 不受 .env 变更影响
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
    // 先从文本中收集新模式 secret（用户 prompt 里的密钥、运行时生成的），再掩码
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
    // 先判断是否有占位符（bash 命令 / write 内容 / edit 文本都可能含占位符）
    const inputStr = JSON.stringify(event.input ?? {});
    if (!map.placeholders().some((ph) => inputStr.includes(ph))) return;

    if (event.toolName === "bash") {
      const command: string = event.input?.command ?? "";
      if (mode === "ask") {
        const allowed = allowCommands.some((pat) => command.startsWith(pat) || new RegExp(pat).test(command));
        if (!allowed) {
          const ok = ctx?.ui?.confirm
            ? await ctx.ui.confirm("Secret mask", `命令包含 secret 占位符，是否用真实值执行？\n\n${command}\n\n（对话框只显示占位符，不显示真实值）`)
            : false;
          if (!ok) {
            ctx?.ui?.notify?.(`已阻止命令执行（含 secret 占位符）：${command.slice(0, 120)}`, "warning");
            return { block: true, reason: "Blocked by secret-mask: 需要真实 secret 执行" };
          }
        }
      }
      event.input.command = map.unmask(command);
      return;
    }

    // write/edit：把内容里的占位符换回真实值（agent 把掩码后的值写回文件时存真值）
    if (event.toolName === "write" || event.toolName === "edit") {
      maskDeep(event.input, (s) => map.unmask(s));
    }
  });

  pi.on("tool_result", (event: any) => {
    if (!event.content) return;
    // 输出中可能含运行时生成的新 secret（如 aws sts 输出），先收集再掩码
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

  // /mask-secret <name>：注册用户提供的 secret（交互输入，agent 不见真值）
  pi.registerCommand("mask-secret", {
    description: "注册一个需要掩码的 secret（交互输入或参数提供，持久化保存）",
    handler: async (args: string, ctx: any) => {
      const parts = (args ?? "").trim().split(/\s+/).filter(Boolean);
      let name = "USER";
      let value = "";
      if (parts.length >= 2) {
        name = parts[0];
        value = parts.slice(1).join(" ");
      } else if (parts.length === 1) {
        // 单个参数视为值，名字用 USER
        value = parts[0];
      } else {
        value = (await ctx.ui.input("要掩码的 secret 值（agent 不会看到）：", "")) ?? "";
      }
      value = value.trim();
      if (!value) {
        ctx.ui.notify("未提供 secret，已取消", "warning");
        return;
      }
      const ph = map.add(value, name);
      userSecrets.set(name, value);
      saveUserSecrets();
      ctx.ui.notify(`已注册 ${name} → ${ph}（agent 只见占位符）`, "info");
    },
  });
}
