/**
 * pi-secret-mask 掩码引擎
 *
 * 职责：
 * - 收集 secret（.env 解析、正则模式、自定义正则、手动补充）
 * - secret ↔ 占位符双向映射
 * - 文本掩码（真实值 → 占位符，单趟 alternation 正则）
 * - 文本还原（占位符 → 真实值，精确匹配）
 */

export interface SecretSource {
  /** 唯一来源名，用于占位符命名（.env KEY / 模式名 / 自定义名） */
  name: string;
  /** 值列表 */
  values: string[];
}

export interface DotenvOptions {
  enabled: boolean;
  files: string[];
  /** 排除的文件（如 .env.example） */
  exclude: string[];
}

export interface MaskOptions {
  /** 手动补充的 secret */
  extraSecrets: { name: string; value: string }[];
  /** 用户自定义正则规则 */
  customPatterns: { name: string; pattern: string; flags?: string }[];
  dotenv: DotenvOptions;
  /** 内置正则模式开关 */
  patterns: {
    openai: boolean;
    github: boolean;
    google: boolean;
    aws: boolean;
    jwt: boolean;
    pem: boolean;
    base64: boolean;
  };
  /** 高熵 base64 最小长度（默认关） */
  base64MinLength: number;
}

export const DEFAULT_MASK_OPTIONS: MaskOptions = {
  extraSecrets: [],
  customPatterns: [],
  dotenv: {
    enabled: true,
    files: [".env", ".env.local", ".env.production", ".env.development"],
    exclude: [".env.example", ".env.sample"],
  },
  patterns: {
    openai: true,
    github: true,
    google: true,
    aws: true,
    jwt: true,
    pem: true,
    base64: false,
  },
  base64MinLength: 32,
};

/** 内置正则模式。捕获组必须把整个 secret 包在组 1。 */
function builtinPatterns(opts: MaskOptions["patterns"]): { name: string; re: RegExp }[] {
  const out: { name: string; re: RegExp }[] = [];
  const add = (name: string, enabled: boolean, source: string, flags = "g") => {
    if (enabled) out.push({ name, re: new RegExp(source, flags) });
  };
  add("OPENAI", opts.openai, "sk-[A-Za-z0-9_-]{20,}");
  add("GITHUB", opts.github, "(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}");
  add("GOOGLE", opts.google, "AIza[0-9A-Za-z_-]{35}");
  add("AWS", opts.aws, "(?:AKIA|ASIA|AIDA)[0-9A-Z]{16}");
  add("JWT", opts.jwt, "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}");
  add("PEM", opts.pem, "-----BEGIN [A-Z ]*PRIVATE KEY-----\\s*[A-Za-z0-9+/=\\s]+?-----END [A-Z ]*PRIVATE KEY-----");
  add("BASE64", opts.base64, `[A-Za-z0-9+/]{${opts.base64MinLength},}={0,2}`);
  return out;
}

/** 解析 .env 内容为 KEY=VALUE 列表。规则：引号剥离、export 前缀、行内注释、CRLF、值可含 =。 */
export function parseDotenv(content: string): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = [];
  for (let rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    let key = line.slice(0, eq).trim();
    if (key.startsWith("export ")) key = key.slice(7).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    let value = line.slice(eq + 1).trim();
    // 行内注释：只在引号外生效（简化：值以引号开头时不做注释剥离）
    const firstQuote = value[0];
    if (firstQuote === '"' || firstQuote === "'") {
      const closing = value.indexOf(firstQuote, 1);
      if (closing > 0) value = value.slice(1, closing);
      // 无闭合引号：取整行
    } else {
      const hash = value.indexOf(" #");
      if (hash >= 0) value = value.slice(0, hash).trim();
    }
    if (value) out.push({ key, value });
  }
  return out;
}

/** 从磁盘读取 .env* 文件（按优先级：后者覆盖前者）。 */
export function loadDotenvFiles(fs: {
  existsSync: (p: string) => boolean;
  readFileSync: (p: string) => string;
}, baseDir: string, opts: DotenvOptions): Map<string, string> {
  const result = new Map<string, string>();
  if (!opts.enabled) return result;
  for (const file of opts.files) {
    if (opts.exclude.includes(file)) continue;
    const path = `${baseDir}/${file}`;
    if (!fs.existsSync(path)) continue;
    const content = fs.readFileSync(path);
    for (const { key, value } of parseDotenv(typeof content === "string" ? content : String(content))) {
      result.set(key, value);
    }
  }
  return result;
}

/** 从文本中提取所有正则命中（全局匹配，去重，按长度降序）。 */
export function collectPatternSecrets(patterns: { name: string; re: RegExp }[], text: string): SecretSource[] {
  const byName = new Map<string, Set<string>>();
  for (const { name, re } of patterns) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const value = m[1] ?? m[0];
      if (value) {
        if (!byName.has(name)) byName.set(name, new Set());
        byName.get(name)!.add(value);
      }
      if (m[0].length === 0) re.lastIndex++; // 防死循环
    }
  }
  return [...byName.entries()].map(([name, values]) => ({
    name,
    values: [...values].sort((a, b) => b.length - a.length),
  }));
}

/** 掩码映射：维护 secret ↔ 占位符。 */
export class MaskMap {
  private secretToPlaceholder = new Map<string, string>();
  private placeholderToSecret = new Map<string, string>();
  private nameCounts = new Map<string, number>();
  /** 按长度降序的 secret 列表（用于 alternation 构造） */
  private sortedSecrets: string[] = [];

  /** 注册 secret。同名自动编号。返回占位符。 */
  add(secret: string, baseName: string): string {
    const existing = this.secretToPlaceholder.get(secret);
    if (existing) return existing;
    const n = (this.nameCounts.get(baseName) ?? 0) + 1;
    this.nameCounts.set(baseName, n);
    const placeholder = n === 1 ? `__SECRET_${baseName}__` : `__SECRET_${baseName}_${n}__`;
    this.secretToPlaceholder.set(secret, placeholder);
    this.placeholderToSecret.set(placeholder, secret);
    this.sortedSecrets = [...this.secretToPlaceholder.keys()].sort((a, b) => b.length - a.length);
    return placeholder;
  }

  /** 移除 secret（.env 中已删除的 key）。 */
  remove(secret: string): void {
    const ph = this.secretToPlaceholder.get(secret);
    if (!ph) return;
    this.secretToPlaceholder.delete(secret);
    this.placeholderToSecret.delete(ph);
    this.sortedSecrets = [...this.secretToPlaceholder.keys()].sort((a, b) => b.length - a.length);
  }

  get size(): number {
    return this.secretToPlaceholder.size;
  }

  has(secret: string): boolean {
    return this.secretToPlaceholder.has(secret);
  }

  placeholderFor(secret: string): string | undefined {
    return this.secretToPlaceholder.get(secret);
  }

  secretFor(placeholder: string): string | undefined {
    return this.placeholderToSecret.get(placeholder);
  }

  placeholders(): string[] {
    return [...this.placeholderToSecret.keys()];
  }

  /** 掩码：真实值 → 占位符。单趟 alternation（按长度降序，防子串冲突）。 */
  mask(text: string): string {
    if (this.sortedSecrets.length === 0) return text;
    const re = new RegExp(
      this.sortedSecrets.map(escapeRegExp).join("|"),
      "g",
    );
    return text.replace(re, (m) => this.secretToPlaceholder.get(m) ?? m);
  }

  /** 还原：占位符 → 真实值。只精确匹配已知占位符（完整 token，前后不接标识符字符）。 */
  unmask(text: string): string {
    if (this.placeholderToSecret.size === 0) return text;
    const re = new RegExp(
      `(?<![A-Za-z0-9_])(?:${[...this.placeholderToSecret.keys()].map(escapeRegExp).join("|")})(?![A-Za-z0-9_])`,
      "g",
    );
    return text.replace(re, (m) => this.placeholderToSecret.get(m) ?? m);
  }

  /** 递归掩码任意结构（消息 content 数组等），返回是否修改过。 */
  maskDeep(value: unknown): boolean {
    return maskDeep(value, (s) => this.mask(s));
  }

  /** 递归还原任意结构。 */
  unmaskDeep(value: unknown): boolean {
    return maskDeep(value, (s) => this.unmask(s));
  }
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** 遍历对象/数组/字符串，对 text 字段应用 fn。返回是否修改过。 */
export function maskDeep(value: unknown, fn: (text: string) => string): boolean {
  if (typeof value === "string") return false; // 字符串容器由调用方处理
  if (Array.isArray(value)) {
    let changed = false;
    for (let i = 0; i < value.length; i++) {
      const item = value[i];
      if (typeof item === "string") {
        const next = fn(item);
        if (next !== item) {
          value[i] = next;
          changed = true;
        }
      } else if (item && typeof item === "object") {
        changed = maskDeep(item, fn) || changed;
      }
    }
    return changed;
  }
  if (value && typeof value === "object") {
    let changed = false;
    for (const key of Object.keys(value as Record<string, unknown>)) {
      const item = (value as Record<string, unknown>)[key];
      if (typeof item === "string") {
        const next = fn(item);
        if (next !== item) {
          (value as Record<string, unknown>)[key] = next;
          changed = true;
        }
      } else if (item && typeof item === "object") {
        changed = maskDeep(item, fn) || changed;
      }
    }
    return changed;
  }
  return false;
}

/** 从文本中收集 secret：内置模式 + 自定义正则。 */
export function collectSecretsFromText(
  text: string,
  opts: MaskOptions,
): SecretSource[] {
  const patterns: { name: string; re: RegExp }[] = builtinPatterns(opts.patterns);
  for (const cp of opts.customPatterns) {
    try {
      patterns.push({ name: cp.name, re: new RegExp(cp.pattern, cp.flags ?? "g") });
    } catch {
      // 忽略非法自定义正则
    }
  }
  return collectPatternSecrets(patterns, text);
}

/** 把收集到的 source 注册进 map。返回本次新增数。 */
export function registerSources(map: MaskMap, sources: SecretSource[]): number {
  let added = 0;
  for (const src of sources) {
    for (const value of src.values) {
      if (!map.has(value)) {
        map.add(value, src.name);
        added++;
      }
    }
  }
  return added;
}

/** 同步移除 map 中已不存在的 secret（基于当前活跃集合）。 */
export function pruneSecrets(map: MaskMap, active: Set<string>): number {
  let removed = 0;
  for (const ph of map.placeholders()) {
    const secret = map.secretFor(ph);
    if (secret && !active.has(secret)) {
      map.remove(secret);
      removed++;
    }
  }
  return removed;
}
