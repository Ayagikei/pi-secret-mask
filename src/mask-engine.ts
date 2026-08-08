/**
 * pi-secret-mask masking engine.
 *
 * Responsibilities:
 * - Collect secrets (.env parsing, regex patterns, custom regexes, manual extras)
 * - Bidirectional secret <-> placeholder mapping
 * - Mask text (real value -> placeholder, single-pass alternation regex)
 * - Unmask text (placeholder -> real value, exact match)
 */

export interface SecretSource {
  /** Unique source name, used for placeholder naming (.env KEY / pattern name / custom name). */
  name: string;
  /** Values. */
  values: string[];
}

export interface DotenvOptions {
  enabled: boolean;
  files: string[];
  /** Files to exclude (e.g. .env.example). */
  exclude: string[];
}

export interface MaskOptions {
  /** Manually supplied secrets. */
  extraSecrets: { name: string; value: string }[];
  /** User-defined regex rules. */
  customPatterns: { name: string; pattern: string; flags?: string }[];
  dotenv: DotenvOptions;
  /** Built-in regex pattern toggles. */
  patterns: {
    openai: boolean;
    github: boolean;
    google: boolean;
    aws: boolean;
    jwt: boolean;
    pem: boolean;
    base64: boolean;
  };
  /** Minimum length for high-entropy base64 (off by default). */
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

/** Built-in regex patterns. A capture group must wrap the whole secret in group 1. */
function builtinPatterns(opts: MaskOptions["patterns"]): { name: string; re: RegExp }[] {
  const out: { name: string; re: RegExp }[] = [];
  const add = (name: string, enabled: boolean, source: string, flags = "g") => {
    if (enabled) out.push({ name, re: new RegExp(source, flags) });
  };
  add("OPENAI", opts.openai, "sk-[A-Za-z0-9_-]{20,}");
  add("GITHUB", opts.github, "(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}");
  add("GOOGLE", opts.google, "AIza[0-9A-Za-z_-]{35}");
  add("AWS", opts.aws, "(?:AKIA|ASIA|AIDA)[0-9A-Z]{16}");
  add("AWS_SK", opts.aws, `"?(?:SecretAccessKey|SessionToken)"?\\s*[:=]\\s*"?([A-Za-z0-9+/=]{20,})"`);
  add("JWT", opts.jwt, "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}");
  add("PEM", opts.pem, "-----BEGIN [A-Z ]*PRIVATE KEY-----\\s*[A-Za-z0-9+/=\\s]+?-----END [A-Z ]*PRIVATE KEY-----");
  add("BASE64", opts.base64, `[A-Za-z0-9+/]{${opts.base64MinLength},}={0,2}`);
  return out;
}

/** Parse .env content into KEY=VALUE pairs. Rules: quote stripping (with \\-escapes), export prefix, inline comments, CRLF, values may contain =. */
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
    const firstQuote = value[0];
    if (firstQuote === '"' || firstQuote === "'") {
      // Quoted value: strip the wrapping quote and honor \\-escapes inside.
      value = value.slice(1);
      let end = -1;
      for (let i = 0; i < value.length; i++) {
        if (value[i] === "\\" && i + 1 < value.length) {
          value = value.slice(0, i) + value[i + 1] + value.slice(i + 2);
          i++; // skip the escaped char
          continue;
        }
        if (value[i] === firstQuote) {
          end = i;
          break;
        }
      }
      if (end >= 0) value = value.slice(0, end);
      // No closing quote: take the whole (already unescaped) remainder.
    } else {
      // Unquoted: an inline comment starts at " #" (dotenv convention).
      const hash = value.indexOf(" #");
      if (hash >= 0) value = value.slice(0, hash).trim();
    }
    if (value) out.push({ key, value });
  }
  return out;
}

/** Read .env* files from disk (later files override earlier keys). */
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

/** Extract all regex matches from text (global match, deduped, sorted by length descending). */
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
      if (m[0].length === 0) re.lastIndex++; // guard against infinite loops
    }
  }
  return [...byName.entries()].map(([name, values]) => ({
    name,
    values: [...values].sort((a, b) => b.length - a.length),
  }));
}

/** Placeholder shape (prevents already-masked content from being re-collected). */
const PLACEHOLDER_RE = /^__SECRET_[A-Za-z0-9_]+(__\d+)?__$/;
/** Characters allowed in placeholder names (dotenv keys, pattern names). */
const NAME_RE = /^[A-Za-z0-9_]+$/;

/** Sanitize a name into a safe placeholder fragment. */
export function sanitizeName(name: string): string {
  return NAME_RE.test(name) ? name : name.replace(/[^A-Za-z0-9_]/g, "_") || "SECRET";
}

/** Masking map: maintains secret <-> placeholder. */
export class MaskMap {
  private secretToPlaceholder = new Map<string, string>();
  private placeholderToSecret = new Map<string, string>();
  private usedPlaceholders = new Set<string>();
  /** Secrets sorted by length descending (for alternation construction). */
  private sortedSecrets: string[] = [];

  /** Register a secret. Placeholders are globally unique. Returns the placeholder. */
  add(secret: string, baseName: string): string {
    const existing = this.secretToPlaceholder.get(secret);
    if (existing) return existing;
    if (PLACEHOLDER_RE.test(secret)) return secret; // never re-register placeholders
    const name = sanitizeName(baseName);
    let placeholder = `__SECRET_${name}__`;
    let n = 1;
    while (this.usedPlaceholders.has(placeholder)) {
      n++;
      placeholder = `__SECRET_${name}_${n}__`;
    }
    this.usedPlaceholders.add(placeholder);
    this.secretToPlaceholder.set(secret, placeholder);
    this.placeholderToSecret.set(placeholder, secret);
    this.sortedSecrets = [...this.secretToPlaceholder.keys()].sort((a, b) => b.length - a.length);
    return placeholder;
  }

  /** Remove a secret (e.g. a key deleted from .env). */
  remove(secret: string): void {
    const ph = this.secretToPlaceholder.get(secret);
    if (!ph) return;
    this.secretToPlaceholder.delete(secret);
    this.placeholderToSecret.delete(ph);
    this.usedPlaceholders.delete(ph);
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

  /** Mask: real value -> placeholder. Single-pass alternation (length-descending, no substring collisions). */
  mask(text: string): string {
    if (this.sortedSecrets.length === 0) return text;
    const re = new RegExp(
      this.sortedSecrets.map(escapeRegExp).join("|"),
      "g",
    );
    return text.replace(re, (m) => this.secretToPlaceholder.get(m) ?? m);
  }

  /** Unmask: placeholder -> real value. Only matches known placeholders as whole tokens (not adjacent to identifier chars). */
  unmask(text: string): string {
    if (this.placeholderToSecret.size === 0) return text;
    const re = new RegExp(
      `(?<![A-Za-z0-9_])(?:${[...this.placeholderToSecret.keys()].map(escapeRegExp).join("|")})(?![A-Za-z0-9_])`,
      "g",
    );
    return text.replace(re, (m) => this.placeholderToSecret.get(m) ?? m);
  }

  /** Recursively mask any structure (message content arrays etc.). Returns whether anything changed. */
  maskDeep(value: unknown): boolean {
    return maskDeep(value, (s) => this.mask(s));
  }

  /** Recursively unmask any structure. */
  unmaskDeep(value: unknown): boolean {
    return maskDeep(value, (s) => this.unmask(s));
  }
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Walk objects/arrays and apply fn to string fields. Returns whether anything changed.
 * Image/binary nodes (type "image"/"input_image") are skipped so base64 data is never touched.
 */
export function maskDeep(value: unknown, fn: (text: string) => string): boolean {
  if (typeof value === "string") return false; // string containers are handled by the caller
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
        if (isImageNode(item)) continue; // never touch image payloads
        changed = maskDeep(item, fn) || changed;
      }
    }
    return changed;
  }
  if (value && typeof value === "object") {
    if (isImageNode(value)) return false;
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

/** Detect provider image content nodes (Anthropic/OpenAI/Google style). */
function isImageNode(v: Record<string, unknown>): boolean {
  const t = v.type;
  if (t === "image" || t === "input_image" || t === "image_url") return true;
  if (typeof v.source === "object" && v.source !== null) {
    const s = v.source as Record<string, unknown>;
    if (s.type === "base64" || s.type === "url" || s.type === "bytes") return true;
  }
  // Google Gemini inlineData blocks carry raw base64 image data.
  if (typeof v.inlineData === "object" && v.inlineData !== null) return true;
  return false;
}

/** Collect secrets from text: built-in patterns + custom regexes. */
export function collectSecretsFromText(
  text: string,
  opts: MaskOptions,
): SecretSource[] {
  const patterns: { name: string; re: RegExp }[] = builtinPatterns(opts.patterns);
  for (const cp of opts.customPatterns) {
    try {
      // Force global flag: collectPatternSecrets loops exec() which requires /g.
      const flags = (cp.flags ?? "").includes("g") ? cp.flags! : (cp.flags ?? "") + "g";
      patterns.push({ name: cp.name, re: new RegExp(cp.pattern, flags) });
    } catch {
      // Ignore invalid custom regexes.
    }
  }
  return collectPatternSecrets(patterns, text);
}

/** Register collected sources into the map. Returns the number of new secrets added. */
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

/** Remove secrets from the map that are no longer in the active set. */
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
