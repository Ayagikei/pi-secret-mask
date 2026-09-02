/** Policy-scoped execution-time resolution for explicit __SECRET_*__ handles. */

export type UnknownHandlePolicy = "block" | "ignore";
export type RuleAdapter = "text" | "json";

export interface ToolResolutionRule {
  /** Exact tool name or a `*`/`?` glob. */
  tool: string;
  /** Dot paths; `*` matches one segment and `**` matches zero or more. */
  paths: string[];
  /** `json` authorizes one JSON object/array container, supplied as an object or JSON string. */
  adapter?: RuleAdapter;
}

export interface ToolResolutionConfig {
  enabled?: boolean;
  includeDefaults?: boolean;
  /** Retained for config compatibility; unknown handles always fail closed. */
  unknownHandle?: UnknownHandlePolicy;
  rules?: ToolResolutionRule[];
}

export interface SecretLookup {
  placeholders(): string[];
  secretFor(handle: string): string | undefined;
}

export interface ResolutionPlan {
  toolName: string;
  handles: string[];
  paths: string[];
  /** Applies a previously validated plan; plan construction itself is non-mutating. */
  apply(): void;
}

export class SecretResolutionError extends Error {
  readonly code: "UNKNOWN_HANDLE" | "UNAUTHORIZED_PATH" | "INVALID_JSON" | "INVALID_INPUT";

  constructor(message: string, code: "UNKNOWN_HANDLE" | "UNAUTHORIZED_PATH" | "INVALID_JSON" | "INVALID_INPUT") {
    super(message);
    this.name = "SecretResolutionError";
    this.code = code;
  }
}

export const DEFAULT_TOOL_RESOLUTION_RULES: ToolResolutionRule[] = [
  { tool: "bash", paths: ["command"] },
  { tool: "powershell", paths: ["command"] },
  { tool: "write", paths: ["content"] },
  { tool: "edit", paths: ["oldText", "newText", "edits.*.oldText", "edits.*.newText"] },
  // Pi's MCP adapter exposes its target arguments as mcp.args. The adapter
  // accepts an object/array container or a JSON-encoded object/array string.
  { tool: "mcp", paths: ["args"], adapter: "json" },
];

const HANDLE_RE = /__SECRET_[A-Za-z0-9_]+__/g;
type PathSegment = string | number;
type Container = Record<string, unknown> | unknown[];
interface Operation { container: Container; key: string | number; value: unknown; }

export function findSecretHandles(text: string): string[] {
  return [...new Set(text.match(HANDLE_RE) ?? [])];
}

export function containsSecretHandle(value: unknown): boolean {
  if (typeof value === "string") return findSecretHandles(value).length > 0;
  if (Array.isArray(value)) return value.some(containsSecretHandle);
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).some(
      ([key, child]) => findSecretHandles(key).length > 0 || containsSecretHandle(child),
    );
  }
  return false;
}

/** Build a validated, non-mutating resolution plan. */
export function planToolSecretResolution(
  toolName: string,
  input: Record<string, unknown>,
  lookup: SecretLookup,
  config: ToolResolutionConfig = {},
): ResolutionPlan | null {
  if ((config.enabled ?? true) === false) return null;
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new SecretResolutionError("Tool input must be an object", "INVALID_INPUT");
  }

  const rules = [
    ...((config.includeDefaults ?? true) ? DEFAULT_TOOL_RESOLUTION_RULES : []),
    ...normalizeRules(config.rules ?? []),
  ].filter((rule) => globMatches(rule.tool, toolName));
  const known = new Set(lookup.placeholders());
  const operations: Operation[] = [];
  const handles = new Set<string>();
  const paths = new Set<string>();

  const useHandles = (found: string[], path: PathSegment[]): void => {
    const unknown = found.filter((handle) => !known.has(handle));
    if (unknown.length > 0) {
      throw new SecretResolutionError(`Unknown or invented secret handle(s): ${unknown.join(", ")}`, "UNKNOWN_HANDLE");
    }
    for (const handle of found) handles.add(handle);
    paths.add(formatPath(path));
  };

  const visit = (value: unknown, path: PathSegment[], parent?: Container, key?: string | number): void => {
    if (typeof value === "string") {
      const found = findSecretHandles(value);
      if (found.length === 0 || parent === undefined || key === undefined) return;
      const rule = findAuthorizingRule(rules, path);
      if (!rule) throwUnauthorized(toolName, path);
      useHandles(found, path);
      if ((rule.adapter ?? "text") === "json") {
        operations.push({ container: parent, key, value: resolveJsonContainer(value, lookup, known, useHandles, path) });
      } else {
        operations.push({ container: parent, key, value: replaceKnownHandles(value, lookup) });
      }
      return;
    }
    if (!value || typeof value !== "object") return;
    for (const [childKey, child] of Object.entries(value as Record<string, unknown>)) {
      const childPath = [...path, childKey];
      if (findSecretHandles(childKey).length > 0) {
        throw new SecretResolutionError(`Secret handles are not allowed in argument keys (${formatPath(childPath)})`, "UNAUTHORIZED_PATH");
      }
      const rule = findAuthorizingRule(rules, childPath);
      if (rule?.adapter === "json" && containsSecretHandle(child)) {
        useJsonContainer(child, childPath, value as Container, childKey, rule, lookup, known, useHandles, operations);
      } else {
        visit(child, childPath, value as Container, childKey);
      }
    }
  };

  visit(input, []);
  if (handles.size === 0) return null;
  return {
    toolName,
    handles: [...handles].sort(),
    paths: [...paths].sort(),
    apply() {
      for (const operation of operations) applyOperation(operation);
    },
  };
}

function applyOperation(operation: Operation): void {
  if (Array.isArray(operation.container) || typeof operation.key === "number") {
    (operation.container as unknown[])[Number(operation.key)] = operation.value;
    return;
  }
  // Preserve own keys such as "__proto__" without invoking legacy setters.
  Object.defineProperty(operation.container, operation.key, {
    value: operation.value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

function useJsonContainer(
  value: unknown,
  path: PathSegment[],
  parent: Container,
  key: string | number,
  _rule: ToolResolutionRule,
  lookup: SecretLookup,
  known: Set<string>,
  useHandles: (found: string[], path: PathSegment[]) => void,
  operations: Operation[],
): void {
  operations.push({ container: parent, key, value: resolveJsonContainer(value, lookup, known, useHandles, path) });
}

function resolveJsonContainer(
  raw: unknown,
  lookup: SecretLookup,
  known: Set<string>,
  useHandles: (found: string[], path: PathSegment[]) => void,
  rootPath: PathSegment[],
): unknown {
  const wasString = typeof raw === "string";
  let parsed: unknown = raw;
  if (wasString) {
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new SecretResolutionError("JSON secret container is invalid; refusing unsafe string substitution", "INVALID_JSON");
    }
  }
  if (!parsed || typeof parsed !== "object") {
    throw new SecretResolutionError("JSON secret containers must be objects or arrays", "INVALID_INPUT");
  }
  const seen = new WeakSet<object>();
  const clone = (value: unknown, path: PathSegment[]): unknown => {
    if (typeof value === "string") {
      const found = findSecretHandles(value);
      if (found.length > 0) useHandles(found, rootPath);
      return replaceKnownHandles(value, lookup);
    }
    if (!value || typeof value !== "object") return value;
    if (seen.has(value)) throw new SecretResolutionError("JSON secret container cannot be cyclic", "INVALID_INPUT");
    seen.add(value);
    if (Array.isArray(value)) return value.map((item, index) => clone(item, [...path, index]));
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (findSecretHandles(key).length > 0) {
        throw new SecretResolutionError(`Secret handles are not allowed in argument keys (${formatPath([...path, key])})`, "UNAUTHORIZED_PATH");
      }
      // JSON permits an own "__proto__" key. Defining it avoids the legacy
      // Object.prototype setter and retains both the key and a safe prototype.
      Object.defineProperty(output, key, {
        value: clone(child, [...path, key]),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return output;
  };
  const resolved = clone(parsed, rootPath);
  return wasString ? JSON.stringify(resolved) : resolved;
}

/** Validate real values before inserting them into a shell command string. */
export function assertShellSafeHandles(plan: ResolutionPlan, lookup: SecretLookup): void {
  if (plan.toolName !== "bash" && plan.toolName !== "powershell") return;
  const safe = /^[A-Za-z0-9._:\/@+=%-]+$/;
  for (const handle of plan.handles) {
    const value = lookup.secretFor(handle) ?? "";
    if (!safe.test(value)) {
      throw new SecretResolutionError(`${handle} contains whitespace or shell metacharacters; refusing command-string substitution`, "UNAUTHORIZED_PATH");
    }
  }
}

function throwUnauthorized(toolName: string, path: PathSegment[]): never {
  throw new SecretResolutionError(`Secret handle use is not authorized for ${toolName}.${formatPath(path)}`, "UNAUTHORIZED_PATH");
}

function normalizeRules(rules: ToolResolutionRule[]): ToolResolutionRule[] {
  return rules.filter((rule) =>
    rule && typeof rule.tool === "string" && rule.tool.length > 0 && Array.isArray(rule.paths) &&
    rule.paths.every((path) => typeof path === "string" && path.length > 0) &&
    (rule.adapter === undefined || rule.adapter === "text" || rule.adapter === "json"),
  );
}

function findAuthorizingRule(rules: ToolResolutionRule[], path: PathSegment[]): ToolResolutionRule | undefined {
  return rules.find((rule) => rule.paths.some((pattern) => pathMatches(parsePathPattern(pattern), path)));
}

function parsePathPattern(pattern: string): string[] {
  return pattern.replace(/^\$\.?/, "").split(".").filter(Boolean);
}

function pathMatches(pattern: string[], path: PathSegment[]): boolean {
  const actual = path.map(String);
  const visit = (patternIndex: number, actualIndex: number): boolean => {
    if (patternIndex === pattern.length) return actualIndex === actual.length;
    const part = pattern[patternIndex];
    if (part === "**") return visit(patternIndex + 1, actualIndex) || (actualIndex < actual.length && visit(patternIndex, actualIndex + 1));
    return actualIndex < actual.length && (part === "*" || part === actual[actualIndex]) && visit(patternIndex + 1, actualIndex + 1);
  };
  return visit(0, 0);
}

function globMatches(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escaped.replace(/\*/g, ".*").replace(/\?/g, ".")}$`).test(value);
}

function replaceKnownHandles(text: string, lookup: SecretLookup): string {
  return text.replace(HANDLE_RE, (handle) => lookup.secretFor(handle) ?? handle);
}

function formatPath(path: PathSegment[]): string {
  if (path.length === 0) return "$";
  return path.map((part, index) => typeof part === "number" ? `[${part}]` : index === 0 ? part : `.${part}`).join("");
}
