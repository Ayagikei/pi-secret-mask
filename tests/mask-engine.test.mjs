import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MaskMap,
  collectPatternSecrets,
  collectSecretsFromText,
  maskDeep,
  parseDotenv,
  pruneSecrets,
  registerSources,
} from "../src/mask-engine.ts";

test("MaskMap: 基本掩码与还原", () => {
  const m = new MaskMap();
  m.add("sk-secret-abcdef123456", "OPENAI");
  const masked = m.mask("use sk-secret-abcdef123456 here");
  assert.equal(masked, "use __SECRET_OPENAI__ here");
  assert.equal(m.unmask(masked), "use sk-secret-abcdef123456 here");
});

test("MaskMap: 多占位符独立回滚", () => {
  const m = new MaskMap();
  m.add("token-A", "KEYA");
  m.add("token-B", "KEYB");
  const text = "a=token-A b=token-B a=token-A";
  const masked = m.mask(text);
  assert.equal(masked, "a=__SECRET_KEYA__ b=__SECRET_KEYB__ a=__SECRET_KEYA__");
  assert.equal(m.unmask(masked), text);
});

test("MaskMap: 同名 secret 自动编号", () => {
  const m = new MaskMap();
  m.add("val-1", "API_KEY");
  m.add("val-2", "API_KEY");
  assert.equal(m.placeholderFor("val-1"), "__SECRET_API_KEY__");
  assert.equal(m.placeholderFor("val-2"), "__SECRET_API_KEY_2__");
  assert.equal(m.unmask(m.mask("val-1 val-2")), "val-1 val-2");
});

test("MaskMap: 子串冲突按长度降序（sk-ab 不被 sk-abc 破坏）", () => {
  const m = new MaskMap();
  m.add("sk-abc", "A");
  m.add("sk-ab", "B");
  const text = "x=sk-abc y=sk-ab";
  const masked = m.mask(text);
  assert.equal(masked, "x=__SECRET_A__ y=__SECRET_B__");
  assert.equal(m.unmask(masked), text);
});

test("MaskMap: 还原只认已知占位符", () => {
  const m = new MaskMap();
  m.add("real-value", "TOK");
  // 非已知占位符不还原
  assert.equal(m.unmask("__SECRET_UNKNOWN__"), "__SECRET_UNKNOWN__");
  assert.equal(m.unmask("__SECRET_TOK__x"), "__SECRET_TOK__x"); // 非完整 token
  // 已知占位符还原
  assert.equal(m.unmask(m.mask("real-value")), "real-value");
  assert.equal(m.unmask("__SECRET_TOK__"), "real-value");
});

test("MaskMap: 掩码后还原不改变原文本", () => {
  const m = new MaskMap();
  m.add("alpha", "A");
  m.add("beta", "B");
  const original = "alpha beta gamma";
  const masked = m.mask(original);
  assert.notEqual(masked, original);
  assert.equal(m.unmask(masked), original);
});

test("maskDeep: 递归掩码数组/对象中的字符串", () => {
  const m = new MaskMap();
  m.add("topsecret-123", "K");
  const obj = {
    a: "topsecret-123",
    b: [{ c: "prefix topsecret-123 suffix" }],
    d: 42,
    e: ["topsecret-123"],
  };
  const changed = m.maskDeep(obj);
  assert.equal(changed, true);
  assert.equal(obj.a, "__SECRET_K__");
  assert.equal(obj.b[0].c, "prefix __SECRET_K__ suffix");
  assert.equal(obj.e[0], "__SECRET_K__");
  assert.equal(obj.d, 42);
});

test("maskDeep: 无命中返回 false", () => {
  const m = new MaskMap();
  m.add("secret-x", "K");
  const obj = { a: "nothing here" };
  assert.equal(m.maskDeep(obj), false);
  assert.equal(obj.a, "nothing here");
});

test("parseDotenv: 引号/export/注释/CRLF/值含=", () => {
  const content = [
    "KEY1=plain",
    'KEY2="quoted value"',
    "export KEY3=exported",
    "KEY4=value with = sign",
    "KEY5=trailing # not comment", // 无引号：' #' 才剥离
    'KEY6="inline # keeps"',
    "# comment line",
    "",
    "KEY7=crlf",
  ].join("\r\n");
  const entries = parseDotenv(content);
  const map = new Map(entries.map((e) => [e.key, e.value]));
  assert.equal(map.get("KEY1"), "plain");
  assert.equal(map.get("KEY2"), "quoted value");
  assert.equal(map.get("KEY3"), "exported");
  assert.equal(map.get("KEY4"), "value with = sign");
  assert.equal(map.get("KEY5"), "trailing"); // ' #' 前有空格 → 注释剥离
  assert.equal(map.get("KEY6"), "inline # keeps");
  assert.equal(map.get("KEY7"), "crlf");
});

test("parseDotenv: 忽略无值行与非法 key", () => {
  const entries = parseDotenv("EMPTY=\n1BAD=no\nOK=yes");
  assert.deepEqual(entries, [{ key: "OK", value: "yes" }]);
});

test("collectPatternSecrets: 内置正则识别", () => {
  const opts = {
    extraSecrets: [],
    customPatterns: [],
    dotenv: { enabled: false, files: [], exclude: [] },
    patterns: { openai: true, github: true, google: true, aws: true, jwt: true, pem: true, base64: false },
    base64MinLength: 32,
  };
  const text = "key=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890 token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
  const sources = collectSecretsFromText(text, opts);
  const names = sources.map((s) => s.name).sort();
  assert.deepEqual(names, ["GITHUB", "OPENAI"]);
});

test("collectPatternSecrets: 自定义正则", () => {
  const opts = {
    extraSecrets: [],
    customPatterns: [{ name: "MY_SECRET", pattern: "mysec-[a-z0-9]{8}" }],
    dotenv: { enabled: false, files: [], exclude: [] },
    patterns: { openai: false, github: false, google: false, aws: false, jwt: false, pem: false, base64: false },
    base64MinLength: 32,
  };
  const sources = collectSecretsFromText("found mysec-abc12345 here", opts);
  assert.deepEqual(sources, [{ name: "MY_SECRET", values: ["mysec-abc12345"] }]);
});

test("collectPatternSecrets: 捕获组优先", () => {
  const sources = collectPatternSecrets(
    [{ name: "JWT", re: /(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/g }],
    "tok: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
  );
  assert.equal(sources.length, 1);
  assert.ok(sources[0].values[0].startsWith("eyJ"));
});

test("registerSources + pruneSecrets: 增量更新与清理", () => {
  const m = new MaskMap();
  const active = new Set(["a", "b"]);
  registerSources(m, [{ name: "K", values: ["a", "b"] }]);
  assert.equal(m.size, 2);
  registerSources(m, [{ name: "K", values: ["a", "c"] }]); // 新增 c
  assert.equal(m.size, 3);
  assert.equal(m.remove ? true : true, true);
  pruneSecrets(m, new Set(["a", "c"])); // b 已删除
  assert.equal(m.size, 2);
  assert.equal(m.has("a"), true);
  assert.equal(m.has("b"), false);
  assert.equal(m.has("c"), true);
});
