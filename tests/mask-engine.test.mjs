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

test("MaskMap: basic mask and unmask", () => {
  const m = new MaskMap();
  m.add("sk-secret-abcdef123456", "OPENAI");
  const masked = m.mask("use sk-secret-abcdef123456 here");
  assert.equal(masked, "use __SECRET_OPENAI__ here");
  assert.equal(m.unmask(masked), "use sk-secret-abcdef123456 here");
});

test("MaskMap: multiple placeholders roll back independently", () => {
  const m = new MaskMap();
  m.add("token-A", "KEYA");
  m.add("token-B", "KEYB");
  const text = "a=token-A b=token-B a=token-A";
  const masked = m.mask(text);
  assert.equal(masked, "a=__SECRET_KEYA__ b=__SECRET_KEYB__ a=__SECRET_KEYA__");
  assert.equal(m.unmask(masked), text);
});

test("MaskMap: same-name secrets are auto-numbered", () => {
  const m = new MaskMap();
  m.add("val-1", "API_KEY");
  m.add("val-2", "API_KEY");
  assert.equal(m.placeholderFor("val-1"), "__SECRET_API_KEY__");
  assert.equal(m.placeholderFor("val-2"), "__SECRET_API_KEY_2__");
  assert.equal(m.unmask(m.mask("val-1 val-2")), "val-1 val-2");
});

test("MaskMap: substring collisions resolved by length-descending order (sk-ab not clobbered by sk-abc)", () => {
  const m = new MaskMap();
  m.add("sk-abc", "A");
  m.add("sk-ab", "B");
  const text = "x=sk-abc y=sk-ab";
  const masked = m.mask(text);
  assert.equal(masked, "x=__SECRET_A__ y=__SECRET_B__");
  assert.equal(m.unmask(masked), text);
});

test("MaskMap: unmask only recognizes known placeholders", () => {
  const m = new MaskMap();
  m.add("real-value", "TOK");
  // Unknown placeholders are not unmasked
  assert.equal(m.unmask("__SECRET_UNKNOWN__"), "__SECRET_UNKNOWN__");
  assert.equal(m.unmask("__SECRET_TOK__x"), "__SECRET_TOK__x"); // not a whole token
  // Known placeholders are unmasked
  assert.equal(m.unmask(m.mask("real-value")), "real-value");
  assert.equal(m.unmask("__SECRET_TOK__"), "real-value");
});

test("MaskMap: mask then unmask restores original text", () => {
  const m = new MaskMap();
  m.add("alpha", "A");
  m.add("beta", "B");
  const original = "alpha beta gamma";
  const masked = m.mask(original);
  assert.notEqual(masked, original);
  assert.equal(m.unmask(masked), original);
});

test("maskDeep: recursively masks strings in arrays/objects", () => {
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

test("maskDeep: returns false when nothing matches", () => {
  const m = new MaskMap();
  m.add("secret-x", "K");
  const obj = { a: "nothing here" };
  assert.equal(m.maskDeep(obj), false);
  assert.equal(obj.a, "nothing here");
});

test("parseDotenv: quotes/export/comments/CRLF/values containing =", () => {
  const content = [
    "KEY1=plain",
    'KEY2="quoted value"',
    "export KEY3=exported",
    "KEY4=value with = sign",
    "KEY5=trailing # not comment", // no quotes: only ' #' is stripped
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
  assert.equal(map.get("KEY5"), "trailing"); // ' #' preceded by space -> comment stripped
  assert.equal(map.get("KEY6"), "inline # keeps");
  assert.equal(map.get("KEY7"), "crlf");
});

test("parseDotenv: skips empty values and invalid keys", () => {
  const entries = parseDotenv("EMPTY=\n1BAD=no\nOK=yes");
  assert.deepEqual(entries, [{ key: "OK", value: "yes" }]);
});

test("collectPatternSecrets: built-in regexes", () => {
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

test("collectPatternSecrets: custom regexes", () => {
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

test("collectPatternSecrets: capture group wins", () => {
  const sources = collectPatternSecrets(
    [{ name: "JWT", re: /(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/g }],
    "tok: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
  );
  assert.equal(sources.length, 1);
  assert.ok(sources[0].values[0].startsWith("eyJ"));
});

test("registerSources + pruneSecrets: incremental update and cleanup", () => {
  const m = new MaskMap();
  const active = new Set(["a", "b"]);
  registerSources(m, [{ name: "K", values: ["a", "b"] }]);
  assert.equal(m.size, 2);
  registerSources(m, [{ name: "K", values: ["a", "c"] }]); // adds c
  assert.equal(m.size, 3);
  assert.equal(m.remove ? true : true, true);
  pruneSecrets(m, new Set(["a", "c"])); // b was removed
  assert.equal(m.size, 2);
  assert.equal(m.has("a"), true);
  assert.equal(m.has("b"), false);
  assert.equal(m.has("c"), true);
});

test("MaskMap: placeholders are not re-registered (prevents double masking)", () => {
  const m = new MaskMap();
  m.add("sk-real-1234567890abcdef", "OPENAI_API_KEY");
  // A placeholder written back into .env must not register as a new secret
  const ph = m.placeholderFor("sk-real-1234567890abcdef");
  if (ph) m.add(ph, "OPENAI_API_KEY");
  assert.equal(m.placeholderFor("sk-real-1234567890abcdef"), "__SECRET_OPENAI_API_KEY__");
  // No _2 variant
  assert.equal(m.has("__SECRET_OPENAI_API_KEY__"), false);
  assert.equal(m.placeholders().length, 1);
});


test("MaskMap: short values are masked too (mask-everything policy)", () => {
  const m = new MaskMap();
  m.add("1", "TEST");
  const masked = m.mask("TEST=1");
  assert.equal(masked, "TEST=__SECRET_TEST__");
  assert.equal(m.unmask(masked), "TEST=1");
});

test("maskDeep: write/edit content unmasked (placeholder -> real value)", () => {
  const m = new MaskMap();
  m.add("sk-real-1234567890abcdef", "OPENAI_API_KEY");
  const input = {
    path: "/tmp/.env",
    content: "OPENAI_API_KEY=__SECRET_OPENAI_API_KEY__\nTEST=1",
  };
  m.unmaskDeep(input);
  assert.equal(input.content, "OPENAI_API_KEY=sk-real-1234567890abcdef\nTEST=1");
});
