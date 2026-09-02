import assert from "node:assert/strict";
import test from "node:test";
import { MAX_SECRET_INPUT_CODEPOINTS, SecretInputBuffer } from "../src/secret-input-buffer.ts";

test("the render-facing API exposes bullets and length, not plaintext", () => {
  const buffer = new SecretInputBuffer();
  buffer.feed("super-secret");
  assert.equal(buffer.length, 12);
  assert.equal(buffer.masked(), "•".repeat(12));
  assert.equal(JSON.stringify({ masked: buffer.masked(), length: buffer.length }).includes("super-secret"), false);
});

test("backspace removes one Unicode code point", () => {
  const buffer = new SecretInputBuffer();
  buffer.feed("ab😀");
  buffer.feed("\x7f");
  assert.equal(buffer.length, 2);
  assert.deepEqual(buffer.feed("\r"), { type: "submit", value: "ab" });
});

test("Ctrl+U clears the buffer", () => {
  const buffer = new SecretInputBuffer();
  buffer.feed("secret");
  buffer.feed("\x15");
  assert.equal(buffer.length, 0);
});

test("bracketed paste accepts one trailing newline", () => {
  const buffer = new SecretInputBuffer();
  buffer.feed("\x1b[200~abc123\n\x1b[201~");
  assert.equal(buffer.length, 6);
  assert.deepEqual(buffer.feed("\r"), { type: "submit", value: "abc123" });
});

test("multi-line paste is rejected without retaining the pasted secret", () => {
  const buffer = new SecretInputBuffer();
  buffer.feed("\x1b[200~line-one\nline-two\x1b[201~");
  assert.match(buffer.error ?? "", /Multi-line/);
  assert.equal(buffer.length, 0);
});

test("Esc cancels and clears the buffer", () => {
  const buffer = new SecretInputBuffer();
  buffer.feed("secret");
  assert.deepEqual(buffer.feed("\x1b"), { type: "cancel" });
  assert.equal(buffer.length, 0);
});

test("empty submission is rejected", () => {
  const buffer = new SecretInputBuffer();
  assert.deepEqual(buffer.feed("\r"), { type: "render" });
  assert.match(buffer.error ?? "", /cannot be empty/);
});

test("terminal controls are discarded and input remains bounded", () => {
  const buffer = new SecretInputBuffer();
  buffer.feed("a\x1b]0;title\x07b\x80c");
  assert.deepEqual(buffer.feed("\r"), { type: "submit", value: "a]0;titlebc" });

  buffer.feed("x".repeat(MAX_SECRET_INPUT_CODEPOINTS + 1));
  assert.equal(buffer.length, MAX_SECRET_INPUT_CODEPOINTS);
  assert.match(buffer.error ?? "", /limited/);
});
