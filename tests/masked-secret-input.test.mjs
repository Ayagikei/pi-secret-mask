import assert from "node:assert/strict";
import test from "node:test";
import { MaskedSecretInput } from "../src/masked-secret-input.ts";

test("masked TUI input bounds prompt display and never renders captured text", () => {
  let captured;
  const input = new MaskedSecretInput(
    "TOKEN\x1b[31m\n" + "n".repeat(200),
    "purpose\x1b]0;title\x07\n" + "p".repeat(200),
    { requestRender() {} },
    { fg: (_style, text) => `\x1b[36m${text}\x1b[0m` },
    (value) => { captured = value; },
  );
  input.focused = true;
  input.handleInput("local-value");
  const lines = input.render(40);
  assert.equal(lines.some((line) => line.includes("local-value")), false);
  assert.equal(lines.some((line) => line.includes("\n")), false);
  assert.ok(lines.some((line) => line.includes("•")));
  input.handleInput("\r");
  assert.equal(captured, "local-value");
});
