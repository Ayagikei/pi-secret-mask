import { SecretInputBuffer } from "./secret-input-buffer.ts";

const MAX_PROMPT_CODEPOINTS = 160;

/** Remove terminal control sequences from model-controlled prompt metadata. */
function safePromptText(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const clean = [...value]
    .filter((char) => {
      const code = char.codePointAt(0)!;
      return code >= 0x20 && code !== 0x7f && (code < 0x80 || code > 0x9f);
    })
    .slice(0, MAX_PROMPT_CODEPOINTS)
    .join("")
    .trim();
  return clean || undefined;
}

/**
 * Minimal structural interface accepted by ctx.ui.custom(). Deliberately uses
 * no direct Pi imports, so pi-secret-mask keeps its existing peer dependencies.
 */
export class MaskedSecretInput {
  focused = false;
  private readonly buffer = new SecretInputBuffer();
  private readonly name: string;
  private readonly purpose: string | undefined;
  private readonly tui: { requestRender?: () => void };
  private readonly theme: { fg?: (style: string, text: string) => string } | undefined;
  private readonly done: (value: string | undefined) => void;

  constructor(
    name: string,
    purpose: string | undefined,
    tui: { requestRender?: () => void },
    theme: { fg?: (style: string, text: string) => string } | undefined,
    done: (value: string | undefined) => void,
  ) {
    this.name = safePromptText(name) ?? "USER";
    this.purpose = safePromptText(purpose);
    this.tui = tui;
    this.theme = theme;
    this.done = done;
  }

  handleInput(data: string): void {
    const action = this.buffer.feed(data);
    if (action.type === "submit") {
      this.done(action.value);
      return;
    }
    if (action.type === "cancel") {
      this.done(undefined);
      return;
    }
    if (action.type === "render") this.tui.requestRender?.();
  }

  render(width: number): string[] {
    const safeWidth = Math.max(1, width || 1);
    const style = (name: string, text: string) => this.theme?.fg?.(name, text) ?? text;
    // Truncate raw text before theming: ANSI escape sequences injected by a
    // theme must never be counted as display characters or split mid-sequence.
    const truncate = (text: string) => [...text].slice(0, safeWidth).join("");
    const title = style("accent", truncate(`Secret requested: ${this.name}`));
    const purpose = this.purpose ? style("muted", truncate(`Purpose: ${this.purpose}`)) : undefined;
    const suffix = ` (${this.buffer.length} chars)`;
    const cursor = this.focused ? "▎" : " ";
    const cursorWidth = [...cursor].length;
    const status = [...suffix].slice(0, Math.max(0, safeWidth - 2 - cursorWidth)).join("");
    const bulletBudget = Math.max(0, safeWidth - 2 - cursorWidth - [...status].length);
    const field = `  ${this.buffer.masked(bulletBudget)}${cursor}${style("dim", status)}`;

    const lines = [title];
    if (purpose) lines.push(purpose);
    lines.push("", field, "");
    if (this.buffer.error) lines.push(style("error", truncate(this.buffer.error)), "");
    lines.push(style("muted", truncate("Enter submit · Esc decline · Backspace edit · Ctrl+U clear")));
    return lines;
  }

  invalidate(): void {}
}
