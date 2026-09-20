/**
 * Pure state machine behind the masked TUI input. Kept independent from Pi so
 * paste handling and non-disclosure can be unit-tested without Pi packages.
 */
export type SecretInputAction =
  | { type: "none" }
  | { type: "render" }
  | { type: "submit"; value: string }
  | { type: "cancel" };

const PASTE_START = "\x1b[200~";
const PASTE_END = "\x1b[201~";
export const MAX_SECRET_INPUT_CODEPOINTS = 4096;

export class SecretInputBuffer {
  private value = "";
  private pasteBuffer = "";
  private inPaste = false;
  private errorMessage: string | undefined;

  get length(): number {
    return [...this.value].length;
  }

  get error(): string | undefined {
    return this.errorMessage;
  }

  /** Returns bullets only; the caller never needs the raw value for rendering. */
  masked(maxBullets = Number.POSITIVE_INFINITY): string {
    return "•".repeat(Math.min(this.length, Math.max(0, maxBullets)));
  }

  clear(): void {
    this.value = "";
    this.pasteBuffer = "";
    this.inPaste = false;
    this.errorMessage = undefined;
  }

  feed(data: string): SecretInputAction {
    this.errorMessage = undefined;

    if (!this.inPaste) {
      const start = data.indexOf(PASTE_START);
      if (start !== -1) {
        const prefix = data.slice(0, start);
        if (prefix) this.appendPrintable(prefix);
        this.inPaste = true;
        this.pasteBuffer = data.slice(start + PASTE_START.length);
        return this.consumePasteBuffer();
      }
    }

    if (this.inPaste) {
      this.pasteBuffer += data;
      return this.consumePasteBuffer();
    }

    if (data === "\r" || data === "\n") {
      if (this.value.length === 0) {
        this.errorMessage = "Secret cannot be empty. Enter a value or press Esc to decline.";
        return { type: "render" };
      }
      const value = this.value;
      this.clear();
      return { type: "submit", value };
    }

    if (data === "\x1b") {
      this.clear();
      return { type: "cancel" };
    }

    if (data === "\x7f" || data === "\b") {
      this.value = [...this.value].slice(0, -1).join("");
      return { type: "render" };
    }

    if (data === "\x15") {
      this.value = "";
      return { type: "render" };
    }

    // Secret capture is a single-line channel. Never silently concatenate a
    // pasted or terminal-buffered multi-line value.
    if (/\r|\n/.test(data)) {
      this.clear();
      this.errorMessage = "Multi-line secret rejected. Use a protected file or a dedicated credential tool instead.";
      return { type: "render" };
    }

    // Ignore escape sequences such as cursor keys. Secret fields intentionally
    // do not support cursor movement, avoiding accidental partial disclosure.
    if (data.startsWith("\x1b")) return { type: "none" };

    return this.appendPrintable(data) ? { type: "render" } : { type: "none" };
  }

  private consumePasteBuffer(): SecretInputAction {
    const end = this.pasteBuffer.indexOf(PASTE_END);
    if (end === -1) return { type: "render" };

    const pasted = this.pasteBuffer.slice(0, end);
    const remainder = this.pasteBuffer.slice(end + PASTE_END.length);
    this.pasteBuffer = "";
    this.inPaste = false;

    // One trailing line ending commonly comes from copying a file. Interior
    // newlines are rejected because request_secret is a single-value channel.
    const normalized = pasted.replace(/(?:\r\n|\r|\n)$/, "");
    if (/\r|\n/.test(normalized)) {
      this.errorMessage = "Multi-line secret rejected. Use a protected file or a dedicated credential tool instead.";
      return { type: "render" };
    }
    this.appendPrintable(normalized);

    if (remainder) return this.feed(remainder);
    return { type: "render" };
  }

  private appendPrintable(data: string): boolean {
    // Strip C0/C1 controls and terminal escape fragments before retaining any
    // input. Retain only a bounded, single-line Unicode value.
    const printable = [...data].filter((char) => {
      const code = char.codePointAt(0)!;
      return code >= 0x20 && code !== 0x7f && (code < 0x80 || code > 0x9f);
    });
    if (printable.length === 0) return false;
    const remaining = MAX_SECRET_INPUT_CODEPOINTS - this.length;
    if (remaining <= 0) {
      this.errorMessage = `Secret is limited to ${MAX_SECRET_INPUT_CODEPOINTS} characters.`;
      return true;
    }
    this.value += printable.slice(0, remaining).join("");
    if (printable.length > remaining) this.errorMessage = `Secret is limited to ${MAX_SECRET_INPUT_CODEPOINTS} characters.`;
    return true;
  }
}
