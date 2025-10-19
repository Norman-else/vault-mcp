# Vault MCP Server

通过 AI 直接访问 AWS 环境中的 HashiCorp Vault，支持多环境（开发/测试/生产）、Slack 集成和隐私保护模式。

## 功能

- 🔐 **多环境支持**：支持 dev/sat/prod 三个环境的独立配置
- 🔑 **AWS IAM 认证**：通过 aws-vault 自动处理 MFA 认证
- 📦 **KV Secrets 读取**：读取完整 secret 或单个字段
- 🔄 **动态 Secrets**：查询数据库凭证、AWS 凭证等动态生成的凭证
- 📋 **路径浏览**：列出和浏览 Vault 中的 secrets 结构
- 🤖 **AI 友好**：自然语言查询支持
- 💬 **Slack 集成**：可选的 Slack 通知功能
- 🔒 **隐私模式**：可配置是否将敏感数据返回给 AI

## 快速开始

### 1. 安装

```bash
cd /path/to/vault-mcp
pip install -e .
```

### 2. 配置 Cursor

在 Cursor 设置中配置 MCP 服务器（设置 → MCP Servers → Edit in settings.json）：

#### macOS/Linux 配置：

```json
{
  "mcpServers": {
    "vault": {
      "command": "/opt/homebrew/bin/python3",
      "args": ["-m", "vault_mcp.server"],
      "env": {
        "VAULT_ADDR_DEV": "https://vault.internal.dev.aws.example.com",
        "VAULT_HEADER_DEV": "vault.dev.example.com",
        "VAULT_ROLE_DEV": "vault_admin",
        "AWS_PROFILE_DEV": "dev",
        "AWS_REGION_DEV": "us-west-2",
        "K8S_CONTEXT_DEV": "dev-cluster",
        "VAULT_ADDR_SAT": "https://vault.internal.sat.aws.example.com",
        "VAULT_HEADER_SAT": "vault.sat.example.com",
        "VAULT_ROLE_SAT": "vault_admin",
        "AWS_PROFILE_SAT": "sat",
        "AWS_REGION_SAT": "us-west-2",
        "K8S_CONTEXT_SAT": "sat-cluster",
        "VAULT_ADDR_PROD": "https://vault.internal.prod.aws.example.com",
        "VAULT_HEADER_PROD": "vault.prod.example.com",
        "VAULT_ROLE_PROD": "vault_admin",
        "AWS_PROFILE_PROD": "prod",
        "AWS_REGION_PROD": "us-west-2",
        "K8S_CONTEXT_PROD": "prod-cluster"
      }
    }
  }
}
```

#### Windows 配置：

```json
{
  "mcpServers": {
    "vault": {
      "command": "python",
      "args": ["-m", "vault_mcp.server"],
      "env": {
        "VAULT_ADDR_DEV": "https://vault.internal.dev.aws.example.com",
        "VAULT_HEADER_DEV": "vault.dev.example.com",
        "VAULT_ROLE_DEV": "vault_admin",
        "AWS_PROFILE_DEV": "dev",
        "AWS_REGION_DEV": "us-west-2",
        "K8S_CONTEXT_DEV": "dev-cluster",
        "VAULT_ADDR_SAT": "https://vault.internal.sat.aws.example.com",
        "VAULT_HEADER_SAT": "vault.sat.example.com",
        "VAULT_ROLE_SAT": "vault_admin",
        "AWS_PROFILE_SAT": "sat",
        "AWS_REGION_SAT": "us-west-2",
        "K8S_CONTEXT_SAT": "sat-cluster",
        "VAULT_ADDR_PROD": "https://vault.internal.prod.aws.example.com",
        "VAULT_HEADER_PROD": "vault.prod.example.com",
        "VAULT_ROLE_PROD": "vault_admin",
        "AWS_PROFILE_PROD": "prod",
        "AWS_REGION_PROD": "us-west-2",
        "K8S_CONTEXT_PROD": "prod-cluster"
      }
    }
  }
}
```

**Windows 注意事项**：
- 使用 `python` 命令（确保 Python 在 PATH 中）
- 或使用完整路径：`C:\\Python312\\python.exe`

**多环境配置说明**：
- 将 `VAULT_ADDR`, `VAULT_HEADER_VALUE`, `VAULT_ROLE`, `AWS_PROFILE` 等后缀改为对应环境：`_DEV`, `_SAT`, `_PROD`
- `K8S_CONTEXT`：Kubernetes 上下文名称（如果 Vault 部署在 k8s 中，登录前会自动切换）
  - 如果不需要切换上下文，可以留空或删除该配置项

### 3. (可选) 启用 Slack 通知

1. **创建 Slack Bot**
   - 访问 https://api.slack.com/apps
   - 创建新应用，添加 Bot Token Scopes: `chat:write`
   - 获取 Bot User OAuth Token (以 `xoxb-` 开头)

2. **获取 User ID**
   ```bash
   curl -H "Authorization: Bearer xoxb-your-token" \
        "https://slack.com/api/users.list"
   ```

3. **配置环境变量**
   ```json
   {
     "env": {
       "SLACK_ENABLED": "true",
       "SLACK_BOT_TOKEN": "xoxb-1234567890-1234567890-abcdefghijklmnop",
       "SLACK_USER_ID": "U0123456789",
       "RETURN_DATA_TO_AI": "true"
     }
   }
   ```

### 4. 在 Cursor 中使用

直接在 AI 对话中使用自然语言：

```
# 登录到指定环境
帮我登录到 dev Vault
帮我登录到 prod Vault

# 读取 secrets
查看 secret/myapp/config 的内容
获取 secret/myapp/config 中的 password 字段

# 获取动态凭证
获取数据库 readonly 角色的临时凭证
获取 database/creds/readonly 的凭证

# 列出 secrets
列出 secret/myapp/ 下的所有 secrets
列出所有可用的数据库角色

# 登出
帮我登出 Vault
彻底登出 Vault，包括 AWS 凭证
```

## 工作原理

```
┌──────────────────────────┐
│ 在 Cursor 中让 AI 登录    │
└──────┬───────────────────┘
       │
       ↓
┌──────────────────────────┐
│ 选择环境 (dev/sat/prod)  │
└──────┬───────────────────┘
       │
       ↓
┌──────────────────────────┐
│ 自动切换 kubectl context │
│ (如果配置了 K8S_CONTEXT) │
└──────┬───────────────────┘
       │
       ↓
┌──────────────────────────┐
│ MCP 服务器自动调用        │
│ aws-vault export <env>   │
└──────┬───────────────────┘
       │
       ↓
┌──────────────────────────┐
│ 弹出 MFA 输入框           │
│ (你有 30 秒输入)          │
└──────┬───────────────────┘
       │
       ↓
┌──────────────────────────┐
│ 获取临时 AWS 凭证         │
└──────┬───────────────────┘
       │
       ↓
┌──────────────────────────┐
│ 使用 AWS IAM 认证登录     │
│ 到指定环境的 Vault       │
└──────────────────────────┘
```

## 可用的 MCP 工具

### 1. vault_login - 登录 Vault

登录到指定环境的 Vault。支持 dev、sat、prod 三个环境。

**参数**：
- `environment` (string, default: "dev") - 环境选择：dev/sat/prod

**示例**：
```
帮我登录到 sat Vault
```

### 2. vault_logout - 登出 Vault

登出当前的 Vault 会话，可选择是否清空 AWS 凭证缓存。

**参数**：
- `clear_aws_cache` (boolean, default: false)
  - `false` - 只清空 Vault token，保留 AWS 凭证缓存（下次登录不需要 MFA）
  - `true` - 同时清空 aws-vault 缓存（下次登录需要重新输入 MFA）

**示例**：
```
帮我登出 Vault
彻底登出 Vault，包括 AWS 凭证
```

### 3. vault_kv_get - 读取完整 Secret

从 KV 存储中读取完整的 secret（所有字段）。

**参数**：
- `path` (string, required) - Secret 路径，如：myapp/config
- `mount_point` (string, default: "secret") - KV mount point

**示例**：
```
查看 secret/myapp/config 的内容
获取 secret/myapp/prod/database 的所有配置
```

### 4. vault_kv_get_key - 读取单个字段

从 KV secret 中读取指定的单个字段。当只需要特定字段时使用。

**参数**：
- `path` (string, required) - Secret 路径，如：myapp/config
- `key` (string, required) - 字段名，如：password、api_key
- `mount_point` (string, default: "secret") - KV mount point

**示例**：
```
获取 secret/myapp/config 中的 password 字段
查询 myapp/config 的 api_key
```

**错误处理**：
```
你: 获取 myapp/config 的 invalid_key

AI: ❌ Key 'invalid_key' not found in secret
    Available keys: ["username", "password", "api_key", "db_host"]
    → 自动提示可用的字段名
```

### 5. vault_kv_list - 列出 KV Secrets

列出 KV 存储中指定路径下的所有 secrets。用于浏览和发现 secrets。

**参数**：
- `path` (string, default: "") - 要列出的路径，如：myapp/
- `mount_point` (string, default: "secret") - KV mount point

**示例**：
```
列出 secret/myapp/ 下的所有 secrets
列出根路径的所有 secrets
```

### 6. vault_read - 读取动态 Secrets

通用的 Vault 读取方法。用于读取数据库凭证、AWS 凭证、证书等动态生成的 secrets。

**参数**：
- `path` (string, required) - 完整的 Vault 路径

**示例**：
```
获取 database/creds/readonly 的凭证
查询 aws/creds/my-role 的 AWS 凭证
```

**返回值**包含**：
- `data` - Secret 数据
- `lease_id` - 租约 ID（动态凭证有效期标识）
- `lease_duration` - 凭证有效期（秒）
- `renewable` - 是否可续期

### 7. vault_list - 列出任意路径

列出指定路径下的所有子路径。这是一个通用的列表方法。

**参数**：
- `path` (string, required) - 要列出的路径

**示例**：
```
列出所有可用的数据库角色
列出 pki/certs 下的所有证书
```

## 🔒 隐私和安全配置

### 默认模式 (RETURN_DATA_TO_AI=true)

敏感数据返回给 AI，方便交互和处理。

```json
{
  "env": {
    "RETURN_DATA_TO_AI": "true"
  }
}
```

**AI 看到的响应**：
```json
{
  "success": true,
  "path": "database/creds/readonly",
  "data": {
    "username": "v-dev-readonly-xyz",
    "password": "A1b2C3d4E5"
  },
  "lease_duration": 3600
}
```

### 隐私模式 (RETURN_DATA_TO_AI=false)

敏感数据不返回给 AI，只发送到 Slack。防止敏感信息出现在 AI 对话历史中。

```json
{
  "env": {
    "RETURN_DATA_TO_AI": "false",
    "SLACK_ENABLED": "true"
  }
}
```

**AI 看到的响应**：
```json
{
  "success": true,
  "path": "database/creds/readonly",
  "message": "✓ Secret retrieved successfully and sent to Slack",
  "data_returned_to_ai": false,
  "slack_notification_sent": true,
  "available_keys": ["username", "password"],
  "lease_duration": 3600
}
```

**优点**：
- ✅ 敏感数据不会出现在 AI 对话历史中
- ✅ 减少数据泄露风险
- ✅ 符合企业合规要求
- ✅ 仍然可以在 Slack 中查看完整数据

### 数据对比表

| 数据项 | RETURN_DATA_TO_AI=true | RETURN_DATA_TO_AI=false |
|--------|------------------------|-----------------------|
| **查询状态** | ✅ 返回成功/失败 | ✅ 返回成功/失败 |
| **Secret 路径** | ✅ 返回 | ✅ 返回 |
| **字段名称 (keys)** | ✅ 返回 | ✅ 返回 |
| **字段值 (values)** | ✅ 完整返回 | ❌ 不返回 |
| **Slack 通知** | ✅ 同时发送 | ✅ 同时发送 |
| **AI 对话记录** | ⚠️ 包含完整 secret | ✅ 不含敏感数据 |
| **租约信息** | ✅ 返回（如有） | ✅ 返回（如有） |

## 🔔 Slack 集成

### 启用方式

在 MCP 配置中设置：

```json
{
  "env": {
    "SLACK_ENABLED": "true",
    "SLACK_BOT_TOKEN": "xoxb-...",
    "SLACK_USER_ID": "U0123456789"
  }
}
```

### 消息格式

**KV Secrets**：
```
🔐 Vault KV Secret Retrieved
Environment: DEV | Time: 2024-10-18 10:30:00
─────────────────────
Service: secret/myapp/config

{
  "api_key": "sk-...",
  "endpoint": "https://..."
}
```

**数据库凭证**：
```
🔐 Vault Secret Retrieved
Environment: DEV | Time: 2024-10-18 10:30:00
─────────────────────
Service: database/creds/readonly

Username: v-dev-readonly-xyz
Password: A1b2C3d4E5
```

### 可靠性保障

系统实现了多层保护机制：

**1. 智能数据格式化**
- 自动处理复杂对象（嵌套字典、列表等）
- 限制文本长度（Slack 限制 3000 字符）
- 超长内容自动截断，保留完整 JSON 结构

**2. 多级降级策略**
```
尝试 1: 发送格式化的 Block Kit 消息（精美格式）
   ↓ 失败
尝试 2: 发送纯文本消息（简化格式）
   ↓ 失败
记录错误日志，便于排查
```

**3. 特殊情况处理**
- 复杂对象自动转换为字符串
- 过长字段自动截断（保留前 500 字符）
- 非 UTF-8 字符自动处理

### 安全提示

⚠️ Slack 消息包含敏感信息，请确保：
- Bot 只能访问私人频道
- 使用后及时删除消息
- 定期轮换 Bot Token

## 使用示例

### 场景 1：获取单个字段 vs 完整 Secret

**只需要密码**：
```
你: 获取 myapp/config 的 password 字段

AI: ✓ 成功获取
   - Path: secret/myapp/config
   - Key: password
   - Value: my-secret-password
```

**需要所有配置**：
```
你: 获取 myapp/config 的所有配置

AI: {
     "username": "admin",
     "password": "my-secret-password",
     "api_key": "sk-xxx",
     "db_host": "localhost"
   }
```

### 场景 2：登出 Vault

**普通登出**（保留 AWS 凭证缓存）：
```
你: 帮我登出 Vault

AI: ✓ 已登出 Vault
   ℹ️  AWS credentials cache was not cleared
```

**完全登出**（清空 AWS 凭证缓存）：
```
你: 彻底登出 Vault，包括 AWS 凭证

AI: ✓ 已登出 Vault
   ✓ 已清空 AWS 凭证缓存
   下次登录需要重新输入 MFA
```

## 故障排查

### ❌ "aws-vault command timed out"

**原因**：没有在 30 秒内输入 MFA 代码

**解决方案**：
1. 重新让 AI 登录
2. 当 MFA 弹窗出现时，**快速输入代码**

### ❌ 认证失败："Failed to authenticate with Vault"

**可能原因**：
1. aws-vault 未配置
2. kubectl 上下文错误（如果 Vault 在 k8s 中）
3. 网络问题

**检查步骤**：
```bash
# 1. 检查 aws-vault
which aws-vault
aws-vault list
aws-vault export dev --format=json

# 2. 检查 kubectl（如果 Vault 在 k8s）
kubectl config get-contexts
kubectl config current-context

# 3. 测试 Vault 连接
curl -k https://vault.internal.dev.aws.example.com/v1/sys/health
```

### 📝 查看详细日志

在 Cursor 中：
1. 打开"输出"面板（View → Output）
2. 选择 "MCP" 频道
3. 查看详细的认证过程和错误信息

## 项目结构

```
vault-mcp/
├── src/vault_mcp/
│   ├── __init__.py
│   └── server.py          # MCP 服务器（核心代码）
├── pyproject.toml         # 项目配置和依赖
└── README.md              # 本文件
```

## 🔒 安全说明

### 只读保证

**本 MCP 服务器经过安全审计，确保 100% 只读操作。**

- ✅ **零写操作**：代码中完全没有实现任何写入、修改、删除方法
- ✅ **只读 API**：只使用 hvac 的读取和列表方法
- ✅ **认证保护**：所有操作都需要有效的 Vault token
- ✅ **错误隐瞒**：异常处理不泄露敏感信息

### 实现的操作

| 操作 | 类型 | 安全性 |
|------|------|--------|
| `vault_login` | 认证 | ✅ 只获取 token |
| `vault_kv_get` | 读取 | ✅ 只读 |
| `vault_kv_get_key` | 读取 | ✅ 只读 |
| `vault_kv_list` | 列表 | ✅ 只列出路径 |
| `vault_read` | 读取 | ✅ 只读 |
| `vault_list` | 列表 | ✅ 只列出路径 |
| `vault_logout` | 清理 | ✅ 只清除本地状态 |

### 未实现的操作（永久禁止）

❌ 写入 / 创建 / 更新 / 删除 / 修改 / 销毁

代码经过设计，确保 100% 只读操作，无任何写入方法。

### 最佳实践

1. **使用只读 Vault 策略**：为此服务配置的角色只授予读取权限
2. **临时凭证**：使用临时 AWS 凭证和 Vault token
3. **审计日志**：所有操作记录在 Vault 审计日志中
4. **最小权限**：只访问必要的 secrets
5. **定期轮换**：定期轮换 Slack Bot Token 和 AWS 凭证

## 依赖

- Python 3.10+
- mcp >= 1.0.0
- hvac >= 2.0.0
- boto3 >= 1.34.0
- python-dotenv >= 1.0.0
- slack-sdk >= 3.27.0（可选，用于 Slack 集成）
- aws-vault（系统命令）

## License

MIT
