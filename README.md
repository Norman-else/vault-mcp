# Vault MCP Server

通过 AI 直接访问 AWS 环境中的 HashiCorp Vault。

## 功能

- 🔐 通过 AWS IAM 认证访问 Vault
- 📦 读取 KV secrets（应用配置、API keys 等）
- 🔄 查询动态 secrets（数据库凭证、AWS 凭证等）
- 📋 列出和浏览 secrets 路径
- 🤖 AI 驱动的自然语言查询

## 快速开始

### 1. 安装

```bash
cd /Users/normanzuo/PersonalRepos/vault-mcp
pip install -e .
```

### 2. 配置

在 Cursor 设置中配置 MCP 服务器（设置 -> MCP Servers -> Edit in settings.json）：

#### macOS/Linux 配置：

```json
{
  "mcpServers": {
    "vault": {
      "command": "/opt/homebrew/Caskroom/miniconda/base/bin/python",
      "args": ["-m", "vault_mcp.server"],
      "env": {
        "VAULT_ADDR": "https://vault.internal.dev.aws.example.com",
        "VAULT_HEADER_VALUE": "vault.dev.example.com",
        "VAULT_ROLE": "vault_admin",
        "AWS_PROFILE": "dev",
        "AWS_REGION": "us-west-2",
        "K8S_CONTEXT": "dev-cluster",
        "PYTHONPATH": "/Users/your-username/vault-mcp/src"
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
        "VAULT_ADDR": "https://vault.internal.dev.aws.example.com",
        "VAULT_HEADER_VALUE": "vault.dev.example.com",
        "VAULT_ROLE": "vault_admin",
        "AWS_PROFILE": "dev",
        "AWS_REGION": "us-west-2",
        "K8S_CONTEXT": "dev-cluster",
        "PYTHONPATH": "C:\\Users\\YourUsername\\vault-mcp\\src"
      }
    }
  }
}
```

**Windows 注意事项**：
- 使用 `python` 命令（确保 Python 在 PATH 中）
- 或使用完整路径：`C:\\Python312\\python.exe`
- PYTHONPATH 使用反斜杠并需要转义：`C:\\Users\\...`
- 或使用正斜杠：`C:/Users/.../vault-mcp/src`

**重要配置项**：
- `K8S_CONTEXT`: Kubernetes 上下文名称（如果 Vault 部署在 k8s 中）
  - 如果不需要切换上下文，可以留空或删除该配置项
  - 查看可用上下文：`kubectl config get-contexts`
  - 登录前会自动切换到指定的 k8s 上下文

### 3. 启动 Cursor

**直接启动** Cursor（从 Dock/Finder/命令行都可以）：

```bash
cursor .
```

### 4. 在 AI 对话中登录

```
帮我登录到 Vault
```

当 MFA 弹窗出现时，**输入你的 MFA 代码**（有 30 秒时间）。

✅ MCP 服务器会自动调用 `aws-vault export` 获取凭证！

## 工作原理

```
┌──────────────────────────┐
│ 在 Cursor 中让 AI 登录    │
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
│ aws-vault export dev     │
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
│ 使用凭证登录 Vault       │
└──────────────────────────┘
```

## 🔔 Slack 集成（可选）

自动将查询结果发送到 Slack，方便团队协作和记录。

### 启用 Slack 通知

1. **创建 Slack Bot**
   - 访问 https://api.slack.com/apps
   - 创建新应用，添加 Bot Token Scopes: `chat:write`
   - 获取 Bot User OAuth Token (以 `xoxb-` 开头)

2. **获取 User ID**
   ```bash
   # 方法 1: 在 Slack 点击你的头像 -> View profile -> More -> Copy member ID
   # 方法 2: 使用 API
   curl -H "Authorization: Bearer xoxb-your-token" \
        "https://slack.com/api/users.list"
   ```

3. **配置环境变量**
   ```json
   {
     "env": {
       "SLACK_ENABLED": "true",
       "SLACK_BOT_TOKEN": "xoxb-1234567890-1234567890-abcdefghijklmnop",
       "SLACK_USER_ID": "U0123456789"
     }
   }
   ```

### 消息格式

**数据库凭证**（只发送必要信息）：
```
🔐 Vault Secret Retrieved
Environment: DEV | Time: 2024-10-18 10:30:00
─────────────────────
Service: database/creds/readonly
Username: v-dev-readonly-xyz
Password: ********
```

**其他 Secrets**（完整 JSON）：
```
🔐 Vault KV Secret Retrieved
Environment: PROD | Time: 2024-10-18 10:30:00
─────────────────────
Service: secret/myapp/config
{
  "api_key": "sk-...",
  "endpoint": "https://..."
}
```

### 安全提示
⚠️ Slack 消息包含敏感信息，请确保：
- Bot 只能访问私人频道
- 使用后及时删除消息
- 定期轮换 Bot Token

## 🔒 高级安全配置

### 禁止返回敏感数据给 AI

为了最大化安全性，可以配置不将敏感数据返回给 AI，只通过 Slack 发送：

```json
{
  "env": {
    "RETURN_DATA_TO_AI": "false",  // 设置为 false 不返回数据给 AI
    "SLACK_ENABLED": "true"        // 必须启用 Slack
  }
}
```

**启用后的效果：**

```
你: "获取数据库 readonly 的凭证"

AI: ✓ Secret retrieved successfully and sent to Slack
    - Path: database/creds/readonly
    - Data returned to AI: No
    - Slack notification sent: Yes
    - Lease ID: database/creds/readonly/abc123
    - Lease duration: 3600 seconds
```

**优点：**
- ✅ 敏感数据不会出现在 AI 对话历史中
- ✅ 减少数据泄露风险
- ✅ 符合合规要求
- ✅ 你仍然可以在 Slack 中查看完整数据

**注意事项：**
- ⚠️ 必须启用 Slack (`SLACK_ENABLED=true`)，否则你无法获取数据
- ⚠️ 租约信息（lease_id、lease_duration）仍会返回，因为不包含敏感数据

### 两种模式对比

| 数据项 | `RETURN_DATA_TO_AI=true` | `RETURN_DATA_TO_AI=false` |
|--------|--------------------------|---------------------------|
| **查询状态** | ✅ 返回成功/失败 | ✅ 返回成功/失败 |
| **Secret 路径** | ✅ 返回 | ✅ 返回 |
| **敏感数据** | ✅ 完整返回给 AI | ❌ 不返回给 AI |
| **Slack 通知** | ✅ 同时发送 | ✅ 同时发送 |
| **AI 对话记录** | ⚠️ 包含完整 secret | ✅ 不含敏感数据 |
| **租约信息** | ✅ 返回（如有） | ✅ 返回（如有） |

**示例 - 查询数据库凭证：**

```bash
# RETURN_DATA_TO_AI=true 时，AI 看到：
{
  "success": true,
  "path": "database/creds/readonly",
  "data": {
    "username": "v-dev-readonly-xyz",    // ⚠️ 暴露给 AI
    "password": "A1b2C3d4E5"             // ⚠️ 暴露给 AI
  },
  "lease_id": "database/creds/readonly/abc123",
  "lease_duration": 3600
}

# RETURN_DATA_TO_AI=false 时，AI 看到：
{
  "success": true,
  "path": "database/creds/readonly",
  "message": "✓ Secret retrieved successfully and sent to Slack",
  "data_returned_to_ai": false,
  "slack_notification_sent": true,
  "lease_id": "database/creds/readonly/abc123",  // 租约信息保留
  "lease_duration": 3600
}

# 在两种模式下，Slack 都会收到完整凭证
```

## 使用示例

在 Cursor 的 AI 对话中：

```
# 登录
"帮我登录到 Vault"

# 读取 KV secret
"查看 secret/myapp/config 的内容"

# 获取数据库临时凭证
"获取数据库 readonly 角色的临时凭证"

# 列出 secrets
"列出 secret/myapp/ 下的所有 secrets"

# 查看数据库角色
"列出所有可用的数据库角色"

# 登出（清空登录状态）
"帮我登出 Vault"
"清空当前的 Vault 登录状态"
```

### 使用场景

#### 📤 登出 Vault
```
# 普通登出（保留 AWS 凭证缓存）
你："帮我登出 Vault"
AI：✓ 已登出 Vault
    ℹ️  AWS credentials cache was not cleared

# 完全登出（同时清空 AWS 凭证缓存）
你："彻底登出 Vault，包括 AWS 凭证"
AI：✓ 已登出 Vault
    ✓ 已清空 AWS 凭证缓存
    下次登录需要重新输入 MFA
```

**两种登出方式**：

1. **普通登出**（默认）
   - 只清空 Vault token
   - 保留 AWS 凭证缓存
   - 下次登录不需要 MFA（如果凭证未过期）

2. **完全登出**（clear_aws_cache=true）
   - 清空 Vault token
   - 清空 aws-vault 的凭证缓存
   - 下次登录需要重新输入 MFA

**使用场景**：
- 切换到不同的 AWS profile 前 → 使用**完全登出**
- 结束工作时 → 使用**完全登出**
- 想强制刷新 AWS 凭证时 → 使用**完全登出**
- 只是切换 Vault 操作，不切换 AWS → 使用**普通登出**
- 遇到认证问题需要重置时 → 使用**完全登出**

## 可用的 MCP 工具

1. **vault_login** - 使用 AWS IAM 认证登录到 Vault
2. **vault_logout** - 登出 Vault，可选择是否清空 AWS 凭证缓存
   - `clear_aws_cache=false`（默认）：只清空 Vault token
   - `clear_aws_cache=true`：同时清空 aws-vault 凭证缓存
3. **vault_kv_get** - 读取 KV secret
4. **vault_kv_list** - 列出 KV secrets
5. **vault_read** - 读取动态 secrets（数据库凭证等）
6. **vault_list** - 列出任意路径

## 故障排查

### ❌ "aws-vault command timed out"

**原因**：没有在 30 秒内输入 MFA 代码

**解决方案**：

1. 重新让 AI 登录
2. 当 MFA 弹窗出现时，**快速输入代码**（有 30 秒时间）

### ❌ 认证失败："Failed to authenticate with Vault"

**可能原因**：

1. **aws-vault 未配置**
2. **kubectl 上下文错误**（如果 Vault 在 k8s 中）
3. **网络问题**

**检查步骤**：

```bash
# 1. 检查 aws-vault
which aws-vault
aws-vault list
aws-vault export dev --format=json

# 2. 检查 kubectl（如果 Vault 在 k8s）
kubectl config get-contexts
kubectl config current-context
kubectl config use-context dev-cluster

# 3. 测试 Vault 连接
curl -k https://vault.internal.dev.aws.example.com/v1/sys/health
```

### 📝 查看详细日志

在 Cursor 中：
1. 打开"输出"面板（View -> Output）
2. 选择 "MCP" 频道
3. 查看详细的认证过程和错误信息

日志会显示：
- 是否从环境变量找到 AWS 凭证
- 是否尝试通过 aws-vault 获取凭证
- Vault 认证是否成功
- 具体的错误信息

## 项目结构

```
vault-mcp/
├── src/vault_mcp/
│   ├── __init__.py
│   └── server.py          # MCP 服务器（核心代码）
├── pyproject.toml         # 项目配置和依赖
├── cursor-config.json     # Cursor MCP 配置
└── README.md              # 本文件
```

## 安全说明

### 🔒 只读保证

**本 MCP 服务器经过安全审计，确保 100% 只读操作。**

- ✅ **零写操作**: 代码中完全没有实现任何写入、修改、删除方法
- ✅ **只读 API**: 只使用 hvac 的读取和列表方法
- ✅ **认证保护**: 所有操作都需要有效的 Vault token
- ✅ **错误隔离**: 异常处理不泄露敏感信息

### 🛡️ 数据隐私保护

**可配置数据返回策略：**

- ✅ **默认模式** (`RETURN_DATA_TO_AI=true`): 数据返回给 AI，方便交互
- ✅ **隐私模式** (`RETURN_DATA_TO_AI=false`): 敏感数据只发送到 Slack，不返回给 AI
  - 避免敏感数据出现在 AI 对话历史中
  - 符合企业合规要求
  - 必须配合 Slack 通知使用

### 实现的操作

| 操作 | 类型 | 安全性 |
|------|------|--------|
| `vault_login` | 认证 | ✅ 只获取 token |
| `vault_kv_get` | 读取 | ✅ 只读 |
| `vault_kv_list` | 列表 | ✅ 只列出路径 |
| `vault_read` | 读取 | ✅ 只读 |
| `vault_list` | 列表 | ✅ 只列出路径 |

### 未实现的操作（永久禁止）

❌ 写入 / 创建 / 更新 / 删除 / 修改 / 销毁

代码经过安全审计，确保 100% 只读操作，无任何写入方法。

### 最佳实践

1. **使用只读 Vault 策略**：为此服务配置的角色只授予读取权限
2. **临时凭证**：使用临时 AWS 凭证和 Vault token
3. **审计日志**：所有操作记录在 Vault 审计日志中
4. **最小权限**：只访问必要的 secrets

## 依赖

- Python 3.10+
- mcp >= 1.0.0
- hvac >= 2.0.0
- boto3 >= 1.34.0
- python-dotenv >= 1.0.0
- aws-vault（系统命令）

## License

MIT
