# Vault Manager

一个功能强大的 HashiCorp Vault 管理工具，提供 **MCP 服务器**和**现代化 Web UI** 两种访问方式，支持多环境管理、AWS IAM 认证和 Slack 集成。

## ✨ 核心特性

### 🖥️ 现代化 Web UI
- **可视化管理**：直观的图形界面管理 KV Secrets 和数据库凭证
- **实时操作**：创建、查看、编辑 secrets，支持版本管理
- **数据库凭证**：一键生成临时数据库凭证，支持密码显示/隐藏和快速复制
- **全局搜索**：快捷键（⌘K/Ctrl+K）快速搜索 secrets 和 keys
- **多主题支持**：Light/Dark 主题自动切换
- **响应式设计**：适配桌面和移动端

### 🤖 MCP 服务器（AI 集成）
- **自然语言交互**：在 Cursor 中通过 AI 对话直接访问 Vault
- **多环境支持**：Dev/SAT/Prod 三个环境独立配置
- **AWS IAM 认证**：通过 aws-vault 自动处理 MFA 认证
- **Slack 集成**：可选的 Slack 通知功能
- **隐私模式**：可配置是否将敏感数据返回给 AI

### 🔐 安全特性
- **只读保证**：MCP 服务器 100% 只读操作（Web UI 支持完整 CRUD）
- **多环境隔离**：Dev/SAT/Prod 环境完全隔离
- **临时凭证**：支持生成临时数据库凭证
- **版本控制**：KV Secrets 版本管理和历史查看
- **审计日志**：所有操作记录在 Vault 审计日志中

## 🚀 快速开始

### 1. 安装

```bash
cd /path/to/vault-mcp
pip install -e .
```

### 2. 启动 Web UI

#### 方法 1：直接启动（推荐）

```bash
# 启动 Web UI（默认端口 8765）
python -m vault_mcp.web_ui
```

浏览器会自动打开 `http://localhost:8765`

#### 方法 2：自定义端口和主机

```bash
# 自定义端口
WEB_UI_PORT=8080 python -m vault_mcp.web_ui

# 指定监听地址（默认 0.0.0.0）
WEB_UI_HOST=127.0.0.1 WEB_UI_PORT=8765 python -m vault_mcp.web_ui
```

### 3. 配置环境变量

创建 `.env` 文件或设置环境变量：

```bash
# Dev 环境配置
VAULT_ADDR_DEV=https://vault.internal.dev.aws.example.com
VAULT_HEADER_DEV=vault.dev.example.com
VAULT_ROLE_DEV=vault_admin
AWS_PROFILE_DEV=dev
AWS_REGION_DEV=us-west-2
K8S_CONTEXT_DEV=dev-cluster

# SAT 环境配置
VAULT_ADDR_SAT=https://vault.internal.sat.aws.example.com
VAULT_HEADER_SAT=vault.sat.example.com
VAULT_ROLE_SAT=vault_admin
AWS_PROFILE_SAT=sat
AWS_REGION_SAT=us-west-2
K8S_CONTEXT_SAT=sat-cluster

# Prod 环境配置
VAULT_ADDR_PROD=https://vault.internal.prod.aws.example.com
VAULT_HEADER_PROD=vault.prod.example.com
VAULT_ROLE_PROD=vault_admin
AWS_PROFILE_PROD=prod
AWS_REGION_PROD=us-west-2
K8S_CONTEXT_PROD=prod-cluster

# Web UI 配置（可选）
WEB_UI_PORT=8765
WEB_UI_HOST=0.0.0.0
```

**注意**：
- `K8S_CONTEXT`：Kubernetes 上下文名称（如果 Vault 部署在 k8s 中，登录前会自动切换）
- 如果不需要切换上下文，可以留空或删除该配置项

### 4. 使用 Web UI

1. **登录**：选择环境（Dev/SAT/Prod/Local），输入 MFA 代码
2. **浏览 Secrets**：左侧树形结构浏览 KV Secrets
3. **管理 Secrets**：创建、编辑 secrets，查看版本历史
4. **生成数据库凭证**：切换到 "Database Credentials" 模式，选择角色生成临时凭证
5. **全局搜索**：按 ⌘K (macOS) 或 Ctrl+K (Windows) 打开搜索框

## 🤖 配置 MCP 服务器（Cursor AI 集成）

### macOS/Linux 配置

在 Cursor 设置中配置 MCP 服务器（设置 → MCP Servers → Edit in settings.json）：

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

### Windows 配置

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

### 在 Cursor 中使用

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

## 📖 Web UI 功能详解

### KV Secrets 管理

#### 浏览和查看
- **树形结构**：左侧面板显示文件夹和 secrets 的层级结构
- **面包屑导航**：快速跳转到父级路径
- **Secret 详情**：查看所有 key-value 对，支持密码显示/隐藏
- **版本管理**：查看和切换 secret 的历史版本

#### 创建和编辑
- **新建 Secret**：点击 "New Secret" 按钮，输入路径和 key-value 对
- **添加字段**：在现有 secret 中添加新的 key-value 对
- **更新值**：修改现有字段的值（自动创建新版本）

#### 高级功能
- **版本回滚**：切换到历史版本查看旧数据
- **复制值**：一键复制 secret 值到剪贴板
- **密码隐藏**：敏感字段默认隐藏，点击眼睛图标显示
- **长文本支持**：textarea 输入框支持多行长文本

### 数据库凭证管理

#### 生成凭证
1. 切换到 "Database Credentials" 模式
2. 从左侧选择数据库角色（如 `readonly`, `readwrite`）
3. 点击 "Generate Credentials" 生成临时凭证
4. 查看 username 和 password，以及有效期信息

#### 凭证操作
- **显示/隐藏密码**：点击眼睛图标切换密码显示
- **复制单个字段**：复制 username 或 password
- **复制全部凭证**：一键复制 username 和 password
- **重新生成**：点击 "Generate New" 生成新凭证（旧凭证会被吊销）

#### 有效期管理
- 显示凭证的租约 ID 和有效期
- 到期前可以重新生成新凭证

### 全局搜索

#### 打开搜索
- **快捷键**：⌘K (macOS) 或 Ctrl+K (Windows/Linux)
- **按钮**：点击顶部工具栏的搜索图标

#### 搜索功能
- **实时搜索**：输入时自动搜索（300ms 防抖）
- **搜索范围**：搜索当前环境下的所有 secret 路径和 key 名称
- **键盘导航**：上下箭头选择结果，Enter 打开，ESC 关闭
- **匹配高亮**：显示匹配类型（路径匹配/Key 匹配）

## 🛠️ MCP 工具参考

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

### 5. vault_kv_list - 列出 KV Secrets

列出 KV 存储中指定路径下的所有 secrets。

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

**返回值包含**：
- `data` - Secret 数据
- `lease_id` - 租约 ID（动态凭证有效期标识）
- `lease_duration` - 凭证有效期（秒）
- `renewable` - 是否可续期

### 7. vault_list - 列出任意路径

列出指定路径下的所有子路径。

**参数**：
- `path` (string, required) - 要列出的路径

**示例**：
```
列出所有可用的数据库角色
列出 pki/certs 下的所有证书
```

### 8. vault_web_ui_open - 打开 Web UI

打开 Vault Web UI 进行交互式管理。

**参数**：无

**功能**：
- 启动 Web UI 服务器（如果未运行）
- 自动在浏览器中打开 UI
- 提供美观的图形界面管理 secrets

**示例**：
```
帮我打开 Vault Web UI
打开 Vault 管理界面
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

## 🔔 Slack 集成（可选）

### 启用方式

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

   如果公司代理或 VPN 替换了 HTTPS 证书链，可以把公司根证书 bundle 配给 Slack 客户端：
   ```json
   {
     "env": {
       "SLACK_CA_BUNDLE": "/path/to/company-ca-bundle.pem"
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

### 安全提示

⚠️ Slack 消息包含敏感信息，请确保：
- Bot 只能访问私人频道
- 使用后及时删除消息
- 定期轮换 Bot Token

## 🏗️ 工作原理

### Web UI 工作流程

```
┌──────────────────────────┐
│ 启动 Web UI 服务器        │
│ python -m vault_mcp.web_ui│
└──────┬───────────────────┘
       │
       ↓
┌──────────────────────────┐
│ 浏览器打开 localhost:8765 │
└──────┬───────────────────┘
       │
       ↓
┌──────────────────────────┐
│ 选择环境并登录            │
│ (Dev/SAT/Prod/Local)     │
└──────┬───────────────────┘
       │
       ↓
┌──────────────────────────┐
│ 输入 MFA 代码             │
└──────┬───────────────────┘
       │
       ↓
┌──────────────────────────┐
│ 浏览和管理 Secrets        │
│ - KV Secrets CRUD        │
│ - 数据库凭证生成          │
│ - 全局搜索               │
└──────────────────────────┘
```

### MCP 服务器工作流程

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
│ (Web UI 不限制等待时间)   │
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

## 📁 项目结构

```
vault-mcp/
├── src/vault_mcp/
│   ├── __init__.py
│   ├── server.py              # MCP 服务器（AI 集成）
│   ├── web_ui.py              # Web UI 服务器（Flask）
│   ├── templates/
│   │   └── vault_ui.html      # Web UI 前端（HTML+CSS+JS）
│   └── static/
│       └── favicon.png        # 网站图标
├── pyproject.toml             # 项目配置和依赖
└── README.md                  # 本文件
```

## 🔒 安全说明

### MCP 服务器：只读保证

**MCP 服务器经过安全审计，确保 100% 只读操作。**

- ✅ **零写操作**：代码中完全没有实现任何写入、修改、删除方法
- ✅ **只读 API**：只使用 hvac 的读取和列表方法
- ✅ **认证保护**：所有操作都需要有效的 Vault token
- ✅ **错误隐瞒**：异常处理不泄露敏感信息

| 操作 | 类型 | 安全性 |
|------|------|--------|
| `vault_login` | 认证 | ✅ 只获取 token |
| `vault_kv_get` | 读取 | ✅ 只读 |
| `vault_kv_get_key` | 读取 | ✅ 只读 |
| `vault_kv_list` | 列表 | ✅ 只列出路径 |
| `vault_read` | 读取 | ✅ 只读 |
| `vault_list` | 列表 | ✅ 只列出路径 |
| `vault_logout` | 清理 | ✅ 只清除本地状态 |
| `vault_web_ui_open` | UI | ✅ 只启动服务器 |

### Web UI：完整管理功能

**Web UI 提供完整的管理功能，包括创建和更新操作。**

| 操作 | KV Secrets | Database Credentials |
|------|-----------|---------------------|
| 查看 | ✅ | ✅ |
| 创建 | ✅ | ✅ 生成 |
| 更新 | ✅ | ✅ 重新生成 |
| 版本管理 | ✅ | N/A |

### 最佳实践

1. **使用适当的 Vault 策略**
   - MCP 服务器：使用只读策略
   - Web UI：根据需要配置读写权限
2. **临时凭证**：使用临时 AWS 凭证和 Vault token
3. **审计日志**：所有操作记录在 Vault 审计日志中
4. **最小权限**：只访问必要的 secrets
5. **定期轮换**：定期轮换 Slack Bot Token 和 AWS 凭证
6. **网络安全**：
   - Web UI 默认监听 0.0.0.0，建议在生产环境使用反向代理
   - 或修改 `WEB_UI_HOST=127.0.0.1` 只允许本地访问

## 🔧 故障排查

### ❌ "aws-vault command timed out"

**原因**：非 Web UI 登录调用仍使用有限的 MFA 等待时间

**解决方案**：
1. 重新登录
2. 如需不限制 MFA 等待时间，请使用 Web UI 登录

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

### ❌ Web UI 无法访问

**可能原因**：
1. 端口被占用
2. 防火墙阻止

**解决方案**：
```bash
# 更换端口
WEB_UI_PORT=8080 python -m vault_mcp.web_ui

# 检查端口占用
lsof -i :8765
netstat -an | grep 8765
```

### 📝 查看详细日志

**MCP 服务器**：
1. 打开 Cursor "输出"面板（View → Output）
2. 选择 "MCP" 频道
3. 查看详细的认证过程和错误信息

**Web UI**：
- 服务器日志会输出到控制台
- 浏览器控制台显示前端错误

## 📦 依赖

- Python 3.10+
- mcp >= 1.0.0
- hvac >= 2.0.0
- boto3 >= 1.34.0
- python-dotenv >= 1.0.0
- flask >= 3.0.0
- flask-cors >= 4.0.0
- slack-sdk >= 3.27.0（可选，用于 Slack 集成）
- aws-vault（系统命令，用于 AWS IAM 认证）
- kubectl（可选，如果 Vault 部署在 k8s 中）

## 📝 License

MIT

---

**提示**：首次使用建议先启动 Web UI 熟悉界面和功能，然后再配置 MCP 服务器用于 AI 集成。
