# 数据流安全分析：vault_kv_get 方法

## 执行流程分析

### 当 `RETURN_DATA_TO_AI=true` 时

```
用户请求：查询 secret/myapp/config
         ↓
┌─────────────────────────────────────────┐
│ vault_kv_get(path="myapp/config",       │
│              mount_point="secret")      │
└─────────────────┬───────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│ 1. 从 Vault 读取 secret                 │
│    response = vault_client.secrets.     │
│               kv.v2.read_secret_version │
│                                          │
│    获取到的数据:                         │
│    data = {                             │
│      "username": "admin",               │
│      "password": "secret123",           │
│      "api_key": "sk-xxxx",              │
│      "db_host": "localhost"             │
│    }                                    │
└─────────────────┬───────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│ 2. 发送 Slack 通知                      │
│    _send_slack_notification(            │
│      data=data,  // 完整数据            │
│      query_type="kv",                   │
│      service_name="secret/myapp/config" │
│    )                                    │
│                                          │
│    Slack 接收：完整 data 内容           │
└─────────────────┬───────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│ 3. 检查 return_data_to_ai 配置          │
│    if not self.return_data_to_ai:       │
│      // false 分支 → 跳过               │
│                                          │
│    self.return_data_to_ai = true        │
│    → 执行第 583-586 行                  │
└─────────────────┬───────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│ 4. 返回给 AI 的完整数据                 │
│    return json.dumps({                  │
│      "success": true,                   │
│      "path": "secret/myapp/config",     │
│      "data": {                          │
│        "username": "admin",      ⚠️     │
│        "password": "secret123",  ⚠️     │
│        "api_key": "sk-xxxx",     ⚠️     │
│        "db_host": "localhost"    ⚠️     │
│      }                                  │
│    })                                   │
└─────────────────┬───────────────────────┘
                  ↓
           AI 接收到完整数据
```

## 返回给 AI 的数据详情

### ✅ 成功响应（RETURN_DATA_TO_AI=true）

```json
{
  "success": true,
  "path": "secret/myapp/config",
  "data": {
    // ⚠️ 所有 Vault secret 的原始内容
    // 包括但不限于：
    "username": "...",      // 用户名
    "password": "...",      // 密码
    "api_key": "...",       // API 密钥
    "private_key": "...",   // 私钥
    "token": "...",         // Token
    "connection_string": "...", // 连接字符串
    // ... 以及 Vault 中存储的任何其他字段
  }
}
```

**暴露的敏感信息：**
- ✅ 完整的 secret 键值对
- ✅ 所有字段名称
- ✅ 所有字段值
- ✅ Secret 的完整路径

**不暴露的信息：**
- ❌ Vault metadata（版本号、创建时间等）
- ❌ Vault 租约信息（KV secret 没有租约）

### ✅ 隐私模式响应（RETURN_DATA_TO_AI=false）

```json
{
  "success": true,
  "path": "secret/myapp/config",
  "message": "✓ Secret retrieved successfully and sent to Slack",
  "data_returned_to_ai": false,
  "slack_notification_sent": true,
  "available_keys": ["username", "password", "api_key", "db_host"]  // ✅ 只返回字段名
}
```

**暴露的信息：**
- ✅ Secret 路径
- ✅ 字段名称（keys）
- ✅ 操作状态

**不暴露的信息：**
- ❌ 字段值（values）- 敏感数据完全隐藏
- ❌ Vault metadata

### ❌ 错误响应（任何配置）

```json
{
  "success": false,
  "error": "hvac.exceptions.InvalidPath: ...",  // ⚠️ 可能泄露 Vault 内部信息
  "path": "secret/myapp/config"
}
```

**暴露的信息：**
- ✅ 错误详情（可能包含 Vault 版本、路径结构等）
- ✅ Secret 路径
- ⚠️ 异常堆栈（str(e) 可能包含敏感信息）

## 安全风险评估

### 🔴 高风险（RETURN_DATA_TO_AI=true）

| 风险项 | 描述 | 影响 |
|--------|------|------|
| **数据完全暴露** | 所有 secret 内容返回给 AI | AI 对话历史中保存完整凭证 |
| **多字段泄露** | 不只是单个字段，所有字段都暴露 | 攻击者获得完整配置 |
| **路径可见** | Secret 完整路径暴露 | 暴露 Vault 组织结构 |
| **错误信息** | 异常详情可能泄露 Vault 信息 | 帮助攻击者了解系统 |

### 🟢 低风险（RETURN_DATA_TO_AI=false）

| 保护项 | 描述 | 效果 |
|--------|------|------|
| **值隐藏** | 不返回字段值 | AI 看不到敏感内容 |
| **键可见** | 返回字段名称列表 | AI 可以理解数据结构 |
| **仅状态信息** | 只返回成功/失败状态 | 最小化信息泄露 |
| **路径仍可见** | 路径名称仍然返回 | ⚠️ 轻微风险 |

## 建议的安全改进

### 1. 敏感字段过滤（即使 RETURN_DATA_TO_AI=true）

```python
# 建议添加敏感字段名称列表
SENSITIVE_FIELD_NAMES = [
    "password", "passwd", "pwd",
    "secret", "token", "key",
    "private_key", "api_key", "apikey",
    "credential", "auth",
]

def mask_sensitive_data(data: dict) -> dict:
    """对敏感字段进行脱敏"""
    masked = {}
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in SENSITIVE_FIELD_NAMES):
            masked[key] = "***REDACTED***"
        else:
            masked[key] = value
    return masked
```

### 2. 错误信息脱敏

```python
except Exception as e:
    # 当前：返回完整错误
    return json.dumps({"success": False, "error": str(e), "path": path})
    
    # 建议：返回通用错误
    logger.error(f"Error reading secret {path}: {e}")
    return json.dumps({
        "success": False, 
        "error": "Failed to retrieve secret",
        "path": path
    })
```

### 3. 路径脱敏（可选）

```python
# 对于极度敏感的环境，可以隐藏路径
if self.return_data_to_ai:
    return json.dumps({
        "success": True,
        "path": f"{mount_point}/{path}",
        "data": data
    })
else:
    return json.dumps({
        "success": True,
        "path_hash": hashlib.sha256(f"{mount_point}/{path}".encode()).hexdigest()[:8],
        "message": "✓ Secret sent to Slack"
    })
```

## 对比表：两种配置模式

| 数据项 | RETURN_DATA_TO_AI=true | RETURN_DATA_TO_AI=false |
|--------|------------------------|-------------------------|
| **success 状态** | ✅ 返回 | ✅ 返回 |
| **path 路径** | ✅ 返回 | ✅ 返回 |
| **available_keys** | ✅ 返回（包含在 data 中） | ✅ 返回（单独字段） |
| **data 字段（完整）** | ✅ 返回 | ❌ 不返回 |
| **字段值（values）** | ✅ 返回 | ❌ 不返回 |
| **username 值** | ✅ 返回 | ❌ 不返回 |
| **password 值** | ✅ 返回 | ❌ 不返回 |
| **其他 secret 值** | ✅ 返回 | ❌ 不返回 |
| **错误详情** | ✅ 返回 | ✅ 返回（当前实现）⚠️ |
| **Slack 通知** | ✅ 发送 | ✅ 发送 |
| **AI 对话记录** | ⚠️ 包含敏感数据 | ✅ 不含敏感数据 |

## 结论

**当 RETURN_DATA_TO_AI=true 时：**
- ✅ 从 Vault 获取的**所有数据**都会返回给 AI
- ⚠️ 包括所有敏感字段（password、api_key、token 等）
- ⚠️ 这些数据会保存在 AI 对话历史中
- ⚠️ 错误信息也可能泄露系统信息

**当 RETURN_DATA_TO_AI=false 时：**
- ✅ 只返回字段名称（keys），不返回字段值（values）
- ✅ AI 可以理解数据结构，但看不到敏感内容
- ✅ 敏感数据只通过 Slack 发送
- ✅ AI 对话历史不包含任何敏感信息

**推荐配置：**
- 生产环境：`RETURN_DATA_TO_AI=false` + `SLACK_ENABLED=true`
- 开发环境：`RETURN_DATA_TO_AI=true`（方便调试）
- 测试环境：`RETURN_DATA_TO_AI=true`（非敏感数据）

