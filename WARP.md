# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview
Vault MCP is an MCP (Model Context Protocol) server that provides AI-powered access to HashiCorp Vault in AWS environments. It supports multi-environment configurations (dev/sat/prod), AWS IAM authentication via aws-vault, Slack integration, and privacy-preserving modes for sensitive data handling.

## Development Setup

### Installation
```bash
# Install in development mode
pip install -e .

# Install with all dependencies including optional ones
pip install -e ".[slack,webui]"
```

### Environment Configuration
The server requires multi-environment configuration through environment variables:
- `VAULT_ADDR_<ENV>`: Vault server URL for each environment (dev/sat/prod)
- `VAULT_HEADER_<ENV>`: Vault header value for routing
- `VAULT_ROLE_<ENV>`: IAM role for authentication
- `AWS_PROFILE_<ENV>`: AWS profile name for aws-vault
- `AWS_REGION_<ENV>`: AWS region
- `K8S_CONTEXT_<ENV>`: Kubernetes context (optional, for vault-in-k8s setups)

Example MCP server configuration for Windows (in Warp/Cursor settings):
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
        "SLACK_ENABLED": "false",
        "RETURN_DATA_TO_AI": "true"
      }
    }
  }
}
```

## Architecture

### Core Components

**VaultMCPServer (server.py)**
- Main MCP server implementing the Model Context Protocol
- Handles authentication via AWS IAM using aws-vault
- Manages multi-environment configurations (dev/sat/prod)
- Provides read-only Vault operations (KV secrets, dynamic credentials)
- Integrates with Slack for secure notifications
- Implements privacy modes for sensitive data protection

**VaultWebUI (web_ui.py)**
- Flask-based web interface for interactive secret management
- Provides REST API endpoints for CRUD operations on secrets
- Browser-based UI for visualization and editing
- Runs on localhost:8765 (configurable via WEB_UI_PORT)

### Authentication Flow
1. User requests login to specific environment (dev/sat/prod)
2. Server switches kubectl context if K8S_CONTEXT is configured
3. Server calls `aws-vault export <profile>` to get temporary AWS credentials
4. User inputs MFA code when prompted (Web UI waits without a timeout limit)
5. Server uses AWS credentials to authenticate to Vault via IAM
6. Vault token is cached for subsequent operations

### Data Privacy Modes

**Default Mode (RETURN_DATA_TO_AI=true)**
- All secret data returned to AI for interactive use
- Convenient for development and non-sensitive environments
- Data appears in AI conversation history

**Privacy Mode (RETURN_DATA_TO_AI=false)**
- Secret values NOT returned to AI
- Only metadata (keys, paths, status) returned
- Full data sent to Slack if configured
- Prevents sensitive data in AI conversation logs
- Recommended for production environments

See `DATA_FLOW_ANALYSIS.md` for detailed security analysis.

## MCP Tools

The server exposes these MCP tools (callable by AI):

- **vault_login**: Authenticate to specified environment (dev/sat/prod)
- **vault_logout**: Clear vault token and optionally AWS credentials cache
- **vault_kv_get**: Read complete secret from KV store
- **vault_kv_get_key**: Read single field from KV secret
- **vault_kv_list**: List secrets in KV path
- **vault_read**: Read dynamic secrets (database creds, AWS creds, etc.)
- **vault_list**: List any Vault path
- **vault_web_ui_open**: Launch interactive web UI

## Key Design Patterns

### Multi-Environment Configuration
The server uses a dictionary-based environment configuration pattern:
```python
self.environments = {
    "dev": {...},
    "sat": {...},
    "prod": {...}
}
```
All environment-specific settings (Vault URL, AWS profile, k8s context) are looked up dynamically based on the selected environment.

### External Dependency Handling
External dependencies (aws-vault, kubectl) are called via subprocess with proper timeout and error handling. Web UI MFA prompts wait without a timeout limit so users can complete the popup at their own pace; non-Web UI calls still use a bounded wait:
```python
result = subprocess.run(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    timeout=30  # Non-Web UI MFA input timeout
)
```

### Graceful Degradation
Optional features (Slack, Web UI) gracefully degrade if dependencies aren't installed:
```python
try:
    from slack_sdk import WebClient
    SLACK_AVAILABLE = True
except ImportError:
    SLACK_AVAILABLE = False
```

### Slack Notification Reliability
Multi-tier fallback strategy for Slack notifications:
1. Try rich Block Kit formatting
2. Fall back to plain text if blocks fail
3. Log errors without failing the main operation

## Code Organization

```
vault-mcp/
├── src/vault_mcp/
│   ├── __init__.py          # Package initialization
│   ├── server.py            # Main MCP server (~1200 lines)
│   ├── web_ui.py            # Web UI server (~400 lines)
│   └── templates/
│       └── vault_ui.html    # Web UI frontend
├── pyproject.toml           # Dependencies and build config
├── README.md                # User documentation
├── DATA_FLOW_ANALYSIS.md    # Security analysis of data flows
└── WEB_UI_INTEGRATION.md    # Web UI integration guide
```

## Important Constraints

### Security Constraints
1. **Read-Only Operations**: Server implements ONLY read operations. No write/update/delete methods exist in the codebase (by design).
2. **No Secret Creation**: The MCP tools cannot create or modify secrets (Web UI can, but that's separate).
3. **Token Security**: Vault tokens are stored in memory only, never persisted to disk.
4. **Audit Trail**: All operations are logged to Vault's audit log.

### Windows-Specific Considerations
- Use `python` command (not `python3`) in MCP configuration
- Paths use backslashes but Python handles this transparently
- PowerShell is the assumed shell for subprocess commands
- aws-vault must be available in PATH

### External Dependencies
- **aws-vault**: Required for AWS authentication (must be installed separately)
- **kubectl**: Required only if Vault is deployed in Kubernetes
- **slack-sdk**: Optional, for Slack notifications
- **flask/flask-cors**: Optional, for Web UI

## Common Development Workflows

### Testing Authentication Flow
```bash
# Manual test of aws-vault export
aws-vault export dev --format=json

# Test Vault connectivity
curl -k https://vault.internal.dev.aws.example.com/v1/sys/health

# Check kubectl context
kubectl config current-context
```

### Testing the MCP Server
```bash
# Run server directly (for debugging)
python -m vault_mcp.server

# The server uses stdio transport, so it expects JSON-RPC on stdin
```

### Adding a New MCP Tool
1. Add method to `VaultMCPServer` class (follow naming: `vault_*`)
2. Register in `list_tools()` function with Tool definition
3. Handle in `call_tool()` function's elif chain
4. Document in README.md and update WARP.md

### Modifying Environment Configuration
All environment configs are in `VaultMCPServer.__init__()`. The `self.environments` dictionary is the single source of truth. Add new environments by following the existing pattern.

## Slack Integration Notes

### Message Formatting
- KV secrets: JSON format with service name
- Dynamic credentials: Key-value pairs with lease information
- Errors: Plain text error messages
- All messages include: Environment, Timestamp, Service/Path

### Size Limits
- Slack enforces 3000 character limit on messages
- Long secrets are automatically truncated
- Fallback to plain text if Block Kit fails

## Security Best Practices

1. **Use privacy mode in production**: Set `RETURN_DATA_TO_AI=false` for production
2. **Rotate Slack tokens regularly**: Slack bot tokens should be rotated
3. **Use read-only Vault policies**: Limit the IAM role's Vault permissions
4. **Clear AWS cache on logout**: Use `clear_aws_cache=true` when done
5. **Monitor Vault audit logs**: All operations are logged

## Troubleshooting

### "aws-vault command timed out"
- Applies to non-Web UI login calls that still use a bounded MFA wait
- Solution: Retry and input MFA when prompted, or use the Web UI for an MFA popup without a timeout limit

### "Failed to authenticate with Vault"
- Check aws-vault is installed and configured
- Verify kubectl context is correct (if K8S_CONTEXT set)
- Test Vault connectivity manually with curl

### Slack notifications not working
- Verify SLACK_BOT_TOKEN and SLACK_USER_ID are correct
- Check bot has `chat:write` scope
- Look for error logs in the MCP server output

### Web UI won't start
- Ensure flask and flask-cors are installed: `pip install flask flask-cors`
- Check port 8765 is not in use
- Verify firewall allows localhost connections

## File-Specific Notes

### server.py
- Main entry point: `main()` function at bottom
- MCP protocol handlers: `list_tools()` and `call_tool()`
- All Vault operations return JSON strings
- Error handling wraps all operations with try/except

### web_ui.py
- Separate thread runs Flask server
- CORS enabled for API endpoints
- Web UI is read-only by default for safety
- Template is embedded in templates/vault_ui.html

### DATA_FLOW_ANALYSIS.md
- Detailed analysis of what data goes to AI vs Slack
- Security risk assessment for each mode
- Recommendations for production use

## Windows PowerShell Commands

When working in PowerShell (as detected in this environment):
```powershell
# List directory contents (not ls -la)
Get-ChildItem -Force

# Environment variables
$env:VARIABLE_NAME = "value"

# Process management
Get-Process | Where-Object {$_.ProcessName -like "python*"}
```
