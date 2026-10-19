"""Caller-provided AWS credentials (used when Infra Desktop runs the web UI).

With VAULT_MCP_AWS_CREDENTIALS=ambient, vault-mcp never runs aws-vault: Vault's AWS IAM login and
kubectl take credentials from the process environment / boto3's default chain, which the desktop
points at its local credential endpoint (AWS_CONTAINER_CREDENTIALS_FULL_URI) so renewals are seen.
"""

import os


def ambient_credentials_enabled() -> bool:
    return os.getenv("VAULT_MCP_AWS_CREDENTIALS") == "ambient"
