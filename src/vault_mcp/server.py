"""MCP server for HashiCorp Vault access."""

import os
import json
import io
import logging
import re
import subprocess
import sys
import shutil
import ssl
import time
from html import unescape
from typing import Any, Optional
from urllib.parse import urljoin, quote
from datetime import datetime

import hvac
import boto3
try:
    import certifi
except ImportError:
    certifi = None
from mcp.server import Server
from mcp.types import Tool, TextContent
from mcp.server.stdio import stdio_server

try:
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError

    SLACK_AVAILABLE = True
except ImportError:
    SLACK_AVAILABLE = False

# Logging setup - dual output strategy
# 1. File logs: record all detailed logs (INFO and above)
# 2. stderr logs: only output ERROR level to keep MCP logs clean

# Force UTF-8 encoding on Windows
stderr_utf8 = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)

# Create log directory in project root
# Get project root directory (src/vault_mcp/server.py -> up two levels)
current_file = os.path.abspath(__file__)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
log_dir = os.path.join(project_root, 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f'vault-mcp-{datetime.now().strftime("%Y%m%d")}.log')

# File handler - record all INFO and above logs
file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

# stderr handler - only output ERROR level to keep MCP logs clean
stderr_handler = logging.StreamHandler(stderr_utf8)
stderr_handler.setLevel(logging.ERROR)
stderr_handler.setFormatter(logging.Formatter('[%(name)s] %(levelname)s: %(message)s'))

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    handlers=[file_handler, stderr_handler]
)
logger = logging.getLogger(__name__)

# Log file location on startup
logger.info(f"Vault MCP Server starting... Logs: {log_file}")

# Reduce third-party library verbose logs
logging.getLogger('werkzeug').setLevel(logging.WARNING)
logging.getLogger('mcp.server').setLevel(logging.WARNING)
logging.getLogger('mcp.server.lowlevel').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('botocore').setLevel(logging.WARNING)

# Import Web UI (lazy import to avoid circular dependency)
try:
    from .web_ui import VaultWebUI
    WEB_UI_AVAILABLE = True
except ImportError:
    WEB_UI_AVAILABLE = False
    logger.warning("Web UI not available. Install flask and flask-cors to enable.")


class VaultMCPServer:
    """MCP Server for Vault operations."""

    INHERITED_SHELL_ENV_KEYS = (
        "PATH",
        "PATHEXT",
        "KUBECONFIG",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "all_proxy",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "SLACK_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "VAULT_CACERT",
        "VAULT_CAPATH",
        "VAULT_SKIP_VERIFY",
    )

    def __init__(self):
        self._inherit_network_settings()
        self.vault_client: Optional[hvac.Client] = None
        self.current_env = None  # Currently logged in environment
        self.auth_check_ttl_seconds = float(
            os.getenv("VAULT_AUTH_CHECK_TTL_SECONDS", "5")
        )
        self._auth_check_cached_result: Optional[bool] = None
        self._auth_check_cached_at = 0.0
        self._auth_check_cached_client_id: Optional[int] = None
        self._last_awsvault_error: Optional[str] = None

        # Slack configuration
        self.slack_enabled = os.getenv("SLACK_ENABLED", "false").lower() == "true"
        self.slack_bot_token = os.getenv("SLACK_BOT_TOKEN", "")
        self.slack_user_id = os.getenv("SLACK_USER_ID", "")
        self.slack_client = None

        # Security configuration: whether to return query results to AI (default: true)
        self.return_data_to_ai = (
            os.getenv("RETURN_DATA_TO_AI", "true").lower() == "true"
        )

        if self.slack_enabled and SLACK_AVAILABLE and self.slack_bot_token:
            try:
                self.slack_client = WebClient(
                    token=self.slack_bot_token,
                    ssl=self._create_slack_ssl_context(),
                )
                logger.info("✓ Slack notifications enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize Slack client: {e}")
                self.slack_enabled = False
        elif self.slack_enabled and not SLACK_AVAILABLE:
            logger.warning(
                "Slack enabled but slack-sdk not installed. Run: pip install slack-sdk"
            )
            self.slack_enabled = False

        # Multi-environment configuration
        self.environments = {
            "dev": {
                "vault_addr": os.getenv(
                    "VAULT_ADDR_DEV", "https://vault.internal.dev.aws.example.com"
                ),
                "vault_header_value": os.getenv(
                    "VAULT_HEADER_DEV", "vault.dev.example.com"
                ),
                "vault_role": os.getenv("VAULT_ROLE_DEV", "vault_admin"),
                "aws_profile": os.getenv("AWS_PROFILE_DEV", "dev"),
                "aws_region": os.getenv("AWS_REGION_DEV", "us-west-2"),
                "k8s_context": os.getenv("K8S_CONTEXT_DEV", "dev-cluster"),
            },
            "sat": {
                "vault_addr": os.getenv(
                    "VAULT_ADDR_SAT", "https://vault.internal.sat.aws.example.com"
                ),
                "vault_header_value": os.getenv(
                    "VAULT_HEADER_SAT", "vault.sat.example.com"
                ),
                "vault_role": os.getenv("VAULT_ROLE_SAT", "vault_admin"),
                "aws_profile": os.getenv("AWS_PROFILE_SAT", "sat"),
                "aws_region": os.getenv("AWS_REGION_SAT", "us-west-2"),
                "k8s_context": os.getenv("K8S_CONTEXT_SAT", "sat-cluster"),
            },
            "prod": {
                "vault_addr": os.getenv(
                    "VAULT_ADDR_PROD", "https://vault.internal.prod.aws.example.com"
                ),
                "vault_header_value": os.getenv(
                    "VAULT_HEADER_PROD", "vault.prod.example.com"
                ),
                "vault_role": os.getenv("VAULT_ROLE_PROD", "vault_admin"),
                "aws_profile": os.getenv("AWS_PROFILE_PROD", "prod"),
                "aws_region": os.getenv("AWS_REGION_PROD", "us-west-2"),
                "k8s_context": os.getenv("K8S_CONTEXT_PROD", "prod-cluster"),
            },
            "local": {
                "vault_addr": os.getenv("VAULT_ADDR_LOCAL", "http://localhost:8200"),
                "token": os.getenv("VAULT_TOKEN_LOCAL", "root"),
            },
        }

        # Web UI configuration
        self.web_ui = None  # Will be initialized when needed

    class VaultCurlClient:
        """Vault client backed by curl/vault CLI instead of requests/hvac."""

        class _AuthAWS:
            def __init__(self, client):
                self.client = client

            def iam_login(
                self,
                access_key: str,
                secret_key: str,
                session_token: Optional[str] = None,
                role: Optional[str] = None,
                header_value: Optional[str] = None,
            ):
                return self.client._aws_iam_login(
                    access_key=access_key,
                    secret_key=secret_key,
                    session_token=session_token,
                    role=role,
                    header_value=header_value,
                )

        class _AuthNamespace:
            def __init__(self, client):
                self.aws = VaultMCPServer.VaultCurlClient._AuthAWS(client)

        class _KVV2:
            def __init__(self, client):
                self.client = client

            def list_secrets(self, path: str = "", mount_point: str = "secret"):
                api_path = self.client._join_api_path(mount_point, "metadata", path)
                return self.client._request("GET", api_path, query={"list": "true"})

            def read_secret_version(
                self,
                path: str,
                mount_point: str = "secret",
                version: Optional[int] = None,
            ):
                api_path = self.client._join_api_path(mount_point, "data", path)
                query = {"version": str(version)} if version else None
                return self.client._request("GET", api_path, query=query)

            def read_secret_metadata(self, path: str, mount_point: str = "secret"):
                api_path = self.client._join_api_path(mount_point, "metadata", path)
                return self.client._request("GET", api_path)

            def create_or_update_secret(
                self,
                path: str,
                secret: dict,
                mount_point: str = "secret",
            ):
                api_path = self.client._join_api_path(mount_point, "data", path)
                return self.client._request("POST", api_path, payload={"data": secret})

            def delete_metadata_and_all_versions(
                self,
                path: str,
                mount_point: str = "secret",
            ):
                api_path = self.client._join_api_path(mount_point, "metadata", path)
                return self.client._request("DELETE", api_path)

        class _KVV1:
            def __init__(self, client):
                self.client = client

            def read_secret(self, path: str, mount_point: str = "secret"):
                api_path = self.client._join_api_path(mount_point, path)
                return self.client._request("GET", api_path)

            def list_secrets(self, path: str = "", mount_point: str = "secret"):
                api_path = self.client._join_api_path(mount_point, path)
                return self.client._request("GET", api_path, query={"list": "true"})

        class _KVNamespace:
            def __init__(self, client):
                self.v1 = VaultMCPServer.VaultCurlClient._KVV1(client)
                self.v2 = VaultMCPServer.VaultCurlClient._KVV2(client)

        class _SecretsNamespace:
            def __init__(self, client):
                self.kv = VaultMCPServer.VaultCurlClient._KVNamespace(client)

        def __init__(self, server, vault_addr: str, token: Optional[str] = None):
            self.server = server
            self.vault_addr = vault_addr.rstrip("/")
            self.token = token
            self.auth = VaultMCPServer.VaultCurlClient._AuthNamespace(self)
            self.secrets = VaultMCPServer.VaultCurlClient._SecretsNamespace(self)

        def _join_api_path(self, *parts: Optional[str]) -> str:
            normalized = [str(part).strip("/") for part in parts if part and str(part).strip("/")]
            return "/".join(normalized)

        def _curl_env(self, token: Optional[str] = None, extra_env: Optional[dict] = None) -> dict:
            env = os.environ.copy()
            env["VAULT_ADDR"] = self.vault_addr
            effective_token = token or self.token
            if effective_token:
                env["VAULT_TOKEN"] = effective_token
            if extra_env:
                env.update({k: v for k, v in extra_env.items() if v})
            return env

        def _build_url(self, api_path: str, query: Optional[dict[str, str]] = None) -> str:
            encoded_path = quote(api_path.lstrip("/"), safe="/")
            url = f"{self.vault_addr}/v1/{encoded_path}"
            if query:
                query_str = "&".join(
                    f"{quote(str(k), safe='')}={quote(str(v), safe='')}"
                    for k, v in query.items()
                )
                url = f"{url}?{query_str}"
            return url

        def _request(
            self,
            method: str,
            api_path: str,
            query: Optional[dict[str, str]] = None,
            payload: Optional[dict] = None,
            token: Optional[str] = None,
        ):
            curl_path = shutil.which("curl")
            if not curl_path:
                raise RuntimeError("curl is required for Vault curl transport")

            url = self._build_url(api_path, query=query)
            cmd = [
                curl_path,
                "-sS",
                "-X",
                method,
                "--connect-timeout",
                "10",
                "--max-time",
                "30",
                "-H",
                "Accept: application/json",
                "-w",
                "\n__CURL_HTTP_CODE__:%{http_code}",
            ]

            effective_token = token or self.token
            if effective_token:
                cmd.extend(["-H", f"X-Vault-Token: {effective_token}"])

            if payload is not None:
                cmd.extend(["-H", "Content-Type: application/json", "--data-binary", json.dumps(payload)])

            cmd.append(url)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=self._curl_env(token=token),
                timeout=35,
            )

            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or "curl request failed")

            marker = "__CURL_HTTP_CODE__:"
            if marker not in result.stdout:
                raise RuntimeError("curl response missing HTTP status marker")

            body, status_line = result.stdout.rsplit(marker, 1)
            body = body.rstrip("\n")
            status_code = int(status_line.strip())

            if status_code >= 400:
                raise RuntimeError(body or f"Vault API request failed with HTTP {status_code}")

            if not body:
                return {}

            return json.loads(body)

        def _aws_iam_login(
            self,
            access_key: str,
            secret_key: str,
            session_token: Optional[str] = None,
            role: Optional[str] = None,
            header_value: Optional[str] = None,
        ):
            vault_path = shutil.which("vault")
            if not vault_path:
                raise RuntimeError("vault CLI is required for AWS IAM login fallback")

            cmd = [
                vault_path,
                "login",
                "-format=json",
                "-method=aws",
            ]

            if role:
                cmd.append(f"role={role}")
            if header_value:
                cmd.append(f"header_value={header_value}")

            env = self._curl_env(
                extra_env={
                    "AWS_ACCESS_KEY_ID": access_key,
                    "AWS_SECRET_ACCESS_KEY": secret_key,
                    "AWS_SESSION_TOKEN": session_token,
                }
            )

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=60,
            )

            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "vault login failed")

            return json.loads(result.stdout)

        def is_authenticated(self) -> bool:
            try:
                self._request("GET", "auth/token/lookup-self")
                return True
            except Exception:
                return False

        def read(self, path: str):
            return self._request("GET", path)

        def list(self, path: str):
            return self._request("GET", path, query={"list": "true"})

    def _sync_env_aliases(self):
        """Mirror upper/lower-case proxy env vars for subprocesses and requests."""
        alias_pairs = (
            ("HTTP_PROXY", "http_proxy"),
            ("HTTPS_PROXY", "https_proxy"),
            ("NO_PROXY", "no_proxy"),
            ("ALL_PROXY", "all_proxy"),
        )

        for primary, alias in alias_pairs:
            primary_value = os.environ.get(primary)
            alias_value = os.environ.get(alias)

            if primary_value and not alias_value:
                os.environ[alias] = primary_value
            elif alias_value and not primary_value:
                os.environ[primary] = alias_value

    def _inherit_network_settings(self):
        """Import network and Vault-related env vars from the user's login shell."""
        if os.getenv("INHERIT_NETWORK_PROXY_FROM_SHELL", "true").lower() != "true":
            self._sync_env_aliases()
            return

        missing_keys = [key for key in self.INHERITED_SHELL_ENV_KEYS if not os.environ.get(key)]
        if not missing_keys:
            self._sync_env_aliases()
            return

        marker = "__VAULT_MCP_NETWORK_ENV__"

        try:
            result = self._inspect_login_shell_environment(marker)
        except Exception as e:
            logger.info(f"Unable to inspect login shell network settings: {e}")
            self._sync_env_aliases()
            return

        if result is None:
            self._sync_env_aliases()
            return

        if result.returncode != 0:
            logger.info(
                f"Login shell exited before settings could be imported: {result.stderr.strip()}"
            )
            self._sync_env_aliases()
            return

        stdout = result.stdout
        start = stdout.find(marker)
        end = stdout.rfind(marker)
        if start == -1 or end == -1 or start == end:
            logger.info("Login shell did not expose environment settings")
            self._sync_env_aliases()
            return

        payload = stdout[start + len(marker):end].strip()
        if not payload:
            self._sync_env_aliases()
            return

        try:
            inherited_values = json.loads(payload)
        except json.JSONDecodeError as e:
            logger.info(f"Failed to parse login shell network settings: {e}")
            self._sync_env_aliases()
            return

        imported_keys = []
        for key, value in inherited_values.items():
            should_replace = key in {"PATH", "PATHEXT"} and value != os.environ.get(key)
            if value and (should_replace or not os.environ.get(key)):
                os.environ[key] = value
                imported_keys.append(key)

        self._sync_env_aliases()

        if imported_keys:
            imported_keys.sort()
            logger.info(
                f"Imported shell environment settings: {', '.join(imported_keys)}"
            )

    def _inspect_login_shell_environment(self, marker: str):
        """Run the user's login shell and print a JSON subset of env vars."""
        import platform

        keys = list(self.INHERITED_SHELL_ENV_KEYS)
        system = platform.system()

        if system == "Windows":
            powershell_path = (
                shutil.which("powershell")
                or shutil.which("powershell.exe")
                or shutil.which("pwsh")
                or shutil.which("pwsh.exe")
            )
            if powershell_path:
                ps_keys = ", ".join(f"'{key}'" for key in keys)
                script = f"""
$keys = @({ps_keys})
$values = @{{}}
foreach ($key in $keys) {{
    $value = [Environment]::GetEnvironmentVariable($key)
    if (-not [string]::IsNullOrEmpty($value)) {{
        $values[$key] = $value
    }}
}}
Write-Output '{marker}'
$values | ConvertTo-Json -Compress
Write-Output '{marker}'
"""
                return subprocess.run(
                    [powershell_path, "-NoProfile", "-Command", script],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

            cmd_path = os.environ.get("COMSPEC") or shutil.which("cmd") or shutil.which("cmd.exe")
            if not cmd_path:
                logger.info("No Windows shell found for environment inspection")
                return None

            script_lines = [
                "@echo off",
                f"echo {marker}",
                "echo {",
            ]

            for index, key in enumerate(keys):
                prefix = "," if index > 0 else ""
                escaped_key = key.replace("\\", "\\\\").replace('"', '\\"')
                script_lines.extend(
                    [
                        f'if defined {key} (',
                        f'  set "_value=!{key}!"',
                        '  set "_value=!_value:\\=\\\\!"',
                        '  set "_value=!_value:"=\\"!"',
                        f'  echo {prefix}"{escaped_key}":"!_value!"',
                        ")",
                    ]
                )

            script_lines.extend(
                [
                    "echo }",
                    f"echo {marker}",
                ]
            )

            return subprocess.run(
                [cmd_path, "/V:ON", "/D", "/C", "\n".join(script_lines)],
                capture_output=True,
                text=True,
                timeout=5,
            )

        shell = os.environ.get("SHELL") or "/bin/zsh"
        shell_script = f"""
python3 - <<'PY'
import json
import os

keys = {keys!r}
values = {{key: os.environ.get(key) for key in keys if os.environ.get(key)}}
print("{marker}")
print(json.dumps(values))
print("{marker}")
PY
"""

        return subprocess.run(
            [shell, "-lc", shell_script],
            capture_output=True,
            text=True,
            timeout=5,
        )

    def _get_proxy_config(self) -> Optional[dict[str, str]]:
        """Build an explicit proxy config for requests-based Vault clients."""
        proxies = {}

        http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        all_proxy = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy")

        if http_proxy:
            proxies["http"] = http_proxy
        if https_proxy:
            proxies["https"] = https_proxy

        if all_proxy:
            proxies.setdefault("http", all_proxy)
            proxies.setdefault("https", all_proxy)

        return proxies or None

    def _create_slack_ssl_context(self) -> ssl.SSLContext:
        """Create an SSL context for Slack API calls with reliable CA roots."""
        ca_file = (
            os.environ.get("SLACK_CA_BUNDLE")
            or os.environ.get("REQUESTS_CA_BUNDLE")
            or os.environ.get("SSL_CERT_FILE")
            or os.environ.get("CURL_CA_BUNDLE")
        )
        ca_path = os.environ.get("SSL_CERT_DIR")

        if ca_file or ca_path:
            logger.info("Using configured CA bundle for Slack SSL verification")
            return ssl.create_default_context(
                cafile=ca_file or None,
                capath=ca_path or None,
            )

        if certifi is not None:
            logger.info("Using certifi CA bundle for Slack SSL verification")
            return ssl.create_default_context(cafile=certifi.where())

        logger.info("Using Python default CA paths for Slack SSL verification")
        return ssl.create_default_context()

    def _preferred_vault_transport(self) -> str:
        """Return the preferred transport for authenticated Vault operations."""
        transport = os.getenv("VAULT_TRANSPORT", "auto").lower()
        if transport in {"curl", "hvac"}:
            return transport
        if shutil.which("curl"):
            return "curl"
        return "hvac"

    def _create_vault_client(self, vault_addr: str, token: Optional[str] = None):
        """Create a Vault client using the preferred transport."""
        if self._preferred_vault_transport() == "curl":
            return self.VaultCurlClient(self, vault_addr=vault_addr, token=token)

        client_kwargs = {"url": vault_addr, "token": token}
        proxies = self._get_proxy_config()
        if proxies:
            client_kwargs["proxies"] = proxies

        return hvac.Client(**client_kwargs)

    def _init_vault_client(self, token: str, vault_addr: str):
        """Initialize Vault client."""
        self.vault_client = self._create_vault_client(vault_addr, token=token)
        self._invalidate_auth_check_cache()

        # Verify token is valid
        try:
            is_authenticated = self.vault_client.is_authenticated()
            self._set_auth_check_cache(is_authenticated)
            if not is_authenticated:
                raise RuntimeError("Vault token verification failed")
            logger.info("Vault client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to authenticate with Vault: {e}")
            self.vault_client = None
            self._invalidate_auth_check_cache()

    def _set_auth_check_cache(self, result: bool):
        """Cache the latest authentication check result for a short TTL."""
        self._auth_check_cached_result = result
        self._auth_check_cached_at = time.monotonic()
        self._auth_check_cached_client_id = id(self.vault_client) if self.vault_client else None

    def _invalidate_auth_check_cache(self):
        """Clear cached authentication check state."""
        self._auth_check_cached_result = None
        self._auth_check_cached_at = 0.0
        self._auth_check_cached_client_id = None

    def _ensure_authenticated(self) -> bool:
        """Ensure authenticated with a short-lived cache to avoid repeated token lookups."""
        if not self.vault_client:
            self._invalidate_auth_check_cache()
            return False

        current_client_id = id(self.vault_client)
        cache_age = time.monotonic() - self._auth_check_cached_at
        if (
            self._auth_check_cached_result is not None
            and self._auth_check_cached_client_id == current_client_id
            and cache_age < self.auth_check_ttl_seconds
        ):
            return self._auth_check_cached_result

        try:
            is_authenticated = self.vault_client.is_authenticated()
        except Exception:
            is_authenticated = False

        self._set_auth_check_cache(is_authenticated)
        return is_authenticated

    def _switch_k8s_context(self, k8s_context: str) -> bool:
        """Switch to specified Kubernetes context.

        Args:
            k8s_context: Kubernetes context name
        """
        if not k8s_context:
            logger.info("No k8s_context specified, skipping kubectl context switch")
            return True

        try:
            logger.info(f"Switching kubectl context to: {k8s_context}")

            # Check if kubectl is installed
            check_cmd = ["kubectl", "config", "current-context"]
            result = subprocess.run(
                check_cmd, capture_output=True, text=True, timeout=5
            )

            current_context = result.stdout.strip()
            logger.info(f"Current kubectl context: {current_context}")

            # Skip switch if already in target context
            if current_context == k8s_context:
                logger.info(f"✓ Already in context: {k8s_context}")
                return True

            # Switch context
            switch_cmd = ["kubectl", "config", "use-context", k8s_context]
            result = subprocess.run(
                switch_cmd, capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                logger.info(f"✓ Switched to kubectl context: {k8s_context}")
                return True
            else:
                logger.error(f"Failed to switch kubectl context: {result.stderr}")
                return False

        except FileNotFoundError:
            logger.warning("kubectl not found, skipping context switch")
            return True  # If kubectl is not found, continue attempting connection
        except Exception as e:
            logger.error(f"Error switching kubectl context: {e}")
            return False

    def _find_aws_vault_path(self) -> Optional[str]:
        """Find aws-vault executable path (cross-platform).
        
        Returns:
            Full path to aws-vault or None if not found
        """
        import platform
        import shutil
        
        system = platform.system()
        
        # Try using shutil.which first (works on all platforms)
        executable_name = "aws-vault.exe" if system == "Windows" else "aws-vault"
        aws_vault_path = shutil.which(executable_name)
        if aws_vault_path and os.path.isfile(aws_vault_path):
            return aws_vault_path
        
        # Platform-specific common paths
        if system == "Windows":
            # Windows common installation paths
            common_paths = [
                os.path.expandvars(r"%LOCALAPPDATA%\Programs\aws-vault\aws-vault.exe"),
                os.path.expandvars(r"%PROGRAMFILES%\aws-vault\aws-vault.exe"),
                os.path.expandvars(r"%PROGRAMFILES(X86)%\aws-vault\aws-vault.exe"),
                os.path.expandvars(r"%USERPROFILE%\bin\aws-vault.exe"),
                r"C:\ProgramData\chocolatey\bin\aws-vault.exe",  # Chocolatey install
            ]
            
            # Check common paths
            for path in common_paths:
                if os.path.isfile(path):
                    return path
            
            # Try using 'where' command on Windows
            try:
                result = subprocess.run(
                    ["where", "aws-vault"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    shell=False
                )
                if result.returncode == 0:
                    path = result.stdout.strip().split('\n')[0]  # Get first match
                    if path and os.path.isfile(path):
                        return path
            except:
                pass
                
        else:
            # Unix/Linux/macOS common paths
            common_paths = [
                "/opt/homebrew/bin/aws-vault",  # Homebrew on Apple Silicon
                "/usr/local/bin/aws-vault",      # Homebrew on Intel Mac
                "/usr/bin/aws-vault",            # System install
                os.path.expanduser("~/.local/bin/aws-vault"),  # User install
            ]
            
            # Check common paths
            for path in common_paths:
                if os.path.isfile(path) and os.access(path, os.X_OK):
                    return path
            
            # Try using 'which' command
            try:
                result = subprocess.run(
                    ["which", "aws-vault"],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    path = result.stdout.strip()
                    if path and os.path.isfile(path):
                        return path
            except:
                pass
        
        return None

    def _build_awsvault_credentials_command(
        self,
        aws_vault_path: str,
        aws_profile: str,
        system: str,
        from_web_ui: bool,
    ) -> tuple[list[str], dict[str, Any]]:
        """Build the aws-vault credential command for the current runtime."""
        run_kwargs: dict[str, Any] = {
            "capture_output": True,
            "text": True,
        }

        if not from_web_ui:
            run_kwargs["timeout"] = 30

        if from_web_ui and system == "Windows":
            run_kwargs["creationflags"] = 0x08000000
            return (
                [
                    aws_vault_path,
                    "exec",
                    aws_profile,
                    "--json",
                    "--prompt=wincredui",
                ],
                run_kwargs,
            )

        if from_web_ui and system == "Darwin":
            return (
                [
                    aws_vault_path,
                    "exec",
                    aws_profile,
                    "--json",
                    "--prompt=osascript",
                ],
                run_kwargs,
            )

        return (
            [aws_vault_path, "export", aws_profile, "--format=json"],
            run_kwargs,
        )

    def _get_aws_credentials_via_awsvault(self, aws_profile: str, from_web_ui: bool = False):
        """Proactively obtain AWS credentials via aws-vault.

        Args:
            aws_profile: AWS profile name
            from_web_ui: Whether called from Web UI (requires GUI popup window)
        """
        import platform
        
        # Find aws-vault executable
        aws_vault_path = self._find_aws_vault_path()
        if not aws_vault_path:
            logger.warning("aws-vault executable not found in common paths")
            self._last_awsvault_error = "aws-vault executable not found"
            return None
        
        logger.info(f"Using aws-vault at: {aws_vault_path}")
        self._last_awsvault_error = None
        
        try:
            logger.info(
                f"Trying to get credentials via aws-vault for profile: {aws_profile}"
            )
            if from_web_ui:
                logger.info("⏳ If MFA prompt appears, please enter your code...")
            else:
                logger.info(
                    "⏳ If MFA prompt appears, please enter your code (30 seconds timeout)..."
                )

            system = platform.system()
            cmd, run_kwargs = self._build_awsvault_credentials_command(
                aws_vault_path=aws_vault_path,
                aws_profile=aws_profile,
                system=system,
                from_web_ui=from_web_ui,
            )
            result = subprocess.run(cmd, **run_kwargs)
            stdout = result.stdout
            stderr = result.stderr
            returncode = result.returncode

            if returncode != 0:
                error_detail = stderr.strip() or stdout.strip() or "aws-vault command failed"
                self._last_awsvault_error = error_detail
                logger.warning(f"aws-vault credential command failed: {error_detail}")
                
                # Clear aws-vault cache to ensure MFA prompt appears on next retry
                # This prevents the issue where incorrect MFA entry blocks subsequent login attempts
                logger.info(f"Clearing aws-vault cache for profile: {aws_profile} to allow retry...")
                try:
                    clear_result = subprocess.run(
                        [aws_vault_path, "clear", aws_profile],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if clear_result.returncode == 0:
                        logger.info(f"✓ Cleared aws-vault cache for {aws_profile}")
                    else:
                        logger.warning(f"Failed to clear aws-vault cache: {clear_result.stderr}")
                except Exception as clear_error:
                    logger.warning(f"Error clearing aws-vault cache: {clear_error}")
                
                return None

            # Parse JSON output
            creds_json = json.loads(stdout)
            logger.info("✓ Successfully obtained AWS credentials via aws-vault")
            self._last_awsvault_error = None

            return {
                "AWS_ACCESS_KEY_ID": creds_json.get("AccessKeyId"),
                "AWS_SECRET_ACCESS_KEY": creds_json.get("SecretAccessKey"),
                "AWS_SESSION_TOKEN": creds_json.get("SessionToken"),
            }

        except subprocess.TimeoutExpired:
            timeout = 90 if from_web_ui else 30
            logger.error(f"✗ aws-vault command timed out ({timeout} seconds)")
            logger.error("Please make sure you enter MFA code when prompted")
            self._last_awsvault_error = f"aws-vault command timed out after {timeout} seconds"
            return None
        except Exception as e:
            logger.warning(f"Failed to get credentials via aws-vault: {e}")
            self._last_awsvault_error = str(e)
            return None

    def _safe_format_data(self, data: dict, max_length: int = 2800) -> str:
        """Safely format data to string, ensuring it doesn't exceed Slack limit.

        Args:
            data: Data to format
            max_length: Maximum character count (Slack text field limit 3000, leaving 200 char buffer)

        Returns:
            Formatted string
        """
        try:
            # Try to serialize as JSON
            formatted = json.dumps(data, indent=2, ensure_ascii=False, default=str)

            # Truncate if exceeds length limit
            if len(formatted) > max_length:
                truncated = formatted[:max_length]
                # Try to truncate at reasonable position (find last complete line)
                last_newline = truncated.rfind("\n")
                if last_newline > 0:
                    truncated = truncated[:last_newline]
                return truncated + f"\n...\n[Truncated - Total {len(formatted)} chars]"

            return formatted
        except Exception as e:
            logger.warning(f"Failed to format data: {e}")
            # Fallback: return simplified string representation
            return str(data)[:max_length]

    def _send_slack_notification(
        self,
        title: str,
        data: dict,
        query_type: str = "general",
        service_name: str = "",
    ):
        """Send Slack notification.

        Args:
            title: Message title
            data: Query result data
            query_type: Query type (database/kv/general)
            service_name: Service name
        """
        if not self.slack_enabled or not self.slack_client or not self.slack_user_id:
            return

        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Build message blocks
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🔐 {title}",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Environment:*\n{self.current_env.upper() if self.current_env else 'N/A'}",
                        },
                        {"type": "mrkdwn", "text": f"*Time:*\n{timestamp}"},
                    ],
                },
                {"type": "divider"},
            ]

            # Format data based on query type
            if query_type == "database":
                # Database credentials: only show username, password and service
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Service:* `{service_name}`",
                        },
                    }
                )

                username = ""
                password = ""
                
                if "username" in data:
                    username = (
                        str(data["username"])
                        if not isinstance(data["username"], str)
                        else data["username"]
                    )
                    username = username[:500]  # Limit length
                
                if "password" in data:
                    password = (
                        str(data["password"])
                        if not isinstance(data["password"], str)
                        else data["password"]
                    )
                    password = password[:500]  # Limit length

                # Add divider
                blocks.append({"type": "divider"})

                # Use code block format to display credentials for easy copy
                if username or password:
                    credentials_code = ""
                    if username:
                        credentials_code += f"Username: {username}\n"
                    if password:
                        credentials_code += f"Password: {password}"
                    
                    # Use Section + mrkdwn code block format
                    blocks.append(
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"```\n{credentials_code}\n```",
                            },
                        }
                    )
                
                # Add hint text
                blocks.append(
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "💡 _Click the code block above and select to copy credentials_",
                            }
                        ],
                    }
                )
            else:
                # Other queries: show service and complete results
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Service:* `{service_name}`",
                        },
                    }
                )

                # Add divider
                blocks.append({"type": "divider"})

                # Use safe formatting method
                formatted_data = self._safe_format_data(data)
                data_text = f"```\n{formatted_data}\n```"
                blocks.append(
                    {"type": "section", "text": {"type": "mrkdwn", "text": data_text}}
                )

            # Add warning note
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "⚠️ _This message contains sensitive information. Please handle it securely and delete it after use._",
                        }
                    ],
                }
            )

            # Send message - try using blocks
            try:
                response = self.slack_client.chat_postMessage(
                    channel=self.slack_user_id,
                    blocks=blocks,
                    text=title,  # fallback text
                )
                logger.info(
                    f"✓ Slack notification sent successfully to {self.slack_user_id}"
                )
            except SlackApiError as e:
                # If blocks format has issues, fallback to plain text message
                if "invalid_blocks" in str(e) or "invalid_text" in str(e):
                    logger.warning(f"Blocks invalid, falling back to plain text: {e}")
                    self._send_slack_fallback(title, data, query_type, service_name)
                else:
                    raise

        except SlackApiError as e:
            logger.error(f"Slack API error: {e.response['error']}")
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")

    def _send_slack_fallback(
        self,
        title: str,
        data: dict,
        query_type: str = "general",
        service_name: str = "",
    ):
        """Fallback: send plain text Slack message (when blocks format fails).

        Args:
            title: Message title
            data: Query result data
            query_type: Query type
            service_name: Service name
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            env = self.current_env.upper() if self.current_env else "N/A"

            # Build plain text message
            if query_type == "database":
                text_parts = [
                    f"🔐 {title}",
                    f"Environment: {env} | Time: {timestamp}",
                    f"Service: {service_name}",
                    "",
                ]
                if "username" in data:
                    username = str(data["username"])[:500]
                    text_parts.append(f"Username: {username}")
                if "password" in data:
                    password = str(data["password"])[:500]
                    text_parts.append(f"Password: {password}")
            else:
                formatted_data = self._safe_format_data(data, max_length=2500)
                text_parts = [
                    f"🔐 {title}",
                    f"Environment: {env} | Time: {timestamp}",
                    f"Service: {service_name}",
                    "",
                    "Data:",
                    formatted_data,
                ]

            text_parts.append("")
            text_parts.append(
                "⚠️ This message contains sensitive information. Please handle it securely."
            )

            message_text = "\n".join(text_parts)

            # Send plain text message
            self.slack_client.chat_postMessage(
                channel=self.slack_user_id, text=message_text
            )

            logger.info(
                f"✓ Slack fallback notification sent successfully to {self.slack_user_id}"
            )
        except Exception as e:
            logger.error(f"Failed to send Slack fallback notification: {e}")

    def _aws_login(self, env_config: dict, from_web_ui: bool = False) -> bool:
        """Login to Vault using AWS IAM authentication.

        Args:
            env_config: Environment configuration dictionary
            from_web_ui: Whether called from Web UI
        """
        try:
            vault_addr = env_config["vault_addr"]
            aws_profile = env_config["aws_profile"]
            aws_region = env_config["aws_region"]
            vault_role = env_config["vault_role"]
            vault_header_value = env_config["vault_header_value"]
            k8s_context = env_config["k8s_context"]

            logger.info(f"Attempting to login to Vault at {vault_addr}")
            logger.info(f"Using AWS profile: {aws_profile}, region: {aws_region}")

            # Step 1: Switch kubectl context (if needed)
            if not self._switch_k8s_context(k8s_context):
                logger.warning(
                    "Failed to switch kubectl context, but continuing anyway..."
                )

            # Create temporary Vault client for login
            temp_client = self._create_vault_client(vault_addr)

            # Get AWS credentials - prefer aws-vault
            access_key = None
            secret_key = None
            session_token = None

            # Method 1: Try to get credentials via aws-vault
            logger.info("Trying to get credentials from aws-vault...")
            aws_env = self._get_aws_credentials_via_awsvault(aws_profile, from_web_ui=from_web_ui)
            awsvault_error = self._last_awsvault_error

            if aws_env and aws_env.get("AWS_ACCESS_KEY_ID"):
                access_key = aws_env["AWS_ACCESS_KEY_ID"]
                secret_key = aws_env["AWS_SECRET_ACCESS_KEY"]
                session_token = aws_env.get("AWS_SESSION_TOKEN")
                logger.info("✓ Using credentials from aws-vault")
            else:
                # Method 2: Try to get from environment variables
                logger.info("aws-vault not available, trying environment variables...")
                access_key = os.environ.get("AWS_ACCESS_KEY_ID")
                secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
                session_token = os.environ.get("AWS_SESSION_TOKEN")

                if access_key and secret_key:
                    logger.info("✓ Using credentials from environment variables")
                else:
                    logger.error("✗ No AWS credentials found")
                    logger.error("")
                    logger.error("Please run in a terminal:")
                    logger.error(f"  aws-vault exec {aws_profile} --duration=8h")
                    logger.error("")
                    logger.error(
                        "Then keep that terminal session open and retry in Cursor"
                    )
                    error_message = "No AWS credentials found"
                    if awsvault_error:
                        error_message = f"{error_message} (aws-vault: {awsvault_error})"
                    raise ValueError(error_message)

            logger.info(f"Using Vault role: {vault_role}")

            # Use AWS IAM authentication
            try:
                response = temp_client.auth.aws.iam_login(
                    access_key=access_key,
                    secret_key=secret_key,
                    session_token=session_token,
                    role=vault_role,
                    header_value=vault_header_value,
                )
            except Exception as login_error:
                error_text = str(login_error)
                if self._preferred_vault_transport() == "curl" or "UNEXPECTED_EOF_WHILE_READING" in error_text:
                    logger.warning(
                        "Python Vault transport failed during AWS login, retrying with vault CLI..."
                    )
                    cli_client = self.VaultCurlClient(self, vault_addr=vault_addr)
                    response = cli_client.auth.aws.iam_login(
                        access_key=access_key,
                        secret_key=secret_key,
                        session_token=session_token,
                        role=vault_role,
                        header_value=vault_header_value,
                    )
                else:
                    raise

            token = response["auth"]["client_token"]
            self._init_vault_client(token, vault_addr)

            logger.info("Successfully authenticated with Vault using AWS IAM")
            return None

        except Exception as e:
            logger.error(f"AWS login failed: {e}")
            logger.error(f"Vault address: {vault_addr}")
            logger.error(f"AWS profile: {aws_profile}")
            logger.error(f"Vault role: {vault_role}")
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")
            return str(e)

    def login_sync(self, environment: str = "dev", from_web_ui: bool = False) -> str:
        """Synchronous version of vault_login.
        
        Args:
            environment: Environment name (dev/sat/prod/local)
            from_web_ui: Whether called from Web UI (affects MFA popup method)
        """
        if environment not in self.environments:
            return json.dumps(
                {
                    "success": False,
                    "message": f"Unknown environment: {environment}. Available: {list(self.environments.keys())}",
                }
            )

        env_config = self.environments[environment]

        # Local environment login
        if environment == "local":
            try:
                vault_addr = env_config["vault_addr"]
                token = env_config["token"]
                self._init_vault_client(token, vault_addr)
                self.current_env = environment
                return json.dumps(
                    {
                        "success": True,
                        "message": "Successfully authenticated with LOCAL Vault",
                        "environment": "local",
                        "vault_addr": vault_addr,
                    }
                )
            except Exception as e:
                return json.dumps(
                    {
                        "success": False,
                        "message": f"Failed to authenticate with LOCAL Vault: {str(e)}",
                    }
                )

        # AWS IAM login for other environments
        error = self._aws_login(env_config, from_web_ui=from_web_ui)
        if error is None:
            self.current_env = environment
            return json.dumps(
                {
                    "success": True,
                    "message": f"Successfully authenticated with {environment.upper()} Vault",
                    "environment": environment,
                    "vault_addr": env_config["vault_addr"],
                }
            )
        else:
            return json.dumps(
                {
                    "success": False,
                    "message": f"Failed to authenticate with {environment.upper()} Vault: {error}",
                }
            )

    def _find_slack_users(self, name: str) -> list:
        """Search Slack workspace for users by display name, real name, or username.

        Args:
            name: The name to search for (case-insensitive partial match)

        Returns:
            List of matching users, each a dict with 'id', 'real_name', 'display_name'
        """
        if not self.slack_client:
            return []

        name_lower = name.lower().strip()
        matches = []
        try:
            cursor = None
            while True:
                kwargs = {"limit": 200}
                if cursor:
                    kwargs["cursor"] = cursor

                response = self.slack_client.users_list(**kwargs)
                members = response.get("members", [])

                for member in members:
                    if member.get("deleted") or member.get("is_bot"):
                        continue
                    profile = member.get("profile", {})
                    candidates = [
                        member.get("name", ""),
                        profile.get("display_name", ""),
                        profile.get("real_name", ""),
                        profile.get("display_name_normalized", ""),
                        profile.get("real_name_normalized", ""),
                    ]
                    if any(name_lower in c.lower() for c in candidates if c):
                        matches.append(
                            {
                                "id": member["id"],
                                "real_name": profile.get("real_name", ""),
                                "display_name": profile.get("display_name", "")
                                or member.get("name", ""),
                            }
                        )

                next_cursor = (
                    response.get("response_metadata", {}).get("next_cursor", "")
                )
                if not next_cursor:
                    break
                cursor = next_cursor

        except SlackApiError as e:
            logger.error(f"Slack API error while searching users: {e.response['error']}")
        except Exception as e:
            logger.error(f"Error searching Slack users: {e}")

        return matches

    def _find_slack_user_id(self, name: str) -> Optional[str]:
        """Search Slack workspace for a user by display name, real name, or username.

        Returns the user ID if exactly one match is found, otherwise None.
        Use _find_slack_users() directly when you need to handle multiple matches.
        """
        matches = self._find_slack_users(name)
        if len(matches) == 1:
            return matches[0]["id"]
        return None

    def _get_slack_user_real_name(self, user_id: str) -> str:
        """Look up a Slack user's real name by their user ID."""
        if not user_id or not self.slack_client:
            return os.getenv("USER", "Unknown")
        try:
            resp = self.slack_client.users_info(user=user_id)
            profile = resp["user"]["profile"]
            return (
                profile.get("real_name")
                or profile.get("display_name")
                or os.getenv("USER", "Unknown")
            )
        except Exception:
            return os.getenv("USER", "Unknown")

    def _get_slack_user_profile_summary(self, user_id: str) -> dict:
        """Return non-sensitive Slack user identity fields."""
        if not user_id or not self.slack_client:
            return {"id": user_id, "name": user_id}
        try:
            resp = self.slack_client.users_info(user=user_id)
            user = resp.get("user", {})
            profile = user.get("profile", {})
            display_name = profile.get("display_name") or user.get("name") or ""
            real_name = profile.get("real_name") or user.get("real_name") or ""
            return {
                "id": user_id,
                "name": real_name or display_name or user_id,
                "real_name": real_name,
                "display_name": display_name,
            }
        except Exception as e:
            logger.warning(f"Failed to look up Slack user {user_id}: {e}")
            return {"id": user_id, "name": user_id}

    def _get_slack_operator_user_id(self) -> Optional[str]:
        """Return the Slack user this server should treat as the operator."""
        return (
            os.getenv("SLACK_OPERATOR_USER_ID")
            or os.getenv("SLACK_USER_ID")
            or self.slack_user_id
            or None
        )

    def _resolve_db_request_channel_id(self, channel_id: Optional[str] = None) -> Optional[str]:
        """Resolve the DB credential request channel without exposing messages."""
        if channel_id:
            return channel_id

        configured_channel_id = (
            os.getenv("SLACK_DB_REQUEST_CHANNEL_ID")
            or os.getenv("SLACK_AUDIT_CHANNEL_ID")
            or "C08GHV4ELRX"
        )
        if configured_channel_id:
            return configured_channel_id

        channel_name = os.getenv("SLACK_DB_REQUEST_CHANNEL_NAME", "database-credentials-ops")
        if not self.slack_client:
            return None

        try:
            cursor = None
            while True:
                kwargs = {
                    "types": "public_channel,private_channel",
                    "exclude_archived": True,
                    "limit": 200,
                }
                if cursor:
                    kwargs["cursor"] = cursor

                response = self.slack_client.conversations_list(**kwargs)
                for channel in response.get("channels", []):
                    if channel.get("name") == channel_name:
                        return channel.get("id")

                cursor = response.get("response_metadata", {}).get("next_cursor")
                if not cursor:
                    break
        except SlackApiError as e:
            logger.error(f"Slack API error while resolving DB request channel: {e.response['error']}")
        except Exception as e:
            logger.error(f"Error resolving DB request channel: {e}")

        return None

    def _bounded_slack_limit(self, limit: Any, default: int = 100) -> int:
        """Normalize Slack result limits from MCP arguments."""
        try:
            parsed_limit = int(limit)
        except (TypeError, ValueError):
            parsed_limit = default
        return min(max(parsed_limit, 1), 200)

    def _db_request_fresh_seconds(self) -> int:
        """Age (seconds) under which a pending request is 'fresh' / actionable."""
        try:
            hours = float(os.getenv("SLACK_DB_REQUEST_FRESH_HOURS", "24"))
        except (TypeError, ValueError):
            hours = 24.0
        return int(max(hours, 0) * 3600)

    def _db_request_lookback_seconds(self) -> int:
        """How far back (seconds) to scan for pending requests, also the stale upper bound."""
        try:
            days = float(os.getenv("SLACK_DB_REQUEST_LOOKBACK_DAYS", "2"))
        except (TypeError, ValueError):
            days = 2.0
        return int(max(days, 0) * 86400)

    def _classify_db_request_age(self, request_ts: str) -> dict:
        """Classify a request's age into fresh / stale tiers from its Slack ts."""
        try:
            request_epoch = float(request_ts)
        except (TypeError, ValueError):
            return {"age_seconds": None, "age_hours": None, "tier": "unknown", "stale": False}

        age_seconds = max(0.0, time.time() - request_epoch)
        fresh_cutoff = self._db_request_fresh_seconds()
        lookback_cutoff = self._db_request_lookback_seconds()

        if age_seconds <= fresh_cutoff:
            tier = "fresh"
        elif age_seconds <= lookback_cutoff:
            tier = "stale"
        else:
            tier = "expired"

        return {
            "age_seconds": int(age_seconds),
            "age_hours": round(age_seconds / 3600, 1),
            "tier": tier,
            "stale": tier != "fresh",
        }

    def _slack_message_text(self, message: dict) -> str:
        """Extract searchable text from Slack message fields without returning it."""
        parts = []

        def add_text(value: Any):
            if isinstance(value, str) and value.strip():
                parts.append(value)

        add_text(message.get("text"))

        for block in message.get("blocks", []) or []:
            block_text = block.get("text")
            if isinstance(block_text, dict):
                add_text(block_text.get("text"))

            for field in block.get("fields", []) or []:
                if isinstance(field, dict):
                    add_text(field.get("text"))

            for element in block.get("elements", []) or []:
                if isinstance(element, dict):
                    add_text(element.get("text"))

        for attachment in message.get("attachments", []) or []:
            add_text(attachment.get("text"))
            add_text(attachment.get("pretext"))
            add_text(attachment.get("fallback"))
            for field in attachment.get("fields", []) or []:
                if isinstance(field, dict):
                    add_text(field.get("title"))
                    add_text(field.get("value"))

        return unescape("\n".join(parts))

    def _normalize_slack_text(self, text: str) -> str:
        """Normalize mrkdwn enough for field parsing."""
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = re.sub(r"[*`_]+", "", text)
        text = re.sub(r"[ \t]+", " ", text)
        return text

    def _parse_db_credential_request_message(
        self,
        message: dict,
        channel_id: str,
        current_user_id: str,
    ) -> Optional[dict]:
        """Parse a DB credential request and return only safe structured fields."""
        raw_text = self._slack_message_text(message)
        current_user_mention = rf"<@{re.escape(current_user_id)}(?:\|[^>]+)?>"
        if not re.search(current_user_mention, raw_text):
            return None

        normalized = self._normalize_slack_text(raw_text)
        if "Please provide the DB credential to" not in normalized:
            return None

        database_match = re.search(r"Database:\s*([^\n|]+)", normalized, re.IGNORECASE)
        environment_match = re.search(r"Environment:\s*([A-Za-z0-9_-]+)", normalized, re.IGNORECASE)
        recipient_match = re.search(
            r"Please provide the DB credential to\s+<@([A-Z0-9]+)(?:\|[^>]+)?>",
            raw_text,
            re.IGNORECASE,
        )

        if not database_match or not environment_match or not recipient_match:
            return None

        database = database_match.group(1).strip(" :")
        environment = environment_match.group(1).strip().lower()
        recipient_user_id = recipient_match.group(1)
        if not database or environment not in self.environments:
            return None

        recipient = self._get_slack_user_profile_summary(recipient_user_id)
        operator = self._get_slack_user_profile_summary(current_user_id)
        ts = message.get("ts")

        return {
            "channel_id": channel_id,
            "request_ts": ts,
            "database": database,
            "environment": environment,
            "secret_type": "db",
            "path": f"database/creds/{database}",
            "recipient": recipient,
            "operator": operator,
        }

    def _parse_audit_notification_message(self, message: dict) -> dict:
        """Extract non-secret audit metadata from a Vault notification."""
        raw_text = self._slack_message_text(message)
        normalized = self._normalize_slack_text(raw_text)

        env_match = re.search(r"\bEnv(?:ironment)?\s*:\s*([A-Za-z0-9_-]+)", normalized, re.IGNORECASE)
        service_match = re.search(r"\bService\s*:\s*([A-Za-z0-9._-]+)", normalized, re.IGNORECASE)
        recipient_match = re.search(r"\bsent to\s+(.+?)\s+at\s+", normalized, re.IGNORECASE)
        sender_match = re.search(r"\sby\s+(.+?)\.?\s*$", normalized, re.IGNORECASE)

        return {
            "ts": message.get("ts"),
            "is_vault_notification": (
                "New Database Credentials Sent" in normalized
                or "New credentials sent" in normalized
            ),
            "environment": env_match.group(1).lower() if env_match else None,
            "service": service_match.group(1).strip().lower() if service_match else None,
            "recipient_name": recipient_match.group(1).strip() if recipient_match else None,
            "sender_name": sender_match.group(1).strip() if sender_match else None,
        }

    def _name_matches(self, expected_profile: dict, observed_name: Optional[str]) -> bool:
        """Compare Slack display/real names from structured profile metadata."""
        if not observed_name:
            return False

        observed = observed_name.strip().lower()
        candidates = {
            str(expected_profile.get("name", "")).strip().lower(),
            str(expected_profile.get("real_name", "")).strip().lower(),
            str(expected_profile.get("display_name", "")).strip().lower(),
        }
        candidates.discard("")
        return observed in candidates

    def _is_trusted_db_request_sender(
        self,
        operator: dict,
        observed_name: Optional[str],
    ) -> bool:
        """Return whether an audit sender can definitively complete DB requests."""
        if self._name_matches(operator, observed_name):
            return True
        if not observed_name:
            return False

        configured_names = os.getenv(
            "SLACK_DB_REQUEST_TRUSTED_SENDER_NAMES",
            "Noodles Wang",
        )
        trusted_names = {
            name.strip().lower()
            for name in configured_names.split(",")
            if name.strip()
        }
        return observed_name.strip().lower() in trusted_names

    def _find_db_credential_request_status(
        self,
        channel_id: str,
        request_ts: str,
        environment: str,
        recipient: dict,
        operator: Optional[dict] = None,
        database: Optional[str] = None,
        limit: int = 100,
    ) -> dict:
        """Find whether a DB request has a later matching Vault audit notification."""
        if not self.slack_client:
            return {
                "already_processed": False,
                "confidence": "none",
                "reason": "Slack is not configured.",
            }

        try:
            response = self.slack_client.conversations_history(
                channel=channel_id,
                oldest=request_ts,
                inclusive=False,
                limit=self._bounded_slack_limit(limit),
            )
        except SlackApiError as e:
            logger.error(f"Slack API error while checking request status: {e.response['error']}")
            return {
                "already_processed": False,
                "confidence": "none",
                "reason": f"Slack API error: {e.response['error']}",
            }
        except Exception as e:
            logger.error(f"Error checking request status: {e}")
            return {
                "already_processed": False,
                "confidence": "none",
                "reason": str(e),
            }

        messages = list(response.get("messages", []) or [])
        try:
            thread_response = self.slack_client.conversations_replies(
                channel=channel_id,
                ts=request_ts,
                limit=self._bounded_slack_limit(limit),
            )
            for message in thread_response.get("messages", []) or []:
                if message.get("ts") and message.get("ts") != request_ts:
                    messages.append(message)
        except SlackApiError as e:
            # Some channels/messages may not have thread access; channel history is still useful.
            logger.info(f"Unable to read request thread while checking status: {e.response['error']}")
        except Exception as e:
            logger.info(f"Unable to read request thread while checking status: {e}")

        seen_ts = set()
        unique_messages = []
        for message in sorted(messages, key=lambda item: item.get("ts", ""), reverse=True):
            ts = message.get("ts")
            if not ts or ts in seen_ts:
                continue
            seen_ts.add(ts)
            unique_messages.append(message)

        expected_env = environment.lower()
        expected_service = database.strip().lower() if database else None
        operator = operator or {}

        for message in unique_messages:
            audit = self._parse_audit_notification_message(message)
            if not audit["is_vault_notification"]:
                continue
            if audit["environment"] != expected_env:
                continue
            if not self._name_matches(recipient, audit["recipient_name"]):
                continue

            # Service-aware matching: when both the request and the notification
            # name a service, they must agree. A notification for a different
            # service to the same recipient/env is NOT a match for this request.
            audit_service = audit.get("service")
            if expected_service and audit_service and audit_service != expected_service:
                continue
            service_confirmed = bool(
                expected_service and audit_service and audit_service == expected_service
            )

            sender_matches = True
            if operator:
                sender_matches = self._is_trusted_db_request_sender(
                    operator,
                    audit["sender_name"],
                )

            if not sender_matches:
                return {
                    "already_processed": True,
                    "confidence": "medium",
                    "processed_ts": audit["ts"],
                    "processed_by": {"name": audit["sender_name"]},
                    "reason": (
                        "Found a later Vault notification for the same recipient "
                        "and environment, but the sender did not match exactly."
                    ),
                }

            if expected_service and not service_confirmed:
                # Recipient/env match, but the notification lacks a parseable
                # Service field (e.g. older audit format), so we cannot confirm
                # it was for THIS database. Flag for human confirmation instead
                # of silently treating a different service as already processed.
                return {
                    "already_processed": True,
                    "confidence": "medium",
                    "processed_ts": audit["ts"],
                    "processed_by": {
                        "id": operator.get("id"),
                        "name": audit["sender_name"] or operator.get("name"),
                    },
                    "reason": (
                        "Found a later Vault notification matching the recipient and "
                        "environment, but it did not include a Service field to confirm "
                        "it was for this database."
                    ),
                }

            return {
                "already_processed": True,
                "confidence": "high",
                "processed_ts": audit["ts"],
                "processed_by": {
                    "id": operator.get("id"),
                    "name": audit["sender_name"] or operator.get("name"),
                },
            }

        return {
            "already_processed": False,
            "confidence": "high",
            "reason": "No later matching Vault notification was found.",
        }

    async def vault_get_db_credential_request_status(
        self,
        channel_id: str,
        request_ts: str,
        environment: str,
        recipient_user_id: str,
        operator_user_id: Optional[str] = None,
        database: Optional[str] = None,
        limit: int = 100,
    ) -> str:
        """Return processed status for one DB credential request without exposing Slack messages."""
        if not SLACK_AVAILABLE or not self.slack_client:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "Slack is not configured. Set SLACK_ENABLED=true and "
                        "SLACK_BOT_TOKEN in environment variables."
                    ),
                }
            )

        if not channel_id or not request_ts or not environment or not recipient_user_id:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "channel_id, request_ts, environment, and recipient_user_id "
                        "are required."
                    ),
                }
            )

        recipient = self._get_slack_user_profile_summary(recipient_user_id)
        operator = None
        if operator_user_id:
            operator = self._get_slack_user_profile_summary(operator_user_id)
        else:
            configured_operator_id = self._get_slack_operator_user_id()
            if configured_operator_id:
                operator = self._get_slack_user_profile_summary(configured_operator_id)

        status = self._find_db_credential_request_status(
            channel_id=channel_id,
            request_ts=request_ts,
            environment=environment,
            recipient=recipient,
            operator=operator,
            database=database,
            limit=limit,
        )

        return json.dumps(
            {
                "success": True,
                "channel_id": channel_id,
                "request_ts": request_ts,
                "environment": environment.lower(),
                "database": database,
                "recipient": recipient,
                "status": status,
                "raw_slack_messages_returned": False,
            },
            indent=2,
        )

    async def vault_get_latest_db_credential_request(
        self,
        channel_id: Optional[str] = None,
        include_processed_status: bool = True,
        limit: int = 100,
    ) -> str:
        """Return the latest DB credential request directed at the configured operator."""
        if not SLACK_AVAILABLE or not self.slack_client:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "Slack is not configured. Set SLACK_ENABLED=true and "
                        "SLACK_BOT_TOKEN in environment variables."
                    ),
                }
            )

        operator_user_id = self._get_slack_operator_user_id()
        if not operator_user_id:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "No Slack operator user configured. Set "
                        "SLACK_OPERATOR_USER_ID or SLACK_USER_ID."
                    ),
                }
            )

        resolved_channel_id = self._resolve_db_request_channel_id(channel_id)
        if not resolved_channel_id:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "Could not resolve DB credential request channel. Set "
                        "SLACK_DB_REQUEST_CHANNEL_ID or SLACK_DB_REQUEST_CHANNEL_NAME."
                    ),
                }
            )

        try:
            response = self.slack_client.conversations_history(
                channel=resolved_channel_id,
                limit=self._bounded_slack_limit(limit),
            )
        except SlackApiError as e:
            logger.error(f"Slack API error while reading DB request candidates: {e.response['error']}")
            return json.dumps({"success": False, "error": f"Slack API error: {e.response['error']}"})
        except Exception as e:
            logger.error(f"Error reading DB request candidates: {e}")
            return json.dumps({"success": False, "error": str(e)})

        latest_request = None
        for message in response.get("messages", []) or []:
            parsed = self._parse_db_credential_request_message(
                message=message,
                channel_id=resolved_channel_id,
                current_user_id=operator_user_id,
            )
            if parsed:
                latest_request = parsed
                break

        if not latest_request:
            return json.dumps(
                {
                    "success": True,
                    "found": False,
                    "channel_id": resolved_channel_id,
                    "message": "No DB credential request directed at the configured operator was found.",
                    "raw_slack_messages_returned": False,
                },
                indent=2,
            )

        if include_processed_status:
            latest_request["status"] = self._find_db_credential_request_status(
                channel_id=latest_request["channel_id"],
                request_ts=latest_request["request_ts"],
                environment=latest_request["environment"],
                recipient=latest_request["recipient"],
                operator=latest_request["operator"],
                database=latest_request["database"],
                limit=limit,
            )

        return json.dumps(
            {
                "success": True,
                "found": True,
                "request": latest_request,
                "raw_slack_messages_returned": False,
                "credential_values_returned": False,
            },
            indent=2,
        )

    def _scan_db_request_messages(self, channel_id: str, oldest_ts: float) -> list:
        """Page through channel history back to oldest_ts, returning raw messages."""
        messages = []
        cursor = None
        # Bound the scan: at most 10 pages of 200 to avoid unbounded paging.
        for _ in range(10):
            kwargs = {
                "channel": channel_id,
                "limit": 200,
                "oldest": f"{oldest_ts:.6f}",
            }
            if cursor:
                kwargs["cursor"] = cursor
            response = self.slack_client.conversations_history(**kwargs)
            messages.extend(response.get("messages", []) or [])
            cursor = (response.get("response_metadata") or {}).get("next_cursor")
            if not cursor:
                break
        return messages

    async def vault_get_pending_db_credential_requests(
        self,
        channel_id: Optional[str] = None,
        include_stale: bool = True,
        limit: int = 100,
    ) -> str:
        """Return all unprocessed DB credential requests for the operator, deduped and aged.

        Requests sharing the same (environment, service, recipient) are collapsed to
        the newest one. Each returned request carries an age tier (fresh/stale) so the
        caller can require explicit confirmation for stale items.
        """
        if not SLACK_AVAILABLE or not self.slack_client:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "Slack is not configured. Set SLACK_ENABLED=true and "
                        "SLACK_BOT_TOKEN in environment variables."
                    ),
                }
            )

        operator_user_id = self._get_slack_operator_user_id()
        if not operator_user_id:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "No Slack operator user configured. Set "
                        "SLACK_OPERATOR_USER_ID or SLACK_USER_ID."
                    ),
                }
            )

        resolved_channel_id = self._resolve_db_request_channel_id(channel_id)
        if not resolved_channel_id:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "Could not resolve DB credential request channel. Set "
                        "SLACK_DB_REQUEST_CHANNEL_ID or SLACK_DB_REQUEST_CHANNEL_NAME."
                    ),
                }
            )

        oldest_ts = max(0.0, time.time() - self._db_request_lookback_seconds())
        try:
            messages = self._scan_db_request_messages(resolved_channel_id, oldest_ts)
        except SlackApiError as e:
            logger.error(f"Slack API error while scanning DB requests: {e.response['error']}")
            return json.dumps({"success": False, "error": f"Slack API error: {e.response['error']}"})
        except Exception as e:
            logger.error(f"Error scanning DB requests: {e}")
            return json.dumps({"success": False, "error": str(e)})

        # Parse every workflow request directed at the operator, newest first.
        parsed_requests = []
        for message in messages:
            parsed = self._parse_db_credential_request_message(
                message=message,
                channel_id=resolved_channel_id,
                current_user_id=operator_user_id,
            )
            if parsed:
                parsed_requests.append(parsed)
        parsed_requests.sort(key=lambda r: r.get("request_ts", ""), reverse=True)

        # Dedup by (environment, service, recipient). Newest wins; older true
        # duplicates are collapsed but counted.
        deduped = []
        seen_keys = {}
        for request in parsed_requests:
            recipient_id = (request.get("recipient") or {}).get("id")
            key = (
                request.get("environment"),
                request.get("database", "").lower(),
                recipient_id,
            )
            if key in seen_keys:
                seen_keys[key]["duplicate_count"] += 1
                continue
            request["duplicate_count"] = 1
            seen_keys[key] = request
            deduped.append(request)

        pending = []
        stale_pending = []
        already_processed_count = 0
        for request in deduped:
            status = self._find_db_credential_request_status(
                channel_id=request["channel_id"],
                request_ts=request["request_ts"],
                environment=request["environment"],
                recipient=request["recipient"],
                operator=request["operator"],
                database=request["database"],
                limit=limit,
            )
            # Definitively handled (high confidence) -> drop. Medium confidence
            # stays in the list flagged, so the operator can confirm.
            if status.get("already_processed") and status.get("confidence") == "high":
                already_processed_count += 1
                continue

            age = self._classify_db_request_age(request["request_ts"])
            if age["tier"] == "expired":
                # Outside the actionable lookback window; skip entirely.
                continue

            request["status"] = status
            request["age"] = age
            request["possibly_processed"] = bool(status.get("already_processed"))
            if age["stale"]:
                stale_pending.append(request)
            else:
                pending.append(request)

        if not include_stale:
            stale_pending = []

        return json.dumps(
            {
                "success": True,
                "channel_id": resolved_channel_id,
                "fresh_hours": self._db_request_fresh_seconds() // 3600,
                "lookback_days": self._db_request_lookback_seconds() // 86400,
                "counts": {
                    "pending": len(pending),
                    "stale_pending": len(stale_pending),
                    "already_processed": already_processed_count,
                },
                "pending_requests": pending,
                "stale_requests": stale_pending,
                "raw_slack_messages_returned": False,
                "credential_values_returned": False,
            },
            indent=2,
        )

    async def vault_mark_db_credential_request(
        self,
        channel_id: str,
        request_ts: str,
        status: str,
    ) -> str:
        """Mark a validated Slack DB credential request as processing or completed."""
        if not SLACK_AVAILABLE or not self.slack_client:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "Slack is not configured. Set SLACK_ENABLED=true and "
                        "SLACK_BOT_TOKEN in environment variables."
                    ),
                }
            )

        reaction_by_status = {
            "processing": "eyes",
            "completed": "white_check_mark",
        }
        reaction = reaction_by_status.get((status or "").lower())
        if not channel_id or not request_ts or not reaction:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "channel_id, request_ts, and status are required; "
                        "status must be processing or completed."
                    ),
                }
            )

        configured_channel_id = self._resolve_db_request_channel_id()
        if not configured_channel_id or channel_id != configured_channel_id:
            return json.dumps(
                {
                    "success": False,
                    "error": "channel_id must match the configured DB request channel.",
                }
            )

        operator_user_id = self._get_slack_operator_user_id()
        if not operator_user_id:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "No Slack operator user configured. Set "
                        "SLACK_OPERATOR_USER_ID or SLACK_USER_ID."
                    ),
                }
            )

        try:
            response = self.slack_client.conversations_replies(
                channel=channel_id,
                ts=request_ts,
                limit=1,
            )
            request_message = next(
                (
                    message
                    for message in response.get("messages", []) or []
                    if message.get("ts") == request_ts
                ),
                None,
            )
            if not request_message or not self._parse_db_credential_request_message(
                message=request_message,
                channel_id=channel_id,
                current_user_id=operator_user_id,
            ):
                return json.dumps(
                    {
                        "success": False,
                        "error": "The target message is not a valid DB credential request.",
                    }
                )

            if status.lower() == "completed":
                try:
                    self.slack_client.reactions_remove(
                        channel=channel_id,
                        timestamp=request_ts,
                        name="eyes",
                    )
                except SlackApiError as e:
                    if e.response["error"] != "no_reaction":
                        raise

            self.slack_client.reactions_add(
                channel=channel_id,
                timestamp=request_ts,
                name=reaction,
            )
        except SlackApiError as e:
            error = e.response["error"]
            if error != "already_reacted":
                logger.error(f"Slack API error while marking DB request: {error}")
                return json.dumps(
                    {"success": False, "error": f"Slack API error: {error}"}
                )
        except Exception as e:
            logger.error(f"Error marking DB request: {e}")
            return json.dumps({"success": False, "error": str(e)})

        return json.dumps(
            {
                "success": True,
                "channel_id": channel_id,
                "request_ts": request_ts,
                "status": status.lower(),
                "reaction": reaction,
                "raw_slack_messages_returned": False,
                "credential_values_returned": False,
            },
            indent=2,
        )

    def _post_credentials_audit(
        self,
        env: str,
        data: dict,
        recipient_name: str,
        audit_timestamp: str,
        service: Optional[str] = None,
        header_text: str = "🚀 New Database Credentials Sent",
        secret_path: Optional[str] = None,
    ) -> None:
        """Post an audit message to the credentials audit channel.

        Defaults produce the db-credentials audit format. kv shares pass a
        distinct header_text and secret_path — the header (and fallback text)
        must NOT contain "New Database Credentials Sent" or "New credentials
        sent", which the DB request processed-status matcher keys on.
        """
        audit_channel = os.getenv("SLACK_AUDIT_CHANNEL_ID", "C08GHV4ELRX")
        if not self.slack_client or not audit_channel:
            return

        sender_name = self._get_slack_user_real_name(self.slack_user_id)
        cred_lines = "\n".join(f"> {k}: {v}" for k, v in data.items())

        # Non-secret context line `*Env:* ... *Service:* ...`. The Service field
        # lets the processed-status check disambiguate which database a recipient
        # was sent, so multiple distinct-service requests can't be confused.
        env_service_text = f"*Env:* `{env.lower()}`"
        if service:
            env_service_text += f"\n*Service:* `{service.lower()}`"
        if secret_path:
            env_service_text += f"\n*Path:* `{secret_path}`"

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": header_text,
                    "emoji": True,
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": env_service_text,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": cred_lines,
                },
            },
            {"type": "divider"},
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"and sent to {recipient_name} at {audit_timestamp} "
                            f"by {sender_name}."
                        ),
                    }
                ],
            },
        ]

        try:
            self.slack_client.chat_postMessage(
                channel=audit_channel,
                blocks=blocks,
                text=(
                    f"Vault secret {secret_path} sent to {recipient_name} by {sender_name}"
                    if secret_path
                    else f"New credentials sent to {recipient_name} by {sender_name}"
                ),
            )
            logger.info(f"✓ Audit message posted to channel {audit_channel}")
        except Exception as e:
            logger.warning(f"Failed to post audit message to channel {audit_channel}: {e}")

    async def vault_share_secret(
        self,
        path: str,
        slack_user: str,
        mount_point: str = "secret",
        secret_type: str = "kv",
        keys: Optional[list] = None,
    ) -> str:
        """Fetch a Vault secret and send it directly to a Slack user as a DM.

        The secret value is NEVER returned to the AI — only success/failure status.

        Args:
            path: Vault secret path.
                  For kv type: KV path under mount_point (e.g., item-management-service)
                  For db type: full database creds path (e.g., database/creds/warehouse-management-service)
            slack_user: Slack user display name, real name, or username
            mount_point: KV mount point (default: secret), only used when secret_type is 'kv'
            secret_type: 'kv' for KV secrets engine (default), 'db' for dynamic database credentials
            keys: Optional list of key names — only these keys of the KV secret
                  are sent. Keys missing from the secret are reported back as
                  missing_keys (names only). Only supported for 'kv' type.
        """
        if not self._ensure_authenticated():
            return json.dumps(
                {"success": False, "error": "Not authenticated. Please login first."}
            )

        if not SLACK_AVAILABLE or not self.slack_client:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "Slack is not configured. Set SLACK_ENABLED=true and "
                        "SLACK_BOT_TOKEN in environment variables."
                    ),
                }
            )

        if keys is not None:
            if secret_type != "kv":
                return json.dumps(
                    {
                        "success": False,
                        "error": (
                            "The 'keys' parameter is only supported for kv secrets. "
                            "Dynamic database credentials are always sent in full."
                        ),
                    }
                )
            if not keys:
                return json.dumps(
                    {
                        "success": False,
                        "error": (
                            "'keys' must be a non-empty list of key names, "
                            "or omitted to share the whole secret."
                        ),
                    }
                )

        # Step 1: Resolve Slack user ID
        matched_users = self._find_slack_users(slack_user)
        if len(matched_users) == 0:
            return json.dumps(
                {
                    "success": False,
                    "error": f"Slack user '{slack_user}' not found in workspace.",
                }
            )
        if len(matched_users) > 1:
            candidates = [
                f"{u['real_name']} (@{u['display_name']})" for u in matched_users
            ]
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        f"Multiple Slack users matched '{slack_user}'. "
                        "Please be more specific and choose one of the following:"
                    ),
                    "candidates": candidates,
                }
            )
        target_user_id = matched_users[0]["id"]

        # Step 2: Fetch secret from Vault (data never leaves this method to AI)
        display_path = path if secret_type == "db" else f"{mount_point}/{path}"
        try:
            if secret_type == "db":
                # Dynamic credentials via generic read (e.g., database/creds/<role>)
                response = self.vault_client.read(path)
                if response is None:
                    return json.dumps(
                        {
                            "success": False,
                            "error": "Path not found or no data returned",
                            "path": path,
                        }
                    )
                data = response["data"]
            else:
                # KV secrets engine
                try:
                    response = self.vault_client.secrets.kv.v2.read_secret_version(
                        path=path, mount_point=mount_point
                    )
                    data = response["data"]["data"]
                except Exception:
                    response = self.vault_client.secrets.kv.v1.read_secret(
                        path=path, mount_point=mount_point
                    )
                    data = response["data"]
        except Exception as e:
            return json.dumps(
                {
                    "success": False,
                    "error": f"Failed to retrieve secret from Vault: {str(e)}",
                    "path": display_path,
                }
            )

        # Step 2.5: Optionally narrow the payload to the requested keys (kv only).
        # Missing keys are reported by NAME only — values never reach the AI.
        shared_keys: Optional[list] = None
        missing_keys: list = []
        if keys is not None:
            missing_keys = [k for k in keys if k not in data]
            present_keys = [k for k in keys if k in data]
            if not present_keys:
                return json.dumps(
                    {
                        "success": False,
                        "error": (
                            "None of the requested keys exist in the secret. "
                            "Nothing was sent."
                        ),
                        "requested_keys": keys,
                        "available_keys": list(data.keys()),
                        "path": display_path,
                    },
                    indent=2,
                )
            data = {k: data[k] for k in present_keys}
            shared_keys = present_keys

        # Step 3: Send secret directly to the target Slack user
        try:
            now = datetime.now()
            timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
            audit_timestamp = now.strftime("%-b %-d, %Y, %-I:%M:%S %p")
            env = self.current_env.upper() if self.current_env else "N/A"
            formatted_data = self._safe_format_data(data)

            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🔐 Vault Secret: {display_path}",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Environment:*\n{env}"},
                        {"type": "mrkdwn", "text": f"*Time:*\n{timestamp}"},
                    ],
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"```\n{formatted_data}\n```",
                    },
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "⚠️ _This message contains sensitive information. Please handle it securely and delete it after use._",
                        }
                    ],
                },
            ]

            if shared_keys is not None:
                # Let the recipient know this is a subset of the secret.
                blocks.insert(
                    2,
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"*Keys:* `{'`, `'.join(shared_keys)}` "
                                "_(partial share — other keys of this secret "
                                "were not included)_"
                            ),
                        },
                    },
                )

            try:
                self.slack_client.chat_postMessage(
                    channel=target_user_id,
                    blocks=blocks,
                    text=f"Vault secret {display_path}",
                )
            except SlackApiError as e:
                if "invalid_blocks" in str(e) or "invalid_text" in str(e):
                    partial_note = (
                        f"Keys: {', '.join(shared_keys)} (partial share)\n"
                        if shared_keys is not None
                        else ""
                    )
                    # Fallback to plain text
                    self.slack_client.chat_postMessage(
                        channel=target_user_id,
                        text=(
                            f"🔐 Vault Secret: {display_path}\n"
                            f"Environment: {env} | Time: {timestamp}\n"
                            f"{partial_note}\n"
                            f"```\n{formatted_data}\n```\n\n"
                            "⚠️ This message contains sensitive information. "
                            "Please handle it securely."
                        ),
                    )
                else:
                    raise

            # Post audit message to credentials audit channel
            recipient_name = matched_users[0].get("real_name") or slack_user
            if secret_type == "db":
                # database/creds/<service> -> <service>
                service_name = path.rstrip("/").rsplit("/", 1)[-1] if path else None
                self._post_credentials_audit(
                    env=env,
                    data=data,
                    recipient_name=recipient_name,
                    audit_timestamp=audit_timestamp,
                    service=service_name,
                )
            else:
                # kv share audit. The header must differ from the db one so the
                # DB request processed-status matcher never picks up kv audits.
                self._post_credentials_audit(
                    env=env,
                    data=data,
                    recipient_name=recipient_name,
                    audit_timestamp=audit_timestamp,
                    header_text="🔐 Vault Secret Sent",
                    secret_path=display_path,
                )

            logger.info(
                f"✓ Vault secret '{display_path}' sent to Slack user "
                f"'{slack_user}' ({target_user_id})"
            )
            result = {
                "success": True,
                "message": (
                    f"Secret '{display_path}' was sent successfully to "
                    f"Slack user '{slack_user}'."
                ),
                "slack_user_id": target_user_id,
                "data_returned_to_ai": False,
            }
            if shared_keys is not None:
                result["shared_keys"] = shared_keys
                if missing_keys:
                    result["missing_keys"] = missing_keys
                    result["warning"] = (
                        "Some requested keys were not found in the secret "
                        f"and were not sent: {', '.join(missing_keys)}"
                    )
            return json.dumps(result, indent=2)

        except SlackApiError as e:
            return json.dumps(
                {
                    "success": False,
                    "error": f"Slack API error: {e.response['error']}",
                }
            )
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    async def vault_login(self, environment: str = "dev") -> str:
        """Login to Vault in specified environment.

        Args:
            environment: Environment name (dev/sat/prod/local)
        """
        return self.login_sync(environment)

    async def vault_logout(self, clear_aws_cache: bool = False) -> str:
        """Logout from Vault, clear all login state and cache.

        Args:
            clear_aws_cache: Whether to also clear aws-vault credential cache
        """
        try:
            # Clear Vault client
            if self.vault_client:
                logger.info("Clearing Vault client...")
                self.vault_client = None
            self._invalidate_auth_check_cache()

            messages = []

            # Get current AWS profile in use
            current_profile = "unknown"
            if self.current_env and self.current_env in self.environments:
                current_profile = self.environments[self.current_env]["aws_profile"]

            messages.append(
                f"✓ Logged out from Vault (was using environment: {self.current_env}, AWS profile: {current_profile})"
            )

            # Clear current environment
            previous_env = self.current_env
            self.current_env = None

            # Clear aws-vault credential cache
            if clear_aws_cache and previous_env:
                logger.info(
                    f"Clearing aws-vault credentials cache for profile: {current_profile}"
                )
                try:
                    import subprocess

                    # Find aws-vault executable
                    aws_vault_path = self._find_aws_vault_path()
                    if not aws_vault_path:
                        logger.warning("aws-vault executable not found")
                        messages.append("⚠️  Could not find aws-vault executable")
                    else:
                        # Use aws-vault clear command to clear temporary credentials
                        result = subprocess.run(
                            [aws_vault_path, "clear", current_profile],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        if result.returncode == 0:
                            logger.info(
                                f"✓ Cleared aws-vault temporary credentials for {current_profile}"
                            )
                            messages.append(
                                f"✓ Cleared AWS temporary credentials for profile: {current_profile}"
                            )
                            messages.append("   Next login will require MFA")
                        else:
                            logger.warning(
                                f"Failed to clear aws-vault cache: {result.stderr}"
                            )
                            messages.append(
                                f"⚠️  Could not clear AWS cache: {result.stderr.strip()}"
                            )
                except Exception as e:
                    logger.warning(f"Error clearing aws-vault cache: {e}")
                    messages.append(f"⚠️  Could not clear AWS cache: {str(e)}")
            else:
                messages.append(
                    "ℹ️  AWS credentials cache was not cleared (use clear_aws_cache=true to clear)"
                )

            return json.dumps(
                {
                    "success": True,
                    "message": "\n".join(messages),
                    "previous_environment": previous_env,
                    "previous_aws_profile": current_profile,
                    "aws_cache_cleared": clear_aws_cache,
                }
            )
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            return json.dumps(
                {
                    "success": False,
                    "error": f"Logout failed: {str(e)}",
                }
            )

    async def vault_kv_get(self, path: str, mount_point: str = "secret") -> str:
        """
        Read KV secret.

        Args:
            path: Secret path (e.g., myapp/config)
            mount_point: KV mount point (default: secret)
        """
        if not self._ensure_authenticated():
            return json.dumps(
                {"success": False, "error": "Not authenticated. Please login first."}
            )

        try:
            # Try KV v2
            try:
                response = self.vault_client.secrets.kv.v2.read_secret_version(
                    path=path, mount_point=mount_point
                )
                data = response["data"]["data"]
            except:
                # Fallback to KV v1
                response = self.vault_client.secrets.kv.v1.read_secret(
                    path=path, mount_point=mount_point
                )
                data = response["data"]

            # Send Slack notification
            self._send_slack_notification(
                title=f"Vault KV Secret Retrieved",
                data=data,
                query_type="kv",
                service_name=f"{mount_point}/{path}",
            )

            # Decide whether to return data to AI based on configuration
            if not self.return_data_to_ai:
                # Only return keys, not values
                keys_only = list(data.keys()) if isinstance(data, dict) else []
                return json.dumps(
                    {
                        "success": True,
                        "path": f"{mount_point}/{path}",
                        "message": "✓ Secret retrieved successfully and sent to Slack",
                        "data_returned_to_ai": False,
                        "slack_notification_sent": self.slack_enabled,
                        "available_keys": keys_only,
                    },
                    indent=2,
                )

            return json.dumps(
                {"success": True, "path": f"{mount_point}/{path}", "data": data},
                indent=2,
            )

        except Exception as e:
            return json.dumps(
                {"success": False, "error": str(e), "path": f"{mount_point}/{path}"}
            )

    async def vault_kv_get_key(
        self, path: str, key: str, mount_point: str = "secret"
    ) -> str:
        """
        Read specific key value from KV secret.

        Args:
            path: Secret path (e.g., myapp/config)
            key: Field name to retrieve (e.g., password)
            mount_point: KV mount point (default: secret)
        """
        if not self._ensure_authenticated():
            return json.dumps(
                {"success": False, "error": "Not authenticated. Please login first."}
            )

        try:
            # Try KV v2
            try:
                response = self.vault_client.secrets.kv.v2.read_secret_version(
                    path=path, mount_point=mount_point
                )
                data = response["data"]["data"]
            except:
                # Fallback to KV v1
                response = self.vault_client.secrets.kv.v1.read_secret(
                    path=path, mount_point=mount_point
                )
                data = response["data"]

            # Check if key exists
            if key not in data:
                return json.dumps(
                    {
                        "success": False,
                        "error": f"Key '{key}' not found in secret",
                        "path": f"{mount_point}/{path}",
                        "available_keys": list(data.keys()),
                    },
                    indent=2,
                )

            # Get specified key value
            value = data[key]

            # Send Slack notification (only send this one key's value)
            self._send_slack_notification(
                title=f"Vault Secret Key Retrieved",
                data={key: value},  # Only send requested key
                query_type="kv",
                service_name=f"{mount_point}/{path}#{key}",
            )

            # Decide whether to return data to AI based on configuration
            if not self.return_data_to_ai:
                return json.dumps(
                    {
                        "success": True,
                        "path": f"{mount_point}/{path}",
                        "key": key,
                        "message": f"✓ Secret key '{key}' retrieved successfully and sent to Slack",
                        "data_returned_to_ai": False,
                        "slack_notification_sent": self.slack_enabled,
                    },
                    indent=2,
                )

            return json.dumps(
                {
                    "success": True,
                    "path": f"{mount_point}/{path}",
                    "key": key,
                    "value": value,
                },
                indent=2,
            )

        except Exception as e:
            return json.dumps(
                {
                    "success": False,
                    "error": str(e),
                    "path": f"{mount_point}/{path}",
                    "key": key,
                }
            )

    async def vault_kv_list(self, path: str = "", mount_point: str = "secret") -> str:
        """
        List KV secrets paths.

        Args:
            path: Path to list (e.g., myapp/)
            mount_point: KV mount point (default: secret)
        """
        if not self._ensure_authenticated():
            return json.dumps(
                {"success": False, "error": "Not authenticated. Please login first."}
            )

        try:
            # Try KV v2
            try:
                response = self.vault_client.secrets.kv.v2.list_secrets(
                    path=path, mount_point=mount_point
                )
            except:
                # Fallback to KV v1
                response = self.vault_client.secrets.kv.v1.list_secrets(
                    path=path, mount_point=mount_point
                )

            keys = response["data"]["keys"]

            return json.dumps(
                {"success": True, "path": f"{mount_point}/{path}", "keys": keys},
                indent=2,
            )

        except Exception as e:
            return json.dumps(
                {"success": False, "error": str(e), "path": f"{mount_point}/{path}"}
            )

    async def vault_read(self, path: str) -> str:
        """
        Generic Vault read method.
        Used for reading database credentials, certificates and other dynamic secrets.

        Args:
            path: Full path (e.g., database/creds/my-role)
        """
        if not self._ensure_authenticated():
            return json.dumps(
                {"success": False, "error": "Not authenticated. Please login first."}
            )

        try:
            response = self.vault_client.read(path)

            if response is None:
                return json.dumps(
                    {
                        "success": False,
                        "error": "Path not found or no data returned",
                        "path": path,
                    }
                )

            # Determine if this is database credentials
            is_database_creds = "database/creds" in path or "database/roles" in path
            query_type = "database" if is_database_creds else "general"

            # Send Slack notification
            self._send_slack_notification(
                title=f"Vault Secret Retrieved",
                data=response["data"],
                query_type=query_type,
                service_name=path,
            )

            # Decide whether to return data to AI based on configuration
            if not self.return_data_to_ai:
                # Only return keys, not values
                keys_only = (
                    list(response["data"].keys())
                    if isinstance(response["data"], dict)
                    else []
                )
                result = {
                    "success": True,
                    "path": path,
                    "message": "✓ Secret retrieved successfully and sent to Slack",
                    "data_returned_to_ai": False,
                    "slack_notification_sent": self.slack_enabled,
                    "available_keys": keys_only,
                }
                # Only return lease info, not sensitive data
                if response.get("lease_id"):
                    result["lease_id"] = response.get("lease_id")
                    result["lease_duration"] = response.get("lease_duration")
                    result["renewable"] = response.get("renewable")
                return json.dumps(result, indent=2)

            return json.dumps(
                {
                    "success": True,
                    "path": path,
                    "data": response["data"],
                    "lease_id": response.get("lease_id"),
                    "lease_duration": response.get("lease_duration"),
                    "renewable": response.get("renewable"),
                },
                indent=2,
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e), "path": path})

    async def vault_list(self, path: str) -> str:
        """
        List specified path.

        Args:
            path: Path to list
        """
        if not self._ensure_authenticated():
            return json.dumps(
                {"success": False, "error": "Not authenticated. Please login first."}
            )

        try:
            response = self.vault_client.list(path)

            if response is None:
                return json.dumps(
                    {"success": False, "error": "Path not found or empty", "path": path}
                )

            keys = response["data"]["keys"]

            return json.dumps({"success": True, "path": path, "keys": keys}, indent=2)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e), "path": path})

    async def vault_kv_delete(self, path: str, mount_point: str = "secret") -> str:
        """
        Permanently delete an entire secret path and all its versions.

        Args:
            path: Secret path to delete (e.g., myapp/config)
            mount_point: KV mount point (default: secret)
        """
        if not self._ensure_authenticated():
            return json.dumps(
                {"success": False, "error": "Not authenticated. Please login first."}
            )

        try:
            self.vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path, mount_point=mount_point
            )

            # Send Slack notification
            self._send_slack_notification(
                title=f"Vault KV Secret Deleted",
                data={"path": f"{mount_point}/{path}", "action": "delete_all_versions"},
                query_type="kv",
                service_name=f"{mount_point}/{path}",
            )

            logger.info(f"Deleted secret and all versions: {mount_point}/{path}")

            return json.dumps(
                {
                    "success": True,
                    "path": f"{mount_point}/{path}",
                    "message": f"Secret '{mount_point}/{path}' and all its versions have been permanently deleted.",
                },
                indent=2,
            )

        except Exception as e:
            return json.dumps(
                {"success": False, "error": str(e), "path": f"{mount_point}/{path}"}
            )

    async def vault_web_ui_open(self) -> str:
        """
        Open Vault Web UI for interactive management.
        
        Returns:
            JSON string with success status and URL
        """
        # Allow opening Web UI without authentication
        # The UI itself will handle login if not authenticated
        
        if not WEB_UI_AVAILABLE:
            return json.dumps({
                "success": False,
                "error": "Web UI not available. Please install flask and flask-cors: pip install flask flask-cors"
            })
        
        try:
            # Initialize Web UI if not already done
            if self.web_ui is None:
                self.web_ui = VaultWebUI(self)
                self.web_ui.start()
                logger.info("Web UI server started")
            elif not self.web_ui.is_running:
                # Web UI exists but is not running (e.g., after timeout shutdown)
                # Restart it
                logger.info("Web UI was stopped, restarting...")
                self.web_ui.start()
                logger.info("Web UI server restarted")
            
            # Open browser
            url = self.web_ui.open_browser()
            
            return json.dumps({
                "success": True,
                "message": "Web UI opened in browser",
                "url": url
            })
            
        except Exception as e:
            logger.error(f"Error opening Web UI: {e}")
            return json.dumps({
                "success": False,
                "error": str(e)
            })


async def main():
    """Main function: Start MCP server."""
    logger.info("Starting Vault MCP Server...")

    vault_server = VaultMCPServer()
    
    # # Auto-start Web UI (if available)
    # if WEB_UI_AVAILABLE and vault_server.web_ui is None:
    #     try:
    #         vault_server.web_ui = VaultWebUI(vault_server)
    #         vault_server.web_ui.start()
    #         logger.info(f"Web UI auto-started at http://{vault_server.web_ui.host}:{vault_server.web_ui.port}")
    #     except Exception as e:
    #         logger.warning(f"Failed to auto-start Web UI: {e}")
    
    server = Server("vault-mcp")

    # Register resources (empty list as we don't use resources)
    @server.list_resources()
    async def list_resources():
        return []

    # Register tools
    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="vault_login",
                description="Login to Vault in specified environment using AWS IAM authentication. Specify the environment (dev/sat/prod/local) in parameters.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "environment": {
                            "type": "string",
                            "enum": ["dev", "sat", "prod", "local"],
                            "description": "Environment to login to: dev (development), sat (testing), prod (production), local (local container)",
                            "default": "dev",
                        }
                    },
                },
            ),
            Tool(
                name="vault_logout",
                description="Logout from Vault and clear current login state. Optionally clear aws-vault credential cache (will require MFA on next login).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "clear_aws_cache": {
                            "type": "boolean",
                            "description": "Whether to also clear aws-vault credential cache. true=clear (next login requires MFA), false=keep (default)",
                            "default": False,
                        }
                    },
                },
            ),
            Tool(
                name="vault_kv_get",
                description="Read complete secret (all fields) from Vault KV storage. Suitable for reading application config, API keys and other static secrets.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Secret path, e.g., myapp/config or myapp/prod/database",
                        },
                        "mount_point": {
                            "type": "string",
                            "description": "KV secrets engine mount point",
                            "default": "secret",
                        },
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="vault_kv_get_key",
                description="Read specific single field from Vault KV secret. Use when you only need a specific field (e.g., password, API key) without the entire secret.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Secret path, e.g., myapp/config",
                        },
                        "key": {
                            "type": "string",
                            "description": "Field name to retrieve, e.g., password, api_key, username",
                        },
                        "mount_point": {
                            "type": "string",
                            "description": "KV secrets engine mount point",
                            "default": "secret",
                        },
                    },
                    "required": ["path", "key"],
                },
            ),
            Tool(
                name="vault_kv_list",
                description="List all secrets under specified path in KV storage. Used for browsing and discovering secrets.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to list, e.g., myapp/ or leave empty to list root path",
                            "default": "",
                        },
                        "mount_point": {
                            "type": "string",
                            "description": "KV secrets engine mount point",
                            "default": "secret",
                        },
                    },
                },
            ),
            Tool(
                name="vault_read",
                description="Generic Vault read method. Used for reading dynamic secrets such as database credentials (database/creds/role), AWS credentials, certificates, etc.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Full Vault path, e.g., database/creds/my-role or aws/creds/my-role",
                        }
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="vault_list",
                description="List all sub-paths under specified path. This is a generic list method that can be used for any Vault path.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to list, e.g., database/roles or pki/certs",
                        }
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="vault_web_ui_open",
                description="Open Vault Web UI for interactive management. Supports browsing, creating, editing secrets with a beautiful graphical interface.",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            Tool(
                name="vault_share_secret",
                description=(
                    "Fetch a Vault secret and send it directly to a Slack user as a private DM. "
                    "The secret content is NEVER returned to the AI — only success/failure status is reported. "
                    "Use this when asked to share credentials or secrets with a specific person in Slack. "
                    "Supports two secret types: 'kv' for KV secrets engine (default), "
                    "'db' for dynamic database credentials (uses vault read, path like database/creds/<service>)."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": (
                                "Vault secret path. "
                                "For kv type: path under mount_point (e.g., item-management-service). "
                                "For db type: full database creds path (e.g., database/creds/warehouse-management-service)."
                            ),
                        },
                        "slack_user": {
                            "type": "string",
                            "description": "Slack user display name, real name, or username to send the secret to",
                        },
                        "mount_point": {
                            "type": "string",
                            "description": "KV mount point (default: secret), only used when secret_type is 'kv'",
                            "default": "secret",
                        },
                        "secret_type": {
                            "type": "string",
                            "description": "'kv' for KV secrets engine (default), 'db' for dynamic database credentials",
                            "enum": ["kv", "db"],
                            "default": "kv",
                        },
                        "keys": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Optional list of key names — only these keys of the KV secret are sent "
                                "to the Slack user. Keys missing from the secret are skipped and reported "
                                "back as missing_keys (names only, never values). "
                                "Only supported when secret_type is 'kv'. Omit to share the whole secret."
                            ),
                        },
                    },
                    "required": ["path", "slack_user"],
                },
            ),
            Tool(
                name="vault_get_latest_db_credential_request",
                description=(
                    "Return the latest DB credential workflow request directed at the configured Slack operator "
                    "from the DB credential request channel. Only structured fields are returned; raw Slack "
                    "messages and credential values are never returned to the AI. When requested, also includes "
                    "whether a later matching Vault notification already processed the request."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "channel_id": {
                            "type": "string",
                            "description": (
                                "Optional Slack channel ID. Defaults to SLACK_DB_REQUEST_CHANNEL_ID, "
                                "SLACK_AUDIT_CHANNEL_ID, or SLACK_DB_REQUEST_CHANNEL_NAME."
                            ),
                        },
                        "include_processed_status": {
                            "type": "boolean",
                            "description": "Whether to check for a later matching Vault notification",
                            "default": True,
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum recent Slack messages for the server-side scan, capped at 200",
                            "default": 100,
                        },
                    },
                },
            ),
            Tool(
                name="vault_get_pending_db_credential_requests",
                description=(
                    "Return ALL unprocessed DB credential workflow requests directed at the configured "
                    "Slack operator, not just the latest. Requests sharing the same (environment, service, "
                    "recipient) are deduplicated to the newest one. Each request includes an age tier "
                    "('fresh' vs 'stale') and processed status. Stale requests (older than the fresh window) "
                    "are returned separately and should be confirmed individually before sending. Only "
                    "structured fields are returned; raw Slack messages and credential values are never returned."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "channel_id": {
                            "type": "string",
                            "description": (
                                "Optional Slack channel ID. Defaults to SLACK_DB_REQUEST_CHANNEL_ID, "
                                "SLACK_AUDIT_CHANNEL_ID, or SLACK_DB_REQUEST_CHANNEL_NAME."
                            ),
                        },
                        "include_stale": {
                            "type": "boolean",
                            "description": (
                                "Whether to include stale (older than SLACK_DB_REQUEST_FRESH_HOURS) "
                                "pending requests in a separate 'stale_requests' list."
                            ),
                            "default": True,
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum Slack messages per status check, capped at 200",
                            "default": 100,
                        },
                    },
                },
            ),
            Tool(
                name="vault_get_db_credential_request_status",
                description=(
                    "Return whether a specific DB credential request has already been processed by finding "
                    "a later matching Vault notification. Only structured status is returned; raw Slack messages "
                    "and credential values are never returned to the AI."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "channel_id": {
                            "type": "string",
                            "description": "Slack channel ID containing the request and Vault notification",
                        },
                        "request_ts": {
                            "type": "string",
                            "description": "Slack timestamp of the DB credential request message",
                        },
                        "environment": {
                            "type": "string",
                            "enum": ["dev", "sat", "prod", "local"],
                            "description": "Vault environment from the request",
                        },
                        "recipient_user_id": {
                            "type": "string",
                            "description": "Slack user ID of the recipient who should receive the credential",
                        },
                        "operator_user_id": {
                            "type": "string",
                            "description": (
                                "Optional Slack user ID of the operator expected to have processed the request. "
                                "Defaults to SLACK_OPERATOR_USER_ID or SLACK_USER_ID."
                            ),
                        },
                        "database": {
                            "type": "string",
                            "description": (
                                "Optional database/service name from the request. When provided, the "
                                "processed-status check requires the Vault notification to be for the same "
                                "service, preventing a different service to the same recipient from being "
                                "treated as a match."
                            ),
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum later Slack messages for the server-side scan, capped at 200",
                            "default": 100,
                        },
                    },
                    "required": [
                        "channel_id",
                        "request_ts",
                        "environment",
                        "recipient_user_id",
                    ],
                },
            ),
            Tool(
                name="vault_mark_db_credential_request",
                description=(
                    "Add a processing (eyes) or completed (white_check_mark) reaction to a validated "
                    "database credential workflow request. The target must be in the configured DB request "
                    "channel and must parse as a request directed at the configured operator."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "channel_id": {
                            "type": "string",
                            "description": "Slack channel ID returned by the DB request preflight tool",
                        },
                        "request_ts": {
                            "type": "string",
                            "description": "Slack timestamp returned by the DB request preflight tool",
                        },
                        "status": {
                            "type": "string",
                            "enum": ["processing", "completed"],
                            "description": (
                                "processing adds eyes; completed adds white_check_mark"
                            ),
                        },
                    },
                    "required": ["channel_id", "request_ts", "status"],
                },
            ),
            Tool(
                name="vault_kv_delete",
                description="Permanently delete an entire secret path and all its versions from Vault KV store",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "The secret path to delete",
                        },
                        "mount_point": {
                            "type": "string",
                            "description": "KV mount point (default: secret)",
                            "default": "secret",
                        },
                    },
                    "required": ["path"],
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: Any) -> list[TextContent]:
        try:
            if name == "vault_login":
                environment = arguments.get("environment", "dev")
                result = await vault_server.vault_login(environment=environment)
            elif name == "vault_logout":
                clear_aws_cache = arguments.get("clear_aws_cache", False)
                result = await vault_server.vault_logout(
                    clear_aws_cache=clear_aws_cache
                )
            elif name == "vault_kv_get":
                result = await vault_server.vault_kv_get(
                    path=arguments.get("path"),
                    mount_point=arguments.get("mount_point", "secret"),
                )
            elif name == "vault_kv_get_key":
                result = await vault_server.vault_kv_get_key(
                    path=arguments.get("path"),
                    key=arguments.get("key"),
                    mount_point=arguments.get("mount_point", "secret"),
                )
            elif name == "vault_kv_list":
                result = await vault_server.vault_kv_list(
                    path=arguments.get("path", ""),
                    mount_point=arguments.get("mount_point", "secret"),
                )
            elif name == "vault_read":
                result = await vault_server.vault_read(path=arguments.get("path"))
            elif name == "vault_list":
                result = await vault_server.vault_list(path=arguments.get("path"))
            elif name == "vault_web_ui_open":
                result = await vault_server.vault_web_ui_open()
            elif name == "vault_kv_delete":
                result = await vault_server.vault_kv_delete(
                    path=arguments.get("path"),
                    mount_point=arguments.get("mount_point", "secret"),
                )
            elif name == "vault_share_secret":
                result = await vault_server.vault_share_secret(
                    path=arguments.get("path"),
                    slack_user=arguments.get("slack_user"),
                    mount_point=arguments.get("mount_point", "secret"),
                    secret_type=arguments.get("secret_type", "kv"),
                    keys=arguments.get("keys"),
                )
            elif name == "vault_get_latest_db_credential_request":
                result = await vault_server.vault_get_latest_db_credential_request(
                    channel_id=arguments.get("channel_id"),
                    include_processed_status=arguments.get(
                        "include_processed_status", True
                    ),
                    limit=arguments.get("limit", 100),
                )
            elif name == "vault_get_pending_db_credential_requests":
                result = await vault_server.vault_get_pending_db_credential_requests(
                    channel_id=arguments.get("channel_id"),
                    include_stale=arguments.get("include_stale", True),
                    limit=arguments.get("limit", 100),
                )
            elif name == "vault_get_db_credential_request_status":
                result = await vault_server.vault_get_db_credential_request_status(
                    channel_id=arguments.get("channel_id"),
                    request_ts=arguments.get("request_ts"),
                    environment=arguments.get("environment"),
                    recipient_user_id=arguments.get("recipient_user_id"),
                    operator_user_id=arguments.get("operator_user_id"),
                    database=arguments.get("database"),
                    limit=arguments.get("limit", 100),
                )
            elif name == "vault_mark_db_credential_request":
                result = await vault_server.vault_mark_db_credential_request(
                    channel_id=arguments.get("channel_id"),
                    request_ts=arguments.get("request_ts"),
                    status=arguments.get("status"),
                )
            else:
                result = json.dumps({"error": f"Unknown tool: {name}"})

            return [TextContent(type="text", text=result)]

        except Exception as e:
            logger.error(f"Error executing tool {name}: {e}", exc_info=True)
            return [TextContent(type="text", text=json.dumps({"error": str(e)}))]

    # Start server
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
