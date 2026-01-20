"""MCP server for HashiCorp Vault access."""

import os
import json
import io
import logging
import subprocess
import sys
from typing import Any, Optional
from urllib.parse import urljoin
from datetime import datetime

import hvac
import boto3
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

    def __init__(self):
        self.vault_client: Optional[hvac.Client] = None
        self.current_env = None  # Currently logged in environment

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
                self.slack_client = WebClient(token=self.slack_bot_token)
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

    def _init_vault_client(self, token: str, vault_addr: str):
        """Initialize Vault client."""
        self.vault_client = hvac.Client(url=vault_addr, token=token)

        # Verify token is valid
        try:
            self.vault_client.is_authenticated()
            logger.info("Vault client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to authenticate with Vault: {e}")
            self.vault_client = None

    def _ensure_authenticated(self) -> bool:
        """Ensure authenticated."""
        if self.vault_client and self.vault_client.is_authenticated():
            return True
        return False

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
            return None
        
        logger.info(f"Using aws-vault at: {aws_vault_path}")
        
        try:
            logger.info(
                f"Trying to get credentials via aws-vault for profile: {aws_profile}"
            )
            logger.info(
                "⏳ If MFA prompt appears, please enter your code (90 seconds timeout)..."
            )

            # Execute aws-vault export to get credentials (may require MFA input)
            cmd = [aws_vault_path, "export", aws_profile, "--format=json"]
            system = platform.system()
            
            # When called from Web UI, need special handling to show MFA GUI prompts
            if from_web_ui:
                if system == "Windows":
                    # Windows: Use wincredui for native GUI MFA prompt, no console window
                    CREATE_NO_WINDOW = 0x08000000
                    env = os.environ.copy()
                    env["AWS_VAULT_PROMPT"] = "wincredui"  # Force Windows Credential UI
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        creationflags=CREATE_NO_WINDOW,
                        env=env,
                    )
                    try:
                        stdout, stderr = process.communicate(timeout=90)
                        returncode = process.returncode
                    except subprocess.TimeoutExpired:
                        process.kill()
                        raise
                elif system == "Darwin":
                    # macOS: aws-vault uses native osascript dialog for MFA
                    env = os.environ.copy()
                    env["AWS_VAULT_PROMPT"] = "osascript"  # Force osascript prompt method
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        env=env,
                    )
                    try:
                        stdout, stderr = process.communicate(timeout=90)
                        returncode = process.returncode
                    except subprocess.TimeoutExpired:
                        process.kill()
                        raise
                else:
                    # Linux/other: Standard execution
                    result = subprocess.run(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=90,
                    )
                    stdout = result.stdout
                    stderr = result.stderr
                    returncode = result.returncode
            else:
                # Called from MCP/AI: Use standard subprocess which allows terminal MFA
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30,
                )
                stdout = result.stdout
                stderr = result.stderr
                returncode = result.returncode

            if returncode != 0:
                logger.warning(f"aws-vault export failed: {stderr}")
                
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

            return {
                "AWS_ACCESS_KEY_ID": creds_json.get("AccessKeyId"),
                "AWS_SECRET_ACCESS_KEY": creds_json.get("SecretAccessKey"),
                "AWS_SESSION_TOKEN": creds_json.get("SessionToken"),
            }

        except subprocess.TimeoutExpired:
            timeout = 90 if from_web_ui else 30
            logger.error(f"✗ aws-vault command timed out ({timeout} seconds)")
            logger.error("Please make sure you enter MFA code when prompted")
            return None
        except Exception as e:
            logger.warning(f"Failed to get credentials via aws-vault: {e}")
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
            temp_client = hvac.Client(url=vault_addr)

            # Get AWS credentials - prefer aws-vault
            access_key = None
            secret_key = None
            session_token = None

            # Method 1: Try to get credentials via aws-vault
            logger.info("Trying to get credentials from aws-vault...")
            aws_env = self._get_aws_credentials_via_awsvault(aws_profile, from_web_ui=from_web_ui)

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
                    raise ValueError("No AWS credentials found")

            logger.info(f"Using Vault role: {vault_role}")

            # Use AWS IAM authentication
            response = temp_client.auth.aws.iam_login(
                access_key=access_key,
                secret_key=secret_key,
                session_token=session_token,
                role=vault_role,
                header_value=vault_header_value,
            )

            token = response["auth"]["client_token"]
            self._init_vault_client(token, vault_addr)

            logger.info("Successfully authenticated with Vault using AWS IAM")
            return True

        except Exception as e:
            logger.error(f"AWS login failed: {e}")
            logger.error(f"Vault address: {vault_addr}")
            logger.error(f"AWS profile: {aws_profile}")
            logger.error(f"Vault role: {vault_role}")
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")
            return False

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
        if self._aws_login(env_config, from_web_ui=from_web_ui):
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
                    "message": f"Failed to authenticate with {environment.upper()} Vault. If you entered an incorrect MFA code, the cache has been cleared - please try again.",
                }
            )

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
