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

# 设置日志 - 使用 stderr 输出（MCP 协议使用 stdout 通信，不能污染）
# 在 Windows 上强制使用 UTF-8 编码，避免 Unicode 字符（✓、✗ 等）导致的 UnicodeEncodeError
stderr_utf8 = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)
logging.basicConfig(
    level=logging.INFO,
    # 简化格式：移除时间戳（Cursor 已经添加），只保留模块名和消息
    format='[%(name)s] %(message)s',
    handlers=[logging.StreamHandler(stderr_utf8)]
)
logger = logging.getLogger(__name__)

# 减少第三方库的日志输出，避免 MCP 日志中显示过多 [error] 标签
# 只显示 WARNING 及以上级别的日志
logging.getLogger('werkzeug').setLevel(logging.WARNING)  # Flask HTTP 服务器
logging.getLogger('mcp.server').setLevel(logging.WARNING)  # MCP 服务器内部日志
logging.getLogger('mcp.server.lowlevel').setLevel(logging.WARNING)  # MCP 低级别日志
logging.getLogger('urllib3').setLevel(logging.WARNING)  # HTTP 请求库
logging.getLogger('boto3').setLevel(logging.WARNING)  # AWS SDK
logging.getLogger('botocore').setLevel(logging.WARNING)  # AWS SDK 核心

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
        self.current_env = None  # 当前登录的环境

        # Slack 配置
        self.slack_enabled = os.getenv("SLACK_ENABLED", "false").lower() == "true"
        self.slack_bot_token = os.getenv("SLACK_BOT_TOKEN", "")
        self.slack_user_id = os.getenv("SLACK_USER_ID", "")
        self.slack_client = None

        # 安全配置：是否将查询结果返回给 AI（默认 true）
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

        # 多环境配置
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

        # Web UI 配置
        self.web_ui = None  # Will be initialized when needed

    def _init_vault_client(self, token: str, vault_addr: str):
        """初始化 Vault 客户端."""
        self.vault_client = hvac.Client(url=vault_addr, token=token)

        # 验证 token 是否有效
        try:
            self.vault_client.is_authenticated()
            logger.info("Vault client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to authenticate with Vault: {e}")
            self.vault_client = None

    def _ensure_authenticated(self) -> bool:
        """确保已认证."""
        if self.vault_client and self.vault_client.is_authenticated():
            return True
        return False

    def _switch_k8s_context(self, k8s_context: str) -> bool:
        """切换到指定的 Kubernetes 上下文.

        Args:
            k8s_context: Kubernetes 上下文名称
        """
        if not k8s_context:
            logger.info("No k8s_context specified, skipping kubectl context switch")
            return True

        try:
            logger.info(f"Switching kubectl context to: {k8s_context}")

            # 检查 kubectl 是否安装
            check_cmd = ["kubectl", "config", "current-context"]
            result = subprocess.run(
                check_cmd, capture_output=True, text=True, timeout=5
            )

            current_context = result.stdout.strip()
            logger.info(f"Current kubectl context: {current_context}")

            # 如果已经是目标上下文，跳过切换
            if current_context == k8s_context:
                logger.info(f"✓ Already in context: {k8s_context}")
                return True

            # 切换上下文
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
            return True  # 如果没有 kubectl，继续尝试连接
        except Exception as e:
            logger.error(f"Error switching kubectl context: {e}")
            return False

    def _get_aws_credentials_via_awsvault(self, aws_profile: str, from_web_ui: bool = False):
        """通过 aws-vault 主动获取 AWS 凭证.

        Args:
            aws_profile: AWS profile 名称
            from_web_ui: 是否从 Web UI 调用（需要弹出 GUI 窗口）
        """
        import platform
        
        try:
            logger.info(
                f"Trying to get credentials via aws-vault for profile: {aws_profile}"
            )
            logger.info(
                "⏳ If MFA prompt appears, please enter your code (90 seconds timeout)..."
            )

            # 执行 aws-vault export 获取凭证（可能需要 MFA 输入）
            cmd = ["aws-vault", "export", aws_profile, "--format=json"]
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
                return None

            # 解析 JSON 输出
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
        """安全地格式化数据为字符串，确保不超过 Slack 限制.

        Args:
            data: 要格式化的数据
            max_length: 最大字符数（Slack text 字段限制 3000，留 200 字符余量）

        Returns:
            格式化后的字符串
        """
        try:
            # 尝试序列化为 JSON
            formatted = json.dumps(data, indent=2, ensure_ascii=False, default=str)

            # 如果超过长度限制，截断
            if len(formatted) > max_length:
                truncated = formatted[:max_length]
                # 尝试在合理位置截断（找最后一个完整行）
                last_newline = truncated.rfind("\n")
                if last_newline > 0:
                    truncated = truncated[:last_newline]
                return truncated + f"\n...\n[Truncated - Total {len(formatted)} chars]"

            return formatted
        except Exception as e:
            logger.warning(f"Failed to format data: {e}")
            # 降级：返回简化的字符串表示
            return str(data)[:max_length]

    def _send_slack_notification(
        self,
        title: str,
        data: dict,
        query_type: str = "general",
        service_name: str = "",
    ):
        """发送 Slack 通知.

        Args:
            title: 消息标题
            data: 查询结果数据
            query_type: 查询类型 (database/kv/general)
            service_name: 服务名称
        """
        if not self.slack_enabled or not self.slack_client or not self.slack_user_id:
            return

        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # 构建消息块
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

            # 根据查询类型格式化数据
            if query_type == "database":
                # 数据库凭证：只显示 username, password 和 service
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
                    username = username[:500]  # 限制长度
                
                if "password" in data:
                    password = (
                        str(data["password"])
                        if not isinstance(data["password"], str)
                        else data["password"]
                    )
                    password = password[:500]  # 限制长度

                # 添加分隔线
                blocks.append({"type": "divider"})

                # 使用代码块格式显示凭证，便于选中复制
                if username or password:
                    credentials_code = ""
                    if username:
                        credentials_code += f"Username: {username}\n"
                    if password:
                        credentials_code += f"Password: {password}"
                    
                    # 使用 Section + mrkdwn 的代码块格式
                    blocks.append(
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"```\n{credentials_code}\n```",
                            },
                        }
                    )
                
                # 添加提示文字
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
                # 其他查询：显示 service 和完整结果
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Service:* `{service_name}`",
                        },
                    }
                )

                # 添加分隔线
                blocks.append({"type": "divider"})

                # 使用安全的格式化方法
                formatted_data = self._safe_format_data(data)
                data_text = f"```\n{formatted_data}\n```"
                blocks.append(
                    {"type": "section", "text": {"type": "mrkdwn", "text": data_text}}
                )

            # 添加警告提示
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

            # 发送消息 - 尝试使用 blocks
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
                # 如果 blocks 格式有问题，降级为纯文本消息
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
        """降级：发送纯文本 Slack 消息（当 blocks 格式失败时）.

        Args:
            title: 消息标题
            data: 查询结果数据
            query_type: 查询类型
            service_name: 服务名称
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            env = self.current_env.upper() if self.current_env else "N/A"

            # 构建纯文本消息
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

            # 发送纯文本消息
            self.slack_client.chat_postMessage(
                channel=self.slack_user_id, text=message_text
            )

            logger.info(
                f"✓ Slack fallback notification sent successfully to {self.slack_user_id}"
            )
        except Exception as e:
            logger.error(f"Failed to send Slack fallback notification: {e}")

    def _aws_login(self, env_config: dict, from_web_ui: bool = False) -> bool:
        """使用 AWS IAM 认证登录 Vault.

        Args:
            env_config: 环境配置字典
            from_web_ui: 是否从 Web UI 调用
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

            # 步骤 1: 切换 kubectl 上下文（如果需要）
            if not self._switch_k8s_context(k8s_context):
                logger.warning(
                    "Failed to switch kubectl context, but continuing anyway..."
                )

            # 创建临时的 Vault 客户端用于登录
            temp_client = hvac.Client(url=vault_addr)

            # 获取 AWS 凭证 - 优先使用 aws-vault
            access_key = None
            secret_key = None
            session_token = None

            # 方式 1: 尝试通过 aws-vault 获取凭证
            logger.info("Trying to get credentials from aws-vault...")
            aws_env = self._get_aws_credentials_via_awsvault(aws_profile, from_web_ui=from_web_ui)

            if aws_env and aws_env.get("AWS_ACCESS_KEY_ID"):
                access_key = aws_env["AWS_ACCESS_KEY_ID"]
                secret_key = aws_env["AWS_SECRET_ACCESS_KEY"]
                session_token = aws_env.get("AWS_SESSION_TOKEN")
                logger.info("✓ Using credentials from aws-vault")
            else:
                # 方式 2: 尝试从环境变量获取
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

            # 使用 AWS IAM 认证
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
            environment: 环境名称 (dev/sat/prod/local)
            from_web_ui: 是否从 Web UI 调用（影响 MFA 弹窗方式）
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
                    "message": f"Failed to authenticate with {environment.upper()} Vault. Please check your AWS credentials and Vault configuration.",
                }
            )

    async def vault_login(self, environment: str = "dev") -> str:
        """登录到指定环境的 Vault.

        Args:
            environment: 环境名称 (dev/sat/prod/local)
        """
        return self.login_sync(environment)

    async def vault_logout(self, clear_aws_cache: bool = False) -> str:
        """登出 Vault，清空所有登录状态和缓存.

        Args:
            clear_aws_cache: 是否同时清空 aws-vault 的凭证缓存
        """
        try:
            # 清空 Vault client
            if self.vault_client:
                logger.info("Clearing Vault client...")
                self.vault_client = None

            messages = []

            # 获取当前使用的 AWS profile
            current_profile = "unknown"
            if self.current_env and self.current_env in self.environments:
                current_profile = self.environments[self.current_env]["aws_profile"]

            messages.append(
                f"✓ Logged out from Vault (was using environment: {self.current_env}, AWS profile: {current_profile})"
            )

            # 清空当前环境
            previous_env = self.current_env
            self.current_env = None

            # 清空 aws-vault 的凭证缓存
            if clear_aws_cache and previous_env:
                logger.info(
                    f"Clearing aws-vault credentials cache for profile: {current_profile}"
                )
                try:
                    import subprocess

                    # 使用 aws-vault clear 命令清空临时凭证
                    result = subprocess.run(
                        ["aws-vault", "clear", current_profile],
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
        读取 KV secret.

        Args:
            path: Secret 路径（例如：myapp/config）
            mount_point: KV mount point（默认：secret）
        """
        if not self._ensure_authenticated():
            return json.dumps(
                {"success": False, "error": "Not authenticated. Please login first."}
            )

        try:
            # 尝试 KV v2
            try:
                response = self.vault_client.secrets.kv.v2.read_secret_version(
                    path=path, mount_point=mount_point
                )
                data = response["data"]["data"]
            except:
                # 回退到 KV v1
                response = self.vault_client.secrets.kv.v1.read_secret(
                    path=path, mount_point=mount_point
                )
                data = response["data"]

            # 发送 Slack 通知
            self._send_slack_notification(
                title=f"Vault KV Secret Retrieved",
                data=data,
                query_type="kv",
                service_name=f"{mount_point}/{path}",
            )

            # 根据配置决定是否返回数据给 AI
            if not self.return_data_to_ai:
                # 只返回 keys，不返回 values
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
        读取 KV secret 中指定 key 的值.

        Args:
            path: Secret 路径（例如：myapp/config）
            key: 要获取的字段名（例如：password）
            mount_point: KV mount point（默认：secret）
        """
        if not self._ensure_authenticated():
            return json.dumps(
                {"success": False, "error": "Not authenticated. Please login first."}
            )

        try:
            # 尝试 KV v2
            try:
                response = self.vault_client.secrets.kv.v2.read_secret_version(
                    path=path, mount_point=mount_point
                )
                data = response["data"]["data"]
            except:
                # 回退到 KV v1
                response = self.vault_client.secrets.kv.v1.read_secret(
                    path=path, mount_point=mount_point
                )
                data = response["data"]

            # 检查 key 是否存在
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

            # 获取指定 key 的值
            value = data[key]

            # 发送 Slack 通知（只发送这一个 key 的值）
            self._send_slack_notification(
                title=f"Vault Secret Key Retrieved",
                data={key: value},  # 只发送请求的 key
                query_type="kv",
                service_name=f"{mount_point}/{path}#{key}",
            )

            # 根据配置决定是否返回数据给 AI
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
        列出 KV secrets 路径.

        Args:
            path: 要列出的路径（例如：myapp/）
            mount_point: KV mount point（默认：secret）
        """
        if not self._ensure_authenticated():
            return json.dumps(
                {"success": False, "error": "Not authenticated. Please login first."}
            )

        try:
            # 尝试 KV v2
            try:
                response = self.vault_client.secrets.kv.v2.list_secrets(
                    path=path, mount_point=mount_point
                )
            except:
                # 回退到 KV v1
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
        通用 Vault 读取方法.
        用于读取数据库凭证、证书等动态 secrets.

        Args:
            path: 完整路径（例如：database/creds/my-role）
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

            # 判断是否是数据库凭证
            is_database_creds = "database/creds" in path or "database/roles" in path
            query_type = "database" if is_database_creds else "general"

            # 发送 Slack 通知
            self._send_slack_notification(
                title=f"Vault Secret Retrieved",
                data=response["data"],
                query_type=query_type,
                service_name=path,
            )

            # 根据配置决定是否返回数据给 AI
            if not self.return_data_to_ai:
                # 只返回 keys，不返回 values
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
                # 只返回租约信息，不返回敏感数据
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
        列出指定路径.

        Args:
            path: 要列出的路径
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
        打开 Vault Web UI 进行交互式管理.
        
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
    """主函数：启动 MCP 服务器."""
    logger.info("Starting Vault MCP Server...")

    vault_server = VaultMCPServer()
    server = Server("vault-mcp")

    # 注册资源（空列表，因为我们不使用 resources）
    @server.list_resources()
    async def list_resources():
        return []

    # 注册工具
    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="vault_login",
                description="使用 AWS IAM 认证登录到指定环境的 Vault。请在参数中指定要登录的环境（dev/sat/prod/local）。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "environment": {
                            "type": "string",
                            "enum": ["dev", "sat", "prod", "local"],
                            "description": "要登录的环境：dev（开发）、sat（测试）、prod（生产）、local（本地容器）",
                            "default": "dev",
                        }
                    },
                },
            ),
            Tool(
                name="vault_logout",
                description="登出 Vault，清空当前的登录状态。可选择是否同时清空 aws-vault 的凭证缓存（清空后下次登录需重新输入 MFA）。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "clear_aws_cache": {
                            "type": "boolean",
                            "description": "是否同时清空 aws-vault 的凭证缓存。true=清空（下次登录需 MFA），false=保留（默认）",
                            "default": False,
                        }
                    },
                },
            ),
            Tool(
                name="vault_kv_get",
                description="从 Vault KV 存储中读取完整的 secret（所有字段）。适用于读取应用配置、API keys 等静态 secrets。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Secret 的路径，例如：myapp/config 或 myapp/prod/database",
                        },
                        "mount_point": {
                            "type": "string",
                            "description": "KV secrets engine 的 mount point",
                            "default": "secret",
                        },
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="vault_kv_get_key",
                description="从 Vault KV secret 中读取指定的单个字段。当只需要获取某个特定字段（如密码、API key）而不需要整个 secret 时使用。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Secret 的路径，例如：myapp/config",
                        },
                        "key": {
                            "type": "string",
                            "description": "要获取的字段名，例如：password、api_key、username",
                        },
                        "mount_point": {
                            "type": "string",
                            "description": "KV secrets engine 的 mount point",
                            "default": "secret",
                        },
                    },
                    "required": ["path", "key"],
                },
            ),
            Tool(
                name="vault_kv_list",
                description="列出 KV 存储中指定路径下的所有 secrets。用于浏览和发现 secrets。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "要列出的路径，例如：myapp/ 或留空列出根路径",
                            "default": "",
                        },
                        "mount_point": {
                            "type": "string",
                            "description": "KV secrets engine 的 mount point",
                            "default": "secret",
                        },
                    },
                },
            ),
            Tool(
                name="vault_read",
                description="通用 Vault 读取方法。用于读取动态 secrets，如数据库凭证（database/creds/role）、AWS 凭证、证书等。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "完整的 Vault 路径，例如：database/creds/my-role 或 aws/creds/my-role",
                        }
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="vault_list",
                description="列出指定路径下的所有子路径。这是一个通用的列表方法，可以用于任何 Vault 路径。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "要列出的路径，例如：database/roles 或 pki/certs",
                        }
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="vault_web_ui_open",
                description="打开 Vault Web UI 进行交互式管理。支持浏览、创建、编辑 secrets，提供美观的图形界面。",
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

    # 启动服务器
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
