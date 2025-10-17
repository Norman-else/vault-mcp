"""MCP server for HashiCorp Vault access."""

import os
import json
import logging
import subprocess
from typing import Any, Optional
from urllib.parse import urljoin

import hvac
import boto3
from mcp.server import Server
from mcp.types import Tool, TextContent
from mcp.server.stdio import stdio_server

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VaultMCPServer:
    """MCP Server for Vault operations."""

    def __init__(self):
        self.vault_client: Optional[hvac.Client] = None
        self.vault_addr = os.getenv("VAULT_ADDR", "")
        self.vault_header_value = os.getenv("VAULT_HEADER_VALUE", "")
        self.vault_role = os.getenv("VAULT_ROLE", "vault_admin")
        self.aws_profile = os.getenv("AWS_PROFILE", "dev")
        self.aws_region = os.getenv("AWS_REGION", "us-east-1")
        self.k8s_context = os.getenv("K8S_CONTEXT", "")  # Kubernetes 上下文

        # 尝试从环境变量获取已存在的 token
        vault_token = os.getenv("VAULT_TOKEN")
        if vault_token:
            self._init_vault_client(vault_token)

    def _init_vault_client(self, token: str):
        """初始化 Vault 客户端."""
        self.vault_client = hvac.Client(url=self.vault_addr, token=token)

        # 验证 token 是否有效
        try:
            self.vault_client.is_authenticated()
            logger.info("Vault client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to authenticate with Vault: {e}")
            self.vault_client = None

    def _ensure_authenticated(self) -> bool:
        """确保已认证，如果没有则尝试登录."""
        if self.vault_client and self.vault_client.is_authenticated():
            return True

        # 尝试使用 AWS 认证
        try:
            return self._aws_login()
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False

    def _switch_k8s_context(self) -> bool:
        """切换到指定的 Kubernetes 上下文."""
        if not self.k8s_context:
            logger.info("No K8S_CONTEXT specified, skipping kubectl context switch")
            return True

        try:
            logger.info(f"Switching kubectl context to: {self.k8s_context}")

            # 检查 kubectl 是否安装
            check_cmd = ["kubectl", "config", "current-context"]
            result = subprocess.run(
                check_cmd, capture_output=True, text=True, timeout=5
            )

            current_context = result.stdout.strip()
            logger.info(f"Current kubectl context: {current_context}")

            # 如果已经是目标上下文，跳过切换
            if current_context == self.k8s_context:
                logger.info(f"✓ Already in context: {self.k8s_context}")
                return True

            # 切换上下文
            switch_cmd = ["kubectl", "config", "use-context", self.k8s_context]
            result = subprocess.run(
                switch_cmd, capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                logger.info(f"✓ Switched to kubectl context: {self.k8s_context}")
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

    def _get_aws_credentials_via_awsvault(self):
        """通过 aws-vault 主动获取 AWS 凭证."""
        try:
            logger.info(
                f"Trying to get credentials via aws-vault for profile: {self.aws_profile}"
            )
            logger.info(
                "⏳ If MFA prompt appears, please enter your code (30 seconds timeout)..."
            )

            # 执行 aws-vault export 获取凭证（可能需要 MFA 输入）
            # 注意：不使用 capture_output=True，这样 MFA 提示可以正常显示
            cmd = ["aws-vault", "export", self.aws_profile, "--format=json"]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                logger.warning(f"aws-vault export failed: {result.stderr}")
                return None

            # 解析 JSON 输出
            creds_json = json.loads(result.stdout)
            logger.info("✓ Successfully obtained AWS credentials via aws-vault")

            return {
                "AWS_ACCESS_KEY_ID": creds_json.get("AccessKeyId"),
                "AWS_SECRET_ACCESS_KEY": creds_json.get("SecretAccessKey"),
                "AWS_SESSION_TOKEN": creds_json.get("SessionToken"),
            }

        except subprocess.TimeoutExpired:
            logger.error("✗ aws-vault command timed out (30 seconds)")
            logger.error("Please make sure you enter MFA code when prompted")
            return None
        except Exception as e:
            logger.warning(f"Failed to get credentials via aws-vault: {e}")
            return None

    def _aws_login(self) -> bool:
        """使用 AWS IAM 认证登录 Vault."""
        try:
            logger.info(f"Attempting to login to Vault at {self.vault_addr}")
            logger.info(
                f"Using AWS profile: {self.aws_profile}, region: {self.aws_region}"
            )

            # 步骤 1: 切换 kubectl 上下文（如果需要）
            if not self._switch_k8s_context():
                logger.warning(
                    "Failed to switch kubectl context, but continuing anyway..."
                )

            # 创建临时的 Vault 客户端用于登录
            temp_client = hvac.Client(url=self.vault_addr)

            # 获取 AWS 凭证 - 优先使用 aws-vault
            access_key = None
            secret_key = None
            session_token = None

            # 方式 1: 尝试通过 aws-vault 获取凭证
            logger.info("Trying to get credentials from aws-vault...")
            aws_env = self._get_aws_credentials_via_awsvault()

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
                    logger.error("  aws-vault exec dev --duration=8h")
                    logger.error("")
                    logger.error(
                        "Then keep that terminal session open and retry in Cursor"
                    )
                    raise ValueError("No AWS credentials found")

            logger.info(f"Using Vault role: {self.vault_role}")

            # 使用 AWS IAM 认证
            response = temp_client.auth.aws.iam_login(
                access_key=access_key,
                secret_key=secret_key,
                session_token=session_token,
                role=self.vault_role,
                header_value=self.vault_header_value,
            )

            token = response["auth"]["client_token"]
            self._init_vault_client(token)

            logger.info("Successfully authenticated with Vault using AWS IAM")
            return True

        except Exception as e:
            logger.error(f"AWS login failed: {e}")
            logger.error(f"Vault address: {self.vault_addr}")
            logger.error(f"AWS profile: {self.aws_profile}")
            logger.error(f"Vault role: {self.vault_role}")
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")
            return False

    async def vault_login(self) -> str:
        """登录到 Vault."""
        if self._aws_login():
            return json.dumps(
                {
                    "success": True,
                    "message": "Successfully authenticated with Vault",
                    "vault_addr": self.vault_addr,
                }
            )
        else:
            return json.dumps(
                {
                    "success": False,
                    "message": "Failed to authenticate with Vault. Please check your AWS credentials and Vault configuration.",
                }
            )

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
            messages.append(
                f"✓ Logged out from Vault (was using AWS profile: {self.aws_profile})"
            )

            # 清空 aws-vault 的凭证缓存
            if clear_aws_cache:
                logger.info(
                    f"Clearing aws-vault credentials cache for profile: {self.aws_profile}"
                )
                try:
                    import subprocess

                    # 使用 aws-vault clear 命令清空临时凭证
                    result = subprocess.run(
                        ["aws-vault", "clear", self.aws_profile],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        logger.info(
                            f"✓ Cleared aws-vault temporary credentials for {self.aws_profile}"
                        )
                        messages.append(
                            f"✓ Cleared AWS temporary credentials for profile: {self.aws_profile}"
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
                    "previous_vault_addr": self.vault_addr,
                    "previous_aws_profile": self.aws_profile,
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

            return json.dumps(
                {"success": True, "path": f"{mount_point}/{path}", "data": data},
                indent=2,
            )

        except Exception as e:
            return json.dumps(
                {"success": False, "error": str(e), "path": f"{mount_point}/{path}"}
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
                description="使用 AWS IAM 认证登录到 Vault。如果你还没有登录或 token 已过期，请先调用此方法。",
                inputSchema={
                    "type": "object",
                    "properties": {},
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
                description="从 Vault KV 存储中读取 secret。适用于读取应用配置、API keys 等静态 secrets。",
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
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: Any) -> list[TextContent]:
        try:
            if name == "vault_login":
                result = await vault_server.vault_login()
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
            elif name == "vault_kv_list":
                result = await vault_server.vault_kv_list(
                    path=arguments.get("path", ""),
                    mount_point=arguments.get("mount_point", "secret"),
                )
            elif name == "vault_read":
                result = await vault_server.vault_read(path=arguments.get("path"))
            elif name == "vault_list":
                result = await vault_server.vault_list(path=arguments.get("path"))
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
