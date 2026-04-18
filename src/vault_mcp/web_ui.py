"""Vault Web UI Server - Interactive web interface for managing Vault secrets."""

import os
import sys
import json
import logging
import random
import socket
import threading
import time
import webbrowser
from datetime import datetime
from typing import Optional
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.serving import make_server

logger = logging.getLogger(__name__)

# Completely suppress werkzeug logs
logging.getLogger('werkzeug').disabled = True


class VaultWebUI:
    """Web UI server for Vault secret management."""

    @staticmethod
    def get_mcp_config_path():
        """
        Get the PostgreSQL MCP config file path based on the operating system.

        Returns:
            str: Path to the PostgreSQL MCP config file
        """
        home_dir = os.path.expanduser('~')
        config_dir = os.path.join(home_dir, 'postgresql-mcp-config')
        config_file = os.path.join(config_dir, 'environments.json')
        return config_file

    def __init__(self, vault_server):
        """
        Initialize the Web UI server.

        Args:
            vault_server: VaultMCPServer instance
        """
        self.vault_server = vault_server
        # Get the directory where this file is located
        current_dir = os.path.dirname(os.path.abspath(__file__))
        static_folder = os.path.join(current_dir, 'static')
        self.app = Flask(__name__, static_folder=static_folder, static_url_path='/static')
        CORS(self.app)  # Enable CORS for API requests
        
        self.is_running = False
        self.host = os.getenv('WEB_UI_HOST', '0.0.0.0')

        # 端口配置：优先使用环境变量，否则使用随机端口
        env_port = os.getenv('WEB_UI_PORT')
        if env_port:
            self.port = int(env_port)
            self._use_random_port = False
        else:
            self.port = None  # 延迟到 start() 时分配
            self._use_random_port = True
        
        # Timeout management
        self.last_access_time = time.time()
        timeout_minutes = int(os.getenv('WEB_UI_TIMEOUT_MINUTES', '10'))
        self.timeout_seconds = timeout_minutes * 60
        self.check_interval_seconds = int(os.getenv('WEB_UI_CHECK_INTERVAL_SECONDS', '1'))
        self.server = None
        self.timeout_check_thread = None
        self._shutdown_event = threading.Event()
        
        self._setup_routes()

    def _check_port_available(self, port: int) -> bool:
        """检查端口是否可用"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind((self.host, port))
            sock.close()
            return True
        except OSError:
            return False

    def _find_available_port(self) -> int:
        """找到一个可用的随机端口（范围 40000-49999）"""
        while True:
            port = random.randint(40000, 49999)
            if self._check_port_available(port):
                return port

    def _setup_routes(self):
        """Setup Flask routes."""
        
        @self.app.before_request
        def update_access_time():
            """Update last access time for timeout tracking."""
            # Exclude static resources and timeout API from access tracking
            if (request.path.startswith('/static/') or 
                request.path == '/favicon.ico' or 
                request.path == '/api/timeout'):
                return
            self.last_access_time = time.time()
        
        @self.app.route('/')
        def index():
            """Serve the main UI page."""
            return self._get_html_template()
        
        @self.app.route('/favicon.ico')
        def favicon():
            """Serve the favicon."""
            return send_from_directory(
                os.path.join(self.app.root_path, 'static'),
                'favicon.png',
                mimetype='image/png'
            )
        
        @self.app.route('/api/secrets/list', methods=['GET'])
        def list_secrets():
            """List all secrets in a path."""
            try:
                path = request.args.get('path', '')
                mount_point = request.args.get('mount_point', 'secret')
                
                if not self.vault_server._ensure_authenticated():
                    return jsonify({
                        'success': False,
                        'error': 'Not authenticated'
                    }), 401
                
                # List secrets
                try:
                    response = self.vault_server.vault_client.secrets.kv.v2.list_secrets(
                        path=path,
                        mount_point=mount_point
                    )
                    keys = response['data']['keys']
                    
                    # Format the response
                    secrets = []
                    for key in keys:
                        if key.endswith('/'):
                            secrets.append({
                                'path': f"{path}{key}" if path else key,
                                'type': 'folder',
                                'name': key.rstrip('/')
                            })
                        else:
                            secrets.append({
                                'path': f"{path}{key}" if path else key,
                                'type': 'secret',
                                'name': key
                            })
                    
                    return jsonify({
                        'success': True,
                        'secrets': secrets,
                        'current_path': path
                    })
                    
                except Exception as e:
                    # Empty path or no secrets
                    return jsonify({
                        'success': True,
                        'secrets': [],
                        'current_path': path
                    })
                    
            except Exception as e:
                logger.error(f"Error listing secrets: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/secrets/get', methods=['GET'])
        def get_secret():
            """Get a specific secret."""
            try:
                path = request.args.get('path')
                mount_point = request.args.get('mount_point', 'secret')
                version = request.args.get('version')  # Optional version parameter
                
                if not path:
                    return jsonify({
                        'success': False,
                        'error': 'Path is required'
                    }), 400
                
                if not self.vault_server._ensure_authenticated():
                    return jsonify({
                        'success': False,
                        'error': 'Not authenticated'
                    }), 401
                
                # Read secret
                try:
                    # Build kwargs for version parameter
                    kwargs = {'path': path, 'mount_point': mount_point}
                    if version:
                        kwargs['version'] = int(version)
                    
                    response = self.vault_server.vault_client.secrets.kv.v2.read_secret_version(**kwargs)
                    data = response['data']['data']
                    metadata = response['data']['metadata']
                    
                    return jsonify({
                        'success': True,
                        'path': path,
                        'data': data,
                        'metadata': {
                            'version': metadata.get('version'),
                            'created_time': metadata.get('created_time'),
                            'updated_time': metadata.get('updated_time'),
                            'deleted_time': metadata.get('deleted_time'),
                            'destroyed': metadata.get('destroyed', False)
                        }
                    })
                except:
                    # Try KV v1
                    response = self.vault_server.vault_client.secrets.kv.v1.read_secret(
                        path=path,
                        mount_point=mount_point
                    )
                    data = response['data']
                    
                    return jsonify({
                        'success': True,
                        'path': path,
                        'data': data,
                        'metadata': {}
                    })
                    
            except Exception as e:
                logger.error(f"Error getting secret: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/secrets/versions', methods=['GET'])
        def get_secret_versions():
            """Get all versions metadata for a secret."""
            try:
                path = request.args.get('path')
                mount_point = request.args.get('mount_point', 'secret')
                
                if not path:
                    return jsonify({
                        'success': False,
                        'error': 'Path is required'
                    }), 400
                
                if not self.vault_server._ensure_authenticated():
                    return jsonify({
                        'success': False,
                        'error': 'Not authenticated'
                    }), 401
                
                # Read secret metadata to get all versions
                try:
                    response = self.vault_server.vault_client.secrets.kv.v2.read_secret_metadata(
                        path=path,
                        mount_point=mount_point
                    )
                    
                    versions_data = response['data']['versions']
                    current_version = response['data']['current_version']
                    
                    # Format versions list
                    versions = []
                    for version_num, version_info in versions_data.items():
                        versions.append({
                            'version': int(version_num),
                            'created_time': version_info.get('created_time'),
                            'deleted_time': version_info.get('deleted_time'),
                            'destroyed': version_info.get('destroyed', False)
                        })
                    
                    # Sort by version number descending
                    versions.sort(key=lambda x: x['version'], reverse=True)
                    
                    return jsonify({
                        'success': True,
                        'path': path,
                        'current_version': current_version,
                        'versions': versions
                    })
                    
                except Exception as e:
                    # KV v1 or error
                    return jsonify({
                        'success': False,
                        'error': 'Version history not available (KV v1 or error)'
                    }), 400
                    
            except Exception as e:
                logger.error(f"Error getting secret versions: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/secrets/create', methods=['POST'])
        def create_secret():
            """Create a new secret."""
            try:
                data = request.get_json()
                path = data.get('path')
                mount_point = data.get('mount_point', 'secret')
                secret_data = data.get('data', {})
                
                if not path:
                    return jsonify({
                        'success': False,
                        'error': 'Path is required'
                    }), 400
                
                if not self.vault_server._ensure_authenticated():
                    return jsonify({
                        'success': False,
                        'error': 'Not authenticated'
                    }), 401
                
                # Create secret
                self.vault_server.vault_client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret=secret_data,
                    mount_point=mount_point
                )
                
                # Audit log
                logger.info(f"Created secret: {mount_point}/{path}")
                
                return jsonify({
                    'success': True,
                    'message': f'Secret created at {mount_point}/{path}'
                })
                
            except Exception as e:
                logger.error(f"Error creating secret: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/secrets/update', methods=['POST'])
        def update_secret():
            """Update a secret (add or modify a key-value pair)."""
            try:
                data = request.get_json()
                path = data.get('path')
                mount_point = data.get('mount_point', 'secret')
                key = data.get('key')
                value = data.get('value')
                
                if not path or not key:
                    return jsonify({
                        'success': False,
                        'error': 'Path and key are required'
                    }), 400
                
                if not self.vault_server._ensure_authenticated():
                    return jsonify({
                        'success': False,
                        'error': 'Not authenticated'
                    }), 401
                
                # Read existing secret
                existing_data = {}
                try:
                    response = self.vault_server.vault_client.secrets.kv.v2.read_secret_version(
                        path=path,
                        mount_point=mount_point
                    )
                    existing_data = response['data']['data']
                except:
                    # Secret doesn't exist, will create new
                    pass
                
                # Update the key
                existing_data[key] = value
                
                # Write back
                self.vault_server.vault_client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret=existing_data,
                    mount_point=mount_point
                )
                
                # Audit log
                logger.info(f"Updated secret: {mount_point}/{path}, key: {key}")
                
                return jsonify({
                    'success': True,
                    'message': f'Key "{key}" updated in {mount_point}/{path}',
                    'data': existing_data
                })
                
            except Exception as e:
                logger.error(f"Error updating secret: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500

        @self.app.route('/api/secrets/delete-key', methods=['POST'])
        def delete_key():
            """Delete a key from a secret."""
            try:
                data = request.get_json()
                path = data.get('path')
                mount_point = data.get('mount_point', 'secret')
                key = data.get('key')

                if not path or not key:
                    return jsonify({
                        'success': False,
                        'error': 'Path and key are required'
                    }), 400

                if not self.vault_server._ensure_authenticated():
                    return jsonify({
                        'success': False,
                        'error': 'Not authenticated'
                    }), 401

                # Read existing secret
                existing_data = {}
                try:
                    response = self.vault_server.vault_client.secrets.kv.v2.read_secret_version(
                        path=path,
                        mount_point=mount_point
                    )
                    existing_data = response['data']['data']
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'error': f'Secret not found: {str(e)}'
                    }), 404

                # Check if key exists
                if key not in existing_data:
                    return jsonify({
                        'success': False,
                        'error': f'Key "{key}" not found in secret'
                    }), 404

                # Delete the key
                del existing_data[key]

                # Write back (even if empty)
                self.vault_server.vault_client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret=existing_data,
                    mount_point=mount_point
                )

                # Audit log
                logger.info(f"Deleted key from secret: {mount_point}/{path}, key: {key}")

                return jsonify({
                    'success': True,
                    'message': f'Key "{key}" deleted from {mount_point}/{path}',
                    'data': existing_data
                })

            except Exception as e:
                logger.error(f"Error deleting key: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500

        @self.app.route('/api/secrets/delete', methods=['POST'])
        def delete_secret():
            """Delete an entire secret path and all its versions."""
            try:
                data = request.get_json()
                path = data.get('path')
                mount_point = data.get('mount_point', 'secret')

                if not path:
                    return jsonify({
                        'success': False,
                        'error': 'Path is required'
                    }), 400

                if not self.vault_server._ensure_authenticated():
                    return jsonify({
                        'success': False,
                        'error': 'Not authenticated'
                    }), 401

                self.vault_server.vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=path,
                    mount_point=mount_point
                )

                # Audit log
                logger.info(f"Deleted entire secret path: {mount_point}/{path}")

                return jsonify({
                    'success': True,
                    'message': f'Secret "{mount_point}/{path}" and all its versions have been permanently deleted.'
                })

            except Exception as e:
                logger.error(f"Error deleting secret: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500

        @self.app.route('/api/secrets/search', methods=['GET'])
        def search_secrets():
            """Search secrets by path and key name."""
            try:
                query = request.args.get('q', '').lower().strip()
                mount_point = request.args.get('mount_point', 'secret')
                
                if not query:
                    return jsonify({
                        'success': True,
                        'results': []
                    })
                
                if not self.vault_server._ensure_authenticated():
                    return jsonify({
                        'success': False,
                        'error': 'Not authenticated'
                    }), 401
                
                results = []
                
                def search_recursive(path=''):
                    """Recursively search through all secrets."""
                    try:
                        response = self.vault_server.vault_client.secrets.kv.v2.list_secrets(
                            path=path,
                            mount_point=mount_point
                        )
                        keys = response['data']['keys']
                        
                        for key in keys:
                            full_path = f"{path}{key}" if path else key
                            
                            if key.endswith('/'):
                                # It's a folder, recurse into it
                                search_recursive(full_path)
                            else:
                                # It's a secret, check if path matches
                                path_matches = query in full_path.lower()
                                
                                # Read the secret to check key names
                                matching_keys = []
                                try:
                                    secret_response = self.vault_server.vault_client.secrets.kv.v2.read_secret_version(
                                        path=full_path,
                                        mount_point=mount_point
                                    )
                                    secret_data = secret_response['data']['data']
                                    
                                    # Check each key name
                                    for key_name in secret_data.keys():
                                        if query in key_name.lower():
                                            matching_keys.append(key_name)
                                except:
                                    pass
                                
                                # Add to results if path or any key matches
                                if path_matches or matching_keys:
                                    results.append({
                                        'path': full_path,
                                        'matching_keys': matching_keys,
                                        'match_type': 'path' if path_matches else 'key'
                                    })
                    except:
                        # Empty path or error, skip
                        pass
                
                # Start recursive search from root
                search_recursive('')
                
                # Limit results to 50
                results = results[:50]
                
                return jsonify({
                    'success': True,
                    'results': results,
                    'query': query
                })
                
            except Exception as e:
                logger.error(f"Error searching secrets: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/database/roles', methods=['GET'])
        def list_database_roles():
            """List all database roles."""
            try:
                if not self.vault_server._ensure_authenticated():
                    return jsonify({
                        'success': False,
                        'error': 'Not authenticated'
                    }), 401
                
                try:
                    response = self.vault_server.vault_client.list('database/roles')
                    roles = response['data']['keys']
                    
                    return jsonify({
                        'success': True,
                        'roles': roles
                    })
                except Exception as e:
                    # No roles or error
                    return jsonify({
                        'success': True,
                        'roles': []
                    })
                    
            except Exception as e:
                logger.error(f"Error listing database roles: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/database/roles/search', methods=['GET'])
        def search_database_roles():
            """Search database roles by name."""
            try:
                query = request.args.get('q', '').lower().strip()
                
                if not query:
                    return jsonify({
                        'success': True,
                        'results': []
                    })
                
                if not self.vault_server._ensure_authenticated():
                    return jsonify({
                        'success': False,
                        'error': 'Not authenticated'
                    }), 401
                
                try:
                    # List all database roles
                    response = self.vault_server.vault_client.list('database/roles')
                    roles = response['data']['keys']
                    
                    # Filter roles that match the query
                    results = []
                    for role in roles:
                        if query in role.lower():
                            results.append({
                                'name': role,
                                'type': 'database_role',
                                'match_type': 'name'
                            })
                    
                    # Limit results to 50
                    results = results[:50]
                    
                    return jsonify({
                        'success': True,
                        'results': results,
                        'query': query
                    })
                    
                except Exception as e:
                    # No roles or error
                    return jsonify({
                        'success': True,
                        'results': []
                    })
                    
            except Exception as e:
                logger.error(f"Error searching database roles: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/database/creds/<role_name>', methods=['POST'])
        def generate_database_creds(role_name):
            """Generate database credentials for a role."""
            try:
                if not self.vault_server._ensure_authenticated():
                    return jsonify({
                        'success': False,
                        'error': 'Not authenticated'
                    }), 401

                # Generate credentials by reading from database/creds/role_name
                response = self.vault_server.vault_client.read(f'database/creds/{role_name}')

                if not response or 'data' not in response:
                    return jsonify({
                        'success': False,
                        'error': 'Failed to generate credentials'
                    }), 500

                data = response['data']

                # Audit log
                logger.info(f"Generated database credentials for role: {role_name}")

                return jsonify({
                    'success': True,
                    'role': role_name,
                    'username': data.get('username'),
                    'password': data.get('password'),
                    'lease_id': response.get('lease_id'),
                    'lease_duration': response.get('lease_duration'),
                    'renewable': response.get('renewable', False)
                })

            except Exception as e:
                logger.error(f"Error generating database credentials for {role_name}: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500

        @self.app.route('/api/database/check-mcp-config', methods=['GET'])
        def check_mcp_config():
            """Check if PostgreSQL MCP config file exists."""
            try:
                mcp_config_path = self.get_mcp_config_path()

                if os.path.exists(mcp_config_path):
                    # Try to read and validate the file
                    try:
                        with open(mcp_config_path, 'r') as f:
                            config = json.load(f)

                        # Check if required environments exist
                        has_dev = 'dev-data' in config.get('environments', {})
                        has_prod = 'prod-data' in config.get('environments', {})

                        return jsonify({
                            'success': True,
                            'exists': True,
                            'path': mcp_config_path,
                            'has_dev_data': has_dev,
                            'has_prod_data': has_prod,
                            'message': 'PostgreSQL MCP config file found and valid'
                        })
                    except json.JSONDecodeError:
                        return jsonify({
                            'success': False,
                            'exists': True,
                            'path': mcp_config_path,
                            'error': 'Config file exists but contains invalid JSON'
                        })
                    except Exception as e:
                        return jsonify({
                            'success': False,
                            'exists': True,
                            'path': mcp_config_path,
                            'error': f'Error reading config file: {str(e)}'
                        })
                else:
                    return jsonify({
                        'success': False,
                        'exists': False,
                        'path': mcp_config_path,
                        'message': 'PostgreSQL MCP config file not found'
                    })

            except Exception as e:
                logger.error(f"Error checking MCP config: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500

        @self.app.route('/api/database/sync-to-mcp', methods=['POST'])
        def sync_to_postgresql_mcp():
            """Sync database credentials to PostgreSQL MCP config file."""
            try:
                if not self.vault_server._ensure_authenticated():
                    return jsonify({
                        'success': False,
                        'error': 'Not authenticated'
                    }), 401

                data = request.get_json()
                role_name = data.get('role_name')
                username = data.get('username')
                password = data.get('password')

                if not all([role_name, username, password]):
                    return jsonify({
                        'success': False,
                        'error': 'Missing required fields: role_name, username, password'
                    }), 400

                # Get current environment
                current_env = self.vault_server.current_env
                if not current_env:
                    return jsonify({
                        'success': False,
                        'error': 'No environment is currently logged in'
                    }), 400

                # Only support dev and prod environments
                if current_env not in ['dev', 'prod']:
                    return jsonify({
                        'success': False,
                        'error': f'Unsupported environment: {current_env}. Only dev and prod are supported.'
                    }), 400

                # Extract service name from role_name
                # e.g., "data-service" -> "data"
                # e.g., "item-management-service" -> "item-management"
                # e.g., "warehouse-management-service" -> "warehouse-management"
                service_name = role_name
                if service_name.endswith('-service'):
                    service_name = service_name[:-8]  # Remove "-service" suffix

                # Build MCP environment name: {env}-{service_name}
                # e.g., "dev-data", "prod-item-management", "dev-warehouse-management"
                mcp_env = f'{current_env}-{service_name}'


                # Path to PostgreSQL MCP config file
                mcp_config_path = self.get_mcp_config_path()

                # Read existing config
                try:
                    with open(mcp_config_path, 'r') as f:
                        mcp_config = json.load(f)
                except FileNotFoundError:
                    return jsonify({
                        'success': False,
                        'error': f'PostgreSQL MCP config file not found: {mcp_config_path}'
                    }), 404
                except json.JSONDecodeError:
                    return jsonify({
                        'success': False,
                        'error': 'Invalid JSON in PostgreSQL MCP config file'
                    }), 500

                # Ensure environments key exists
                if 'environments' not in mcp_config:
                    mcp_config['environments'] = {}

                # Check if environment exists
                env_exists = mcp_env in mcp_config['environments']

                if env_exists:
                    # Environment exists - just update credentials
                    if 'database' not in mcp_config['environments'][mcp_env]:
                        mcp_config['environments'][mcp_env]['database'] = {}

                    mcp_config['environments'][mcp_env]['database']['user'] = username
                    mcp_config['environments'][mcp_env]['database']['password'] = password

                    logger.info(f"Updated existing environment {mcp_env} with new credentials")
                else:
                    # Environment doesn't exist - create new configuration
                    # Read db_server from secret/application
                    db_host = None
                    try:
                        response = self.vault_server.vault_client.secrets.kv.v2.read_secret_version(
                            path='application',
                            mount_point='secret'
                        )
                        app_data = response['data']['data']
                        db_host = app_data.get('host.db_server')

                        if not db_host:
                            return jsonify({
                                'success': False,
                                'error': f'host.db_server not found in secret/application. Cannot create new environment {mcp_env}.'
                            }), 400
                    except Exception as e:
                        return jsonify({
                            'success': False,
                            'error': f'Failed to read secret/application: {str(e)}. Cannot create new environment {mcp_env}.'
                        }), 500

                    # Create new environment configuration
                    mcp_config['environments'][mcp_env] = {
                        'description': f'[{service_name.title()}] {current_env.title()} database environment',
                        'database': {
                            'host': db_host,
                            'port': 5432,
                            'database': role_name.replace('-', '_'),  # Convert role name to database name
                            'user': username,
                            'password': password,
                            'ssl_mode': 'prefer'
                        },
                        'max_query_limit': 1000000,
                        'default_query_limit': 200000,
                        'read_only': False
                    }

                    logger.info(f"Created new environment {mcp_env} with host {db_host}")

                # Write back to file
                try:
                    with open(mcp_config_path, 'w') as f:
                        json.dump(mcp_config, f, indent=2)
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'error': f'Failed to write to config file: {str(e)}'
                    }), 500

                # Prepare response message
                if env_exists:
                    message = f'Credentials updated in {mcp_env} environment'
                    action = 'updated'
                else:
                    message = f'New environment {mcp_env} created and credentials synced'
                    action = 'created'

                # Audit log
                logger.info(f"Synced credentials to PostgreSQL MCP config: {mcp_env} (action: {action})")

                return jsonify({
                    'success': True,
                    'message': message,
                    'environment': mcp_env,
                    'config_path': mcp_config_path,
                    'action': action,
                    'service_name': service_name
                })

            except Exception as e:
                logger.error(f"Error syncing to PostgreSQL MCP: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/environment', methods=['GET'])
        def get_environment():
            """Get current environment info."""
            return jsonify({
                'success': True,
                'environment': self.vault_server.current_env,
                'authenticated': self.vault_server._ensure_authenticated(),
                'available_environments': list(self.vault_server.environments.keys())
            })
        
        @self.app.route('/api/timeout', methods=['GET'])
        def get_timeout():
            """Get remaining time until auto-shutdown."""
            if not self.is_running:
                return jsonify({
                    'success': True,
                    'remaining_seconds': 0,
                    'timeout_seconds': self.timeout_seconds
                })
            
            elapsed = time.time() - self.last_access_time
            remaining = max(0, self.timeout_seconds - elapsed)
            
            return jsonify({
                'success': True,
                'remaining_seconds': int(remaining),
                'timeout_seconds': self.timeout_seconds
            })

        @self.app.route('/api/login', methods=['POST'])
        def login():
            """Login to Vault environment from Web UI."""
            try:
                data = request.get_json()
                environment = data.get('environment', 'dev')
                
                # Call synchronous login method with from_web_ui=True
                # This enables GUI-based MFA prompts on Windows/macOS
                result_json = self.vault_server.login_sync(environment, from_web_ui=True)
                result = json.loads(result_json)
                
                return jsonify(result)
                
            except Exception as e:
                logger.error(f"Error logging in: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
    
    def _get_html_template(self):
        """Return the HTML template for the UI."""
        template_path = os.path.join(
            os.path.dirname(__file__),
            'templates',
            'vault_ui.html'
        )
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error loading HTML template: {e}")
            return "<h1>Error loading UI template</h1>"
    
    def _check_timeout(self):
        """Background thread to check for timeout and shutdown server if needed."""
        while not self._shutdown_event.is_set():
            # Wait for check interval or shutdown event
            if self._shutdown_event.wait(timeout=self.check_interval_seconds):
                # Shutdown event was set, exit the loop
                break
            
            # Check if timeout has been reached
            if self.is_running and self.server:
                elapsed = time.time() - self.last_access_time
                if elapsed > self.timeout_seconds:
                    logger.info(f"Web UI timeout reached ({elapsed:.0f}s > {self.timeout_seconds}s), shutting down...")
                    self.stop()
                    break
    
    def stop(self):
        """Stop the Web UI server gracefully."""
        if not self.is_running:
            return
        
        logger.info("Stopping Web UI server...")
        
        # Signal timeout check thread to stop
        self._shutdown_event.set()
        
        # Shutdown the server
        if self.server:
            try:
                self.server.shutdown()
                logger.info("Web UI server stopped gracefully")
            except Exception as e:
                logger.error(f"Error stopping server: {e}")
        
        self.is_running = False
        self.server = None
    
    def start(self):
        """Start the Web UI server in a background thread."""
        if self.is_running:
            logger.info("Web UI is already running")
            return

        # 分配端口
        if self._use_random_port or self.port is None:
            self.port = self._find_available_port()
            logger.info(f"Using random port: {self.port}")
        else:
            # 检查指定端口是否可用
            if not self._check_port_available(self.port):
                raise RuntimeError(f"Port {self.port} is already in use")

        # Reset shutdown event and access time
        self._shutdown_event.clear()
        self.last_access_time = time.time()

        def run_server():
            # Use make_server instead of app.run() to avoid Flask CLI messages
            # This completely bypasses Flask's CLI output system
            server = make_server(
                self.host,
                self.port,
                self.app,
                threaded=True
            )
            # Disable werkzeug's request logging
            server.log = lambda *args, **kwargs: None
            
            # Save server instance for timeout shutdown
            self.server = server
            server.serve_forever()
        
        # Start server thread
        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        self.is_running = True
        
        # Start timeout check thread
        self.timeout_check_thread = threading.Thread(target=self._check_timeout, daemon=True)
        self.timeout_check_thread.start()
        
        logger.info(f"✓ Web UI started at http://{self.host}:{self.port} (timeout: {self.timeout_seconds//60} minutes)")
    
    def open_browser(self):
        """Open the Web UI in the default browser."""
        url = f"http://localhost:{self.port}"
        webbrowser.open(url)
        logger.info(f"✓ Opened browser at {url}")
        return url
