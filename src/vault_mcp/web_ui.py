"""Vault Web UI Server - Interactive web interface for managing Vault secrets."""

import os
import json
import logging
import threading
import webbrowser
from datetime import datetime
from typing import Optional
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

logger = logging.getLogger(__name__)


class VaultWebUI:
    """Web UI server for Vault secret management."""
    
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
        self.port = int(os.getenv('WEB_UI_PORT', '8765'))
        self.host = os.getenv('WEB_UI_HOST', '0.0.0.0')
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup Flask routes."""
        
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
        
        @self.app.route('/api/environment', methods=['GET'])
        def get_environment():
            """Get current environment info."""
            return jsonify({
                'success': True,
                'environment': self.vault_server.current_env,
                'authenticated': self.vault_server._ensure_authenticated(),
                'available_environments': list(self.vault_server.environments.keys())
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
    
    def start(self):
        """Start the Web UI server in a background thread."""
        if self.is_running:
            logger.info("Web UI is already running")
            return
        
        def run_server():
            self.app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False
            )
        
        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        self.is_running = True
        
        logger.info(f"✓ Web UI started at http://{self.host}:{self.port}")
    
    def open_browser(self):
        """Open the Web UI in the default browser."""
        url = f"http://localhost:{self.port}"
        webbrowser.open(url)
        logger.info(f"✓ Opened browser at {url}")
        return url
