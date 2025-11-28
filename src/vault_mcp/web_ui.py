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
        self.app = Flask(__name__, static_folder=None)
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
                    response = self.vault_server.vault_client.secrets.kv.v2.read_secret_version(
                        path=path,
                        mount_point=mount_point
                    )
                    data = response['data']['data']
                    metadata = response['data']['metadata']
                    
                    return jsonify({
                        'success': True,
                        'path': path,
                        'data': data,
                        'metadata': {
                            'version': metadata.get('version'),
                            'created_time': metadata.get('created_time'),
                            'updated_time': metadata.get('updated_time')
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
        
        @self.app.route('/api/environment', methods=['GET'])
        def get_environment():
            """Get current environment info."""
            return jsonify({
                'success': True,
                'environment': self.vault_server.current_env or 'Not logged in',
                'authenticated': self.vault_server._ensure_authenticated()
            })
    
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
