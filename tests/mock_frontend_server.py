"""Serve the built frontend with in-memory APIs for safe manual browser regression.

Run: python tests/mock_frontend_server.py (http://localhost:8766).
No Vault, AWS, Kubernetes, or PostgreSQL configuration operations are performed.
"""
from pathlib import Path
import time
from flask import Flask, jsonify, request, send_from_directory

ROOT = Path(__file__).resolve().parents[1] / 'src' / 'vault_mcp' / 'static'
app = Flask(__name__, static_folder=str(ROOT), static_url_path='/static')
state = {'environment': 'dev', 'authenticated': True, 'restart': False}
secrets = {'alpha': {'username': 'mock-user', 'enabled': True},
           'team/long-application-name-for-sidebar-layout-regression/config': {'host': 'mock.example'}}


@app.get('/')
def index():
    return send_from_directory(ROOT / 'ui', 'index.html')


@app.route('/api/<path:endpoint>', methods=['GET', 'POST'])
def api(endpoint):
    body = request.get_json(silent=True) or {}
    path = request.args.get('path', body.get('path', ''))
    data = {'success': True}
    if endpoint == 'environment':
        data.update(state, available_environments=['dev', 'sat', 'prod'])
    elif endpoint == 'login':
        time.sleep(1)
        state.update(environment=body['environment'], authenticated=True)
        data.update(environment=state['environment'])
    elif endpoint == 'timeout':
        data.update(remaining_seconds=28000, timeout_seconds=28800)
    elif endpoint == 'secrets/list':
        entries = {}
        for name in secrets:
            if name.startswith(path):
                part = name[len(path):].split('/')[0]
                folder = '/' in name[len(path):]
                entries[part] = {'name': part, 'path': path + part + ('/' if folder else ''), 'type': 'folder' if folder else 'secret'}
        data['secrets'] = list(entries.values())
    elif endpoint == 'secrets/get':
        data.update(path=path, data=secrets.get(path, {}), metadata={'version': 2, 'created_time': '2026-09-18T00:00:00Z'})
    elif endpoint == 'secrets/versions':
        data.update(current_version=2, versions=[{'version': n, 'created_time': '2026-09-18T00:00:00Z', 'deleted_time': '', 'destroyed': False} for n in [2, 1]])
    elif endpoint in ['secrets/create', 'secrets/update-json']:
        secrets[path] = body['data']
    elif endpoint == 'secrets/update':
        secrets.setdefault(path, {})[body['key']] = body['value']
    elif endpoint == 'secrets/delete-key':
        secrets[path].pop(body['key'], None)
    elif endpoint == 'secrets/delete':
        secrets.pop(path, None)
    elif endpoint == 'secrets/search':
        data['results'] = [{'path': name, 'matching_keys': []} for name in secrets if request.args.get('q', '') in name]
    elif endpoint == 'database/roles':
        data['roles'] = ['readonly-role', 'long-database-service-role-for-sidebar-layout']
    elif endpoint == 'database/roles/search':
        data['results'] = [{'name': 'readonly-role'}]
    elif endpoint.startswith('database/creds/'):
        data.update(role=endpoint.split('/')[-1], username='mock-user', password='mock-password', lease_id='mock-lease', lease_duration=3600, renewable=True)
    elif endpoint == 'database/check-mcp-config':
        data.update(exists=True, path='mock-only/environments.json')
    elif endpoint == 'database/sync-to-mcp':
        data['message'] = 'Mock sync successful — no file written'
    elif endpoint == 'k8s/deployments':
        data['deployments'] = [{'namespace': 'default', 'name': 'mock-service', 'ready': 2, 'total': 2}]
    elif endpoint == 'k8s/deployments/restart':
        state['restart'] = True
    elif endpoint == 'k8s/deployments/status':
        data['status'] = {'total': 2, 'updated': 2, 'ready': 2, 'available': 2, 'complete': True, 'failed': False, 'message': '', 'pods': [{'name': 'mock-service-pod', 'phase': 'Running', 'ready': '1/1'}]}
    else:
        return jsonify(success=False, error='Unknown mock endpoint'), 404
    return jsonify(data)


if __name__ == '__main__':
    app.run(host='localhost', port=8766, debug=False)
