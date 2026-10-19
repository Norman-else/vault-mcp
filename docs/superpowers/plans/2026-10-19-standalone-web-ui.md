# vault-mcp Standalone Web UI (Infra Desktop stage 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Infra Desktop run vault-mcp's web UI on its own — `python -m vault_mcp.web_ui --env dev --port 9291` — logged in with AWS credentials the desktop provides, with no aws-vault call and no MFA prompt from vault-mcp.

**Architecture:** A `VAULT_MCP_AWS_CREDENTIALS=ambient` switch makes Vault's AWS IAM login and the web UI's kubectl calls use boto3's default credential chain (which reads the desktop's `AWS_CONTAINER_CREDENTIALS_FULL_URI` endpoint) instead of aws-vault, and stops touching the global kubectl context. A `main()` in `web_ui.py` starts only the Flask UI, locked to one environment, logs in, keeps the Vault token fresh, and reports health. MCP mode is unchanged.

**Tech Stack:** Python 3 (Flask, hvac, boto3), unittest; React/Vite frontend with vitest.

**Spec:** `K:\radar-desktop\docs\superpowers\specs\2026-10-19-infra-desktop-vault-design.md` (repo Norman-else/infra-desktop) — §3 vault-mcp changes, §4 wiring.

## Global Constraints

- Env var `VAULT_MCP_AWS_CREDENTIALS=ambient` enables caller-provided credentials; any other value or unset = today's behaviour.
- Command: `python -m vault_mcp.web_ui --env <dev|sat|prod> --port <n> [--host 127.0.0.1]`; `--host` defaults to `127.0.0.1` in standalone mode (never `0.0.0.0`).
- `--version` prints exactly `vault-mcp-web-ui standalone 1` and exits 0 (capability check for the desktop).
- Ready line on stdout, flushed: `VAULT_WEB_UI_READY http://127.0.0.1:<port>`.
- Busy port: exit code 2 with stderr `Port <n> is already in use`.
- Idle shutdown disabled in standalone mode (the desktop owns the lifetime).
- `GET /api/health` → `{"vault": "authenticated" | "unauthenticated" | "error", "environment": <env>, "message"?: str, "token_ttl"?: int}`; never includes secrets or credentials.
- Locked environment: `/api/environment` returns `"locked": true` and `available_environments: [<env>]`; `POST /api/login` for another env → HTTP 400.
- In ambient mode, re-login when the Vault token has ≤ 5 minutes left (checked every 60 s), and on `POST /api/login`.
- Tests: `PYTHONPATH=src .venv/Scripts/python.exe -m unittest discover -s tests` (Windows) and `npm --prefix frontend test`; built UI assets in `src/vault_mcp/static/ui` are committed after frontend changes.

## Review Focus

1. Ambient mode with no credentials available (endpoint down / not set) → login fails with a clear message, `/api/health` reports `error`, no aws-vault process is started. (Task 1 test `ambient login without credentials reports an error`.)
2. Ambient mode never changes the user's global kubectl context. (Task 1 test `ambient login does not switch kubectl context`.)
3. MCP mode (env var unset) still uses aws-vault exactly as before. (Task 1 test `default mode still uses aws-vault`.)
4. Desktop renews AWS credentials, then calls `POST /api/login` → new Vault token, same env, no 400. (Task 2 test `login for the locked env re-authenticates`.)
5. Standalone started twice on the same port → second exits 2 with the port message, first keeps serving. (Task 2 test `busy port exits with code 2`.)

---

### Task 1: Ambient AWS credentials

**Files:**
- Modify: `src/vault_mcp/server.py` (`_aws_login`), `src/vault_mcp/web_ui.py` (`_kubectl`, `_kubectl_aws_creds`)
- Test: `tests/test_ambient_credentials.py` (stub `hvac`/`boto3`/`mcp` like `tests/test_awsvault_web_ui_login.py`)

**Interfaces:**
- Produces (`server.py`):
  - `def ambient_credentials_enabled() -> bool` — `os.getenv("VAULT_MCP_AWS_CREDENTIALS") == "ambient"`.
  - `VaultMCPServer._ambient_aws_credentials(self, region: str) -> tuple[str, str, Optional[str]]` — `boto3.Session(region_name=region).get_credentials()`; raises `ValueError("No AWS credentials available from the environment (VAULT_MCP_AWS_CREDENTIALS=ambient)")` when `None`; returns frozen `(access_key, secret_key, token)`.
  - `VaultMCPServer.vault_token_expires_at: Optional[float]` — set from the login response `auth.lease_duration` (epoch seconds; `None` when lease is 0/missing).

- [ ] **Step 1: Write failing tests**:
  - `ambient login uses boto3 credentials and not aws-vault` — env var set, `boto3.Session().get_credentials().get_frozen_credentials()` returns `('AK','SK','TOK')`; `iam_login` called with those; `_get_aws_credentials_via_awsvault` not called.
  - `ambient login does not switch kubectl context` — `_switch_k8s_context` not called.
  - `ambient login without credentials reports an error` — `get_credentials()` returns `None` → `login_sync('dev')` JSON has `success: false` and message containing `No AWS credentials available`.
  - `default mode still uses aws-vault` — env var unset → `_get_aws_credentials_via_awsvault` called once.
  - `token expiry is recorded` — `iam_login` returns `auth.lease_duration = 3600` → `vault_token_expires_at` within 5 s of `time.time() + 3600`.
  - `kubectl in ambient mode inherits credentials` — with Flask test client and patched `subprocess.run`, `GET /api/k8s/deployments` runs kubectl with an env that has no `AWS_PROFILE`, keeps `AWS_CONTAINER_CREDENTIALS_FULL_URI` from `os.environ`, and `_get_aws_credentials_via_awsvault` is not called.
- [ ] **Step 2: Run** `PYTHONPATH=src .venv/Scripts/python.exe -m unittest tests.test_ambient_credentials -v` — expect FAIL.
- [ ] **Step 3: Implement** the helpers; in `_aws_login`, when ambient: skip `_switch_k8s_context` and the aws-vault/env-var block, use `_ambient_aws_credentials(aws_region)`; after login set `vault_token_expires_at`. In `web_ui._kubectl`, when ambient: don't set `AWS_PROFILE` and don't merge `_kubectl_aws_creds`.
- [ ] **Step 4: Run** the full Python suite — expect all pass (56 + 6).
- [ ] **Step 5: Commit** `feat: use caller-provided AWS credentials when VAULT_MCP_AWS_CREDENTIALS=ambient`.

### Task 2: Standalone entry point, health, locked environment, token refresh

**Files:**
- Modify: `src/vault_mcp/web_ui.py` (constructor options, routes, `main`)
- Test: `tests/test_standalone_web_ui.py`

**Interfaces:**
- Consumes: Task 1 (`ambient_credentials_enabled`, `vault_token_expires_at`).
- Produces:
  - `VaultWebUI.__init__(self, vault_server, host: Optional[str] = None, port: Optional[int] = None, timeout_minutes: Optional[int] = None, locked_env: Optional[str] = None)` — `None` keeps today's env-var defaults; `timeout_minutes=0` disables idle shutdown.
  - `GET /api/health` and the locked-env behaviour from Global Constraints.
  - `def main(argv: Optional[list[str]] = None) -> int` in `web_ui.py`, plus `if __name__ == "__main__": sys.exit(main())`.
  - `VaultWebUI.refresh_login_if_needed(self) -> None` — ambient mode only: `login_sync(locked_env)` when `vault_token_expires_at` is within 300 s; `main` calls it every 60 s from a daemon thread.

- [ ] **Step 1: Write failing tests** (Flask test client; server object stubbed with `SimpleNamespace` like `test_k8s_restart.py`):
  - `health reports authenticated` / `health reports unauthenticated` — via `vault_server.is_authenticated()`; body has `environment` and, when known, integer `token_ttl`; no key named like `token`/`secret` besides `token_ttl`.
  - `locked environment is reported` — `/api/environment` → `locked: true`, `available_environments == ['dev']`.
  - `login for another env is rejected when locked` → 400.
  - `login for the locked env re-authenticates` → calls `login_sync('dev', from_web_ui=True)`, 200.
  - `refresh logs in again near token expiry` — ambient on, `vault_token_expires_at = time.time() + 120` → `login_sync` called; `+ 3600` → not called.
  - `version flag prints the capability line` — `main(['--version'])` returns 0, stdout `vault-mcp-web-ui standalone 1`.
  - `busy port exits with code 2` — bind a socket on a free port, `main(['--env','dev','--port',str(p)])` returns 2, stderr contains `Port <p> is already in use`.
- [ ] **Step 2: Run** `PYTHONPATH=src .venv/Scripts/python.exe -m unittest tests.test_standalone_web_ui -v` — expect FAIL.
- [ ] **Step 3: Implement**; `main` builds `VaultMCPServer()`, `VaultWebUI(server, host=args.host, port=args.port, timeout_minutes=0, locked_env=args.env)`, starts it, prints the ready line, runs `login_sync(args.env, from_web_ui=True)` (logs result to stderr, never exits on login failure — health shows it), starts the refresh thread, then blocks until interrupted.
- [ ] **Step 4: Run** the full Python suite — expect all pass.
- [ ] **Step 5: Commit** `feat: standalone web UI for Infra Desktop`.

### Task 3: Frontend hides the environment switch when locked

**Files:**
- Modify: `frontend/shared` (Environment type gains `locked?: boolean`), `frontend/client/Session.tsx`, `frontend/client/App.tsx`, built assets in `src/vault_mcp/static/ui`
- Test: `frontend/tests/ui.test.tsx`

- [ ] **Step 1: Write failing tests**: `hides the environment selector when the server is locked` (login page and signed-in header both render no environment select/switch when `locked: true`, and show the env name as text); `keeps the selector when not locked`.
- [ ] **Step 2: Run** `npm --prefix frontend test` — expect FAIL.
- [ ] **Step 3: Implement** the conditional rendering.
- [ ] **Step 4: Run** `npm --prefix frontend test` — expect all pass; then `npm --prefix frontend run build`; Python suite still green (`test_frontend_assets` checks the built assets).
- [ ] **Step 5: Commit** `feat(ui): lock the environment in standalone mode` (sources + rebuilt `static/ui`).

### Task 4: Docs, real-environment check, push

- [ ] **Step 1:** README: "Standalone web UI (Infra Desktop)" section — command, flags, `VAULT_MCP_AWS_CREDENTIALS=ambient`, ready line, `/api/health`.
- [ ] **Step 2: Real check (read-only)** against DEV with the user's cached 8h session: in a clean env (no `PYTHONPATH`), with the `VAULT_*`/`AWS_REGION_*`/`K8S_CONTEXT_*` values from the `vault` entry of `~/.claude.json`, run `aws-vault exec dev --duration=8h -- env VAULT_MCP_AWS_CREDENTIALS=ambient .venv/Scripts/python.exe -m vault_mcp.web_ui --env dev --port 9391`; expect the ready line, then `GET http://127.0.0.1:9391/api/health` → `"vault": "authenticated"` and no aws-vault MFA prompt; `kubectl config current-context` unchanged before/after. Stop the process by its PID.
- [ ] **Step 3:** Push vault-mcp `main`.
