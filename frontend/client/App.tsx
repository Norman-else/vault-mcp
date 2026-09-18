import { useEffect, useRef, useState } from "react";
import type { SecretEntry } from "../shared/types";
import { api, errorMessage, isAborted } from "./api";
import { ErrorBanner, Icon, IconButton, Loading, Modal } from "./components";
import { DatabasePanel } from "./DatabasePanel";
import { NewSecretModal, SecretPanel } from "./SecretPanel";
import { SearchModal } from "./SearchModal";
import { parentPath } from "./utils";
import { Tooltip } from "./Tooltip";
import { Sidebar } from "./Sidebar";
import { K8sModal } from "./K8sModal";
import { Select } from "./Select";
import { Timeout } from "./Session";

export interface Environment {
  environment: string;
  authenticated: boolean;
  available_environments: string[];
}
type Mode = "kv" | "db";

export default function Workspace({
  environment,
  onSwitch,
}: {
  environment: Environment;
  onSwitch: (next: string) => void;
}) {
  const [mount, setMount] = useState("secret");
  const [mountDraft, setMountDraft] = useState("secret");
  const [mountOpen, setMountOpen] = useState(false);
  const [k8sOpen, setK8sOpen] = useState(false);
  const [mode, setMode] = useState<Mode>("kv");
  const [directory, setDirectory] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [entries, setEntries] = useState<SecretEntry[]>([]);
  const [roles, setRoles] = useState<string[]>([]);
  const [roleFilter, setRoleFilter] = useState("");
  const [listLoading, setListLoading] = useState(true);
  const [listError, setListError] = useState("");
  const [listRefresh, setListRefresh] = useState(0);
  const [searchOpen, setSearchOpen] = useState(false);
  const [newOpen, setNewOpen] = useState(false);
  const [toast, setToast] = useState<{
    message: string;
    error: boolean;
  } | null>(null);
  const toastTimer = useRef<number | undefined>(undefined);
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    try {
      return localStorage.getItem("vault-ops-theme") === "light"
        ? "light"
        : "dark";
    } catch {
      return "dark";
    }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("vault-ops-theme", theme);
    } catch {
      /* A blocked preference store does not prevent the app from working. */
    }
  }, [theme]);
  useEffect(() => {
    if (!environment) return;
    const controller = new AbortController();
    setListLoading(true);
    setListError("");
    setEntries([]);
    setRoles([]);
    void (async () => {
      try {
        if (mode === "kv") {
          const data = await api<{ secrets: SecretEntry[] }>(
            `/api/secrets/list?path=${encodeURIComponent(directory ? `${directory}/` : "")}&mount_point=${encodeURIComponent(mount)}`,
            { signal: controller.signal },
          );
          if (!controller.signal.aborted) setEntries(data.secrets);
        } else {
          const data = await api<{ roles: string[] }>("/api/database/roles", {
            signal: controller.signal,
          });
          if (!controller.signal.aborted) setRoles(data.roles);
        }
      } catch (error) {
        if (!isAborted(error)) setListError(errorMessage(error));
      } finally {
        if (!controller.signal.aborted) setListLoading(false);
      }
    })();
    return () => controller.abort();
  }, [mode, directory, listRefresh, environment, mount]);
  useEffect(() => {
    const keyboard = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        if (!document.querySelector('[role="dialog"]')) {
          if (event.shiftKey) setK8sOpen(true);
          else setSearchOpen(true);
        }
      }
    };
    window.addEventListener("keydown", keyboard);
    return () => window.removeEventListener("keydown", keyboard);
  }, [environment]);
  useEffect(() => () => window.clearTimeout(toastTimer.current), []);
  function notify(message: string, error = false) {
    window.clearTimeout(toastTimer.current);
    setToast({ message, error });
    toastTimer.current = window.setTimeout(() => setToast(null), 4000);
  }
  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      notify("Copied to clipboard");
    } catch {
      notify(
        "Could not access the clipboard. Open this service over HTTPS and allow clipboard access.",
        true,
      );
    }
  }
  function switchMode(next: Mode) {
    if (next === mode) return;
    setMode(next);
    setSelected(null);
    setDirectory("");
    setRoleFilter("");
    setNewOpen(false);
  }
  function openDirectory(path: string) {
    setMode("kv");
    setDirectory(path.replace(/\/$/, ""));
    setSelected(null);
  }
  function openSecret(path: string) {
    setMode("kv");
    setDirectory(parentPath(path));
    setSelected(path);
  }
  function selectSearch(type: "secret" | "role", path: string) {
    setSearchOpen(false);
    if (type === "secret") openSecret(path);
    else {
      setMode("db");
      setSelected(path);
      setDirectory("");
      setRoleFilter("");
    }
  }
  const pathParts = (selected || directory).split("/").filter(Boolean);
  const filteredRoles = roles.filter((role) =>
    role.toLowerCase().includes(roleFilter.toLowerCase()),
  );
  return (
    <div className="app-shell">
      <Sidebar>
        <div className="sidebar-header">
          <Icon name="lock" />
          <span>Vault Manager</span>
        </div>
        <div className="sidebar-content">
          <button
            className="button primary new-secret-button"
            onClick={() => setNewOpen(true)}
            disabled={!environment}
          >
            <Icon name="plus" />
            New Secret
          </button>
          <nav className="mode-selector" aria-label="Secret engines">
            <button
              className={`nav-item ${mode === "kv" ? "active" : ""}`}
              onClick={() => switchMode("kv")}
              aria-current={mode === "kv" ? "page" : undefined}
            >
              <Icon name="lock" />
              KV Secrets
            </button>
            <button
              className={`nav-item ${mode === "db" ? "active" : ""}`}
              onClick={() => switchMode("db")}
              aria-current={mode === "db" ? "page" : undefined}
            >
              <Icon name="database" />
              Database Credentials
            </button>
          </nav>
          <div className="explorer-heading">
            <h2>{mode === "kv" ? "Secrets Explorer" : "Database Roles"}</h2>
            <IconButton
              icon="refresh"
              label={
                mode === "kv"
                  ? "Refresh secrets list"
                  : "Refresh database roles"
              }
              onClick={() => setListRefresh((value) => value + 1)}
              disabled={listLoading || !environment}
            />
          </div>
          {mode === "kv" && directory && (
            <>
              <button
                className="nav-item parent-directory"
                onClick={() => openDirectory(parentPath(directory))}
              >
                <Icon name="arrow" />
                Parent folder
              </button>
              <Tooltip content={directory}>
                <div className="directory-label" tabIndex={0}>
                  {directory}/
                </div>
              </Tooltip>
            </>
          )}
          {mode === "db" && (
            <div className="role-filter">
              <Icon name="search" />
              <input
                aria-label="Filter database roles"
                placeholder="Filter roles…"
                value={roleFilter}
                onChange={(event) => setRoleFilter(event.target.value)}
              />
            </div>
          )}
          {environment &&
            (listLoading ? (
              <Loading text="Loading…" />
            ) : listError ? (
              <ErrorBanner message={listError}>
                <button
                  className="text-button"
                  onClick={() => setListRefresh((value) => value + 1)}
                >
                  Try again
                </button>
              </ErrorBanner>
            ) : mode === "kv" ? (
              <div className="explorer-list" aria-label="Secrets">
                {[...entries]
                  .sort((a, b) =>
                    a.type === b.type
                      ? a.name.localeCompare(b.name)
                      : a.type === "folder"
                        ? -1
                        : 1,
                  )
                  .map((entry) => (
                    <Tooltip
                      content={entry.path}
                      key={`${entry.type}:${entry.path}`}
                    >
                      <button
                        className={`nav-item explorer-item ${selected === entry.path && entry.type === "secret" ? "selected" : ""}`}
                        onClick={() =>
                          entry.type === "folder"
                            ? openDirectory(entry.path)
                            : openSecret(entry.path)
                        }
                      >
                        <Icon
                          name={entry.type === "folder" ? "folder" : "lock"}
                        />
                        <span>{entry.name.replace(/\/$/, "")}</span>
                        {entry.type === "folder" && <Icon name="chevron" />}
                      </button>
                    </Tooltip>
                  ))}
                {!entries.length && (
                  <p className="sidebar-empty">No secrets in this folder.</p>
                )}
              </div>
            ) : (
              <div className="explorer-list" aria-label="Database roles">
                {filteredRoles.map((role) => (
                  <Tooltip content={role} key={role}>
                    <button
                      className={`nav-item explorer-item ${selected === role ? "selected" : ""}`}
                      onClick={() => setSelected(role)}
                    >
                      <Icon name="database" />
                      <span>{role}</span>
                    </button>
                  </Tooltip>
                ))}
                {!filteredRoles.length && (
                  <p className="sidebar-empty">
                    {roleFilter
                      ? "No matching database roles."
                      : "No database roles available."}
                  </p>
                )}
              </div>
            ))}
        </div>
        <div className="sidebar-footer">
          <button
            className="nav-item theme-toggle"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          >
            <Icon name={theme === "dark" ? "sun" : "moon"} />
            <span>{theme === "dark" ? "Light Mode" : "Dark Mode"}</span>
          </button>
          {mode === "kv" ? (
            <Tooltip content="Configure KV mount">
              <button
                className="sidebar-caption mount-settings"
                aria-label="Configure KV mount"
                onClick={() => {
                  setMountDraft(mount);
                  setMountOpen(true);
                }}
              >
                {mount} engine
              </button>
            </Tooltip>
          ) : (
            <span className="sidebar-caption">database engine</span>
          )}
        </div>
      </Sidebar>
      <div className="main">
        <header className="top-bar">
          <nav className="breadcrumbs" aria-label="Breadcrumb">
            <button
              onClick={() =>
                mode === "kv" ? openDirectory("") : setSelected(null)
              }
            >
              {mode === "kv" ? "KV Secrets" : "Database Credentials"}
            </button>
            {mode === "kv"
              ? pathParts.map((part, index) => (
                  <span className="breadcrumb-part" key={`${index}:${part}`}>
                    <Icon name="chevron" />
                    {index === pathParts.length - 1 ? (
                      <span aria-current="page">{part}</span>
                    ) : (
                      <button
                        onClick={() =>
                          openDirectory(pathParts.slice(0, index + 1).join("/"))
                        }
                      >
                        {part}
                      </button>
                    )}
                  </span>
                ))
              : selected && (
                  <span className="breadcrumb-part">
                    <Icon name="chevron" />
                    <span aria-current="page">{selected}</span>
                  </span>
                )}
          </nav>
          <div className="top-actions">
            <Tooltip content="Restart Deployment (Ctrl+Shift+K)">
              <button
                className="deployment-trigger"
                aria-label="Restart Deployment (Ctrl+Shift+K)"
                onClick={() => setK8sOpen(true)}
              >
                <Icon name="refresh" />
                <span>Restart Deployment</span>
              </button>
            </Tooltip>
            <button
              className="search-trigger"
              onClick={() => setSearchOpen(true)}
              disabled={!environment}
              aria-label="Search Vault"
            >
              <Icon name="search" />
              <span>Search</span>
              <kbd>Ctrl K</kbd>
            </button>
            <div className="header-environment">
              <span className="status-dot" aria-hidden="true" />
              <Select
                id="environment"
                label="Environment"
                value={environment.environment}
                options={environment.available_environments.map((value) => ({
                  value,
                  label: value.toUpperCase(),
                }))}
                onChange={onSwitch}
              />
            </div>
            <Timeout />
          </div>
        </header>
        <main className="content-area" id="main-content">
          {selected ? (
            mode === "kv" ? (
              <SecretPanel
                key={`kv:${mount}:${selected}`}
                path={selected}
                mount={mount}
                copy={(value) => void copy(value)}
                onChanged={() => {
                  setListRefresh((value) => value + 1);
                  notify("Secret saved");
                }}
                onDeleted={() => {
                  setSelected(null);
                  setListRefresh((value) => value + 1);
                  notify("Secret permanently deleted");
                }}
              />
            ) : (
              <DatabasePanel
                key={`db:${selected}`}
                role={selected}
                environment={environment.environment}
                copy={(value) => void copy(value)}
              />
            )
          ) : (
            <div className="empty-state welcome-state">
              <div className="empty-illustration">
                <Icon name={mode === "kv" ? "lock" : "database"} />
              </div>
              <h1>
                {mode === "kv" ? "Select a Secret" : "Select a Database Role"}
              </h1>
              <p>
                {mode === "kv"
                  ? "Choose a secret from the sidebar or create a new one to get started. Your secrets are securely stored in Vault."
                  : "Choose a database role from the sidebar to generate credentials managed by Vault."}
              </p>
              <div className="empty-actions">
                {mode === "kv" && (
                  <button className="button" onClick={() => setNewOpen(true)}>
                    <Icon name="plus" />
                    Create Secret
                  </button>
                )}
                <button className="button" onClick={() => setSearchOpen(true)}>
                  <Icon name="search" />
                  Search {mode === "kv" ? "Secrets" : "Roles"}
                </button>
              </div>
              {!listLoading && !listError && (
                <div className="empty-stats">
                  {mode === "kv" ? (
                    <>
                      <div>
                        <strong>
                          {
                            entries.filter((entry) => entry.type === "secret")
                              .length
                          }
                        </strong>
                        <span>Secrets in folder</span>
                      </div>
                      <div>
                        <strong>
                          {
                            entries.filter((entry) => entry.type === "folder")
                              .length
                          }
                        </strong>
                        <span>Folders</span>
                      </div>
                    </>
                  ) : (
                    <div>
                      <strong>{roles.length}</strong>
                      <span>Database roles</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </main>
      </div>
      {newOpen && environment && (
        <NewSecretModal
          directory={mode === "kv" ? directory : ""}
          mount={mount}
          onClose={() => setNewOpen(false)}
          onCreated={(path) => {
            setNewOpen(false);
            openSecret(path);
            setListRefresh((value) => value + 1);
            notify("Secret created");
          }}
        />
      )}
      {searchOpen && environment && (
        <SearchModal
          environment={environment.environment}
          mount={mount}
          onClose={() => setSearchOpen(false)}
          onSelect={selectSearch}
        />
      )}
      {mountOpen && (
        <Modal title="KV mount settings" onClose={() => setMountOpen(false)}>
          <form
            className="mount-form"
            onSubmit={(event) => {
              event.preventDefault();
              if (!mountDraft.trim()) return;
              if (mountDraft.trim() !== mount) {
                setSelected(null);
                setDirectory("");
                setMount(mountDraft.trim());
                setNewOpen(false);
                setSearchOpen(false);
              }
              setMountOpen(false);
            }}
          >
            <p className="muted">
              The default KV secrets engine is secret. Change this only when
              using another mount.
            </p>
            <label htmlFor="kv-mount">KV mount</label>
            <input
              id="kv-mount"
              data-autofocus
              value={mountDraft}
              onChange={(event) => setMountDraft(event.target.value)}
            />
            <div className="modal-actions">
              <button
                type="button"
                className="button"
                onClick={() => setMountOpen(false)}
              >
                Cancel
              </button>
              <button className="button primary" disabled={!mountDraft.trim()}>
                Apply
              </button>
            </div>
          </form>
        </Modal>
      )}
      {k8sOpen && (
        <K8sModal
          environment={environment.environment}
          onClose={() => setK8sOpen(false)}
        />
      )}
      {toast && (
        <div
          className={`toast ${toast.error ? "toast-error" : ""}`}
          role={toast.error ? "alert" : "status"}
        >
          {!toast.error && <Icon name="check" />}
          {toast.message}
        </div>
      )}
    </div>
  );
}
