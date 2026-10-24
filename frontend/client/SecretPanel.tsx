import { useEffect, useRef, useState, type FormEvent } from "react";
import type { SecretData, SecretResult, VersionInfo } from "../shared/types";
import { CodeEditor } from "./CodeEditor";
import { Select } from "./Select";
import { api, errorMessage, isAborted, post } from "./api";
import {
  ErrorBanner,
  Icon,
  IconButton,
  Loading,
  MaskedValue,
  Modal,
} from "./components";
import {
  diffSecret,
  displayValue,
  formatTime,
  parseSecretJson,
  parseTypedValue,
  valueType,
  type SecretChange,
  type ValueType,
} from "./utils";

type EditMode =
  | { kind: "json" }
  | { kind: "key"; key?: string }
  | { kind: "delete-key"; key: string }
  | { kind: "delete-secret" }
  | { kind: "restore"; data: SecretData; version: number };
type VersionsResponse = { current_version: number; versions: VersionInfo[] };

export function SecretDiff({
  changes,
  copy,
}: {
  changes: SecretChange[];
  copy: (value: string) => void;
}) {
  if (!changes.length) return <p className="muted">No differences.</p>;
  return (
    <div className="secret-diff" aria-label="Changes">
      {changes.map((change) => (
        <div className={`diff-row ${change.kind}`} key={change.key}>
          <span className="diff-kind">{change.kind}</span>
          <code className="key-name">{change.key}</code>
          <div className="diff-values">
            {change.kind !== "added" && (
              <MaskedValue
                value={displayValue(change.before ?? null)}
                label={`old value for ${change.key}`}
                copy={copy}
              />
            )}
            {change.kind !== "removed" && (
              <MaskedValue
                value={displayValue(change.after ?? null)}
                label={`new value for ${change.key}`}
                copy={copy}
              />
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function JsonEditor({
  value,
  onChange,
  error,
  onError,
  label = "Secret JSON",
}: {
  value: string;
  onChange: (value: string) => void;
  error: string;
  onError: (value: string) => void;
  label?: string;
}) {
  return (
    <div className="field">
      <div className="field-heading">
        <label htmlFor="json-editor">{label}</label>
        <button
          type="button"
          className="text-button"
          onClick={() => {
            try {
              onChange(JSON.stringify(parseSecretJson(value), null, 2));
              onError("");
            } catch (error) {
              onError(errorMessage(error));
            }
          }}
        >
          <Icon name="code" />
          Format JSON
        </button>
      </div>
      <CodeEditor
        value={value}
        onChange={(next) => {
          onChange(next);
          onError("");
        }}
        label={label}
        invalid={!!error}
      />
      <small id="json-help">
        Strings, numbers, booleans, null, arrays, and nested objects are
        preserved.
      </small>
    </div>
  );
}

export function NewSecretModal({
  directory,
  mount,
  onClose,
  onCreated,
}: {
  directory: string;
  mount: string;
  onClose: () => void;
  onCreated: (path: string) => void;
}) {
  const [path, setPath] = useState(directory ? `${directory}/` : "");
  const [json, setJson] = useState("{}");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const controller = useRef(new AbortController());
  useEffect(() => {
    const active = new AbortController();
    controller.current = active;
    return () => active.abort();
  }, []);
  async function create(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      const data = parseSecretJson(json);
      if (
        !path.trim() ||
        path !== path.trim() ||
        path.startsWith("/") ||
        path.endsWith("/") ||
        path.split("/").some((part) => !part || part === "." || part === "..")
      )
        throw new Error(
          "Enter a relative secret path without empty, leading, or trailing slashes.",
        );
      setBusy(true);
      await post(
        "/api/secrets/create",
        { path, data, mount_point: mount },
        controller.current.signal,
      );
      if (!controller.current.signal.aborted) onCreated(path);
    } catch (error) {
      if (!isAborted(error)) setError(errorMessage(error));
    } finally {
      if (!controller.current.signal.aborted) setBusy(false);
    }
  }
  return (
    <Modal title="Create Secret" onClose={onClose} wide busy={busy}>
      <form noValidate onSubmit={(event) => void create(event)}>
        <div className="field">
          <label htmlFor="secret-path">Secret path</label>
          <div className="path-input">
            <span>{mount}/</span>
            <input
              id="secret-path"
              data-autofocus
              value={path}
              onChange={(event) => setPath(event.target.value)}
              placeholder="team/application"
              required
              autoComplete="off"
              spellCheck={false}
            />
          </div>
        </div>
        <JsonEditor
          label="Initial JSON data"
          value={json}
          onChange={setJson}
          error={error}
          onError={setError}
        />
        <p className="muted">
          Use <code>{"{}"}</code> to create an empty secret, then add keys.
        </p>
        {error && <ErrorBanner message={error} />}
        <div className="modal-actions">
          <button
            type="button"
            className="button"
            onClick={onClose}
            disabled={busy}
          >
            Cancel
          </button>
          <button className="button primary" disabled={busy}>
            {busy ? "Creating…" : "Create Secret"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function EditModal({
  mode,
  secret,
  mount,
  copy,
  onClose,
  onSaved,
  onDeleted,
}: {
  mode: EditMode;
  secret: SecretResult;
  mount: string;
  copy: (value: string) => void;
  onClose: () => void;
  onSaved: () => void;
  onDeleted: () => void;
}) {
  const keyMode = mode.kind === "key";
  const originalKey = keyMode ? mode.key : undefined;
  const originalValue =
    originalKey !== undefined ? secret.data[originalKey] : "";
  const [key, setKey] = useState(originalKey ?? "");
  const [value, setValue] = useState(displayValue(originalValue));
  const [type, setType] = useState<ValueType>(valueType(originalValue));
  const [json, setJson] = useState(JSON.stringify(secret.data, null, 2));
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  // Saves show the key-level diff first; a second submit writes it.
  const [review, setReview] = useState<SecretChange[] | null>(
    mode.kind === "restore" ? diffSecret(secret.data, mode.data) : null,
  );
  const controller = useRef(new AbortController());
  useEffect(() => {
    const active = new AbortController();
    controller.current = active;
    return () => active.abort();
  }, []);
  const title =
    mode.kind === "restore"
      ? `Restore v${mode.version}`
      : mode.kind === "json"
        ? "Edit JSON"
        : mode.kind === "delete-secret"
          ? "Delete Entire Secret"
          : mode.kind === "delete-key"
            ? "Delete Key"
            : originalKey !== undefined
              ? "Edit Key"
              : "Add Key";
  async function save(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      let endpoint: string;
      let body: object;
      let next: SecretData | undefined;
      if (mode.kind === "json" || mode.kind === "restore") {
        endpoint = "update-json";
        next = mode.kind === "json" ? parseSecretJson(json) : mode.data;
        body = { path: secret.path, data: next };
      } else if (mode.kind === "key") {
        if (!key.trim()) throw new Error("Enter a key name.");
        if (originalKey === undefined && Object.hasOwn(secret.data, key))
          throw new Error(
            "This key already exists. Edit the existing key instead.",
          );
        endpoint = "update";
        const parsed = parseTypedValue(value, type);
        next = { ...secret.data, [key]: parsed };
        body = { path: secret.path, key, value: parsed };
      } else if (mode.kind === "delete-key") {
        endpoint = "delete-key";
        body = { path: secret.path, key: mode.key };
      } else {
        if (confirmation !== secret.path)
          throw new Error("Type the exact secret path to confirm deletion.");
        endpoint = "delete";
        body = { path: secret.path, confirmation };
      }
      if (next && !review) {
        const changes = diffSecret(secret.data, next);
        if (!changes.length) throw new Error("No changes to save.");
        setReview(changes);
        return;
      }
      setBusy(true);
      await post(
        `/api/secrets/${endpoint}`,
        { ...body, mount_point: mount },
        controller.current.signal,
      );
      if (!controller.current.signal.aborted) {
        if (mode.kind === "delete-secret") onDeleted();
        else onSaved();
      }
    } catch (error) {
      if (!isAborted(error)) {
        setError(errorMessage(error));
      }
    } finally {
      if (!controller.current.signal.aborted) setBusy(false);
    }
  }
  const destructive = mode.kind.startsWith("delete");
  return (
    <Modal
      title={title}
      onClose={onClose}
      editor={mode.kind === "json"}
      busy={busy}
    >
      <form noValidate onSubmit={(event) => void save(event)}>
        <div className="edit-modal-body">
          <p className="modal-context">
            <Icon name="lock" />
            <code>{secret.path}</code>
            <span className="badge">
              {secret.metadata.version
                ? `v${secret.metadata.version}`
                : "KV v1"}
            </span>
          </p>
          {review && (
            <div className="field">
              <label>
                {mode.kind === "restore"
                  ? `Latest → v${mode.version}`
                  : "Review changes"}
              </label>
              <SecretDiff changes={review} copy={copy} />
              {review.length > 0 && (
                <small>
                  Saving creates a new version. Older versions stay in history.
                </small>
              )}
            </div>
          )}
          {!review && mode.kind === "json" && (
            <JsonEditor
              value={json}
              onChange={setJson}
              error={error}
              onError={setError}
            />
          )}
          {!review && mode.kind === "key" && (
            <>
              <div className="field">
                <label htmlFor="key-name">Key name</label>
                <input
                  id="key-name"
                  data-autofocus
                  value={key}
                  onChange={(event) => setKey(event.target.value)}
                  readOnly={originalKey !== undefined}
                  required
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
              <div className="field">
                <label htmlFor="value-type">Value type</label>
                <Select
                  id="value-type"
                  value={type}
                  options={[
                    "string",
                    "number",
                    "boolean",
                    "null",
                    "object",
                    "array",
                  ].map((value) => ({ value, label: value }))}
                  onChange={(nextValue) => {
                    const next = nextValue as ValueType;
                    setType(next);
                    if (
                      next === "boolean" &&
                      value !== "true" &&
                      value !== "false"
                    )
                      setValue("false");
                  }}
                />
              </div>
              <div className="field">
                <label htmlFor="key-value">Value</label>
                {type === "boolean" ? (
                  <Select
                    id="key-value"
                    value={value}
                    onChange={setValue}
                    options={["true", "false"].map((value) => ({
                      value,
                      label: value,
                    }))}
                  />
                ) : type === "null" ? (
                  <input id="key-value" value="null" readOnly />
                ) : (
                  <textarea
                    id="key-value"
                    value={value}
                    onChange={(event) => setValue(event.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                    rows={5}
                    className="mono"
                  />
                )}
              </div>
            </>
          )}
          {mode.kind === "delete-key" && (
            <p className="explanation">
              Remove <code>{mode.key}</code> from the latest secret? This
              creates a new version. Existing versions remain in Vault history.
            </p>
          )}
          {mode.kind === "delete-secret" && (
            <>
              <p className="explanation">
                Permanently delete this secret and{" "}
                <strong>all of its versions</strong>. This cannot be undone.
              </p>
              <div className="field">
                <label htmlFor="delete-confirmation">
                  Type {secret.path} to confirm
                </label>
                <input
                  id="delete-confirmation"
                  data-autofocus
                  value={confirmation}
                  onChange={(event) => setConfirmation(event.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
            </>
          )}
          {error && <ErrorBanner message={error} />}
        </div>
        <div className="modal-actions">
          {review && mode.kind !== "restore" ? (
            <button
              type="button"
              className="button"
              onClick={() => setReview(null)}
              disabled={busy}
            >
              Back to Edit
            </button>
          ) : (
            <button
              type="button"
              className="button"
              onClick={onClose}
              disabled={busy}
            >
              Cancel
            </button>
          )}
          <button
            className={`button ${destructive ? "danger-fill" : "primary"}`}
            disabled={
              busy ||
              (mode.kind === "delete-secret" && confirmation !== secret.path) ||
              review?.length === 0
            }
          >
            {busy
              ? "Saving…"
              : destructive || mode.kind === "restore"
                ? title
                : review
                  ? "Confirm Save"
                  : "Save Changes"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

type EnvironmentSecret = {
  environment: string;
  status: "ok" | "missing" | "signed_out" | "not_running" | "error";
  keys?: Record<string, string>;
  values?: SecretData;
  error?: string;
};

type CompareCell = "same" | "different" | "missing" | "only" | "absent";
const compareLabel: Record<CompareCell, string> = {
  same: "Same",
  different: "Different",
  missing: "Missing",
  only: "Only here",
  absent: "",
};

function CompareModal({
  path,
  mount,
  copy,
  onClose,
}: {
  path: string;
  mount: string;
  copy: (value: string) => void;
  onClose: () => void;
}) {
  const [result, setResult] = useState<{
    current: string;
    environments: EnvironmentSecret[];
  } | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    api<{ current: string; environments: EnvironmentSecret[] }>(
      `/api/secrets/compare?path=${encodeURIComponent(path)}&mount_point=${encodeURIComponent(mount)}`,
      { signal: controller.signal },
    )
      .then((data) => {
        if (!controller.signal.aborted) setResult(data);
      })
      .catch((error) => {
        if (!isAborted(error)) setError(errorMessage(error));
      });
    return () => controller.abort();
  }, [path, mount]);
  const [differencesOnly, setDifferencesOnly] = useState(true);
  const readable =
    result?.environments.filter((env) => env.status === "ok") ?? [];
  // Everything is compared with the current environment (or the first readable one).
  const base =
    readable.find((env) => env.environment === result?.current) ?? readable[0];
  const others = readable.filter((env) => env !== base);
  const unavailable =
    result?.environments.filter((env) => env.status !== "ok") ?? [];
  const keys = [
    ...new Set(readable.flatMap((env) => Object.keys(env.keys ?? {}))),
  ].sort();
  const compare = (env: EnvironmentSecret, key: string): CompareCell => {
    const own = env.keys?.[key];
    const baseline = base?.keys?.[key];
    if (!own) return baseline ? "missing" : "absent";
    if (!baseline) return "only";
    return own === baseline ? "same" : "different";
  };
  const differs = (key: string) =>
    !base?.keys?.[key] || others.some((env) => compare(env, key) !== "same");
  const rows = differencesOnly ? keys.filter(differs) : keys;
  const name = (env: EnvironmentSecret) => env.environment.toUpperCase();
  const value = (env: EnvironmentSecret, key: string) =>
    env.keys?.[key] && env.values && Object.hasOwn(env.values, key) ? (
      <MaskedValue
        value={displayValue(env.values[key])}
        label={`${key} in ${name(env)}`}
        copy={copy}
      />
    ) : null;
  const statusText = {
    missing: "No secret",
    signed_out: "Not signed in",
    not_running: "Not running",
    error: "Unreadable",
    ok: "",
  };
  return (
    <Modal title="Compare Environments" onClose={onClose} editor>
      <div className="compare-body">
        <p className="modal-context">
          <Icon name="lock" />
          <code>
            {mount}/{path}
          </code>
        </p>
        {error && <ErrorBanner message={error} />}
        {!result && !error && <Loading text="Reading environments…" />}
        {result && (
          <>
            {unavailable.length > 0 && (
              <p className="compare-unavailable">
                Not compared:{" "}
                {unavailable.map((env) => (
                  <span
                    key={env.environment}
                    className="badge"
                    title={env.error}
                  >
                    {name(env)} · {statusText[env.status]}
                  </span>
                ))}
              </p>
            )}
            {unavailable
              .filter((env) => env.status === "error")
              .map((env) => (
                <ErrorBanner
                  key={env.environment}
                  message={`${name(env)} could not be read: ${env.error || "unknown error"}`}
                />
              ))}
            {base && others.length === 0 && (
              <p className="notice">
                Only {name(base)} could be read — start or sign in to another
                environment to compare.
              </p>
            )}
            {base && others.length > 0 && (
              <>
                <div className="compare-summary">
                  {others.map((env) => {
                    const count = (kind: CompareCell) =>
                      keys.filter((key) => compare(env, key) === kind).length;
                    return (
                      <div key={env.environment}>
                        <strong>
                          {name(env)} vs {name(base)}
                        </strong>
                        {(
                          [
                            ["different", "different"],
                            ["missing", `missing in ${name(env)}`],
                            ["only", `only in ${name(env)}`],
                            ["same", "same"],
                          ] as const
                        )
                          .filter(([kind]) => count(kind) > 0)
                          .map(([kind, text]) => (
                            <span key={kind} className={`compare-pill ${kind}`}>
                              {count(kind)} {text}
                            </span>
                          ))}
                      </div>
                    );
                  })}
                </div>
                <label className="compare-filter">
                  <input
                    type="checkbox"
                    checked={differencesOnly}
                    onChange={(event) =>
                      setDifferencesOnly(event.target.checked)
                    }
                  />
                  Differences only ({keys.filter(differs).length} of{" "}
                  {keys.length} keys)
                </label>
                <div className="secret-table-wrap">
                  <table className="secret-table compare-table">
                    <thead>
                      <tr>
                        <th>KEY</th>
                        <th>{name(base)} · baseline</th>
                        {others.map((env) => (
                          <th key={env.environment}>{name(env)}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((key) => (
                        <tr key={key}>
                          <td>
                            <code className="key-name">{key}</code>
                          </td>
                          <td>
                            <div className="compare-value">
                              {!base.keys?.[key] && (
                                <span className="compare-pill missing">
                                  Missing
                                </span>
                              )}
                              {value(base, key)}
                            </div>
                          </td>
                          {others.map((env) => {
                            const cell = compare(env, key);
                            return (
                              <td key={env.environment}>
                                <div className="compare-value">
                                  {cell !== "absent" && (
                                    <span className={`compare-pill ${cell}`}>
                                      {compareLabel[cell]}
                                    </span>
                                  )}
                                  {value(env, key)}
                                </div>
                              </td>
                            );
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {!rows.length && (
                  <p className="muted">
                    All {keys.length} keys match {name(base)}.
                  </p>
                )}
                <p className="muted">
                  Values are hidden until you click the eye icon. Different
                  values between environments are often expected (each
                  environment has its own credentials).
                </p>
              </>
            )}
          </>
        )}
      </div>
      <div className="modal-actions">
        <button className="button" onClick={onClose}>
          Close
        </button>
      </div>
    </Modal>
  );
}

export function SecretPanel({
  path,
  mount,
  canCompare = false,
  copy,
  onChanged,
  onDeleted,
}: {
  path: string;
  mount: string;
  canCompare?: boolean;
  copy: (value: string) => void;
  onChanged: () => void;
  onDeleted: () => void;
}) {
  const [secret, setSecret] = useState<SecretResult | null>(null);
  const [versions, setVersions] = useState<VersionInfo[]>([]);
  const [currentVersion, setCurrentVersion] = useState(0);
  const [selectedVersion, setSelectedVersion] = useState<number | undefined>();
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [mode, setMode] = useState<EditMode | null>(null);
  const [filter, setFilter] = useState("");
  const [showJson, setShowJson] = useState(false);
  const [latest, setLatest] = useState<SecretResult | null>(null);
  const [comparing, setComparing] = useState(false);
  const [comparingEnvironments, setComparingEnvironments] = useState(false);
  const historical =
    selectedVersion !== undefined && selectedVersion !== currentVersion;
  useEffect(() => {
    setLatest(null);
    setComparing(false);
    if (!historical) return;
    const controller = new AbortController();
    api<SecretResult>(
      `/api/secrets/get?path=${encodeURIComponent(path)}&mount_point=${encodeURIComponent(mount)}`,
      { signal: controller.signal },
    )
      .then((data) => {
        if (!controller.signal.aborted) setLatest(data);
      })
      .catch((error) => {
        if (!isAborted(error)) setError(errorMessage(error));
      });
    return () => controller.abort();
  }, [path, mount, historical, refresh]);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setSecret(null);
    setShowJson(false);
    void (async () => {
      try {
        const history = await api<VersionsResponse>(
          `/api/secrets/versions?path=${encodeURIComponent(path)}&mount_point=${encodeURIComponent(mount)}`,
          { signal: controller.signal },
        ).catch((error: unknown) => {
          if (isAborted(error)) throw error;
          return { current_version: 0, versions: [] };
        });
        if (controller.signal.aborted) return;
        setVersions(history.versions);
        setCurrentVersion(history.current_version);
        const version = history.versions.find(
          (item) =>
            item.version === (selectedVersion ?? history.current_version),
        );
        if (!version?.destroyed && !version?.deleted_time) {
          const data = await api<SecretResult>(
            `/api/secrets/get?path=${encodeURIComponent(path)}&mount_point=${encodeURIComponent(mount)}${selectedVersion || history.current_version ? `&version=${selectedVersion ?? history.current_version}` : ""}`,
            { signal: controller.signal },
          );
          if (!controller.signal.aborted) setSecret(data);
        }
      } catch (error) {
        if (!isAborted(error)) setError(errorMessage(error));
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    })();
    return () => controller.abort();
  }, [path, mount, selectedVersion, refresh]);
  const version = versions.find(
    (item) => item.version === (selectedVersion ?? currentVersion),
  );
  const entries = Object.entries(secret?.data || {}).filter(([key]) =>
    key.toLowerCase().includes(filter.toLowerCase()),
  );
  function saved() {
    setMode(null);
    setSelectedVersion(undefined);
    setRefresh((value) => value + 1);
    onChanged();
  }
  function switchVersion(value: number | undefined) {
    setSecret(null);
    setShowJson(false);
    setLoading(true);
    setSelectedVersion(value);
  }
  return (
    <section className="detail-panel secret-detail-panel">
      <div className="page-heading">
        <div>
          <div className="eyebrow">KV SECRET</div>
          <h1>
            <Icon name="lock" />
            Secret Information
          </h1>
          <p className="secret-path">
            <span>{mount}/</span>
            {path}
          </p>
        </div>
        <div className="row-actions">
          {canCompare && (
            <button
              className="button small"
              onClick={() => setComparingEnvironments(true)}
            >
              Compare Environments
            </button>
          )}
          <IconButton
            icon="refresh"
            label="Refresh secret"
            onClick={() => setRefresh((value) => value + 1)}
            disabled={loading}
          />
        </div>
      </div>
      <div className="secret-toolbar">
        <div className="version-control">
          <Icon name="clock" />
          <label htmlFor="secret-version">Version</label>
          <Select
            id="secret-version"
            popupMinWidth={300}
            value={String(selectedVersion ?? "latest")}
            onChange={(value) =>
              switchVersion(value === "latest" ? undefined : Number(value))
            }
            disabled={loading}
            options={[
              {
                value: "latest",
                label: `Latest${currentVersion ? ` (v${currentVersion})` : ""}`,
                description: "Automatically follows the latest",
              },
              ...[...versions]
                .sort((a, b) => b.version - a.version)
                .map((item) => ({
                  value: String(item.version),
                  label: `v${item.version}`,
                  description: formatTime(item.created_time),
                  badges: [
                    ...(item.version === currentVersion ? ["Latest"] : []),
                    ...(item.destroyed
                      ? ["Destroyed"]
                      : item.deleted_time
                        ? ["Deleted"]
                        : []),
                  ],
                })),
            ]}
          />
        </div>
        <span className="muted">
          {secret ? `${Object.keys(secret.data).length} keys` : ""}
        </span>
      </div>
      {historical && (
        <div className="notice">
          Viewing a historical version.{" "}
          <button
            className="text-button"
            onClick={() => switchVersion(undefined)}
          >
            Return to latest
          </button>
          <span className="notice-actions">
            <button
              className="button small"
              onClick={() => setComparing((value) => !value)}
              disabled={!latest || !secret}
              aria-pressed={comparing}
            >
              {comparing ? "Hide Comparison" : "Compare with Latest"}
            </button>
            <button
              className="button small primary"
              onClick={() =>
                secret &&
                setMode({
                  kind: "restore",
                  data: secret.data,
                  version: selectedVersion!,
                })
              }
              disabled={!latest || !secret}
            >
              Restore This Version
            </button>
          </span>
        </div>
      )}
      {comparing && latest && secret && (
        <div className="card compare-card">
          <div className="card-heading">
            <h2>
              v{selectedVersion} → Latest (v{currentVersion})
            </h2>
          </div>
          <SecretDiff
            changes={diffSecret(secret.data, latest.data)}
            copy={copy}
          />
        </div>
      )}
      {loading ? (
        <Loading text="Loading secret…" />
      ) : error ? (
        <ErrorBanner message={error}>
          <button
            className="button"
            onClick={() => setRefresh((value) => value + 1)}
          >
            Try again
          </button>
        </ErrorBanner>
      ) : version && (version.destroyed || version.deleted_time) ? (
        <div className="empty-state compact">
          <Icon name="clock" />
          <h2>
            Version {version.version}{" "}
            {version.destroyed ? "destroyed" : "deleted"}
          </h2>
          <p>
            This version has no readable data. Select an available version from
            history.
          </p>
        </div>
      ) : (
        secret && (
          <>
            <div className="card">
              <div className="card-heading">
                <h2>Secret Data</h2>
                <div className="row-actions">
                  <button
                    className="button small"
                    onClick={() => setShowJson((value) => !value)}
                  >
                    <Icon name="code" />
                    {showJson ? "Hide JSON" : "Reveal JSON"}
                  </button>
                  <button
                    className="button small"
                    onClick={() => setMode({ kind: "json" })}
                    disabled={historical}
                  >
                    <Icon name="edit" />
                    Edit JSON
                  </button>
                  <button
                    className="button small primary"
                    onClick={() => setMode({ kind: "key" })}
                    disabled={historical}
                  >
                    <Icon name="plus" />
                    Add Key
                  </button>
                </div>
              </div>
              {showJson ? (
                <div className="json-preview">
                  <div className="json-preview-actions">
                    <IconButton
                      icon="copy"
                      label="Copy secret JSON"
                      onClick={() => copy(JSON.stringify(secret.data, null, 2))}
                    />
                  </div>
                  <pre>{JSON.stringify(secret.data, null, 2)}</pre>
                </div>
              ) : (
                <>
                  {Object.keys(secret.data).length > 0 && (
                    <div className="table-filter">
                      <Icon name="search" />
                      <input
                        aria-label="Filter keys"
                        placeholder="Filter keys…"
                        value={filter}
                        onChange={(event) => setFilter(event.target.value)}
                      />
                    </div>
                  )}
                  {entries.length ? (
                    <div className="secret-table-wrap">
                      <table className="secret-table">
                        <thead>
                          <tr>
                            <th>KEY</th>
                            <th>VALUE</th>
                            <th className="actions-column">
                              <span className="sr-only">Actions</span>
                            </th>
                          </tr>
                        </thead>
                        <tbody>
                          {entries.map(([key, value]) => (
                            <tr key={`${secret.metadata.version}:${key}`}>
                              <td>
                                <code className="key-name">{key}</code>
                                <span className="value-type">
                                  {valueType(value)}
                                </span>
                              </td>
                              <td>
                                <MaskedValue
                                  value={displayValue(value)}
                                  label={`value for ${key}`}
                                  copy={copy}
                                />
                              </td>
                              <td>
                                <div className="row-actions">
                                  <IconButton
                                    icon="edit"
                                    label={`Edit ${key}`}
                                    onClick={() =>
                                      setMode({ kind: "key", key })
                                    }
                                    disabled={historical}
                                  />
                                  <IconButton
                                    icon="trash"
                                    label={`Delete ${key}`}
                                    onClick={() =>
                                      setMode({ kind: "delete-key", key })
                                    }
                                    disabled={historical}
                                    danger
                                  />
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="empty-state compact">
                      <Icon name="key" />
                      <h3>
                        {filter ? "No matching keys" : "This secret is empty"}
                      </h3>
                      <p>
                        {filter
                          ? "Try another key name."
                          : "Add your first key to store a value."}
                      </p>
                      {!filter && (
                        <button
                          className="button primary"
                          onClick={() => setMode({ kind: "key" })}
                          disabled={historical}
                        >
                          <Icon name="plus" />
                          Add Key
                        </button>
                      )}
                    </div>
                  )}
                </>
              )}
              <div className="card-footer">
                <span>Created {formatTime(secret.metadata.created_time)}</span>
                <span>
                  {secret.metadata.version
                    ? `Version ${secret.metadata.version}`
                    : "KV v1"}
                </span>
              </div>
            </div>
            {!historical && (
              <div className="danger-zone">
                <div>
                  <h3>Delete this secret</h3>
                  <p>Permanently remove the secret and all versions.</p>
                </div>
                <button
                  className="button danger"
                  onClick={() => setMode({ kind: "delete-secret" })}
                >
                  <Icon name="trash" />
                  Delete Secret
                </button>
              </div>
            )}
          </>
        )
      )}
      {comparingEnvironments && (
        <CompareModal
          path={path}
          mount={mount}
          copy={copy}
          onClose={() => setComparingEnvironments(false)}
        />
      )}
      {mode && secret && (mode.kind !== "restore" || latest) && (
        <EditModal
          mode={mode}
          secret={mode.kind === "restore" ? latest! : secret}
          mount={mount}
          copy={copy}
          onClose={() => setMode(null)}
          onSaved={saved}
          onDeleted={onDeleted}
        />
      )}
    </section>
  );
}
