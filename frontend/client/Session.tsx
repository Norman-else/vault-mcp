import { useEffect, useRef, useState } from "react";
import Workspace, { type Environment } from "./App";
import { api, errorMessage, isAborted, post } from "./api";
import { ErrorBanner, Loading } from "./components";
import { Select } from "./Select";
import { Tooltip } from "./Tooltip";

export function Session() {
  const [environment, setEnvironment] = useState<Environment | null>(null);
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [epoch, setEpoch] = useState(0);
  const pending = useRef(false);
  useEffect(() => {
    try {
      document.documentElement.dataset.theme =
        localStorage.getItem("vault-ops-theme") === "light" ? "light" : "dark";
    } catch {
      document.documentElement.dataset.theme = "dark";
    }
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    api<Environment>("/api/environment", { signal: controller.signal })
      .then((result) => {
        if (!controller.signal.aborted) {
          setEnvironment(result);
          setTarget(
            result.environment || result.available_environments[0] || "",
          );
        }
      })
      .catch((error) => {
        if (!isAborted(error)) setError(errorMessage(error));
      });
    return () => controller.abort();
  }, [refresh]);
  useEffect(() => {
    const expired = () => {
      setEnvironment((current) =>
        current ? { ...current, authenticated: false } : null,
      );
      setEpoch((value) => value + 1);
      setError("Session expired. Log in again to continue.");
    };
    window.addEventListener("vault-auth-expired", expired);
    return () => window.removeEventListener("vault-auth-expired", expired);
  }, []);
  async function login(next: string) {
    if (pending.current || !next) return;
    pending.current = true;
    setTarget(next);
    setBusy(true);
    setError("");
    setEpoch((value) => value + 1);
    // Unmount secrets before the server changes environment. Aborting HTTP cannot cancel native MFA.
    setEnvironment((current) =>
      current ? { ...current, authenticated: false } : null,
    );
    let failure = "";
    try {
      await post("/api/login", { environment: next });
    } catch (error) {
      failure = errorMessage(error);
    }
    try {
      const actual = await api<Environment>("/api/environment");
      setEnvironment(actual);
      setTarget(actual.environment || next);
    } catch (error) {
      setEnvironment(null);
      failure = `${failure} Could not reconcile server environment: ${errorMessage(error)}`;
    } finally {
      setError(failure);
      setBusy(false);
      pending.current = false;
    }
  }
  if (environment?.authenticated && !busy)
    return (
      <>
        <Workspace
          key={`${environment.environment}:${epoch}`}
          environment={environment}
          onSwitch={(next) => void login(next)}
        />
        {error && (
          <div className="toast toast-error" role="alert">
            {error}
            <button className="text-button" onClick={() => setError("")}>
              Dismiss
            </button>
          </div>
        )}
      </>
    );
  return (
    <main className="login-page">
      <section className="card login-card">
        <h1>Vault Manager</h1>
        <p className="muted">Authenticate with AWS IAM to manage Vault.</p>
        {error && <ErrorBanner message={error} />}
        {busy ? (
          <>
            <Loading text={`Connecting to ${target.toUpperCase()}…`} />
            <p>
              Complete MFA in the operating-system prompt. This may take as long
              as you need.
            </p>
            <p className="muted">
              Closing or reloading this page does not cancel server-side login.
            </p>
          </>
        ) : environment ? (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void login(target);
            }}
          >
            <label htmlFor="login-environment">Environment</label>
            <Select
              id="login-environment"
              value={target}
              onChange={setTarget}
              options={environment.available_environments.map((value) => ({
                value,
                label: value.toUpperCase(),
              }))}
            />
            <button className="button primary" disabled={!target}>
              Log in
            </button>
          </form>
        ) : (
          <button
            className="button"
            onClick={() => {
              setError("");
              setRefresh((value) => value + 1);
            }}
          >
            Reconnect
          </button>
        )}
      </section>
    </main>
  );
}

export function Timeout() {
  const [remaining, setRemaining] = useState<number | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    let timer: number;
    async function poll() {
      try {
        const result = await api<{ remaining_seconds: number }>(
          "/api/timeout",
          { signal: controller.signal },
        );
        if (!controller.signal.aborted) {
          setRemaining(result.remaining_seconds);
          setUnavailable(false);
        }
      } catch (error) {
        if (!isAborted(error)) setUnavailable(true);
      }
      if (!controller.signal.aborted)
        timer = window.setTimeout(() => void poll(), 1000);
    }
    void poll();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, []);
  if (unavailable || remaining === 0)
    return (
      <span className="timeout danger" role="alert">
        {unavailable ? "Server unavailable" : "Session closed — reopen Web UI"}
      </span>
    );
  if (remaining === null) return null;
  const hours = Math.floor(remaining / 3600);
  const clock = [hours, Math.floor((remaining % 3600) / 60), remaining % 60]
    .map((value) => String(value).padStart(2, "0"))
    .join(":");
  return (
    <Tooltip content="Idle time until Web UI shutdown; API actions reset the timer">
      <span
        className={`timeout ${remaining <= 120 ? "danger" : ""}`}
        role={remaining <= 120 ? "alert" : undefined}
        tabIndex={0}
      >
        {clock}
        {remaining <= 120 && " — save your work"}
      </span>
    </Tooltip>
  );
}
