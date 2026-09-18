import { useEffect, useRef, useState } from "react";
import { api, errorMessage, isAborted, post } from "./api";
import { ErrorBanner, Icon, Loading, Modal } from "./components";
import { formatTime } from "./utils";
interface Deployment {
  namespace: string;
  name: string;
  ready: number;
  total: number;
  created?: string;
}
interface Rollout {
  total: number;
  updated: number;
  ready: number;
  available: number;
  complete: boolean;
  failed: boolean;
  message: string;
  pods: { name: string; phase: string; ready: string; created?: string }[];
}
export function K8sModal({
  environment,
  onClose,
}: {
  environment: string;
  onClose: () => void;
}) {
  const [deployments, setDeployments] = useState<Deployment[]>([]);
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const [selected, setSelected] = useState<Deployment | null>(null);
  const [phase, setPhase] = useState<"search" | "confirm" | "progress">(
    "search",
  );
  const [status, setStatus] = useState<Rollout | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const request = useRef(new AbortController());
  useEffect(() => {
    const controller = new AbortController();
    request.current = controller;
    return () => controller.abort();
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    api<{ deployments: Deployment[] }>("/api/k8s/deployments", {
      signal: controller.signal,
    })
      .then((result) => {
        if (!controller.signal.aborted) setDeployments(result.deployments);
      })
      .catch((error) => {
        if (!isAborted(error)) setError(errorMessage(error));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [retry]);
  useEffect(() => {
    if (!selected) return;
    const controller = new AbortController();
    let timer: number;
    const started = Date.now();
    setStatus(null);
    setError("");
    setElapsed(0);
    async function poll() {
      try {
        const result = await api<{ status: Rollout }>(
          `/api/k8s/deployments/status?namespace=${encodeURIComponent(selected!.namespace)}&name=${encodeURIComponent(selected!.name)}`,
          { signal: controller.signal },
        );
        if (controller.signal.aborted) return;
        setStatus(result.status);
        setElapsed(Math.round((Date.now() - started) / 1000));
        if (
          phase === "progress" &&
          !result.status.complete &&
          !result.status.failed
        ) {
          if (Date.now() - started >= 300000)
            setError(
              "Timed out after five minutes. Check the cluster directly.",
            );
          else timer = window.setTimeout(() => void poll(), 1500);
        }
      } catch (error) {
        if (!isAborted(error)) setError(errorMessage(error));
      }
    }
    void poll();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [selected, phase, retry]);
  const filtered = deployments.filter((item) =>
    `${item.namespace}/${item.name}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  useEffect(() => {
    document
      .querySelector(".deployment-result.selected")
      ?.scrollIntoView({ block: "nearest" });
  }, [index, query]);
  function select(item: Deployment) {
    setSelected(item);
    setPhase("confirm");
  }
  async function restart() {
    if (!selected || busy) return;
    setBusy(true);
    setError("");
    try {
      await post(
        "/api/k8s/deployments/restart",
        { namespace: selected.namespace, name: selected.name },
        request.current.signal,
      );
      if (!request.current.signal.aborted) setPhase("progress");
    } catch (error) {
      if (!isAborted(error)) setError(errorMessage(error));
    } finally {
      if (!request.current.signal.aborted) setBusy(false);
    }
  }
  return (
    <Modal title="Restart Deployment" onClose={onClose} wide busy={busy}>
      <div className="deployment-context">
        <span className="environment-badge">{environment.toUpperCase()}</span>
        <span>
          {phase === "search"
            ? "Select a deployment to restart."
            : phase === "confirm"
              ? "Review the target before restarting."
              : "Monitor the deployment rollout."}
        </span>
      </div>
      {environment.startsWith("prod") && (
        <p className="error-banner">
          PRODUCTION — restarting will replace running pods.
        </p>
      )}
      {error && (
        <ErrorBanner message={error}>
          <button
            className="button"
            disabled={busy}
            onClick={() => setRetry((value) => value + 1)}
          >
            Retry status
          </button>
        </ErrorBanner>
      )}
      {phase === "search" ? (
        <>
          <div className="field deployment-search">
            <label htmlFor="deployment-search">Search deployments</label>
            <input
              id="deployment-search"
              data-autofocus
              placeholder="Filter by name or namespace…"
              autoComplete="off"
              spellCheck={false}
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setIndex(0);
              }}
              onKeyDown={(event) => {
                if (!filtered.length) return;
                if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                  event.preventDefault();
                  setIndex(
                    (value) =>
                      (value +
                        (event.key === "ArrowDown" ? 1 : -1) +
                        filtered.length) %
                      filtered.length,
                  );
                }
                if (event.key === "Enter" && filtered[index]) {
                  event.preventDefault();
                  select(filtered[index]);
                }
              }}
            />
          </div>
          <div className="deployment-list" aria-label="Deployments">
            {loading ? (
              <Loading />
            ) : (
              filtered.map((item, i) => (
                <button
                  className={`deployment-result ${i === index ? "selected" : ""}`}
                  key={`${item.namespace}/${item.name}`}
                  onClick={() => select(item)}
                >
                  <Icon name="refresh" />
                  <span className="deployment-identity">
                    <strong>{item.name}</strong>
                    <span className="deployment-namespace">
                      {item.namespace}
                    </span>
                  </span>
                  <span
                    className={`deployment-readiness ${item.ready === item.total && item.total > 0 ? "ready" : ""}`}
                  >
                    {item.ready}/{item.total} ready
                  </span>
                  <Icon name="chevron" />
                </button>
              ))
            )}
            {!loading && !filtered.length && (
              <p className="muted">No deployments found.</p>
            )}
          </div>
          <div className="deployment-footer">
            <span>{filtered.length} deployments</span>
            <span>
              <kbd>↑</kbd> <kbd>↓</kbd> navigate · <kbd>Enter</kbd> select
            </span>
          </div>
        </>
      ) : (
        <>
          <div className="deployment-target">
            <span className="deployment-namespace">{selected?.namespace}</span>
            <h3>{selected?.name}</h3>
          </div>
          {phase === "confirm" ? (
            <p className="deployment-description">
              Perform a rolling restart of this deployment?
            </p>
          ) : (
            <div role="status" className="rollout-summary">
              <h3>
                {status?.failed
                  ? "Rollout failed"
                  : status?.complete
                    ? "Restart complete — all replicas ready"
                    : "Rolling out new pods…"}
              </h3>
              <p>{status?.message}</p>
              <progress
                max={Math.max(1, (status?.total || 0) * 2)}
                value={
                  status?.complete
                    ? Math.max(1, (status.total || 0) * 2)
                    : (status?.updated || 0) + (status?.available || 0)
                }
              />
              <p>
                Updated {status?.updated ?? 0} · Ready {status?.ready ?? 0} ·
                Available {status?.available ?? 0} · Total {status?.total ?? 0}{" "}
                · {elapsed}s
              </p>
            </div>
          )}
          {!status && !error && <Loading text="Loading pod status…" />}
          <div className="pod-list">
            {status?.pods.map((pod) => (
              <div className="pod-row" key={pod.name}>
                <div className="pod-identity">
                  <code>{pod.name}</code>
                  {pod.created && (
                    <span className="pod-created">
                      Created {formatTime(pod.created)}
                    </span>
                  )}
                </div>
                <div className="pod-status">
                  <span className="badge">{pod.phase}</span>
                  <span>{pod.ready} ready</span>
                </div>
              </div>
            ))}
          </div>
          <div className="modal-actions">
            {phase === "confirm" ? (
              <>
                <button
                  className="button"
                  disabled={busy}
                  onClick={() => {
                    setSelected(null);
                    setPhase("search");
                  }}
                >
                  Back
                </button>
                <button
                  className={`button ${environment.startsWith("prod") ? "danger-fill" : "primary"}`}
                  disabled={busy}
                  onClick={() => void restart()}
                >
                  {busy ? "Restarting…" : "Confirm Restart"}
                </button>
              </>
            ) : (
              <button className="button" onClick={onClose}>
                Close
              </button>
            )}
          </div>
        </>
      )}
    </Modal>
  );
}
