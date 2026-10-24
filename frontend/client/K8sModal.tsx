import { useEffect, useRef, useState } from "react";
import { api, errorMessage, isAborted, post } from "./api";
import { ErrorBanner, Icon, Loading, Modal } from "./components";
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
  observed?: boolean;
  new_ready?: number | null;
  pods_error?: string;
  pods: {
    name: string;
    phase: string;
    ready: string;
    created?: string;
    is_new?: boolean;
    is_ready?: boolean;
    detail?: string;
  }[];
}
export function rolloutHeading(status: Rollout | null): string {
  if (!status) return "Waiting for cluster status…";
  if (status.failed) return "Rollout failed — check pod details";
  if (status.complete) return "Restart complete — all replicas available";
  if (status.observed === false)
    return "Waiting for the deployment controller…";
  if (status.pods_error)
    return "Pod status unavailable — monitoring deployment";
  if (
    status.pods.some(
      (pod) => pod.is_new && !pod.is_ready && pod.phase !== "Terminating",
    )
  )
    return "Waiting for new pods to become ready…";
  if (status.updated < status.total) return "Creating replacement pods…";
  if (status.pods.some((pod) => pod.is_new === false))
    return "Waiting for old pods to terminate…";
  return "Waiting for new replicas to become available…";
}

type Pod = Rollout["pods"][number];
type Step = "done" | "active" | "pending" | "failed";

function podLabel(pod: Pod): string {
  if (pod.phase !== "Running") return pod.phase;
  if (pod.is_ready === true) return "Ready";
  if (pod.is_ready === false || pod.ready.startsWith("0/"))
    return "Running · not ready";
  return "Running";
}
function podTone(pod: Pod): string {
  if (pod.phase === "Running" && pod.is_ready !== false) return "ok";
  if (pod.phase === "Failed" || pod.detail) return "bad";
  return "wait";
}

function RolloutProgress({
  status,
  error,
  elapsed,
  lastUpdated,
}: {
  status: Rollout | null;
  error: string;
  elapsed: number;
  lastUpdated: number | null;
}) {
  const tone = error
    ? "paused"
    : status?.failed
      ? "failed"
      : status?.complete
        ? "complete"
        : "running";
  const label = {
    paused: "PAUSED",
    failed: "FAILED",
    complete: "DONE",
    running: "IN PROGRESS",
  }[tone];
  const total = status?.total ?? 0;
  const created = status && status.observed !== false ? status.updated : null;
  const newReady = status?.new_ready ?? null;
  const old =
    !status || status.pods_error || newReady == null
      ? null
      : status.pods.filter((pod) => pod.is_new === false).length;
  // ponytail: each step is done once its count hits the target; the first unfinished step is the active one.
  const reached = status?.complete
    ? [true, true, true]
    : [
        created != null && created >= total,
        newReady != null && newReady >= total,
        old === 0,
      ];
  const current = reached.indexOf(false);
  const steps: { text: string; count: string }[] = [
    {
      text: "Replacement pods created",
      count: `${created ?? "—"} / ${total}`,
    },
    { text: "New pods ready", count: `${newReady ?? "—"} / ${total}` },
    { text: "Old pods removed", count: old == null ? "—" : `${old} left` },
  ];
  return (
    <div role="status" className={`rollout-summary ${tone}`}>
      <div className="rollout-banner">
        <span className="rollout-icon" aria-hidden>
          {tone === "complete" ? (
            "✓"
          ) : tone === "running" ? (
            <span className="spinner" />
          ) : (
            "!"
          )}
        </span>
        <div>
          <span className="rollout-state">{label}</span>
          <h3>
            {error
              ? "Live updates paused — retry status"
              : rolloutHeading(status)}
          </h3>
        </div>
        <span className="rollout-time">
          {elapsed}s
          {lastUpdated && (
            <small>{new Date(lastUpdated).toLocaleTimeString()}</small>
          )}
        </span>
      </div>
      {status?.failed && status.message && (
        <p className="error-banner">{status.message}</p>
      )}
      {status?.pods_error && (
        <p className="error-banner">
          Pod details unavailable: {status.pods_error}
        </p>
      )}
      {status && (
        <ol className="rollout-steps">
          {steps.map((step, i) => {
            const state: Step = reached[i]
              ? "done"
              : i === current
                ? status.failed
                  ? "failed"
                  : "active"
                : "pending";
            return (
              <li key={step.text} className={state}>
                <span className="step-mark" aria-hidden>
                  {state === "done" ? "✓" : state === "failed" ? "✕" : i + 1}
                </span>
                <span>
                  {step.text} <strong>{step.count}</strong>
                </span>
              </li>
            );
          })}
        </ol>
      )}
      {elapsed >= 300 && !status?.complete && !status?.failed && (
        <p className="muted">
          Taking longer than five minutes — check pods below.
        </p>
      )}
    </div>
  );
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
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const [history, setHistory] = useState<{ time: string; text: string }[]>([]);
  const startedAt = useRef<number | null>(null);
  const previous = useRef<Rollout | null>(null);
  const request = useRef(new AbortController());
  useEffect(() => {
    if (phase !== "progress" || status?.complete || status?.failed) return;
    const timer = window.setInterval(() => {
      if (startedAt.current)
        setElapsed(Math.round((Date.now() - startedAt.current) / 1000));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [phase, status?.complete, status?.failed]);
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
    setError("");
    async function poll() {
      try {
        const result = await api<{ status: Rollout }>(
          `/api/k8s/deployments/status?namespace=${encodeURIComponent(selected!.namespace)}&name=${encodeURIComponent(selected!.name)}`,
          { signal: controller.signal },
        );
        if (controller.signal.aborted) return;
        const next = result.status;
        setStatus(next);
        setLastUpdated(Date.now());
        if (phase === "progress") {
          const changes: string[] = [];
          if (rolloutHeading(previous.current) !== rolloutHeading(next))
            changes.push(rolloutHeading(next));
          for (const pod of next.pods) {
            const old = previous.current?.pods.find(
              (item) => item.name === pod.name,
            );
            if (
              !old ||
              old.phase !== pod.phase ||
              old.ready !== pod.ready ||
              old.detail !== pod.detail
            )
              changes.push(
                `${pod.name}: ${pod.phase}, ${pod.ready} containers ready${pod.detail ? ` — ${pod.detail}` : ""}`,
              );
          }
          if (!next.pods_error) {
            for (const pod of previous.current?.pods || []) {
              if (!next.pods.some((item) => item.name === pod.name))
                changes.push(`${pod.name}: removed`);
            }
          }
          if (changes.length)
            setHistory((items) =>
              [
                ...changes.map((text) => ({
                  time: new Date().toLocaleTimeString(),
                  text,
                })),
                ...items,
              ].slice(0, 40),
            );
          previous.current = next;
        }
        if (
          phase === "progress" &&
          !result.status.complete &&
          !result.status.failed
        ) {
          timer = window.setTimeout(() => void poll(), 1500);
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
    setStatus(null);
    setLastUpdated(null);
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
      if (!request.current.signal.aborted) {
        startedAt.current = Date.now();
        previous.current = null;
        setStatus(null);
        setElapsed(0);
        setLastUpdated(null);
        setHistory([
          {
            time: new Date().toLocaleTimeString(),
            text: "Restart accepted — waiting for cluster updates",
          },
        ]);
        setPhase("progress");
      }
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
            <RolloutProgress
              status={status}
              error={error}
              elapsed={elapsed}
              lastUpdated={lastUpdated}
            />
          )}
          {!status && !error && <Loading text="Loading pod status…" />}
          <div className="pod-list">
            {status?.pods.map((pod) => (
              <div className="pod-row" key={pod.name}>
                <span className={`pod-dot ${podTone(pod)}`} aria-hidden />
                <div className="pod-identity">
                  <code>{pod.name}</code>
                  {pod.detail && (
                    <span className="pod-detail">{pod.detail}</span>
                  )}
                </div>
                {phase === "progress" && pod.is_new != null && (
                  <span className={`pod-generation ${pod.is_new ? "new" : ""}`}>
                    {pod.is_new ? "NEW" : "OLD"}
                  </span>
                )}
                <span className="pod-status">{podLabel(pod)}</span>
              </div>
            ))}
          </div>
          {phase === "progress" && (
            <details className="rollout-history">
              <summary>Details &amp; recent changes</summary>
              {status?.message && !status.failed && (
                <p className="rollout-message">{status.message}</p>
              )}
              <ol>
                {history.map((item, i) => (
                  <li key={`${item.time}-${i}`}>
                    <time>{item.time}</time>
                    <span>{item.text}</span>
                  </li>
                ))}
              </ol>
            </details>
          )}
          <div className="modal-actions">
            {phase === "progress" && (
              <span className="muted">
                Closing stops monitoring, not the restart.
              </span>
            )}
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
