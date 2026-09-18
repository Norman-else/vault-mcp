import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import type { SearchResult } from "../shared/types";
import { api, errorMessage, isAborted } from "./api";
import { ErrorBanner, Icon, Loading, Modal } from "./components";

type Result =
  | { type: "secret"; path: string; matching_keys: string[] }
  | { type: "role"; path: string; matching_keys: never[] };
export function SearchModal({
  environment,
  mount,
  onClose,
  onSelect,
}: {
  environment: string;
  mount: string;
  onClose: () => void;
  onSelect: (type: "secret" | "role", path: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<Result[]>([]);
  const [selected, setSelected] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [limited, setLimited] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const controller = new AbortController();
    setResults([]);
    setSelected(0);
    setError("");
    setLimited(false);
    if (!query.trim()) {
      setLoading(false);
      return () => controller.abort();
    }
    setLoading(true);
    const timer = window.setTimeout(() => {
      void (async () => {
        const [secrets, roles] = await Promise.allSettled([
          api<{
            results: SearchResult[];
            truncated: boolean;
            partial?: boolean;
          }>(
            `/api/secrets/search?q=${encodeURIComponent(query.trim())}&mount_point=${encodeURIComponent(mount)}`,
            {
              signal: controller.signal,
            },
          ),
          api<{ results: { name: string }[] }>(
            `/api/database/roles/search?q=${encodeURIComponent(query.trim())}`,
            { signal: controller.signal },
          ),
        ]);
        if (controller.signal.aborted) return;
        const next: Result[] = [];
        const errors: string[] = [];
        if (secrets.status === "fulfilled") {
          next.push(
            ...secrets.value.results.map((item) => ({
              type: "secret" as const,
              path: item.path,
              matching_keys: item.matching_keys || [],
            })),
          );
          setLimited(secrets.value.truncated || !!secrets.value.partial);
        } else if (!isAborted(secrets.reason))
          errors.push(`Secrets: ${errorMessage(secrets.reason)}`);
        if (roles.status === "fulfilled")
          next.push(
            ...roles.value.results.map((item) => ({
              type: "role" as const,
              path: item.name,
              matching_keys: [] as never[],
            })),
          );
        else if (!isAborted(roles.reason))
          errors.push(`Database roles: ${errorMessage(roles.reason)}`);
        setResults(next);
        setError(errors.join(" "));
        setLoading(false);
      })();
    }, 300);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [query, mount]);
  useEffect(() => {
    listRef.current
      ?.querySelector('[aria-selected="true"]')
      ?.scrollIntoView({ block: "nearest" });
  }, [selected]);
  function keyboard(event: KeyboardEvent<HTMLInputElement>) {
    if (!results.length) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setSelected((value) => (value + 1) % results.length);
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      setSelected((value) => (value - 1 + results.length) % results.length);
    }
    if (event.key === "Enter") {
      event.preventDefault();
      const result = results[selected];
      if (result) onSelect(result.type, result.path);
    }
  }
  return (
    <Modal title="Search Vault" onClose={onClose} wide>
      <div className="search-input">
        <Icon name="search" />
        <input
          data-autofocus
          role="combobox"
          aria-label="Search secrets, keys, and database roles"
          aria-autocomplete="list"
          aria-expanded={results.length > 0}
          aria-controls="search-results"
          aria-activedescendant={
            results[selected] ? `search-result-${selected}` : undefined
          }
          placeholder="Search secrets, keys, and database roles…"
          value={query}
          maxLength={256}
          onChange={(event) => {
            setQuery(event.target.value);
            setResults([]);
          }}
          onKeyDown={keyboard}
          autoComplete="off"
          spellCheck={false}
        />
      </div>
      <div className="search-hints">
        <span>
          <kbd>↑↓</kbd> Navigate <kbd>Enter</kbd> Open <kbd>Esc</kbd> Close
        </span>
        <span className="badge">{environment.toUpperCase()}</span>
      </div>
      {error && <ErrorBanner message={error} />}
      {limited && (
        <div className="notice">
          Results are incomplete because of search limits or inaccessible paths.
          Refine your search or browse the explorer.
        </div>
      )}
      <div
        className="search-results"
        id="search-results"
        role="listbox"
        aria-label="Search results"
        ref={listRef}
      >
        {loading ? (
          <Loading text="Searching Vault…" />
        ) : results.length ? (
          results.map((result, index) => (
            <button
              key={`${result.type}:${result.path}`}
              id={`search-result-${index}`}
              className={`search-result ${selected === index ? "selected" : ""}`}
              role="option"
              aria-selected={selected === index}
              onMouseMove={() => setSelected(index)}
              onClick={() => onSelect(result.type, result.path)}
            >
              <Icon name={result.type === "secret" ? "lock" : "database"} />
              <span className="search-result-content">
                <span className="result-path">{result.path}</span>
                <span className="result-type">
                  {result.type === "secret" ? "KV Secret" : "Database Role"}
                </span>
                {result.matching_keys.length > 0 && (
                  <span className="matching-keys">
                    Keys: {result.matching_keys.join(", ")}
                  </span>
                )}
              </span>
              <Icon name="chevron" />
            </button>
          ))
        ) : (
          <div className="empty-state compact">
            <Icon name="search" />
            <h3>
              {query.trim() ? "No results found" : "Start typing to search"}
            </h3>
            <p>
              {query.trim()
                ? "Try another path, key name, or database role."
                : "Search secret paths and key names. Secret values are never searched."}
            </p>
          </div>
        )}
      </div>
    </Modal>
  );
}
