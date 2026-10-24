import { StrictMode } from "react";
import { EditorView } from "codemirror";
import { CodeEditor } from "../client/CodeEditor";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import Workspace from "../client/App";
import { Session } from "../client/Session";
import { DatabasePanel } from "../client/DatabasePanel";
import { SecretPanel } from "../client/SecretPanel";
import { K8sModal, rolloutHeading } from "../client/K8sModal";
import { api } from "../client/api";
import { parseSecretJson } from "../client/utils";

const environment = {
  environment: "dev",
  authenticated: true,
  available_environments: ["dev", "prod"],
};
const calls: {
  path: string;
  body: Record<string, unknown>;
  signal?: AbortSignal | null;
}[] = [];
let handler: (url: URL, options: RequestInit) => unknown | Promise<unknown>;
const response = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
beforeEach(() => {
  localStorage.clear();
  calls.length = 0;
  Element.prototype.scrollIntoView = vi.fn();
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      disconnect() {}
    },
  );
  handler = (url) => {
    if (url.pathname === "/api/environment") return environment;
    if (url.pathname === "/api/timeout") return { remaining_seconds: 3600 };
    if (url.pathname === "/api/secrets/list")
      return {
        secrets: [
          { name: "alpha", path: "alpha", type: "secret" },
          { name: "beta", path: "beta", type: "secret" },
          { name: "team", path: "team/", type: "folder" },
        ],
      };
    if (url.pathname === "/api/secrets/versions")
      return {
        current_version: 2,
        versions: [
          { version: 2, created_time: "", deleted_time: "", destroyed: false },
          { version: 1, created_time: "", deleted_time: "", destroyed: false },
        ],
      };
    if (url.pathname === "/api/secrets/get")
      return {
        path: url.searchParams.get("path"),
        data: { key: "value" },
        metadata: { version: 2 },
      };
    if (url.pathname === "/api/database/roles") return { roles: ["reader"] };
    if (url.pathname === "/api/database/check-mcp-config")
      return { exists: true, path: "/mock/environments.json" };
    if (url.pathname.startsWith("/api/database/creds/"))
      return {
        role: "reader",
        username: "test-user",
        password: "test-password",
        lease_duration: 600,
        renewable: true,
        lease_id: "test-lease",
      };
    if (url.pathname === "/api/k8s/deployments")
      return {
        deployments: [
          { namespace: "default", name: "service", ready: 1, total: 1 },
        ],
      };
    if (url.pathname === "/api/k8s/deployments/status")
      return {
        status: {
          total: 1,
          updated: 1,
          ready: 1,
          available: 1,
          complete: true,
          failed: false,
          message: "",
          pods: [{ name: "service-pod", ready: "1/1", phase: "Running" }],
        },
      };
    return { success: true };
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, options: RequestInit = {}) => {
      const url = new URL(input, "http://localhost");
      calls.push({
        path: url.pathname + url.search,
        body: options.body ? JSON.parse(String(options.body)) : {},
        signal: options.signal,
      });
      const result = await handler(url, options);
      return result instanceof Response
        ? result
        : response({ success: true, ...(result as object) });
    }),
  );
});
afterEach(() => {
  cleanup();
  delete document.documentElement.dataset.theme;
  vi.unstubAllGlobals();
});
const workspace = () =>
  render(
    <StrictMode>
      <Workspace environment={environment} onSwitch={vi.fn()} />
    </StrictMode>,
  );

describe("migrated UI regressions", () => {
  it("explains new pod readiness instead of counting old pods as progress", async () => {
    const original = handler;
    const status = { total: 2, updated: 1, ready: 2, available: 2, complete: false, failed: false,
      observed: true, new_ready: 0, message: "", pods: [
        { name: "new-pod", phase: "Running", ready: "0/1", is_new: true, is_ready: false, detail: "Readiness probe failed" },
        { name: "old-pod", phase: "Running", ready: "1/1", is_new: false, is_ready: true },
      ] };
    handler = (url, options) => url.pathname === "/api/k8s/deployments/status" ? { status } : original(url, options);
    render(<K8sModal environment="dev" onClose={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: /service/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Confirm Restart" }));
    await screen.findByRole("heading", { name: "Waiting for new pods to become ready…" });
    expect(screen.queryByRole("progressbar")).toBeNull();
    expect(screen.getByText("NEW")).toBeTruthy();
    expect(screen.getByText("OLD")).toBeTruthy();
    expect(screen.getByText("New pods ready").textContent).toContain("0 / 2");
    expect(screen.getByText("Running · not ready")).toBeTruthy();
    expect(rolloutHeading({ ...status, observed: false })).toContain("controller");
    expect(rolloutHeading({ ...status, pods_error: "Forbidden" })).toContain("unavailable");
    expect(rolloutHeading({ ...status, complete: true })).toContain("Restart complete");
    expect(rolloutHeading({ ...status, failed: true })).toContain("failed");
  });
  it("separates version metadata and preserves explicit versus latest selection", async () => {
    const defaultHandler = handler;
    handler = (url, options) => url.pathname === "/api/secrets/versions" ? {
      current_version: 20,
      versions: [20, 19, 18].map((version) => ({
        version,
        created_time: "2026-09-10T15:35:26Z",
        deleted_time: version === 19 ? "2026-09-11T00:00:00Z" : "",
        destroyed: version === 18,
      })),
    } : defaultHandler(url, options);
    workspace();
    fireEvent.click(await screen.findByRole("button", { name: "alpha" }));
    await screen.findByText("Secret Data");
    const trigger = screen.getByRole("combobox", { name: "Version" });
    expect(trigger.textContent).toBe("Latest (v20)");
    fireEvent.click(trigger);
    const options = screen.getAllByRole("option");
    expect(options).toHaveLength(4);
    expect(options[1].querySelector(".select-option-heading")?.textContent).toBe("v20Latest");
    expect(options[1].querySelector(".select-option-description")?.textContent).toBeTruthy();
    expect(options[2].querySelector(".select-option-badge")?.textContent).toBe("Deleted");
    expect(options[3].querySelector(".select-option-badge")?.textContent).toBe("Destroyed");
    fireEvent.click(options[1]);
    await waitFor(() => expect(trigger.textContent).toBe("v20"));
    await screen.findByText("Secret Data");
    expect(calls.some((call) => call.path.includes("version=20"))).toBe(true);
    fireEvent.click(trigger);
    fireEvent.keyDown(trigger, { key: "End" });
    fireEvent.keyDown(trigger, { key: "Enter" });
    await screen.findByRole("heading", { name: "Version 18 destroyed" });
    expect(trigger.textContent).toBe("v18");
    fireEvent.click(trigger);
    fireEvent.keyDown(trigger, { key: "Home" });
    fireEvent.keyDown(trigger, { key: "Enter" });
    await screen.findByText("Secret Data");
    expect(trigger.textContent).toBe("Latest (v20)");
  });
  it("preserves the themed editor and edits when switching appearance", () => {
    document.documentElement.dataset.theme = "light";
    const onChange = vi.fn();
    const { container, rerender } = render(
      <CodeEditor
        value={'{"key":"example"}'}
        onChange={onChange}
        label="JSON"
        invalid={false}
      />,
    );
    const content = screen.getByRole("textbox", { name: "JSON" });
    const view = EditorView.findFromDOM(content)!;
    const stringToken = Array.from(content.querySelectorAll("span")).find(
      (element) => element.textContent === '"example"',
    );
    expect(stringToken).toBeDefined();
    const tokenClass = stringToken!.className;
    expect(tokenClass).not.toBe("");
    document.documentElement.dataset.theme = "dark";
    expect(EditorView.findFromDOM(content)).toBe(view);
    expect(stringToken!.className).toBe(tokenClass);
    expect(container.querySelector(".cm-editor")).not.toBeNull();
    view.dispatch({ changes: { from: 8, to: 15, insert: "updated" } });
    expect(onChange).toHaveBeenLastCalledWith('{"key":"updated"}');
    rerender(
      <CodeEditor value="{}" onChange={onChange} label="JSON" invalid={true} />,
    );
    expect(view.state.doc.toString()).toBe("{}");
    expect(content.getAttribute("aria-invalid")).toBe("true");
  });
  it("replaces sidebar selection immediately and aborts previous detail loads", async () => {
    workspace();
    fireEvent.click(await screen.findByRole("button", { name: "alpha" }));
    await screen.findByText("Secret Data");
    fireEvent.click(screen.getByRole("button", { name: "beta" }));
    expect(
      screen.getByRole("button", { name: "alpha" }).className,
    ).not.toContain("selected");
    expect(screen.getByRole("button", { name: "beta" }).className).toContain(
      "selected",
    );
    await waitFor(() =>
      expect(
        calls.some(
          (call) => call.path.includes("path=alpha") && call.signal?.aborted,
        ),
      ).toBe(true),
    );
  });
  it("copies individual masked credentials without revealing them and preserves StrictMode requests", async () => {
    const copy = vi.fn();
    render(
      <StrictMode>
        <DatabasePanel role="reader" environment="dev" copy={copy} />
      </StrictMode>,
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Generate Credentials" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Copy username" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Copy password" }));
    expect(copy.mock.calls).toEqual([["test-user"], ["test-password"]]);
    expect(screen.queryByText("test-password")).toBeNull();
    expect(
      calls.find((call) => call.path.includes("/creds/"))?.signal?.aborted,
    ).toBe(false);
    await waitFor(() =>
      expect(
        (
          screen.getByRole("button", {
            name: "Sync to PostgreSQL MCP",
          }) as HTMLButtonElement
        ).disabled,
      ).toBe(false),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Sync to PostgreSQL MCP" }),
    );
    await screen.findByText("Credentials synced to PostgreSQL MCP.");
    expect(
      calls.find((call) => call.path.endsWith("sync-to-mcp"))?.body,
    ).toEqual({
      role_name: "reader",
      username: "test-user",
      password: "test-password",
    });
  });
  it("reports clipboard denial through the workspace", async () => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockRejectedValue(new Error("denied")) },
    });
    workspace();
    fireEvent.click(
      screen.getByRole("button", { name: "Database Credentials" }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "reader" }));
    fireEvent.click(
      screen.getByRole("button", { name: "Generate Credentials" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Copy password" }),
    );
    expect(
      await screen.findByText(/Could not access the clipboard/),
    ).toBeTruthy();
  });
  it("uses folder trailing slashes and custom mount for list/get/create", async () => {
    workspace();
    fireEvent.click(await screen.findByRole("button", { name: "team" }));
    await waitFor(() =>
      expect(calls.some((call) => call.path.includes("path=team%2F"))).toBe(
        true,
      ),
    );
    expect(screen.queryByRole("button", { name: "Apply" })).toBeNull();
    const restart = screen.getByRole("button", {
      name: "Restart Deployment (Ctrl+Shift+K)",
    });
    expect(restart.closest("header")).not.toBeNull();
    expect(restart.closest("aside")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Configure KV mount" }));
    fireEvent.change(screen.getByLabelText("KV mount"), {
      target: { value: "custom" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() =>
      expect(
        calls.some((call) => call.path.includes("mount_point=custom")),
      ).toBe(true),
    );
    fireEvent.click(screen.getByRole("button", { name: "New Secret" }));
    fireEvent.change(screen.getByLabelText("Secret path"), {
      target: { value: "new-secret" },
    });
    fireEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: "Create Secret",
      }),
    );
    await waitFor(() =>
      expect(calls.find((call) => call.path.endsWith("/create"))?.body).toEqual(
        { path: "new-secret", data: {}, mount_point: "custom" },
      ),
    );
  });
  it("reads KV v1 even when version history is unavailable", async () => {
    const original = handler;
    handler = (url, options) =>
      url.pathname.endsWith("/versions")
        ? response({ success: false, error: "KV v1" }, 400)
        : original(url, options);
    render(
      <SecretPanel
        path="legacy"
        mount="custom"
        copy={vi.fn()}
        onChanged={vi.fn()}
        onDeleted={vi.fn()}
      />,
    );
    await screen.findByText("Secret Data");
    expect(
      calls.some(
        (call) =>
          call.path.includes("/get?") &&
          call.path.includes("mount_point=custom") &&
          !call.path.includes("version="),
      ),
    ).toBe(true);
  });
  it("reviews key-level changes before saving", async () => {
    render(
      <SecretPanel
        path="alpha"
        mount="secret"
        copy={vi.fn()}
        onChanged={vi.fn()}
        onDeleted={vi.fn()}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Edit key" }));
    fireEvent.change(screen.getByLabelText("Value"), {
      target: { value: "changed" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));
    const changes = await screen.findByLabelText("Changes");
    expect(within(changes).getByText("changed")).toBeTruthy();
    expect(calls.some((call) => call.path.startsWith("/api/secrets/update"))).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Confirm Save" }));
    await waitFor(() =>
      expect(calls.find((call) => call.path === "/api/secrets/update")?.body).toEqual({
        path: "alpha",
        key: "key",
        value: "changed",
        mount_point: "secret",
      }),
    );
  });
  it("refuses to save when nothing changed", async () => {
    render(
      <SecretPanel
        path="alpha"
        mount="secret"
        copy={vi.fn()}
        onChanged={vi.fn()}
        onDeleted={vi.fn()}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Edit key" }));
    fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));
    await screen.findByText("No changes to save.");
  });
  it("compares a historical version and restores it as a new version", async () => {
    const original = handler;
    handler = (url, options) =>
      url.pathname === "/api/secrets/get" && url.searchParams.get("version") === "1"
        ? { path: "alpha", data: { key: "old", gone: 1 }, metadata: { version: 1 } }
        : original(url, options);
    render(
      <SecretPanel
        path="alpha"
        mount="secret"
        copy={vi.fn()}
        onChanged={vi.fn()}
        onDeleted={vi.fn()}
      />,
    );
    await screen.findByText("Secret Data");
    fireEvent.click(screen.getByRole("combobox", { name: "Version" }));
    fireEvent.click(screen.getByRole("option", { name: /^v1/ }));
    const compare = await screen.findByRole("button", { name: "Compare with Latest" });
    await waitFor(() => expect((compare as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(compare);
    const diff = await screen.findByLabelText("Changes");
    expect(within(diff).getByText("removed")).toBeTruthy();
    expect(within(diff).getByText("changed")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Restore This Version" }));
    fireEvent.click(await screen.findByRole("button", { name: "Restore v1" }));
    await waitFor(() =>
      expect(calls.find((call) => call.path === "/api/secrets/update-json")?.body).toEqual({
        path: "alpha",
        data: { key: "old", gone: 1 },
        mount_point: "secret",
      }),
    );
  });
  it("compares every environment with the current one", async () => {
    const original = handler;
    handler = (url, options) =>
      url.pathname === "/api/secrets/compare"
        ? {
            current: "dev",
            environments: [
              { environment: "dev", status: "ok", keys: { a: "h1", b: "h2" }, values: { a: "same", b: "dev-b" } },
              { environment: "sat", status: "ok", keys: { a: "h1", b: "h3", c: "h4" }, values: { a: "same", b: "sat-b", c: 4 } },
              { environment: "prod", status: "not_running" },
              { environment: "qa", status: "error", error: "permission denied" },
            ],
          }
        : original(url, options);
    render(
      <SecretPanel
        path="alpha"
        mount="secret"
        canCompare
        copy={vi.fn()}
        onChanged={vi.fn()}
        onDeleted={vi.fn()}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Compare Environments" }),
    );
    const dialog = await screen.findByRole("dialog");
    await within(dialog).findByText("PROD · Not running");
    expect(within(dialog).getByText("QA could not be read: permission denied")).toBeTruthy();
    expect(within(dialog).getByText("1 different")).toBeTruthy();
    expect(within(dialog).getByText("1 only in SAT")).toBeTruthy();
    // identical keys are hidden until "Differences only" is cleared
    const hidden = "••••••••••••";
    let rows = within(dialog).getAllByRole("row").map((row) => row.textContent);
    expect(rows).toEqual([
      "KEYDEV · baselineSAT",
      `b${hidden}Different${hidden}`,
      `cMissingOnly here${hidden}`,
    ]);
    // values stay hidden until revealed, one cell at a time
    expect(within(dialog).queryByText("sat-b")).toBeNull();
    fireEvent.click(within(dialog).getByRole("button", { name: "Reveal b in SAT" }));
    expect(within(dialog).getByText("sat-b")).toBeTruthy();
    expect(within(dialog).queryByText("dev-b")).toBeNull();
    fireEvent.click(within(dialog).getByRole("checkbox", { name: /Differences only/ }));
    rows = within(dialog).getAllByRole("row").map((row) => row.textContent);
    expect(rows[1]).toBe(`a${hidden}Same${hidden}`);
  });
  it("offers environment compare only when the server can compare", async () => {
    render(
      <Workspace
        environment={{ ...environment, locked: true, available_environments: ["dev"], can_compare: true }}
        onSwitch={vi.fn()}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "alpha" }));
    await screen.findByRole("button", { name: "Compare Environments" });
    cleanup();
    render(<Workspace environment={environment} onSwitch={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: "alpha" }));
    await screen.findByText("Secret Data");
    expect(screen.queryByRole("button", { name: "Compare Environments" })).toBeNull();
  });
  it("does not open the close tooltip when a dialog without a field opens", async () => {
    const original = handler;
    handler = (url, options) =>
      url.pathname === "/api/secrets/compare"
        ? { current: "dev", environments: [{ environment: "dev", status: "ok", keys: {}, values: {} }] }
        : original(url, options);
    render(
      <SecretPanel path="alpha" mount="secret" canCompare copy={vi.fn()} onChanged={vi.fn()} onDeleted={vi.fn()} />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Compare Environments" }));
    const dialog = await screen.findByRole("dialog");
    expect(document.activeElement).toBe(dialog);
    expect(screen.queryByRole("tooltip")).toBeNull();
  });
  it("blocks invalid JSON root values", () => {
    expect(() => parseSecretJson("[]")).toThrow("JSON object");
    expect(() => parseSecretJson('{"value":1e999}')).toThrow("finite");
    expect(parseSecretJson('{"enabled":true,"count":2}')).toEqual({
      enabled: true,
      count: 2,
    });
  });
  it("clears old environment data during login and reconciles failed switches", async () => {
    let complete: (value: unknown) => void = () => {};
    const original = handler;
    handler = (url, options) =>
      url.pathname === "/api/login"
        ? new Promise((resolve) => {
            complete = resolve;
          })
        : original(url, options);
    render(
      <StrictMode>
        <Session />
      </StrictMode>,
    );
    await screen.findByRole("button", { name: "alpha" });
    fireEvent.click(screen.getByRole("combobox", { name: "Environment" }));
    fireEvent.click(screen.getByRole("option", { name: "PROD" }));
    await screen.findByText(/Complete MFA/);
    expect(screen.queryByRole("button", { name: "alpha" })).toBeNull();
    complete(response({ success: false, error: "MFA canceled" }));
    await screen.findByRole("button", { name: "alpha" });
    expect(screen.getByText("MFA canceled")).toBeTruthy();
    expect(
      screen.getByRole("combobox", { name: "Environment" }).textContent,
    ).toContain("DEV");
  });
  it("shows no environment in the header when the server is locked", async () => {
    const original = handler;
    handler = (url, options) =>
      url.pathname === "/api/environment"
        ? { ...environment, available_environments: ["dev"], locked: true }
        : url.pathname === "/api/timeout"
          ? { disabled: true, remaining_seconds: null }
          : original(url, options);
    const { container } = render(<Session />);
    await screen.findByRole("button", { name: "alpha" });
    expect(screen.queryByRole("combobox", { name: "Environment" })).toBeNull();
    // Infra Desktop shows and switches the environment itself.
    expect(container.querySelector(".header-environment")).toBeNull();
    expect(screen.queryByText("DEV")).toBeNull();
    expect(screen.queryByText(/Session closed/)).toBeNull();
  });
  it("shows no environment choice on the login page when locked", async () => {
    const original = handler;
    handler = (url, options) =>
      url.pathname === "/api/environment"
        ? { environment: "dev", authenticated: false, available_environments: ["dev"], locked: true }
        : url.pathname === "/api/login"
          ? { success: false, message: "denied" }
          : original(url, options);
    render(<Session />);
    // automatic sign-in failed: the button is there to retry
    await screen.findByRole("button", { name: "Log in" });
    expect(screen.queryByRole("combobox", { name: "Environment" })).toBeNull();
    expect(screen.queryByText("DEV")).toBeNull();
  });
  it("signs in automatically when locked", async () => {
    let signedIn = false;
    const original = handler;
    handler = (url, options) => {
      if (url.pathname === "/api/environment")
        return { environment: "dev", authenticated: signedIn, available_environments: ["dev"], locked: true };
      if (url.pathname === "/api/login") {
        signedIn = true;
        return { success: true, environment: "dev" };
      }
      return original(url, options);
    };
    render(<Session />);
    await screen.findByRole("button", { name: "alpha" });
    const logins = calls.filter((c) => c.path === "/api/login");
    expect(logins).toHaveLength(1);
    expect(logins[0].body).toEqual({ environment: "dev" });
  });
  it("says it is signing in, not asking for MFA, when locked", async () => {
    const original = handler;
    handler = (url, options) =>
      url.pathname === "/api/environment"
        ? { environment: "dev", authenticated: false, available_environments: ["dev"], locked: true }
        : url.pathname === "/api/login"
          ? new Promise(() => {})
          : original(url, options);
    render(<Session />);
    await screen.findByText(/Signing in/);
    expect(screen.queryByText(/Complete MFA/)).toBeNull();
  });
  it("keeps the environment selector when not locked", async () => {
    render(<Session />);
    await screen.findByRole("button", { name: "alpha" });
    expect(screen.getByRole("combobox", { name: "Environment" })).toBeTruthy();
  });
  it("does not expire a new session for aborted stale unauthorized requests", async () => {
    const listener = vi.fn();
    window.addEventListener("vault-auth-expired", listener);
    handler = () =>
      response({ success: false, error: "Not authenticated" }, 401);
    const controller = new AbortController();
    controller.abort();
    await expect(
      api("/api/secrets/get", { signal: controller.signal }),
    ).rejects.toThrow();
    expect(listener).not.toHaveBeenCalled();
    window.removeEventListener("vault-auth-expired", listener);
  });
  it("requires restart confirmation, displays pods, and polls completion", async () => {
    render(
      <StrictMode>
        <K8sModal environment="prod" onClose={vi.fn()} />
      </StrictMode>,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /service.*default/ }),
    );
    await screen.findByText("service-pod");
    expect(calls.some((call) => call.path.endsWith("/restart"))).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Confirm Restart" }));
    await screen.findByRole("heading", { name: "Restart complete — all replicas available" });
    expect(calls.find((call) => call.path.endsWith("/restart"))?.body).toEqual({
      namespace: "default",
      name: "service",
    });
  });
  it("disables database sync when config is unavailable", async () => {
    handler = (url) =>
      url.pathname.includes("/creds/")
        ? { role: "reader", username: "u", password: "p", lease_duration: 1 }
        : response({ success: false, error: "Config missing" });
    render(<DatabasePanel role="reader" environment="sat" copy={vi.fn()} />);
    fireEvent.click(
      screen.getByRole("button", { name: "Generate Credentials" }),
    );
    await screen.findByText("Config missing");
    expect(
      (
        screen.getByRole("button", {
          name: "Sync to PostgreSQL MCP",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });
  it("allows database sync in SAT when configuration is available", async () => {
    render(<DatabasePanel role="reader" environment="sat" copy={vi.fn()} />);
    fireEvent.click(
      screen.getByRole("button", { name: "Generate Credentials" }),
    );
    const sync = await screen.findByRole("button", {
      name: "Sync to PostgreSQL MCP",
    });
    await waitFor(() =>
      expect((sync as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(sync);
    await screen.findByText("Credentials synced to PostgreSQL MCP.");
    expect(calls.some((call) => call.path.endsWith("sync-to-mcp"))).toBe(true);
  });
  it("preserves sidebar width and theme choices", async () => {
    workspace();
    const resize = screen.getByRole("separator", { name: "Resize navigation" });
    expect(resize.getAttribute("aria-valuenow")).toBe("320");
    fireEvent.keyDown(resize, { key: "ArrowRight" });
    expect(localStorage.getItem("vault-ops-sidebar-width")).toBe("336");
    fireEvent.click(screen.getByRole("button", { name: "Light Mode" }));
    expect(document.documentElement.dataset.theme).toBe("light");
    await screen.findByRole("button", { name: "alpha" });
  });
  it("shows failed rollout details without claiming success", async () => {
    const original = handler;
    handler = (url, options) =>
      url.pathname.endsWith("/status")
        ? {
            status: {
              total: 1,
              ready: 0,
              updated: 1,
              available: 0,
              failed: true,
              complete: false,
              message: "Progress deadline exceeded",
              pods: [],
            },
          }
        : original(url, options);
    render(<K8sModal environment="dev" onClose={vi.fn()} />);
    fireEvent.click(
      await screen.findByRole("button", { name: /service.*default/ }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm Restart" }));
    await screen.findByRole("heading", { name: "Rollout failed — check pod details" });
    expect(screen.getByText("Progress deadline exceeded")).toBeTruthy();
    expect(screen.queryByText(/Restart complete/)).toBeNull();
  });
  it("shows pod logs and rolls back a failed rollout after confirmation", async () => {
    const original = handler;
    handler = (url, options) =>
      url.pathname.endsWith("/status")
        ? {
            status: {
              total: 1, ready: 0, updated: 1, available: 0, failed: true, complete: false,
              message: "Progress deadline exceeded",
              pods: [{ name: "app-pod", phase: "Running", ready: "0/1", is_ready: false }],
            },
          }
        : url.pathname === "/api/k8s/pods/logs"
          ? { logs: "[pod/app-pod/web] boom" }
          : original(url, options);
    render(<K8sModal environment="dev" onClose={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: /service.*default/ }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm Restart" }));
    await screen.findByRole("heading", { name: "Rollout failed — check pod details" });
    fireEvent.click(screen.getByRole("button", { name: "Logs for app-pod" }));
    await screen.findByText("[pod/app-pod/web] boom");
    fireEvent.click(screen.getByRole("checkbox", { name: "Previous container" }));
    await waitFor(() =>
      expect(calls.some((call) => call.path.includes("pod=app-pod&previous=1"))).toBe(true),
    );
    fireEvent.click(screen.getByRole("button", { name: "Roll Back" }));
    expect(calls.some((call) => call.path.endsWith("/rollback"))).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Confirm Roll Back" }));
    await waitFor(() =>
      expect(calls.find((call) => call.path.endsWith("/rollback"))?.body).toEqual({
        namespace: "default",
        name: "service",
      }),
    );
  });
});
