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
import { K8sModal } from "../client/K8sModal";
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
    await screen.findByText("Restart complete — all replicas ready");
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
    await screen.findByText("Rollout failed");
    expect(screen.getByText("Progress deadline exceeded")).toBeTruthy();
    expect(screen.queryByText(/Restart complete/)).toBeNull();
  });
});
