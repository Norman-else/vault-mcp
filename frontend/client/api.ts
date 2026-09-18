export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });
  const data = (await response.json().catch(() => null)) as
    | ({ success?: boolean; error?: string; message?: string } & T)
    | null;
  if (!response.ok || !data || data.success === false) {
    if (
      response.status === 401 &&
      path !== "/api/login" &&
      !options.signal?.aborted
    )
      window.dispatchEvent(new Event("vault-auth-expired"));
    throw new ApiError(
      data?.error ||
        data?.message ||
        `Request failed (${response.status}). Please try again.`,
      response.status,
    );
  }
  return data;
}

export function post<T>(path: string, data: unknown, signal?: AbortSignal) {
  return api<T>(path, { method: "POST", body: JSON.stringify(data), signal });
}

export function errorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "Something went wrong. Please try again.";
}

export function isAborted(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}
