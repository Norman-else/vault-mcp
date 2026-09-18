import type { JsonValue, SecretData } from "../shared/types";

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateFiniteNumbers(value: unknown): void {
  const pending = [value];
  while (pending.length) {
    const item = pending.pop();
    if (typeof item === "number" && !Number.isFinite(item))
      throw new Error(
        "JSON numbers must be finite. Quote very large values to preserve them as strings.",
      );
    if (Array.isArray(item)) for (const child of item) pending.push(child);
    else if (isObject(item))
      for (const child of Object.values(item)) pending.push(child);
  }
}

export function parseSecretJson(text: string): SecretData {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new Error(
      `Invalid JSON: ${error instanceof Error ? error.message : "check the syntax"}`,
    );
  }
  if (!isObject(value))
    throw new Error(
      'Secret data must be a JSON object, for example {"key": "value"}.',
    );
  validateFiniteNumbers(value);
  return value as SecretData;
}

export type ValueType =
  | "string"
  | "number"
  | "boolean"
  | "null"
  | "object"
  | "array";
export function valueType(value: JsonValue): ValueType {
  return value === null
    ? "null"
    : Array.isArray(value)
      ? "array"
      : (typeof value as ValueType);
}

export function displayValue(value: JsonValue): string {
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

export function parseTypedValue(text: string, type: ValueType): JsonValue {
  if (type === "string") return text;
  if (type === "null") return null;
  let value: JsonValue;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`Enter a valid JSON ${type}.`);
  }
  if (
    valueType(value) !== type ||
    (typeof value === "number" && !Number.isFinite(value))
  )
    throw new Error(`Value must be a ${type}.`);
  validateFiniteNumbers(value);
  return value;
}

export function parentPath(path: string): string {
  return path.replace(/\/$/, "").split("/").slice(0, -1).join("/");
}
export function formatTime(time?: string): string {
  const date = new Date(time || "");
  return Number.isNaN(date.getTime()) ? time || "—" : date.toLocaleString();
}
