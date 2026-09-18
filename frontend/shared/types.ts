export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };
export type SecretData = Record<string, JsonValue>;
export interface EnvironmentInfo {
  id: string;
  label: string;
  kvMount: string;
  databaseMount: string;
}
export interface SecretEntry {
  name: string;
  path: string;
  type: "folder" | "secret";
}
export interface SecretMetadata {
  version: number;
  created_time: string;
  deleted_time: string;
  destroyed: boolean;
}
export interface SecretResult {
  success: true;
  path: string;
  data: SecretData;
  metadata: Partial<SecretMetadata>;
}
export interface VersionInfo {
  version: number;
  created_time: string;
  deleted_time: string;
  destroyed: boolean;
}
export interface SearchResult {
  path: string;
  matching_keys: string[];
  match_type: "path" | "key";
}
export interface DatabaseCredentials {
  success: true;
  role: string;
  username: string;
  password: string;
  lease_id: string;
  lease_duration: number;
  renewable: boolean;
}
