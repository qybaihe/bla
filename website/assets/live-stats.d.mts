export interface ChallengeRow {
  readonly id: string;
  readonly name: string;
  readonly status: string;
  readonly kind: "current" | "snapshot" | "archived" | "other";
  readonly path: string | null;
}

export type ReadmeParse =
  | { readonly ok: true; readonly current: ChallengeRow; readonly rows: readonly ChallengeRow[] }
  | { readonly ok: false; readonly reason: string; readonly rows: readonly ChallengeRow[] };

export interface SealCommitment {
  readonly product: string;
  readonly blaVersion: string;
  readonly label: string;
  readonly flagSha256: string;
}

export interface FetchFailure {
  readonly ok: false;
  readonly errorKind: string;
  readonly status?: number;
  readonly retryAt?: number;
}

export interface FetchResponse {
  readonly ok: boolean;
  readonly status: number;
  readonly headers?: { get(name: string): string | null };
  json(): Promise<unknown>;
}

export type FetchImpl = (url: string, init?: RequestInit) => Promise<FetchResponse>;

export const STAR_ENDPOINT: string;
export const CONTENT_PREFIX: string;
export const STAR_SOURCE_LABEL: string;
export const README_PATH: string;
export const README_SOURCE_LABEL: string;
export const STAR_REFRESH_MS: number;
export const CRACKME_REFRESH_MS: number;
export const FETCH_FRESH_MS: number;
export const FETCH_TIMEOUT_MS: number;
export const POLL_CHECK_MS: number;
export const MAX_STAR_COUNT: number;
export const GH_HEADERS: { readonly Accept: string; readonly "X-GitHub-Api-Version": string };

export function formatExactCount(value: number): string | null;
export function readStarCount(payload: unknown): number | null;
export function formatUtcMinute(ms: number): string | null;
export function fillTemplate(template: string, vars?: Record<string, string | null | undefined>): string;
export function shouldFetch(input: {
  readonly now: number;
  readonly fetchedAt?: number;
  readonly visible: boolean;
  readonly reason: "open" | "timer" | "visible";
  readonly freshMs: number;
  readonly intervalMs: number;
  readonly retryAt?: number;
}): boolean;
export function contentUrl(path: string): string | null;
export function safeGithubUrl(url: string): string | null;
export function versionTreeUrl(dirPath: string): string | null;
export function sealPathFor(dirPath: string): string | null;
export function decodeBase64Utf8(content: string): string | null;
export function parseChallengeReadme(markdown: string): ReadmeParse;
export function readSealCommitment(value: unknown): SealCommitment | null;
export function fetchJson(
  url: string,
  input: { readonly fetchImpl: FetchImpl; readonly timeoutMs: number; readonly now: number },
): Promise<{ readonly ok: true; readonly payload: unknown } | FetchFailure>;
export function loadStars(input: {
  readonly fetchImpl: FetchImpl;
  readonly timeoutMs?: number;
  readonly now: number;
}): Promise<{ readonly ok: true; readonly count: number; readonly fetchedAt: number } | FetchFailure>;
export function loadGithubText(
  path: string,
  input: { readonly fetchImpl: FetchImpl; readonly timeoutMs: number; readonly now: number },
): Promise<{ readonly ok: true; readonly text: string; readonly htmlUrl: string | null } | FetchFailure>;
export function loadCrackmeStatus(input: {
  readonly fetchImpl: FetchImpl;
  readonly timeoutMs?: number;
  readonly now: number;
}): Promise<
  | {
      readonly ok: true;
      readonly fetchedAt: number;
      readonly current: ChallengeRow;
      readonly rows: readonly ChallengeRow[];
      readonly seal: SealCommitment | null;
      readonly sealError: string | null;
      readonly readmeUrl: string | null;
    }
  | FetchFailure
>;
export function readStoredRecord(raw: string): Record<string, unknown> | null;
