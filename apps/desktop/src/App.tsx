import { ChangeEvent, FormEvent, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

type HealthResponse = {
  status: string;
  appVersion: string;
  scannerVersion: string;
};

type ScanToggleState = {
  cors: boolean;
  csp: boolean;
  graphql: boolean;
  apiSecurity: boolean;
  jwt: boolean;
  openapi: boolean;
  massAssignment: boolean;
  oauthOidc: boolean;
  rateLimit: boolean;
  cveTemplates: boolean;
  websocket: boolean;
};

type FullScanRequest = {
  targetUrls: string[];
  activeChecks: boolean;
  dryRun: boolean;
  noDiscovery: boolean;
  concurrency: number;
  timeoutSecs: number;
  retries: number;
  delayMs: number;
  toggles: ScanToggleState;
};

type TopCheck = {
  check: string;
  count: number;
};

type ScanSummary = {
  target: string;
  scanned: number;
  skipped: number;
  findingsTotal: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  errors: number;
  elapsedMs: number;
  topChecks: TopCheck[];
};

type ScanExports = {
  prettyJson: string;
  ndjson: string;
  sarif: string;
};

type FullScanResponse = {
  scanId: number;
  summary: ScanSummary;
  exports: ScanExports;
};

type SaveExportResponse = {
  path: string;
};

type ScanEventPayload = {
  scanId: number;
  event: string;
  message: string;
  totalUrls?: number;
  completedUrls?: number;
  url?: string;
  findings?: number;
  critical?: number;
  high?: number;
  medium?: number;
  errors?: number;
  elapsedMs?: number;
};

type TargetProgress = {
  url: string;
  status: "pending" | "completed";
  findings: number;
  critical: number;
  high: number;
  medium: number;
};

const DEFAULT_TOGGLES: ScanToggleState = {
  cors: true,
  csp: true,
  graphql: true,
  apiSecurity: true,
  jwt: true,
  openapi: true,
  massAssignment: true,
  oauthOidc: true,
  rateLimit: true,
  cveTemplates: true,
  websocket: true,
};

const TOGGLE_FIELDS: Array<{ key: keyof ScanToggleState; label: string }> = [
  { key: "cors", label: "CORS" },
  { key: "csp", label: "CSP" },
  { key: "graphql", label: "GraphQL" },
  { key: "apiSecurity", label: "API Security" },
  { key: "jwt", label: "JWT" },
  { key: "openapi", label: "OpenAPI" },
  { key: "massAssignment", label: "Mass Assignment" },
  { key: "oauthOidc", label: "OAuth/OIDC" },
  { key: "rateLimit", label: "Rate Limit" },
  { key: "cveTemplates", label: "CVE Templates" },
  { key: "websocket", label: "WebSocket" },
];

const MAX_TARGETS = 100;
const TEXT_ENCODER = new TextEncoder();

export default function App() {
  const tauriRuntimeAvailable = hasTauriIpc();
  const [targetInput, setTargetInput] = useState("https://httpbin.org");
  const [activeChecks, setActiveChecks] = useState(false);
  const [dryRun, setDryRun] = useState(true);
  const [noDiscovery, setNoDiscovery] = useState(true);
  const [concurrency, setConcurrency] = useState(4);
  const [timeoutSecs, setTimeoutSecs] = useState(15);
  const [retries, setRetries] = useState(1);
  const [delayMs, setDelayMs] = useState(0);
  const [toggles, setToggles] = useState<ScanToggleState>(DEFAULT_TOGGLES);

  const [loading, setLoading] = useState(false);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [exports, setExports] = useState<ScanExports | null>(null);
  const [savedPaths, setSavedPaths] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [totalUrls, setTotalUrls] = useState(0);
  const [completedUrls, setCompletedUrls] = useState(0);
  const [targetProgress, setTargetProgress] = useState<TargetProgress[]>([]);
  const [exportPrefix, setExportPrefix] = useState<string | null>(null);
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [savingAll, setSavingAll] = useState(false);

  useEffect(() => {
    if (!tauriRuntimeAvailable) {
      return () => {};
    }

    let disposed = false;
    let unlisten: (() => void) | undefined;

    listen<ScanEventPayload>("scan-event", (event) => {
      const payload = event.payload;
      setLogs((prev) => {
        const next = [...prev, `[${payload.event}] ${payload.message}`];
        return next.slice(-250);
      });
      if (typeof payload.totalUrls === "number") {
        setTotalUrls(payload.totalUrls);
      }
      if (typeof payload.completedUrls === "number") {
        setCompletedUrls(payload.completedUrls);
      }
      if (payload.url && payload.event === "progress") {
        setTargetProgress((prev) => {
          const idx = prev.findIndex((item) => item.url === payload.url);
          const updated: TargetProgress = {
            url: payload.url ?? "",
            status: "completed",
            findings: payload.findings ?? 0,
            critical: payload.critical ?? 0,
            high: payload.high ?? 0,
            medium: payload.medium ?? 0,
          };
          if (idx === -1) {
            return [...prev, updated];
          }
          const next = [...prev];
          next[idx] = updated;
          return next;
        });
      }
    })
      .then((fn) => {
        if (disposed) {
          fn();
          return;
        }
        unlisten = fn;
      })
      .catch((err) => {
        if (!disposed) {
          setError(String(err));
        }
      });

    return () => {
      disposed = true;
      if (unlisten) {
        unlisten();
        unlisten = undefined;
      }
    };
  }, [tauriRuntimeAvailable]);

  const progressPct = useMemo(() => {
    if (totalUrls <= 0) return 0;
    return Math.min(100, Math.round((completedUrls / totalUrls) * 100));
  }, [completedUrls, totalUrls]);
  const parsedTargets = useMemo(() => parseTargetsText(targetInput), [targetInput]);
  const invalidTargets = useMemo(
    () => parsedTargets.filter((target) => !isValidHttpUrl(target)),
    [parsedTargets],
  );
  const targetCount = parsedTargets.length;
  const validTargetCount = targetCount - invalidTargets.length;
  const effectiveParallel = useMemo(() => {
    if (validTargetCount <= 0) {
      return 0;
    }
    return Math.min(Math.max(1, concurrency), validTargetCount);
  }, [concurrency, validTargetCount]);
  const exportStats = useMemo(() => {
    if (!exports) {
      return null;
    }
    return {
      json: TEXT_ENCODER.encode(exports.prettyJson).length,
      ndjson: TEXT_ENCODER.encode(exports.ndjson).length,
      sarif: TEXT_ENCODER.encode(exports.sarif).length,
    };
  }, [exports]);

  async function fetchHealth() {
    setError(null);
    try {
      const result = await invokeCommand<HealthResponse>("health_check");
      setHealth(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function runFullScan(e: FormEvent) {
    e.preventDefault();
    const targetUrls = parsedTargets;
    if (targetUrls.length === 0) {
      setError("Add at least one target URL.");
      return;
    }
    if (targetUrls.length > MAX_TARGETS) {
      setError(`A maximum of ${MAX_TARGETS} targets is allowed per scan.`);
      return;
    }
    if (invalidTargets.length > 0) {
      setError(
        `Found ${invalidTargets.length} invalid target URL(s). Example: ${invalidTargets[0]}`,
      );
      return;
    }

    const startedAt = Date.now();
    setLoading(true);
    setError(null);
    setLogs([]);
    setSummary(null);
    setExports(null);
    setSavedPaths([]);
    setTotalUrls(0);
    setCompletedUrls(0);
    setExportPrefix(null);
    setTargetProgress(
      targetUrls.map((url) => ({
        url,
        status: "pending",
        findings: 0,
        critical: 0,
        high: 0,
        medium: 0,
      })),
    );

    const request: FullScanRequest = {
      targetUrls,
      activeChecks,
      dryRun,
      noDiscovery,
      concurrency: Math.max(1, concurrency),
      timeoutSecs: Math.max(1, timeoutSecs),
      retries: Math.max(0, retries),
      delayMs: Math.max(0, delayMs),
      toggles,
    };

    try {
      const result = await invokeCommand<FullScanResponse>("run_full_scan", {
        request,
      });
      setSummary(result.summary);
      setExports(result.exports);
      setExportPrefix(
        buildExportPrefix(result.scanId, targetUrls.length, startedAt),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function importTargetsFromCsv(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) {
      return;
    }

    try {
      const text = await file.text();
      const csvTargets = parseTargetsCsv(text);
      if (csvTargets.length === 0) {
        setError("No targets were detected in the CSV file.");
        return;
      }

      const merged = dedupeTargets([
        ...parseTargetsText(targetInput),
        ...csvTargets,
      ]);
      if (merged.length > MAX_TARGETS) {
        setError(
          `CSV import would exceed ${MAX_TARGETS} targets. Remove some entries first.`,
        );
        return;
      }

      setTargetInput(merged.join("\n"));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      e.target.value = "";
    }
  }

  async function invokeCommand<T>(
    command: string,
    args?: Record<string, unknown>,
  ): Promise<T> {
    if (!tauriRuntimeAvailable) {
      throw new Error(
        "Tauri IPC is unavailable. Start the desktop app with `npm run tauri dev` or the built binary.",
      );
    }
    return invoke<T>(command, args);
  }

  function setToggleField(field: keyof ScanToggleState, value: boolean) {
    setToggles((prev) => ({ ...prev, [field]: value }));
  }

  function downloadText(filename: string, mimeType: string, content: string) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function saveExport(
    filename: string,
    mimeType: string,
    content: string,
  ): Promise<string> {
    if (!tauriRuntimeAvailable) {
      downloadText(filename, mimeType, content);
      return filename;
    }

    const result = await invokeCommand<SaveExportResponse>("save_export", {
      request: {
        fileName: filename,
        content,
      },
    });
    return result.path;
  }

  async function saveSingleExport(
    key: "json" | "ndjson" | "sarif",
    filename: string,
    mimeType: string,
    content: string,
  ): Promise<void> {
    setError(null);
    setSavedPaths([]);
    setSavingKey(key);

    try {
      const path = await saveExport(filename, mimeType, content);
      setSavedPaths([path]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSavingKey(null);
    }
  }

  async function saveAllExports(): Promise<void> {
    if (!exports) {
      return;
    }

    setSavingAll(true);
    setSavingKey(null);
    setError(null);
    setSavedPaths([]);

    const jsonName = getExportFilename(exportPrefix, "json");
    const ndjsonName = getExportFilename(exportPrefix, "ndjson");
    const sarifName = getExportFilename(exportPrefix, "sarif");

    try {
      const outputs = await Promise.all([
        saveExport(jsonName, "application/json", exports.prettyJson),
        saveExport(ndjsonName, "application/x-ndjson", exports.ndjson),
        saveExport(sarifName, "application/json", exports.sarif),
      ]);
      setSavedPaths(outputs);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSavingAll(false);
    }
  }

  return (
    <main className="app-shell">
      <section className="panel panel-hero">
        <h1 className="hero-title">
          <BrandSymbol />
          <span>ApiHunter Desktop</span>
        </h1>
        <p>
          Configure a scan profile, watch real-time progress events, and export
          reports directly from the desktop app.
        </p>
        <div className="hero-metrics">
          <span className="metric-chip">
            targets: {validTargetCount}/{MAX_TARGETS}
          </span>
          <span className="metric-chip">parallel workers: {effectiveParallel}</span>
          <span className="metric-chip">
            exports: {exportStats ? "ready" : "pending"}
          </span>
        </div>
        {!tauriRuntimeAvailable && (
          <p className="status-error">
            Tauri runtime not detected. Use <code>npm run tauri dev</code> or
            launch the built desktop binary.
          </p>
        )}
      </section>

      <section className="panel">
        <h2>Connection</h2>
        <button type="button" className="btn secondary" onClick={fetchHealth}>
          Check Backend Health
        </button>
        {health && (
          <div className="status-ok" role="status">
            <p>status: {health.status}</p>
            <p>app version: {health.appVersion}</p>
            <p>scanner version: {health.scannerVersion}</p>
          </div>
        )}
      </section>

      <section className="panel">
        <h2>Full Scan</h2>
        <form onSubmit={runFullScan} className="scan-form">
          <label htmlFor="targetInput">Targets (max 100)</label>
          <textarea
            id="targetInput"
            rows={6}
            required
            value={targetInput}
            onChange={(e) => setTargetInput(e.target.value)}
            placeholder={
              "https://api.example.com\nhttps://httpbin.org\nhttps://example.org/v1"
            }
          />
          <div className="target-toolbar">
            <label className="csv-import">
              Load CSV
              <input
                type="file"
                accept=".csv,text/csv"
                onChange={importTargetsFromCsv}
              />
            </label>
            <span
              className={
                targetCount > MAX_TARGETS ? "target-count-error" : "muted"
              }
            >
              {targetCount}/{MAX_TARGETS} targets
            </span>
          </div>
          <p className="muted">
            Enter one URL per line (or comma separated). CSV import appends to
            the same list.
          </p>
          <div className="field-help">
            <p>
              URL separators: newline, comma (<code>,</code>) or semicolon (
              <code>;</code>).
            </p>
            <p>
              CSV format: values in any column are accepted. Header names like{" "}
              <code>url</code>, <code>target</code>, <code>endpoint</code> are
              ignored automatically.
            </p>
          </div>
          {invalidTargets.length > 0 && (
            <p className="status-error compact">
              Invalid targets detected: {invalidTargets.length}. Example:{" "}
              {invalidTargets[0]}
            </p>
          )}

          <div className="grid-options">
            <div className="option-card">
              <label title="Send active test probes (for example authz/mutation/rate-limit checks).">
                <input
                  type="checkbox"
                  checked={activeChecks}
                  onChange={(e) => setActiveChecks(e.target.checked)}
                />
                active checks
              </label>
              <p className="muted">
                Enables probe-based testing beyond passive analysis. More
                coverage, potentially more intrusive.
              </p>
            </div>
            <div className="option-card">
              <label title="Plan and simulate active checks without sending state-changing payloads where supported.">
                <input
                  type="checkbox"
                  checked={dryRun}
                  onChange={(e) => setDryRun(e.target.checked)}
                />
                dry run
              </label>
              <p className="muted">
                Safer mode for active checks. Useful for first pass on production-like targets.
              </p>
            </div>
            <div className="option-card">
              <label title="Skip endpoint discovery and only scan the URLs you provided.">
                <input
                  type="checkbox"
                  checked={noDiscovery}
                  onChange={(e) => setNoDiscovery(e.target.checked)}
                />
                no discovery
              </label>
              <p className="muted">
                Faster and more predictable scans for large target lists. Turn off to crawl for
                additional endpoints.
              </p>
            </div>
          </div>

          <div className="grid-numbers">
            <label>
              concurrency
              <input
                type="number"
                min={1}
                value={concurrency}
                onChange={(e) => setConcurrency(Number(e.target.value))}
              />
            </label>
            <label>
              timeout secs
              <input
                type="number"
                min={1}
                value={timeoutSecs}
                onChange={(e) => setTimeoutSecs(Number(e.target.value))}
              />
            </label>
            <label>
              retries
              <input
                type="number"
                min={0}
                value={retries}
                onChange={(e) => setRetries(Number(e.target.value))}
              />
            </label>
            <label>
              delay ms
              <input
                type="number"
                min={0}
                value={delayMs}
                onChange={(e) => setDelayMs(Number(e.target.value))}
              />
            </label>
          </div>

          <fieldset className="toggle-grid">
            <legend>Scanner toggles</legend>
            {TOGGLE_FIELDS.map((item) => (
              <label key={item.key}>
                <input
                  type="checkbox"
                  checked={toggles[item.key]}
                  onChange={(e) => setToggleField(item.key, e.target.checked)}
                />
                {item.label}
              </label>
            ))}
          </fieldset>

          <button type="submit" className="btn" disabled={loading}>
            {loading ? "Scanning..." : "Run Full Scan"}
          </button>
        </form>

        {error && <p className="status-error">{error}</p>}
      </section>

      <section className="panel">
        <h2>Live Progress</h2>
        <p>
          {totalUrls > 0
            ? `${completedUrls}/${totalUrls} URLs completed (${progressPct}%)`
            : "Waiting for scan start..."}
        </p>
        <div className="progress-track" aria-hidden="true">
          <div className="progress-fill" style={{ width: `${progressPct}%` }} />
        </div>
        {targetProgress.length > 0 && (
          <div className="target-progress-wrap">
            <div className="target-progress-header">
              <p className="muted">
                Completed: {completedUrls} | Remaining:{" "}
                {Math.max(0, totalUrls - completedUrls)} | Concurrency:{" "}
                {effectiveParallel}
              </p>
            </div>
            <div className="target-progress-grid">
              {targetProgress.map((item) => (
                <article
                  key={item.url}
                  className={`target-progress-card ${item.status}`}
                >
                  <p className="target-url" title={item.url}>
                    {item.url}
                  </p>
                  <p className="muted">
                    {item.status === "completed"
                      ? `${item.findings} findings (C:${item.critical} H:${item.high} M:${item.medium})`
                      : "queued/running"}
                  </p>
                </article>
              ))}
            </div>
          </div>
        )}
        <div className="log-view">
          {logs.length === 0 ? (
            <p className="muted">No events yet.</p>
          ) : (
            logs.map((line, idx) => <p key={`${idx}-${line}`}>{line}</p>)
          )}
        </div>
      </section>

      {summary && (
        <section className="panel">
          <h2>Results</h2>
          <div className="result-grid">
            <article className="result-card">
              <h3>Summary</h3>
              <p>Target: {summary.target}</p>
              <p>Scanned: {summary.scanned}</p>
              <p>Skipped: {summary.skipped}</p>
              <p>Elapsed: {summary.elapsedMs} ms</p>
              <p>Errors: {summary.errors}</p>
            </article>

            <article className="result-card">
              <h3>Findings</h3>
              <p>Total: {summary.findingsTotal}</p>
              <p>Critical: {summary.critical}</p>
              <p>High: {summary.high}</p>
              <p>Medium: {summary.medium}</p>
              <p>Low: {summary.low}</p>
              <p>Info: {summary.info}</p>
            </article>

            <article className="result-card">
              <h3>Top checks</h3>
              {summary.topChecks.length === 0 ? (
                <p>No findings reported.</p>
              ) : (
                <ul>
                  {summary.topChecks.map((entry) => (
                    <li key={entry.check}>
                      {entry.check}: {entry.count}
                    </li>
                  ))}
                </ul>
              )}
            </article>
          </div>

          {exports && (
            <div className="export-row exports-grid">
              <button
                type="button"
                className="btn"
                disabled={savingAll || savingKey !== null}
                onClick={() => void saveAllExports()}
              >
                {savingAll ? "Saving all..." : "Save All Reports"}
              </button>
              <button
                type="button"
                className="btn secondary"
                disabled={savingAll || savingKey !== null}
                onClick={() =>
                  void saveSingleExport(
                    "json",
                    getExportFilename(exportPrefix, "json"),
                    "application/json",
                    exports.prettyJson,
                  )
                }
              >
                {savingKey === "json"
                  ? "Saving JSON..."
                  : `Save JSON (${formatBytes(exportStats?.json ?? 0)})`}
              </button>
              <button
                type="button"
                className="btn secondary"
                disabled={savingAll || savingKey !== null}
                onClick={() =>
                  void saveSingleExport(
                    "ndjson",
                    getExportFilename(exportPrefix, "ndjson"),
                    "application/x-ndjson",
                    exports.ndjson,
                  )
                }
              >
                {savingKey === "ndjson"
                  ? "Saving NDJSON..."
                  : `Save NDJSON (${formatBytes(exportStats?.ndjson ?? 0)})`}
              </button>
              <button
                type="button"
                className="btn secondary"
                disabled={savingAll || savingKey !== null}
                onClick={() =>
                  void saveSingleExport(
                    "sarif",
                    getExportFilename(exportPrefix, "sarif"),
                    "application/json",
                    exports.sarif,
                  )
                }
              >
                {savingKey === "sarif"
                  ? "Saving SARIF..."
                  : `Save SARIF (${formatBytes(exportStats?.sarif ?? 0)})`}
              </button>
              <p className="muted">
                For high target counts, export size can grow quickly. Use NDJSON
                for stream-style ingestion and Save All for consistent per-run
                filenames.
              </p>
            </div>
          )}
          {savedPaths.length > 0 && (
            <div className="status-ok">
              <p>Saved files:</p>
              <ul className="saved-paths">
                {savedPaths.map((path) => (
                  <li key={path}>{path}</li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}
    </main>
  );
}

function BrandSymbol() {
  return (
    <svg
      aria-hidden="true"
      className="brand-symbol"
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <rect x="6" y="6" width="52" height="52" rx="12" fill="#0F4F95" />
      <path
        d="M32 14L46 20V31C46 41 39.2 49.8 32 52C24.8 49.8 18 41 18 31V20L32 14Z"
        fill="#7CC8FF"
      />
      <circle cx="32" cy="31" r="8" fill="#0F4F95" />
      <path d="M32 21V41M22 31H42" stroke="#FFFFFF" strokeWidth="3" />
    </svg>
  );
}

function parseTargetsText(input: string): string[] {
  const tokens = input
    .split(/[\n,;]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  return dedupeTargets(tokens);
}

function parseTargetsCsv(csvText: string): string[] {
  const rows = csvText.split(/\r?\n/);
  const targets: string[] = [];

  rows.forEach((row, rowIdx) => {
    const columns = row
      .split(",")
      .map((column) => column.trim().replace(/^"(.*)"$/, "$1"))
      .filter((column) => column.length > 0);

    if (columns.length === 0) {
      return;
    }

    for (const value of columns) {
      const lower = value.toLowerCase();
      if (
        rowIdx === 0 &&
        (lower === "url" ||
          lower === "urls" ||
          lower === "target" ||
          lower === "targets" ||
          lower === "endpoint" ||
          lower === "endpoints")
      ) {
        continue;
      }
      targets.push(value);
    }
  });

  return dedupeTargets(targets);
}

function dedupeTargets(values: string[]): string[] {
  const seen = new Set<string>();
  const targets: string[] = [];
  for (const raw of values) {
    const value = raw.trim();
    if (value.length === 0 || seen.has(value)) {
      continue;
    }
    seen.add(value);
    targets.push(value);
  }
  return targets;
}

function isValidHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unitIdx = 0;
  while (value >= 1024 && unitIdx < units.length - 1) {
    value /= 1024;
    unitIdx += 1;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unitIdx]}`;
}

function getExportFilename(
  prefix: string | null,
  format: "json" | "ndjson" | "sarif",
): string {
  const safePrefix =
    prefix ??
    `apihunter-scan-${new Date()
      .toISOString()
      .replace(/[-:]/g, "")
      .replace(/\..+$/, "")
      .replace("T", "-")}`;
  return `${safePrefix}.${format}`;
}

function buildExportPrefix(
  scanId: number,
  targetCount: number,
  startedAtMs: number,
): string {
  const startedAt = new Date(startedAtMs);
  const stamp = startedAt
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\..+$/, "")
    .replace("T", "-");
  return `apihunter-scan-${scanId}-${targetCount}targets-${stamp}`;
}

function hasTauriIpc(): boolean {
  if (typeof window === "undefined") {
    return false;
  }

  const internals = (
    window as typeof window & {
      __TAURI_INTERNALS__?: { invoke?: unknown };
    }
  ).__TAURI_INTERNALS__;

  return typeof internals?.invoke === "function";
}
