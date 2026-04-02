import { FormEvent, useEffect, useMemo, useState } from "react";
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
  targetUrl: string;
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

export default function App() {
  const tauriRuntimeAvailable = hasTauriIpc();
  const [targetUrl, setTargetUrl] = useState("https://httpbin.org");
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
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [totalUrls, setTotalUrls] = useState(0);
  const [completedUrls, setCompletedUrls] = useState(0);

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
    setLoading(true);
    setError(null);
    setLogs([]);
    setSummary(null);
    setExports(null);
    setSavedPath(null);
    setTotalUrls(0);
    setCompletedUrls(0);

    const request: FullScanRequest = {
      targetUrl,
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
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
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
  ): Promise<void> {
    setError(null);
    setSavedPath(null);

    if (!tauriRuntimeAvailable) {
      downloadText(filename, mimeType, content);
      return;
    }

    try {
      const result = await invokeCommand<SaveExportResponse>("save_export", {
        request: {
          fileName: filename,
          content,
        },
      });
      setSavedPath(result.path);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <main className="app-shell">
      <section className="panel panel-hero">
        <h1>ApiHunter Desktop</h1>
        <p>
          Configure a scan profile, watch real-time progress events, and export
          reports directly from the desktop app.
        </p>
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
          <label htmlFor="targetUrl">Target URL</label>
          <input
            id="targetUrl"
            type="url"
            required
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://api.example.com"
          />

          <div className="grid-options">
            <label>
              <input
                type="checkbox"
                checked={activeChecks}
                onChange={(e) => setActiveChecks(e.target.checked)}
              />
              active checks
            </label>
            <label>
              <input
                type="checkbox"
                checked={dryRun}
                onChange={(e) => setDryRun(e.target.checked)}
              />
              dry run
            </label>
            <label>
              <input
                type="checkbox"
                checked={noDiscovery}
                onChange={(e) => setNoDiscovery(e.target.checked)}
              />
              no discovery
            </label>
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
            <div className="export-row">
              <button
                type="button"
                className="btn secondary"
                onClick={() =>
                  void saveExport(
                    "apihunter-report.json",
                    "application/json",
                    exports.prettyJson,
                  )
                }
              >
                Download JSON
              </button>
              <button
                type="button"
                className="btn secondary"
                onClick={() =>
                  void saveExport(
                    "apihunter-report.ndjson",
                    "application/x-ndjson",
                    exports.ndjson,
                  )
                }
              >
                Download NDJSON
              </button>
              <button
                type="button"
                className="btn secondary"
                onClick={() =>
                  void saveExport(
                    "apihunter-report.sarif",
                    "application/json",
                    exports.sarif,
                  )
                }
              >
                Download SARIF
              </button>
            </div>
          )}
          {savedPath && <p className="status-ok">Saved file: {savedPath}</p>}
        </section>
      )}
    </main>
  );
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
