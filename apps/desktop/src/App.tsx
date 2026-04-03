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
  apiVersioning: boolean;
  grpcProtobuf: boolean;
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
  responseDiffDeep: boolean;
  noDiscovery: boolean;
  noFilter: boolean;
  filterTimeout: number;
  maxEndpoints: number;
  concurrency: number;
  timeoutSecs: number;
  retries: number;
  delayMs: number;
  wafEvasion: boolean;
  userAgents: string[];
  perHostClients: boolean;
  adaptiveConcurrency: boolean;
  headers: string[];
  cookies: string[];
  proxy: string | null;
  oastBase: string | null;
  dangerAcceptInvalidCerts: boolean;
  authBearer: string | null;
  authBasic: string | null;
  unauthStripHeaders: string[];
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
  apiVersioning: true,
  grpcProtobuf: true,
  massAssignment: true,
  oauthOidc: true,
  rateLimit: true,
  cveTemplates: true,
  websocket: true,
};

const TOGGLE_FIELDS: Array<{
  key: keyof ScanToggleState;
  label: string;
  hint: string;
}> = [
  { key: "cors", label: "CORS", hint: "Origin and credential policy checks." },
  { key: "csp", label: "CSP", hint: "Header hardening and policy weakness signals." },
  { key: "graphql", label: "GraphQL", hint: "Introspection and schema leakage checks." },
  {
    key: "apiSecurity",
    label: "API Security",
    hint: "IDOR/BOLA, headers, debug/admin, SSRF and gateway checks.",
  },
  { key: "jwt", label: "JWT", hint: "Token weakness and alg confusion checks." },
  { key: "openapi", label: "OpenAPI", hint: "Spec exposure and risky operation checks." },
  {
    key: "apiVersioning",
    label: "API Versioning",
    hint: "Version drift and deprecation signals.",
  },
  {
    key: "grpcProtobuf",
    label: "gRPC/Protobuf",
    hint: "gRPC transport and reflection/health surface checks.",
  },
  {
    key: "massAssignment",
    label: "Mass Assignment",
    hint: "Mutation field injection checks (active checks).",
  },
  {
    key: "oauthOidc",
    label: "OAuth/OIDC",
    hint: "Redirect, state and metadata security checks.",
  },
  { key: "rateLimit", label: "Rate Limit", hint: "Burst and bypass limiter probes." },
  {
    key: "cveTemplates",
    label: "CVE Templates",
    hint: "Template-driven active vulnerability probes.",
  },
  { key: "websocket", label: "WebSocket", hint: "Upgrade/origin and auth boundary checks." },
];

const MAX_TARGETS = 100;
const MAX_CSV_FILE_BITS = 5 * 1024;
const MAX_CSV_FILE_BYTES = Math.floor(MAX_CSV_FILE_BITS / 8);
const MAX_TARGET_INPUT_CHARS = 32_000;
const TEXT_ENCODER = new TextEncoder();
const RUNTIME_LIMIT_RULES = {
  concurrency: { min: 1, max: 512 },
  timeoutSecs: { min: 1, max: 600 },
  retries: { min: 0, max: 20 },
  delayMs: { min: 0, max: 60_000 },
  maxEndpoints: { min: 0, max: 100_000 },
  filterTimeout: { min: 1, max: 120 },
} as const;

type RuntimeLimitField = keyof typeof RUNTIME_LIMIT_RULES;

function clampRuntimeValue(value: number, field: RuntimeLimitField): number {
  const { min, max } = RUNTIME_LIMIT_RULES[field];
  if (!Number.isFinite(value)) {
    return min;
  }
  const normalized = Math.trunc(value);
  return Math.min(max, Math.max(min, normalized));
}

function sanitizeRuntimeInput(raw: string, field: RuntimeLimitField): number {
  const digitsOnly = raw.replace(/[^\d]/g, "");
  if (digitsOnly.length === 0) {
    return RUNTIME_LIMIT_RULES[field].min;
  }
  const withoutLeadingZeros = digitsOnly.replace(/^0+(?=\d)/, "");
  const parsed = Number.parseInt(withoutLeadingZeros, 10);
  return clampRuntimeValue(parsed, field);
}

export default function App() {
  const tauriRuntimeAvailable = hasTauriIpc();
  const [targetInput, setTargetInput] = useState("https://httpbin.org");
  const [targetInputNotice, setTargetInputNotice] = useState<string | null>(null);
  const [csvImportError, setCsvImportError] = useState<string | null>(null);
  const [activeChecks, setActiveChecks] = useState(false);
  const [dryRun, setDryRun] = useState(true);
  const [responseDiffDeep, setResponseDiffDeep] = useState(false);
  const [noDiscovery, setNoDiscovery] = useState(true);
  const [noFilter, setNoFilter] = useState(false);
  const [filterTimeout, setFilterTimeout] = useState(3);
  const [maxEndpoints, setMaxEndpoints] = useState(50);
  const [concurrency, setConcurrency] = useState(4);
  const [timeoutSecs, setTimeoutSecs] = useState(15);
  const [retries, setRetries] = useState(1);
  const [delayMs, setDelayMs] = useState(0);
  const [wafEvasion, setWafEvasion] = useState(false);
  const [perHostClients, setPerHostClients] = useState(false);
  const [adaptiveConcurrency, setAdaptiveConcurrency] = useState(false);
  const [proxy, setProxy] = useState("");
  const [oastBase, setOastBase] = useState("");
  const [dangerAcceptInvalidCerts, setDangerAcceptInvalidCerts] = useState(false);
  const [headersInput, setHeadersInput] = useState("");
  const [cookiesInput, setCookiesInput] = useState("");
  const [authBearer, setAuthBearer] = useState("");
  const [authBasic, setAuthBasic] = useState("");
  const [unauthStripHeadersInput, setUnauthStripHeadersInput] = useState("");
  const [userAgentsInput, setUserAgentsInput] = useState("");
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

  function handleTargetInputChange(raw: string) {
    const sanitized = sanitizeTargetTextareaInput(raw);
    setTargetInput(sanitized.value);
    if (sanitized.truncated) {
      setTargetInputNotice(
        `Target input was truncated at ${MAX_TARGET_INPUT_CHARS.toLocaleString()} characters.`,
      );
    } else {
      setTargetInputNotice(null);
    }
  }

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
    if (!noFilter && filterTimeout < 1) {
      setError("Filter timeout must be at least 1 second when filtering is enabled.");
      return;
    }
    if (authBasic.trim().length > 0 && !authBasic.includes(":")) {
      setError("auth basic must use USER:PASS format.");
      return;
    }
    if (oastBase.trim().length > 0) {
      try {
        const parsed = new URL(oastBase.trim());
        if (!(parsed.protocol === "http:" || parsed.protocol === "https:")) {
          setError("OAST callback base must use http or https.");
          return;
        }
      } catch {
        setError("OAST callback base must be a valid absolute URL.");
        return;
      }
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
      responseDiffDeep,
      noDiscovery,
      noFilter,
      filterTimeout: clampRuntimeValue(filterTimeout, "filterTimeout"),
      maxEndpoints: clampRuntimeValue(maxEndpoints, "maxEndpoints"),
      concurrency: clampRuntimeValue(concurrency, "concurrency"),
      timeoutSecs: clampRuntimeValue(timeoutSecs, "timeoutSecs"),
      retries: clampRuntimeValue(retries, "retries"),
      delayMs: clampRuntimeValue(delayMs, "delayMs"),
      wafEvasion,
      userAgents: parseLineList(userAgentsInput),
      perHostClients,
      adaptiveConcurrency,
      headers: parseLineList(headersInput),
      cookies: parseLineList(cookiesInput),
      proxy: proxy.trim().length > 0 ? proxy.trim() : null,
      oastBase: oastBase.trim().length > 0 ? oastBase.trim() : null,
      dangerAcceptInvalidCerts,
      authBearer: authBearer.trim().length > 0 ? authBearer.trim() : null,
      authBasic: authBasic.trim().length > 0 ? authBasic.trim() : null,
      unauthStripHeaders: parseTokenList(unauthStripHeadersInput),
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
    setCsvImportError(null);
    if (file.size > MAX_CSV_FILE_BYTES) {
      setCsvImportError(
        `CSV file is too large. Maximum supported size is ${MAX_CSV_FILE_BITS.toLocaleString()} bits (${MAX_CSV_FILE_BYTES.toLocaleString()} bytes).`,
      );
      e.target.value = "";
      return;
    }

    try {
      const text = await file.text();
      const csvTargets = parseTargetsCsv(text);
      if (csvTargets.length === 0) {
        setCsvImportError("No targets were detected in the CSV file.");
        return;
      }

      const merged = dedupeTargets([
        ...parseTargetsText(targetInput),
        ...csvTargets,
      ]);
      if (merged.length > MAX_TARGETS) {
        setCsvImportError(
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

  function applyPreset(mode: "quick" | "balanced" | "deep") {
    const allScanners = { ...DEFAULT_TOGGLES };
    if (mode === "quick") {
      setActiveChecks(false);
      setDryRun(true);
      setResponseDiffDeep(false);
      setNoDiscovery(true);
      setNoFilter(false);
      setFilterTimeout(3);
      setMaxEndpoints(40);
      setConcurrency(4);
      setTimeoutSecs(12);
      setRetries(1);
      setDelayMs(0);
      setWafEvasion(false);
      setPerHostClients(false);
      setAdaptiveConcurrency(false);
      setToggles({
        ...allScanners,
        massAssignment: false,
        oauthOidc: false,
        rateLimit: false,
        cveTemplates: false,
        websocket: false,
      });
      return;
    }

    if (mode === "balanced") {
      setActiveChecks(true);
      setDryRun(true);
      setResponseDiffDeep(true);
      setNoDiscovery(false);
      setNoFilter(false);
      setFilterTimeout(3);
      setMaxEndpoints(80);
      setConcurrency(5);
      setTimeoutSecs(15);
      setRetries(1);
      setDelayMs(50);
      setWafEvasion(false);
      setPerHostClients(true);
      setAdaptiveConcurrency(false);
      setToggles(allScanners);
      return;
    }

    setActiveChecks(true);
    setDryRun(false);
    setResponseDiffDeep(true);
    setNoDiscovery(false);
    setNoFilter(false);
    setFilterTimeout(4);
    setMaxEndpoints(0);
    setConcurrency(6);
    setTimeoutSecs(20);
    setRetries(2);
    setDelayMs(100);
    setWafEvasion(true);
    setPerHostClients(true);
    setAdaptiveConcurrency(true);
    setToggles(allScanners);
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
            onChange={(e) => handleTargetInputChange(e.target.value)}
            onBlur={() => setTargetInput(parseTargetsText(targetInput).join("\n"))}
            placeholder={
              "https://api.example.com\nhttps://httpbin.org\nhttps://example.org/v1"
            }
          />
          {targetInputNotice && (
            <p className="status-error compact">{targetInputNotice}</p>
          )}
          <div className="target-toolbar">
            <label className="csv-import">
              Load CSV
              <span className="csv-limit-label">
                Max upload: {MAX_CSV_FILE_BITS.toLocaleString()} bits
              </span>
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
          {csvImportError && (
            <p className="status-error compact">{csvImportError}</p>
          )}
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
              ignored automatically. Max CSV size: <code>5,120 bits (640 bytes)</code>.
            </p>
          </div>
          <div className="preset-row">
            <p className="muted">Start with a preset profile:</p>
            <div className="preset-buttons">
              <button
                type="button"
                className="btn secondary preset-btn"
                onClick={() => applyPreset("quick")}
              >
                Quick Passive
              </button>
              <button
                type="button"
                className="btn secondary preset-btn"
                onClick={() => applyPreset("balanced")}
              >
                Balanced (Recommended)
              </button>
              <button
                type="button"
                className="btn secondary preset-btn"
                onClick={() => applyPreset("deep")}
              >
                Deep Active
              </button>
            </div>
          </div>
          {invalidTargets.length > 0 && (
            <p className="status-error compact">
              Invalid targets detected: {invalidTargets.length}. Example:{" "}
              {invalidTargets[0]}
            </p>
          )}

          <h3 className="form-section-title">1) Safety and Scan Behavior</h3>
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
              <label title="Enable deeper API response drift probes (extra query/header variants).">
                <input
                  type="checkbox"
                  checked={responseDiffDeep}
                  onChange={(e) => setResponseDiffDeep(e.target.checked)}
                />
                response diff deep
              </label>
              <p className="muted">
                Adds deeper variant-based response comparison in API versioning checks.
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
            <div className="option-card">
              <label title="Skip the pre-scan accessibility check and scan all provided targets directly.">
                <input
                  type="checkbox"
                  checked={noFilter}
                  onChange={(e) => setNoFilter(e.target.checked)}
                />
                no filter
              </label>
              <p className="muted">
                Disables reachability pre-check. Use this for strict target sets where blocked URLs
                should still be attempted.
              </p>
            </div>
            <div className="option-card">
              <label title="Allow self-signed/invalid TLS certificates (dangerous).">
                <input
                  type="checkbox"
                  checked={dangerAcceptInvalidCerts}
                  onChange={(e) => setDangerAcceptInvalidCerts(e.target.checked)}
                />
                accept invalid TLS certs
              </label>
              <p className="muted">
                Use only in controlled environments. This lowers transport security validation.
              </p>
            </div>
          </div>

          <h3 className="form-section-title">2) Runtime Limits</h3>
          <p className="runtime-limits-help">
            Tune speed and stability. These values apply scan-wide and stay aligned across screen sizes.
          </p>
          <div className="grid-numbers">
            <label className="runtime-field">
              <span className="runtime-label">concurrency</span>
              <input
                type="number"
                min={RUNTIME_LIMIT_RULES.concurrency.min}
                max={RUNTIME_LIMIT_RULES.concurrency.max}
                step={1}
                inputMode="numeric"
                value={concurrency}
                onChange={(e) =>
                  setConcurrency(sanitizeRuntimeInput(e.target.value, "concurrency"))
                }
                onBlur={() =>
                  setConcurrency(clampRuntimeValue(concurrency, "concurrency"))
                }
              />
            </label>
            <label className="runtime-field">
              <span className="runtime-label">timeout (s)</span>
              <input
                type="number"
                min={RUNTIME_LIMIT_RULES.timeoutSecs.min}
                max={RUNTIME_LIMIT_RULES.timeoutSecs.max}
                step={1}
                inputMode="numeric"
                value={timeoutSecs}
                onChange={(e) =>
                  setTimeoutSecs(sanitizeRuntimeInput(e.target.value, "timeoutSecs"))
                }
                onBlur={() =>
                  setTimeoutSecs(clampRuntimeValue(timeoutSecs, "timeoutSecs"))
                }
              />
            </label>
            <label className="runtime-field">
              <span className="runtime-label">retries</span>
              <input
                type="number"
                min={RUNTIME_LIMIT_RULES.retries.min}
                max={RUNTIME_LIMIT_RULES.retries.max}
                step={1}
                inputMode="numeric"
                value={retries}
                onChange={(e) =>
                  setRetries(sanitizeRuntimeInput(e.target.value, "retries"))
                }
                onBlur={() => setRetries(clampRuntimeValue(retries, "retries"))}
              />
            </label>
            <label className="runtime-field">
              <span className="runtime-label">delay (ms)</span>
              <input
                type="number"
                min={RUNTIME_LIMIT_RULES.delayMs.min}
                max={RUNTIME_LIMIT_RULES.delayMs.max}
                step={1}
                inputMode="numeric"
                value={delayMs}
                onChange={(e) =>
                  setDelayMs(sanitizeRuntimeInput(e.target.value, "delayMs"))
                }
                onBlur={() => setDelayMs(clampRuntimeValue(delayMs, "delayMs"))}
              />
            </label>
            <label className="runtime-field">
              <span className="runtime-label">max endpoints/site</span>
              <input
                type="number"
                min={RUNTIME_LIMIT_RULES.maxEndpoints.min}
                max={RUNTIME_LIMIT_RULES.maxEndpoints.max}
                step={1}
                inputMode="numeric"
                value={maxEndpoints}
                onChange={(e) =>
                  setMaxEndpoints(sanitizeRuntimeInput(e.target.value, "maxEndpoints"))
                }
                onBlur={() =>
                  setMaxEndpoints(clampRuntimeValue(maxEndpoints, "maxEndpoints"))
                }
              />
            </label>
            <label className="runtime-field">
              <span className="runtime-label">filter timeout (s)</span>
              <input
                type="number"
                min={RUNTIME_LIMIT_RULES.filterTimeout.min}
                max={RUNTIME_LIMIT_RULES.filterTimeout.max}
                step={1}
                inputMode="numeric"
                disabled={noFilter}
                value={filterTimeout}
                onChange={(e) =>
                  setFilterTimeout(sanitizeRuntimeInput(e.target.value, "filterTimeout"))
                }
                onBlur={() =>
                  setFilterTimeout(clampRuntimeValue(filterTimeout, "filterTimeout"))
                }
              />
            </label>
          </div>

          <details className="advanced-panel">
            <summary>Advanced Transport, Auth, and Performance</summary>
            <p className="muted">
              Optional controls for proxy/auth, stealth behavior, and SSRF callback correlation.
            </p>
            <div className="advanced-grid">
              <label>
                proxy URL
                <input
                  type="text"
                  value={proxy}
                  onChange={(e) => setProxy(e.target.value)}
                  placeholder="http://127.0.0.1:8080"
                />
              </label>
              <label>
                auth bearer token
                <input
                  type="password"
                  value={authBearer}
                  onChange={(e) => setAuthBearer(e.target.value)}
                  placeholder="eyJhbGciOi..."
                />
              </label>
              <label>
                auth basic (user:pass)
                <input
                  type="text"
                  value={authBasic}
                  onChange={(e) => setAuthBasic(e.target.value)}
                  placeholder="username:password"
                />
              </label>
              <label>
                OAST callback base (blind SSRF)
                <input
                  type="text"
                  value={oastBase}
                  onChange={(e) => setOastBase(e.target.value)}
                  placeholder="https://oast.your-domain.tld"
                />
              </label>
            </div>
            <p className="muted">
              Blind SSRF callback correlation uses this base when active checks are enabled.
              Leave empty to skip callback correlation probes.
            </p>

            <div className="advanced-grid two-cols">
              <label>
                default headers (one per line, NAME:VALUE)
                <textarea
                  rows={4}
                  value={headersInput}
                  onChange={(e) => setHeadersInput(e.target.value)}
                  placeholder={"X-Api-Key: abc123\nX-Tenant-Id: demo"}
                />
              </label>
              <label>
                cookies (one per line, NAME=VALUE)
                <textarea
                  rows={4}
                  value={cookiesInput}
                  onChange={(e) => setCookiesInput(e.target.value)}
                  placeholder={"session=abc123\nfeature_flag=true"}
                />
              </label>
              <label>
                user-agent pool (one per line, enables WAF evasion)
                <textarea
                  rows={4}
                  value={userAgentsInput}
                  onChange={(e) => setUserAgentsInput(e.target.value)}
                  placeholder={"Mozilla/5.0 ...\nApiHunterDesktop/0.1"}
                />
              </label>
              <label>
                unauth strip headers (comma/newline)
                <textarea
                  rows={4}
                  value={unauthStripHeadersInput}
                  onChange={(e) => setUnauthStripHeadersInput(e.target.value)}
                  placeholder={"Authorization\nX-Api-Key"}
                />
              </label>
            </div>

            <div className="advanced-toggles">
              <label>
                <input
                  type="checkbox"
                  checked={wafEvasion}
                  onChange={(e) => setWafEvasion(e.target.checked)}
                />
                waf evasion
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={perHostClients}
                  onChange={(e) => setPerHostClients(e.target.checked)}
                />
                per-host clients
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={adaptiveConcurrency}
                  onChange={(e) => setAdaptiveConcurrency(e.target.checked)}
                />
                adaptive concurrency
              </label>
            </div>
          </details>

          <fieldset className="toggle-grid">
            <legend>Scanner toggles</legend>
            <p className="muted scanner-help">
              Disable modules you do not need to reduce scan time and noise.
            </p>
            {TOGGLE_FIELDS.map((item) => (
              <label key={item.key} className="toggle-item">
                <div className="toggle-title-row">
                  <input
                    type="checkbox"
                    checked={toggles[item.key]}
                    onChange={(e) => setToggleField(item.key, e.target.checked)}
                  />
                  <span>{item.label}</span>
                </div>
                <small className="toggle-hint">{item.hint}</small>
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

function parseLineList(input: string): string[] {
  return input
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function parseTokenList(input: string): string[] {
  return input
    .split(/[\n,;]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function parseTargetsText(input: string): string[] {
  const tokens = input
    .split(/[\n,;]+/)
    .map((item) => normalizeTargetToken(item))
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
      targets.push(normalizeTargetToken(value));
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

function sanitizeTargetTextareaInput(input: string): {
  value: string;
  truncated: boolean;
} {
  const normalizedLineBreaks = input.replace(/\r\n?/g, "\n");
  const strippedControls = normalizedLineBreaks.replace(
    /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g,
    "",
  );
  const value = strippedControls.slice(0, MAX_TARGET_INPUT_CHARS);
  return {
    value,
    truncated: strippedControls.length > MAX_TARGET_INPUT_CHARS,
  };
}

function normalizeTargetToken(raw: string): string {
  const strippedQuotes = raw.trim().replace(/^['"]+|['"]+$/g, "");
  if (strippedQuotes.length === 0) {
    return "";
  }
  try {
    const parsed = new URL(strippedQuotes);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return parsed.toString();
    }
  } catch {
    // Keep non-URL tokens for explicit user feedback via invalid target list.
  }
  return strippedQuotes;
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
