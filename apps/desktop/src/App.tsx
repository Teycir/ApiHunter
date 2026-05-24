import React, {
  useState,
  useEffect,
  useMemo,
  useRef,
  type ChangeEvent,
  type FormEvent,
  type ReactNode,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";

const UI_RELEASE_VERSION = __APP_VERSION__;

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
  insomniaCollectionJson: string;
  insomniaRunnerDataJson: string;
  perTargetJson: TargetJsonExport[];
  targetSummaries: TargetDiscoverySummary[];
  discoveryRanking: TargetDiscoveryRank[];
  targetSummaryJson: string;
  discoveryRankingJson: string;
};

type TargetJsonExport = {
  target: string;
  fileName: string;
  prettyJson: string;
};

type TargetDiscoverySummary = {
  target: string;
  discoveries: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  errors: number;
};

type TargetDiscoveryRank = {
  rank: number;
  target: string;
  discoveries: number;
};

type FullScanResponse = {
  scanId: number;
  summary: ScanSummary;
  exports: ScanExports;
};

type SaveExportResponse = {
  path: string;
};

type LoadedScanResponse = {
  path: string;
  meta: {
    generatedAt: string;
    elapsedMs: number;
    scanned: number;
    skipped: number;
    scannerVer: string;
  };
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    errors: number;
  };
  findings: Array<{
    url: string;
    check: string;
    title: string;
    severity: string;
    detail: string;
    evidence?: string;
    scanner: string;
  }>;
  errors: unknown[];
};

type PersistedTargetMeta = {
  target: string;
  fileName: string;
};

type PersistedExports = {
  ndjson: string;
  sarif: string;
  prettyJson: string;
  insomniaCollectionJson: string;
  insomniaRunnerDataJson: string;
  targetSummaryJson: string;
  discoveryRankingJson: string;
  perTargetMeta: PersistedTargetMeta[];
  targetSummaries: TargetDiscoverySummary[];
  discoveryRanking: TargetDiscoveryRank[];
};

type PersistedScan = {
  scanId: number;
  persistedAt: string;
  summary: ScanSummary;
  exports: PersistedExports;
};

type EnrichHostResult = {
  host: string;
  /** Origin URL (scheme+host+port) used for promote-to-deep-scan. */
  representativeUrl: string;
  score: number;
  severity: string;
  signals: string[];
  ports: number[];
  cveIds: string[];
  asn: string | null;
  country: string | null;
  domainAgeDays: number | null;
  hasLikelyVulnerability: boolean;
};

type EnrichResponse = {
  enrichedNdjson: string;
  hosts: EnrichHostResult[];
  totalFindings: number;
  uniqueHosts: number;
  enrichedCount: number;
  elapsedMs: number;
  errors: string[];
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

const MAX_CSV_FILE_BYTES = 5 * 1024; // 5 KiB hard limit on imported CSV files
const MAX_TARGET_INPUT_CHARS = 32_000;
const TEXT_ENCODER = new TextEncoder();
const TARGET_SUMMARY_FILENAME = "target-discovery-summary.json";
const TARGET_RANKING_FILENAME = "target-discovery-ranking.json";
const INSOMNIA_COLLECTION_SUFFIX = "postman_collection.json";
const INSOMNIA_RUNNER_DATA_SUFFIX = "insomnia_runner_data.json";

type ExportKey = "ndjson" | "sarif" | "insomnia" | "insomniaRunnerData";
const EXPORT_MAP: Record<ExportKey, {
  format: "ndjson" | "sarif" | "insomnia" | "insomniaRunnerData";
  mimeType: string;
  getContent: (e: ScanExports) => string;
}> = {
  ndjson:            { format: "ndjson",            mimeType: "application/x-ndjson", getContent: (e) => e.ndjson },
  sarif:             { format: "sarif",              mimeType: "application/json",     getContent: (e) => e.sarif },
  insomnia:          { format: "insomnia",           mimeType: "application/json",     getContent: (e) => e.insomniaCollectionJson },
  insomniaRunnerData:{ format: "insomniaRunnerData", mimeType: "application/json",     getContent: (e) => e.insomniaRunnerDataJson },
};

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

const PRESET_LABELS: Record<string, string> = {
  mass: "Mass Sweep",
  quick: "Quick Passive",
  deep: "Deep Active",
};

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
  const [activePreset, setActivePreset] = useState<string | null>(null);

  const [loading, setLoading] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [exports, setExports] = useState<ScanExports | null>(null);
  const [savedPaths, setSavedPaths] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const logViewRef = useRef<HTMLDivElement>(null);
  const userScrolledRef = useRef(false);
  const [totalUrls, setTotalUrls] = useState(0);
  const [completedUrls, setCompletedUrls] = useState(0);
  const [targetProgress, setTargetProgress] = useState<TargetProgress[]>([]);
  const [exportPrefix, setExportPrefix] = useState<string | null>(null);
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [savingAll, setSavingAll] = useState(false);
  const [loadedScan, setLoadedScan] = useState<LoadedScanResponse | null>(null);
  const [loadScanPath, setLoadScanPath] = useState("");
  const [restoredFromSession, setRestoredFromSession] = useState(false);
  const [sessionRestoredAt, setSessionRestoredAt] = useState<string | null>(null);
  
  // Enrich state
  const [enrichLoading, setEnrichLoading] = useState(false);
  const [enrichResult, setEnrichResult] = useState<EnrichResponse | null>(null);
  const [enrichConcurrency, setEnrichConcurrency] = useState(50);
  const [enrichTimeout, setEnrichTimeout] = useState(5);
  const [enrichSavedPath, setEnrichSavedPath] = useState<string | null>(null);
  const [enrichNdjson, setEnrichNdjson] = useState("");
  const [enrichPromoteMinScore, setEnrichPromoteMinScore] = useState(25);


  function handleTargetInputChange(raw: string) {
    const sanitized = sanitizeTargetTextareaInput(raw);
    setTargetInput(sanitized.value);
    setActivePreset(null); // clear preset highlight when user edits manually
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

  useEffect(() => {
    if (!tauriRuntimeAvailable) {
      return;
    }

    void fetchHealth();
  }, [tauriRuntimeAvailable]);

  // On mount, restore the last scan from the Tauri app-data store.
  useEffect(() => {
    if (!tauriRuntimeAvailable) return;

    invokeCommand<PersistedScan | null>("load_persisted_scan")
      .then((persisted) => {
        if (!persisted) return;
        // Reconstruct a ScanExports-compatible shape from persisted data.
        // per_target_json full bodies are not stored; we reconstruct stubs.
        const restoredExports: ScanExports = {
          prettyJson: persisted.exports.prettyJson,
          ndjson: persisted.exports.ndjson,
          sarif: persisted.exports.sarif,
          insomniaCollectionJson: persisted.exports.insomniaCollectionJson,
          insomniaRunnerDataJson: persisted.exports.insomniaRunnerDataJson,
          targetSummaryJson: persisted.exports.targetSummaryJson,
          discoveryRankingJson: persisted.exports.discoveryRankingJson,
          perTargetJson: persisted.exports.perTargetMeta.map((m) => ({
            target: m.target,
            fileName: m.fileName,
            prettyJson: "", // not persisted — user must re-save from the NDJSON
          })),
          targetSummaries: persisted.exports.targetSummaries,
          discoveryRanking: persisted.exports.discoveryRanking,
        };
        setSummary(persisted.summary);
        setExports(restoredExports);
        setExportPrefix(
          `scan-${persisted.scanId}-restored`,
        );
        setRestoredFromSession(true);
        setSessionRestoredAt(persisted.persistedAt);
      })
      .catch(() => {
        // Store missing or corrupt — silently ignore; it will be overwritten on next scan.
      });
  }, [tauriRuntimeAvailable]);

  // Auto-scroll log view to bottom when new lines arrive, unless user scrolled up.
  useEffect(() => {
    const el = logViewRef.current;
    if (!el || userScrolledRef.current) return;
    el.scrollTop = el.scrollHeight;
  }, [logs]);

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
    const perTargetJsonBytes = exports.perTargetJson.reduce(
      (acc, item) => acc + TEXT_ENCODER.encode(item.prettyJson).length,
      0,
    );
    return {
      json: perTargetJsonBytes,
      ndjson: TEXT_ENCODER.encode(exports.ndjson).length,
      sarif: TEXT_ENCODER.encode(exports.sarif).length,
      insomnia: TEXT_ENCODER.encode(exports.insomniaCollectionJson).length,
      insomniaRunnerData: TEXT_ENCODER.encode(exports.insomniaRunnerDataJson).length,
      summary: TEXT_ENCODER.encode(exports.targetSummaryJson).length,
      ranking: TEXT_ENCODER.encode(exports.discoveryRankingJson).length,
    };
  }, [exports]);
  const releaseVersion = health?.appVersion ?? UI_RELEASE_VERSION;

  // ── Derived results analytics ──────────────────────────────────────────
  const parsedFindings = useMemo(() => {
    if (!exports) return [];
    return exports.ndjson.split("\n").flatMap((line) => {
      try {
        const obj = JSON.parse(line) as Record<string, unknown>;
        if (
          typeof obj.url === "string" &&
          typeof obj.check === "string" &&
          typeof obj.severity === "string" &&
          typeof obj.scanner === "string"
        ) {
          return [{ url: obj.url, check: obj.check, severity: obj.severity, scanner: obj.scanner }];
        }
        return [];
      } catch { return []; }
    });
  }, [exports]);

  const worstTarget = useMemo(() => {
    if (!exports || exports.targetSummaries.length === 0) return null;
    return [...exports.targetSummaries].sort(
      (a, b) =>
        (b.critical * 4 + b.high * 2 + b.medium) -
        (a.critical * 4 + a.high * 2 + a.medium)
    )[0];
  }, [exports]);

  const errorRate = useMemo(() => {
    if (!summary || summary.scanned === 0) return 0;
    return summary.errors / summary.scanned;
  }, [summary]);

  const scanEfficiency = useMemo(() => {
    if (!summary || summary.scanned === 0) return 0;
    return summary.findingsTotal / summary.scanned;
  }, [summary]);

  const scannerCoverage = useMemo(() => {
    if (parsedFindings.length === 0) return [];
    const counts: Record<string, number> = {};
    for (const f of parsedFindings) {
      counts[f.scanner] = (counts[f.scanner] ?? 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [parsedFindings]);

  const cleanTargets = useMemo(() => {
    if (!exports) return [];
    return exports.targetSummaries.filter((t) => t.discoveries === 0);
  }, [exports]);

  const topVulnPaths = useMemo(() => {
    if (parsedFindings.length === 0) return [];
    const counts: Record<string, number> = {};
    for (const f of parsedFindings) {
      try {
        const path = new URL(f.url).pathname || "/";
        counts[path] = (counts[path] ?? 0) + 1;
      } catch { /* skip unparseable */ }
    }
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
  }, [parsedFindings]);

  const checkSeverityBreakdown = useMemo(() => {
    if (parsedFindings.length === 0) return [];
    const map: Record<string, Record<string, number>> = {};
    for (const f of parsedFindings) {
      if (!map[f.check]) map[f.check] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
      const sev = f.severity.toUpperCase();
      map[f.check][sev] = (map[f.check][sev] ?? 0) + 1;
    }
    return Object.entries(map)
      .map(([check, sevs]) => ({ 
        check, 
        CRITICAL: sevs.CRITICAL ?? 0,
        HIGH: sevs.HIGH ?? 0,
        MEDIUM: sevs.MEDIUM ?? 0,
        LOW: sevs.LOW ?? 0,
        INFO: sevs.INFO ?? 0,
        total: Object.values(sevs).reduce((a, b) => a + b, 0) 
      }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 5);
  }, [parsedFindings]);

  const repeatOffenders = useMemo(() => {
    if (parsedFindings.length === 0) return [];
    const hostsByCheck: Record<string, Set<string>> = {};
    for (const f of parsedFindings) {
      try {
        const host = new URL(f.url).hostname;
        if (!hostsByCheck[f.check]) hostsByCheck[f.check] = new Set();
        hostsByCheck[f.check].add(host);
      } catch { /* skip */ }
    }
    return Object.entries(hostsByCheck)
      .map(([check, hosts]) => ({ check, hostCount: hosts.size }))
      .filter((e) => e.hostCount > 1)
      .sort((a, b) => b.hostCount - a.hostCount)
      .slice(0, 10);
  }, [parsedFindings]);

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
    userScrolledRef.current = false; // reset so new scan auto-scrolls from top
    setSummary(null);
    setExports(null);
    setSavedPaths([]);
    setTotalUrls(0);
    setCompletedUrls(0);
    setExportPrefix(null);
    setRestoredFromSession(false);
    setSessionRestoredAt(null);
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
      // Persist last scan to Tauri app-data store (fire-and-forget; failure is non-fatal).
      void invokeCommand("persist_last_scan", {
        scanId: result.scanId,
        summary: result.summary,
        exports: result.exports,
      }).catch(() => { /* silently ignore persistence errors */ });
      // Auto-populate Enrich panel with finding lines from this scan.
      // If the user already has custom NDJSON loaded, ask before overwriting.
      const findingLines = result.exports.ndjson.split("\n").filter((line) => {
        try {
          const obj = JSON.parse(line) as Record<string, unknown>;
          return typeof obj.url === "string" && typeof obj.check === "string" && typeof obj.severity === "string";
        } catch {
          return false;
        }
      });
      const newNdjson = findingLines.join("\n");
      if (
        enrichNdjson.trim().length === 0 ||
        window.confirm(
          "A scan just finished. Replace the current findings in the Enrich panel with results from this scan?"
        )
      ) {
        setEnrichNdjson(newNdjson);
        setEnrichResult(null);
        setEnrichSavedPath(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
      setCancelling(false);
    }
  }

  async function cancelScan() {
    if (!loading || cancelling) return;
    setCancelling(true);
    try {
      await invokeCommand("cancel_scan");
    } catch {
      // Backend may already be done; swallow the error and let finally clean up.
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
        `CSV file is too large. Maximum supported size is ${MAX_CSV_FILE_BYTES.toLocaleString()} bytes (5 KiB).`,
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

  function applyPreset(mode: "quick" | "mass" | "deep") {
    const allScanners = { ...DEFAULT_TOGGLES };
    setActivePreset(mode);
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

    if (mode === "mass") {
      // Optimised for large target sweeps: high concurrency, fast timeout,
      // no discovery, no filter, passive scanners only.
      // Designed to produce a findings NDJSON for a follow-up `enrich` pass.
      setActiveChecks(false);
      setDryRun(false);
      setResponseDiffDeep(false);
      setNoDiscovery(true);
      setNoFilter(true);
      setFilterTimeout(3);
      setMaxEndpoints(0);
      setConcurrency(100);
      setTimeoutSecs(4);
      setRetries(0);
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

    // deep — explicit block so future insertions cannot silently break preset logic
    if (mode === "deep") {
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

  async function saveExportFile(
    filename: string,
    mimeType: string,
    content: string,
    folderName: string,
  ): Promise<string> {
    if (!tauriRuntimeAvailable) {
      downloadText(filename, mimeType, content);
      return filename;
    }

    const result = await invokeCommand<SaveExportResponse>("save_export", {
      request: {
        fileName: filename,
        content,
        folderName,
      },
    });
    return result.path;
  }

  async function saveExportArtifacts(
    files: Array<{ fileName: string; mimeType: string; content: string }>,
    folderName: string,
  ): Promise<string[]> {
    const outputs = await Promise.all(
      files.map((file) =>
        saveExportFile(file.fileName, file.mimeType, file.content, folderName),
      ),
    );
    return outputs;
  }

  function buildPerTargetJsonArtifacts(scanExports: ScanExports): Array<{
    fileName: string;
    mimeType: string;
    content: string;
  }> {
    return [
      ...scanExports.perTargetJson.map((entry) => ({
        fileName: entry.fileName,
        mimeType: "application/json",
        content: entry.prettyJson,
      })),
      {
        fileName: TARGET_SUMMARY_FILENAME,
        mimeType: "application/json",
        content: scanExports.targetSummaryJson,
      },
      {
        fileName: TARGET_RANKING_FILENAME,
        mimeType: "application/json",
        content: scanExports.discoveryRankingJson,
      },
    ];
  }

  async function saveSingleExport(
    key: "json" | ExportKey,
  ): Promise<void> {
    setError(null);
    setSavedPaths([]);
    setSavingKey(key);

    if (!exports) {
      setSavingKey(null);
      return;
    }

    const folderName = buildExportFolderName(exportPrefix);

    try {
      if (key === "json") {
        const jsonArtifacts = buildPerTargetJsonArtifacts(exports);
        const paths = await saveExportArtifacts(jsonArtifacts, folderName);
        setSavedPaths(paths);
        return;
      }

      const spec = EXPORT_MAP[key];
      const fileName = getExportFilename(exportPrefix, spec.format);
      const content = spec.getContent(exports);
      const path = await saveExportFile(fileName, spec.mimeType, content, folderName);
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

    const folderName = buildExportFolderName(exportPrefix);
    const ndjsonName = getExportFilename(exportPrefix, "ndjson");
    const sarifName = getExportFilename(exportPrefix, "sarif");
    const insomniaName = getExportFilename(exportPrefix, "insomnia");
    const insomniaRunnerDataName = getExportFilename(
      exportPrefix,
      "insomniaRunnerData",
    );
    const jsonArtifacts = buildPerTargetJsonArtifacts(exports);
    const files = [
      ...jsonArtifacts,
      {
        fileName: ndjsonName,
        mimeType: "application/x-ndjson",
        content: exports.ndjson,
      },
      {
        fileName: sarifName,
        mimeType: "application/json",
        content: exports.sarif,
      },
      {
        fileName: insomniaName,
        mimeType: "application/json",
        content: exports.insomniaCollectionJson,
      },
      {
        fileName: insomniaRunnerDataName,
        mimeType: "application/json",
        content: exports.insomniaRunnerDataJson,
      },
    ];

    try {
      const outputs = await saveExportArtifacts(files, folderName);
      setSavedPaths(outputs);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSavingAll(false);
    }
  }

  async function loadPastScan() {
    if (!loadScanPath.trim()) {
      setError("Enter a scan directory path.");
      return;
    }
    setError(null);
    setLoadedScan(null);
    try {
      const result = await invokeCommand<LoadedScanResponse>("load_past_scan", {
        scanDir: loadScanPath.trim(),
      });
      setLoadedScan(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function browseScanDirectory() {
    if (!tauriRuntimeAvailable) {
      setError("Directory picker requires Tauri runtime.");
      return;
    }
    setError(null);
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: "Select Scan Export Directory",
      });
      console.log("Dialog result:", selected);
      if (selected && typeof selected === "string") {
        setLoadScanPath(selected);
      } else if (!selected) {
        console.log("User cancelled dialog");
      }
    } catch (err) {
      console.error("Browse error:", err);
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  // ── Enrich mode handlers ────────────────────────────────────────────────

  /** Browse and load an NDJSON file from disk into the Enrich input. */
  async function browseAndLoadNdjsonFile() {
    if (!tauriRuntimeAvailable) {
      setError("File picker requires Tauri runtime.");
      return;
    }
    setError(null);
    try {
      const selected = await open({
        multiple: false,
        title: "Select Findings NDJSON File",
        filters: [{ name: "NDJSON", extensions: ["ndjson", "jsonl", "json"] }],
      });
      if (selected && typeof selected === "string") {
        const result = await invokeCommand<{ content: string }>("read_text_file", { path: selected });
        setEnrichNdjson(result.content.trim());
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function runEnrich(e: FormEvent) {
    e.preventDefault();
    if (!enrichNdjson.trim()) {
      setError("Paste findings NDJSON or load from last scan first.");
      return;
    }
    setError(null);
    setEnrichResult(null);
    setEnrichSavedPath(null);
    setEnrichLoading(true);
    try {
      const result = await invokeCommand<EnrichResponse>("run_enrich", {
        request: {
          ndjson: enrichNdjson.trim(),
          concurrency: enrichConcurrency,
          timeoutSecs: enrichTimeout,
        },
      });
      setEnrichResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setEnrichLoading(false);
    }
  }

  /** Promote a single enriched host's representative URL into the Full Scan textarea
   *  and switch the form to the Deep Active preset. */
  function promoteEnrichHost(representativeUrl: string) {
    const existing = parseTargetsText(targetInput);
    const merged = dedupeTargets([...existing, representativeUrl]);
    setTargetInput(merged.join("\n"));
    applyPreset("deep");
  }

  /** Promote all hosts scoring at or above minScore into Full Scan + apply Deep preset. */
  function promoteEnrichAboveScore(minScore: number) {
    if (!enrichResult) return;
    const qualifying = enrichResult.hosts
      .filter((h) => h.score >= minScore)
      .map((h) => h.representativeUrl);
    if (qualifying.length === 0) {
      setError(`No enriched hosts score ≥ ${minScore}. Lower the threshold.`);
      return;
    }
    const existing = parseTargetsText(targetInput);
    const merged = dedupeTargets([...existing, ...qualifying]);
    setTargetInput(merged.join("\n"));
    applyPreset("deep");
  }

  /** Save the enriched NDJSON to disk. */
  async function saveEnrichedNdjson() {
    if (!enrichResult) return;
    setEnrichSavedPath(null);
    const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const fileName = `apihunter-enriched-${ts}.ndjson`;
    try {
      const path = await saveExportFile(
        fileName,
        "application/x-ndjson",
        enrichResult.enrichedNdjson,
        `apihunter-enrich-${ts}`,
      );
      setEnrichSavedPath(path);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <main className="app-shell">
      <CollapsiblePanel title="Overview" className="panel-hero" defaultOpen>
        <h1 className="hero-title">
          <BrandSymbol />
          <span>ApiHunter Desktop</span>
        </h1>
        <p>
          Configure a scan profile, watch real-time progress events, and export
          reports directly from the desktop app.
        </p>
        <div className="hero-metrics">
          <span className="metric-chip">release: v{releaseVersion}</span>
          <span className="metric-chip">
            targets: {validTargetCount}
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
      </CollapsiblePanel>

      <CollapsiblePanel title="Connection" defaultOpen>
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
      </CollapsiblePanel>

      <CollapsiblePanel title="Load Past Scan" defaultOpen={false}>
        <div className="scan-form">
          <label htmlFor="loadScanPath">Scan Directory Path</label>
          <div className="path-input-row">
            <input
              id="loadScanPath"
              type="text"
              value={loadScanPath}
              onChange={(e) => setLoadScanPath(e.target.value)}
              placeholder="/home/user/Downloads/apihunter-scan-..."
              className="path-input-flex"
            />
            <button
              type="button"
              className="btn secondary"
              onClick={browseScanDirectory}
              style={{ margin: 0 }}
            >
              Browse
            </button>
          </div>
          <button type="button" className="btn" onClick={loadPastScan}>
            Load Scan
          </button>
          {loadedScan && (
            <div className="status-ok">
              <h3>Loaded Scan Summary</h3>
              <p><strong>Path:</strong> {loadedScan.path}</p>
              <p><strong>Scanner:</strong> {loadedScan.meta.scannerVer}</p>
              <p><strong>Elapsed:</strong> {formatElapsedMs(loadedScan.meta.elapsedMs)}</p>
              <p><strong>Scanned:</strong> {loadedScan.meta.scanned} URLs</p>
              
              <h4>Findings Overview</h4>
              <div className="result-grid">
                <article className="result-card">
                  <h3>Total: {loadedScan.summary.total}</h3>
                  <p style={{ color: "var(--color-critical)", fontWeight: "bold" }}>Critical: {loadedScan.summary.critical}</p>
                  <p style={{ color: "var(--color-high)", fontWeight: "bold" }}>High: {loadedScan.summary.high}</p>
                  <p>Medium: {loadedScan.summary.medium}</p>
                  <p>Low: {loadedScan.summary.low}</p>
                  <p>Info: {loadedScan.summary.info}</p>
                  <p>Errors: {loadedScan.summary.errors}</p>
                </article>
              </div>

              {(loadedScan.summary.critical > 0 || loadedScan.summary.high > 0) && (
                <>
                  <h4>Critical &amp; High Severity Findings</h4>
                  <div className="per-target-grid" style={{ maxHeight: "480px", overflowY: "auto", marginTop: "8px" }}>
                    {loadedScan.findings
                      .filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH")
                      .map((finding, idx) => (
                        <article
                          key={idx}
                          className={`target-result-card ${finding.severity === "CRITICAL" ? "has-critical" : "has-high"}`}
                        >
                          <span className={`sev-chip ${finding.severity === "CRITICAL" ? "critical" : "high"}`} style={{ marginBottom: "6px", display: "inline-block" }}>
                            {finding.severity}
                          </span>
                          <p style={{ fontWeight: 700, margin: "0 0 4px", fontSize: "0.9rem" }}>{finding.title}</p>
                          <p className="target-url-label" title={finding.url}>{finding.url}</p>
                          <p style={{ margin: "2px 0", fontSize: "0.82rem", color: "var(--text-muted)" }}>
                            <strong>Check:</strong> {finding.check} &nbsp;·&nbsp; <strong>Scanner:</strong> {finding.scanner}
                          </p>
                          <p style={{ margin: "4px 0 0", fontSize: "0.83rem", color: "var(--text-mid)" }}>{finding.detail}</p>
                          {finding.evidence && (
                            <details style={{ marginTop: "8px" }}>
                              <summary style={{ cursor: "pointer", fontWeight: 600, fontSize: "0.8rem" }}>Evidence</summary>
                              <pre style={{
                                background: "var(--bg-surface)",
                                padding: "8px",
                                borderRadius: "4px",
                                overflow: "auto",
                                maxHeight: "200px",
                                fontSize: "0.72rem",
                                marginTop: "6px",
                              }}>{finding.evidence}</pre>
                            </details>
                          )}
                        </article>
                      ))}
                  </div>
                </>
              )}

              <div className="result-grid results-layout--two-col" style={{ marginTop: "12px" }}>
                <article className="result-card">
                  <h3>By Scanner</h3>
                  <ul className="check-list">
                    {Object.entries(
                      loadedScan.findings.reduce((acc, f) => {
                        acc[f.scanner] = (acc[f.scanner] || 0) + 1;
                        return acc;
                      }, {} as Record<string, number>)
                    )
                      .sort((a, b) => b[1] - a[1])
                      .map(([scanner, count]) => (
                        <li key={scanner} className="check-item">
                          <span className="check-name">{scanner}</span>
                          <span className="check-count">{count}</span>
                        </li>
                      ))}
                  </ul>
                </article>
                <article className="result-card">
                  <h3>Top Checks</h3>
                  <ul className="check-list">
                    {Object.entries(
                      loadedScan.findings.reduce((acc, f) => {
                        acc[f.check] = (acc[f.check] || 0) + 1;
                        return acc;
                      }, {} as Record<string, number>)
                    )
                      .sort((a, b) => b[1] - a[1])
                      .slice(0, 10)
                      .map(([check, count]) => (
                        <li key={check} className="check-item">
                          <span className="check-name">{check}</span>
                          <span className="check-count">{count}</span>
                        </li>
                      ))}
                  </ul>
                </article>
              </div>
            </div>
          )}
        </div>
      </CollapsiblePanel>

      <CollapsiblePanel title="Full Scan" defaultOpen>
        <form onSubmit={runFullScan} className="scan-form">
          <label htmlFor="targetInput">Targets</label>
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
                Max upload: {MAX_CSV_FILE_BYTES.toLocaleString()} bytes (5 KiB)
              </span>
              <input
                type="file"
                accept=".csv,text/csv"
                onChange={importTargetsFromCsv}
              />
            </label>
            <span className="muted">
              {targetCount} targets
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
              ignored automatically. Max CSV size: <code>5 KiB (5,120 bytes)</code>.
            </p>
          </div>
          <div className="preset-row">
            <p className="muted">Start with a preset profile:</p>
            <div className="preset-buttons">
              <button
                type="button"
                className={`btn secondary preset-btn${activePreset === "mass" ? " preset-btn--active" : ""}`}
                onClick={() => { applyPreset("mass"); }}
                title="Passive sweep of large target lists — produces NDJSON for Enrich → Deep Scan pipeline"
              >
                Mass Sweep
              </button>
              <button
                type="button"
                className={`btn secondary preset-btn${activePreset === "quick" ? " preset-btn--active" : ""}`}
                onClick={() => { applyPreset("quick"); }}
              >
                Quick Passive
              </button>
              <button
                type="button"
                className={`btn secondary preset-btn${activePreset === "deep" ? " preset-btn--active" : ""}`}
                onClick={() => { applyPreset("deep"); }}
              >
                Deep Active
              </button>
            </div>
          </div>
          <div className="pipeline-callout">
            <strong>Recommended pipeline:</strong>{" "}
            <span className="pipeline-step">Mass Sweep</span>
            {" → "}
            <span className="pipeline-step">Enrich</span>
            {" → "}
            <span className="pipeline-step">Deep Active</span>
            <span className="pipeline-hint">
              {" "}— Run a Mass Sweep to collect findings NDJSON, enrich hosts with threat-intel, then promote high-scoring targets for a deep active scan.
            </span>
          </div>
          {invalidTargets.length > 0 && (
            <p className="status-error compact">
              Invalid targets detected: {invalidTargets.length}. Example:{" "}
              {invalidTargets[0]}
            </p>
          )}

          <details className="section-panel">
            <summary className="section-panel-summary">
              Safety and Scan Behavior
            </summary>
            <div className="section-panel-body">
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
                    Safer mode for active checks. Useful for first pass on
                    production-like targets.
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
                    Adds deeper variant-based response comparison in API
                    versioning checks.
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
                    Faster and more predictable scans for large target lists.
                    Turn off to crawl for additional endpoints.
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
                    Disables reachability pre-check. Use this for strict target
                    sets where blocked URLs should still be attempted.
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
                    Use only in controlled environments. This lowers transport
                    security validation.
                  </p>
                </div>
              </div>
            </div>
          </details>

          <details className="section-panel">
            <summary className="section-panel-summary">Runtime Limits</summary>
            <div className="section-panel-body">
              <p className="runtime-limits-help">
                Tune speed and stability. These values apply scan-wide and stay
                aligned across screen sizes.
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
            </div>
          </details>

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

          <details className="section-panel">
            <summary className="section-panel-summary">Scanner toggles</summary>
            <div className="section-panel-body">
              <p className="muted scanner-help">
                Disable modules you do not need to reduce scan time and noise.
              </p>
              <div className="toggle-grid">
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
              </div>
            </div>
          </details>

          <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            <button type="submit" className="btn" disabled={loading}>
              {loading
                ? `Scanning${activePreset ? ` (${PRESET_LABELS[activePreset]})` : ""}\u2026`
                : activePreset
                ? `Run Full Scan \u2014 ${PRESET_LABELS[activePreset]}`
                : "Run Full Scan"}
            </button>
            {loading && (
              <button
                type="button"
                className="btn secondary"
                disabled={cancelling}
                onClick={() => void cancelScan()}
              >
                {cancelling ? "Cancelling…" : "Cancel"}
              </button>
            )}
          </div>
        </form>

        {error && <p className="status-error">{error}</p>}
      </CollapsiblePanel>

      <CollapsiblePanel title="Live Progress" defaultOpen>
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
        <div
          className="log-view"
          ref={logViewRef}
          onScroll={() => {
            const el = logViewRef.current;
            if (!el) return;
            // If user has scrolled more than 40px from the bottom, stop auto-scrolling.
            userScrolledRef.current = el.scrollHeight - el.scrollTop - el.clientHeight > 40;
          }}
        >
          {logs.length === 0 ? (
            <p className="muted">No events yet.</p>
          ) : (
            logs.map((line, idx) => <p key={`${idx}-${line}`}>{line}</p>)
          )}
        </div>
      </CollapsiblePanel>

      {summary && (
        <CollapsiblePanel
          title={
            restoredFromSession
              ? `Results · ⟳ restored from last session${sessionRestoredAt ? ` (${new Date(sessionRestoredAt).toLocaleString()})` : ""}`
              : "Results"
          }
          defaultOpen
        >
          <ResultsErrorBoundary>

          {/* ── 1. Severity heatmap ───────────────────────────────────── */}
          <SeverityHeatmap summary={summary} />

          {/* ── 2. Worst target + 3. Error rate flag + 4. Efficiency ─── */}
          <div className="result-meta-row">
            {worstTarget && (worstTarget.critical > 0 || worstTarget.high > 0 || worstTarget.medium > 0) && (
              <div className="meta-card meta-card--worst">
                <span className="meta-card-label">⚠ Start here</span>
                <span className="meta-card-value" title={worstTarget.target}>{worstTarget.target}</span>
                <span className="meta-card-sub">
                  C:{worstTarget.critical} H:{worstTarget.high} M:{worstTarget.medium} · score {worstTarget.critical * 4 + worstTarget.high * 2 + worstTarget.medium}
                </span>
              </div>
            )}
            <div className="meta-card">
              <span className="meta-card-label">Scan efficiency</span>
              <span className="meta-card-value">{scanEfficiency.toFixed(2)}</span>
              <span className="meta-card-sub">findings / URL scanned</span>
            </div>
            {errorRate > 0 && (
              <div className={`meta-card ${errorRate >= 0.2 ? "meta-card--warn" : ""}`}>
                <span className="meta-card-label">{errorRate >= 0.2 ? "⚠ High error rate" : "Error rate"}</span>
                <span className="meta-card-value">{(errorRate * 100).toFixed(1)}%</span>
                <span className="meta-card-sub">{summary.errors} errors / {summary.scanned} scanned{errorRate >= 0.2 ? " — WAF or auth issue?" : ""}</span>
              </div>
            )}
          </div>

          <div className="result-grid">
            <article className="result-card">
              <h3>Summary</h3>
              <p>Target: {summary.target}</p>
              <p>Scanned: {summary.scanned}</p>
              <p>Skipped: {summary.skipped}</p>
              <p>Elapsed: {formatElapsedMs(summary.elapsedMs)}</p>
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
                <ul className="check-list">
                  {summary.topChecks.map((entry) => (
                    <li key={entry.check} className="check-item">
                      <span className="check-name">{entry.check}</span>
                      <span className="check-count">{entry.count}</span>
                    </li>
                  ))}
                </ul>
              )}
            </article>

            {exports && (
              <article className="result-card">
                <h3>Target ranking</h3>
                {exports.discoveryRanking.length === 0 ? (
                  <p>No target discoveries reported.</p>
                ) : (
                  <ul className="check-list">
                    {exports.discoveryRanking.map((entry) => (
                      <li key={`${entry.rank}-${entry.target}`} className="check-item">
                        <span className="check-name" title={entry.target}>#{entry.rank} {entry.target}</span>
                        <span className="check-count">{entry.discoveries}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </article>
            )}

            {/* ── Ranking by most HIGH findings ──────────────────────── */}
            {exports && exports.targetSummaries.some((t) => t.high > 0) && (
              <article className="result-card">
                <h3 style={{ color: "var(--color-high)" }}>Most Highs</h3>
                <ul className="check-list">
                  {[...exports.targetSummaries]
                    .filter((t) => t.high > 0)
                    .sort((a, b) => b.high - a.high)
                    .map((t) => (
                      <li key={t.target} className="check-item">
                        <span className="check-name" title={t.target}>{t.target}</span>
                        <span className="check-count" style={{ background: "#fff5ee", color: "var(--color-high)", border: "1px solid var(--color-high)" }}>{t.high}</span>
                      </li>
                    ))}
                </ul>
              </article>
            )}

            {/* ── Ranking by most CRITICAL findings ──────────────────── */}
            {exports && exports.targetSummaries.some((t) => t.critical > 0) && (
              <article className="result-card">
                <h3 style={{ color: "var(--color-critical)" }}>Most Criticals</h3>
                <ul className="check-list">
                  {[...exports.targetSummaries]
                    .filter((t) => t.critical > 0)
                    .sort((a, b) => b.critical - a.critical)
                    .map((t) => (
                      <li key={t.target} className="check-item">
                        <span className="check-name" title={t.target}>{t.target}</span>
                        <span className="check-count" style={{ background: "#fff0f0", color: "var(--color-critical)", border: "1px solid var(--color-critical)" }}>{t.critical}</span>
                      </li>
                    ))}
                </ul>
              </article>
            )}

            {/* ── 5. Scanner coverage ────────────────────────────────── */}
            {scannerCoverage.length > 0 && (
              <article className="result-card">
                <h3>Scanner coverage</h3>
                <ul className="check-list">
                  {scannerCoverage.map(([scanner, count]) => (
                    <li key={scanner} className="check-item">
                      <span className="check-name">{scanner}</span>
                      <span className="check-count">{count}</span>
                    </li>
                  ))}
                </ul>
                {exports && (() => {
                  const active = new Set(scannerCoverage.map(([s]) => s));
                  const all = ["cors","csp","graphql","apiSecurity","jwt","openapi","apiVersioning","grpcProtobuf","massAssignment","oauthOidc","rateLimit","cveTemplates","websocket"];
                  const silent = all.filter((s) => !active.has(s));
                  return silent.length > 0 ? (
                    <p className="muted" style={{ marginTop: "8px", fontSize: "0.78rem" }}>
                      Silent: {silent.join(", ")}
                    </p>
                  ) : null;
                })()}
              </article>
            )}

            {/* ── 6. Clean targets ───────────────────────────────────── */}
            {cleanTargets.length > 0 && (
              <article className="result-card">
                <h3>Clean targets <span style={{ fontWeight: 400, fontSize: "0.82rem", color: "var(--color-text-muted)" }}>({cleanTargets.length})</span></h3>
                <details>
                  <summary style={{ cursor: "pointer", fontSize: "0.85rem", color: "var(--color-text-muted)" }}>
                    Zero findings — show all
                  </summary>
                  <ul className="check-list" style={{ marginTop: "6px" }}>
                    {cleanTargets.map((t) => (
                      <li key={t.target} className="check-item">
                        <span className="check-name" title={t.target}>{t.target}</span>
                        <span className="check-count" style={{ background: "var(--color-ok-bg)", color: "var(--color-low)", border: "1px solid var(--color-ok-border)" }}>✓</span>
                      </li>
                    ))}
                  </ul>
                </details>
              </article>
            )}

            {/* ── 8. Top vulnerable paths ────────────────────────────── */}
            {topVulnPaths.length > 0 && (
              <article className="result-card">
                <h3>Top vulnerable paths</h3>
                <ul className="check-list">
                  {topVulnPaths.map(([path, count]) => (
                    <li key={path} className="check-item">
                      <span className="check-name">{path}</span>
                      <span className="check-count">{count}</span>
                    </li>
                  ))}
                </ul>
              </article>
            )}

            {/* ── 9. Check-to-severity breakdown ─────────────────────── */}
            {checkSeverityBreakdown.length > 0 && (
              <article className="result-card">
                <h3>Check severity breakdown <span style={{ fontWeight: 400, fontSize: "0.78rem", color: "var(--text-muted)" }}>top 5</span></h3>
                <div className="sev-breakdown-table">
                  {checkSeverityBreakdown.map((row) => (
                    <div key={row.check} className="sev-breakdown-row">
                      <span className="sev-breakdown-check" title={row.check}>{row.check}</span>
                      <div className="sev-breakdown-chips">
                        {(row.CRITICAL ?? 0) > 0 && <span className="sev-chip critical">C:{row.CRITICAL}</span>}
                        {(row.HIGH     ?? 0) > 0 && <span className="sev-chip high">H:{row.HIGH}</span>}
                        {(row.MEDIUM   ?? 0) > 0 && <span className="sev-chip medium">M:{row.MEDIUM}</span>}
                        {(row.LOW      ?? 0) > 0 && <span className="sev-chip low">L:{row.LOW}</span>}
                        {(row.INFO     ?? 0) > 0 && <span className="sev-chip info">I:{row.INFO}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </article>
            )}

            {/* ── 10. Repeat offender checks ─────────────────────────── */}
            {repeatOffenders.length > 0 && (
              <article className="result-card">
                <h3>Repeat offenders <span style={{ fontWeight: 400, fontSize: "0.78rem", color: "var(--text-muted)" }}>by distinct hosts</span></h3>
                <ul className="check-list">
                  {repeatOffenders.map(({ check, hostCount }) => (
                    <li key={check} className="check-item">
                      <span className="check-name">{check}</span>
                      <span className="check-count" style={{ background: "#fff0f0", color: "var(--color-critical)", border: "1px solid var(--color-critical)" }}>{hostCount} hosts</span>
                    </li>
                  ))}
                </ul>
              </article>
            )}

            {exports && (
              <article className="result-card">
                <h3>Per-target summary</h3>
                {exports.targetSummaries.length === 0 ? (
                  <p>No target summaries available.</p>
                ) : (
                  <ul className="check-list">
                    {exports.targetSummaries.map((entry) => (
                      <li key={entry.target} className="check-item">
                        <span className="check-name" title={entry.target}>{entry.target}</span>
                        <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", flexShrink: 0 }}>
                          C:{entry.critical} H:{entry.high} M:{entry.medium} L:{entry.low}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </article>
            )}
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
                onClick={() => void saveSingleExport("json")}
              >
                {savingKey === "json"
                  ? "Saving Target JSON..."
                  : `Save Target JSON Bundle (${formatBytes(exportStats?.json ?? 0)})`}
              </button>
              <button
                type="button"
                className="btn secondary"
                disabled={savingAll || savingKey !== null}
                onClick={() => void saveSingleExport("ndjson")}
              >
                {savingKey === "ndjson"
                  ? "Saving NDJSON..."
                  : `Save NDJSON (${formatBytes(exportStats?.ndjson ?? 0)})`}
              </button>
              <button
                type="button"
                className="btn secondary"
                disabled={savingAll || savingKey !== null}
                onClick={() => void saveSingleExport("sarif")}
              >
                {savingKey === "sarif"
                  ? "Saving SARIF..."
                  : `Save SARIF (${formatBytes(exportStats?.sarif ?? 0)})`}
              </button>
              <button
                type="button"
                className="btn secondary"
                disabled={savingAll || savingKey !== null}
                onClick={() => void saveSingleExport("insomnia")}
              >
                {savingKey === "insomnia"
                  ? "Saving Insomnia Collection..."
                  : `Save Insomnia Collection (${formatBytes(exportStats?.insomnia ?? 0)})`}
              </button>
              <button
                type="button"
                className="btn secondary"
                disabled={savingAll || savingKey !== null}
                onClick={() => void saveSingleExport("insomniaRunnerData")}
              >
                {savingKey === "insomniaRunnerData"
                  ? "Saving Runner Data..."
                  : `Save Insomnia Runner Data (${formatBytes(exportStats?.insomniaRunnerData ?? 0)})`}
              </button>
              <p className="muted">
                Export writes into a timestamped folder. JSON exports are split
                per target and include discovery summary/ranking files plus an
                Insomnia-importable collection and runner data file.
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
          </ResultsErrorBoundary>
        </CollapsiblePanel>
      )}

      <CollapsiblePanel title="Enrich Mode" defaultOpen={!!enrichNdjson}>
        <p className="muted" style={{ marginBottom: "12px" }}>
          Adds threat-intel context (InternetDB · ipinfo.io · RDAP) to the findings from your last scan — one probe per unique host.
          After a Full Scan completes the findings are loaded automatically. You can then run Enrich and promote high-scoring hosts directly to a Deep Active scan.
        </p>

        {!enrichNdjson && (
          <div className="enrich-empty-notice">
            <p>
              No findings loaded yet. Run a <strong>Full Scan</strong> above — the results will appear here automatically.
              You can also load an NDJSON file saved from a previous scan:
            </p>
            <button
              type="button"
              className="btn secondary"
              style={{ marginTop: "8px" }}
              onClick={() => void browseAndLoadNdjsonFile()}
            >
              Browse NDJSON file…
            </button>
            <p className="muted" style={{ marginTop: "8px", fontSize: "0.8rem" }}>
              The NDJSON file is saved when you click <em>Save NDJSON</em> (or <em>Save All Reports</em>) in the Results panel.
              It lives in the timestamped export folder next to the scan JSON.
            </p>
          </div>
        )}

        {enrichNdjson && (
          <form onSubmit={runEnrich} className="scan-form">
            <div className="enrich-ndjson-loaded">
              <span className="enrich-ndjson-count">
                {enrichNdjson.split("\n").filter(Boolean).length} finding lines ready
              </span>
              <button
                type="button"
                className="btn secondary"
                style={{ margin: 0, padding: "4px 10px", fontSize: "12px" }}
                onClick={() => void browseAndLoadNdjsonFile()}
              >
                Replace with file…
              </button>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
              <div>
                <label htmlFor="enrichConcurrency">Concurrency</label>
                <input
                  id="enrichConcurrency"
                  type="number"
                  min="1"
                  max="200"
                  value={enrichConcurrency}
                  onChange={(e) => setEnrichConcurrency(Number(e.target.value))}
                />
              </div>
              <div>
                <label htmlFor="enrichTimeout">Timeout (seconds)</label>
                <input
                  id="enrichTimeout"
                  type="number"
                  min="1"
                  max="60"
                  value={enrichTimeout}
                  onChange={(e) => setEnrichTimeout(Number(e.target.value))}
                />
              </div>
            </div>

            <button type="submit" className="btn" disabled={enrichLoading}>
              {enrichLoading ? "Enriching…" : "Run Enrich"}
            </button>
          </form>
        )}

        {enrichResult && (
          <div style={{ marginTop: "24px" }}>
            <div className="status-ok" style={{ marginBottom: "16px" }}>
              <p>
                <strong>{enrichResult.enrichedCount}</strong> of {enrichResult.totalFindings} findings enriched
                across <strong>{enrichResult.uniqueHosts}</strong> unique hosts &nbsp;·&nbsp;
                {formatElapsedMs(enrichResult.elapsedMs)}
                {enrichResult.errors.length > 0 && (
                  <span style={{ color: "var(--color-critical)", marginLeft: "8px" }}>
                    {enrichResult.errors.length} probe error(s)
                  </span>
                )}
              </p>
            </div>

            <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "16px", flexWrap: "wrap" }}>
              <label style={{ fontWeight: "bold", fontSize: "13px" }}>Promote hosts scoring ≥</label>
              <input
                type="number"
                min="0"
                max="100"
                value={enrichPromoteMinScore}
                onChange={(e) => setEnrichPromoteMinScore(Number(e.target.value))}
                style={{ width: "64px" }}
              />
              <button
                type="button"
                className="btn secondary"
                style={{ margin: 0 }}
                onClick={() => promoteEnrichAboveScore(enrichPromoteMinScore)}
                title="Merge qualifying hosts into Full Scan and apply Deep Active preset"
              >
                → Deep Scan
              </button>
              <button
                type="button"
                className="btn secondary"
                style={{ margin: 0 }}
                onClick={() => void saveEnrichedNdjson()}
              >
                Save Enriched NDJSON
              </button>
              {enrichSavedPath && (
                <span className="enrich-saved-path">Saved: {enrichSavedPath}</span>
              )}
            </div>

            <div style={{ maxHeight: "680px", overflow: "auto" }}>
              {enrichResult.hosts.map((host, idx) => {
                const borderColor =
                  host.severity === "CRITICAL" ? "var(--color-critical)" :
                  host.severity === "HIGH"     ? "var(--color-high)" :
                  host.severity === "MEDIUM"   ? "var(--color-medium)" : "var(--color-border)";
                const badgeBg =
                  host.severity === "CRITICAL" ? "var(--color-critical)" :
                  host.severity === "HIGH"     ? "var(--color-high)" :
                  host.severity === "MEDIUM"   ? "var(--color-medium)" : "var(--color-border)";
                const badgeColor = host.severity === "MEDIUM" ? "#212529" : "white";

                return (
                  <article
                    key={idx}
                    className="result-card"
                    style={{ marginBottom: "10px", borderLeft: `4px solid ${borderColor}` }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "8px" }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <p style={{ fontWeight: "bold", fontSize: "15px", margin: "0 0 2px" }}>
                          #{idx + 1} {host.host}
                        </p>
                        <p style={{ fontSize: "0.82rem", color: "var(--color-text-muted)", margin: 0 }}>
                          Score: <strong>{host.score}</strong>/100
                          {host.asn && `  ·  ${host.asn}`}
                          {host.country && ` (${host.country})`}
                        </p>
                      </div>
                      <div style={{ display: "flex", gap: "6px", flexShrink: 0, alignItems: "center" }}>
                        <span style={{
                          background: badgeBg, color: badgeColor,
                          padding: "3px 8px", borderRadius: "4px",
                          fontSize: "11px", fontWeight: "bold", letterSpacing: "0.05em",
                        }}>
                          {host.severity}
                        </span>
                        {host.hasLikelyVulnerability && (
                          <span style={{
                            background: "var(--color-critical)", color: "#fff",
                            padding: "3px 8px", borderRadius: "4px",
                            fontSize: "11px", fontWeight: "bold",
                          }}>
                            VULN
                          </span>
                        )}
                        <button
                          type="button"
                          className="btn secondary"
                          style={{ margin: 0, padding: "3px 10px", fontSize: "12px" }}
                          onClick={() => promoteEnrichHost(host.representativeUrl)}
                          title={`Promote ${host.representativeUrl} to Full Scan with Deep Active preset`}
                        >
                          → Deep Scan
                        </button>
                      </div>
                    </div>

                    {(host.ports.length > 0 || host.cveIds.length > 0 || host.domainAgeDays !== null) && (
                      <div style={{ marginTop: "6px", fontSize: "13px", display: "flex", gap: "16px", flexWrap: "wrap" }}>
                        {host.ports.length > 0 && (
                          <span><strong>Ports:</strong> {host.ports.join(", ")}</span>
                        )}
                        {host.cveIds.length > 0 && (
                          <span style={{ color: "var(--color-critical)" }}><strong>CVEs:</strong> {host.cveIds.join(", ")}</span>
                        )}
                        {host.domainAgeDays !== null && (
                          <span><strong>Domain age:</strong> {host.domainAgeDays}d</span>
                        )}
                      </div>
                    )}

                    {host.signals.length > 0 && (
                      <details style={{ marginTop: "6px" }}>
                        <summary style={{ cursor: "pointer", fontSize: "0.83rem", color: "var(--color-text-muted)" }}>
                          Signals ({host.signals.length})
                        </summary>
                        <ul style={{ margin: "4px 0 0 0", paddingLeft: "18px" }}>
                          {host.signals.map((sig, sidx) => (
                            <li key={sidx} style={{ fontSize: "0.8rem", color: "var(--color-text-mid)" }}>{sig}</li>
                          ))}
                        </ul>
                      </details>
                    )}

                    <p style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", margin: "6px 0 0" }}>
                      {host.representativeUrl}
                    </p>
                  </article>
                );
              })}
            </div>

            {enrichResult.errors.length > 0 && (
              <details style={{ marginTop: "12px" }}>
                <summary style={{ cursor: "pointer", fontWeight: 700, color: "var(--color-critical)", fontSize: "0.85rem" }}>
                  Probe errors ({enrichResult.errors.length})
                </summary>
                <div style={{ marginTop: "6px", maxHeight: "180px", overflow: "auto" }}>
                  {enrichResult.errors.map((err, idx) => (
                    <p key={idx} style={{ fontSize: "0.82rem", color: "var(--color-critical)", margin: "2px 0" }}>{err}</p>
                  ))}
                </div>
              </details>
            )}
          </div>
        )}
      </CollapsiblePanel>
    </main>
  );
}

function CollapsiblePanel({
  title,
  children,
  className,
  defaultOpen = true,
  panelRef,
}: {
  title: string;
  children: ReactNode;
  className?: string;
  defaultOpen?: boolean;
  panelRef?: React.RefObject<HTMLElement | null>;
}) {
  // Use local state so parent re-renders (logs, progress, scan state) don't
  // force the panel back to its initial open/closed state on every render.
  const [isOpen, setIsOpen] = useState(defaultOpen);
  const panelClassName = className ? `panel ${className}` : "panel";
  return (
    <details
      ref={panelRef as React.RefObject<HTMLDetailsElement> | undefined}
      className={`${panelClassName} collapsible-panel`}
      open={isOpen}
      onToggle={(e) => setIsOpen((e.currentTarget as HTMLDetailsElement).open)}
    >
      <summary className="panel-summary">{title}</summary>
      <div className="panel-body">{children}</div>
    </details>
  );
}

class ResultsErrorBoundary extends React.Component<
  { children: ReactNode },
  { error: Error | null }
> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  override render() {
    if (this.state.error) {
      return (
        <div className="status-error" style={{ margin: "16px 0" }}>
          <strong>Results panel error:</strong> {this.state.error.message}
          <br />
          <button
            className="btn secondary"
            style={{ marginTop: "10px" }}
            onClick={() => this.setState({ error: null })}
          >
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function SeverityHeatmap({ summary }: { summary: ScanSummary }) {
  const total = summary.critical + summary.high + summary.medium + summary.low + summary.info;
  if (total === 0) return null;
  const pct = (n: number) => `${((n / total) * 100).toFixed(1)}%`;
  const segments = [
    { label: "Critical", val: summary.critical, segCls: "seg-critical" },
    { label: "High",     val: summary.high,     segCls: "seg-high" },
    { label: "Medium",   val: summary.medium,   segCls: "seg-medium" },
    { label: "Low",      val: summary.low,      segCls: "seg-low" },
    { label: "Info",     val: summary.info,     segCls: "seg-info" },
  ].filter((s) => s.val > 0);
  return (
    <div className="heatmap-wrap">
      <div className="heatmap-bar">
        {segments.map((s) => (
          <div
            key={s.label}
            className={`heatmap-seg ${s.segCls}`}
            style={{ width: pct(s.val) }}
            title={`${s.label}: ${s.val}`}
          />
        ))}
      </div>
      <div className="heatmap-legend">
        {segments.map((s) => (
          <span key={s.label} className="heatmap-legend-item">
            <span className={`heatmap-dot ${s.segCls}`} />
            {s.label} <strong>{s.val}</strong> ({pct(s.val)})
          </span>
        ))}
      </div>
    </div>
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

function formatElapsedMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const totalSecs = Math.round(ms / 1000);
  const mins = Math.floor(totalSecs / 60);
  const secs = totalSecs % 60;
  return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
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
  format: "json" | "ndjson" | "sarif" | "insomnia" | "insomniaRunnerData",
): string {
  const safePrefix =
    prefix ??
    `apihunter-scan-${new Date()
      .toISOString()
      .replace(/[-:]/g, "")
      .replace(/\..+$/, "")
      .replace("T", "-")}`;
  if (format === "insomnia") {
    return `${safePrefix}.${INSOMNIA_COLLECTION_SUFFIX}`;
  }
  if (format === "insomniaRunnerData") {
    return `${safePrefix}.${INSOMNIA_RUNNER_DATA_SUFFIX}`;
  }
  return `${safePrefix}.${format}`;
}

function buildExportFolderName(prefix: string | null): string {
  const base = prefix ?? "apihunter-scan";
  const stamp = new Date()
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\..+$/, "")
    .replace("T", "-");
  return `${base}-exports-${stamp}`;
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
