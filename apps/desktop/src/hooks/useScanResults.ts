import { useRef, useState } from "react";

export type TargetProgress = {
  url: string;
  status: "pending" | "completed";
  findings: number;
  critical: number;
  high: number;
  medium: number;
};

export type ScanSummary = {
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
  topChecks: { check: string; count: number }[];
};

export type ScanExports = {
  prettyJson: string;
  ndjson: string;
  sarif: string;
  insomniaCollectionJson: string;
  insomniaRunnerDataJson: string;
  perTargetJson: { target: string; fileName: string; prettyJson: string }[];
  targetSummaries: {
    target: string;
    discoveries: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    errors: number;
  }[];
  discoveryRanking: { rank: number; target: string; discoveries: number }[];
  targetSummaryJson: string;
  discoveryRankingJson: string;
};

export function useScanResults() {
  const [loading, setLoading] = useState(false);
  const [cancelling, setCancelling] = useState(false);
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
  const [loadedScan, setLoadedScan] = useState<{
    path: string;
    meta: { generatedAt: string; elapsedMs: number; scanned: number; skipped: number; scannerVer: string };
    summary: { total: number; critical: number; high: number; medium: number; low: number; info: number; errors: number };
    findings: { url: string; check: string; title: string; severity: string; detail: string; evidence?: string; scanner: string }[];
    errors: unknown[];
  } | null>(null);
  const [loadScanPath, setLoadScanPath] = useState("");

  function resetForNewScan(targetUrls: string[]) {
    setLoading(true);
    setCancelling(false);
    setError(null);
    setLogs([]);
    userScrolledRef.current = false;
    setSummary(null);
    setExports(null);
    setSavedPaths([]);
    setTotalUrls(0);
    setCompletedUrls(0);
    setExportPrefix(null);
    setTargetProgress(
      targetUrls.map((url) => ({ url, status: "pending", findings: 0, critical: 0, high: 0, medium: 0 })),
    );
  }

  function appendLog(message: string) {
    setLogs((prev) => [...prev, message].slice(-250));
  }

  return {
    loading, setLoading,
    cancelling, setCancelling,
    summary, setSummary,
    exports, setExports,
    savedPaths, setSavedPaths,
    error, setError,
    logs,
    logViewRef,
    userScrolledRef,
    totalUrls, setTotalUrls,
    completedUrls, setCompletedUrls,
    targetProgress, setTargetProgress,
    exportPrefix, setExportPrefix,
    savingKey, setSavingKey,
    savingAll, setSavingAll,
    loadedScan, setLoadedScan,
    loadScanPath, setLoadScanPath,
    resetForNewScan,
    appendLog,
  };
}
