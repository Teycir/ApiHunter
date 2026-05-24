import { useState } from "react";

export type EnrichHostResult = {
  host: string;
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

export type EnrichResponse = {
  enrichedNdjson: string;
  hosts: EnrichHostResult[];
  totalFindings: number;
  uniqueHosts: number;
  enrichedCount: number;
  elapsedMs: number;
  errors: string[];
};

export function useEnrich() {
  const [enrichLoading, setEnrichLoading] = useState(false);
  const [enrichResult, setEnrichResult] = useState<EnrichResponse | null>(null);
  const [enrichConcurrency, setEnrichConcurrency] = useState(50);
  const [enrichTimeout, setEnrichTimeout] = useState(5);
  const [enrichSavedPath, setEnrichSavedPath] = useState<string | null>(null);
  const [enrichNdjson, setEnrichNdjson] = useState("");
  const [enrichPromoteMinScore, setEnrichPromoteMinScore] = useState(25);

  function resetEnrich() {
    setEnrichResult(null);
    setEnrichSavedPath(null);
  }

  return {
    enrichLoading, setEnrichLoading,
    enrichResult, setEnrichResult,
    enrichConcurrency, setEnrichConcurrency,
    enrichTimeout, setEnrichTimeout,
    enrichSavedPath, setEnrichSavedPath,
    enrichNdjson, setEnrichNdjson,
    enrichPromoteMinScore, setEnrichPromoteMinScore,
    resetEnrich,
  };
}
