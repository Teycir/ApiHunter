import { useState } from "react";

export type ScanToggleState = {
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

export const DEFAULT_TOGGLES: ScanToggleState = {
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

export function useScanConfig() {
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
      setToggles({ ...allScanners, massAssignment: false, oauthOidc: false, rateLimit: false, cveTemplates: false, websocket: false });
      return;
    }
    if (mode === "mass") {
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
      setToggles({ ...allScanners, massAssignment: false, oauthOidc: false, rateLimit: false, cveTemplates: false, websocket: false });
      return;
    }
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

  return {
    targetInput, setTargetInput,
    targetInputNotice, setTargetInputNotice,
    csvImportError, setCsvImportError,
    activeChecks, setActiveChecks,
    dryRun, setDryRun,
    responseDiffDeep, setResponseDiffDeep,
    noDiscovery, setNoDiscovery,
    noFilter, setNoFilter,
    filterTimeout, setFilterTimeout,
    maxEndpoints, setMaxEndpoints,
    concurrency, setConcurrency,
    timeoutSecs, setTimeoutSecs,
    retries, setRetries,
    delayMs, setDelayMs,
    wafEvasion, setWafEvasion,
    perHostClients, setPerHostClients,
    adaptiveConcurrency, setAdaptiveConcurrency,
    proxy, setProxy,
    oastBase, setOastBase,
    dangerAcceptInvalidCerts, setDangerAcceptInvalidCerts,
    headersInput, setHeadsInput: setHeadersInput,
    cookiesInput, setCookiesInput,
    authBearer, setAuthBearer,
    authBasic, setAuthBasic,
    unauthStripHeadersInput, setUnauthStripHeadersInput,
    userAgentsInput, setUserAgentsInput,
    toggles, setToggleField,
    activePreset, setActivePreset,
    applyPreset,
  };
}
