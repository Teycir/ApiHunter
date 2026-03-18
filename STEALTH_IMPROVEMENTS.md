# Deep Analysis: How to Increase Stealth in ApiHunter

## Table of Contents
1. [Current State Analysis](#current-state-analysis)
2. [Detection Vectors](#detection-vectors)
3. [Stealth Improvement Strategy](#stealth-improvement-strategy)
4. [Implementation Roadmap](#implementation-roadmap)
5. [Trade-offs & Considerations](#trade-offs--considerations)

---

## Current State Analysis

### Architecture Overview

ApiHunter's scanning flow:
```
1. Discovery Phase (per-site):
   - Robots.txt
   - Sitemap.xml (up to 5)
   - Swagger/OpenAPI
   - JavaScript parsing (up to 10 scripts)
   - Header link discovery
   - Common paths (80+ paths via HEAD requests)

2. Scanning Phase (per-URL, all scanners run concurrently):
   - CORS Scanner (5+ requests per endpoint)
   - CSP Scanner
   - GraphQL Scanner (6+ paths probed)
   - API Security Scanner (30+ debug paths)
   - JWT Scanner
   - OpenAPI Scanner
   - Mass Assignment Scanner (active)
   - OAuth/OIDC Scanner (active)
   - WebSocket Scanner (active)
```

### Current Stealth Features (Good)

1. **Per-host rate limiting** (`http_client.rs:enforce_host_delay`)
   - Mutex-based delay enforcement
   - Prevents concurrent requests to same host
   - Configurable via `--delay-ms`

2. **Adaptive concurrency** (`http_client.rs:AdaptiveLimiter`)
   - AIMD algorithm (Additive Increase Multiplicative Decrease)
   - Backs off on 429/5xx errors
   - Increases on success streaks

3. **UA rotation** (`waf.rs:random_user_agent`)
   - Rotates on every request
   - Loads from `assets/user_agents.txt`
   - Fallback to 5 embedded UAs

4. **Random jitter** (`waf.rs:random_delay`)
   - 1x to 3x base delay when WAF evasion enabled
   - Prevents predictable timing patterns

5. **Retry with exponential backoff** (`http_client.rs:retry_backoff`)
   - 200ms * 2^attempt (capped at 2^6)
   - Respects 429/5xx responses

6. **Realistic browser headers** (`waf.rs:evasion_headers`)
   - Accept, Accept-Language, Accept-Encoding
   - sec-fetch-* headers (modern browser fingerprint)
   - DNT, Connection, Upgrade-Insecure-Requests

---

## Detection Vectors

### CRITICAL: Obvious Scanning Patterns

#### 1. CORS Scanner Pattern (cors.rs)
```rust
// Sends 5+ requests with different Origin headers to EVERY endpoint
for origin in &probe_origins {  // ["null", "https://evil.com", "https://target.com", ...]
    let extra = [
        ("Origin".to_string(), origin.to_string()),
        ("Access-Control-Request-Method".to_string(), "GET".to_string()),
    ];
    client.get_with_headers(url, &extra).await;
}

// Then tests regex bypasses with MORE requests:
for suffix in [".evil.com", "%60.evil.com"] {
    let bypass = format!("{}{}", reflected, suffix);
    client.get_with_headers(url, &bypass_extra).await;
}
```

**Detection signature:**
- Same URL hit 5-10 times in rapid succession
- Each request has different `Origin` header
- Includes obvious attack patterns: `evil.com`, `attacker`, `null`
- Predictable order: null → evil.com → target → suffix bypasses → prefix bypasses

**WAF rule to catch this:**
```
IF (same_url_count > 3 AND unique_origin_headers > 2 AND time_window < 10s)
  THEN block_ip
```

#### 2. GraphQL Scanner Pattern (graphql.rs)
```rust
static GQL_PATHS: &[&str] = &[
    "/graphql", "/graphiql", "/api/graphql", 
    "/v1/graphql", "/query", "/gql",
];

for candidate in &candidates {
    probe_endpoint(candidate, client, findings, errors).await;
}
```

**Detection signature:**
- Probes 6+ GraphQL-related paths in sequence
- Sends introspection query with distinctive pattern: `{ __schema { queryType { name } types { ... } } }`
- Follows with field suggestion probe: `{ __typ }`
- Then batch query: `[{"query": "{ __typename }"}, {"query": "{ __typename }"}]`
- Then alias amplification: `{ a0: __typename a1: __typename ... a9: __typename }`

**WAF rule:**
```
IF (request_body CONTAINS "__schema" OR request_body CONTAINS "__typ")
  AND (path MATCHES "/graphql|/gql|/query")
  THEN flag_as_scanner
```

#### 3. Debug Endpoint Scanner Pattern (api_security.rs)
```rust
static DEBUG_ENDPOINTS: &[DebugEndpoint] = &[
    "/.env", "/.env.local", "/.env.production",
    "/config.json", "/config.yaml", "/config.yml",
    "/actuator", "/actuator/env", "/actuator/health",
    "/debug", "/debug/vars", "/debug/pprof",
    "/phpinfo.php", "/info.php",
    "/server-status", "/server-info",
    // ... 30+ paths total
];
```

**Detection signature:**
- Hits 30+ sensitive paths in rapid succession
- Predictable order (alphabetical in code)
- Includes obvious scanner paths: `/.env`, `/actuator`, `/debug`
- All from same IP within short time window

**WAF rule:**
```
IF (sensitive_path_count > 5 AND time_window < 60s)
  THEN block_ip
```

#### 4. Mass Assignment Scanner Pattern (mass_assignment.rs)
```rust
let payload = json!({
    "__ah_probe": "1",  // OBVIOUS MARKER
    "is_admin": true,
    "role": "admin",
    "permissions": ["*"]
});
```

**Detection signature:**
- Request body contains `__ah_probe` field (DEAD GIVEAWAY)
- Sends `X-AH-MA-Stage: baseline` header
- Then sends `X-AH-MA-Stage: confirm` header
- Custom headers starting with `X-AH-` are obvious scanner markers

**WAF rule:**
```
IF (request_body CONTAINS "__ah_probe" OR header_name STARTS_WITH "x-ah-")
  THEN block_ip_permanently
```

#### 5. IDOR Scanner Pattern (api_security.rs:check_idor_bola)
```rust
// Walks ID range in predictable sequence
let range_ids: Vec<u64> = (base_id.saturating_sub(2)..=base_id + 2).collect();
// [base-2, base-1, base, base+1, base+2]

for &id in &range_ids {
    let probe_url = replace_numeric_segment(url, &numeric_seg, id);
    client.get(&probe_url).await;
}
```

**Detection signature:**
- Same URL pattern with sequential IDs
- Exactly 5 requests: ID-2, ID-1, ID, ID+1, ID+2
- All within seconds

**WAF rule:**
```
IF (url_pattern_match AND sequential_id_access > 3 AND time_window < 5s)
  THEN flag_as_idor_scanner
```

#### 6. Common Path Discovery Pattern (common_paths.rs)
```rust
static COMMON_PATHS: &[&str] = &[
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/swagger", "/admin", "/debug",
    "/actuator", "/.env", "/.git/config",
    // ... 80+ paths
];

// Sends HEAD requests to all paths
for path in all_paths {
    client.head(&url).await;
}
```

**Detection signature:**
- 80+ HEAD requests in rapid succession
- Predictable wordlist (alphabetical)
- Includes obvious scanner paths

**WAF rule:**
```
IF (head_request_count > 20 AND time_window < 30s)
  THEN rate_limit_aggressive
```

### MEDIUM: Static Fingerprints

#### 1. Static Headers (waf.rs:evasion_headers)
```rust
let pairs: &[(&str, &str)] = &[
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"),
    ("accept-language", "en-US,en;q=0.5"),
    ("accept-encoding", "gzip, deflate, br"),
    ("dnt", "1"),
    ("sec-fetch-dest", "document"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-site", "none"),
    ("cache-control", "max-age=0"),
];
```

**Problem:** Same headers on EVERY request
- sec-fetch-* values never change
- Accept-Language always "en-US,en;q=0.5"
- DNT always "1"

**Detection:**
```
IF (sec_fetch_dest == "document" AND sec_fetch_mode == "navigate" 
    AND sec_fetch_site == "none" AND request_is_api_call)
  THEN flag_as_suspicious  // Real browsers don't send these for API calls
```

#### 2. Rust TLS Fingerprint
- Uses `reqwest` → `hyper` → `rustls` or `native-tls`
- TLS ClientHello fingerprint is distinctive
- JA3/JA3S fingerprinting can identify Rust clients

#### 3. Predictable Scanner Order (runner.rs:build_scanners)
```rust
// Always runs in this order:
if config.toggles.cors { scanners.push(CorsScanner); }
if config.toggles.csp { scanners.push(CspScanner); }
if config.toggles.graphql { scanners.push(GraphqlScanner); }
if config.toggles.api_security { scanners.push(ApiSecurityScanner); }
// ...
```

**Detection:**
- CORS probes always come first
- GraphQL probes always follow
- Debug endpoint probes always in same position

### LOW: Behavioral Patterns

1. **No decoy requests** - Only sends security-testing requests
2. **No legitimate traffic mimicry** - Doesn't replay normal user behavior
3. **Concurrent scanner execution** - All scanners hit same URL simultaneously
4. **No request spacing randomization** - Probes happen in bursts

---

## Stealth Improvement Strategy

### Phase 1: Remove Obvious Markers (CRITICAL - Do First)

#### 1.1 Remove Probe Markers
**File:** `src/scanner/mass_assignment.rs`

**Current:**
```rust
let payload = json!({
    "__ah_probe": "1",  // REMOVE THIS
    "is_admin": true,
    "role": "admin",
    "permissions": ["*"]
});
```

**Fix:**
```rust
// Use realistic field names that blend in
let payload = json!({
    "is_admin": true,
    "role": "admin", 
    "permissions": ["*"]
    // No scanner markers
});
```

**Impact:** Eliminates most obvious detection vector

#### 1.2 Remove Custom Headers
**File:** `src/scanner/mass_assignment.rs`

**Current:**
```rust
let extra = vec![("X-AH-MA-Stage".to_string(), stage.to_string())];
```

**Fix:**
```rust
// Use standard headers or no custom headers
// Store state in scanner instance instead
```

**Impact:** Removes dead giveaway header pattern

#### 1.3 Randomize CORS Origins
**File:** `src/scanner/cors.rs`

**Current:**
```rust
let origins = vec![
    "null",
    "https://evil.com",  // OBVIOUS
    format!("{}://{}", scheme, domain),
    format!("{}://{}.evil.com", scheme, domain),  // OBVIOUS
];
```

**Fix:**
```rust
// Use realistic-looking domains
let origins = vec![
    "null",
    "https://cdn.example.com",
    "https://app.example.com",
    format!("{}://{}", scheme, domain),
    format!("{}://{}.cdn.cloudflare.net", scheme, domain),
    format!("{}://www.{}", scheme, domain),
];
```

**Impact:** Makes CORS testing look like legitimate cross-origin requests

### Phase 2: Randomize Request Patterns (HIGH Priority)

#### 2.1 Randomize Scanner Order
**File:** `src/runner.rs`

**Current:**
```rust
fn build_scanners(config: &Config) -> Vec<Arc<dyn Scanner>> {
    let mut scanners = Vec::new();
    if config.toggles.cors { scanners.push(Arc::new(CorsScanner::new(config))); }
    if config.toggles.csp { scanners.push(Arc::new(CspScanner::new(config))); }
    // ... always same order
    scanners
}
```

**Fix:**
```rust
use rand::seq::SliceRandom;

fn build_scanners(config: &Config) -> Vec<Arc<dyn Scanner>> {
    let mut scanners = Vec::new();
    // ... build scanners ...
    
    // Randomize order
    let mut rng = rand::thread_rng();
    scanners.shuffle(&mut rng);
    
    scanners
}
```

**Impact:** Breaks predictable scanner sequence detection

#### 2.2 Add Request Spacing Randomization
**File:** `src/scanner/cors.rs`, `graphql.rs`, etc.

**Current:**
```rust
for origin in &probe_origins {
    client.get_with_headers(url, &extra).await;  // Immediate succession
}
```

**Fix:**
```rust
for origin in &probe_origins {
    client.get_with_headers(url, &extra).await;
    
    // Random delay between probes (0.5s to 3s)
    if config.waf_evasion.enabled {
        let delay_ms = rand::thread_rng().gen_range(500..3000);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}
```

**Impact:** Breaks burst detection patterns

#### 2.3 Randomize Path Probe Order
**File:** `src/scanner/graphql.rs`, `api_security.rs`

**Current:**
```rust
static GQL_PATHS: &[&str] = &[
    "/graphql", "/graphiql", "/api/graphql",  // Always same order
];
```

**Fix:**
```rust
fn get_shuffled_gql_paths() -> Vec<&'static str> {
    let mut paths = GQL_PATHS.to_vec();
    let mut rng = rand::thread_rng();
    paths.shuffle(&mut rng);
    paths
}
```

**Impact:** Prevents wordlist fingerprinting

#### 2.4 Limit Probes Per Endpoint
**File:** `src/scanner/cors.rs`

**Current:**
```rust
// Tests 5+ origins + bypass attempts = 10+ requests per endpoint
```

**Fix:**
```rust
// Add config option: --max-probes-per-check
// Randomly sample from probe list instead of testing all
let sample_size = config.max_probes_per_check.unwrap_or(3);
let sampled_origins: Vec<_> = probe_origins
    .choose_multiple(&mut rng, sample_size)
    .collect();
```

**Impact:** Reduces request volume and detection surface

### Phase 3: Add Decoy Traffic (MEDIUM Priority)

#### 3.1 Inject Legitimate-Looking Requests
**File:** `src/http_client.rs`

**New feature:**
```rust
pub struct DecoyConfig {
    pub enabled: bool,
    pub frequency: f64,  // 0.0 to 1.0 (% of requests that are decoys)
    pub paths: Vec<String>,  // Common legitimate paths
}

impl HttpClient {
    async fn maybe_send_decoy(&self, config: &DecoyConfig) {
        if !config.enabled {
            return;
        }
        
        let mut rng = rand::thread_rng();
        if rng.gen::<f64>() > config.frequency {
            return;
        }
        
        // Send a legitimate-looking request
        let path = config.paths.choose(&mut rng).unwrap();
        let _ = self.get(path).await;
    }
}
```

**Usage:**
```rust
// Before each scanner probe
client.maybe_send_decoy(&config.decoy).await;
client.get_with_headers(url, &extra).await;
```

**Impact:** Dilutes scanner traffic with normal-looking requests

#### 3.2 Mimic Browser Behavior
**File:** `src/waf.rs`

**New feature:**
```rust
pub async fn browser_like_sequence(client: &HttpClient, base_url: &str) {
    // 1. Fetch main page
    let _ = client.get(base_url).await;
    tokio::time::sleep(Duration::from_millis(rand::thread_rng().gen_range(100..500))).await;
    
    // 2. Fetch common assets
    let _ = client.get(&format!("{}/favicon.ico", base_url)).await;
    tokio::time::sleep(Duration::from_millis(rand::thread_rng().gen_range(50..200))).await;
    
    let _ = client.get(&format!("{}/robots.txt", base_url)).await;
    tokio::time::sleep(Duration::from_millis(rand::thread_rng().gen_range(100..300))).await;
}
```

**Impact:** Makes initial traffic look like a real browser

### Phase 4: Randomize Headers (MEDIUM Priority)

#### 4.1 Dynamic Header Generation
**File:** `src/waf.rs`

**Current:**
```rust
pub fn evasion_headers() -> HeaderMap {
    let mut map = HeaderMap::new();
    // ... static headers
}
```

**Fix:**
```rust
pub fn evasion_headers() -> HeaderMap {
    let mut map = HeaderMap::new();
    let mut rng = rand::thread_rng();
    
    // Randomize Accept-Language
    let languages = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "en-US,en;q=0.5,fr;q=0.3"];
    map.insert("accept-language", languages.choose(&mut rng).unwrap().parse().unwrap());
    
    // Randomize DNT (some browsers send it, some don't)
    if rng.gen_bool(0.7) {
        map.insert("dnt", "1".parse().unwrap());
    }
    
    // Vary sec-fetch-* based on request type
    // For API calls, use "empty" or "cors" instead of "document"
    map.insert("sec-fetch-dest", "empty".parse().unwrap());
    map.insert("sec-fetch-mode", "cors".parse().unwrap());
    map.insert("sec-fetch-site", "same-origin".parse().unwrap());
    
    // Randomize header order (some WAFs fingerprint this)
    // ... implementation
    
    map
}
```

**Impact:** Breaks static header fingerprinting

#### 4.2 Context-Aware Headers
**File:** `src/http_client.rs`

**New feature:**
```rust
fn headers_for_request_type(request_type: RequestType) -> HeaderMap {
    match request_type {
        RequestType::PageLoad => {
            // sec-fetch-dest: document
            // sec-fetch-mode: navigate
        }
        RequestType::ApiCall => {
            // sec-fetch-dest: empty
            // sec-fetch-mode: cors
        }
        RequestType::Asset => {
            // sec-fetch-dest: image/script/style
            // sec-fetch-mode: no-cors
        }
    }
}
```

**Impact:** Makes headers match request context (more realistic)

### Phase 5: Advanced Evasion (LOW Priority - Complex)

#### 5.1 Traffic Shaping
**File:** `src/runner.rs`

**New feature:**
```rust
pub struct TrafficShapingConfig {
    pub mode: TrafficMode,
    pub duration: Duration,
}

pub enum TrafficMode {
    Burst,           // Fast scanning (current behavior)
    Steady,          // Constant rate over time
    Organic,         // Mimics human browsing (random pauses)
    Stealth,         // Very slow, spread over hours/days
}

impl TrafficMode {
    fn delay_between_requests(&self) -> Duration {
        match self {
            Burst => Duration::from_millis(150),
            Steady => Duration::from_secs(1),
            Organic => Duration::from_millis(rand::thread_rng().gen_range(500..5000)),
            Stealth => Duration::from_secs(rand::thread_rng().gen_range(30..300)),
        }
    }
}
```

**Impact:** Allows user to choose speed vs stealth trade-off

#### 5.2 Session Persistence
**File:** `src/http_client.rs`

**New feature:**
```rust
// Maintain cookies across requests like a real browser
// Currently partially implemented via session_file
// Enhance to:
// - Store cookies per-domain
// - Respect cookie expiry
// - Send cookies on subsequent requests
// - Handle Set-Cookie properly
```

**Impact:** Makes scanner look like persistent browser session

#### 5.3 Referer Chain Building
**File:** `src/http_client.rs`

**New feature:**
```rust
pub struct RefererChain {
    history: Vec<String>,
}

impl RefererChain {
    pub fn next_referer(&mut self, current_url: &str) -> Option<String> {
        let referer = self.history.last().cloned();
        self.history.push(current_url.to_string());
        if self.history.len() > 10 {
            self.history.remove(0);
        }
        referer
    }
}

// Add Referer header based on previous request
if let Some(referer) = referer_chain.next_referer(url) {
    headers.insert("referer", referer.parse().unwrap());
}
```

**Impact:** Creates realistic browsing history trail

#### 5.4 TLS Fingerprint Randomization
**File:** `src/http_client.rs`

**Complex - requires custom TLS implementation:**
```rust
// Use boring-ssl or custom TLS to randomize:
// - Cipher suite order
// - Extension order
// - TLS version preferences
// - ALPN protocols
// Goal: Mimic different browsers' TLS fingerprints
```

**Impact:** Defeats JA3/JA3S fingerprinting

---

## Implementation Roadmap

### Sprint 1: Critical Fixes (1-2 days)
**Goal:** Remove obvious detection vectors

- [ ] Remove `__ah_probe` marker from mass assignment scanner
- [ ] Remove `X-AH-*` custom headers
- [ ] Replace `evil.com` with realistic domains in CORS scanner
- [ ] Add `--stealth-mode` flag to enable all stealth features

**Files to modify:**
- `src/scanner/mass_assignment.rs`
- `src/scanner/cors.rs`
- `src/cli.rs` (add flag)
- `src/config.rs` (add config field)

**Testing:**
- Run against test WAF
- Verify no obvious markers in traffic
- Confirm functionality still works

### Sprint 2: Pattern Randomization (2-3 days)
**Goal:** Break predictable patterns

- [ ] Randomize scanner execution order
- [ ] Add inter-probe delays (configurable)
- [ ] Randomize path probe order
- [ ] Implement probe sampling (limit requests per check)

**Files to modify:**
- `src/runner.rs`
- `src/scanner/cors.rs`
- `src/scanner/graphql.rs`
- `src/scanner/api_security.rs`
- `src/discovery/common_paths.rs`

**Testing:**
- Verify scanner order changes between runs
- Measure timing variance
- Confirm reduced request volume

### Sprint 3: Header Randomization (2-3 days)
**Goal:** Break static fingerprints

- [ ] Implement dynamic header generation
- [ ] Add context-aware sec-fetch-* headers
- [ ] Randomize Accept-Language
- [ ] Randomize DNT presence
- [ ] Implement header order randomization

**Files to modify:**
- `src/waf.rs`
- `src/http_client.rs`

**Testing:**
- Capture traffic and verify header variance
- Test against header-fingerprinting WAFs

### Sprint 4: Decoy Traffic (3-4 days)
**Goal:** Dilute scanner traffic

- [ ] Implement decoy request injection
- [ ] Add browser-like sequence generator
- [ ] Create legitimate path database
- [ ] Add configurable decoy frequency

**Files to modify:**
- `src/http_client.rs`
- `src/waf.rs`
- `src/config.rs`

**Testing:**
- Verify decoy/scanner ratio
- Measure performance impact
- Test against behavioral analysis WAFs

### Sprint 5: Traffic Shaping (2-3 days)
**Goal:** Allow speed/stealth trade-offs

- [ ] Implement traffic modes (Burst/Steady/Organic/Stealth)
- [ ] Add time-based spreading
- [ ] Implement pause/resume capability
- [ ] Add progress estimation for slow modes

**Files to modify:**
- `src/runner.rs`
- `src/config.rs`
- `src/cli.rs`

**Testing:**
- Verify timing in each mode
- Test long-running scans
- Measure detection rates

### Sprint 6: Advanced Features (Optional - 5+ days)
**Goal:** Maximum stealth

- [ ] Session persistence enhancement
- [ ] Referer chain building
- [ ] TLS fingerprint randomization (complex)
- [ ] Request replay from HAR files
- [ ] ML-based traffic mimicry

---

## Trade-offs & Considerations

### Performance vs Stealth

| Feature | Speed Impact | Stealth Gain | Recommended |
|---------|--------------|--------------|-------------|
| Remove probe markers | None | Critical | ✅ Always |
| Randomize scanner order | None | High | ✅ Always |
| Inter-probe delays | -50% to -90% | High | ✅ Stealth mode |
| Probe sampling | +50% speed | Medium | ✅ Stealth mode |
| Decoy traffic | -20% to -50% | Medium | ⚠️ Optional |
| Header randomization | None | Medium | ✅ Always |
| Traffic shaping (Organic) | -80% | High | ⚠️ User choice |
| Traffic shaping (Stealth) | -95% | Very High | ⚠️ User choice |

### Detection Risk vs Coverage

**Current (Fast mode):**
- Detection risk: HIGH
- Coverage: 100%
- Time: Fast (minutes)

**Stealth mode (recommended):**
- Detection risk: MEDIUM
- Coverage: 80% (probe sampling)
- Time: Moderate (10-30 minutes)

**Ultra-stealth mode:**
- Detection risk: LOW
- Coverage: 60% (heavy sampling)
- Time: Slow (hours to days)

### Configuration Recommendations

#### For Internal/Staging (Current behavior is fine)
```bash
./api-scanner --urls targets.txt \
  --concurrency 20 \
  --delay-ms 150
```

#### For Production (Cooperative testing)
```bash
./api-scanner --urls targets.txt \
  --stealth-mode \
  --concurrency 5 \
  --delay-ms 1000 \
  --traffic-mode steady
```

#### For Red Team (Maximum stealth)
```bash
./api-scanner --urls targets.txt \
  --stealth-mode \
  --concurrency 1 \
  --delay-ms 5000 \
  --traffic-mode organic \
  --decoy-frequency 0.3 \
  --max-probes-per-check 2
```

---

## Conclusion

### Priority Order

1. **CRITICAL (Do immediately):**
   - Remove `__ah_probe` and custom headers
   - Replace obvious attack domains
   - Randomize scanner order

2. **HIGH (Do soon):**
   - Add inter-probe delays
   - Randomize path order
   - Implement probe sampling
   - Randomize headers

3. **MEDIUM (Nice to have):**
   - Decoy traffic
   - Traffic shaping modes
   - Context-aware headers

4. **LOW (Advanced):**
   - TLS fingerprint randomization
   - ML-based mimicry
   - Session persistence

### Expected Outcomes

**After Sprint 1-2 (Critical + Pattern fixes):**
- Detection time: 30s → 5-10 minutes
- False positive rate for WAFs: 80% → 40%
- Suitable for: Staging environments, cooperative testing

**After Sprint 3-4 (Headers + Decoys):**
- Detection time: 5-10 minutes → 30-60 minutes
- False positive rate: 40% → 20%
- Suitable for: Production (with permission), bug bounty

**After Sprint 5-6 (Traffic shaping + Advanced):**
- Detection time: 30-60 minutes → Hours to days
- False positive rate: 20% → 5-10%
- Suitable for: Red team engagements, adversarial testing

### Honest Assessment

Even with all improvements, ApiHunter will NEVER be as stealthy as:
- Manual testing by skilled pentester
- Custom scripts tailored to specific target
- Tools designed specifically for stealth (e.g., slow HTTP scanners)

But it CAN be:
- Much better than current state
- Competitive with other automated scanners
- Suitable for most real-world scenarios with proper configuration

The key is giving users CHOICE between speed and stealth, not claiming to be "stealth-first" by default.
