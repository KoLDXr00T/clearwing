# 1Password $1M CTF — Clearwing Assessment & Plan

## 1. CTF Goals

### Target

A secure note containing "bad poetry" stored in a dedicated 1Password Bug Bounty
CTF account at `bugbounty-ctf.1password.com`. The note is protected by the full
1Password security stack: SRP authentication, two-secret key derivation (2SKD),
AES-256-GCM vault encryption, and TLS transport.

### Win condition

Recover the plaintext content of the secure note and submit the steps used to
capture it via HackerOne.

### Constraints

- No known vulnerabilities or starting point — this is a live, hardened production
  system with a purpose-built CTF account.
- No phishing, malware, or compromise of real 1Password member accounts.
- Only the `bugbounty-ctf.1password.com` scope is in play.
- Partial theories and collaboration are welcome via `bugbounty@agilebits.com`.

### What we need to break

At least one of the following must fail for the flag to be recoverable:

| Layer | Protection | What a break looks like |
|-------|-----------|------------------------|
| **Authentication** | SRP-6a + 2SKD (account password × Secret Key) | Bypass or forge SRP verifier; recover both secrets; exploit protocol flaw |
| **Key derivation** | PBKDF2-HMAC-SHA256 (100k+ iterations) + 128-bit Secret Key XOR | Reduce keyspace; side-channel leak of derived key; skip KDF entirely |
| **Vault encryption** | AES-256-GCM per-item, keys wrapped by personal keyset | Recover AUK or vault key; forge AEAD tag; exploit key hierarchy |
| **Transport** | TLS 1.3 + HSTS | MITM; downgrade; certificate substitution |
| **Server-side** | Access control, encrypted blob storage | Server-side bug (IDOR, authz bypass, API logic flaw) exposes encrypted or plaintext vault data |
| **Key distribution** | Public-key encryption (no user-to-user verification) | MITM on public key exchange; server substitutes attacker key |
| **Web client** | JavaScript delivered over TLS | Tamper with client delivery; exploit browser-side weakness; XSS in client app |

The white paper's "Beware of the Leopard" appendix (Appendix A) explicitly
acknowledges weaknesses in several of these layers. Those are the most
productive starting points.


## 2. Existing Clearwing Features That Apply

### 2.1 Browser Automation (recon/browser_tools)

**Relevance: HIGH** — the web client is the #1 acknowledged attack surface.

Playwright-based headless Chromium with:
- `browser_navigate` / `browser_get_html` / `browser_get_content` — load the
  login page, extract the full JavaScript bundle, map the authentication flow
- `browser_execute_js` — execute arbitrary JavaScript in the page context to:
  - Hook `SubtleCrypto` (`crypto.subtle.importKey`, `deriveBits`, `encrypt`,
    `decrypt`) and log every call with arguments
  - Intercept the SRP handshake values (A, B, M1, M2, salt, iteration count)
  - Inspect IndexedDB / localStorage for cached key material
  - Monkey-patch the fetch/XHR layer to log all API traffic with bodies
- `browser_get_cookies` / `browser_set_cookie` — extract session tokens, test
  session fixation, inject modified auth state
- `browser_fill` / `browser_click` — automate the login flow end-to-end

**Limitations:** Output truncated to 10k chars. Requires human approval for JS
execution. No persistent browser profile across sessions.

### 2.2 HTTP Proxy (recon/proxy_tools)

**Relevance: MEDIUM** — useful for API-level probing, not for TLS interception.

- `proxy_request` — send crafted HTTP requests to 1Password API endpoints;
  enumerate `/api/v*` routes; probe for IDOR, authz bypass, or undocumented
  endpoints
- `proxy_replay` — capture a legitimate SRP handshake then replay with modified
  parameters (malformed A value, zero-value SRP parameters, truncated proofs)
- `proxy_get_history` / `proxy_export_history` — review all API traffic for
  patterns, timing differences, or information leakage

**Limitations:** Not a true intercepting proxy — uses `urllib.request`, not a
MITM setup. Cannot decrypt TLS. Cannot inspect certificate chains. Cannot
perform SSL stripping. Far weaker than Burp Suite or mitmproxy for protocol
analysis.

### 2.3 Source Code Hunter (sourcehunt/)

**Relevance: MEDIUM** — conditional on open-source components being in scope.

1Password has several public repositories. The sourcehunt pipeline can:
- Clone, preprocess, and rank files by attack surface and attacker reachability
- Deploy the `crypto_primitive` specialist hunter to look for timing side
  channels, nonce reuse, key lifecycle failures, MAC-before-decrypt, weak PRNG
- Adversarially verify findings; generate and validate PoCs in sandboxed
  containers with ASan/UBSan
- Run variant detection to find the same bug class across the codebase

The hunter's system prompt already includes detailed guidance for:
- Timing side channels (`memcmp`/`strcmp` on secrets → CWE-208)
- IV/nonce reuse (static IVs for AES-GCM → CWE-323)
- Key lifecycle (no `memset_s`/`explicit_bzero` → CWE-327)
- MAC verification order (MAC after decrypt → padding oracle → CWE-354)
- Weak PRNG (`rand()`/`random()` for key material → CWE-338)
- Elliptic curve errors (incomplete point validation, twist attacks → CWE-327)

### 2.4 Kali Docker Container (ops/kali_docker_tool)

**Relevance: MEDIUM** — provides the full offensive toolchain.

- `nmap` with NSE scripts for TLS cipher suite enumeration (`ssl-enum-ciphers`)
  and certificate analysis
- `testssl.sh` for comprehensive TLS configuration audit
- `hashcat` / `john` for offline cracking if key material or hashes are captured
- `openssl s_client` for manual TLS handshake inspection
- `sqlmap`, `nikto`, `dirb` for web application scanning
- Compile and run custom C/Python exploit code

**Limitations:** Requires human approval for every command. No pre-built SRP or
PBKDF2 attack modules — the attacker must supply the logic.

### 2.5 Network Scanning (scan/)

**Relevance: LOW-MEDIUM** — infrastructure reconnaissance.

- `scan_ports` — enumerate open ports on the CTF infrastructure
- `detect_services` — banner grab and fingerprint server software versions
- `scan_vulnerabilities` — cross-reference detected services against NVD
- `detect_os` — TTL-based OS fingerprinting

Useful for initial recon but unlikely to find the path to the flag directly.

### 2.6 Knowledge Graph (data/knowledge/)

**Relevance: MEDIUM** — attack surface mapping and progress tracking.

NetworkX-backed graph that tracks targets → ports → services → CVEs → exploits
with persistence across sessions. Useful for maintaining situational awareness
across a long-running CTF engagement.

### 2.7 CTF Flag Detection (agent/runtime)

**Relevance: LOW** — convenience feature.

Automatic regex matching for `flag{...}`, `CTF{...}`, `HTB{...}`, and 32-char
hex patterns. Will auto-capture the flag if it appears in any tool output. The
1Password flag is described as "bad poetry" — may not match standard patterns.

### 2.8 Dynamic Tool Creation (ops/dynamic_tool_creator)

**Relevance: HIGH** — fills gaps by letting the agent write custom attack tools
at runtime.

`create_custom_tool` generates new Python async functions on the fly with access
to `asyncio`, `json`, `re`, `socket`, `subprocess`. The agent can write
protocol-specific fuzzing tools, custom API clients, or SRP parameter
manipulation scripts without leaving the loop.

### 2.9 Exploit Search (exploit/exploit_search)

**Relevance: LOW** — searches Exploit-DB and NVD for prior art against 1Password
or its dependencies. Unlikely to yield direct results for the CTF but worth
running for completeness.


## 3. High-Level Attack Plan

### Phase 1: Reconnaissance

1. **Infrastructure scan** — `scan_ports` + `detect_services` + `detect_os` on
   `bugbounty-ctf.1password.com` to map the network surface.
2. **TLS audit** — Kali container running `testssl.sh` and `nmap --script
   ssl-enum-ciphers` to identify supported cipher suites, TLS versions,
   certificate details, and potential downgrade paths.
3. **Web client extraction** — `browser_navigate` + `browser_get_html` to
   download the full JavaScript bundle. Identify the SRP library, key derivation
   parameters, encryption routines, and API endpoint paths.
4. **API enumeration** — `proxy_request` to systematically probe API routes:
   `/api/v1/auth`, `/api/v1/vaults`, `/api/v1/items`, and undocumented paths.
   Map request/response schemas, required headers, and error behavior.
5. **Public source analysis** — `hunt_source_code` against 1Password's public
   GitHub repositories to find crypto implementation bugs.
6. **CVE/exploit search** — `search_exploit_db` + `search_cves` for 1Password,
   SRP, PBKDF2, and WebCrypto-related vulnerabilities.

### Phase 2: Protocol Analysis

7. **SRP handshake capture** — `browser_execute_js` to hook the SRP client and
   log: username, salt, iteration count, group parameters (N, g), ephemeral
   values (A, B), proofs (M1, M2), and the session key.
8. **SRP parameter validation** — `proxy_replay` to send edge-case SRP values:
   - A = 0 (classic SRP zero-key attack)
   - A = N (reduces shared secret to zero)
   - A = k*N (multiples of the modulus)
   - Truncated or malformed proofs
   - Invalid salt values
9. **Key derivation inspection** — `browser_execute_js` to hook
   `crypto.subtle.deriveBits` and extract: algorithm, iteration count, salt,
   key length. Verify whether the Secret Key XOR step (2SKD) is correctly
   applied client-side.
10. **WebCrypto API hooking** — instrument `crypto.subtle.encrypt`,
    `crypto.subtle.decrypt`, `crypto.subtle.importKey` to observe key material
    flowing through the browser's crypto stack.

### Phase 3: Attack Execution

11. **Server-side logic bugs** — test for:
    - IDOR on vault/item endpoints (substitute vault IDs, item IDs)
    - Authorization bypass (access CTF vault items with a different account's
      session)
    - Race conditions in vault sharing / key distribution
    - API parameter pollution or type confusion
12. **Public key substitution** — the white paper acknowledges no user-to-user
    public key verification (Appendix A.3). Test whether the server can be
    induced to serve a substitute public key for vault sharing operations.
13. **Recovery group exploitation** — if the CTF account has recovery groups
    configured, test whether recovery flows leak key material or allow
    unauthorized keyset replacement.
14. **Web client tampering** — analyze the JavaScript for:
    - DOM-based XSS that could leak decrypted vault contents
    - Service worker manipulation
    - Cache poisoning of the JavaScript bundle
    - PostMessage handler vulnerabilities
15. **Timing side channels** — measure response times for authentication
    attempts to detect information leakage about username validity, password
    correctness, or Secret Key structure.

### Phase 4: Exploit Development & Validation

16. **Custom tooling** — `create_custom_tool` or Kali container to build
    targeted exploits for any discovered weakness.
17. **PoC development** — document the full attack chain from initial access to
    flag recovery.
18. **Report generation** — compile findings, evidence, and reproduction steps
    for HackerOne submission.


## 4. Features to Add to Clearwing

The following capabilities are missing from Clearwing and would substantially
improve its effectiveness against cryptographic protocol targets like 1Password.

### 4.1 TLS Inspection & Analysis Suite

**Gap:** Clearwing has no ability to inspect TLS handshakes, enumerate cipher
suites, validate certificate chains, or detect downgrade vulnerabilities. The
proxy tools use `urllib.request` — they cannot intercept encrypted traffic.

**Design:**

```
clearwing/agent/tools/scan/tls_tools.py
```

New tool module with:

- **`scan_tls_config(target, port)`** — Connect with `ssl.SSLSocket`, negotiate
  handshake, return: protocol version, cipher suite, key exchange algorithm,
  certificate chain (issuer, subject, SAN, expiry, key size, signature
  algorithm), OCSP stapling status, HSTS header presence.

- **`enumerate_cipher_suites(target, port)`** — Iterate over all cipher suites
  attempting connection with each. Return supported vs. rejected, ordered by
  server preference. Flag weak suites (RC4, DES, export-grade, NULL).

- **`test_tls_downgrade(target, port)`** — Attempt connections at TLS 1.0, 1.1,
  1.2, 1.3 and SSL 3.0. Report which versions are accepted. Test for
  POODLE, DROWN, FREAK, Logjam conditions.

- **`inspect_certificate(target, port)`** — Deep certificate analysis: key
  strength, chain completeness, CT log presence, pinning headers, known
  revocation.

**Dependencies:** `ssl` (stdlib), `cryptography` (for certificate parsing).

**Knowledge graph integration:** New entity types `tls_version`,
`cipher_suite`, `certificate` with relationships `USES_CIPHER`,
`PRESENTS_CERT`, `VULNERABLE_TO_DOWNGRADE`.

### 4.2 SRP Protocol Testing Framework

**Gap:** Clearwing has zero SRP capabilities — no client implementation, no
parameter manipulation, no protocol-level fuzzing.

**Design:**

```
clearwing/agent/tools/crypto/srp_tools.py
clearwing/crypto/srp.py              # Pure-Python SRP-6a implementation
```

Core library (`srp.py`):

- Full SRP-6a client implementation: generate ephemeral keypair (a, A),
  compute session key S and proof M1, verify server proof M2.
- Parameterized: configurable group (N, g), hash function, KDF.
- Instrumented: every intermediate value logged for analysis.

Agent tools (`srp_tools.py`):

- **`srp_handshake(target, username, password, secret_key)`** — Execute a
  complete SRP authentication against the target, returning all intermediate
  values and the session key.

- **`srp_fuzz_parameters(target, username, test_vectors)`** — Send malformed
  SRP values:
  - A = 0, A = N, A = 2N (zero-key attacks)
  - Truncated/oversized salt
  - Wrong group parameters
  - Malformed M1 proof
  Report server responses and detect improper validation.

- **`srp_extract_verifier_info(target, username)`** — Probe the server to
  extract: salt, iteration count, group parameters. Measure response
  differences between valid and invalid usernames.

- **`srp_timing_attack(target, username, samples)`** — Send N authentication
  attempts with controlled inputs, measure response latency at microsecond
  precision. Statistical analysis for timing leaks in username lookup, password
  verification, or proof validation.

**Dependencies:** `gmpy2` or Python `pow()` with modular exponentiation for
big-integer SRP math.

### 4.3 Key Derivation Function Analysis Tools

**Gap:** No tools to analyze PBKDF2 parameters, test key derivation correctness,
or attack weak KDF configurations.

**Design:**

```
clearwing/agent/tools/crypto/kdf_tools.py
```

- **`analyze_kdf_parameters(target)`** — Extract KDF parameters from the
  authentication flow (via SRP handshake or JS hooking): algorithm, iteration
  count, salt length, output key length. Compare against current best
  practices (OWASP minimums).

- **`benchmark_kdf_cracking(algorithm, iterations, key_length)`** — Estimate
  offline attack cost: compute hashes/second on CPU and GPU (via hashcat
  benchmark mode), project time-to-crack for given password entropy.

- **`test_2skd_implementation(target)`** — Verify the two-secret key derivation
  (2SKD) implementation:
  - Is the Secret Key XOR applied after PBKDF2?
  - Is the derived key split correctly into AUK and SRP-x?
  - Does changing the password produce a new AUK (and does it NOT produce a
    new keyset, per the white paper)?

- **`kdf_oracle_test(target, samples)`** — Test whether the server leaks
  information about KDF correctness through response timing, error messages,
  or behavioral differences.

**Dependencies:** `hashlib` (stdlib), `cryptography` (for HKDF).

### 4.4 MITM Proxy with TLS Interception

**Gap:** The current proxy is a simple HTTP client with request logging. It
cannot intercept live traffic, inspect encrypted payloads, or modify requests
in flight. This is the single largest tooling gap vs. Burp Suite.

**Design:**

```
clearwing/agent/tools/recon/mitm_proxy.py
clearwing/proxy/                      # Core proxy engine
clearwing/proxy/ca.py                 # Certificate authority
clearwing/proxy/interceptor.py        # Request/response hooks
```

Architecture:

1. **CA module** (`ca.py`) — Generate a root CA certificate on first run, store
   in `~/.clearwing/ca/`. Generate per-domain leaf certificates on the fly
   for TLS interception. Export CA cert for browser trust store installation.

2. **Proxy engine** (`interceptor.py`) — Async TCP proxy (built on `asyncio`
   streams) that:
   - Accepts client connections on a configurable local port
   - Performs TLS termination with dynamic certificates
   - Forwards requests to the upstream server over a fresh TLS connection
   - Logs full plaintext request/response pairs to the proxy history
   - Supports request/response modification via hooks

3. **Agent tools** (`mitm_proxy.py`):
   - **`mitm_start(listen_port, upstream_target)`** — Start the intercepting
     proxy. Returns the CA certificate path for browser installation.
   - **`mitm_set_intercept_rule(url_pattern, action, modification)`** — Define
     rules: drop, delay, modify header/body, replace response.
   - **`mitm_get_decrypted_traffic(filter)`** — Query decrypted traffic log
     with filters on URL, method, content type, status code.
   - **`mitm_inject_response(url_pattern, response_body)`** — Serve a
     modified response for matching requests (e.g., substitute a tampered
     JavaScript bundle or a fake public key).

4. **Browser integration** — Configure the Playwright browser context to use
   the local proxy and trust the generated CA certificate, enabling transparent
   interception of all 1Password web client traffic.

**Dependencies:** `cryptography` (CA cert generation), `asyncio` (proxy
engine).

### 4.5 Vault Encryption Analysis Tools

**Gap:** No tools to analyze, parse, or attack 1Password's vault encryption
format — AES-256-GCM with a key hierarchy rooted in the AUK.

**Design:**

```
clearwing/agent/tools/crypto/vault_tools.py
```

- **`parse_vault_blob(encrypted_data)`** — Parse the structure of an encrypted
  vault item: extract IV/nonce, ciphertext, authentication tag, key ID,
  algorithm identifier. Identify the encryption scheme without decryption.

- **`analyze_key_hierarchy(session_data)`** — Given captured session data
  (from browser hooks or MITM), map the key hierarchy: AUK → personal
  keyset → vault keys → item keys. Identify which keys are derived vs.
  wrapped.

- **`test_aead_integrity(encrypted_data, modifications)`** — Attempt
  ciphertext modifications (bit flips, truncation, tag substitution) and
  observe server/client responses. Test for AEAD misuse (nonce reuse,
  associated data omission, tag verification bypass).

- **`key_wrap_analysis(wrapped_keys)`** — Analyze key wrapping scheme: is
  AES-KW used? RSA-OAEP? Are wrapped keys distinguishable? Is there a
  padding oracle in the unwrap path?

**Dependencies:** `cryptography` (AES-GCM, RSA-OAEP primitives for local
testing).

### 4.6 Timing Side-Channel Framework

**Gap:** No systematic timing attack capability. Response time measurement
exists nowhere in the tool chain.

**Design:**

```
clearwing/agent/tools/crypto/timing_tools.py
```

- **`timing_probe(target, request_generator, samples, warmup)`** — Send N
  requests generated by a callback function, measure response time at
  nanosecond precision (using `time.perf_counter_ns`). Return statistical
  summary: mean, median, stddev, percentiles, distribution histogram.

- **`timing_compare(target, request_a_gen, request_b_gen, samples)`** —
  Compare timing distributions of two request types (e.g., valid vs. invalid
  username). Apply Welch's t-test for statistical significance. Report
  whether a timing difference exists and its magnitude.

- **`timing_bitwise_probe(target, base_request, field, charset, position)`** —
  Byte-at-a-time timing attack: for each candidate byte at a given position,
  send N requests and measure response time. Identify the candidate that
  produces the longest (or shortest) response, indicating a correct byte
  match.

**Statistical rigor:** All timing tools should account for network jitter by:
- Running warmup requests to prime caches
- Interleaving A/B samples to cancel drift
- Reporting confidence intervals, not just point estimates
- Supporting configurable outlier rejection (IQR or z-score)

**Dependencies:** `numpy` (statistical analysis), `scipy.stats` (t-test).

### 4.7 Cryptographic Protocol Skill Pack

**Gap:** The skill system has vulnerability-specific playbooks for SQL
injection, XSS, SSRF, etc. — but nothing for cryptographic protocol attacks.

**Design:**

```
clearwing/core/skills/crypto/
├── srp_attacks.md          # SRP-6a attack methodology
├── kdf_analysis.md         # KDF parameter assessment
├── padding_oracle.md       # CBC padding oracle exploitation
├── aead_misuse.md          # AES-GCM nonce reuse, tag forgery
├── key_hierarchy.md        # Key wrapping and derivation attacks
├── tls_assessment.md       # TLS configuration testing playbook
└── timing_attacks.md       # Side-channel timing methodology
```

Each skill provides the agent with:
- Attack theory (what the vulnerability is and why it works)
- Detection methodology (what to look for)
- Exploitation steps (ordered tool invocations)
- Validation criteria (how to confirm the attack succeeded)
- Known mitigations (what a secure implementation looks like)

Example excerpt from `srp_attacks.md`:
```
## SRP Zero-Key Attack
If the server does not validate that A % N != 0, the client can send A = 0
(or any multiple of N), causing the shared secret S to equal zero regardless
of the password. The session key K = H(S) becomes a known constant.

### Detection
1. srp_fuzz_parameters(target, username, [{A: "0"}])
2. If server accepts and returns M2, the implementation is vulnerable.

### Exploitation
1. Compute K = H(0)
2. Use K to decrypt vault key hierarchy
3. Decrypt vault items with recovered keys
```

### 4.8 WebCrypto Instrumentation Module

**Gap:** While `browser_execute_js` can run arbitrary JavaScript, there is no
pre-built instrumentation for WebCrypto. The agent must write hooking code from
scratch every time, which is error-prone and wastes tokens.

**Design:**

```
clearwing/agent/tools/recon/webcrypto_hooks.py
clearwing/static/webcrypto_instrument.js   # Injected JS payload
```

Pre-built JavaScript instrumentation (`webcrypto_instrument.js`):

```javascript
// Wraps all SubtleCrypto methods with logging
const original = crypto.subtle;
const hooked = {};
for (const method of ['encrypt','decrypt','sign','verify',
    'digest','generateKey','deriveKey','deriveBits',
    'importKey','exportKey','wrapKey','unwrapKey']) {
  hooked[method] = async function(...args) {
    const result = await original[method].apply(original, args);
    window.__clearwing_crypto_log.push({
      method, args: serializeArgs(args), timestamp: performance.now()
    });
    return result;
  };
}
```

Agent tools (`webcrypto_hooks.py`):

- **`install_webcrypto_hooks(tab_name)`** — Inject the instrumentation script
  into the page. Returns confirmation.

- **`get_webcrypto_log(tab_name, filter)`** — Retrieve captured crypto
  operations, optionally filtered by method name. Returns structured data
  with arguments, timing, and (where safe) key material.

- **`extract_srp_values(tab_name)`** — Parse the crypto log to extract SRP
  handshake values: salt, iteration count, A, B, M1, M2, session key.

- **`extract_key_hierarchy(tab_name)`** — Parse the crypto log to reconstruct
  the key derivation chain: password → PBKDF2 → AUK → keyset decryption →
  vault key unwrapping.

### 4.9 Knowledge Graph Extensions for Crypto

**Gap:** The knowledge graph has no entity types for cryptographic protocols,
algorithms, or key material. It cannot model the relationships that matter for
a crypto-focused engagement.

**Design:**

New entity types:
- `protocol` — SRP, TLS, OAuth, HKDF, AES-KW
- `algorithm` — AES-256-GCM, PBKDF2-HMAC-SHA256, RSA-OAEP, X25519
- `key_material` — AUK, vault key, personal keyset, SRP verifier, Secret Key
- `certificate` — TLS leaf cert, intermediate, root CA
- `kdf_config` — algorithm + iteration count + salt length + output length

New relationship types:
- `USES_ALGORITHM` — protocol → algorithm
- `DERIVES_KEY` — kdf_config → key_material
- `WRAPS_KEY` — key_material → key_material
- `DECRYPTS` — key_material → encrypted blob
- `AUTHENTICATES_WITH` — protocol → key_material
- `PRESENTS_CERT` — target → certificate
- `VULNERABLE_TO` — algorithm/protocol → attack technique

This allows queries like:
- "What key material is derived from the account password?"
- "What algorithms does the SRP handshake use?"
- "Show the full key chain from password to vault decryption"

### 4.10 Findings Schema Extensions

**Gap:** The Finding dataclass has no fields for cryptographic weaknesses. A
timing side channel and a SQL injection are represented identically.

**Design:**

Add optional fields to `clearwing/findings/types.py`:

```python
# Crypto-specific fields
protocol: Optional[str]           # "SRP-6a", "TLS 1.3", "AES-KW"
algorithm: Optional[str]          # "PBKDF2-HMAC-SHA256", "AES-256-GCM"
crypto_attack_class: Optional[str] # "timing_side_channel", "parameter_validation",
                                   # "nonce_reuse", "padding_oracle", "downgrade"
key_material_exposed: Optional[str] # Description of what key material is at risk
crypto_evidence: Optional[dict]    # Timing measurements, parameter dumps, etc.
```

Extend the evidence ladder with crypto-specific levels:

```python
evidence_level: Literal[
    "suspicion",
    "static_corroboration",
    "parameter_anomaly",        # NEW: KDF iterations too low, weak group
    "timing_confirmed",         # NEW: Statistically significant timing leak
    "crash_reproduced",
    "root_cause_explained",
    "assumption_broken",        # NEW: Crypto assumption violated (e.g., S=0)
    "exploit_demonstrated",
    "key_material_recovered",   # NEW: Actual key material obtained
    "patch_validated",
]
```

### 4.11 Authentication Flow Recorder

**Gap:** Analyzing a multi-step authentication protocol requires capturing the
full sequence of requests, responses, and client-side computation. Currently
each tool captures one piece — there is no unified view.

**Design:**

```
clearwing/agent/tools/recon/auth_recorder.py
```

- **`record_auth_flow(target, credentials, tab_name)`** — Orchestrate a full
  authentication attempt while simultaneously:
  1. Installing WebCrypto hooks in the browser
  2. Routing browser traffic through the MITM proxy
  3. Logging all API requests/responses with decrypted bodies
  4. Capturing all client-side crypto operations with timing

  Returns a unified `AuthFlowRecord`:
  ```python
  @dataclass
  class AuthFlowRecord:
      steps: list[AuthStep]       # Ordered request/response pairs
      crypto_ops: list[CryptoOp]  # Client-side crypto with timing
      srp_values: SRPValues       # Extracted SRP parameters
      kdf_config: KDFConfig       # Extracted KDF parameters
      session_tokens: dict        # Resulting session state
      timing: dict                # Per-step latency measurements
  ```

- **`diff_auth_flows(flow_a, flow_b)`** — Compare two recorded flows
  (e.g., correct password vs. wrong password) and highlight differences in
  server responses, timing, crypto operations, and error messages.

- **`replay_auth_flow(record, modifications)`** — Replay a recorded flow with
  selective modifications to specific steps (e.g., change SRP parameter A in
  step 3, observe what changes downstream).

### 4.12 Password & Secret Key Attack Tools

**Gap:** The existing `crack_password` tool is an online dictionary attack with
20 default passwords. It is useless against a system protected by 2SKD where
offline attacks require both the account password and the 128-bit Secret Key.

**Design:**

```
clearwing/agent/tools/crypto/credential_tools.py
```

- **`analyze_2skd_entropy()`** — Calculate the effective keyspace of the
  combined (password × Secret Key) system. Report: password entropy estimate,
  Secret Key entropy (128 bits), combined entropy, estimated cost to brute
  force at various GPU price points.

- **`test_secret_key_validation(target, username, password, malformed_keys)`**
  — Send authentication attempts with known-correct password but malformed
  Secret Keys to test server-side validation: does the server distinguish
  "wrong password" from "wrong Secret Key"? Information leakage here could
  allow attacking each factor independently.

- **`enumerate_secret_key_format(target)`** — Probe the enrollment and
  authentication endpoints to determine Secret Key format, length, character
  set, and structure. Identify whether any portion is predictable (e.g.,
  account UUID prefix).

- **`offline_crack_setup(captured_data, wordlist, hashcat_mode)`** — Given
  captured SRP verifier data or PBKDF2 parameters, generate a hashcat command
  line (or wrapper script) for GPU-accelerated offline cracking. Estimate
  time-to-crack based on `hashcat --benchmark` results.


## 5. Implementation Priority

Ranked by expected impact on the 1Password CTF specifically:

| Priority | Feature | Rationale |
|----------|---------|-----------|
| **P0** | WebCrypto Instrumentation (4.8) | Fastest path to understanding the client-side crypto — captures every key derivation, encryption, and SRP operation without reverse-engineering the JS bundle |
| **P0** | SRP Protocol Testing (4.2) | The authentication protocol is the front door; parameter validation bugs (zero-key) are the most likely class of exploitable weakness |
| **P0** | Auth Flow Recorder (4.11) | Unifies browser hooks + proxy + timing into a single observable flow — eliminates manual correlation |
| **P1** | MITM Proxy (4.4) | Enables full visibility into encrypted API traffic; required for many downstream attack tools |
| **P1** | Timing Side-Channel Framework (4.6) | The white paper acknowledges WebCrypto forces PBKDF2 (not Argon2) — timing attacks on the KDF or SRP are plausible |
| **P1** | TLS Inspection (4.1) | Validates transport security claims; identifies downgrade paths |
| **P1** | Crypto Skill Pack (4.7) | Gives the agent structured attack methodology for crypto protocols — prevents flailing |
| **P2** | KDF Analysis Tools (4.3) | Important but secondary — the KDF is likely correctly parameterized |
| **P2** | Vault Encryption Analysis (4.5) | Only reachable after breaking authentication or key derivation |
| **P2** | Knowledge Graph Extensions (4.9) | Organizational — valuable for long engagements but not blocking |
| **P2** | Findings Schema Extensions (4.10) | Reporting quality — not blocking for the CTF itself |
| **P3** | Credential Attack Tools (4.12) | 2SKD makes brute force infeasible by design; these tools validate that assumption rather than break it |
