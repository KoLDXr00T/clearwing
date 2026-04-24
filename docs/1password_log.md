# 1Password CTF — Engagement Log

## Step 1.1 — Infrastructure Scan

**Date:** 2026-04-23
**Target:** bugbounty-ctf.1password.com
**Scan:** Full port scan (1-65535), 500 threads

### Open Ports

| Port | Protocol | Service | Banner |
|------|----------|---------|--------|
| 80 | tcp | HTTP | `awselb/2.0` — returns 403 Forbidden |
| 443 | tcp | HTTPS | `awselb/2.0` — returns 400 (plain HTTP probe to TLS port) |

All other ports (1-65535) closed or filtered.

### Infrastructure

- Behind **AWS Elastic Load Balancer** (`awselb/2.0`)
- No direct access to application servers
- Port 80 returns `403 Forbidden` with body "HTTP Forbidden" — HTTP access blocked, forces HTTPS
- OS fingerprint: Unknown (ELB masks backend)

### False Positives

The NVD scanner flagged two CVEs by generic string match against "HTTP" — neither applies:
- CVE-2017-9788 (Apache httpd mod_http2) — server is awselb, not Apache
- CVE-2017-5638 (Apache Struts RCE) — no Struts in evidence

### Assessment

Minimal attack surface. Only standard web ports exposed, both behind AWS ELB.
No SSH, no database ports, no admin interfaces, no non-standard services.
The engagement proceeds entirely through the HTTPS endpoint on port 443.


## Step 1.2 — TLS Configuration Audit

**Date:** 2026-04-23

### Protocol Versions

| Version | Accepted | Cipher Negotiated | Bits |
|---------|----------|-------------------|------|
| TLS 1.3 | Yes | TLS_AES_128_GCM_SHA256 | 128 |
| TLS 1.2 | Yes | ECDHE-RSA-AES128-GCM-SHA256 | 128 |
| TLS 1.1 | **No** | — | — |
| TLS 1.0 | **No** | — | — |

No downgrade to TLS 1.1 or 1.0. POODLE, BEAST, and legacy protocol attacks are
not applicable.

### Cipher Suites Accepted

**TLS 1.3** (1 suite):
- `TLS_AES_128_GCM_SHA256` (128-bit)

**TLS 1.2** (4 suites):
- `ECDHE-RSA-AES256-GCM-SHA384` (256-bit)
- `ECDHE-RSA-AES128-GCM-SHA256` (128-bit)
- `ECDHE-RSA-AES256-SHA384` (256-bit)
- `ECDHE-RSA-AES128-SHA256` (128-bit)

**Weak ciphers:** None. No RC4, DES, 3DES, export-grade, or NULL suites. All
suites use ECDHE for forward secrecy.

**Note:** TLS 1.3 only negotiated AES-128-GCM, not AES-256-GCM or
CHACHA20-POLY1305. This is likely an AWS ELB default preference — not a
vulnerability, but worth noting that the server prefers 128-bit over 256-bit.

### Certificate

| Field | Value |
|-------|-------|
| Subject | `CN=1password.com` |
| Issuer | `CN=Amazon RSA 2048 M01, O=Amazon, C=US` |
| Key | RSA 2048-bit |
| Signature | SHA-256 with RSA |
| Valid from | 2026-01-22 |
| Valid until | 2027-02-20 |
| Days remaining | 302 |
| SANs | `1password.com`, `*.1password.com` |
| OCSP | `http://ocsp.r2m01.amazontrust.com` |
| Version | v3 |

Wildcard cert covering all `*.1password.com` subdomains. Amazon-issued (ACM).
RSA 2048 is the minimum recommended key size — adequate but not exceptional.
No ECC key.

### Security Headers

The root path (`/`) returns `403` from the ELB with minimal headers:
- `x-content-type-options: nosniff` — present
- `Strict-Transport-Security` — **absent** on the 403 response
- `Content-Security-Policy` — **absent**
- `X-Frame-Options` — **absent**
- `Server` header — **absent** (good, no server fingerprinting)

The missing HSTS on the 403 is likely because the ELB default page doesn't
set it. The actual application pages (login, vault UI) may set HSTS separately.
This should be verified in Step 1.3 (Web Client Extraction).

### Assessment

TLS configuration is solid:
- No protocol downgrade path (TLS 1.1/1.0 rejected)
- All cipher suites use AEAD modes with ECDHE forward secrecy
- No weak or deprecated ciphers
- Certificate is valid, properly chained, with appropriate SANs

Minor observations (not vulnerabilities):
- RSA-2048 key (minimum recommended; EC P-256 or RSA-4096 would be stronger)
- TLS 1.3 prefers AES-128-GCM over AES-256-GCM
- HSTS not observed on ELB 403 page — **confirmed present on application pages**
  (see Step 1.3)


## Step 1.3 — Web Client Extraction

**Date:** 2026-04-23

### Application Structure

The root URL (`/`) serves the full SPA. All paths (`/signin`, `/sign-in`,
`/login`, `/app`) return the same shell HTML — client-side routing. The `/app`
path returns a slightly different CSP (more restrictive).

- **Build version:** `data-version="2248"`
- **Git revision:** `data-gitrev="33a8e241e543"`
- **Build time:** 23 Apr 26 18:49 +0000 (same day as our scan)
- **Environment:** `prd` (production)
- **Canonical URL:** `https://my.1password.com/`
- **Sibling domains:** `1password.ca`, `1password.eu`, `ent.1password.com`

### JavaScript Bundles

All served from `https://app.1password.com/` with SRI integrity hashes:

| Bundle | Hash (truncated) | Purpose |
|--------|-------------------|---------|
| `runtime-62c8ad17.min.js` | `sha384-lnpYOr...` | Webpack runtime |
| `vendor-1password-383fec46.min.js` | `sha384-ps/sIb...` | 1Password core library |
| `vendor-other-8afa0afd.min.js` | `sha384-yTVzGZ...` | Third-party deps |
| `vendor-react-7f2b22fd.min.js` | `sha384-AxAeyL...` | React framework |
| `vendor-lodash-11dceb72.min.js` | `sha384-/jCcn7...` | Lodash utilities |
| `webapi-d3ad37f2.min.js` | `sha384-0oSoS6...` | Web API client |
| `vendor-moment-a350876a.min.js` | `sha384-bgHnUo...` | Date/time library |
| `app-4b7678e0.min.js` | `sha384-PdqkKN...` | Main application |
| `sk-2c17b526.min.js` | `sha384-9UxhaJ...` | Secret Key retrieval (fallback) |

All scripts use `crossorigin="anonymous"` and SRI hashes — tampering with the
CDN content would be detected by the browser.

### WebAssembly Security

The client ships WASM modules (likely the crypto core) with a **hash whitelist**:

```
trustedWasmHashes = [
    'k6RLu5bHUSGOTADUeeTBQ1gSKjiazKFiBbHk0NxflHY=',
    'L7kNpxXKV0P6GuAmJUXBXt6yaNJLdHqWzXzGFEjIYXQ=',
    'GVnMETAEUL/cu/uTpjD6w6kwDLUYqiEQ7fBsUcd+QJw=',
    '+yHBrSgjtws1YuUDyoaT3KkY0eOi0gVCBOZsGNPJcOs=',
    'I+k/SNmZg4ElHUSaENw7grySgWIki/yjg62WZcsxXy8=',
    'WwqUPAGJ2F3JdfFPHqHJpPrmVI5xmLlfIJadWXKRQR8='
]
```

Every WASM module is SHA-256 hashed before loading and compared against this
list. `WebAssembly.compile`, `instantiate`, `validate`, and
`compileStreaming` are all monkey-patched to enforce this check. The non-async
`Module` constructor is blocked entirely.

This is a defense against WASM substitution attacks — even with a MITM, an
attacker cannot inject a modified crypto module without matching one of these
hashes. **This significantly raises the bar for client-side attacks.**

WASM base URL: `https://app.1password.com/wasm/`

### Security Headers (Application Pages)

All security headers are present and well-configured on the application pages:

| Header | Value |
|--------|-------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` |
| `Content-Security-Policy` | Strict — see below |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `Cross-Origin-Opener-Policy` | `restrict-properties` |
| `Permissions-Policy` | `interest-cohort=()` |
| `Cache-Control` | `max-age=60, no-cache, no-store` |
| CSP Reporting | `report-to csp-endpoint` -> `https://csp.1passwordservices.com/report` |

### Content Security Policy (Parsed)

```
default-src:       'none'
script-src:        https://app.1password.com 'wasm-unsafe-eval' + 2 inline hashes
style-src:         https://app.1password.com + 1 inline hash
connect-src:       'self' blob: https://app.1password.com wss://b5n.1password.com
                   https://*.1password.com https://*.1password.ca https://*.1password.eu
                   https://*.ent.1password.com https://f.1passwordusercontent.com
                   https://a.1passwordusercontent.com https://watchtower.1password.com
                   https://api.pwnedpasswords.com + Firebase, Sentry, telemetry
font-src:          https://app.1password.com
img-src:           data: blob: https://app.1password.com + avatar/cache CDNs
child-src/frame-src: 'self' + Duo Security, billing, survey, email providers
worker-src:        'self'
form-action:       https://app.kolide.com/ https://app.trelica.com/
frame-ancestors:   https://*.1password.com
upgrade-insecure-requests
```

**CSP Analysis:**
- `default-src 'none'` — strict baseline, everything must be explicitly allowed
- `script-src` — **no `unsafe-inline` or `unsafe-eval`** — only hashed inlines
  and `https://app.1password.com`. `wasm-unsafe-eval` is required for WASM
  execution but is mitigated by the WASM hash whitelist
- `connect-src` — allows WebSocket to `wss://b5n.1password.com` (push notifications?)
  and HTTPS to various 1Password service domains
- `frame-ancestors: https://*.1password.com` — prevents clickjacking from
  non-1password origins
- CSP violation reporting is active — any injection attempt would be reported

**XSS attack surface is very limited.** No `unsafe-inline`, no `unsafe-eval`,
SRI on all scripts, WASM hash whitelist, strict frame-ancestors.

### Exposed Configuration Data

The HTML `<head>` tag contains `data-*` attributes with configuration:

**Potentially interesting for the engagement:**
- `data-brex-client-id`: `bri_b2df18d65bc82a948573537157eceb07`
- `data-brex-auth`: `CLIENT_SECRET` (literal string, not an actual secret)
- `data-fcm-api-key`: `AIzaSyCs8WNa10YE5AVyfL33RBHBKQdYZMw7OB0` (Firebase Cloud Messaging)
- `data-fcm-project-id`: `b5-notification-prd`
- `data-sentry-dsn`: `https://6342e577bc314e54ab2c5650a4c5be8f:f7b7d11056d84dd0b09e9a9ca31a72e8@web-ui-sentry.1passwordservices.com/...`
- `data-slack-client-id`: `36986904051.273534103040`
- `data-stripe-key`: `pk_live_F59R8NjiAi5Eu7MJcnHmdNjj`
- `data-fastmail-client-id`: `35c941ae`
- `data-snowplow-url`: `https://telemetry.1passwordservices.com` (analytics)
- `data-webpack-public-path`: `https://app.1password.com/` (CDN origin)

The page includes `data-bug-researcher-notes` that explicitly states: "All keys
below are intended to be exposed publicly, and are therefore not vulnerable."

### Assessment

The web client is well-hardened:
- SRI on all scripts prevents CDN tampering
- WASM hash whitelist prevents crypto module substitution
- Strict CSP blocks most XSS vectors
- HSTS with preload prevents SSL stripping
- `X-Frame-Options: DENY` prevents clickjacking
- CSP violation reporting is active

The main avenue for client-side attacks would be:
1. Finding an XSS that works within the CSP constraints (very difficult)
2. Compromising `app.1password.com` CDN itself (the only allowed script source)
3. Exploiting `wasm-unsafe-eval` if a WASM module can be substituted (blocked by
   hash whitelist, but worth investigating the validation code path)

The `vendor-1password` and `webapi` bundles are the highest-value targets for
reverse engineering — they contain the SRP client, key derivation, and vault
encryption logic.


## Step 1.4 — API Enumeration

**Date:** 2026-04-23

### CORS Configuration

`OPTIONS /api/v1/auth` returns:
- `access-control-allow-origin: https://bugbounty-ctf.1password.com` (strict, not `*`)
- `access-control-allow-credentials: true`
- `access-control-allow-headers: X-AgileBits-Client, X-AgileBits-MAC, Cache-Control, X-AgileBits-Session-ID, Content-Type, OP-User-Agent, ChannelJoinAuth`
- `access-control-allow-methods: GET, POST, PUT, PATCH, DELETE`

Notable custom headers: `X-AgileBits-Client`, `X-AgileBits-MAC`,
`X-AgileBits-Session-ID` — likely required for authenticated requests.
The MAC header suggests request signing.

### Auth Endpoints

| Endpoint | Method | Status | Response |
|----------|--------|--------|----------|
| `/api/v1/auth` | POST | 401 | `{}` (empty, no differentiation by email) |
| `/api/v2/auth` | POST | 401 | `{}` |
| `/api/v2/auth/complete` | POST | 401 | `{}` |
| `/api/v2/auth/confirm-key` | POST | 401 | `{}` |
| `/api/v2/auth/methods` | POST | **200** | `{"authMethods":[{"type":"PASSWORD+SK"}],...}` |
| `/api/v1/auth/verify` | POST | 401 | `{}` |
| `/api/v1/auth/mfa` | POST | 401 | `{}` |
| `/api/v3/auth` | POST | 404 | No v3 API |

The auth init endpoint returns identical `401 {}` for all email addresses
including empty string — **no username enumeration** via this path.

### Key Finding: `/api/v2/auth/methods`

This endpoint returns 200 for any request and confirms:
```json
{"authMethods":[{"type":"PASSWORD+SK"}],"signInAddress":"https://bugbounty-ctf.1password.com"}
```

- Auth method is `PASSWORD+SK` (password + Secret Key, i.e., 2SKD)
- Returns the same response for all emails including empty/nonexistent
- Returns 400 only for malformed email strings (e.g., `"not-an-email"`)
- **No SSO** — pure password + Secret Key auth only
- **No email enumeration** possible through this endpoint

### Endpoint Map (from JS Bundle)

The `webapi` bundle (934 KB) contains ~200 API endpoint paths. Key categories:

**Auth flow (v2):**
- `/api/v2/auth` — SRP init
- `/api/v2/auth/complete` — SRP verify / session creation
- `/api/v2/auth/confirm-key` — Secret Key confirmation
- `/api/v2/auth/methods` — query auth methods (public)
- `/api/v2/auth/webauthn/register` — WebAuthn registration
- `/api/v2/auth/webauthn/register/challenge` — WebAuthn challenge
- `/api/v2/auth/sso/reconnect` — SSO reconnection

**Recovery (v2) — high-value attack surface:**
- `/api/v2/recovery-keys/session/new` — start recovery session
- `/api/v2/recovery-keys/session/auth/cv1/start` — recovery auth start
- `/api/v2/recovery-keys/session/auth/cv1/confirm` — recovery auth confirm
- `/api/v2/recovery-keys/session/complete` — complete recovery
- `/api/v2/recovery-keys/session/identity-verification/email/start` — email verification
- `/api/v2/recovery-keys/session/identity-verification/email/submit` — submit verification
- `/api/v2/recovery-keys/session/material` — recovery key material
- `/api/v2/recovery-keys/session/status` — session status
- `/api/v2/recovery-keys/policies` — recovery policies (returns 401)
- `/api/v2/recovery-keys/keys` — recovery keys (returns 401)
- `/api/v2/recovery-keys/attempts` — recovery attempts (returns 401)

**Account/keyset management:**
- `/api/v2/account/keysets` — account keysets (returns 401)
- `/api/v1/account` — account info (returns 401)
- `/api/v1/device` — device registration (returns 401)
- `/api/v1/session/signout` — session termination
- `/api/v1/session/touch` — session keepalive
- `/api/v2/session-restore/*` — session restore flow (save-key, restore-key, destroy-key)

**Vault operations:**
- `/api/v2/vault` — vault access
- `/api/v2/mycelium/u` / `/api/v2/mycelium/v` — unknown (Mycelium?)
- `/api/v1/vault/personal` — personal vault
- `/api/v1/vault/everyone` — shared vault
- `/api/v1/vault/managed` — managed vault
- `/api/v1/vault/account-transfer` — vault transfer

**Other interesting:**
- `/api/v1/confidential-computing/session` — confidential computing
- `/api/v1/signinattempts` / `/api/v2/signinattempts` — sign-in attempt logs
- `/api/v1/monitoring/status` — monitoring
- `/api/v2/perftrace` / `/api/v2/preauth-perftrace` — performance tracing
- `/api/v1/oidc/token` — OIDC token endpoint

### Error Behavior

All authenticated endpoints return `401 {}` (empty JSON body) — the server
leaks no information about why the request failed. No differentiated error
messages, no descriptive error codes.

Signup endpoints (`/api/v1/signup`, `/api/v2/signup`) return `400 {}` for all
payloads — signup may be disabled on the CTF instance.

### Rate Limiting

5 rapid sequential requests to `/api/v1/auth` all returned `401` with no
throttling or blocking. No `Retry-After` header. No CAPTCHA challenge.
**Rate limiting may be absent or has a high threshold.**

### Assessment

The API surface is large (~200 endpoints) but consistently requires
authentication. Key observations:

1. **No username/email enumeration** — all auth endpoints return identical
   responses regardless of email
2. **Recovery key flow is extensive** — 10+ endpoints for account recovery.
   This is the white paper's Appendix A.4 weakness. Worth deep investigation
   in Phase 3.
3. **Custom request signing** — `X-AgileBits-MAC` header suggests HMAC-based
   request authentication. Need to understand this from the JS bundle.
4. **Session restore flow** — save/restore/destroy key endpoints could be
   a secondary attack surface for session hijacking.
5. **No rate limiting observed** — brute force may be feasible if the auth
   protocol allows it (2SKD makes this moot for password attacks, but
   session/token brute force could be viable).
6. **v2 auth flow** — the client uses v2 (`/api/v2/auth` -> `/api/v2/auth/complete`)
   rather than v1. Both respond similarly.


## Step 1.5 — Public Source Analysis

**Date:** 2026-04-23

### 1Password Public Repositories

93 public repos on GitHub under `github.com/1Password`. Relevant repos:

**Highest value:**

| Repo | Language | Description |
|------|----------|-------------|
| `1Password/srp` | Go | **SRP-6a implementation used by 1Password Teams** (389 stars) |
| `burp-1password-session-analyzer` | Java | **Burp plugin for analyzing encrypted 1Password sessions** (79 stars) |
| `passkey-rs` | Rust | WebAuthn authenticator framework |
| `curve25519-dalek` | Rust | Fork with specific bug fix |

### SRP Library Analysis (`1Password/srp`)

**Files:** 13 Go source files, ~70KB total. Full SRP-6a implementation with both
standard (RFC 5054) and non-standard (1Password legacy) modes.

**Key classes:**
- `SRP` struct — main client/server object
- `Group` — Diffie-Hellman group parameters
- `Hash` — configurable hash (SHA-256 default)

#### Critical Validation: `IsPublicValid()` (srp.go:208)

```go
func (s *SRP) IsPublicValid(AorB *big.Int) bool {
    if s.group.Reduce(AorB).Cmp(bigOne) == 0 {
        return false  // Rejects A % N == 1
    }
    if s.group.IsZero(AorB) {
        return false  // Rejects A == 0
    }
    return true
}
```

**Assessment:** This validates A != 0 and A % N != 1, but **does NOT check
A % N != 0** directly. The `Reduce` call computes `A mod N`. If `A = N`, then
`Reduce(A) = 0`, which is caught by `IsZero`. If `A = 2N`, then `Reduce(A) = 0`,
also caught. But the check for `Cmp(bigOne)` only catches `A % N == 1`, not
`A % N == 0` when A > 0.

Wait — re-reading: `IsZero` checks if the value is zero. `Reduce(A)` gives
`A mod N`. So:
- A=0: `IsZero(0)` = true -> rejected
- A=N: `Reduce(N) = 0`, `IsZero(0)` = true -> rejected
- A=2N: `Reduce(2N) = 0`, `IsZero(0)` = true -> rejected
- A=kN: same, all rejected

**The zero-key attack is properly mitigated in this library.** The library also
rejects A=1 (which would make the session key deterministic but not trivially
zero). Additional safety: `SetOthersPublic()` calls `IsPublicValid()` and sets
`badState=true` on failure, preventing any further key computation.

#### Non-Standard u Calculation

The library has a documented bug:
```go
// BUG(jpg): Calculation of u does not use RFC 5054 compatible padding/hashing
```

The non-standard mode (`calculateUNonStd`) concatenates hex strings of A and B
with leading zeros stripped, then hashes. This differs from RFC 5054 which
requires fixed-width padding. The standard mode (`calculateUStd`) uses proper
padding. **The web client likely uses the standard mode** (`NewClientStd`), but
this should be verified.

#### Other Observations

- SHA-256 is hardcoded as the default hash
- Ephemeral secret minimum size: 32 bytes (per RFC 5054)
- `u == 0` is explicitly rejected (would make session key independent of password)
- Server-side key computation: `S = (A * v^u) ^ b mod N`
- Client-side key computation: `S = (B - k*g^x) ^ (a + u*x) mod N`

### Burp Plugin Insight

The `burp-1password-session-analyzer` README reveals critical architecture:

> "We require every request and response that are specific to a 1Password account
> to be protected by the account's master password and secret key, which means
> every bit of data that gets sent is encrypted, and every request is authenticated."

This confirms:
1. **All API payloads are encrypted** — not just auth, ALL requests/responses
2. **Every request is MAC'd** — explains the `X-AgileBits-MAC` header from Step 1.4
3. **Standard web fuzzing tools don't work** — you can't tamper with requests
   without the session key
4. The Burp plugin requires a valid session key to decrypt/re-encrypt payloads

This means:
- IDOR/parameter tampering is not possible without first obtaining a valid session
- API fuzzing requires understanding the encryption layer
- The `X-AgileBits-Session-ID` + `X-AgileBits-MAC` headers are integral to the
  protocol, not optional

### Assessment

The SRP library is well-implemented:
- Zero-key attacks (A=0, A=N, A=kN) are properly rejected
- The library is well-tested (20KB of tests)
- SHA-256 is used throughout
- Session key derivation follows standard SRP-6a

The main attack surface from source analysis:
1. **Non-standard u calculation** — if the server uses the legacy mode, the
   different padding could theoretically be exploitable, though this is unlikely
2. **All-encrypted API protocol** — makes server-side testing much harder than
   anticipated. We need the session key to even send valid requests
3. **Burp plugin exists** — we should use this for any authenticated testing
