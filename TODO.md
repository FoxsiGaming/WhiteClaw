## WhiteClaw — Active Web Security Tests

Run active tests: `pytest tests/active/ -v`
Run destructive tests (set ENABLE_DESTRUCTIVE_TESTS=True first): `pytest tests/destructive/ -v`
Run only unit tests: `pytest` (active/destructive excluded from default run)

---

### 1. Reconnaissance
- [x] Fingerprint web server via Server header
- [x] Fingerprint via X-Powered-By header
- [x] Enumerate robots.txt sensitive paths
- [x] Enumerate sitemap.xml
- [x] Identify supported HTTP methods (OPTIONS)
- [x] Check for .DS_Store exposure
- [x] Check for .git directory exposure
- [x] Check for .env file exposure
- [x] Check for exposed admin panels
- [x] Detect debug/test endpoints
- [x] Version disclosure in response headers
- [x] Framework/technology detection from headers
- [x] Hidden directory scan (common wordlist)
- [x] Cloud storage bucket URLs in HTML

### 2. Access Control
- [x] Directory listing enabled check
- [x] Path traversal basic (../../../etc/passwd)
- [x] Path traversal URL-encoded (%2e%2e%2f)
- [x] Path traversal double-encoded
- [x] Forced browsing without auth (skip: needs auth context)
- [x] Vertical privilege escalation (skip: needs auth)
- [x] Horizontal privilege escalation (skip: needs auth)
- [x] IDOR numeric object reference (skip: needs auth)
- [x] Authorization on API endpoints (skip: needs auth)
- [x] JWT scope enforcement (skip: needs JWT)
- [x] Mass assignment via API (skip: needs auth)
- [x] Parameter pollution to bypass ACL
- [x] Missing function-level access control
- [x] Client-side access control check (skip: browser-based)
- [x] RBAC boundary validation (skip: needs auth)

### 3. Injection
- [x] SQL injection error-based
- [x] SQL injection boolean blind
- [x] SQL injection time-based (skip: side-effects)
- [x] NoSQL injection (MongoDB operators)
- [x] HTML injection
- [x] OS command injection detection
- [x] SSTI detection
- [x] Header injection via Host
- [x] Header injection via X-Forwarded-For
- [x] CRLF injection
- [x] GraphQL injection
- [x] LDAP injection (skip: no generic probe)
- [x] XPath injection
- [x] Log injection via User-Agent
- [x] Email header injection (skip: needs email flow)
- [x] CSV injection (skip: needs auth to see saved data)
- [x] Second-order SQL injection (skip: needs stored context)
- [x] ORM injection detection

### 4. Cross-Site Scripting (XSS)
- [x] Reflected XSS basic probe
- [x] Reflected XSS in error messages
- [x] Stored XSS (skip: needs write + read auth)
- [x] DOM-based XSS via URL fragment
- [x] XSS via User-Agent header
- [x] XSS via Referer header
- [x] XSS through JSON response reflection
- [x] XSS WAF evasion basic probe
- [x] Mutation XSS probe
- [x] XSS via file upload SVG (skip: needs upload)
- [x] XSS via PostMessage (skip: browser-based)
- [x] XSS in WebSockets (skip: browser-based)
- [x] XSS in PDF rendering (skip: needs PDF endpoint)
- [x] CSP header presence and strength

### 5. Authentication & Session Management
- [x] Username enumeration via login response
- [x] Username enumeration via forgot-password
- [x] Account lockout passive check
- [x] Default credentials passive check
- [x] httpOnly flag on session cookies
- [x] Secure flag on session cookies
- [x] SameSite attribute on cookies
- [x] Cookie expiry check
- [x] HTTPS-only login enforcement
- [x] Password reset token in URL
- [x] OAuth open redirect
- [x] MFA enabled check (skip: needs auth)
- [x] Session token entropy (skip: needs auth)
- [x] Session invalidation on logout (skip: needs auth)
- [x] JWT algorithm confusion (skip: needs JWT)
- [x] JWT expiration (skip: needs JWT)
- [x] Weak password policy (skip: needs create-account endpoint)
- [x] SSO/SAML assertion (skip: SAML-specific)

### 6. Input Validation
- [x] Max length enforcement probe
- [x] Integer overflow in query params
- [x] Negative numbers in quantity params
- [x] Special characters in params
- [x] Null bytes in params
- [x] Double encoding bypass
- [x] HTTP parameter pollution
- [x] Unicode normalization attack
- [x] XXE injection probe
- [x] Regex ReDoS detection in source
- [x] File upload unrestricted type (skip: needs upload endpoint)
- [x] File upload path traversal (skip: needs upload)
- [x] Insecure deserialization (skip: hard to test generically)
- [x] Type juggling (skip: PHP-specific)

### 7. HTTP Headers & Transport Security
- [x] HSTS header present
- [x] HSTS max-age sufficient (>= 31536000)
- [x] X-Frame-Options clickjacking protection
- [x] X-Content-Type-Options nosniff
- [x] Content-Security-Policy present
- [x] Referrer-Policy present
- [x] Permissions-Policy present
- [x] HTTP to HTTPS redirect
- [x] Mixed content (HTTP assets on HTTPS page)
- [x] TLS version (reject TLS 1.0/1.1)
- [x] Weak cipher suites
- [x] Certificate validity (not expired, not self-signed)
- [x] CORS wildcard Access-Control-Allow-Origin
- [x] CORS preflight handling
- [x] HTTP TRACE method disabled
- [x] Dangerous HTTP methods (PUT, DELETE)
- [x] Cache-Control on sensitive responses
- [x] Sensitive data in response headers

### 8. Cryptography
- [x] Hardcoded secrets/API keys in JS files
- [x] Sensitive data in URLs (tokens in query string)
- [x] Cleartext sensitive data in response
- [x] TLS for all data in transit
- [x] Sensitive data in browser cache (Cache-Control)
- [x] API keys in JavaScript source
- [x] Secrets in HTML source comments

### 9. Security Misconfiguration
- [x] Exposed admin interfaces (recheck with misconfiguration angle)
- [x] Verbose error messages leaking stack traces
- [x] Dev/debug mode in production
- [x] Exposed .git directory
- [x] Exposed .env file
- [x] Exposed /actuator endpoints (Spring Boot)
- [x] Exposed /swagger or /api-docs
- [x] Directory listing on web server
- [x] Error pages revealing server/framework info
- [x] Internal IPs in responses
- [x] Open cloud storage buckets
- [x] Default credentials (skip: active brute-force → destructive)

### 10. Vulnerable & Outdated Components
- [x] Frontend library versions in HTML/JS
- [x] Vulnerable jQuery version detection
- [x] CMS version detection (WordPress, Drupal)
- [x] Server-side framework version detection
- [x] Apache/Nginx version in headers
- [x] Outdated Bootstrap version
- [x] Prototype pollution library indicators
- [x] Known vulnerable CDN library patterns

### 11. CSRF & Business Logic
- [x] Missing CSRF token on state-changing requests
- [x] Weak/predictable CSRF token
- [x] CSRF via JSON (Content-Type bypass)
- [x] CSRF via GET requests
- [x] Negative price in params
- [x] Workflow step bypass
- [x] Discount/coupon logic (skip: e-commerce specific)
- [x] Race conditions (skip → destructive)

### 12. SSRF
- [x] SSRF URL parameter detection
- [x] SSRF cloud metadata endpoint (169.254.169.254)
- [x] SSRF via Host header injection
- [x] SSRF partial URL parsers
- [x] SSRF via redirect
- [x] Blind SSRF via DNS (skip: needs OOB infra)
- [x] SSRF via SVG upload (skip: needs upload)
- [x] SSRF in PDF generation (skip: needs PDF endpoint)

### 13. API Security
- [x] Unauthenticated API endpoints scan
- [x] API key in URL vs headers
- [x] Excessive data exposure in responses
- [x] Rate limiting on API endpoints
- [x] Old API versions still live
- [x] GraphQL introspection enabled
- [x] API error verbosity
- [x] API input validation probe
- [x] BOLA/IDOR (skip: needs auth)
- [x] Broken function-level auth (skip: needs auth)
- [x] WebSocket auth (skip: needs WS endpoint)

### 14. Security Logging & Monitoring
- [x] Failed login events detectable (passive)
- [x] Log injection via User-Agent
- [x] Sensitive data in error responses
- [x] Audit trail check (skip: needs auth context)

### 15. Client-Side
- [x] Clickjacking (X-Frame-Options)
- [x] Open redirects
- [x] PostMessage origin validation in source
- [x] eval() with user-controlled data in source
- [x] innerHTML with user-controlled data in source
- [x] Sensitive comments in HTML source
- [x] API keys in JavaScript source
- [x] Autocomplete on sensitive form fields
- [x] Reverse tabnapping (target=_blank without rel=noopener)
- [x] JSONP callback injection
- [x] Client-side authorization checks (bypassable)
- [x] Prototype pollution in JS source
- [x] Sensitive data in localStorage (skip: browser-based)
- [x] Sensitive data in cookies (unencrypted)

### 16. File & Resource Handling
- [x] LFI via include/page parameter
- [x] RFI remote file inclusion
- [x] Path traversal in file download
- [x] SVG-based XSS/SSRF probe
- [x] SSRF via file fetch features
- [x] XXE in XML input probe
- [x] Zip slip (skip: needs upload)

### 17. Infrastructure & Deployment
- [x] Staging/dev environment exposure
- [x] Internal IP address disclosure
- [x] Exposed Redis port
- [x] Exposed Elasticsearch without auth
- [x] Docker/Kubernetes dashboard exposure
- [x] Exposed CI/CD pipelines
- [x] Exposed database admin panels
- [x] Open ports beyond 80/443

### 18. DoS & Rate Limiting (passive)
- [x] Rate limiting on login endpoint
- [x] Rate limiting on password reset
- [x] Rate limiting on OTP/2FA
- [x] Regex ReDoS patterns in JavaScript
- [x] XML bomb (skip → destructive)
- [x] GraphQL complexity DoS (skip → destructive)
- [x] Slowloris (skip → destructive)

### 19. Supply Chain & Third-Party
- [x] CDN scripts have SRI (integrity attribute)
- [x] All external scripts have integrity checks
- [x] Third-party script origins are recognized
- [x] Dependency version disclosure

### 20. Modern Attack Surfaces
- [x] HTTP Request Smuggling detection probe
- [x] Cache poisoning via Host header
- [x] Web cache deception
- [x] SSI injection
- [x] HTTP Host header attacks
- [x] Referer-based access control
- [x] Reverse tabnapping
- [x] PII leakage in error messages
- [x] OAuth state parameter CSRF
- [x] User-controlled redirect destination
- [x] 304 Not Modified cache data leakage
- [x] Insecure deserialization markers in responses
- [x] Subdomain takeover passive check
- [x] Account takeover via password reset poisoning
- [x] CORS on credentialed requests
- [x] JWT kid header injection (skip: needs JWT)
- [x] SAML signature wrapping (skip: SAML-specific)
- [x] DNS rebinding (skip: requires browser)
- [x] Timing attacks on auth (skip: requires precision measurement)

### Destructive Tests (ENABLE_DESTRUCTIVE_TESTS=True required)
- [x] Brute-force on login endpoint
- [x] Brute-force on OTP/2FA codes
- [x] Credential stuffing simulation
- [x] Account lockout DoS
- [x] Large payload DoS via oversized input
- [x] XML bomb (billion laughs)
- [x] GraphQL complexity-based DoS
- [x] Slowloris / slow HTTP attack
- [x] File upload: webshell
- [x] File upload: zip bomb
- [x] Active SSRF to internal services
- [x] SSRF via DNS rebinding
- [x] Race condition double-spend
- [x] Actual SQL injection exploitation
- [x] Actual command injection exploitation
