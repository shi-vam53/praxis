# Security Policy & Hardening

Praxis enforces platform security, candidate data integrity, and API protection through defense-in-depth engineering.

---

## 🛡️ Security Architecture Highlights

1. **Server-Side Authentication & Session Life Cycle**:
   - Access to administrative routes (`/api/admin/*`), user exports, and submission reviews is strictly gated by server-side bearer token authentication (`_require_user` and `is_admin == True`).
   - Admin access is determined exclusively by the database record, not client-side username checks.
   - Session tokens are generated using `secrets.token_hex(24)` and have explicit expiration dates (`expires_at`).
2. **Credential & Secret Protection**:
   - Passwords are encrypted using PBKDF2-HMAC-SHA256 (100,000 iterations) with unique per-user 16-byte random salts.
   - Password hashes are stored solely in the private backend database and are strictly excluded from any external database synchronizations.
   - Environment variables decouple all runtime secrets (`GITHUB_TOKEN`, `GROQ_API_KEY`, `ADMIN_INITIAL_PASSWORD`).
3. **Assessment & Credential Integrity**:
   - Readiness assessments require exact submission validation against server-side question pools.
   - Completion certificates are gated behind verified quiz pass status and generated ephemerally, ignoring client-tampered query parameters.
4. **Brute-Force & Abuse Mitigation**:
   - Rate limiting and automated account lockout enforce protection against credential stuffing on authentication endpoints.
   - Submission inputs enforce bounded recursion depths to prevent Denial of Service (`RecursionError`).
5. **HTTP & Transport Hardening**:
   Every response includes modern security headers:
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: SAMEORIGIN`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Permissions-Policy: geolocation=(), microphone=(), camera=()`
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
   - `Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';`
   - Scoped CORS origins limiting API access to authorized deployment domains.
6. **Injection Protection**:
   - All database queries use SQLite parameterized query bindings (`?`), eliminating SQL injection.
   - User inputs and submission texts are strictly sanitized before rendering in the DOM.

---

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability or credential leak within this repository:
1. Please do **NOT** open a public GitHub issue.
2. Contact the maintainer directly or report privately via GitHub Security Advisories.
3. Include detailed steps to reproduce the issue. We aim to acknowledge reports within 24 hours.
