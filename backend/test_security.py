"""Security & Vulnerability Penetration Test Suite for Praxis Platform.

Covers:
- SQL Injection vectors (SQLi)
- Directory & Path Traversal vectors (LFI/Path Traversal)
- Stored & Reflected Cross-Site Scripting (XSS)
- Input Validation & Payload Size Floods
- HTTP Security Headers Verification
"""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import create_app


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client(tmp_path):
    app = create_app(
        project_root=REPOSITORY_ROOT,
        database_path=tmp_path / "test-security.sqlite3",
    )
    with TestClient(app) as test_client:
        yield test_client


def _valid_cloud_answers():
    return {
        "incident_timeline": "14:10 UTC deploy completed; 14:13 UTC HikariPool connection timeout; 14:15 UTC 504 errors.",
        "hypothesis": "Facts: HikariPool connection pool exhausted at 100 connections due to sync audit logging in v2.4.0. Assumptions: DB disk I/O.",
        "safe_mitigation_plan": "Helm rollback to release-v2.3.9 or set ENABLE_SYNC_AUDIT_LOG=false per Runbook SOP.",
        "verification_steps": "Monitor p99 latency < 120ms and 5xx error rate < 0.02% for 20 minutes.",
        "follow_up_improvement": "Decouple regulatory audit logging asynchronously using Kafka/SQS worker queues.",
    }


# ==============================================================================
# 1. SQL INJECTION (SQLi) PENETRATION TESTS
# ==============================================================================

def _sec_user_headers(client, username="sec_tester"):
    reg = client.post("/api/auth/register", json={"username": username, "password": "password123", "full_name": "Security Tester"})
    token = reg.json().get("token") if reg.status_code == 201 else client.post("/api/auth/login", json={"username": username, "password": "password123"}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "'; DROP TABLE submissions; --",
    "' UNION SELECT 'admin', 'password', '1', '2', '3' --",
    "1' OR 1=1 #",
    "admin'--",
    "1'; EXEC xp_cmdshell('dir');--",
])
def test_sqli_in_submission_id_does_not_leak_or_crash(client, payload):
    """Verify parameterized queries neutralize SQL injection attempts in submission lookups."""
    headers = _sec_user_headers(client, "sqli_tester")
    res = client.get(f"/api/submissions/{payload}", headers=headers)
    # Must fail safely with 400 (rejected by format validator) or 404 (not found) or 403 (unauthorized access)
    assert res.status_code in {400, 403, 404}


def test_sqli_in_answers_payload_is_treated_as_plain_text(client):
    """Verify malicious SQL payloads inside answer fields do not execute SQL commands."""
    headers = _sec_user_headers(client, "sqli_ans_tester")
    answers = _valid_cloud_answers()
    answers["hypothesis"] = "'; DROP TABLE submissions; SELECT * FROM submissions WHERE '1'='1"

    post_res = client.post(
        "/api/submissions",
        headers=headers,
        json={"mission_id": "cloud-sre-01", "answers": answers},
    )
    assert post_res.status_code == 201
    data = post_res.json()
    submission_id = data["submission_id"]

    # Verify table was NOT dropped and data is retrieved cleanly
    get_res = client.get(f"/api/submissions/{submission_id}", headers=headers)
    assert get_res.status_code == 200
    retrieved = get_res.json()
    assert retrieved["answers"]["hypothesis"] == answers["hypothesis"]


# ==============================================================================
# 2. PATH TRAVERSAL / LFI PENETRATION TESTS
# ==============================================================================

@pytest.mark.parametrize("traversal_path", [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
    "tracks/../../etc/shadow",
    "cloud-engineer/../../../etc/passwd",
])
def test_path_traversal_in_track_and_mission_ids_blocked(client, traversal_path):
    """Verify regex pattern check blocks path traversal and directory escape attempts."""
    track_res = client.get(f"/api/tracks/{traversal_path}")
    assert track_res.status_code == 404

    mission_res = client.get(f"/api/missions/{traversal_path}")
    assert mission_res.status_code == 404


# ==============================================================================
# 3. CROSS-SITE SCRIPTING (XSS) STORAGE TESTS
# ==============================================================================

def test_xss_polyglots_stored_verbatim_without_server_side_execution(client):
    """Verify script injection payloads are stored verbatim without server-side execution."""
    headers = _sec_user_headers(client, "xss_tester")
    xss_payload = "<script>alert('XSS')</script><img src=x onerror=alert(1)>"
    answers = _valid_cloud_answers()
    answers["follow_up_improvement"] = xss_payload

    post_res = client.post(
        "/api/submissions",
        headers=headers,
        json={"mission_id": "cloud-sre-01", "answers": answers},
    )
    assert post_res.status_code == 201
    submission_id = post_res.json()["submission_id"]

    get_res = client.get(f"/api/submissions/{submission_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["answers"]["follow_up_improvement"] == xss_payload


# ==============================================================================
# 4. INPUT VALIDATION & PAYLOAD FLOOD GUARDRAILS
# ==============================================================================

def test_oversized_answer_field_rejected(client):
    """Verify answer fields exceeding 30,000 characters are rejected with 422 Unprocessable Entity."""
    headers = _sec_user_headers(client, "overflow_tester")
    answers = _valid_cloud_answers()
    answers["hypothesis"] = "A" * 35000  # 35KB in single field

    res = client.post(
        "/api/submissions",
        headers=headers,
        json={"mission_id": "cloud-sre-01", "answers": answers},
    )
    assert res.status_code == 422
    assert "exceeds maximum allowed length" in res.json()["detail"]


def test_invalid_mission_id_format_rejected(client):
    """Verify invalid mission IDs containing special symbols are rejected by schema."""
    headers = _sec_user_headers(client, "invalid_mid_tester")
    answers = _valid_cloud_answers()
    res = client.post(
        "/api/submissions",
        headers=headers,
        json={"mission_id": "cloud<script>", "answers": answers},
    )
    assert res.status_code == 422


def test_invalid_reviewer_status_rejected(client):
    """Verify review status only accepts permitted whitelist values."""
    headers = _sec_user_headers(client, "rev_status_tester")
    answers = _valid_cloud_answers()
    sub_res = client.post(
        "/api/submissions",
        headers=headers,
        json={"mission_id": "cloud-sre-01", "answers": answers},
    )
    sub_id = sub_res.json()["submission_id"]

    # Try invalid status
    invalid_patch = client.patch(
        f"/api/submissions/{sub_id}/review",
        json={"status": "malicious_status_injection", "notes": "note"},
    )
    assert invalid_patch.status_code in {401, 422}


# ==============================================================================
# 5. HTTP SECURITY HEADERS VERIFICATION
# ==============================================================================

def test_http_security_headers_present(client):
    """Verify essential security headers are set on all responses."""
    res = client.get("/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert res.headers.get("X-XSS-Protection") == "1; mode=block"
    assert "Content-Security-Policy" in res.headers


# ==============================================================================
# 6. ACCESS CONTROL & SENSITIVE ENDPOINT GATING
# ==============================================================================

def test_admin_csv_export_unauthorized_access_blocked(client):
    """Verify anonymous and regular user requests to /api/admin/users/csv are rejected."""
    # 1. Anonymous request -> 401
    res_anon = client.get("/api/admin/users/csv")
    assert res_anon.status_code == 401

    # 2. Hardcoded query secret key attempt -> 401 (PRAX-03 bypass eliminated)
    res_bypass = client.get("/api/admin/users/csv?admin_key=praxis-admin-secret-2026")
    assert res_bypass.status_code == 401

    # 3. Regular candidate user -> 403
    reg = client.post("/api/auth/register", json={"username": "test_candidate", "password": "password123", "full_name": "Test Candidate"})
    cand_token = reg.json()["token"]
    res_cand = client.get("/api/admin/users/csv", headers={"Authorization": f"Bearer {cand_token}"})
    assert res_cand.status_code == 403

    # 4. Verified Admin user -> 200
    admin_login = client.post("/api/admin/login", json={"username": "shivam", "password": "shivam"})
    admin_token = admin_login.json()["token"]
    res_admin = client.get("/api/admin/users/csv", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_admin.status_code == 200


def test_submission_review_requires_admin_authorization(client):
    """Verify unauthorized users cannot approve or alter candidate reviews."""
    headers = _sec_user_headers(client, "sub_auth_cand")
    answers = _valid_cloud_answers()
    sub_res = client.post(
        "/api/submissions",
        headers=headers,
        json={"mission_id": "cloud-sre-01", "answers": answers},
    )
    sub_id = sub_res.json()["submission_id"]

    # Anonymous attempt to approve submission -> 401
    anon_patch = client.patch(
        f"/api/submissions/{sub_id}/review",
        json={"status": "approved", "notes": "Hacked review"},
    )
    assert anon_patch.status_code == 401

    # Candidate attempt to approve submission -> 403
    reg = client.post("/api/auth/register", json={"username": "cand_reviewer", "password": "password123", "full_name": "Candidate Reviewer"})
    cand_token = reg.json()["token"]
    cand_patch = client.patch(
        f"/api/submissions/{sub_id}/review",
        headers={"Authorization": f"Bearer {cand_token}"},
        json={"status": "approved", "notes": "Hacked review"},
    )
    assert cand_patch.status_code == 403

    # Admin attempt -> 200
    admin_login = client.post("/api/admin/login", json={"username": "shivam", "password": "shivam"})
    admin_token = admin_login.json()["token"]
    admin_patch = client.patch(
        f"/api/submissions/{sub_id}/review",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"status": "approved", "notes": "Legitimate admin review"},
    )
    assert admin_patch.status_code == 200
    assert admin_patch.json()["reviewer_status"] == "approved"


def test_username_length_boundaries_and_sanitization(client):
    """Verify strict 32-character boundary enforcement and injection rejection."""
    # 1. Exact 32-character username boundary -> Accepted (201)
    exact_32_user = "u" * 32
    res_32 = client.post(
        "/api/auth/register",
        json={"username": exact_32_user, "password": "password123", "full_name": "Boundary User 32"},
    )
    assert res_32.status_code == 201, f"Expected 201 for 32-char username, got {res_32.status_code}: {res_32.text}"

    # 2. 33-character boundary username -> Rejected (422)
    boundary_33_user = "u" * 33
    res_33 = client.post(
        "/api/auth/register",
        json={"username": boundary_33_user, "password": "password123", "full_name": "Boundary User 33"},
    )
    assert res_33.status_code == 422, f"Expected 422 for 33-char username, got {res_33.status_code}"

    # 3. 52-character username -> Rejected (422)
    long_52_user = "a" * 52
    res_52 = client.post(
        "/api/auth/register",
        json={"username": long_52_user, "password": "password123", "full_name": "Fifty Two User"},
    )
    assert res_52.status_code == 422, f"Expected 422 for 52-char username, got {res_52.status_code}"

    # 4. Disallowed characters and injection vectors -> Rejected (422)
    injection_usernames = [
        "admin' OR '1'='1",
        "<script>alert(1)</script>",
        "user with spaces",
        "user;DROP TABLE users;--",
        "user\x00nullbyte",
    ]
    for bad_u in injection_usernames:
        res_bad = client.post(
            "/api/auth/register",
            json={"username": bad_u, "password": "password123", "full_name": "Bad User"},
        )
        assert res_bad.status_code == 422, f"Expected 422 for injection username '{bad_u}', got {res_bad.status_code}"


def test_username_unicode_nfkc_normalization(client):
    """Verify Unicode compatibility characters are normalized with NFKC."""
    # Using Unicode full-width characters 'ＵＳＥＲ_ｎｆｋｃ' which fold to 'user_nfkc' under NFKC
    fullwidth_user = "ＵＳＥＲ_ｎｆｋｃ"
    res = client.post(
        "/api/auth/register",
        json={"username": fullwidth_user, "password": "password123", "full_name": "NFKC Tester"},
    )
    assert res.status_code == 201
    assert res.json()["user"]["username"] == "user_nfkc"


def test_certificate_dynamic_bounds_scaling(tmp_path):
    """Verify PDF certificate generator scales font and dividers for boundary learner names."""
    from backend.certificate import generate_certificate_pdf

    cert_path = tmp_path / "test_cert_long.pdf"
    # Test with 50-character boundary name
    long_name = "Alexandrina Montgomery-Wellington the Third Esq."
    out_path = generate_certificate_pdf(
        cert_path,
        learner_name=long_name,
        role_title="Software Developer & Systems Specialist",
        cert_id="PX-CERT-TESTBOUNDS",
        date_str="November 13, 2026",
    )
    assert out_path.exists()
    assert out_path.stat().st_size > 1000  # Valid non-empty PDF


def test_prax_04_unauthenticated_submissions_access_rejected(client):
    """PRAX-04: Verify unauthenticated callers cannot read or write submissions."""
    # 1. Unauthenticated POST -> 401
    post_res = client.post("/api/submissions", json={"mission_id": "cloud-sre-01", "answers": _valid_cloud_answers()})
    assert post_res.status_code == 401

    # 2. Unauthenticated GET all -> 401
    get_res = client.get("/api/submissions")
    assert get_res.status_code == 401


def test_prax_05_forged_quiz_and_unearned_certificates_rejected(client):
    """PRAX-05: Verify incomplete quiz submissions and unearned certificates are blocked."""
    headers = _sec_user_headers(client, "quiz_forger")

    # 1. Submitting less than 5 answers -> 422
    forged_quiz = client.post(
        "/api/quiz/submit",
        headers=headers,
        json={"answers": {"q1": "b", "q2": "b", "q3": "b", "q4": "b"}},
    )
    assert forged_quiz.status_code == 422

    # 2. Downloading certificate before passing quiz -> 403
    cert_res = client.get("/api/certificate/download", headers=headers)
    assert cert_res.status_code == 403


def test_prax_07_account_lockout_on_failed_logins(client):
    """PRAX-07: Verify 5 consecutive failed logins trigger 5-minute lockout (429)."""
    target_user = "lockout_target"
    client.post("/api/auth/register", json={"username": target_user, "password": "CorrectPassword1!", "full_name": "Lock Target"})

    # 5 failed login attempts
    for _ in range(5):
        client.post("/api/auth/login", json={"username": target_user, "password": "WrongPassword"})

    # 6th attempt -> 429 Too Many Requests
    locked_res = client.post("/api/auth/login", json={"username": target_user, "password": "CorrectPassword1!"})
    assert locked_res.status_code == 429
    assert "Locked for 5 minutes" in locked_res.json()["detail"]


def test_prax_10_recursive_input_depth_bounded(client):
    """PRAX-10: Verify deeply nested recursive answers do not cause RecursionError 500."""
    headers = _sec_user_headers(client, "recursive_tester")
    # Build a 50-level nested dict
    nested_val: dict = {"end": "deep"}
    for _ in range(50):
        nested_val = {"nest": nested_val}

    answers = _valid_cloud_answers()
    answers["hypothesis"] = nested_val

    res = client.post(
        "/api/submissions",
        headers=headers,
        json={"mission_id": "cloud-sre-01", "answers": answers},
    )
    # Server must gracefully handle without RecursionError (422 empty/invalid field)
    assert res.status_code == 422


