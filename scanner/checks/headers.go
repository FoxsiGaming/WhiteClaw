package checks

import (
	"fmt"
	"net/http"
	"strings"

	"whiteclaw/scanner/models"
)

// Headers checks for server banner / technology disclosure headers.
func Headers(client *http.Client, cfg models.ScanConfig) {
	models.Status("Checking server disclosure headers...")
	resp, err := get(client, cfg.URL)
	if err != nil {
		models.Error("headers: " + err.Error())
		return
	}
	defer drainClose(resp)

	disclose := []struct{ name, fix string }{
		{"Server", "Set ServerTokens Prod (Apache) or server_tokens off (Nginx)."},
		{"X-Powered-By", "Remove via app config. Express: app.disable('x-powered-by')."},
		{"X-AspNet-Version", "Remove in web.config: <httpRuntime enableVersionHeader=\"false\">."},
		{"X-AspNetMvc-Version", "Remove in Application_Start: MvcHandler.DisableMvcResponseHeader = true;"},
		{"X-Generator", "Remove the generator meta-tag and response header."},
		{"X-Debug-Token", "Disable the Symfony profiler in production (APP_ENV=prod)."},
		{"X-Debug-Token-Link", "Disable the Symfony profiler in production (APP_ENV=prod)."},
	}
	for _, h := range disclose {
		if v := resp.Header.Get(h.name); v != "" {
			models.Emit(models.Finding{
				Type:     "finding",
				Severity: "LOW",
				Category: "vulnerabilities",
				Title:    fmt.Sprintf("Server disclosure: %s", h.name),
				Detail:   fmt.Sprintf("Header %q reveals: %q", h.name, v),
				Fix:      h.fix,
			})
		}
	}
}

// SecurityHeaders checks for missing defensive response headers.
func SecurityHeaders(client *http.Client, cfg models.ScanConfig) {
	models.Status("Checking security headers...")
	resp, err := get(client, cfg.URL)
	if err != nil {
		return
	}
	defer drainClose(resp)

	type rule struct {
		name string
		sev  string
		fix  string
	}
	rules := []rule{
		{"Strict-Transport-Security", "HIGH",
			"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"},
		{"Content-Security-Policy", "HIGH",
			"Implement a Content-Security-Policy restricting script/style sources."},
		{"X-Frame-Options", "HIGH",
			"Add: X-Frame-Options: DENY"},
		{"X-Content-Type-Options", "MEDIUM",
			"Add: X-Content-Type-Options: nosniff"},
		{"Referrer-Policy", "MEDIUM",
			"Add: Referrer-Policy: strict-origin-when-cross-origin"},
		{"Permissions-Policy", "LOW",
			"Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"},
		{"Cross-Origin-Opener-Policy", "MEDIUM",
			"Add: Cross-Origin-Opener-Policy: same-origin"},
	}
	for _, r := range rules {
		if resp.Header.Get(r.name) == "" {
			models.Emit(models.Finding{
				Type:     "finding",
				Severity: r.sev,
				Category: "vulnerabilities",
				Title:    "Missing security header: " + r.name,
				Detail:   fmt.Sprintf("The response does not include the %q header.", r.name),
				Fix:      r.fix,
			})
		}
	}

	// Flag dangerous CSP directives if CSP exists
	csp := resp.Header.Get("Content-Security-Policy")
	if csp != "" {
		for _, bad := range []string{"'unsafe-inline'", "'unsafe-eval'", "* "} {
			if strings.Contains(csp, bad) {
				models.Emit(models.Finding{
					Type:     "finding",
					Severity: "HIGH",
					Category: "vulnerabilities",
					Title:    fmt.Sprintf("Dangerous CSP directive: %s", strings.TrimSpace(bad)),
					Detail:   fmt.Sprintf("CSP: %s", csp[:min(len(csp), 250)]),
					Fix:      fmt.Sprintf("Remove %q from your CSP — it largely negates XSS protection.", bad),
				})
			}
		}
	}
}

// Cookies checks Set-Cookie headers for missing security flags.
func Cookies(client *http.Client, cfg models.ScanConfig) {
	models.Status("Checking cookie security flags...")
	resp, err := get(client, cfg.URL)
	if err != nil {
		return
	}
	defer drainClose(resp)

	for _, raw := range resp.Header["Set-Cookie"] {
		low := strings.ToLower(raw)
		name := strings.SplitN(raw, "=", 2)[0]
		if !strings.Contains(low, "httponly") {
			models.Emit(models.Finding{
				Type:     "finding",
				Severity: "MEDIUM",
				Category: "vulnerabilities",
				Title:    fmt.Sprintf("Cookie missing HttpOnly: %s", name),
				Detail:   fmt.Sprintf("Cookie %q has no HttpOnly attribute — readable by JavaScript.", name),
				Fix:      "Add HttpOnly to all session and authentication cookies.",
			})
		}
		if !strings.Contains(low, "secure") {
			models.Emit(models.Finding{
				Type:     "finding",
				Severity: "MEDIUM",
				Category: "vulnerabilities",
				Title:    fmt.Sprintf("Cookie missing Secure flag: %s", name),
				Detail:   fmt.Sprintf("Cookie %q can be sent over plain HTTP.", name),
				Fix:      "Add the Secure flag to all cookies.",
			})
		}
		if !strings.Contains(low, "samesite") {
			models.Emit(models.Finding{
				Type:     "finding",
				Severity: "LOW",
				Category: "vulnerabilities",
				Title:    fmt.Sprintf("Cookie missing SameSite: %s", name),
				Detail:   fmt.Sprintf("Cookie %q has no SameSite restriction.", name),
				Fix:      "Set SameSite=Strict or SameSite=Lax on all cookies.",
			})
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
