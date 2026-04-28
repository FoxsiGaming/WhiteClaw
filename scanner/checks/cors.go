package checks

import (
	"net/http"
	"strings"

	"whiteclaw/scanner/models"
)

// CORS tests for wildcard and reflected-origin misconfigurations.
func CORS(client *http.Client, cfg models.ScanConfig) {
	models.Status("Testing CORS policy...")
	req, err := http.NewRequest("GET", cfg.URL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Origin", "https://evil-attacker.com")
	req.Header.Set("User-Agent", randomUA())

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer drainClose(resp)

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))

	if acao == "*" {
		models.Emit(models.Finding{
			Type:     "finding",
			Severity: "MEDIUM",
			Category: "vulnerabilities",
			Title:    "CORS: wildcard Access-Control-Allow-Origin",
			Detail:   "Server returns ACAO: * — any origin can read responses.",
			Fix:      "Restrict ACAO to an explicit allowlist. Never combine * with credentials.",
		})
	}

	if strings.Contains(acao, "evil-attacker.com") {
		sev := "HIGH"
		note := ""
		if acac == "true" {
			sev = "CRITICAL"
			note = " with credentials — session tokens exfiltrable!"
		}
		models.Emit(models.Finding{
			Type:     "finding",
			Severity: sev,
			Category: "vulnerabilities",
			Title:    "CORS: arbitrary Origin reflected" + note,
			Detail:   "ACAO: " + acao + "  ACAC: " + acac,
			Fix:      "Validate the Origin header against a hardcoded server-side allowlist before reflecting it.",
		})
	}
}
