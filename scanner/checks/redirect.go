package checks

import (
	"net/http"
	"net/url"
	"strings"

	"whiteclaw/scanner/models"
)

var redirectPayloads = []string{
	"https://evil-attacker.com",
	"//evil-attacker.com",
	"/\\evil-attacker.com",
	"https://evil-attacker.com/",
	"https%3A%2F%2Fevil-attacker.com",
	"////evil-attacker.com",
}

// OpenRedirect tests URL parameters for open redirect vulnerabilities.
func OpenRedirect(client *http.Client, cfg models.ScanConfig) {
	models.Status("Testing open redirect...")
	if len(cfg.Params) == 0 {
		return
	}

	for _, param := range cfg.Params {
		for _, payload := range redirectPayloads {
			injected := injectParam(cfg.URL, param, payload)
			req, err := http.NewRequest("GET", injected, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", randomUA())
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			drainClose(resp)

			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				loc := resp.Header.Get("Location")
				parsed, err := url.Parse(loc)
				if err == nil && strings.Contains(parsed.Host, "evil-attacker.com") {
					models.Emit(models.Finding{
						Type:     "finding",
						Severity: "HIGH",
						Category: "vulnerabilities",
						Title:    "Open redirect via parameter: " + param,
						Detail:   "Server redirected to evil-attacker.com without validation.\nLocation: " + loc,
						Fix:      "Validate redirect destinations against an explicit allowlist. Reject external hosts.",
					})
					goto nextParam
				}
			}
		}
	nextParam:
	}
}
