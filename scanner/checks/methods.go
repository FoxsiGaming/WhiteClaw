package checks

import (
	"fmt"
	"net/http"
	"strings"

	"whiteclaw/scanner/models"
)

var dangerousMethods = []string{"TRACE", "TRACK", "PUT", "DELETE", "PATCH", "PROPFIND"}

// HTTPMethods tests for dangerous HTTP verbs enabled on the server.
func HTTPMethods(client *http.Client, cfg models.ScanConfig) {
	models.Status("Testing dangerous HTTP methods...")

	// Check OPTIONS Allow header
	req, err := http.NewRequest("OPTIONS", cfg.URL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", randomUA())
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	drainClose(resp)

	allow := strings.ToUpper(resp.Header.Get("Allow"))
	if allow != "" {
		models.Emit(models.Finding{
			Type:     "finding",
			Severity: "INFO",
			Category: "vulnerabilities",
			Title:    "HTTP OPTIONS reveals allowed methods",
			Detail:   "Allow: " + allow,
			Fix:      "Restrict allowed methods to GET/POST/HEAD in your server config.",
		})
		for _, m := range dangerousMethods {
			if strings.Contains(allow, m) {
				models.Emit(models.Finding{
					Type:     "finding",
					Severity: "HIGH",
					Category: "vulnerabilities",
					Title:    fmt.Sprintf("Dangerous HTTP method enabled: %s", m),
					Detail:   "OPTIONS Allow header includes " + m + ".",
					Fix:      fmt.Sprintf("Disable %s in your web server configuration.", m),
				})
			}
		}
	}

	// Directly probe TRACE (XST)
	traceReq, err := http.NewRequest("TRACE", cfg.URL, nil)
	if err != nil {
		return
	}
	traceReq.Header.Set("User-Agent", randomUA())
	traceReq.Header.Set("X-Custom-Header", "whiteclaw-xst-probe")
	traceResp, err := client.Do(traceReq)
	if err != nil {
		return
	}
	drainClose(traceResp)
	if traceResp.StatusCode == 200 && !strings.Contains(allow, "TRACE") {
		models.Emit(models.Finding{
			Type:     "finding",
			Severity: "MEDIUM",
			Category: "vulnerabilities",
			Title:    "HTTP TRACE enabled — Cross-Site Tracing (XST)",
			Detail:   fmt.Sprintf("Server responded %d to TRACE request.", traceResp.StatusCode),
			Fix:      "Disable TRACE: TraceEnable Off (Apache) or deny_methods TRACE (Nginx).",
		})
	}
}
