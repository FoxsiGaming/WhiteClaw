package checks

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"whiteclaw/scanner/models"
)

var jsPatterns = []struct {
	name string
	re   *regexp.Regexp
	sev  string
}{
	{"AWS Access Key ID", regexp.MustCompile(`(?:AKIA|ASIA|AROA)[A-Z0-9]{16}`), "CRITICAL"},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}["'][A-Za-z0-9/+=]{40}["']`), "CRITICAL"},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), "HIGH"},
	{"Stripe Secret Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), "CRITICAL"},
	{"Stripe Publishable Key", regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`), "MEDIUM"},
	{"SendGrid API Key", regexp.MustCompile(`SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`), "HIGH"},
	{"GitHub PAT", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), "CRITICAL"},
	{"OpenAI API Key", regexp.MustCompile(`sk-[A-Za-z0-9]{48}`), "CRITICAL"},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]+`), "HIGH"},
	{"Generic API Key", regexp.MustCompile(`(?i)api[_\-]?key\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']`), "HIGH"},
	{"Hardcoded Password", regexp.MustCompile(`(?i)password\s*[:=]\s*["'][^"']{6,}["']`), "HIGH"},
	{"MongoDB URI", regexp.MustCompile(`mongodb(?:\+srv)?://[^\s"'<>]{10,}`), "CRITICAL"},
	{"PostgreSQL URI", regexp.MustCompile(`postgres(?:ql)?://[^\s"'<>]{10,}`), "CRITICAL"},
	{"Redis URI", regexp.MustCompile(`redis://[^\s"'<>]{6,}`), "HIGH"},
	{"JWT Token", regexp.MustCompile(`eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+`), "MEDIUM"},
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']`)

// JSSecrets scans JavaScript files for hardcoded credentials and tokens.
func JSSecrets(client *http.Client, cfg models.ScanConfig) {
	models.Status("Scanning JavaScript files for hardcoded secrets...")

	jsURLs := make([]string, 0, len(cfg.JSURLs))
	jsURLs = append(jsURLs, cfg.JSURLs...)

	if len(jsURLs) == 0 {
		resp, err := get(client, cfg.URL)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			resp.Body.Close()
			for _, m := range scriptSrcRe.FindAllSubmatch(body, -1) {
				src := string(m[1])
				switch {
				case strings.HasPrefix(src, "//"):
					src = "https:" + src
				case !strings.HasPrefix(src, "http"):
					src = strings.TrimRight(cfg.BaseURL, "/") + "/" + strings.TrimLeft(src, "/")
				}
				jsURLs = append(jsURLs, src)
			}
		}
	}

	if len(jsURLs) == 0 {
		models.Status("JSSecrets: no JS files found.")
		return
	}

	sem := newSem(cfg.Workers)
	var wg sync.WaitGroup

	for _, jsURL := range jsURLs {
		wg.Add(1)
		jsURL := jsURL
		sem.Acquire()
		go func() {
			defer wg.Done()
			defer sem.Release()

			resp, err := get(client, jsURL)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
			resp.Body.Close()
			src := string(body)

			for _, pat := range jsPatterns {
				m := pat.re.FindString(src)
				if m == "" {
					continue
				}
				snippet := m
				if len(snippet) > 80 {
					snippet = snippet[:80] + "..."
				}
				models.Emit(models.Finding{
					Type:     "finding",
					Severity: pat.sev,
					Category: "vulnerabilities",
					Title:    fmt.Sprintf("Hardcoded secret in JS: %s", pat.name),
					Detail:   fmt.Sprintf("File: %s\nMatch: %s", jsURL, snippet),
					Fix:      "Move secrets to server-side environment variables. Never ship credentials in client-side bundles.",
				})
			}
		}()
	}
	wg.Wait()
}
