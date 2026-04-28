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

var apiPaths = []string{
	"/api", "/api/v1", "/api/v2", "/api/v3",
	"/graphql", "/graphiql", "/graphql/playground",
	"/rest", "/rest/v1",
	"/swagger", "/swagger.json", "/swagger.yaml", "/swagger-ui.html",
	"/openapi.json", "/openapi.yaml",
	"/api-docs", "/docs/api",
	"/v1", "/v2", "/v3",
	"/.well-known/openid-configuration",
	"/wp-json", "/wp-json/wp/v2",
	"/admin/api", "/api/admin", "/internal/api",
}

var endpointRe = regexp.MustCompile(
	`(?:fetch|axios\.[a-z]+)\s*\(\s*["']([/][^"'?\s]{2,80})["']|["'](/api/[^"'?\s]{2,80})["']`,
)

// APIs discovers API endpoints via path probing and inline JS mining.
func APIs(client *http.Client, cfg models.ScanConfig) {
	models.Status("Discovering API endpoints...")
	sem := newSem(cfg.Workers)
	var wg sync.WaitGroup

	// Probe known paths concurrently
	for _, p := range apiPaths {
		wg.Add(1)
		p := p
		sem.Acquire()
		go func() {
			defer wg.Done()
			defer sem.Release()

			u := strings.TrimRight(cfg.BaseURL, "/") + p
			resp, err := get(client, u)
			if err != nil {
				return
			}
			drainClose(resp)

			if resp.StatusCode < 400 {
				sev := "INFO"
				if resp.StatusCode == 200 {
					sev = "MEDIUM"
				}
				models.Emit(models.Finding{
					Type:     "finding",
					Severity: sev,
					Category: "apis",
					Title:    fmt.Sprintf("API endpoint found: %s", p),
					Detail:   fmt.Sprintf("%s returned HTTP %d.", u, resp.StatusCode),
					Fix:      "Ensure the endpoint requires authentication and rate-limiting.",
				})
			}
		}()
	}

	// Mine inline JS for fetch/axios calls
	resp, err := get(client, cfg.URL)
	if err == nil {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()

		seen := map[string]bool{}
		for _, m := range endpointRe.FindAllSubmatch(buf, -1) {
			ep := string(m[1])
			if ep == "" {
				ep = string(m[2])
			}
			if ep == "" || seen[ep] {
				continue
			}
			seen[ep] = true

			wg.Add(1)
			ep := ep
			sem.Acquire()
			go func() {
				defer wg.Done()
				defer sem.Release()
				u := strings.TrimRight(cfg.BaseURL, "/") + ep
				r, err := get(client, u)
				if err != nil {
					return
				}
				drainClose(r)
				if r.StatusCode < 400 {
					models.Emit(models.Finding{
						Type:     "finding",
						Severity: "INFO",
						Category: "apis",
						Title:    fmt.Sprintf("JS-mined API endpoint: %s", ep),
						Detail:   fmt.Sprintf("Found in inline JS; %s returned HTTP %d.", u, r.StatusCode),
						Fix:      "Verify this endpoint enforces proper authentication.",
					})
				}
			}()
		}
	}

	wg.Wait()
}
