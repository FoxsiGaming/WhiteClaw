package checks

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"whiteclaw/scanner/models"
)

var disallowRe = regexp.MustCompile(`(?im)^Disallow:\s*(\S+)`)
var sitemapRe = regexp.MustCompile(`(?im)^Sitemap:\s*(\S+)`)
var sitemapLocRe = regexp.MustCompile(`<loc>([^<]+)</loc>`)

// RobotsAndSitemap fetches robots.txt and sitemap.xml and reports findings.
func RobotsAndSitemap(client *http.Client, cfg models.ScanConfig) {
	models.Status("Checking robots.txt and sitemap.xml...")
	base := strings.TrimRight(cfg.BaseURL, "/")

	// robots.txt
	resp, err := get(client, base+"/robots.txt")
	if err == nil && resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		text := string(body)

		models.Emit(models.Finding{
			Type:     "finding",
			Severity: "INFO",
			Category: "ctf",
			Title:    "robots.txt found",
			Detail:   text[:min(len(text), 800)],
			Fix:      "Never rely on robots.txt to hide sensitive paths — use proper access controls.",
		})

		var paths []string
		for _, m := range disallowRe.FindAllStringSubmatch(text, -1) {
			p := strings.TrimSpace(m[1])
			if p != "" && p != "/" {
				paths = append(paths, p)
			}
		}
		if len(paths) > 0 {
			models.Emit(models.Finding{
				Type:     "finding",
				Severity: "INFO",
				Category: "ctf",
				Title:    fmt.Sprintf("robots.txt discloses %d hidden path(s)", len(paths)),
				Detail:   strings.Join(paths, "\n"),
				Fix:      "Disallowed paths in robots.txt are public — use server-side auth to protect them.",
			})
		}

		for _, m := range sitemapRe.FindAllStringSubmatch(text, -1) {
			models.Emit(models.Finding{
				Type:     "finding",
				Severity: "INFO",
				Category: "ctf",
				Title:    "Sitemap discovered via robots.txt",
				Detail:   "Sitemap: " + strings.TrimSpace(m[1]),
				Fix:      "Review sitemap entries for unintentionally exposed endpoints.",
			})
		}
	} else if resp != nil {
		drainClose(resp)
	}

	// sitemap.xml
	sresp, err := get(client, base+"/sitemap.xml")
	if err == nil && sresp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(sresp.Body, 128*1024))
		sresp.Body.Close()
		urls := sitemapLocRe.FindAllSubmatch(body, -1)
		models.Emit(models.Finding{
			Type:     "finding",
			Severity: "INFO",
			Category: "ctf",
			Title:    fmt.Sprintf("sitemap.xml accessible (%d URLs)", len(urls)),
			Detail:   fmt.Sprintf("GET %s/sitemap.xml returned 200.", base),
			Fix:      "Review sitemap entries. If it contains admin or internal URLs, restrict access.",
		})
	} else if sresp != nil {
		drainClose(sresp)
	}
}
