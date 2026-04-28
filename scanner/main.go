package main

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"

	"whiteclaw/scanner/checks"
	"whiteclaw/scanner/models"
)

func main() {
	var cfg models.ScanConfig
	if err := json.NewDecoder(os.Stdin).Decode(&cfg); err != nil {
		models.Error("Failed to decode scan config: " + err.Error())
		models.Done()
		return
	}
	if cfg.Workers == 0 {
		cfg.Workers = 20
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 8
	}

	client := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConnsPerHost: cfg.Workers,
		},
		// Do not follow redirects automatically — some checks need raw Location headers.
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Run all checks concurrently — each is independent.
	all := []func(*http.Client, models.ScanConfig){
		checks.Headers,
		checks.SecurityHeaders,
		checks.Cookies,
		checks.CORS,
		checks.SensitiveFiles,
		checks.APIs,
		checks.Databases,
		checks.SQLi,
		checks.XSS,
		checks.OpenRedirect,
		checks.HTTPMethods,
		checks.PathTraversal,
		checks.SSRF,
		checks.JSSecrets,
		checks.RobotsAndSitemap,
	}

	var wg sync.WaitGroup
	for _, fn := range all {
		wg.Add(1)
		fn := fn
		go func() {
			defer wg.Done()
			fn(client, cfg)
		}()
	}
	wg.Wait()
	models.Done()
}
