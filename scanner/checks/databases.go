package checks

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"whiteclaw/scanner/models"
)

var dbEndpoints = []struct{ path, name string }{
	{"/phpmyadmin", "phpMyAdmin"},
	{"/phpmyadmin/", "phpMyAdmin"},
	{"/pma", "phpMyAdmin"},
	{"/adminer.php", "Adminer"},
	{"/adminer", "Adminer"},
	{"/pgadmin", "pgAdmin"},
	{"/pgadmin4", "pgAdmin 4"},
	{"/mongo-express", "Mongo Express"},
	{"/mongoexpress", "Mongo Express"},
	{"/redis", "Redis Web UI"},
	{"/redisinsight", "RedisInsight"},
	{"/kibana", "Kibana"},
	{"/_cat", "Elasticsearch"},
	{"/couchdb", "CouchDB"},
}

// Databases probes known database admin interface paths.
func Databases(client *http.Client, cfg models.ScanConfig) {
	models.Status("Probing database admin interfaces...")
	sem := newSem(cfg.Workers)
	var wg sync.WaitGroup

	for _, ep := range dbEndpoints {
		wg.Add(1)
		ep := ep
		sem.Acquire()
		go func() {
			defer wg.Done()
			defer sem.Release()

			u := strings.TrimRight(cfg.BaseURL, "/") + ep.path
			resp, err := get(client, u)
			if err != nil {
				return
			}
			drainClose(resp)

			// 200 = login page or open, 401/403 = protected but exposed, 302 = redirects to login
			if resp.StatusCode == 200 || resp.StatusCode == 302 ||
				resp.StatusCode == 401 || resp.StatusCode == 403 {
				sev := "HIGH"
				if resp.StatusCode == 200 {
					sev = "CRITICAL"
				}
				models.Emit(models.Finding{
					Type:     "finding",
					Severity: sev,
					Category: "database",
					Title:    fmt.Sprintf("DB admin interface accessible: %s", ep.name),
					Detail:   fmt.Sprintf("%s returned HTTP %d at %s.", ep.name, resp.StatusCode, u),
					Fix:      fmt.Sprintf("Restrict %s to internal networks only. Use IP allowlisting or a VPN.", ep.name),
				})
			}
		}()
	}
	wg.Wait()
}
