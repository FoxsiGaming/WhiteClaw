package checks

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"whiteclaw/scanner/models"
)

var sensitivePaths = []struct{ path, title, sev string }{
	{"/.env", "Environment file exposed (.env)", "CRITICAL"},
	{"/.env.local", "Local environment file exposed", "CRITICAL"},
	{"/.env.production", "Production environment file exposed", "CRITICAL"},
	{"/.env.backup", "Backup environment file exposed", "CRITICAL"},
	{"/.env.staging", "Staging environment file exposed", "CRITICAL"},
	{"/.git/HEAD", "Git repository exposed (HEAD)", "CRITICAL"},
	{"/.git/config", "Git config exposed", "CRITICAL"},
	{"/.git/COMMIT_EDITMSG", "Git commit message exposed", "HIGH"},
	{"/.git/index", "Git index exposed — full repo reconstructable", "CRITICAL"},
	{"/wp-config.php", "WordPress config exposed", "CRITICAL"},
	{"/wp-config.php.bak", "WordPress config backup exposed", "CRITICAL"},
	{"/backup.zip", "Backup archive exposed", "CRITICAL"},
	{"/backup.tar.gz", "Backup archive exposed", "CRITICAL"},
	{"/backup.sql", "SQL backup exposed", "CRITICAL"},
	{"/dump.sql", "Database dump exposed", "CRITICAL"},
	{"/database.sql", "Database SQL exposed", "CRITICAL"},
	{"/db.sql", "Database SQL exposed", "CRITICAL"},
	{"/terraform.tfstate", "Terraform state — cloud credentials exposed", "CRITICAL"},
	{"/.vault-token", "HashiCorp Vault token exposed", "CRITICAL"},
	{"/.ssh/id_rsa", "SSH private key exposed", "CRITICAL"},
	{"/private-key.pem", "PEM private key exposed", "CRITICAL"},
	{"/server.key", "TLS server private key exposed", "CRITICAL"},
	{"/config.php", "PHP config exposed", "HIGH"},
	{"/config.js", "JS config exposed", "HIGH"},
	{"/config.json", "JSON config exposed", "HIGH"},
	{"/config/database.yml", "Rails database config exposed", "HIGH"},
	{"/config/secrets.yml", "Rails secrets exposed", "HIGH"},
	{"/settings.py", "Python settings exposed", "HIGH"},
	{"/web.config", "IIS web.config exposed", "HIGH"},
	{"/phpinfo.php", "phpinfo() leaks server internals", "HIGH"},
	{"/info.php", "PHP info page exposed", "HIGH"},
	{"/_profiler", "Symfony profiler exposed", "HIGH"},
	{"/telescope", "Laravel Telescope debug dashboard", "HIGH"},
	{"/horizon", "Laravel Horizon queue monitor", "HIGH"},
	{"/storage/logs/laravel.log", "Laravel log file exposed", "HIGH"},
	{"/error.log", "Error log exposed", "HIGH"},
	{"/.ssh/authorized_keys", "SSH authorized_keys exposed", "HIGH"},
	{"/test.php", "Test PHP file on server", "MEDIUM"},
	{"/server-status", "Apache server-status exposed", "MEDIUM"},
	{"/server-info", "Apache server-info exposed", "MEDIUM"},
	{"/wp-login.php", "WordPress login detected", "MEDIUM"},
	{"/wp-admin", "WordPress admin panel", "MEDIUM"},
	{"/.htaccess", "htaccess config exposed", "MEDIUM"},
	{"/access.log", "Access log exposed", "MEDIUM"},
	{"/.DS_Store", "macOS .DS_Store exposes directory layout", "LOW"},
	{"/package.json", "package.json reveals dependency versions", "LOW"},
	{"/package-lock.json", "package-lock.json reveals full dependency tree", "LOW"},
	{"/composer.json", "composer.json reveals PHP dependencies", "LOW"},
	{"/Gemfile", "Gemfile reveals Ruby dependencies", "LOW"},
	{"/yarn.lock", "yarn.lock reveals full JS dependency tree", "LOW"},
	{"/swagger-ui.html", "Swagger UI — full API docs public", "INFO"},
	{"/.well-known/security.txt", "security.txt vulnerability disclosure policy", "INFO"},
}

// SensitiveFiles probes all known sensitive paths concurrently.
func SensitiveFiles(client *http.Client, cfg models.ScanConfig) {
	models.Status(fmt.Sprintf("Probing %d sensitive paths...", len(sensitivePaths)))
	sem := newSem(cfg.Workers)
	var wg sync.WaitGroup

	for _, p := range sensitivePaths {
		wg.Add(1)
		p := p
		sem.Acquire()
		go func() {
			defer wg.Done()
			defer sem.Release()

			u := strings.TrimRight(cfg.BaseURL, "/") + p.path
			req, err := http.NewRequest("HEAD", u, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", randomUA())
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			drainClose(resp)

			if resp.StatusCode == 200 {
				models.Emit(models.Finding{
					Type:     "finding",
					Severity: p.sev,
					Category: "vulnerabilities",
					Title:    p.title,
					Detail:   fmt.Sprintf("Path %q returned HTTP 200.", u),
					Fix:      "Remove or restrict access to this path via server configuration.",
				})
			}
		}()
	}
	wg.Wait()
}
