"""Category 17: Infrastructure & Deployment — exposed services and internal assets."""
import socket
import re
import pytest

from tests.active.helpers import safe_get, url_join, target_host
from tests.active.config import TARGET_URL, TIMEOUT

INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3})\b"
)


def _tcp_connect(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.close()
        return True
    except Exception:
        return False


class TestStagingEnvironmentExposure:
    def test_staging_subdomains_not_accessible(self):
        host = target_host()
        parts = host.split(".")
        if len(parts) < 2:
            pytest.skip("can't derive staging domain")
        base = ".".join(parts[-2:])
        staging_hosts = [
            f"staging.{base}", f"dev.{base}", f"test.{base}",
            f"uat.{base}", f"qa.{base}", f"demo.{base}", f"preprod.{base}",
        ]
        exposed = []
        for h in staging_hosts:
            try:
                socket.gethostbyname(h)
                r = safe_get(f"https://{h}/")
                if r and r.status_code == 200:
                    exposed.append(h)
            except socket.gaierror:
                pass
        if exposed:
            pytest.fail(
                f"Staging/dev subdomains resolve and return 200: {exposed}"
            )


class TestInternalIpDisclosure:
    def test_no_internal_ip_in_response_body(self, base_html):
        found = INTERNAL_IP_RE.findall(base_html)
        assert not found, (
            f"Internal IP addresses in response body: {list(set(found))[:5]}"
        )

    def test_no_internal_ip_in_response_headers(self, base_headers):
        header_str = " ".join(base_headers.values())
        found = INTERNAL_IP_RE.findall(header_str)
        assert not found, (
            f"Internal IP addresses in response headers: {list(set(found))}"
        )


class TestExposedServices:
    def test_redis_not_publicly_accessible(self):
        host = target_host()
        open_ = _tcp_connect(host, 6379)
        assert not open_, (
            f"Redis port 6379 is open on {host} — Redis should never be publicly accessible"
        )

    def test_mongodb_not_publicly_accessible(self):
        host = target_host()
        open_ = _tcp_connect(host, 27017)
        assert not open_, (
            f"MongoDB port 27017 is open on {host} — database exposed to internet"
        )

    def test_postgresql_not_publicly_accessible(self):
        host = target_host()
        open_ = _tcp_connect(host, 5432)
        assert not open_, (
            f"PostgreSQL port 5432 is open on {host} — database exposed to internet"
        )

    def test_mysql_not_publicly_accessible(self):
        host = target_host()
        open_ = _tcp_connect(host, 3306)
        assert not open_, (
            f"MySQL port 3306 is open on {host} — database exposed to internet"
        )

    def test_memcached_not_publicly_accessible(self):
        host = target_host()
        open_ = _tcp_connect(host, 11211)
        assert not open_, (
            f"Memcached port 11211 is open on {host} — unauth access possible"
        )


class TestElasticsearchExposure:
    def test_elasticsearch_not_publicly_accessible(self):
        host = target_host()
        for port in [9200, 9300]:
            if _tcp_connect(host, port):
                r = safe_get(f"http://{host}:{port}/")
                if r and r.status_code == 200 and "elasticsearch" in r.text.lower():
                    pytest.fail(
                        f"Elasticsearch on port {port} is publicly accessible without auth"
                    )


class TestDockerKubernetesExposure:
    def test_kubernetes_dashboard_not_accessible(self):
        for path in ["/api/v1", "/api/v1/namespaces", "/healthz"]:
            for port in [8001, 8443, 6443]:
                host = target_host()
                r = safe_get(f"http://{host}:{port}{path}")
                if r and r.status_code == 200 and ("namespace" in r.text.lower() or
                                                     "kubernetes" in r.text.lower()):
                    pytest.fail(f"Kubernetes API exposed at port {port}{path}")

    def test_docker_daemon_not_accessible(self):
        host = target_host()
        r = safe_get(f"http://{host}:2375/version")
        if r and r.status_code == 200 and "docker" in r.text.lower():
            pytest.fail("Docker daemon API accessible without TLS on port 2375")


class TestCiCdExposure:
    def test_jenkins_not_accessible(self):
        for path in ["/jenkins", "/jenkins/", "/view/All/", "/job"]:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200 and "jenkins" in r.text.lower():
                pytest.fail(f"Jenkins CI/CD exposed at {path}")

    def test_github_actions_webhook_not_guessable(self):
        host = target_host()
        # Check for common CI webhook paths
        for path in ["/.github/workflows", "/webhook/jenkins", "/ci/webhook"]:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200:
                pytest.fail(f"CI/CD webhook or workflow config exposed at {path}")


class TestDatabaseAdminPanels:
    def test_phpmyadmin_not_accessible(self):
        for path in ["/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/"]:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200 and "phpmyadmin" in r.text.lower():
                pytest.fail(f"phpMyAdmin accessible at {path}")

    def test_pgadmin_not_accessible(self):
        for path in ["/pgadmin", "/pgadmin4", "/pgadmin/"]:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200:
                pytest.fail(f"pgAdmin accessible at {path}")

    def test_adminer_not_accessible(self):
        for path in ["/adminer.php", "/adminer", "/adminer/"]:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200:
                pytest.fail(f"Adminer database UI accessible at {path}")
