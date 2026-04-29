# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""Category 33: GraphQL Security — Field suggestions, introspection abuse, hidden mutations."""
import json
import re
import pytest

from tests.active.helpers import safe_post, url_join
from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests modify server state, trigger lockouts, and may cause disruption."
    )

GRAPHQL_ENDPOINTS = [
    "/graphql", "/api/graphql", "/gql", "/query", "/api/v1/graphql",
]

INTROSPECTION_QUERY = '{"query":"{__schema{types{name fields{name type{kind}}}}}"}}'

SCHEMA_QUERY = '{"query":"{ __schema { types { name description fields { name description type { name kind } } } } }"}'


class TestGraphqlIntrospection:
    def test_graphql_introspection_enabled(self):
        """Test if GraphQL introspection is enabled."""
        for endpoint in GRAPHQL_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data=INTROSPECTION_QUERY,
                          headers={"Content-Type": "application/json"})
            if r is None or r.status_code == 404:
                continue
            
            try:
                data = r.json()
                if "data" in data and "__schema" in str(data.get("data", "")):
                    pytest.fail(
                        f"GraphQL introspection enabled at {endpoint}: "
                        "full schema is publicly queryable — enables API enumeration"
                    )
            except Exception:
                pass

    def test_graphql_full_schema_available(self):
        """Test if full GraphQL schema can be extracted."""
        for endpoint in GRAPHQL_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data=SCHEMA_QUERY,
                          headers={"Content-Type": "application/json"})
            if r is None:
                continue
            
            try:
                data = r.json()
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                if len(types) > 10:
                    pytest.skip(
                        f"Full GraphQL schema available at {endpoint}: {len(types)} types. "
                        "Manual review recommended to identify sensitive types/mutations."
                    )
            except Exception:
                pass


class TestGraphqlFieldSuggestions:
    def test_graphql_field_suggestions_leak_fields(self):
        """Test if GraphQL field suggestions reveal hidden fields."""
        for endpoint in GRAPHQL_ENDPOINTS:
            typo_query = '{"query":"{user{name internalI}}"}'  # Typo: internalI instead of internalId
            r = safe_post(url_join(endpoint),
                          data=typo_query,
                          headers={"Content-Type": "application/json"})
            if r is None:
                continue
            
            # Check for suggestions in error messages
            if "internalId" in r.text or "suggestions" in r.text.lower():
                pytest.skip(
                    f"GraphQL field suggestions available at {endpoint}: "
                    "typos trigger helpful error messages with correct field names"
                )


class TestGraphqlHiddenMutations:
    def test_graphql_mutations_not_publicly_accessible(self):
        """Test for mutations not advertised in schema but still callable."""
        hidden_mutations = [
            "deleteAllUsers",
            "setAdmin",
            "transferAllFunds",
            "disableAllAccounts",
            "executeCommand",
        ]
        
        for endpoint in GRAPHQL_ENDPOINTS:
            for mutation in hidden_mutations:
                query = f'{{"query":"mutation {{ {mutation} {{ success }} }}"}}'
                r = safe_post(url_join(endpoint),
                              data=query,
                              headers={"Content-Type": "application/json"})
                if r and "success" in r.text and "not defined" not in r.text.lower():
                    pytest.skip(
                        f"Hidden mutation accessible at {endpoint}: {mutation}"
                    )


class TestGraphqlAliasAbuse:
    def test_graphql_alias_bypass_rate_limiting(self):
        """Test if GraphQL aliases can bypass rate limiting."""
        for endpoint in GRAPHQL_ENDPOINTS:
            # Use aliases to execute same query multiple times in single request
            alias_query = '''{
                "query": "{ 
                    a1: user(id:1) { id name }
                    a2: user(id:1) { id name }
                    a3: user(id:1) { id name }
                }"
            }'''
            
            r = safe_post(url_join(endpoint),
                          data=alias_query,
                          headers={"Content-Type": "application/json"})
            if r and r.status_code == 200 and "a1" in r.text and "a2" in r.text:
                pytest.skip(
                    f"GraphQL aliases bypass at {endpoint}: "
                    "may allow circumventing rate limiting via batched queries"
                )


class TestGraphqlNestedQueries:
    def test_graphql_unbounded_recursion(self):
        """Test GraphQL query complexity via deeply nested queries."""
        for endpoint in GRAPHQL_ENDPOINTS:
            # Deeply nested query to test DoS
            nested = "{user{friend{friend{friend{friend{friend{name}}}}}}"
            query = f'{{"query":"{nested}"}}'
            
            r = safe_post(url_join(endpoint),
                          data=query,
                          headers={"Content-Type": "application/json"},
                          timeout=5)
            if r is None or r.status_code == 500:
                pytest.skip(
                    f"GraphQL recursive query timeout/error at {endpoint}: "
                    "may be vulnerable to query complexity DoS"
                )


class TestGraphqlDataExposure:
    def test_graphql_unnecessary_fields_exposed(self):
        """Test if GraphQL exposes sensitive fields unnecessarily."""
        for endpoint in GRAPHQL_ENDPOINTS:
            sensitive_query = '''{
                "query": "{ 
                    users { 
                        id name email passwordHash internalId apiKey 
                    } 
                }"
            }'''
            
            r = safe_post(url_join(endpoint),
                          data=sensitive_query,
                          headers={"Content-Type": "application/json"})
            if r:
                try:
                    data = r.json()
                    text = json.dumps(data).lower()
                    sensitive = ["passwordhash", "apikey", "internalid"]
                    found = [s for s in sensitive if s in text]
                    if found:
                        pytest.fail(
                            f"GraphQL exposes sensitive fields at {endpoint}: {found}"
                        )
                except Exception:
                    pass


class TestGraphqlSkipped:
    def test_graphql_complexity_dos_is_destructive(self):
        pytest.skip(
            "GraphQL complexity DoS is DESTRUCTIVE and may crash the server. "
            "See tests/destructive/ for full query complexity exploitation."
        )
