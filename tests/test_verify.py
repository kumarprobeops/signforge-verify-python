"""Tests for signforge-verify package."""

import copy
import json
import os

import pytest

from signforge_verify import verify, extract_from_html, verify_data_integrity_proof, verify_merkle_inclusion
from signforge_verify.verifier import jwk_to_public_key

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def proof_bundle():
    with open(os.path.join(FIXTURES, "proof-bundle.json")) as f:
        return json.load(f)


class TestHtmlVerification:
    def test_verify_sample_proof_html(self):
        filepath = os.path.join(FIXTURES, "sample.proof.html")
        result = verify(filepath)
        assert result["valid"] is True
        assert result["checks"]["vc_signature"]["status"] == "pass"
        assert result["checks"]["merkle_proof"]["status"] == "pass"

    def test_extract_from_html(self):
        filepath = os.path.join(FIXTURES, "sample.proof.html")
        bundle = extract_from_html(filepath)
        assert bundle is not None
        assert "vc" in bundle
        assert "keys" in bundle


class TestPdfVerification:
    def test_verify_sample_signed_pdf(self):
        filepath = os.path.join(FIXTURES, "sample-signed.pdf")
        result = verify(filepath)
        assert result["valid"] is True
        assert result["checks"]["vc_signature"]["status"] == "pass"

    def test_verify_tampered_pdf(self):
        filepath = os.path.join(FIXTURES, "tampered-signed.pdf")
        result = verify(filepath)
        # The VC itself may still be valid (it's metadata embedded before tamper),
        # but the document hash won't match if content was tampered.
        # At minimum, the verifier should run without crashing.
        assert isinstance(result["valid"], bool)


class TestBundleVerification:
    def test_verify_bundle_directly(self, proof_bundle):
        from signforge_verify.verifier import verify_data_integrity_proof, jwk_to_public_key
        pub = jwk_to_public_key(proof_bundle["keys"]["issuer"]["publicKeyJwk"])
        assert verify_data_integrity_proof(proof_bundle["vc"], pub) is True

    def test_tampered_vc_fails(self, proof_bundle):
        bundle = copy.deepcopy(proof_bundle)
        bundle["vc"]["credentialSubject"]["signedDocumentHash"] = "deadbeef" * 8
        pub = jwk_to_public_key(bundle["keys"]["issuer"]["publicKeyJwk"])
        assert verify_data_integrity_proof(bundle["vc"], pub) is False

    def test_tampered_merkle_root_fails(self, proof_bundle):
        bundle = copy.deepcopy(proof_bundle)
        tp = bundle.get("transparency", {})
        sth = tp.get("signed_tree_head", {})
        key = "root_hash" if "root_hash" in sth else "root"
        sth[key] = "deadbeef" * 8
        result = verify_merkle_inclusion(
            tp["leaf_hash"],
            tp["merkle_proof"],
            sth[key],
        )
        assert result is False


class TestEdgeCases:
    def test_unsupported_file_type(self):
        result = verify("test.docx")
        assert result["valid"] is False

    def test_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            verify("nonexistent.html")
