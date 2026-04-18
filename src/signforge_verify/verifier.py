"""Core verification logic for SignForge proof bundles.

All cryptographic operations use the ``cryptography`` library.
PDF extraction requires ``PyMuPDF`` (optional dependency).
"""

import base64
import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# ---------------------------------------------------------------------------
# Base58btc (for did:key decoding)
# ---------------------------------------------------------------------------

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_DECODE_MAP = {c: i for i, c in enumerate(_B58_ALPHABET)}


def _b58_decode(s: str) -> bytes:
    n = 0
    for c in s.encode("ascii"):
        n = n * 58 + _B58_DECODE_MAP[c]
    leading_zeros = 0
    for c in s:
        if c == "1":
            leading_zeros += 1
        else:
            break
    if n == 0:
        return b"\x00" * leading_zeros
    byte_length = (n.bit_length() + 7) // 8
    return b"\x00" * leading_zeros + n.to_bytes(byte_length, "big")


def multibase_b58btc_decode(s: str) -> bytes:
    if not s.startswith("z"):
        raise ValueError("Expected 'z' multibase prefix")
    return _b58_decode(s[1:])


# ---------------------------------------------------------------------------
# Public key extraction
# ---------------------------------------------------------------------------

_P256_MULTICODEC_PREFIX = bytes([0x80, 0x24])


def did_key_to_public_key(did_key: str) -> ec.EllipticCurvePublicKey:
    """Convert did:key:z... to an EC public key object."""
    multibase = did_key.split(":")[-1]
    raw = multibase_b58btc_decode(multibase)
    if not raw.startswith(_P256_MULTICODEC_PREFIX):
        raise ValueError("Not a P-256 did:key")
    compressed = raw[len(_P256_MULTICODEC_PREFIX):]
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), compressed)


def jwk_to_public_key(jwk: dict) -> ec.EllipticCurvePublicKey:
    """Convert a JWK dict to an EC public key object."""
    def _pad_b64(s: str) -> str:
        return s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
    x = int.from_bytes(base64.urlsafe_b64decode(_pad_b64(jwk["x"])), "big")
    y = int.from_bytes(base64.urlsafe_b64decode(_pad_b64(jwk["y"])), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


# ---------------------------------------------------------------------------
# JCS canonicalization (RFC 8785)
# ---------------------------------------------------------------------------

def jcs_canonicalize(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------------------
# VC DataIntegrityProof verification
# ---------------------------------------------------------------------------

def verify_data_integrity_proof(vc: dict, pub: ec.EllipticCurvePublicKey) -> bool:
    """Verify a W3C VC DataIntegrityProof (ecdsa-jcs-2019)."""
    proof = vc.get("proof")
    if not proof or proof.get("type") != "DataIntegrityProof":
        return False

    proof_value = proof.get("proofValue", "")
    sig_bytes = multibase_b58btc_decode(proof_value)

    vc_no_proof = {k: v for k, v in vc.items() if k != "proof"}
    vc_hash = hashlib.sha256(jcs_canonicalize(vc_no_proof).encode("utf-8")).digest()

    proof_options = {k: v for k, v in proof.items() if k != "proofValue"}
    options_hash = hashlib.sha256(jcs_canonicalize(proof_options).encode("utf-8")).digest()

    combined = options_hash + vc_hash
    try:
        pub.verify(sig_bytes, combined, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# JAdES JWS verification
# ---------------------------------------------------------------------------

def verify_jades_jws(jws_compact: str, pub: ec.EllipticCurvePublicKey) -> bool:
    """Verify a JAdES compact JWS (ES256)."""
    parts = jws_compact.split(".")
    if len(parts) != 3:
        return False

    header_b64, payload_b64, sig_b64 = parts

    def _pad(s: str) -> str:
        return s + "=" * (4 - len(s) % 4) if len(s) % 4 else s

    raw_sig = base64.urlsafe_b64decode(_pad(sig_b64))
    if len(raw_sig) != 64:
        return False

    r = int.from_bytes(raw_sig[:32], "big")
    s_val = int.from_bytes(raw_sig[32:], "big")
    der_sig = encode_dss_signature(r, s_val)

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        pub.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Merkle proof verification
# ---------------------------------------------------------------------------

def verify_merkle_inclusion(leaf_hash: str, proof_path: List[dict], root: str) -> bool:
    """Verify a Merkle inclusion proof (RFC 6962 domain-separated nodes)."""
    _NODE_PREFIX = b"\x01"
    if not proof_path:
        return leaf_hash == root
    current = bytes.fromhex(leaf_hash)
    for step in proof_path:
        sibling = bytes.fromhex(step["hash"])
        if step.get("position") == "left":
            current = hashlib.sha256(_NODE_PREFIX + sibling + current).digest()
        else:
            current = hashlib.sha256(_NODE_PREFIX + current + sibling).digest()
    return current.hex() == root


# ---------------------------------------------------------------------------
# Extract proof data from PDF or HTML
# ---------------------------------------------------------------------------

def _extract_bundle_from_html_bytes(html_bytes: bytes) -> Optional[dict]:
    """Parse <script id="proof-bundle"> from proof HTML bytes."""
    try:
        html_text = html_bytes.decode("utf-8", errors="replace")
        m = re.search(
            r'<script\s+type="application/json"\s+id="proof-bundle">(.*?)</script>',
            html_text,
            re.DOTALL,
        )
        if m:
            return json.loads(m.group(1).strip())
    except Exception:
        pass
    return None


def extract_from_pdf(filepath: str) -> Optional[dict]:
    """Extract proof bundle from a signed PDF.

    Requires ``PyMuPDF`` (install with ``pip install signforge-verify[pdf]``).
    """
    try:
        import fitz  # type: ignore[import-untyped]
    except ImportError:
        print("WARNING: PyMuPDF (fitz) not installed. Install with: pip install signforge-verify[pdf]")
        return None

    doc = fitz.open(filepath)
    names = doc.embfile_names()

    # Bundle format (signforge_proof.json)
    if "signforge_proof.json" in names:
        raw = doc.embfile_get("signforge_proof.json")
        doc.close()
        return json.loads(raw)

    # Consolidated format: extract from proof HTML
    if "signforge_proof.html" in names:
        html_raw = doc.embfile_get("signforge_proof.html")
        doc.close()
        bundle = _extract_bundle_from_html_bytes(html_raw)
        if bundle:
            return bundle
        return None

    # Legacy format: reconstruct bundle from separate files
    bundle: Dict[str, Any] = {"formatVersion": "1.0", "type": "SignForgeProofBundle"}
    if "signforge_verification.json" in names:
        bundle["verification"] = json.loads(doc.embfile_get("signforge_verification.json"))
    if "signforge_receipt.vc.json" in names:
        bundle["vc"] = json.loads(doc.embfile_get("signforge_receipt.vc.json"))
    if "signforge_keys.json" in names:
        bundle["keys"] = json.loads(doc.embfile_get("signforge_keys.json"))
    doc.close()
    return bundle if "vc" in bundle else None


def extract_from_html(filepath: str) -> Optional[dict]:
    """Extract proof data from a .proof.html file."""
    with open(filepath, "r", encoding="utf-8") as f:
        html = f.read()

    # Try consolidated proof-bundle block first
    bundle_match = re.search(
        r'<script\s+type="application/json"\s+id="proof-bundle">(.*?)</script>',
        html,
        re.DOTALL,
    )
    if bundle_match:
        try:
            bundle = json.loads(bundle_match.group(1).strip())
            if bundle.get("vc"):
                return bundle
        except json.JSONDecodeError:
            pass

    # Fall back to individual per-block extraction
    bundle = {"formatVersion": "1.0", "type": "SignForgeProofBundle"}
    pattern = r'<script\s+type="application/json"\s+id="(proof-[^"]+)">(.*?)</script>'
    for match in re.finditer(pattern, html, re.DOTALL):
        block_id, content = match.group(1), match.group(2).strip()
        try:
            data = json.loads(content)
            if block_id == "proof-vc":
                bundle["vc"] = data
            elif block_id == "proof-keys":
                bundle["keys"] = data
            elif block_id == "proof-merkle":
                bundle["transparency"] = data
            elif block_id == "proof-timestamp":
                bundle["timestamp"] = data
            elif block_id == "proof-did-snapshot":
                bundle["didSnapshot"] = data
            elif block_id == "proof-signer-identities":
                bundle["signerIdentities"] = data
            elif block_id == "proof-metadata":
                bundle["verification"] = data
        except json.JSONDecodeError:
            pass

    return bundle if "vc" in bundle else None


# ---------------------------------------------------------------------------
# Main verification
# ---------------------------------------------------------------------------

def verify(filepath: str) -> dict:
    """Run all verification checks on a SignForge document.

    Args:
        filepath: Path to a signed PDF or .proof.html file.

    Returns:
        A dict with ``valid`` (bool), ``checks`` (dict), and ``file`` (str).
    """
    results: Dict[str, Any] = {
        "file": filepath,
        "checks": {},
        "valid": False,
    }

    # Extract proof data
    if filepath.endswith(".pdf"):
        bundle = extract_from_pdf(filepath)
    elif filepath.endswith(".html") or filepath.endswith(".proof.html"):
        bundle = extract_from_html(filepath)
    else:
        return results

    if not bundle:
        return results

    results["formatVersion"] = bundle.get("formatVersion", "unknown")

    # Get public key
    keys = bundle.get("keys", {})
    issuer_jwk = keys.get("issuer", {}).get("publicKeyJwk")
    pub = None
    if issuer_jwk:
        try:
            pub = jwk_to_public_key(issuer_jwk)
            results["checks"]["public_key"] = {"status": "found", "source": "embedded_keys"}
        except Exception as e:
            results["checks"]["public_key"] = {"status": "error", "detail": str(e)}

    # Check 1: VC DataIntegrityProof
    vc = bundle.get("vc")
    if vc and pub:
        valid = verify_data_integrity_proof(vc, pub)
        results["checks"]["vc_signature"] = {
            "status": "pass" if valid else "FAIL",
            "detail": "ECDSA P-256 DataIntegrityProof verified" if valid else "Signature invalid — document may be tampered",
        }
    elif vc:
        results["checks"]["vc_signature"] = {"status": "skip", "detail": "No public key available"}
    else:
        results["checks"]["vc_signature"] = {"status": "skip", "detail": "No VC found"}

    # Check 2: JAdES JWS
    jades = bundle.get("jades")
    if jades and pub:
        valid = verify_jades_jws(jades, pub)
        results["checks"]["jades_jws"] = {
            "status": "pass" if valid else "FAIL",
            "detail": "ES256 JAdES JWS verified" if valid else "JWS signature invalid",
        }
    elif jades:
        results["checks"]["jades_jws"] = {"status": "skip", "detail": "No public key"}

    # Check 3: Merkle transparency proof
    tp = bundle.get("transparency")
    if tp and tp.get("merkle_proof") and tp.get("signed_tree_head"):
        try:
            sth = tp["signed_tree_head"]
            leaf = tp.get("leaf_hash", "")
            proof_path = tp["merkle_proof"]
            root = sth.get("root_hash") or sth.get("root", "")
            valid = verify_merkle_inclusion(leaf, proof_path, root)
            tree_size = sth.get("tree_size") or sth.get("size", "?")
            results["checks"]["merkle_proof"] = {
                "status": "pass" if valid else "FAIL",
                "detail": f"Merkle inclusion verified (tree size: {tree_size})" if valid else "Merkle proof invalid",
            }
        except Exception as e:
            results["checks"]["merkle_proof"] = {"status": "error", "detail": str(e)}
    else:
        results["checks"]["merkle_proof"] = {"status": "skip", "detail": "No transparency proof"}

    # Check 4: RFC 3161 timestamp
    ts = bundle.get("timestamp")
    if ts:
        tsa = ts.get("tsa") or ts.get("tsa_name", "unknown")
        signing_time = ts.get("signingTime") or ts.get("signing_time", "unknown")
        results["checks"]["timestamp"] = {
            "status": "present",
            "tsa": tsa,
            "signingTime": signing_time,
            "detail": f"RFC 3161 timestamp from {tsa} at {signing_time}",
        }
    else:
        results["checks"]["timestamp"] = {"status": "absent", "detail": "No timestamp"}

    # Check 5: Signer identities
    signer_ids = bundle.get("signerIdentities", [])
    if signer_ids and pub:
        all_valid = True
        for sid in signer_ids:
            if not verify_data_integrity_proof(sid, pub):
                all_valid = False
                break
        results["checks"]["signer_identities"] = {
            "status": "pass" if all_valid else "FAIL",
            "count": len(signer_ids),
            "detail": f"{len(signer_ids)} signer identity VC(s) verified" if all_valid else "Signer identity VC signature invalid",
        }
    elif signer_ids:
        results["checks"]["signer_identities"] = {"status": "skip", "detail": "No public key"}

    # Check 6: DID snapshot
    did = bundle.get("didSnapshot")
    if did:
        results["checks"]["did_snapshot"] = {
            "status": "present",
            "capturedAt": did.get("capturedAt"),
            "detail": f"DID document captured at {did.get('capturedAt', 'unknown')}",
        }

    # Overall verdict
    check_statuses = [c.get("status") for c in results["checks"].values()]
    results["valid"] = "FAIL" not in check_statuses and "pass" in check_statuses

    return results
