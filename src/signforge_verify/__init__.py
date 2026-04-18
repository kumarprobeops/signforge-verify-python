"""SignForge Standalone Proof Verifier — Python

Verifies SignForge-signed PDFs and .proof.html files offline.
Uses only Python stdlib + cryptography (PyMuPDF optional for PDF extraction).

Usage::

    from signforge_verify import verify
    result = verify("document-signed.pdf")
    print(result["valid"])  # True

MIT License — https://signforge.io/verify
"""

from signforge_verify.verifier import (
    verify,
    extract_from_pdf,
    extract_from_html,
    verify_data_integrity_proof,
    verify_jades_jws,
    verify_merkle_inclusion,
)

__version__ = "1.0.0"
__all__ = [
    "verify",
    "extract_from_pdf",
    "extract_from_html",
    "verify_data_integrity_proof",
    "verify_jades_jws",
    "verify_merkle_inclusion",
]
