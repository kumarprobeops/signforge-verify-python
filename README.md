# signforge-verify

Verify [SignForge](https://signforge.io)-signed documents offline. No account needed, no internet needed for cryptographic verification.

[![PyPI version](https://img.shields.io/pypi/v/signforge-verify)](https://pypi.org/project/signforge-verify/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/signforge-verify)](https://pypi.org/project/signforge-verify/)

## What This Verifies

Every SignForge-signed document contains a cryptographic proof bundle. This package verifies:

- **W3C Verifiable Credential** -- ECDSA P-256 DataIntegrityProof (ecdsa-jcs-2019)
- **JAdES JWS** -- EU-standard ES256 compact signature
- **Merkle transparency proof** -- RFC 6962 inclusion proof against a signed tree head
- **RFC 3161 timestamp** -- DigiCert TSA timestamp presence
- **Signer identity credentials** -- per-signer W3C VCs
- **DID:web platform identity** -- DID document snapshot

## Install

```bash
pip install signforge-verify
```

For PDF verification (optional):
```bash
pip install signforge-verify[pdf]
```

**1 dependency:** `cryptography` (widely used, well-maintained).
PyMuPDF is optional -- only needed to extract proof from PDFs.

## Quick Start

```python
from signforge_verify import verify

# Verify a signed PDF
result = verify("document-signed.pdf")
print(result["valid"])  # True

# Verify a .proof.html file
result = verify("document.proof.html")
print(result["checks"]["vc_signature"]["status"])  # "pass"
```

## CLI Usage

```bash
# Verify a signed PDF
signforge-verify document-signed.pdf

# Verify a proof document
signforge-verify document.proof.html

# JSON output
signforge-verify document-signed.pdf --json
```

Example output:
```
============================================================
  SignForge Proof Verifier
============================================================
  File: document-signed.pdf
  Format: v1.0

  ✓  Vc Signature: ECDSA P-256 DataIntegrityProof verified
  ✓  Jades Jws: ES256 JAdES JWS verified
  ✓  Merkle Proof: Merkle inclusion verified (tree size: 23)
  •  Timestamp: RFC 3161 timestamp from DigiCert at 2026-04-15T11:56:56Z
  ✓  Signer Identities: 1 signer identity VC(s) verified
  •  Did Snapshot: DID document captured at 2026-04-15T11:56:56Z

  ✅ DOCUMENT VERIFIED
============================================================
```

## API Reference

### `verify(filepath) -> dict`

Run all verification checks on a signed PDF or .proof.html file.

Returns a dict with:
- `valid` (bool) -- overall verification result
- `checks` (dict) -- individual check results
- `file` (str) -- input file path
- `formatVersion` (str) -- proof format version

### `extract_from_pdf(filepath) -> dict | None`

Extract the proof bundle from a signed PDF. Requires PyMuPDF.

### `extract_from_html(filepath) -> dict | None`

Extract the proof bundle from a .proof.html file.

### `verify_data_integrity_proof(vc, pub) -> bool`

Verify a W3C VC DataIntegrityProof signature.

### `verify_jades_jws(jws_compact, pub) -> bool`

Verify a JAdES compact JWS (ES256).

### `verify_merkle_inclusion(leaf_hash, proof_path, root) -> bool`

Verify a Merkle inclusion proof (RFC 6962).

## How It Works

SignForge embeds a W3C Verifiable Credential and supporting cryptographic proofs inside every signed document. This verifier:

1. Extracts the proof bundle from the document
2. Imports the embedded ECDSA P-256 public key (JWK format)
3. Verifies the VC signature using JCS canonicalization (RFC 8785)
4. Verifies the JAdES JWS signature
5. Verifies Merkle inclusion against the transparency log tree head
6. Reports timestamp and identity credential status

All verification happens locally -- no network requests, no SignForge servers involved.

[Verification Architecture](https://signforge.io/docs/verification-architecture) | [Proof Format Spec](https://signforge.io/docs/proof-format)

## Related

- [SignForge](https://signforge.io) -- Free e-signature platform
- [@signforge/verify](https://www.npmjs.com/package/@signforge/verify) -- JavaScript/TypeScript verification package

## License

MIT
