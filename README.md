# signforge-verify

Verify [SignForge](https://signforge.io)-signed documents offline. No account needed, no internet needed for cryptographic verification.

[![PyPI version](https://img.shields.io/pypi/v/signforge-verify)](https://pypi.org/project/signforge-verify/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/signforge-verify)](https://pypi.org/project/signforge-verify/)

## Why Independent Verification Matters

Most e-signature platforms lock your proof inside their ecosystem. If the vendor disappears, your proof disappears. [SignForge](https://signforge.io) takes a different approach: every signed document contains a complete, self-verifying cryptographic proof bundle using open standards.

This package lets **anyone** verify a SignForge-signed document -- developers, auditors, legal teams, or even AI agents -- without needing a SignForge account or any internet connection.

> **"Don't trust us. Verify yourself."** -- [SignForge Trust Architecture](https://signforge.io/docs/verification-architecture)

## What This Verifies

Every [SignForge](https://signforge.io)-signed document contains a cryptographic proof bundle. This package verifies:

- **W3C Verifiable Credential** -- ECDSA P-256 DataIntegrityProof ([ecdsa-jcs-2019](https://www.w3.org/TR/vc-di-ecdsa/))
- **JAdES JWS** -- EU-standard ES256 compact signature ([ETSI TS 119 182](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf))
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

# JSON output (for scripting / CI pipelines)
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

[SignForge](https://signforge.io) embeds a W3C Verifiable Credential and supporting cryptographic proofs inside every signed document. This verifier:

1. Extracts the proof bundle from the document
2. Imports the embedded ECDSA P-256 public key (JWK format)
3. Verifies the VC signature using JCS canonicalization (RFC 8785)
4. Verifies the JAdES JWS signature
5. Verifies Merkle inclusion against the transparency log tree head
6. Reports timestamp and identity credential status

All verification happens locally -- no network requests, no SignForge servers involved.

Learn more:
- [Verification Architecture](https://signforge.io/docs/verification-architecture) -- technical deep-dive for developers
- [Proof Format Specification v1.0](https://signforge.io/docs/proof-format) -- full bundle schema reference
- [Online Verifier](https://signforge.io/verify) -- verify documents in your browser

## Use Cases

- **Developers** -- integrate document verification into your app or CI pipeline
- **Legal & Compliance** -- independently audit e-signature validity
- **AI Agents** -- let ChatGPT or Claude verify documents via tool use
- **Archival** -- confirm document integrity years after signing, even if SignForge no longer exists

## Related

- [SignForge](https://signforge.io) -- Free e-signature platform. Sign documents in seconds.
- [SignForge Verify (online)](https://signforge.io/verify) -- Verify documents in your browser
- [@signforge/verify (npm)](https://www.npmjs.com/package/@signforge/verify) -- JavaScript/TypeScript verification package
- [Sign PDF Online Free](https://signforge.io/sign-pdf-online-free) -- Sign PDFs without creating an account

## License

MIT
