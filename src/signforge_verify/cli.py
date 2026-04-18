"""SignForge Standalone Proof Verifier — CLI

Usage::

    signforge-verify document-signed.pdf
    signforge-verify document.proof.html --json
"""

import argparse
import json
import sys

from signforge_verify.verifier import verify


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SignForge Standalone Proof Verifier",
        epilog="Verifies signed PDFs and .proof.html files. MIT License — https://signforge.io/verify",
    )
    parser.add_argument("file", help="Path to signed PDF or .proof.html file")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    results = verify(args.file)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"  SignForge Proof Verifier")
        print(f"{'='*60}")
        print(f"  File: {results['file']}")
        print(f"  Format: v{results.get('formatVersion', '?')}")
        print()

        for name, check in results.get("checks", {}).items():
            status = check.get("status", "?")
            icon = {
                "pass": "\u2713",
                "FAIL": "\u2717",
                "present": "\u2022",
                "skip": "\u25CB",
                "found": "\u2022",
                "absent": "\u25CB",
            }.get(status, "?")
            label = name.replace("_", " ").title()
            print(f"  {icon}  {label}: {check.get('detail', status)}")

        print()
        if results["valid"]:
            print(f"  \u2705 DOCUMENT VERIFIED")
        else:
            if "FAIL" in [c.get("status") for c in results.get("checks", {}).values()]:
                print(f"  \u274c VERIFICATION FAILED \u2014 document may be tampered")
            else:
                print(f"  \u26a0\ufe0f  PARTIAL \u2014 some checks could not be performed")
        print(f"{'='*60}\n")

    sys.exit(0 if results["valid"] else 1)


if __name__ == "__main__":
    main()
