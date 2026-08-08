#!/usr/bin/env python3
"""OpenVEX document gate (#1092).

Validates `security/vex/openvex.json` against the parts of the OpenVEX spec a
consumer relies on, so a malformed edit fails a pull request instead of
shipping with a release and being discovered by whoever tries to join it to the
SBOM.

What it refuses, and why each one matters to a consumer:

* a missing or unparsable document, or one whose `@context` is not an OpenVEX
  namespace - a consumer keys its parser off that field;
* a missing or wrongly typed top-level field (`@id`, `author`, `timestamp`,
  `version`, `statements`);
* a statement without a vulnerability, without products, or without a status;
* a status outside the OpenVEX enum, a `not_affected` statement whose
  justification is free text rather than an enum member, and a `not_affected`
  statement with no `impact_statement` for a human to read;
* a product identifier that is absent from the SBOM, when an SBOM is given.

Fail-closed: anything it cannot read is an error, not a pass. A document with
zero statements is valid and is the correct state while nothing is triaged as
not-exploitable - the file has to exist from day one for the release legs and
the consumers that join it to the SBOM.

Usage: check-vex.py <openvex.json> [<cyclonedx-sbom.json>]
"""

import json
import sys
from pathlib import Path

STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}

# OpenVEX v0.2.0 justification enum. A justification outside it is not
# machine-readable, which is the whole point of carrying one.
JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}

REQUIRED_TOP_LEVEL = {
    "@context": str,
    "@id": str,
    "author": str,
    "timestamp": str,
    "version": int,
    "statements": list,
}


def fail(message):
    print(f"::error::{message}", file=sys.stderr)
    sys.exit(1)


def sbom_identifiers(path):
    """Every purl and bom-ref a CycloneDX document offers as a product identifier."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        fail(f"SBOM {path} could not be read: {error}")

    identifiers = set()
    for component in document.get("components", []):
        for key in ("purl", "bom-ref"):
            value = component.get(key)
            if isinstance(value, str) and value:
                identifiers.add(value)

    metadata_component = document.get("metadata", {}).get("component", {})
    for key in ("purl", "bom-ref"):
        value = metadata_component.get(key)
        if isinstance(value, str) and value:
            identifiers.add(value)

    if not identifiers:
        fail(f"SBOM {path} lists no purl or bom-ref, so no product could be checked against it")

    return identifiers


def product_ids(statement):
    """The identifiers a statement claims, across the 0.2.0 and legacy shapes."""
    identifiers = []
    for product in statement.get("products", []):
        if isinstance(product, str):
            identifiers.append(product)
        elif isinstance(product, dict):
            if isinstance(product.get("@id"), str):
                identifiers.append(product["@id"])
            for name, value in product.get("identifiers", {}).items():
                del name
                if isinstance(value, str):
                    identifiers.append(value)

    return identifiers


def check_statement(index, statement, known_identifiers):
    where = f"statement {index}"
    if not isinstance(statement, dict):
        fail(f"{where} is not an object")

    if not statement.get("vulnerability"):
        fail(f"{where} names no vulnerability")

    identifiers = product_ids(statement)
    if not identifiers:
        fail(f"{where} names no product")

    status = statement.get("status")
    if status not in STATUSES:
        fail(f"{where} has status {status!r}, which is outside the OpenVEX enum {sorted(STATUSES)}")

    if status == "not_affected":
        justification = statement.get("justification")
        if justification not in JUSTIFICATIONS:
            fail(
                f"{where} is not_affected with justification {justification!r}, which is not an OpenVEX "
                f"enum member: {sorted(JUSTIFICATIONS)}"
            )

        if not statement.get("impact_statement"):
            fail(f"{where} is not_affected but carries no impact_statement for a reader")

    if known_identifiers is not None:
        for identifier in identifiers:
            if identifier not in known_identifiers:
                fail(f"{where} names product {identifier!r}, which is in no component of the SBOM")


def main(argv):
    if not 2 <= len(argv) <= 3:
        print(__doc__, file=sys.stderr)
        return 2

    path = argv[1]
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        fail(f"VEX document {path} could not be read: {error}")

    if not isinstance(document, dict):
        fail(f"VEX document {path} is not an object")

    for field, expected in REQUIRED_TOP_LEVEL.items():
        if field not in document:
            fail(f"VEX document {path} has no {field}")

        # bool is an int in Python, and a boolean version is not a version.
        if not isinstance(document[field], expected) or isinstance(document[field], bool):
            fail(f"VEX document {path}: {field} is {type(document[field]).__name__}, expected {expected.__name__}")

    if not document["@context"].startswith("https://openvex.dev/ns"):
        fail(f"VEX document {path}: @context {document['@context']!r} is not an OpenVEX namespace")

    known_identifiers = sbom_identifiers(argv[2]) if len(argv) == 3 else None

    for index, statement in enumerate(document["statements"]):
        check_statement(index, statement, known_identifiers)

    scope = "against the SBOM" if known_identifiers else "structurally (no SBOM given)"
    print(f"ok: {path} is a valid OpenVEX document with {len(document['statements'])} statement(s), checked {scope}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
