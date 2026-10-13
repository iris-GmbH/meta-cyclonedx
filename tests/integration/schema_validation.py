# SPDX-License-Identifier: MIT
"""CycloneDX schema validation against the vendored 1.7 JSON schema.

This module is the only place the repository references the `jsonschema`
library — a deliberate integration-layer-only dependency (see
docs/testing.md). The conftest fixture imports it lazily, so unit tests
never require it; when it is missing they skip with a hint instead.

The schema set lives in ``vendor/cyclonedx/`` with its provenance and
license attribution; no network access and no third-party library schema
defaults are involved.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import referencing.jsonschema
from referencing import Registry, Resource

#: Vendored schema directory (see the README there for the pin).
SCHEMA_DIR = Path(__file__).resolve().parent / "vendor" / "cyclonedx"

#: The specification version the harness validates against, matching the
#: layer's default `CYCLONEDX_SPEC_VERSION`.
SPEC_VERSION = "1.7"


def bom_validator() -> jsonschema.Draft7Validator:
    """Draft-7 validator over the vendored CycloneDX 1.7 schema set."""
    #: The bom schema $refs spdx.schema.json and jsf-0.82.schema.json.
    names = (f"bom-{SPEC_VERSION}.schema.json",
             "spdx.schema.json", "jsf-0.82.schema.json")
    documents = {
        path.as_uri(): json.loads(path.read_text())
        for path in ((SCHEMA_DIR / name).resolve() for name in names)
    }
    registry = Registry().with_resources(
        (uri, Resource.from_contents(
            contents, default_specification=referencing.jsonschema.DRAFT7))
        for uri, contents in documents.items()
    )
    bom_uri = (SCHEMA_DIR / names[0]).resolve().as_uri()
    return jsonschema.Draft7Validator(documents[bom_uri], registry=registry)


def describe_errors(errors, limit: int = 5) -> str:
    """First *limit* violations as compact `json-pointer: message` lines."""
    ordered = sorted(errors, key=lambda error: list(error.absolute_path))
    lines = []
    for index, error in enumerate(ordered):
        if index >= limit:
            lines.append(f"... {len(ordered) - index} more")
            break
        pointer = "/".join(str(part) for part in error.absolute_path)
        lines.append(f"/{pointer}: {error.message[:200]}")
    return "\n".join(lines) if lines else "(none)"
