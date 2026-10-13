<!-- SPDX-License-Identifier: MIT -->
<!-- SPDX-FileCopyrightText: meta-cyclonedx contributors -->

# Vendored CycloneDX 1.7 JSON schemas

Schema files used by the integration layer's deployed-document validation
(`tests/integration/test_deployed_artifact_oracle.py`). They are vendored so
schema validation needs neither network access nor a schema bundled by a
third-party library's defaults — see the acceptance-harness spec, "Schema
validation".

| File | Role |
| --- | --- |
| `bom-1.7.schema.json` | The CycloneDX 1.7 JSON schema (validates both the SBOM and the VEX document) |
| `spdx.schema.json` | Transitive `$ref` of `bom-1.7.schema.json` (SPDX license identifiers) |
| `jsf-0.82.schema.json` | Transitive `$ref` of `bom-1.7.schema.json` (JSON Schema Form) |

## Provenance and license

All three schemas come unmodified from the CycloneDX specification
repository <https://github.com/CycloneDX/specification>, directory `schema/`,
pinned at commit
[`0bd48c88d1b1877c7a3536252e06893850763190`](https://github.com/CycloneDX/specification/commit/0bd48c88d1b1877c7a3536252e06893850763190)
(2026-02-25, newest revision of `bom-1.7.schema.json`).

The schemas are licensed under the Apache License, Version 2.0 — the full
text is in [`LICENSE`](LICENSE), the specification repository's license file.
The schema files themselves carry `"license": [{ "id": "Apache-2.0" }]`
declarations. This repository's own MIT license applies only to the
harness code around them.

Refresh the pin by re-downloading the three files from a newer
`schema/` revision and updating the commit above.
