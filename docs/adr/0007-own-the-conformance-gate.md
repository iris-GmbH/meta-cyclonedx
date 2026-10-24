---
status: superseded by ADR-0011
---

# Own the conformance gate

Strict validation will use the official pinned CycloneDX schema and a project-owned conformance matrix covering every TR-03183-2 and BSI-taxonomy requirement. Community validators such as `sbomqs` may run as differential CI checks but are not authoritative gates, because BSI publishes no official validator and third-party mappings are incomplete or inconsistent with the taxonomy.
