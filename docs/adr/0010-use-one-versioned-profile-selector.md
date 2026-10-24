---
status: superseded by ADR-0011
---

# Use one versioned profile selector

A single `CYCLONEDX_PROFILE` value will select both the exact conformance baseline and its assurance tier. Independent version and strictness variables, and an unversioned floating profile, are rejected because they permit unsupported combinations and nondeterministic semantics. A conformance value is exposed only after its complete behavior exists; no placeholder profile is shipped.
