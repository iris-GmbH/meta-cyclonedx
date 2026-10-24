---
status: superseded by ADR-0011
---

# Stage TR-03183 assurance

meta-cyclonedx will separate an alignment preset from a conformance profile. The alignment preset applies available mappings and checks without claiming conformance; the conformance profile will fail closed against an exact, pinned baseline and target a build-time delivery-item SBOM. This preserves useful partial output without presenting it as proof of CRA or TR-03183-2 conformity.
