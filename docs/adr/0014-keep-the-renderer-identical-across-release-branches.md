# Keep the renderer identical across release branches

`lib/meta_cyclonedx.py` stays byte-identical on the development branch and every release branch; all release-specific divergence — BitBake version differences, output naming defaults, features a branch does not offer — lives in the BitBake adapter. The renderer consumes normalized facts and is stdlib-only, so adapter-side absorption is always available; allowing per-branch renderer edits would fork the module silently, break the portability of its behavioral test suite, and reinstate the drift that motivated ADR-0013.

## Consequences

- Renderer behavior that differs between branches is a defect signal, not a configuration: escalate, fix on the development branch, and backport the module again — never edit it on a release branch.
- Release branches may carry renderer code paths that no adapter on that branch invokes (e.g. sbom-cve-check merging on scarthgap); dead-but-identical beats divergent-but-lean.
