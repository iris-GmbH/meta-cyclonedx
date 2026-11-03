# Backport the renderer seam to release branches

The renderer extraction (commit 1cb76e9, implementing ADR-0008) is tagged "Development branch only; not for backport", yet we decided to backport it to the blacksail, wrynose, and scarthgap release branches anyway. Release branches are maintained for multiple years; keeping the seam on the development branch only would let the inline BitBake document assembly drift per branch, so every future main-branch change would conflict on cherry-pick, and the renderer's behavioral test suite would never protect release users.

## Considered Options

- Leave release branches on the inline class as the commit instructs — rejected: maximizes exactly the drift and conflict cost the seam was extracted to remove, and forfeits testability on the branches with the longest support horizon.
- Port the renderer to some branches only — rejected: a half-ported seam is the worst of both worlds, doubling the backport surface (port once, twice, or three times) while still diverging.

## Consequences

- The backport is a `git cherry-pick -x` per branch with one PR per branch; branch-local configuration (output naming and deployment defaults, spec-version defaults) wins over development-branch context in conflict resolution — no user-visible output paths or names change.
- The seam's signature tracking (`[file-checksums]`) was verified supported unchanged in BitBake 2.8 through current, so no per-branch compatibility fallback is needed.
- scarthgap gains the renderer with its two generation paths wired; its absent sbom-cve-check feature stays absent, and the renderer's unused merge code is dead weight accepted for invariance (ADR-0014).
- Backporting makes the 1.4 retirement visible on release branches; see ADR-0015.
