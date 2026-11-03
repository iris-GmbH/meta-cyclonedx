# Retire CycloneDX 1.4 on release branches

The renderer supports CycloneDX 1.6 and 1.7 only, so the backport (ADR-0013) removes the 1.4 acceptance the release branches had reinstated: scarthgap flips its `CYCLONEDX_SPEC_VERSION` default from 1.4 to 1.6, and explicit `1.4` configurations now fail at build time on all three branches. CycloneDX 1.4 predates the ECMA-424 standardization, which is built on the 1.6 line, so aligning the maintained branches with the standardized family is the point rather than a cost. Backport commits carry `+semver: breaking`.

## Consequences

- scarthgap's README documents the default flip, the ECMA-424 argument, and the escape hatch: users who require 1.4 pin meta-cyclonedx to the pre-backport commit.
- blacksail and wrynose keep their 1.6 defaults; their READMEs carry the short variant — 1.4 was accepted before the backport and is not anymore, pin if mandatory.
