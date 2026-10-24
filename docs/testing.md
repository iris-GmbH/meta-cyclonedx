# Integration test suite (kas acceptance build)

This suite is a maintainer workflow: external contributors are not expected
to run it. Default test runs stay unit-only, fast, and dependency-free.

The real end-to-end acceptance build, a `core-image-minimal` built through
the kas container wrapper with this layer's working tree mounted in place,
is selected explicitly:

```sh
pytest -m integration
```

Prerequisites:

- A working container runtime: Podman or Docker. `pytest` skips
  the whole layer with an install hint if none is found. Set
  `KAS_CONTAINER_ENGINE=podman|docker` to override the probe, or
  `KAS_CONTAINER_ENGINE=none` to select direct mode (see below) — the
  probe itself never selects direct mode implicitly.
- The kas tool arrives as the tag-pinned git submodule under `tools/kas`;
  the fixture initializes it automatically (`git submodule update --init
tools/kas`), and the wrapper's container-image version stays in
  lockstep with the pin; a missing-or-unfetchable checkout or a pin
  mismatch skips the matrix with the reason rather than erroring.
- Network access (upstream clones + source downloads).
- The `jsonschema` Python package, used only by the integration layer to
  validate the deployed documents against the CycloneDX 1.7 JSON schema
  vendored under `tests/integration/vendor/cyclonedx/` (attribution and
  pin in its README). Unit runs never import it; if it is missing, the
  schema-validation tests skip with an install hint, e.g.
  `sudo apt-get install python3-jsonschema` or
  `python3 -m pip install jsonschema`.

## Invocation modes

**Container mode** (the default, and what the probe always selects when
the override is unset) drives the build through the submodule's
`tools/kas/kas-container` wrapper, which runs kas inside the pinned kas
release container. **Direct mode** (`KAS_CONTAINER_ENGINE=none`) execs
the kas tool installed in the current environment — on the CI runners,
the runner Pod *is* that image (see the CI tiers below) — and never
nests a second container engine, privileged or otherwise. Its version
tie compares the executing kas's reported version against the submodule
pin; a mismatch skips the matrix with the reason, like every other
prerequisite gap. Mode selection is never inferred: byte-identity
claims must not hinge on what happens to be installed, so an unset
variable keeps container-mode behavior byte-for-byte.

Checkout, build directory, downloads, and sstate cache all live under the
single git-ignored `.integration/` directory, and `rm_work` caps the work
directories. Expect a few hours and ~25 GB disk (plus ~10 GB under
`.integration/`) for a cold first run on a 4-core machine; warm re-runs
finish in minutes. Deleting `.integration/` is a complete reset. On
worktrees stored on NFS the build directory is transparently placed on
NFS-safe storage under `${TMPDIR:-/var/tmp}`, kept reachable at
`.integration/build` via a symlink — BitBake refuses its `TMPDIR` on NFS.

In one session the acceptance matrix re-invokes that same build through
the kas wrapper and records every run against the same workspace:

- **R1 — cold build**: the full deployed-artifact oracle (schema
  validity, primary-component identity, known package, dependency and
  VEX reference integrity, image-metadata pair). The version's tie to a
  dated image artifact is enforced on the invocation that generated the
  documents; over cache-served documents it reports as a skip — byte
  identity of served artifacts is R2's claim.
  The image-metadata manifest and its SBOM/VEX are captured from
  `tmp/cyclonedx/image/<machine-arch>/<image-recipe>/` when the run
  completes. Both manifest-selected documents must match the deployed
  pair; the rootfs package-list manifest is a separate artifact.
- **R2 — unchanged re-invocation**: every deployed artifact byte-identical;
  no real task reran (sstate served everything).
- **R3 — signature-source mutation**: one inert comment is inserted into
  the _signature-carrying generator source_ — the tracked file named by
  the `SIGNATURE_SOURCE` parameter in `tests/integration/kas_env.py`
  (the export class on pre-seam branches, the renderer module on
  post-seam ones). The documents must regenerate:
  serial numbers differ, the raw documents stay schema-valid, and with
  the volatile fields normalized (timestamps, layer git state — both
  in the `yocto:layer:*` properties and layer reference URLs — and the
  build-`DATETIME` suffix of version strings), they compare equal to R1.
  Declared serial numbers and bom-refs are mapped to distinct stable
  identities across the SBOM/VEX pair, preserving dependency targets
  and cross-document references; dangling references are not masked.
  See `tests/integration/document_compare.py`.
  Teardown reverts the comment byte-exactly and a follow-up invocation
  must restore the deployed CycloneDX artifacts byte-for-byte. (Image
  artifacts are exempt from that claim: any run that re-parses recipes
  regenerates BitBake's `DATETIME`, and the image files are named after
  it, so their dated names rotate through the mutation run.)
  Pre-existing staged and unstaged generator edits are preserved; a
  clean checkout is not required.
  On a workspace whose cache has seen the mutated hash before, BitBake
  may serve the mutated generation from sstate instead of regenerating
  it; `do_rootfs` reruns either way (it has no sstate), so the rerun
  observation accepts reran-or-restored for the deploy task.
- **R4 — graph isolation**: one trivial _unused_ recipe added to a
  dedicated fixture layer; artifacts stay byte-identical.
- **R5 — image content change**: one small harness-owned package
  (`harness-image-extra`, in the fixture layer) joins the install list,
  delivered through the `CORE_IMAGE_EXTRA_INSTALL` variable — container
  mode sets it inside the build container via the kas wrapper's
  `--runtime-args` channel (the wrapper forwards only a fixed
  host-environment whitelist), direct mode passes it in the process
  environment, which the project config's `env:` block forwards; the
  claim is identical in both modes. It must appear in the rootfs
  manifest and as a component with a dependency edge in the deployed
  SBOM.

R2/R4 comparisons are byte-level; cross-regeneration comparisons (R3)
use the `canonicalize` helper and never claim byte-identity. The
graph-isolation fixture layer lives as a local (URL-less) repository
under `.integration/fixtures`, created by the fixture and removed on
teardown; a manual `kas build kas.yml` outside `pytest` needs that
directory to exist first. Cold run: expect the first invocation to
dominate the wall time (see the disk/time note above); every further
row of the matrix adds only minutes — except the R3 mutated run and
the R5 run, which reassemble the image rootfs and take a few minutes
each on a warm cache.

If any BitBake task fails, the harness interrupts the build process group
with SIGINT and reports the build-log tail. The five-minute shutdown
deadline starts when the failure is observed, not when the build starts;
remaining processes are killed with SIGKILL after that grace period.
Interrupting pytest uses the same cleanup, and a second interrupt skips
the grace period. The recorder reaps the child and joins its output reader
before returning or propagating an exception, so R3 restores its source
only after the build has stopped.

The committed `kas.yml` project configuration pins the _release
coordinates_: each upstream repo has a `branch:` (the release series,
which must match `LAYERSERIES_COMPAT` in `conf/layer.conf` of the
checked-out branch) and a `commit:` (the exact commit, so repeated runs
are bit-for-bit reproducible). Refresh `branch:` and `commit:` together when
rebasing the harness; backported variants of the harness must differ
only in those coordinates.

The run pulls shared build results from the Yocto Project's published
autobuilder sstate cache by default:

```sh
SSTATE_MIRRORS="file://.* http://sstate.yoctoproject.org/all/PATH;downloadfilename=PATH"
```

That default lives in `kas.yml`. A non-empty `SSTATE_MIRRORS` in your
shell environment overrides it for one run; to disable shared state
entirely, point it at an inert location, e.g.
`SSTATE_MIRRORS="file://.* file:///nonexistent/PATH;downloadfilename=PATH"` —
missing mirror objects are silently treated as misses.

The published objects are built for the generic QEMU machines of the
various Poky releases — this harness builds exactly one of them
(`qemux86-64`, `DISTRO=poky`), so it can benefit directly. Reuse is
hash-addressed, so the hit rate follows how close the branch sits to what
the autobuilder last published: sampled at ~40 % hits on `master` tip and
higher on release branches. A miss is harmless — the task simply builds
locally.

## CI tiers

Two GitHub Actions tiers carry these suites automatically (the decision
record is `docs/adr/0012-run-acceptance-ci-on-self-managed-runners.md`);
the workflow files are byte-identical between the fork and upstream, and
every repository difference lives in configuration.

- **Unit tier** — the dependency-free unit suite on GitHub-hosted
  runners across Python 3.11, 3.12 and 3.13, on every pull request and
  every merge to a supported branch (main, blacksail, wrynose,
  scarthgap). This is the pre-merge gate; contributors need no Yocto
  environment for their PR to get a verdict.
- **Acceptance tier** — the R1–R5 matrix in **direct mode**, on
  merge to a supported branch (path-filtered to layer and harness
  files), nightly against the default branch, or on dispatch against
  any ref. It is never triggered by pull requests: GitHub's security
  guidance for public repositories forbids routing fork-contributor
  code to self-managed machines, so acceptance is a merge-first event
  model. Every run publishes the deployed SBOM/VEX documents and the
  comparison summaries; a failed run also publishes the build-log tail;
  artifacts are retained 14 days. A cold build needs the disk and hours
  noted above — which is exactly why this tier cannot live on
  GitHub-hosted runners — and gets an 8-hour timeout so a cold
  mirror-miss build is a slow success, not a false red. The session
  starts cold (fresh runner Pod, reuse only from the published
  autobuilder sstate mirror); within one session the R2/R4
  re-invocations are warm as on a maintainer machine.

The runners are maintainer-provided and self-managed; this project's
instance is autoscaling Kubernetes jobs (actions-runner-controller scale
sets): ephemeral Pods, one job per Pod, never privileged, with ≥ 64 GB
node-local scratch. The runner Pod *is* the runner image — the kas
release image named by the `tools/kas` submodule pin, plus the Actions
runner binary, pytest, and jsonschema — built by the dispatch-only
`runner-image` workflow into the same repository's own package
namespace (`ghcr.io/<owner>/<repo>/kas-runner:<kas-version>-<runner-version>`),
so no cross-repository package trust is required and no nested container
engine ever appears. Shared warm-cache infrastructure (RWX PVC or
S3-backed sstate) is the documented upgrade path, not part of the setup.

### Enabling acceptance on a repository (rollout checklist)

Until a repository completes this list its acceptance runs appear with
everything skipped — inert by design, which is also what makes the
identical workflow file safe to merge upstream:

1. Register self-managed runners for the repository, labeled
   `self-hosted`, `Linux`, `X64` plus a dedicated project label, with
   Pods pulling the runner image from the repository's own package
   namespace (confirm the cluster can pull it; record any registry
   detour otherwise).
2. Set the repository Actions variable `ACCEPTANCE_RUNNER_LABELS` to
   the JSON array of labels, e.g.
   `["self-hosted", "Linux", "X64", "meta-cyclonedx"]` — unset means
   skipped, never queued.
3. Branch protection on main, blacksail, wrynose and scarthgap:
   require the three `unit (Python …)` checks before merge with admin
   enforcement, and require code-owner review for `.github/workflows/`
   (CODEOWNERS). Applied identically in both repositories.
4. Prove the tier on this repository: one dispatch-driven full-matrix
   run and one nightly, both green with downloadable artifacts.
