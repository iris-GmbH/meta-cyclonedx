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
  `KAS_CONTAINER_ENGINE=podman|docker` to override the probe.
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
- **R2 — unchanged re-invocation**: every deployed artifact byte-identical;
  no real task reran (sstate served everything).
- **R3 — signature-source mutation**: one inert comment is inserted into
  the _signature-carrying generator source_ — the tracked file named by
  the `SIGNATURE_SOURCE` parameter in `tests/integration/kas_env.py`
  (the export class on pre-seam branches, the renderer module on
  post-seam ones). The documents must regenerate:
  serial numbers differ, the raw documents stay schema-valid, and with
  the volatile fields removed (document serials and the bom-refs derived
  from them, timestamps, layer git state — both in the `yocto:layer:*`
  properties and in layer reference URLs — and the build-`DATETIME`
  suffix of version strings; see `tests/integration/document_compare.py`)
  they compare equal to R1.
  Teardown reverts the comment byte-exactly and a follow-up invocation
  must restore the deployed CycloneDX artifacts byte-for-byte. (Image
  artifacts are exempt from that claim: any run that re-parses recipes
  regenerates BitBake's `DATETIME`, and the image files are named after
  it, so their dated names rotate through the mutation run.)
  On a workspace whose cache has seen the mutated hash before, BitBake
  may serve the mutated generation from sstate instead of regenerating
  it; `do_rootfs` reruns either way (it has no sstate), so the rerun
  observation accepts reran-or-restored for the deploy task.
- **R4 — graph isolation**: one trivial _unused_ recipe added to a
  dedicated fixture layer; artifacts stay byte-identical.
- **R5 — image content change**: one small harness-owned package
  (`harness-image-extra`, in the fixture layer, delivered through the
  `CORE_IMAGE_EXTRA_INSTALL` variable — set inside the build container
  via the kas wrapper's `--runtime-args` channel, since the wrapper
  forwards only a fixed host-environment whitelist) joins the install
  list; it must appear in the rootfs manifest and as a component with a
  dependency edge in the deployed SBOM.

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

If any BitBake task fails, the harness interrupts the build at once
(SIGINT to the build process group, so the container shuts down) and
fails with the build-log tail instead of waiting for in-flight tasks to
drain.

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
