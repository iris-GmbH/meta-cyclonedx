# SPDX-License-Identifier: MIT
"""Container-runtime probing, kas workspace layout, and run mutations.

Helper for the integration fixtures and pure unit tests; importing this
module never triggers a build or a container.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

#: Repository root (the layer under test, a URL-less kas repository entry).
REPO_ROOT = Path(__file__).resolve().parents[2]

#: The one git-ignored, repo-local directory holding checkout, build
#: directory, downloads and sstate cache. Caches are partitioned per release
#: by the branch-per-release convention, not by versioning inside paths.
WORKSPACE = REPO_ROOT / ".integration"

#: Release coordinates shared between kas.yml and the assertions over its
#: output (kas.yml declares them once; keep them in sync when editing).
MACHINE = "qemux86-64"
TARGET = "core-image-minimal"
#: Deployed-artifact names the acceptance oracle asserts over, derived
#: from the release coordinates above. The harness fixes the recipe-name
#: export basename in kas.yml (`CYCLONEDX_EXPORT_BASENAME =
#: "${IMAGE_BASENAME}.cyclonedx"`), so the SBOM/VEX paths are stable across
#: runs; the manifest name follows OE-core's image-artifact-names default
#: `<image>-<machine><IMAGE_NAME_SUFFIX>.manifest`.
SBOM_NAME = f"{TARGET}.cyclonedx.bom.json"
VEX_NAME = f"{TARGET}.cyclonedx.vex.json"
MANIFEST_NAME = f"{TARGET}-{MACHINE}.rootfs.manifest"

#: Tag-pinned kas tool submodule (its wrapper script pins the container image).
KAS_DIR = REPO_ROOT / "tools" / "kas"
KAS_CONTAINER = KAS_DIR / "kas-container"

#: The fixture layer: an untracked, fixture-initialized local (URL-less)
#: repository in the integration workspace, listed in kas.yml; the
#: graph-isolation run adds one trivial unused recipe to it (R4). All
#: fixture code lives here; teardown removes the repository again.
FIXTURES_REPO = WORKSPACE / "fixtures"
FIXTURES_LAYER = FIXTURES_REPO / "meta-integration-fixtures"
FIXTURES_RECIPE = (
    FIXTURES_LAYER / "recipes-support" / "harness-unused" / "harness-unused_0.1.bb"
)

#: R3's mutation target: the *signature-carrying generator source* — the
#: tracked file whose content rides into the generation tasks' signatures.
#: On this pre-seam branch that is the export class itself: its
#: `export_cyclonedx` function is a codependency of the image's
#: do_rootfs (through ROOTFS_POSTUNINSTALL_COMMAND) and of
#: do_deploy_cyclonedx, so its source text is part of those tasks'
#: signatures. Post-seam branches set this to the renderer module instead
#: — the matrix code never hardcodes a path.
SIGNATURE_SOURCE = REPO_ROOT / "classes" / "cyclonedx-export.bbclass"

#: Where the mutation comment lands: immediately after this exact line,
#: one indent deeper. A comment at the end of the file is invisible to
#: BitBake's signature machinery; one *inside* the generator function
#: changes every signature that reaches it. None means append at the end
#: of the file — the correct placement for targets checksummed whole (a
#: post-seam renderer module wired in via file-checksums).
SIGNATURE_MUTATION_ANCHOR = "def export_cyclonedx(d):"

#: The inert comment the mutation-run (R3) inserts.
SIGNATURE_MUTATION_COMMENT = (
    "# acceptance harness R3: mutation of the signature-carrying source"
)

#: R5's image content change: a small harness-owned package added to the
#: image install list. The recipe lives in the fixture layer (untracked).
#: The install-list change rides CORE_IMAGE_EXTRA_INSTALL, which kas.yml
#: forwards into BitBake through its env: block — in container mode via
#: the wrapper's documented --runtime-args channel (only a fixed
#: whitelist of host variables reaches the build container, and the
#: wrapper rejects --preserve-env; see runtime_env_args), in direct mode
#: via the process environment (see kas_invocation). The value must
#: contain no whitespace: core-image.bbclass interpolates the variable
#: inside a whitespace-separated IMAGE_INSTALL assignment, and the
#: wrapper word-splits the runtime-args string. No tracked file is ever
#: touched; the delta is exactly one installed package.
IMAGE_EXTRA_RECIPE_NAME = "harness-image-extra"
FIXTURES_IMAGE_EXTRA_RECIPE = (
    FIXTURES_LAYER
    / "recipes-support"
    / IMAGE_EXTRA_RECIPE_NAME
    / f"{IMAGE_EXTRA_RECIPE_NAME}_0.1.bb"
)
IMAGE_EXTRA_INSTALL_ENV = {"CORE_IMAGE_EXTRA_INSTALL": IMAGE_EXTRA_RECIPE_NAME}

SKIP_HINT = (
    "no container runtime found: install Podman (https://podman.io, "
    "preferred) or Docker and re-run `pytest -m integration`; set "
    "KAS_CONTAINER_ENGINE=podman|docker to override the probe"
)


#: CycloneDX schema validation uses the `jsonschema` library — an
#: integration-layer-only dependency the unit suite never imports; the
#: schema itself is vendored under tests/integration/vendor/cyclonedx.
JSONSCHEMA_HINT = (
    "the `jsonschema` Python package is not installed: install it for the "
    "integration layer, e.g. `sudo apt-get install python3-jsonschema` or "
    "`python3 -m pip install jsonschema` (integration-only dependency, "
    "documented in docs/testing.md; unit runs never import it)"
)

#: The engine-override value selecting direct mode: the kas tool installed
#: in the current image runs the build, with no container engine and no
#: wrapper nesting (the CI runner Pod *is* the kas image). Direct mode is
#: never inferred — an unset override keeps the container-mode probe, so
#: byte-identity claims are never silently voided by mode drift.
KAS_DIRECT = "none"


def detect_container_runtime(which=shutil.which, get=None):
    """Return the container engine name to drive kas with, or None.

    The ``KAS_CONTAINER_ENGINE`` environment variable (the engine override
    documented by the kas wrapper itself) is honored as-is; the explicit
    value ``none`` selects direct mode (*KAS_DIRECT*) without any probing.
    Otherwise Podman is preferred and Docker accepted. ``which``/``get``
    are injection points for testing.
    """
    get = os.environ.get if get is None else get
    override = get("KAS_CONTAINER_ENGINE")
    if override is not None:
        if override == KAS_DIRECT:
            return KAS_DIRECT
        return override if which(override) else None
    for name in ("podman", "docker"):
        if which(name):
            return name
    return None


def _git(*args, cwd=REPO_ROOT):
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout


def ensure_kas_submodule():
    """Initialize the kas submodule automatically if it is not checked out."""
    status = _git("submodule", "status", "--", "tools/kas")
    if status.startswith("-"):
        _git("submodule", "update", "--init", "--", "tools/kas")
    if not KAS_CONTAINER.is_file():
        raise RuntimeError(
            f"{KAS_CONTAINER} is missing; `git submodule update --init "
            "tools/kas` did not produce a checkout"
        )


def _pin_tag():
    return _git("describe", "--tags", "--exact-match", cwd=KAS_DIR).strip()


def check_kas_pin(running_version=None, describe=None):
    """Verify the executing kas's version tie to the submodule pin.

    Returns ``(tag, version)``. Raises if the submodule is not checked
    out at a release tag or the versions diverged — the skip-with-reason
    philosophy of the matrix: acceptance evidence never silently comes
    from the wrong userland.

    Container mode (no *running_version*): the wrapper's container-image
    pin must match the submodule tag — the wrapper derives its default
    image tag from the ``KAS_CONTAINER_SCRIPT_VERSION`` baked into the
    tagged script, so tag and script version staying equal is what keeps
    the container image in lockstep with the pin.

    Direct mode (*running_version*: what the executing kas tool reports
    about itself, see direct_kas_version): v-normalized, it must equal
    the submodule's release tag — the runner image is built FROM the
    pinned kas release, so a drift here means the wrong image answered.
    """
    tag = (_pin_tag if describe is None else describe)()
    if running_version is not None:
        version = running_version.lstrip("v")
        if tag.lstrip("v") != version:
            raise RuntimeError(
                f"the executing kas reports version {running_version!r}, "
                f"but the submodule pin is tag {tag!r}; the kas running the "
                "matrix and the pinned kas release must stay in lockstep"
            )
        return tag, version
    script_version = re.search(
        r'^KAS_CONTAINER_SCRIPT_VERSION="([^"]+)"',
        KAS_CONTAINER.read_text(),
        re.MULTILINE,
    )
    if script_version is None:
        raise RuntimeError(
            f"{KAS_CONTAINER} does not carry a KAS_CONTAINER_SCRIPT_VERSION "
            "line; is the submodule a real kas release checkout?"
        )
    version = script_version.group(1)
    if tag.lstrip("v") != version:
        raise RuntimeError(
            f"kas submodule checked out at {tag!r}, but the wrapper pins "
            f"container image version {version!r}; check the submodule out "
            "at the recorded release tag"
        )
    return tag, version


def direct_kas_version(which=shutil.which, run=subprocess.run):
    """The version the kas tool installed in the current image reports.

    ``kas --version`` prints e.g.
    ``kas 5.5 (configuration format version 19, ...)``; the first
    version token is the direct-mode version-tie input. ``None`` means
    no kas is on PATH (or it reported nothing parseable) — direct mode
    then skips the matrix with the reason, matching the wrapper pin
    check's philosophy. ``which``/``run`` are injection points for
    testing.
    """
    kas = which("kas")
    if kas is None:
        return None
    reported = run([kas, "--version"], capture_output=True, text=True)
    match = re.search(r"\d+(?:\.\w+)*", reported.stdout or "")
    return match.group(0) if match else None


# --- run observations -------------------------------------------------------


def artifact_checksums(root):
    """Content fingerprint of every entry under *root*, keyed by relative path.

    Files hash as ``sha256:<hex>``, symlinks (resolved or dangling) record
    their target as ``link:<target>``. A missing root raises: "identical"
    compares against this mapping, and an empty mapping for a vanished
    deploy directory would make every run byte-identical to every other.
    """
    if not root.is_dir():
        raise FileNotFoundError(f"deploy directory {root} does not exist")
    fingerprints = {}
    for entry in sorted(root.rglob("*")):
        rel = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            fingerprints[rel] = f"link:{os.readlink(entry)}"
        elif entry.is_file():
            digest = hashlib.sha256()
            with entry.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
            fingerprints[rel] = f"sha256:{digest.hexdigest()}"
        elif entry.is_dir():
            fingerprints[rel] = "dir"
        else:
            fingerprints[rel] = "special"
    return fingerprints


#: A real (non-setscene, non-noexec) task execution, as streamed by kas.
#: The image's ``do_rm_work`` rides this channel on every fully-served
#: re-run; all other entries mean work redid something.
_WORK_TASK_RUN = re.compile(r"Running task \d+ of \d+ \((?P<task>[^()]*)\)")

#: A setscene restore (sstate served the task's outputs instead of
#: running it). The deployed bytes are the object's, byte-for-byte — but
#: no work happened, so these never count as reran tasks.
_SETSCENE_RESTORE = re.compile(
    r"Running setscene task \d+ of \d+ "
    r"\((?P<task>[^()]*:do_[a-z0-9_]+)_setscene\)"
)


def work_tasks_reran(text):
    """Set of recipe:task entries BitBake actually re-executed as work.

    Empty means sstate served everything: setscene restores and noexec
    bookkeeping do no work and are not counted.
    """
    return {match.group("task") for match in _WORK_TASK_RUN.finditer(text)}


def setscene_restored_tasks(text):
    """Set of recipe:do_* entries served from sstate as setscene restores.

    Names carry no ``_setscene`` suffix, so the result composes with
    :func:`work_tasks_reran` when asking "did this task's output land in
    this run, by running or by restoring?".
    """
    return {match.group("task") for match in _SETSCENE_RESTORE.finditer(text)}


# --- fixture layer ----------------------------------------------------------


def fixture_layer_conf_text(compat):
    """conf/layer.conf of the minimal fixture layer, series *compat*."""
    return (
        "# SPDX-License-Identifier: MIT\n"
        "# Fixture layer owned by the acceptance harness; nothing here is\n"
        "# part of the layer under test.\n"
        'BBPATH .= ":${LAYERDIR}"\n'
        'BBFILES += "${LAYERDIR}/recipes-*/*/*.bb"\n'
        'BBFILE_COLLECTIONS += "integration-fixtures"\n'
        'BBFILE_PATTERN_integration-fixtures = "^${LAYERDIR}/"\n'
        'LAYERDEPENDS_integration-fixtures = "core"\n'
        f'LAYERSERIES_COMPAT_integration-fixtures = "{compat}"\n'
    )


def fixture_recipe_text():
    """The trivial unused recipe the graph-isolation run (R4) adds.

    Parses cleanly, fetches nothing, drags in no dependencies — and no
    image target installs it, so no deployed artifact may change.
    """
    return (
        "# SPDX-License-Identifier: MIT\n"
        'SUMMARY = "Acceptance-harness fixture; nothing depends on this recipe"\n'
        'LICENSE = "MIT"\n'
        'INHIBIT_DEFAULT_DEPS = "1"\n'
    )


def _fixture_series_compat():
    """The series name the layer under test declares compatible.

    The fixture layer must name the same release series; deriving it from
    the layer's own conf/layer.conf keeps backported harness variants
    working unchanged.
    """
    text = (REPO_ROOT / "conf" / "layer.conf").read_text()
    match = re.search(r'^LAYERSERIES_COMPAT_\w+\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if match is None:
        raise RuntimeError(
            "cannot derive the release series from conf/layer.conf; the "
            "fixture layer needs its LAYERSERIES_COMPAT value"
        )
    return match.group(1)


def _fixture_git(*args):
    subprocess.run(
        ["git", *args],
        cwd=FIXTURES_REPO,
        capture_output=True,
        text=True,
        check=True,
        # A hermetic identity keeps the fixture repo commit reproducible on
        # machines without a configured user.
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "kas-integration-harness",
            "GIT_AUTHOR_EMAIL": "harness@invalid",
            "GIT_COMMITTER_NAME": "kas-integration-harness",
            "GIT_COMMITTER_EMAIL": "harness@invalid",
        },
    )


def fixture_status(tracked_only=False):
    """Porcelain status of the fixture repository.

    Public so tests assert the mutation's tracked/untracked character
    through this module — the single place fixture-repo knowledge lives.
    """
    command = ["git", "status", "--porcelain"]
    if tracked_only:
        command.append("--untracked-files=no")
    return subprocess.run(
        command,
        cwd=FIXTURES_REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def ensure_fixture_layer():
    """Create/update the fixture layer repository; idempotent.

    Tracked content is exactly conf/layer.conf, committed once; the recipe
    added by the graph-isolation run stays untracked on purpose. Called
    before every kas invocation, so it also restores the layer after a
    teardown removed it.
    """
    conf_dir = FIXTURES_LAYER / "conf"
    conf_dir.mkdir(parents=True, exist_ok=True)
    (conf_dir / "layer.conf").write_text(
        fixture_layer_conf_text(_fixture_series_compat())
    )
    _fixture_git("init", "-q")
    # Stage the tracked file only: an already-present fixture recipe must
    # never ride into the tracked tree.
    _fixture_git("add", "--", "meta-integration-fixtures/conf/layer.conf")
    if fixture_status(tracked_only=True):
        _fixture_git("commit", "-q", "-m", "Fixture layer initialized by the harness")


def add_fixture_recipe():
    """Write the unused fixture recipe (untracked); returns its path."""
    FIXTURES_RECIPE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURES_RECIPE.write_text(fixture_recipe_text())
    return FIXTURES_RECIPE


def fixture_image_extra_recipe_text():
    """The small installable package the image-change run (R5) adds.

    Fetches nothing, needs no compiler, installs one tiny file — and
    RDEPENDS on one package that is certain to be in the image, which
    guarantees the new component arrives with a resolvable dependency
    edge instead of floating unconnected.
    """
    return (
        "# SPDX-License-Identifier: MIT\n"
        'SUMMARY = "Acceptance-harness image content probe (R5)"\n'
        'LICENSE = "MIT"\n'
        'SRC_URI = ""\n'
        'INHIBIT_DEFAULT_DEPS = "1"\n'
        'RDEPENDS:${PN} = "busybox"\n'
        "do_install() {\n"
        "    install -d ${D}${sysconfdir}\n"
        '    echo "acceptance-harness image content probe" > \\\n'
        "        ${D}${sysconfdir}/harness-image-extra\n"
        "}\n"
    )


def add_image_extra_recipe():
    """Write the R5 recipe into the fixture layer (untracked); returns it."""
    FIXTURES_IMAGE_EXTRA_RECIPE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURES_IMAGE_EXTRA_RECIPE.write_text(fixture_image_extra_recipe_text())
    return FIXTURES_IMAGE_EXTRA_RECIPE


def revert_fixture_mutations():
    """Drop every untracked fixture mutation; assert the tracked tree clean.

    Raises if anything tracked changed — a mutation run that dirtied the
    tracked tree is a harness bug, not a build finding.
    """
    for recipe in (FIXTURES_RECIPE, FIXTURES_IMAGE_EXTRA_RECIPE):
        if recipe.exists():
            recipe.unlink()
        for empty_dir in (recipe.parent, recipe.parent.parent):
            if empty_dir.is_dir() and not any(empty_dir.iterdir()):
                empty_dir.rmdir()
    leftovers = fixture_status()
    if leftovers:
        raise RuntimeError(
            f"fixture mutations left {FIXTURES_REPO} dirty:\n{leftovers}"
        )


def remove_fixture_layer():
    """Teardown: remove the whole fixture layer repository."""
    shutil.rmtree(FIXTURES_REPO, ignore_errors=True)


# --- signature-source mutation (R3) -----------------------------------------


def mutation_text(text, anchor=SIGNATURE_MUTATION_ANCHOR,
                  comment=SIGNATURE_MUTATION_COMMENT):
    """*text* with the inert mutation comment placed where it is hashed.

    With an anchor the comment goes immediately after that exact line, one
    indent deeper — inside the function body, i.e. inside the source text
    BitBake folds into the generation tasks' signatures. With anchor=None
    the comment is appended at the end of the file, correct for targets
    whose *whole content* is checksummed into the signature. Raises if an
    anchor matches zero or several lines: a mutation that silently misses
    its target would turn R3 into a false positive.
    """
    if anchor is None:
        prefix = "" if not text or text.endswith("\n") else "\n"
        return f"{text}{prefix}{comment}\n"
    lines = text.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines) if line.rstrip("\n") == anchor]
    if not matches:
        raise ValueError(f"mutation anchor {anchor!r} not found in the source")
    if len(matches) > 1:
        count = "twice" if len(matches) == 2 else f"{len(matches)} times"
        raise ValueError(
            f"mutation anchor {anchor!r} found {count}; exactly one match needed"
        )
    indent = " " * (len(anchor) - len(anchor.lstrip()) + 4)
    lines.insert(matches[0] + 1, f"{indent}{comment}\n")
    return "".join(lines)


def mutate_signature_source(path=SIGNATURE_SOURCE,
                            anchor=SIGNATURE_MUTATION_ANCHOR):
    """Insert the mutation comment into *path*; return the original text.

    The caller hands the returned text to `revert_signature_source` at
    teardown — byte-exact restoration without git operations on the layer
    under test, which *is* this checkout.
    """
    original = path.read_text()
    path.write_text(mutation_text(original, anchor))
    return original


def revert_signature_source(original, path=SIGNATURE_SOURCE):
    """Restore the signature-carrying source byte-for-byte."""
    path.write_text(original)


def is_tracked(path):
    """True if *path* is tracked in this checkout."""
    return bool(_git("ls-files", "--", str(path)).strip())


def working_tree_status(path):
    """Porcelain status of *path* in this checkout; empty means pristine."""
    return _git("status", "--porcelain", "--", str(path)).strip()


def _fs_type(path):
    """Filesystem type of *path*, as coreutils `stat -f` reports it."""
    return subprocess.run(
        ["stat", "-f", "-c", "%T", str(path)],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def _checkout_id(repo_root):
    digest = hashlib.sha1(str(repo_root).encode()).hexdigest()[:8]
    return f"{repo_root.name}-{digest}"


def build_dir(workspace=WORKSPACE, environ=None, fs_type=None):
    """Host path of the kas build directory, guaranteed NFS-free.

    BitBake's sanity checker hard-errors on a TMPDIR inside NFS, which the
    plain repo-local layout would give on NFS-mounted worktrees (the
    development VM has an NFS home). The visible
    workspace entry `.integration/build` is then created as a symlink to a
    machine-local, per-checkout directory under ${TMPDIR:-/var/tmp}, so the
    single-directory workspace contract is kept where the filesystem allows
    it and stays functional where it does not.
    """
    environ = os.environ if environ is None else environ
    fs_type = _fs_type if fs_type is None else fs_type
    visible = workspace / "build"
    if fs_type(workspace) != "nfs":
        visible.mkdir(parents=True, exist_ok=True)
        return visible
    local = (
        Path(environ.get("TMPDIR", "/var/tmp"))
        / "meta-cyclonedx-integration"
        / _checkout_id(REPO_ROOT)
        / "build"
    )
    local.mkdir(parents=True, exist_ok=True)
    if visible.is_symlink():
        visible.unlink()
    elif visible.is_dir():
        if any(visible.iterdir()):
            raise RuntimeError(
                f"{visible} is a real directory on an NFS worktree, where "
                "BitBake refuses TMPDIR; delete it to let the harness place "
                "the build directory on NFS-safe storage instead"
            )
        visible.rmdir()
    visible.parent.mkdir(parents=True, exist_ok=True)
    visible.symlink_to(local)
    return local.resolve()


def workspace_env():
    """Environment for the kas wrapper: everything under one repo-local dir."""
    dirs = {
        "KAS_BUILD_DIR": build_dir(),
        "DL_DIR": WORKSPACE / "downloads",
        "SSTATE_DIR": WORKSPACE / "sstate-cache",
        "KAS_REPO_REF_DIR": WORKSPACE / "repo-ref",
    }
    for directory in dirs.values():
        directory.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["KAS_WORK_DIR"] = str(REPO_ROOT)
    env.update({key: str(value) for key, value in dirs.items()})
    return env


def runtime_env_args(env):
    """kas-container options that set *env* inside the build container.

    The wrapper forwards only a fixed whitelist of host variables into
    the container (and rejects -E/--preserve-env outright), so host-side
    exports cannot reach BitBake. --runtime-args is the wrapper's
    documented pass-through to the container runtime; the string is
    word-split by the wrapper, so neither key nor value may contain
    whitespace. The kas configuration's env: block then forwards such
    container-side variables into the BitBake datastore.
    """
    args = []
    for key, value in sorted(env.items()):
        value = str(value)
        if not key or any(c.isspace() for c in key + value):
            raise ValueError(
                f"runtime env {key!s}={value!r} must not contain whitespace: "
                "kas-container word-splits --runtime-args"
            )
        args += ["--runtime-args", f"-e {key}={value}"]
    return args


def kas_invocation(engine, extra_env=None):
    """The (command, process-env extras) for one kas build invocation.

    Container mode drives kas through the submodule's wrapper
    (*KAS_CONTAINER*), whose environment whitelist forces *extra_env*
    onto the --runtime-args channel (see runtime_env_args). Direct mode
    execs the kas tool installed in the current image — a plain
    invocation, no wrapper argument chain — so *extra_env* rides the
    process environment instead, and the project config's env: block
    forwards it into BitBake the same way; the R5 install-list change
    reaches the build config identically in both modes.
    """
    if engine == KAS_DIRECT:
        return ["kas", "build", "kas.yml"], dict(extra_env or {})
    command = [str(KAS_CONTAINER)]
    if extra_env:
        command += runtime_env_args(extra_env)
    return command + ["build", "kas.yml"], {}


def tail(text, lines=60):
    """Last *lines* lines of *text*, for surfacing build-log context on error."""
    return "\n".join(text.splitlines()[-lines:])
