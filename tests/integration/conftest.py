# SPDX-License-Identifier: MIT
"""Fixtures for the kas-driven BitBake acceptance layer.

A session-scoped recorder runs the matrix's kas invocations — each one
once — against a single workspace, recording per-run observations; tests
assert over those records so a failure names its run in the report.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

import pytest

from tests.integration import kas_env

# BitBake's per-task failure line, surfaced by kas as it streams events.
_TASK_FAILURE = re.compile(r"ERROR: Task .* failed with exit code")
_SHUTDOWN_TIMEOUT = 300.0


class KasBuildResult:
    """Record of one kas container build invocation."""

    def __init__(self, engine, returncode, output, build_dir):
        self.engine = engine
        self.returncode = returncode
        self.build_dir = build_dir
        self.output_tail = kas_env.tail("".join(output))

    @property
    def deploy_dir(self):
        """The documented output location: TMPDIR/deploy/images/<machine>."""
        return self.build_dir / "tmp" / "deploy" / "images" / kas_env.MACHINE

    @property
    def image_metadata_dir(self):
        """CycloneDX sstate output for this single-config, machine-specific image.

        ``CYCLONEDX_IMAGEDATA`` embeds ``BB_CURRENT_MC``, and BitBake
        names the base (non-multiconfig) configuration "default", so the
        sstate-restored documents live under that segment.
        """
        machine_arch = kas_env.MACHINE.replace("-", "_")
        return (
            self.build_dir / "tmp" / "cyclonedx" / "image" / "default"
            / machine_arch / kas_env.TARGET
        )

    def deployed(self, name):
        return self.deploy_dir / name


class RunRecord:
    """Record of one kas invocation within the re-invocation matrix.

    Snapshots deployed-artifact checksums, CycloneDX documents, and
    image metadata at the moment the invocation completes
    — a later invocation writes the same deploy paths (sstate restores
    older bytes over them), and evidence must name the bytes this run
    deployed, not the current occupants of the file. Also parses
    BitBake's task-execution lines, the log observation distinguishing
    "nothing reran" from a build that redid work.
    """

    def __init__(self, name, build, output):
        self.name = name
        self.build = build
        self.returncode = build.returncode
        self.output_tail = build.output_tail
        self.log = "".join(output)
        self.checksums = None
        self.document_captures = {}
        self.image_metadata_captures = {}
        if build.returncode == 0:
            self.checksums = kas_env.artifact_checksums(build.deploy_dir)
            for doc_name in (kas_env.SBOM_NAME, kas_env.VEX_NAME):
                path = build.deployed(doc_name)
                if path.is_file():
                    self.document_captures[doc_name] = path.read_text()
            metadata_dir = build.image_metadata_dir
            self.image_metadata_captures = {
                path.relative_to(metadata_dir).as_posix(): path.read_text()
                for path in metadata_dir.rglob("*.json")
                if path.is_file()
            }
        self.reran_tasks = kas_env.work_tasks_reran(self.log)
        self._documents = None

    @property
    def documents(self):
        """Lazy deployed-document evidence over this run's build."""
        if self._documents is None:
            self._documents = RunDocuments(self)
        return self._documents


class KasRunRecorder:
    """Multiple kas invocations against one workspace, recorded in order.

    Each invocation streams output like the cold run, re-ensures the
    fixture layer (idempotent, so a teardown that removed it is invisible
    to later runs), and memoizes a named RunRecord.
    """

    def __init__(self, container_runtime):
        self.engine = container_runtime
        self.results: dict[str, RunRecord] = {}
        self._pinned = False

    def __getitem__(self, name):
        return self.results[name]

    def invoke(self, name, extra_env=None):
        """Run the matrix configuration under this name; return its record.

        *extra_env* is set in the build environment (the image-change
        run's install-list forwarding) through the mode-appropriate
        channel — the wrapper's --runtime-args channel in container
        mode (a plain host export would be dropped by the wrapper's
        environment whitelist), the process environment in direct mode
        (the project config's env: block forwards it) — and never leaks
        into another run.

        A failed invocation aborts the remaining stages: BitBake did
        not advance any stamp, so the next invocation would replay the
        identical failure for minutes or hours while every stage
        observation is guarded off the failed build anyway. Zero-exit
        invocations never gate, keeping stage independence for
        assertion failures.
        """
        if name in self.results:
            return self.results[name]
        for failed in self.results.values():
            if failed.returncode != 0:
                pytest.skip(
                    f"prior kas invocation {failed.name!r} failed "
                    f"(exit {failed.returncode}); later stages would "
                    "only replay it\nbuild-log tail:\n"
                    f"{failed.output_tail}"
                )
        if not self._pinned:
            try:
                kas_env.ensure_kas_submodule()
                if self.engine == kas_env.KAS_DIRECT:
                    running = kas_env.direct_kas_version()
                    if running is None:
                        raise RuntimeError(
                            "KAS_CONTAINER_ENGINE=none selects direct mode, "
                            "but no kas executable is on PATH; install the "
                            "kas tool (the CI runner image ships it) or unset "
                            "the override"
                        )
                    tag, version = kas_env.check_kas_pin(running_version=running)
                else:
                    tag, version = kas_env.check_kas_pin()
            except (RuntimeError, subprocess.CalledProcessError) as exc:
                # Prerequisite gaps (submodule not checked out and not
                # fetchable — a git fetch failure surfaces as
                # CalledProcessError through the _git helpers —, a pin
                # or version-tie mismatch, or direct mode without a kas
                # tool) skip the matrix with the reason, as contributor
                # documentation promises, rather than erroring out of
                # every run at once.
                pytest.skip(str(exc) or repr(exc))
            print(f"kas {version} (tag {tag}) via {self.engine}", file=sys.stderr)
            self._pinned = True
        kas_env.ensure_fixture_layer()
        env = kas_env.workspace_env()
        env["KAS_CONTAINER_ENGINE"] = self.engine
        command, env_extras = kas_env.kas_invocation(self.engine, extra_env=extra_env)
        env.update(env_extras)
        returncode, lines = self._stream(command, env)
        build = KasBuildResult(
            engine=self.engine,
            returncode=returncode,
            output=lines,
            build_dir=kas_env.build_dir(),
        )
        self.results[name] = record = RunRecord(name, build, lines)
        return record

    def _stream(self, command, env):
        """Run *command*, echoing live (cold builds run for tens of minutes)."""
        proc = subprocess.Popen(
            command,
            cwd=kas_env.REPO_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        lines: list[str] = []
        aborted: list[str] = []
        task_failed = threading.Event()

        def pump() -> None:
            for line in proc.stdout:
                lines.append(line)
                sys.stderr.write(line)
                sys.stderr.flush()
                if _TASK_FAILURE.search(line) and not task_failed.is_set():
                    aborted.append(line)
                    task_failed.set()

        def signal_group(sig):
            try:
                # The group may outlive its leader; getpgid(proc.pid) would
                # fail once the wrapper exits while descendants still run.
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                pass

        reader = threading.Thread(target=pump)
        try:
            reader.start()
            while not task_failed.is_set():
                try:
                    proc.wait(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    pass
        finally:
            # Also runs on KeyboardInterrupt: start_new_session means the
            # build does not receive the terminal's interrupt itself.
            try:
                if proc.poll() is None:
                    signal_group(signal.SIGINT)
                deadline = time.monotonic() + _SHUTDOWN_TIMEOUT
                proc.wait(timeout=_SHUTDOWN_TIMEOUT)
                if reader.ident is not None:
                    reader.join(timeout=max(0, deadline - time.monotonic()))
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                # A second interrupt skips the grace period.
                pass
            finally:
                # Kill any remaining descendants as well, including ones
                # holding stdout open after the wrapper has exited.
                signal_group(signal.SIGKILL)
                proc.wait()
                if reader.ident is not None:
                    reader.join()
                proc.stdout.close()
        if aborted:
            lines.append("\nHARNESS: build aborted early (first failed task): "
                         f"{aborted[0].strip()}\n")
        return proc.returncode, lines


class RunDocuments:
    """Named evidence over one recorded run's deployed documents.

    The CycloneDX documents are the bytes captured when the run
    completed — a later run restores the same deploy paths from sstate,
    and evidence must name what this run deployed, not whoever occupies
    the file now. The manifest is read live (the matrix ends with the
    image-change run, and R5 asserts over exactly that run's files). Any
    failure names the observation and carries the build-log tail, so
    diagnosis needs no re-run with more verbosity.
    """

    def __init__(self, record):
        self.record = record
        self.build = record.build
        self._documents = {}

    def deployed(self, name, what):
        """The deployed *name*, failing named with the build-log tail."""
        path = self.build.deployed(name)
        if not path.is_file():
            pytest.fail(
                f"{what} {name} is not deployed under "
                f"{self.build.deploy_dir}; build-log tail:\n"
                f"{self.build.output_tail}"
            )
        return path

    def document(self, name, what):
        text = self.record.document_captures.get(name)
        if text is None:
            text = self.deployed(name, what).read_text()
        document = self._documents.get(name)
        if document is None:
            try:
                document = json.loads(text)
            except ValueError as exc:
                pytest.fail(
                    f"{what} {name} is not parseable JSON: {exc}; "
                    f"build-log tail:\n{self.build.output_tail}"
                )
            self._documents[name] = document
        return document

    @property
    def sbom(self):
        return self.document(kas_env.SBOM_NAME, "image SBOM")

    @property
    def vex(self):
        return self.document(kas_env.VEX_NAME, "image VEX")


@pytest.fixture(scope="session")
def container_runtime():
    engine = kas_env.detect_container_runtime()
    if engine is None:
        pytest.skip(kas_env.SKIP_HINT)
    return engine


@pytest.fixture(scope="session")
def kas_runs(container_runtime):
    """The re-invocation recorder: one workspace, every run named."""
    return KasRunRecorder(container_runtime)


@pytest.fixture(scope="session")
def kas_build(kas_runs):
    """Run one real ``core-image-minimal`` build through the kas wrapper.

    This is R1 of the run matrix; the cache-semantics and regeneration
    runs re-invoke the same recorder against the same workspace.
    """
    return kas_runs.invoke("cold").build


@pytest.fixture(scope="session")
def cold_run(kas_build, kas_runs):
    """The recorded cold-run evidence: documents captured when the cold
    invocation completed, not read from the shared deploy directory at
    test time (later runs restore those paths)."""
    return kas_runs["cold"].documents


@pytest.fixture(scope="session")
def cyclonedx_16_validator():
    """Validator over the vendored CycloneDX 1.6 JSON schema.

    `jsonschema` is an integration-layer-only dependency: the module
    carrying it is imported here, lazily, never at collection time, so the
    deselected unit suite never requires it.
    """
    try:
        from tests.integration import schema_validation
    except ImportError:
        pytest.skip(kas_env.JSONSCHEMA_HINT)
    return schema_validation.bom_validator()
