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

import pytest

from tests.integration import kas_env

# BitBake's per-task failure line, surfaced by kas as it streams events.
_TASK_FAILURE = re.compile(r"ERROR: Task .* failed with exit code")


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

    def deployed(self, name):
        return self.deploy_dir / name


class RunRecord:
    """Record of one kas invocation within the re-invocation matrix.

    Snapshots the deployed-artifact checksums *and the deployed
    CycloneDX document contents* at the moment the invocation completes
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
        if build.returncode == 0:
            self.checksums = kas_env.artifact_checksums(build.deploy_dir)
            for doc_name in (kas_env.SBOM_NAME, kas_env.VEX_NAME):
                path = build.deployed(doc_name)
                if path.is_file():
                    self.document_captures[doc_name] = path.read_text()
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

        *extra_env* is set inside the build container (the image-change
        run's install-list forwarding) via the wrapper's --runtime-args
        channel — a plain host export would be dropped by the wrapper's
        environment whitelist — and never leaks into another run.
        """
        if name in self.results:
            return self.results[name]
        if not self._pinned:
            try:
                kas_env.ensure_kas_submodule()
                tag, version = kas_env.check_kas_pin()
            except (RuntimeError, subprocess.CalledProcessError) as exc:
                # Prerequisite gaps (submodule not checked out and not
                # fetchable — a git fetch failure surfaces as
                # CalledProcessError through the _git helpers — or a
                # wrapper/tag pin mismatch) skip the matrix with the
                # reason, as contributor documentation promises,
                # rather than erroring out of every run at once.
                pytest.skip(str(exc) or repr(exc))
            print(f"kas {version} (tag {tag}) via {self.engine}", file=sys.stderr)
            self._pinned = True
        kas_env.ensure_fixture_layer()
        env = kas_env.workspace_env()
        env["KAS_CONTAINER_ENGINE"] = self.engine
        command = [str(kas_env.KAS_CONTAINER)]
        if extra_env:
            command += kas_env.runtime_env_args(extra_env)
        command += ["build", "kas.yml"]
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

        def pump() -> None:
            for line in proc.stdout:
                lines.append(line)
                sys.stderr.write(line)
                sys.stderr.flush()
                # A failed BitBake task otherwise lets the build drain every
                # in-flight task (tens of minutes for an llvm/gcc compile).
                # Interrupt at the first failure instead; the process group
                # covers the kas wrapper and the engine's `run` client, so the
                # container itself shuts down too.
                if _TASK_FAILURE.search(line) and not aborted:
                    aborted.append(line)
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGINT)
                    except ProcessLookupError:
                        pass

        reader = threading.Thread(target=pump)
        reader.start()
        try:
            # SIGINT reaches kas and BitBake, which stop cleanly; escalate only
            # if the shutdown stalls.
            returncode = proc.wait(timeout=300.0 if aborted else None)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            returncode = proc.wait()
        reader.join()
        if aborted:
            lines.append("\nHARNESS: build aborted early (first failed task): "
                         f"{aborted[0].strip()}\n")
        return returncode, lines


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
