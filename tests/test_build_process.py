# SPDX-License-Identifier: MIT
"""Real subprocess regressions for cancellation and late build failures."""

import os
import signal
from subprocess import Popen
import sys
import time

import pytest

from tests.integration import conftest


@pytest.fixture
def build_process(monkeypatch):
    children = []
    popen = Popen

    def launch(*args, **kwargs):
        proc = popen(*args, **kwargs)
        children.append(proc)
        return proc

    monkeypatch.setattr(conftest.subprocess, "Popen", launch)
    monkeypatch.setattr(conftest, "_SHUTDOWN_TIMEOUT", 0.1)
    try:
        yield children
    finally:
        for proc in children:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)
            proc.stdout.close()


def test_interruption_reaps_a_build_that_ignores_sigint(
    monkeypatch, tmp_path, build_process
):
    wait = Popen.wait
    ready = tmp_path / "ready"
    interrupted = False

    def interrupt_once(proc, timeout=None):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            deadline = time.monotonic() + 5
            while not ready.exists():
                if time.monotonic() >= deadline:
                    pytest.fail("child did not become ready")
                time.sleep(0.01)
            raise KeyboardInterrupt
        return wait(proc, timeout=timeout)

    monkeypatch.setattr(Popen, "wait", interrupt_once)
    command = [sys.executable, "-u", "-c", (
        "import signal; from pathlib import Path; "
        "signal.signal(signal.SIGINT, signal.SIG_IGN); signal.alarm(5); "
        f"Path({str(ready)!r}).touch(); signal.pause()"
    )]
    with pytest.raises(KeyboardInterrupt):
        conftest.KasRunRecorder("podman")._stream(command, dict(os.environ))
    assert build_process[0].poll() == -signal.SIGKILL


def test_failure_after_wait_begins_starts_shutdown_deadline(
    monkeypatch, tmp_path, build_process
):
    waiting = tmp_path / "waiting"
    wait = Popen.wait

    def notify_wait(proc, timeout=None):
        waiting.touch()
        return wait(proc, timeout=timeout)

    monkeypatch.setattr(Popen, "wait", notify_wait)
    command = [sys.executable, "-u", "-c", (
        "import signal, time\nfrom pathlib import Path\n"
        "signal.signal(signal.SIGINT, signal.SIG_IGN)\nsignal.alarm(5)\n"
        f"while not Path({str(waiting)!r}).exists(): time.sleep(0.01)\n"
        "print(\"ERROR: Task (probe.bb:do_compile) failed with exit code '1'\", flush=True)\n"
        "signal.pause()\n"
    )]
    returncode, _ = conftest.KasRunRecorder("podman")._stream(
        command, dict(os.environ)
    )
    assert returncode == -signal.SIGKILL
