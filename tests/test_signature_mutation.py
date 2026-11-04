# SPDX-License-Identifier: MIT
"""Unit tests for the regeneration-run helpers (no build, no container).

R3 mutates the *signature-carrying generator source* — the tracked file
named by the harness parameter ``kas_env.SIGNATURE_SOURCE`` — with an
inert comment placed where BitBake's signature codependency reaches it;
R5 adds one small harness-owned package to the image install list. The
mutation/revert helpers and the fixture recipe text are pure functions
over given inputs and are tested here.
"""

import subprocess
from functools import partial
from types import SimpleNamespace

import pytest

from tests.integration import kas_env, test_regeneration


def write_source(tmp_path):
    """A class-file-shaped source: two functions, comments, blank lines."""
    source = tmp_path / "cyclonedx-export.bbclass"
    source.write_text(
        "# SPDX-License-Identifier: MIT\n"
        "CYCLONEDX_SOMETHING = \"1\"\n"
        "\n"
        "def helper(d):\n"
        "    return d\n"
        "\n"
        "def export_cyclonedx(d):\n"
        '    """Doc."""\n'
        "    pass\n"
        "\n"
        "addtask do_export_cyclonedx before do_build\n"
    )
    return source


def test_mutation_lands_inside_the_anchored_function_body(tmp_path):
    source = write_source(tmp_path)
    original = kas_env.mutate_signature_source(
        path=source, anchor="def export_cyclonedx(d):"
    )
    mutated = source.read_text()
    assert mutated != original
    lines = mutated.splitlines()
    marker = lines[lines.index("def export_cyclonedx(d):") + 1]
    # Inert: a comment, indented inside the function body it was anchored to.
    assert marker.startswith("    # ")
    # Everything else is byte-preserved.
    assert mutated.replace(marker + "\n", "") == original


def test_mutation_is_reversible_byte_exactly(tmp_path):
    source = write_source(tmp_path)
    original = kas_env.mutate_signature_source(
        path=source, anchor="def export_cyclonedx(d):"
    )
    kas_env.revert_signature_source(original, path=source)
    assert source.read_text() == original


def test_mutation_fixture_preserves_existing_staged_and_unstaged_edits(
    tmp_path, monkeypatch
):
    source = write_source(tmp_path)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=tmp_path, capture_output=True, text=True, check=True
        ).stdout

    git("add", source.name)
    git("-c", "user.name=Harness", "-c", "user.email=harness@invalid",
        "-c", "commit.gpgsign=false", "commit", "-qm", "baseline")
    source.write_text(source.read_text() + "# staged maintainer edit\n")
    git("add", source.name)
    staged = git("show", f":{source.name}")
    source.write_text(source.read_text() + "# unstaged maintainer edit\n")
    original = source.read_bytes()
    status = git("status", "--porcelain", "--", source.name)
    monkeypatch.setattr(kas_env, "SIGNATURE_SOURCE", source)
    monkeypatch.setattr(kas_env, "_git", git)
    monkeypatch.setattr(
        kas_env, "mutate_signature_source",
        partial(kas_env.mutate_signature_source, path=source),
    )
    monkeypatch.setattr(
        kas_env, "revert_signature_source",
        partial(kas_env.revert_signature_source, path=source),
    )
    recorder = SimpleNamespace(invoke=lambda name: SimpleNamespace(returncode=0))
    runs = test_regeneration.mutation_runs.__wrapped__(recorder, None)
    test_regeneration.test_teardown_restored_the_generator_source(runs)
    assert source.read_bytes() == original
    assert git("show", f":{source.name}") == staged
    assert git("status", "--porcelain", "--", source.name) == status


def test_mutation_without_anchor_appends_at_end_of_file(tmp_path):
    # Post-seam targets (a whole-file-checksummed renderer module) carry
    # every byte in the signature; appending there is the right placement.
    source = tmp_path / "renderer.py"
    source.write_text("def render(x):\n    return x\n")
    original = kas_env.mutate_signature_source(path=source, anchor=None)
    mutated = source.read_text()
    assert mutated.startswith(original)
    assert mutated[len(original):].startswith("# ")


def test_ambiguous_or_missing_anchor_is_a_hard_error(tmp_path):
    source = tmp_path / "ambiguous.bbclass"
    source.write_text("def f():\n    pass\n\ndef f():\n    pass\n")
    with pytest.raises(ValueError, match="twice"):
        kas_env.mutate_signature_source(path=source, anchor="def f():")
    missing = tmp_path / "missing.bbclass"
    missing.write_text("x = 1\n")
    with pytest.raises(ValueError, match="not found"):
        kas_env.mutate_signature_source(path=missing, anchor="def gone():")
    assert missing.read_text() == "x = 1\n"




def test_runtime_env_rejects_whitespace():
    with pytest.raises(ValueError):
        kas_env.runtime_env_args({"CORE_IMAGE_EXTRA_INSTALL": "package one"})


def test_signature_source_matches_the_branch_generation_logic():
    # The parameter must name the file the generation tasks actually
    # checksum: post-seam the renderer module, which the class folds in
    # via [file-checksums]; pre-seam the export class, whose generator
    # function is a codependency of those tasks.
    renderer = kas_env.REPO_ROOT / "lib" / "meta_cyclonedx.py"
    klass = kas_env.REPO_ROOT / "classes" / "cyclonedx-export.bbclass"
    if renderer.exists():
        assert kas_env.SIGNATURE_SOURCE == renderer
        assert kas_env.SIGNATURE_MUTATION_ANCHOR is None, (
            "a whole-file-checksummed target takes the append mutation"
        )
        klass_text = klass.read_text()
        wired = {
            line.split("[", 1)[0]: line
            for line in klass_text.splitlines()
            if "[file-checksums]" in line and "meta_cyclonedx.py" in line
        }
        for task in (
            "do_populate_cyclonedx",
            "do_rootfs",
            "do_deploy_cyclonedx",
            "do_cyclonedx_sbom_cve_check",
        ):
            assert task in wired, (
                f"{task} must checksum the renderer module: dropping the "
                "wiring would silently serve stale documents from sstate"
            )
            # BitBake >= 6.1 parses entries as `path:exists`; a raw path
            # crashes prep_taskhash with an IndexError. Only a real build
            # shows this, so the encoding is pinned here. The module is tracked in
            # the layer, so the honest flag is True.
            assert wired[task].rstrip().endswith("meta_cyclonedx.py:True\""), (
                f"{task}'s renderer entry lacks BitBake's path:exists "
                "encoding and would crash task-hash preparation"
            )
    else:
        assert kas_env.SIGNATURE_SOURCE == klass
        anchor = kas_env.SIGNATURE_MUTATION_ANCHOR
        occurrences = klass.read_text().count(anchor + "\n")
        assert occurrences == 1, "the mutation anchor must match exactly once"
