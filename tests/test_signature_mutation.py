# SPDX-License-Identifier: MIT
"""Unit tests for the regeneration-run helpers (no build, no container).

R3 mutates the *signature-carrying generator source* — the tracked file
named by the harness parameter ``kas_env.SIGNATURE_SOURCE`` — with an
inert comment placed where BitBake's signature codependency reaches it;
R5 adds one small harness-owned package to the image install list. The
mutation/revert helpers and the fixture recipe text are pure functions
over given inputs and are tested here.
"""

import pytest

from tests.integration import kas_env


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


def test_mutation_comment_is_inert():
    # The inserted line must not change any parsed metadata or code path.
    assert kas_env.SIGNATURE_MUTATION_COMMENT.startswith("#")


def test_this_branch_names_the_pre_seam_signature_source():
    # On this (pre-seam) branch the parameter is the class file itself; its
    # generator function is a signature dependency of the generation tasks.
    assert kas_env.SIGNATURE_SOURCE == (
        kas_env.REPO_ROOT / "classes" / "cyclonedx-export.bbclass"
    )
    anchor = kas_env.SIGNATURE_MUTATION_ANCHOR
    occurrences = kas_env.SIGNATURE_SOURCE.read_text().count(anchor + "\n")
    assert occurrences == 1, "the mutation anchor must match exactly once"


def test_image_extra_recipe_is_a_small_installable_package():
    # R5's package: no sources fetched, no compiler needed, one tiny
    # installed file, and one RDEPENDS on a package certain to be in the
    # image so the dependency edge is guaranteed.
    text = kas_env.fixture_image_extra_recipe_text()
    assert 'RDEPENDS:${PN} = "busybox"' in text
    assert 'SRC_URI = ""' in text
    assert "INHIBIT_DEFAULT_DEPS" in text
    assert kas_env.IMAGE_EXTRA_RECIPE_NAME == "harness-image-extra"
    assert kas_env.IMAGE_EXTRA_RECIPE_NAME in str(
        kas_env.FIXTURES_IMAGE_EXTRA_RECIPE
    )


def test_image_extra_install_reaches_the_container_environment():
    # kas-container drops host variables outside its whitelist and
    # word-splits the --runtime-args string: R5's setting must ride as a
    # whitespace-free single token, so the delivery is asserted here.
    assert kas_env.runtime_env_args(kas_env.IMAGE_EXTRA_INSTALL_ENV) == [
        "--runtime-args",
        "-e CORE_IMAGE_EXTRA_INSTALL=harness-image-extra",
    ]
    for tainted in (" a b", "a\tb", "a\nb", "a\r\n"):
        with pytest.raises(ValueError):
            kas_env.runtime_env_args({"CORE_IMAGE_EXTRA_INSTALL": tainted})
