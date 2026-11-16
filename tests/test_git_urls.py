# SPDX-License-Identifier: MIT

"""Git remote urls: the scp-style shorthand rewritten into ssh URIs."""

import pytest

import meta_cyclonedx


def test_scp_style_remote_becomes_an_ssh_uri():
    # The un-rewritten form is no URI: an external reference url built from
    # it ("git@ssh.server.example:repo/meta-test@<rev>") fails schema
    # validation.
    assert meta_cyclonedx.git_url_as_uri(
        "git@ssh.server.example:repo/meta-test") == \
        "ssh://git@ssh.server.example/repo/meta-test"


def test_scp_style_remote_without_user_becomes_an_ssh_uri():
    assert meta_cyclonedx.git_url_as_uri(
        "ssh.server.example:repo/meta-test") == \
        "ssh://ssh.server.example/repo/meta-test"


def test_absolute_scp_style_path_gains_exactly_one_separator():
    assert meta_cyclonedx.git_url_as_uri(
        "git@ssh.example.org:/srv/git/meta-test.git") == \
        "ssh://git@ssh.example.org/srv/git/meta-test.git"


def test_rewrite_is_idempotent():
    uri = meta_cyclonedx.git_url_as_uri("git@ssh.server.example:repo/meta-test")

    assert meta_cyclonedx.git_url_as_uri(uri) == uri


@pytest.mark.parametrize("url", [
    "https://example.org/repo/meta-test",
    "http://example.org/repo/meta-test",
    "ssh://git@ssh.example.org:2222/repo/meta-test",
    "git://git.example.org/repo/meta-test",
    "git+ssh://git@ssh.example.org/repo/meta-test",
    "file:///srv/git/meta-test",
    "HTTPS://example.org/repo/meta-test",
])
def test_scheme_carrying_urls_are_returned_unchanged(url):
    assert meta_cyclonedx.git_url_as_uri(url) == url


@pytest.mark.parametrize("path", [
    "/srv/git/meta-test",       # local absolute path
    "../meta-test",             # local relative path
    "C:/work/meta-test",        # Windows drive path, not host "C"
    "git@ssh.server.example:",  # colon but no path
])
def test_paths_are_returned_unchanged(path):
    assert meta_cyclonedx.git_url_as_uri(path) == path
