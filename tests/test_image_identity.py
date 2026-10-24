"""Image component identity: CPE generation/validation and PURL assembly."""

import pytest

import meta_cyclonedx


@pytest.mark.parametrize("image_type,part", [
    ("application", "a"),
    ("device", "h"),
    ("firmware", "o"),
    ("operating-system", "o"),
    ("platform", "*"),
])
def test_cpe_part_follows_the_image_type(image_type, part):
    cpe = meta_cyclonedx.image_cpe(image_type, "vendor", "image", "1.0")

    assert cpe == f"cpe:2.3:{part}:vendor:image:1.0:*:*:*:*:*:*:*"


def test_generated_cpe_escapes_reserved_characters():
    # The default image version carries a "+" (DISTRO_VERSION +git/snapshot
    # suffixes), which CPE 2.3 reserves; it must arrive escaped.
    cpe = meta_cyclonedx.image_cpe(
        "operating-system", "Foo Inc", "core-image", "4.1+snapshot-20261024")

    assert cpe == (
        "cpe:2.3:o:foo\\ inc:core-image:4.1\\+snapshot-20261024"
        ":*:*:*:*:*:*:*"
    )
    assert meta_cyclonedx.cpe_23_is_valid(cpe)


def test_generated_cpe_uses_the_wildcard_vendor_by_default():
    cpe = meta_cyclonedx.image_cpe("firmware", "", "core-image", "1.0")

    assert cpe.startswith("cpe:2.3:o:*:core-image:1.0:")


def test_configured_cpe_override_is_returned_verbatim():
    override = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"

    assert meta_cyclonedx.image_cpe(
        "firmware", "other", "ignored", "9.9", override=override) == override


def test_configured_cpe_override_is_validated():
    assert meta_cyclonedx.config_errors(
        "1.7", "firmware", "cpe:2.3:o:linux:linux_kernel:6.18.56:*:*:*:*:*:*:*") is None

    error = meta_cyclonedx.config_errors("1.7", "firmware", "cpe:2.3:z:v:p:1:*:*:*:*:*:*:*")
    assert error is not None and "CYCLONEDX_IMAGE_CPE" in error
    assert meta_cyclonedx.config_errors("1.7", "firmware", "not a cpe") is not None


def test_purl_without_layer_facts_is_the_base_purl():
    assert meta_cyclonedx.image_purl("pkg:yocto/core/core-image@1.0") == \
        "pkg:yocto/core/core-image@1.0"


def test_purl_qualifiers_are_ordered_and_url_encoded():
    purl = meta_cyclonedx.image_purl(
        "pkg:yocto/core/core-image@1.0", "abc123", "https://example.com/meta-image.git?x=1&y=2")

    assert purl == (
        "pkg:yocto/core/core-image@1.0?layer_version=abc123"
        "&repository_url=https%3A%2F%2Fexample.com%2Fmeta-image.git%3Fx%3D1%26y%3D2"
    )


def test_purl_omits_unresolvable_qualifiers():
    assert meta_cyclonedx.image_purl(
        "pkg:yocto/core/core-image@1.0", None, "https://example.com/l.git") == \
        "pkg:yocto/core/core-image@1.0?repository_url=https%3A%2F%2Fexample.com%2Fl.git"
    assert meta_cyclonedx.image_purl(
        "pkg:yocto/core/core-image@1.0", "abc123", None) == \
        "pkg:yocto/core/core-image@1.0?layer_version=abc123"
