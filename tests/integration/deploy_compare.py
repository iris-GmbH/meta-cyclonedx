# SPDX-License-Identifier: MIT
"""Byte-identity reporting over recorded deploy directories.

The recorder (tests/integration/conftest.py) snapshots a checksum map per
invocation; this module turns a mismatch into a report that names the
run and the added/removed/changed entries. Byte-identity claims live in
the cache-reuse runs (R2, R4); the CycloneDX-subset filter serves the
R3 revert run, where dated image artifacts legitimately rotate.
"""


def cyclonedx_checksums(checksums):
    """The checksum map restricted to the CycloneDX artifacts."""
    return {
        name: digest
        for name, digest in checksums.items()
        if ".cyclonedx." in name
    }


def identity_report(record, before, subset=None):
    """Report why *record*'s artifacts are not byte-identical to *before*.

    *before* is a recorded run or its checksums mapping. *subset*, if
    given, is a checksums filter naming the claim's subject.
    """
    now = record.checksums
    then = getattr(before, "checksums", before)
    if subset:
        now, then = subset(now), subset(then)
    added = sorted(key for key in now if key not in then)
    removed = sorted(key for key in then if key not in now)
    changed = sorted(
        key for key, value in now.items() if key in then and then[key] != value
    )
    return (
        f"deployed artifacts differ after the {record.name} run:\n"
        f"  added:   {added}\n"
        f"  removed: {removed}\n"
        f"  changed: {changed}\n"
        f"build-log tail:\n{record.output_tail}"
    )
