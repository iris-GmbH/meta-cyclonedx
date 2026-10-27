# SPDX-License-Identifier: MIT
"""Conservative kernel source matching, independent of BitBake's release API.

DWARF source lists are evidence, not a complete inventory. Only exact C files
with a unique existing source/build mapping may cause automatic exclusions.
"""

import json
import os
from pathlib import Path
import re
import shlex


def exact_relative_path(path):
    return (isinstance(path, str) and bool(path)
            and all(part not in ("", ".", "..")
                    and re.fullmatch(r"[A-Za-z0-9_.+-]+", part)
                    for part in path.split("/")))


class SourcePaths:
    """Resolve CVE and debug-source paths against source/build roots.

    A unique mapping is a (root_relative_path, physical_path) tuple. The
    relative path describes a kernel source or known sysroot header in
    diagnostics; the canonical physical path identifies compiled files,
    including symlink aliases. Missing, unsupported or ambiguous mappings
    return None.
    """

    def __init__(self, roots, source_package_prefix, kernel_src_path, debug_prefix_map="",
                 external_header_roots=()):
        self.roots = sorted({os.path.abspath(root) for root in roots if root})
        self.external_header_roots = sorted({os.path.abspath(root)
                                             for root in external_header_roots if root})
        self.source_package_prefix = source_package_prefix
        self.kernel_src_path = kernel_src_path
        self.prefix_maps = []
        for flag in shlex.split(debug_prefix_map):
            if flag.startswith(("-fdebug-prefix-map=", "-ffile-prefix-map=")):
                old, sep, new = flag.split("=", 1)[1].partition("=")
                if sep and os.path.isabs(old) and os.path.isabs(new):
                    self.prefix_maps.append((old, new))

    @staticmethod
    def suffix(path, root):
        root = root.rstrip("/") + "/"
        return path[len(root):] if path.startswith(root) else None

    def _physical(self, path):
        matches = set()
        path = os.path.abspath(path)
        for root in self.roots:
            relative = self.suffix(path, root)
            if relative and os.path.isfile(path):
                # Compare physical files too, so a compiled symlink alias cannot
                # make the original source appear absent.
                matches.add((relative, os.path.realpath(path)))
        # GCC intrinsics can put toolchain headers into kernel DWARF. Resolve
        # only existing headers from the recipe's known sysroots; an unknown
        # source or any external C translation unit must still fail closed.
        if path.endswith('.h'):
            for root in self.external_header_roots:
                relative = self.suffix(path, root)
                if relative and os.path.isfile(path):
                    matches.add((relative, os.path.realpath(path)))
        return matches

    def affected(self, path):
        """Map an exact kernel-relative C path from a CVE record, or return None."""
        if not exact_relative_path(path) or not path.endswith(".c"):
            return None
        matches = set()
        for root in self.roots:
            matches.update(self._physical(os.path.join(root, path)))
        return next(iter(matches)) if len(matches) == 1 else None

    def compiled(self, path):
        """Map a debug-source path using known prefixes, or return None."""
        if not isinstance(path, str) or not path or "\x00" in path:
            return None
        matches = set()
        if os.path.isabs(path):
            paths = {path}
            if path.endswith('.h'):
                # OE removes recipe-sysroot prefixes from compiler headers.
                paths.update(os.path.join(root, path.lstrip('/'))
                             for root in self.external_header_roots)
            # Reverse known compiler prefix mappings, never guess a suffix.
            for old, new in self.prefix_maps:
                suffix = self.suffix(path, new)
                if suffix is not None:
                    paths.add(os.path.join(old, suffix))
            if self.kernel_src_path:
                suffix = self.suffix(path, self.kernel_src_path)
                if suffix is not None:
                    paths.update(os.path.join(root, suffix) for root in self.roots)
            for candidate in paths:
                matches.update(self._physical(candidate))
        else:
            relatives = {path}
            if self.source_package_prefix:
                suffix = self.suffix(path, self.source_package_prefix)
                if suffix is not None:
                    relatives.add(suffix)
            for relative in relatives:
                for root in self.roots:
                    matches.update(self._physical(os.path.join(root, relative)))
        return next(iter(matches)) if len(matches) == 1 else None


def affected_c_files(record, paths):
    """All affected entries must supply exact, resolvable C paths."""
    containers = record.get("containers", {})
    if not isinstance(containers, dict):
        return None
    cna = containers.get("cna", {})
    if not isinstance(cna, dict):
        return None
    entries = cna.get("affected")
    if not isinstance(entries, list) or not entries:
        return None
    # Do not overlook affected paths supplied by an additional data provider.
    providers = containers.get("adp", [])
    if not isinstance(providers, list):
        return None
    for adp in providers:
        if not isinstance(adp, dict):
            return None
        if "affected" in adp:
            extra = adp["affected"]
            if not isinstance(extra, list) or not extra:
                return None
            entries = entries + extra
    files = set()
    for entry in entries:
        if (not isinstance(entry, dict)
                or entry.get("vendor") != "Linux" or entry.get("product") != "Linux"):
            return None
        program_files = entry.get("programFiles")
        if not isinstance(program_files, list) or not program_files:
            return None
        for path in program_files:
            mapped = paths.affected(path)
            if mapped is None:
                return None
            files.add(mapped)
    return files or None


def find_exclusions(datadir, compiled_sources, paths, version, matcher,
                    protected_ids=(), log=lambda level, message: None):
    """Return candidate CVE IDs/details; leave every uncertain case unchanged.

    The caller supplies OE-Core's module for version matching. Keeping that API
    and compiled-source collection outside this module simplifies backports.
    """
    prefix = "CYCLONEDX_VEX_ADD_KERNEL_CVE: "
    if not compiled_sources:
        log("warn", prefix + "no compiled-source debug information; check kernel packaging/source extraction; leaving CVE assessments unchanged")
        return {}
    compiled = set()
    for source in compiled_sources:
        mapped = paths.compiled(source)
        if mapped is None:
            log("warn", prefix + "unmapped or ambiguous debug source %r; check source/build paths and DEBUG_PREFIX_MAP; leaving CVE assessments unchanged" % source)
            return {}
        _, physical_path = mapped
        compiled.add(physical_path)
    try:
        kernel_version = matcher.Version(version.split("+git")[0])
    except (ValueError, TypeError, AttributeError):
        log("warn", prefix + "unrecognized kernel version %r; leaving CVE assessments unchanged" % version)
        return {}

    exclusions = {}
    records = {}
    # A duplicate ID is ambiguous even if one of the records appears eligible.
    for filename in sorted(Path(datadir).rglob("CVE-*.json")):
        records.setdefault(filename.stem, []).append(filename)
    protected_ids = set(protected_ids)
    match_version = matcher.get_cpe_applicability
    for cve_id, filenames in records.items():
        if (cve_id in protected_ids or len(filenames) != 1
                or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id)):
            continue
        try:
            record = json.loads(filenames[0].read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            log(2, prefix + "retaining %s: cannot read CVE record (%s)" % (cve_id, error))
            continue
        if not isinstance(record, dict):
            continue
        metadata = record.get("cveMetadata", {})
        if (not isinstance(metadata, dict) or metadata.get("state") != "PUBLISHED"
                or metadata.get("cveId") != cve_id):
            continue
        affected = affected_c_files(record, paths)
        if not affected or any(physical in compiled for _, physical in affected):
            continue
        # OE's matcher expects well-formed CVE version metadata. Limit handling
        # of malformed data to this boundary so local assessment errors surface.
        try:
            applicability = match_version(record, kernel_version)
        except (ValueError, TypeError, KeyError, IndexError, AttributeError) as error:
            log(2, prefix + "retaining %s: cannot match CVE version metadata (%s)" % (cve_id, error))
            continue
        if applicability[0] is not True:
            continue
        exclusions[cve_id] = (
            "C-only DWARF heuristic: affected files absent from the normalized "
            "compiled-source list: " + ", ".join(sorted(path for path, _ in affected)))
    return exclusions
