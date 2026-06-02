#!/usr/bin/env python3

"""
SPDX-License-Identifier: CC0-1.0
SPDX-FileCopyrightText: No Rights Reserved
Full license text: http://creativecommons.org/publicdomain/zero/1.0/

Upload CycloneDX SBOM and VEX files to DependencyTrack.

This script is designed to be idempotent and safe to retry from CI/CD pipelines.
It will:
  1. Ensure the project/version exists:
     a. If the version already exists, skip creation (idempotent re-run).
     b. If a latest version exists, clone it to preserve tags, properties,
        audit history, ACL, and policy violations.
     c. If no project exists at all, create one from scratch (first version).
  2. Upload the SBOM and wait for processing to complete.
  3. Optionally upload the VEX and wait for processing to complete.

The clone deliberately excludes components, dependencies, and services because
the SBOM upload replaces them.  Cloning stale data would leave the project in
an inconsistent state if the upload subsequently fails.

Required environment variables:
  DEPENDENCY_TRACK_URL          - Base API URL (e.g. https://dtrack.example.com/api)
  DEPENDENCY_TRACK_TOKEN        - API key with BOM_UPLOAD + PORTFOLIO_MANAGEMENT +
                                  VULNERABILITY_ANALYSIS permissions
  DEPENDENCY_TRACK_PROJECT_NAME - Project name in DependencyTrack
  VERSION                       - Project version string

Usage:
  python3 upload-to-dependency-track.py <sbom_file> [<vex_file>]
"""

import argparse
import base64
import logging
import os
import sys
import time

import requests
import semantic_version

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
POLL_INTERVAL_SECONDS = 2
POLL_TIMEOUT_SECONDS = 300  # 5 minutes max wait for processing


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        log.error("Required environment variable %s is not set", name)
        sys.exit(1)
    return value


def parse_version(version_str: str) -> semantic_version.Version:
    """Parse a version string into a semantic_version.Version.

    Strips a leading 'v' prefix if present.  Raises ValueError if the
    resulting string is not valid semantic versioning.
    """
    stripped = version_str.lstrip("v")
    try:
        return semantic_version.Version(stripped)
    except ValueError:
        raise ValueError(
            f"Version '{version_str}' (stripped: '{stripped}') "
            f"is not a valid semantic version"
        )


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------
class DependencyTrackClient:
    def __init__(self, base_url: str, api_key: str):
        # Strip trailing slash for consistent URL building
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "X-Api-Key": api_key,
        })

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    # -- Project operations ------------------------------------------------

    def lookup_project(self, name: str, version: str) -> dict | None:
        """Look up a project by name and version.

        Returns the project dict or None if it doesn't exist.
        """
        resp = self.session.get(
            self._url("/v1/project/lookup"),
            params={"name": name, "version": version},
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def get_latest_project(self, name: str) -> dict | None:
        """Get the latest version of a project by name.

        Returns the project dict or None if no project with that name exists.
        """
        resp = self.session.get(self._url(f"/v1/project/latest/{name}"))
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def clone_project(
        self, source_uuid: str, new_version: str, *, is_latest: bool,
    ) -> str:
        """Clone an existing project version.

        Preserves tags, properties, audit history, ACL, and policy violations.
        Skips components, dependencies, and services (replaced by SBOM upload).

        Returns the processing token.
        """
        payload = {
            "project": source_uuid,
            "version": new_version,
            "includeTags": True,
            "includeProperties": True,
            "includeAuditHistory": True,
            "includeACL": True,
            "includePolicyViolations": True,
            "includeComponents": False,
            "includeDependencies": False,
            "includeServices": False,
            "makeCloneLatest": is_latest,
        }
        resp = self.session.put(
            self._url("/v1/project/clone"),
            json=payload,
        )
        resp.raise_for_status()
        token = resp.json()["token"]
        log.info("Clone accepted, processing token: %s", token)
        return token

    def create_project(
        self, name: str, version: str, *, is_latest: bool,
    ) -> dict:
        """Create a brand-new project (used only for the very first version)."""
        payload = {
            "name": name,
            "version": version,
            "classifier": "OPERATING_SYSTEM",
            "active": True,
            "isLatest": is_latest,
        }
        resp = self.session.put(
            self._url("/v1/project"),
            json=payload,
        )
        # 409 means a project with the same name/version already exists.
        # That is fine for idempotency – just look it up instead.
        if resp.status_code == 409:
            log.info("Project %s %s already exists (409), looking it up", name, version)
            project = self.lookup_project(name, version)
            if project is None:
                raise RuntimeError(
                    f"Got 409 creating project but lookup returned 404 for {name} {version}"
                )
            return project
        resp.raise_for_status()
        return resp.json()

    def ensure_project_version(self, name: str, version: str) -> dict:
        """Return the project version, creating it by clone or from scratch.

        Logic:
          1. If the target version already exists -> return it (idempotent).
          2. If a "latest" version exists        -> clone it.
          3. Otherwise                           -> create from scratch.

        The ``isLatest`` / ``makeCloneLatest`` flag is only set when the new
        version is strictly greater than the current latest (compared as
        semantic versions with any leading ``v`` stripped).
        """
        new_semver = parse_version(version)

        # 1. Already exists?
        project = self.lookup_project(name, version)
        if project is not None:
            log.info(
                "Project '%s' version '%s' already exists (uuid=%s)",
                name, version, project["uuid"],
            )
            return project

        # 2. Clone from latest?
        latest = self.get_latest_project(name)
        if latest is not None:
            latest_semver = parse_version(latest["version"])
            is_latest = new_semver > latest_semver
            log.info(
                "Cloning from latest version '%s' (uuid=%s), "
                "new version will%s be marked as latest",
                latest["version"], latest["uuid"],
                "" if is_latest else " NOT",
            )
            clone_token = self.clone_project(
                latest["uuid"], version, is_latest=is_latest,
            )
            self.wait_for_token(clone_token, label="Clone")

            # Look up the newly created version
            project = self.lookup_project(name, version)
            if project is None:
                raise RuntimeError(
                    f"Clone completed but lookup returned 404 for {name} {version}"
                )
            log.info("Cloned project uuid=%s", project["uuid"])
            return project

        # 3. First-ever version — create from scratch (always latest)
        log.info(
            "No existing project '%s' found, creating first version '%s'",
            name, version,
        )
        project = self.create_project(name, version, is_latest=True)
        log.info("Created project uuid=%s", project["uuid"])
        return project

    # -- BOM upload --------------------------------------------------------

    def upload_bom(self, project_uuid: str, bom_path: str) -> str:
        """Upload a CycloneDX BOM file.  Returns the processing token."""
        log.info("Uploading SBOM from %s", bom_path)
        with open(bom_path, "rb") as f:
            bom_content = f.read()

        bom_b64 = base64.b64encode(bom_content).decode("ascii")

        payload = {
            "project": project_uuid,
            "bom": bom_b64,
        }
        resp = self.session.put(
            self._url("/v1/bom"),
            json=payload,
        )
        resp.raise_for_status()
        token = resp.json()["token"]
        log.info("SBOM upload accepted, processing token: %s", token)
        return token

    # -- VEX upload --------------------------------------------------------

    def upload_vex(self, project_uuid: str, vex_path: str) -> str:
        """Upload a CycloneDX VEX file.  Returns the processing token."""
        log.info("Uploading VEX from %s", vex_path)
        with open(vex_path, "rb") as f:
            vex_content = f.read()

        vex_b64 = base64.b64encode(vex_content).decode("ascii")

        payload = {
            "project": project_uuid,
            "vex": vex_b64,
        }
        resp = self.session.put(
            self._url("/v1/vex"),
            json=payload,
        )
        resp.raise_for_status()
        token = resp.json()["token"]
        log.info("VEX upload accepted, processing token: %s", token)
        return token

    # -- Processing status -------------------------------------------------

    def wait_for_token(self, token: str, label: str = "task") -> None:
        """Poll the event/token endpoint until processing is complete."""
        log.info("Waiting for %s processing to complete (token=%s) ...", label, token)
        deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            resp = self.session.get(self._url(f"/v1/event/token/{token}"))
            resp.raise_for_status()
            processing = resp.json().get("processing", False)
            if not processing:
                log.info("%s processing complete", label)
                return
            time.sleep(POLL_INTERVAL_SECONDS)

        raise TimeoutError(
            f"{label} processing did not complete within {POLL_TIMEOUT_SECONDS}s "
            f"(token={token})"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Upload CycloneDX SBOM and VEX to DependencyTrack",
    )
    parser.add_argument("sbom_file", help="Path to the CycloneDX SBOM JSON file")
    parser.add_argument("vex_file", nargs="?", default=None,
                        help="Path to the CycloneDX VEX JSON file (optional)")
    args = parser.parse_args()

    # Validate files exist early
    if not os.path.isfile(args.sbom_file):
        log.error("File not found: %s", args.sbom_file)
        sys.exit(1)
    if args.vex_file is not None and not os.path.isfile(args.vex_file):
        log.error("File not found: %s", args.vex_file)
        sys.exit(1)

    api_url = require_env("DEPENDENCY_TRACK_URL")
    api_key = require_env("DEPENDENCY_TRACK_TOKEN")
    project_name = require_env("DEPENDENCY_TRACK_PROJECT_NAME")
    version = require_env("VERSION")

    # Validate version early so we fail fast on bad input
    parse_version(version)

    client = DependencyTrackClient(api_url, api_key)

    # Step 1 – Ensure the project/version exists (clone from latest or create)
    project = client.ensure_project_version(project_name, version)
    project_uuid = project["uuid"]

    # Step 2 – Upload SBOM and wait for processing
    bom_token = client.upload_bom(project_uuid, args.sbom_file)
    client.wait_for_token(bom_token, label="SBOM")

    # Step 3 – Upload VEX and wait for processing (optional)
    # The VEX must be uploaded after the SBOM has been fully processed so that
    # DependencyTrack can match vulnerability analyses to known components.
    if args.vex_file is not None:
        vex_token = client.upload_vex(project_uuid, args.vex_file)
        client.wait_for_token(vex_token, label="VEX")
    else:
        log.info("No VEX file provided, skipping VEX upload")

    log.info("Done. Project '%s' version '%s' is up to date.", project_name, version)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log.error("Fatal: %s", exc)
        sys.exit(1)
