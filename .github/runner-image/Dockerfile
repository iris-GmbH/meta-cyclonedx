# SPDX-License-Identifier: MIT
#
# The acceptance runner Pod *is* this image: a complete kas build host
# that doubles as a GitHub Actions runner, so acceptance jobs exec the
# image-installed kas directly (direct mode) — no nested container
# engine, no privileged Pod.
#
# The base is the kas project's release image at the version the
# tools/kas submodule pin names; the harness's version tie enforces the
# equality at run time, so a pin bump and an image rebuild ride the same
# PR. The build workflow (runner-image.yml) resolves the pin and passes
# it as KAS_TAG; it publishes to this repository's own package
# namespace, so fork and upstream need no cross-repo package trust.

ARG KAS_TAG=5.5
FROM ghcr.io/siemens/kas/kas:${KAS_TAG}

# Pin the runner binary here; the build workflow reads this value to
# form the image tag (<kas-tag>-<runner-version>).
ARG RUNNER_VERSION=2.338.1
ARG RUNNER_ARCH=x64

# pytest runs the harness; jsonschema validates the deployed documents
# (the integration layer's only extra dependency); ICU and OpenSSL back
# the runner's .NET host.
RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        python3-pytest python3-jsonschema libicu-dev libssl-dev && \
    rm -rf /var/log/* /var/tmp/* /var/cache/apt/archives

# The Actions runner binary, owned by the image's build user (BitBake
# refuses to run as root). Registration/scale-set wiring stays
# operator-side; this image only carries the binary.
RUN curl -fSsL -o /tmp/actions-runner.tar.gz \
        "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz" && \
    mkdir -p /builder/actions-runner && \
    tar -xzf /tmp/actions-runner.tar.gz -C /builder/actions-runner && \
    rm /tmp/actions-runner.tar.gz && \
    chown -R builder:builder /builder/actions-runner

WORKDIR /builder
