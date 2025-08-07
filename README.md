# meta-cyclonedx

`meta-cyclonedx` is a [Yocto](https://www.yoctoproject.org/) meta-layer which
produces [CycloneDX](https://cyclonedx.org/) Software Bill of Materials
(aka [SBOMs](https://www.ntia.gov/SBOM)) from your target root filesystem.

This repository was originally forked from
[BG Networks repository](https://github.com/bgnetworks/meta-dependencytrack)
but differs by the following:

- Direct integration with DependencyTrack has been removed in favor of generic
  CycloneDX support.
- Support for multiple supported Yocto (LTS) releases.
- Improved package matching against the [NIST NVD](https://nvd.nist.gov/) by
  fixing [CPE](https://nvd.nist.gov/products/cpe) generation process.
- Included [purl](https://github.com/package-url/purl-spec) package URLs.
- Added generation of an additional CycloneDX VEX file which contains
  information on patched and ignored CVEs from within the OpenEmbedded build
  system.
- Added option to reduce the SBOM size by limiting SBOM collection to run-time
  packages ([which might potentially come at some expense](#potentially-missing-packages-after-runtime-filtering))

## Installation

To install this meta-layer simply clone the repository into the `sources`
directory, check out the corresponding branch for your Yocto release
(e.g. scarthgap, kirkstone, ...)
and add it to your `build/conf/bblayers.conf` file:

```sh
$ cd sources
$ git clone https://github.com/iris-GmbH/meta-cyclonedx.git
$ cd meta-cyclonedx
$ git checkout <YOCTO_RELEASE>
```

and in your `bblayers.conf` file:

```sh
BBLAYERS += "${BSPDIR}/sources/meta-cyclonedx"
```

## Configuration

To enable and configure the layer simply inherit the `cyclonedx-export` class
in your `local.conf` file and then set the following variable:

```sh
INHERIT += "cyclonedx-export"
```

On kirkstone, meta-cyclonedx will include build-time as well as run-time
packages in the SBOM by default. Via an optional configuration flag, you
can limit this to run-time packages, which drastically reduces the number
of potentially irrelevant packages.
However, this can lead to valid packages being omitted from the SBOM
(see [here](#potentially-missing-packages-after-runtime-filtering)).
Add the following configuration setting to enable this feature
(e.g in your local.conf):

```
CYCLONEDX_RUNTIME_PACKAGES_ONLY = "1"
```

## Usage

Once everything is configured simply build your image as you normally would.
By default the final CycloneDX SBOMs are saved to the folder
`${DEPLOY_DIR}/${PN}/cyclonedx-export` as `bom.json` and `vex.json`
respectively.

## Uploading to DependencyTrack (tested against DT v4.11.4)

While this layer does not offer a direct integration with DependencyTrack
(we consider that a feature, since it removes dependencies to external
infrastructure in your build),
it is perfectly possible to use the produced SBOMs within DependencyTrack.

At the time of writing DependencyTrack does not support uploading component
and vulnerability information in one go (which is why we currently create a
separate `vex.json` file). The status on supporting this may be tracked
[here](https://github.com/DependencyTrack/dependency-track/issues/919).

### Manual Upload

1. Go into an existing project in your DependencyTrack instance or create a new
   one.
2. Go to the _Components_ tab and click _Upload BOM_.
3. Select the `bom.json` file from your deploy directory.
4. Wait for the vulnerability analysis to complete.
5. Go to the _Audit Vulnerabilities_ tab and click _Apply VEX_.
6. Select the `vex.json` file from your deploy directory.

### Automated Upload

You may want to script the upload of the SBOM files to DependencyTrack,
e.g. as part of a CI job that runs after your build is complete.

This is possible by leveraging DependencyTracks REST API.

At the time of writing this can be done by leveraging the following API
endpoints:

1. `/v1/bom` for uploading the `bom.json`.
2. `/v1/event/token/{uuid}` for checking the status on the `bom.json`
   processing.
3. `/v1/vex` for uploading the `vex.json`.

Please refer to [DependencyTracks REST API documentation](https://docs.dependencytrack.org/integrations/rest-api/)
regarding the usage of these endpoints as well as the required token
permissions.

In the future we might include an example script in this repository.

## Known Limitations

### Potentially Missing Packages After Run-time Filtering

We use the `image_list_installed_packages` function from upstream
OpenEmbedded as a means to reduce the SBOM contents to packages that are added
to the final resulting rootfs. This drastically reduces the "noise" generated
by CVEs in build-time dependencies. This however comes with some potential
downsides (i.e. Missing some packages), as discussed
[here](https://github.com/savoirfairelinux/meta-cyclonedx/issues/9#issue-2494183505).

### Missing Dependencies with Modern Programming Languages

OpenEmbedded and its core mechanisms work best with "traditional" programming
languages such as C and C++, as these are the languages that they were initially
designed around. For instance, a core-assumption prevalent in many OE mechanisms
(including those we depend on in meta-cyclonedx) is that each library is
described in its own OE recipe. This however does not work well with many
modern programming languages, which often come with their own package managers
(e.g. NPM, Cargo, Go Modules, ...), which do not necessarily integrate well
into the OpenEmbedded ecosystem and depend of potentially hundreds of external
dependencies (good luck writing a separate OE recipe for each dependency in a
small-medium sized Node.js project).

Thus, if you rely on packages written in programming languages that come with
their own package managers, you might be better off with a divide and
conquer approach for covering their packages as well (your mileage may vary):

1. Use this meta-layer to generate a CycloneDX SBOM which covers your OE-based
   operating system, system libraries, etc.
2. Use tools designed explicitly for generating CycloneDX SBOMs for these
   languages (e.g. [Rust](https://github.com/CycloneDX/cyclonedx-rust-cargo),
   [NPM](https://github.com/CycloneDX/cyclonedx-node-npm),
   [Golang](https://github.com/CycloneDX/cyclonedx-gomod), ...)
3. Optionally, use some glue code to merge the SBOMs together
   ([cyclonedx-cli](https://github.com/CycloneDX/cyclonedx-cli) offers merge
   functionality)
