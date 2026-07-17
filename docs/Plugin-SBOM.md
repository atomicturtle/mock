---
layout: default
title: Plugin SBOM Generator
---

This plugin generates a Software Bill of Materials (SBOM) in CycloneDX format for packages built with Mock. The SBOM provides detailed information about the build environment, source files, and resulting packages, optimized for security use cases.

## Features

* Generates SBOM in CycloneDX 1.6 format (JSON) and SPDX 2.3 format
* Deep Chroot Integration:
  * Queries the target RPM database via host/bootstrap `rpm --root` using `doOutChroot`
    (same pattern as `package_state` / `buildroot_lock`), avoiding fragile in-chroot RPM.
  * Correctly handles path mapping between chroot and host environments.
* Captures detailed information about:
  * Source files and patches from spec files with a resilient regex-based fallback for legacy/strict syntax errors.
  * Binary RPM metadata with standard PURL and CPE identifiers.
  * Complete build toolchain packages with per-package GPG signature metadata.
  * Runtime dependencies.
  * File hashes (SHA-256).
* Optimized Performance: Consolidated file listing and metadata extraction into a single pass.
* Outputs SBOM in the build results directory.
* Compatible with security scanners (Grype, Trivy, Snyk).
* Standalone CLI: `mock-sbom-generator` can generate an SBOM from a result directory
  without running a full Mock build. The plugin invokes this tool after the build.
* Retains `sbom-prebuild.json` in the result directory as a forensic snapshot of
  pre-build sources/spec metadata.

## Usage

### Basic Usage

The simplest way to use the SBOM generator is to enable it for a single build:

```bash
# Build a package and generate SBOM
mock --enable-plugin=sbom_generator --rebuild package.src.rpm

# Or build from an existing SRPM
mock --enable-plugin=sbom_generator --rebuild ~/rpmbuild/SRPMS/package-1.0-1.fc42.src.rpm

# Specify a chroot configuration
mock --enable-plugin=sbom_generator --rebuild package.src.rpm -r rocky-9-x86_64
```

After the build completes, the SBOM will be available in the build results directory

### Viewing and Analyzing the SBOM

The generated SBOM can be analyzed using various tools:

```bash
# View basic SBOM information
jq '.metadata.component' sbom.cyclonedx.json
jq '.components | length' sbom.cyclonedx.json
jq '.dependencies | length' sbom.cyclonedx.json

# List all built packages
jq '.components[] | select(.type == "library") | {name, version, purl}' sbom.cyclonedx.json

# List source files used in the build
jq '.components[] | select(.properties[]?.name == "mock:source:type") | {name, hashes}' sbom.cyclonedx.json

# View runtime dependencies for a specific package
jq '.dependencies[] | select(.ref | contains("httpd"))' sbom.cyclonedx.json
```

### Using with Security Scanners

The SBOM can be directly used with security vulnerability scanners:

```bash

# Scan with SBOM Auditor
sbom-auditor sbom.cyclonedx.json

# Scan with Grype
grype sbom:./sbom.cyclonedx.json

# Scan with Trivy
trivy sbom sbom.cyclonedx.json

# Export to other formats if needed
syft convert sbom.cyclonedx.json -o spdx-json > sbom.spdx.json
```

## Configuration

### Enabling the Plugin

The plugin is disabled by default. You can enable it in several ways:

**Option 1: Command line (recommended for one-off builds)**
```bash
mock --enable-plugin=sbom_generator --rebuild package.src.rpm
```

**Option 2: Configuration file (for persistent enablement)**

Add to your Mock configuration file (e.g., `/etc/mock/fedora-rawhide-x86_64.cfg`):

```python
config_opts['plugin_conf']['sbom_generator_enable'] = True
config_opts['plugin_conf']['sbom_generator_opts'] = {
    'generate_sbom': True
}
```

**Option 3: User configuration**

Add to `~/.config/mock/mock.cfg`:

```python
config_opts['plugin_conf']['sbom_generator_enable'] = True
```

### Configuration Options

The plugin supports several configuration options to control SBOM generation:

```python
config_opts['plugin_conf']['sbom_generator_opts'] = {
    'generate_sbom': True,              # Enable SBOM generation (default: True)
    'type': 'cyclonedx',                # 'cyclonedx' or 'spdx'
    'command': '/usr/bin/mock-sbom-generator',  # Standalone generator executable
    'include_file_components': True,    # Include file-level components (default: True)
    'include_file_dependencies': False, # Include file-to-package dependencies (default: False)
    'include_debug_files': False,       # Include debug files in file components (default: False)
    'include_man_pages': True,          # Include man pages in file components (default: True)
    'include_toolchain_dependencies': False,  # Include build toolchain in dependencies (default: False)
}
```

**Standalone usage (no Mock build required):**

```bash
mock-sbom-generator --type cyclonedx \
    --resultdir /var/lib/mock/fedora-rawhide-x86_64/result \
    --root /var/lib/mock/fedora-rawhide-x86_64/root
```

**Configuration Options Explained:**

- `type`: SBOM format (`cyclonedx` or `spdx`).
- `command`: Path to the `mock-sbom-generator` executable invoked by the plugin.
- `generate_cpe`: When enabled, emit heuristic CPE identifiers labeled with
  `mock:cpe:confidence=heuristic` (default: `False` — off, to avoid false
  vulnerability matches from fabricated CPEs).
- `include_file_components`: When enabled, creates individual file components for each file in built packages, including hashes, permissions, and ownership information.
- `include_file_dependencies`: Creates dependency relationships showing which files belong to which packages.
- `include_debug_files`: Filters out debug files (`.debug`, files in `/usr/lib/debug`) from file components.
- `include_man_pages`: Filters out man pages from file components.
- `include_toolchain_dependencies`: Adds build toolchain packages to the dependencies array (useful for complete build provenance, but can make dependency graphs very large).

## Output

The plugin generates a file named `<name>-<version>-<release>.sbom` (for CycloneDX) or `<name>-<version>-<release>.spdx.json` (for SPDX) in the build results directory (never a generic name like `plugin.sbom`). The SBOM includes:

* CycloneDX/SPDX document metadata
  * Build timestamp
  * Tool information (Mock SBOM Generator)
  * Mock-specific build properties (host, distribution, chroot, config)
  * Network / isolation status from the live Mock build:
    * `mock:build:network:online` (`config_opts['online']`)
    * `mock:build:network:rpmbuild` (`config_opts['rpmbuild_networking']`)
    * `mock:build:isolation` / `mock:build:nspawn` when set
  * Evidence-backed completeness: `sbom:completeness` is computed from collector
    success (`complete` / `partial` / `minimal`); failures are listed in
    `mock:sbom:collection_errors`
  * Signature status tri-state: `verified` / `present-unverified` / `unsigned`
    (never claims valid without cryptographic check)
  * Host forensics: kernel, SELinux mode, host distribution
  * Sidecar digest: `<sbom>.sha256`
  * RPM header metadata surfaced at the document level (buildhost, buildtime, source RPM, group, epoch, distribution, manufacture/vendor)
* Components array containing:
  * Built packages (type: "library" or "application")
    * Package name, version, and PURL
    * CPE identifiers for vulnerability matching
    * License information plus RPM summary as description
    * RPM file SHA-256 hash
    * Vendor, packager, buildhost, buildtime, source RPM, group, epoch, distribution metadata
    * Upstream/project URLs and source RPM links via `externalReferences`
    * GPG signature details
    * Note: Source tarballs and patches are represented as separate file components in the components array with their own BOM refs for traceability
  * Build toolchain packages (type: "library")
    * All packages installed in the build environment
    * Signature information
    * Marked with `mock:role: "build-toolchain"` property
  * Source files (type: "file")
    * Source and patch files from spec
    * SHA-256 hashes
    * Signature information if available
* Dependencies array
  * Runtime dependencies for built packages (libraries/RPMs the package depends on)
  * Dependency relationships modeled using bom-refs
  * Note: Source code relationships are represented in component properties and the components array, not in the dependencies section (source code is a build input, not a runtime dependency)

### Interpreting auditor WARN findings

When auditing with `sbom-auditor`, some WARN results are expected depending on build policy:

* **Hermetic Build** — PASS only when both `config_opts['online'] = False` and
  `config_opts['rpmbuild_networking'] = False`. Default Mock configs that enable
  network for dependency download correctly score WARN (`online=true`).
* **Build-output signatures** — Freshly built binary RPMs and the *rebuilt*
  result-dir ``*.src.rpm`` correctly report `mock:signature:status=unsigned`.
  Chain-of-custody checks the *input* SRPM from Mock's
  ``builddir/build/originals/`` (captured at prebuild). A signed vendor SRPM
  should appear as a build-input with `mock:source:type=source_rpm`. Toolchain
  packages from the chroot must report `verified` (or `present-unverified` if
  the keyring cannot confirm the key). An all-unsigned toolchain is a generator
  failure.
* **Hardening `pie_enabled=false` / `fips_enabled=false`** — Flags are always
  recorded; a false value is reported but does not by itself fail the audit when
  the property is present.

## Example SBOM Structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-19T15:20:00Z",
    "tools": [
      {
        "vendor": "Mock",
        "name": "mock-sbom-generator",
        "version": "1.0"
      }
    ],
    "properties": [
      { "name": "mock:build:host", "value": "build.example.com" },
      { "name": "mock:build:distribution", "value": "Fedora 42" },
      { "name": "mock:build:chroot", "value": "/var/lib/mock/fedora-42-x86_64/root" },
      { "name": "mock:rpm:buildhost", "value": "builder.fedora.example.org" },
      { "name": "mock:rpm:buildtime", "value": "2024-01-19T15:15:00+00:00" },
      { "name": "mock:rpm:sourcerpm", "value": "package-name-1.0-1.fc42.src.rpm" },
      { "name": "mock:rpm:group", "value": "System Environment/Libraries" },
      { "name": "mock:rpm:epoch", "value": "1" }
    ],
    "manufacture": {
      "name": "Fedora Project"
    },
    "component": {
      "type": "application",
      "name": "package-name",
      "version": "1.0-1.fc42",
      "bom-ref": "build-output:package-name",
      "description": "Package summary (build output containing 3 package(s))",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "externalReferences": [
        { "type": "distribution", "url": "package-name-1.0-1.fc42.src.rpm" },
        { "type": "website", "url": "https://example.com/package-name" }
      ]
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:rpm/fedora/package-name@1.0-1.fc42?arch=x86_64",
      "name": "package-name",
      "version": "1.0-1.fc42",
      "purl": "pkg:rpm/fedora/package-name@1.0-1.fc42?arch=x86_64",
      "externalReferences": [
        {
          "type": "other",
          "comment": "CPE 2.3",
          "url": "cpe:2.3:a:fedora:package-name:1.0:*:*:*:*:*:*:*:*"
        },
        {
          "type": "website",
          "url": "https://src.fedoraproject.org/rpms/package-name"
        },
        {
          "type": "distribution",
          "url": "package-name-1.0-1.fc42.src.rpm"
        }
      ],
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "..."
        }
      ],
      "properties": [
        {
          "name": "mock:rpm:vendor",
          "value": "Fedora Project"
        },
        {
          "name": "mock:rpm:buildhost",
          "value": "builder.fedora.example.org"
        },
        {
          "name": "mock:rpm:buildtime",
          "value": "2024-01-19T15:15:00+00:00"
        },
        {
          "name": "mock:rpm:sourcerpm",
          "value": "package-name-1.0-1.fc42.src.rpm"
        },
        {
          "name": "mock:signature:type",
          "value": "GPG"
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:rpm/fedora/package-name@1.0-1.fc42",
      "dependsOn": [
        "pkg:rpm/fedora/glibc@2.38-1.fc42"
      ]
    }
  ]
}
```

## Security Tool Compatibility

The generated CycloneDX SBOM is compatible with popular security scanners:

* **Grype**: `grype sbom:./sbom.cyclonedx.json`
* **Trivy**: `trivy sbom sbom.cyclonedx.json`
* **Snyk**: Supports CycloneDX format for vulnerability scanning

The SBOM includes PURL (Package URL) and CPE identifiers for accurate vulnerability matching.

## Requirements

* Python 3.x
* Access to build environment for package information
* Native `rpm` and `specfile` libraries (recommended)

## Notes

* The plugin runs in the `postbuild` hook, after the build completes.
* SBOM generation is skipped if no RPM, source RPM, or spec file is found.
* **Hybrid Analysis**: Uses `doChroot` to analyze artifacts within the buildroot (ensuring compatibility with target RPM versions) and host tools for artifacts already exported to the `result/` directory.
* **Resilient Parsing**: Includes a regex-based fallback for spec files that fail strict parsing by the `specfile` library (e.g., legacy `%patchN` syntax).
* **PURL format**: `pkg:rpm/{distro}/{package}@{version}?arch={arch}`. Architecture is always separated into a qualifier, never baked into the version string.
* Mock-specific metadata is stored in properties with the `mock:` prefix.

## Competitive Advantages

This SBOM generator leverages Mock's unique build environment visibility:

* **Complete Build Toolchain**: Captures every package installed in the build chroot, not just declared dependencies
* **Build-Time Provenance**: Records the exact build environment, including tool versions and signatures
* **RPM-Native Intelligence**: Deep integration with RPM metadata, spec files, and package signatures
* **Reproducible Build Context**: Complete build environment fingerprinting for reproducibility verification

Available since version 6.7. 