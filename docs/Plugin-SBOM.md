---
layout: default
title: Plugin SBOM Generator
---

This plugin generates a Software Bill of Materials (SBOM) in CycloneDX format for packages built with Mock. The SBOM provides detailed information about the build environment, source files, and resulting packages, optimized for security use cases.

## Features

* Generates SBOM in CycloneDX 1.5 format (JSON)
* Captures information about:
  * Source files and patches from spec files
  * Binary RPM metadata with PURL and CPE identifiers
  * Complete build toolchain packages
  * Runtime dependencies
  * File hashes (SHA-256)
  * GPG signatures with detailed metadata
* Outputs SBOM as JSON file in the build results directory
* Compatible with security scanners (Grype, Trivy, Snyk)

## Configuration

The plugin is disabled by default. To enable it, add this to your configuration:

```python
config_opts['plugin_conf']['sbom_generator_enable'] = True
config_opts['plugin_conf']['sbom_generator_opts'] = {
    'generate_sbom': True
}
```

You can also enable it for a single build using the command line:

    mock --enable-plugin=sbom_generator --rebuild package.src.rpm

## Output

The plugin generates a file named `sbom.cyclonedx.json` in the build results directory (typically `/var/lib/mock/fedora-42-x86_64/result/`). The SBOM includes:

* CycloneDX document metadata
  * Build timestamp
  * Tool information (Mock SBOM Generator)
  * Mock-specific build properties (host, distribution, chroot, config)
* Components array containing:
  * Built packages (type: "library" or "application")
    * Package name, version, and PURL
    * CPE identifiers for vulnerability matching
    * License information
    * RPM file SHA-256 hash
    * Vendor and packager metadata
    * GPG signature details
  * Build toolchain packages (type: "library")
    * All packages installed in the build environment
    * Signature information
    * Marked with `mock:role: "build-toolchain"` property
  * Source files (type: "file")
    * Source and patch files from spec
    * SHA-256 hashes
    * Signature information if available
* Dependencies array
  * Runtime dependencies for built packages
  * Dependency relationships modeled using bom-refs

## Example SBOM Structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-19T15:20:00Z",
    "tools": [
      {
        "vendor": "Mock",
        "name": "mock-sbom-generator",
        "version": "0.9"
      }
    ],
    "properties": [
      {
        "name": "mock:build:host",
        "value": "build.example.com"
      },
      {
        "name": "mock:build:distribution",
        "value": "Fedora 42"
      }
    ]
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
          "type": "cpe23Type",
          "url": "cpe:2.3:a:fedora:package-name:1.0:*:*:*:*:*:*:*:*"
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
* RPM tools for package metadata extraction
* Access to build environment for package information

## Notes

* The plugin runs in the `postbuild` hook, after the build completes
* SBOM generation is skipped if no RPM, source RPM, or spec file is found
* The plugin is designed to work with both source and binary RPM builds
* Build environment information is collected using `rpm -qa` command
* All build toolchain packages are captured, providing complete build provenance
* PURL format: `pkg:rpm/{distro}/{package}@{version}?arch={arch}`
* Mock-specific metadata is stored in component and metadata properties with `mock:` prefix

## Competitive Advantages

This SBOM generator leverages Mock's unique build environment visibility:

* **Complete Build Toolchain**: Captures every package installed in the build chroot, not just declared dependencies
* **Build-Time Provenance**: Records the exact build environment, including tool versions and signatures
* **RPM-Native Intelligence**: Deep integration with RPM metadata, spec files, and package signatures
* **Reproducible Build Context**: Complete build environment fingerprinting for reproducibility verification

Available since version 6.1. 