#! /usr/bin/python3
# -*- coding: utf-8 -*-
# vim:expandtab:autoindent:tabstop=4:shiftwidth=4:filetype=python:textwidth=0:
# License: GPL2 or later see COPYING
# Written by Scott R. Shinn <scott@atomicorp.com>
# Copyright (C) 2026, Atomicorp, Inc.
# pylint: disable=invalid-name
"""
Generate a CycloneDX or SPDX SBOM from Mock build artifacts.

This tool is usable without running the full Mock toolchain.  Given a result
directory (and optionally a chroot root for toolchain/macro queries), it
produces the same SBOM artifacts as the sbom_generator plugin.
"""

import argparse
import json
import logging
import os
import subprocess
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("mock-sbom-generator")


class _SimpleLog:
    """Tiny logger duck-typed like buildroot.root_log."""

    def debug(self, msg, *args, **_kwargs):
        log.debug(msg, *args)

    def info(self, msg, *args, **_kwargs):
        log.info(msg, *args)

    def warning(self, msg, *args, **_kwargs):
        log.warning(msg, *args)

    def error(self, msg, *args, **_kwargs):
        log.error(msg, *args)


class StandaloneContext:
    """Minimal buildroot duck-type for standalone SBOM generation."""

    def __init__(self, rootdir, resultdir, mock_version=None, mock_config=None,
                 online=True, rpmbuild_networking=False, isolation=None, use_nspawn=None):
        self.rootdir = os.path.abspath(rootdir)
        self.resultdir = os.path.abspath(resultdir)
        self.builddir = os.path.join(self.rootdir, "builddir")
        self.root_log = _SimpleLog()
        self.state = None
        self.config = {
            "version": mock_version or "unknown",
            "config_path": mock_config or "standalone",
            "online": online,
            "rpmbuild_networking": rpmbuild_networking,
        }
        if isolation is not None:
            self.config["isolation"] = isolation
        if use_nspawn is not None:
            self.config["use_nspawn"] = use_nspawn

    def make_chroot_path(self, *paths):
        new_path = self.rootdir
        for path in paths:
            if path.startswith("/"):
                path = path[1:]
            new_path = os.path.join(new_path, path)
        return new_path

    def from_chroot_path(self, host_path):
        if host_path.startswith(self.rootdir):
            rel_path = host_path[len(self.rootdir):]
            if not rel_path.startswith("/"):
                rel_path = "/" + rel_path
            return rel_path
        return host_path

    def doOutChroot(self, command, *args, **kwargs):  # pylint: disable=invalid-name,unused-argument
        """Execute command on the host (standalone has no bootstrap chroot)."""
        shell = kwargs.pop("shell", False)
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        result = subprocess.run(
            command,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            env=env,
        )
        return result.stdout, result.returncode


def _parse_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _argparser():
    parser = argparse.ArgumentParser(
        description="Generate CycloneDX/SPDX SBOM from RPM build artifacts.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--type",
        choices=("cyclonedx", "spdx"),
        default="cyclonedx",
        help="SBOM document format",
    )
    parser.add_argument(
        "--resultdir",
        required=True,
        help="Directory containing built RPMs/SRPMs (Mock result dir)",
    )
    parser.add_argument(
        "--root",
        default="/",
        help="Path to the build chroot root (for toolchain/macro queries)",
    )
    parser.add_argument(
        "--prebuild-json",
        help="Optional JSON file with prebuild spec metadata and source files",
    )
    parser.add_argument("--mock-version", help="Mock version recorded in SBOM metadata")
    parser.add_argument("--mock-config", help="Mock config path recorded in SBOM metadata")
    parser.add_argument(
        "--online",
        default=None,
        help="Whether Mock had network access (config_opts['online'])",
    )
    parser.add_argument(
        "--rpmbuild-networking",
        default=None,
        help="Whether rpmbuild phases had network (config_opts['rpmbuild_networking'])",
    )
    parser.add_argument(
        "--isolation",
        default=None,
        help="Mock isolation mode (e.g. nspawn, simple, auto)",
    )
    parser.add_argument(
        "--use-nspawn",
        default=None,
        help="Whether systemd-nspawn was used for the build",
    )
    parser.add_argument("--include-file-components", default="true")
    parser.add_argument("--include-file-dependencies", default="false")
    parser.add_argument("--include-debug-files", default="false")
    parser.add_argument("--include-man-pages", default="true")
    parser.add_argument("--include-source-dependencies", default="true")
    parser.add_argument("--include-toolchain-dependencies", default="false")
    parser.add_argument(
        "--generate-cpe",
        default="false",
        help="Emit heuristic CPE identifiers (default: false; labeled confidence=heuristic)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    return parser


def main(argv=None):
    parser = _argparser()
    args = parser.parse_args(argv)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not os.path.isdir(args.resultdir):
        log.error("Result directory does not exist: %s", args.resultdir)
        return 1

    prebuild_source_files = []
    prebuild_spec_metadata = {}
    prebuild_capture_errors = []
    prebuild_input_srpm = None
    build_env = {}
    if args.prebuild_json and os.path.isfile(args.prebuild_json):
        with open(args.prebuild_json, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        prebuild_source_files = state.get("source_files") or []
        prebuild_spec_metadata = state.get("spec_metadata") or {}
        prebuild_capture_errors = state.get("capture_errors") or []
        prebuild_input_srpm = state.get("input_srpm")
        build_env = state.get("build_env") or {}

    # CLI flags override values captured in prebuild JSON when provided.
    online = (
        _parse_bool(args.online) if args.online is not None
        else build_env.get("online", True)
    )
    rpmbuild_networking = (
        _parse_bool(args.rpmbuild_networking) if args.rpmbuild_networking is not None
        else build_env.get("rpmbuild_networking", False)
    )
    isolation = args.isolation if args.isolation is not None else build_env.get("isolation")
    if args.use_nspawn is not None:
        use_nspawn = _parse_bool(args.use_nspawn)
    elif "use_nspawn" in build_env:
        use_nspawn = build_env.get("use_nspawn")
    else:
        use_nspawn = None

    conf = {
        "generate_sbom": True,
        "type": args.type,
        "include_file_components": _parse_bool(args.include_file_components),
        "include_file_dependencies": _parse_bool(args.include_file_dependencies),
        "include_debug_files": _parse_bool(args.include_debug_files),
        "include_man_pages": _parse_bool(args.include_man_pages),
        "include_source_dependencies": _parse_bool(args.include_source_dependencies),
        "include_toolchain_dependencies": _parse_bool(args.include_toolchain_dependencies),
        "generate_cpe": _parse_bool(args.generate_cpe),
    }

    context = StandaloneContext(
        rootdir=args.root,
        resultdir=args.resultdir,
        mock_version=args.mock_version,
        mock_config=args.mock_config,
        online=online,
        rpmbuild_networking=rpmbuild_networking,
        isolation=isolation,
        use_nspawn=use_nspawn,
    )
    # Late import so argparse-manpage can load this module without rpm bindings.
    from mockbuild.sbom_generate import SBOMGenerator

    generator = SBOMGenerator(
        conf,
        context,
        prebuild_source_files=prebuild_source_files,
        prebuild_spec_metadata=prebuild_spec_metadata,
        prebuild_capture_errors=prebuild_capture_errors,
        prebuild_input_srpm=prebuild_input_srpm,
    )
    generator.generate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
