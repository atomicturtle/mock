# -*- coding: utf-8 -*-
# vim:expandtab:autoindent:tabstop=4:shiftwidth=4:filetype=python:textwidth=0:
# License: GPL2 or later see COPYING
# Written by Scott R. Shinn <scott@atomicorp.com>
# Copyright (C) 2026, Atomicorp, Inc.
"""Mock plugin that invokes mock-sbom-generator after a successful build."""

import json
import os

from mockbuild.sbom_utils import RpmQueryHelper
from mockbuild.trace_decorator import traceLog
import mockbuild.util

# pylint: disable=invalid-name
requires_api_version = "1.1"
# pylint: enable=invalid-name

DEFAULT_COMMAND = "/usr/bin/mock-sbom-generator"
# Visible forensic artifact retained in the result directory
PREBUILD_STATE_FILENAME = "sbom-prebuild.json"
# Legacy hidden name from earlier builds (still accepted if present)
LEGACY_PREBUILD_STATE_FILENAME = ".sbom-prebuild.json"


@traceLog()
def init(plugins, conf, buildroot):
    """Initializes the SBOM generator plugin."""
    if "type" in conf and conf["type"] not in ("cyclonedx", "spdx"):
        buildroot.root_log.warning(
            "SBOM generator type '%s' not supported, defaulting to 'cyclonedx'",
            conf["type"],
        )
        conf["type"] = "cyclonedx"

    SBOMGeneratorPlugin(plugins, conf, buildroot)


class SBOMGeneratorPlugin:
    """Thin plugin wrapper that captures prebuild state and calls the CLI tool."""

    # pylint: disable=too-few-public-methods
    @traceLog()
    def __init__(self, plugins, conf, buildroot):
        self.buildroot = buildroot
        self.conf = conf
        self.rpm_helper = RpmQueryHelper(self.buildroot)
        self.state = buildroot.state
        self.sbom_enabled = self.conf.get("generate_sbom", True)
        self.sbom_type = self.conf.get("type", "cyclonedx")
        self.command = self.conf.get("command", DEFAULT_COMMAND)
        self.sbom_done = False
        self.prebuild_state_path = os.path.join(
            self.buildroot.resultdir, PREBUILD_STATE_FILENAME
        )

        if self.sbom_enabled:
            plugins.add_hook("prebuild", self._capture_prebuild_state)
            plugins.add_hook("postbuild", self._run_sbom_generator)

    def _capture_input_srpm(self):
        """Record the original (signed) input SRPM from Mock's originals/ tree.

        The result-dir ``*.src.rpm`` is a rebuilt, typically unsigned artifact.
        Chain-of-custody checks must use the pristine input under
        ``<builddir>/originals/`` (honoring ``config_opts['chroothome']``).
        """
        originals_dir = self.buildroot.make_chroot_path(
            self.buildroot.builddir, "originals"
        )
        try:
            return self.rpm_helper.capture_originals_input_srpm(originals_dir)
        except OSError as exc:
            self.buildroot.root_log.warning(
                "[SBOM] Failed scanning originals for input SRPM: %s", exc
            )
        return None

    @traceLog()
    def _capture_prebuild_state(self):
        """Captures pristine source artifacts before the build begins.

        Runs under ``uid_manager`` (mockbuild) and refuses to follow symlinks
        that escape the chroot when hashing SPECS/SOURCES/originals.
        """
        self.buildroot.root_log.debug("Capturing pre-build state from SPECS and SOURCES")
        specs_dir = self.buildroot.make_chroot_path(self.buildroot.builddir, "SPECS")
        state = {
            "spec_metadata": {},
            "source_files": [],
            "input_srpm": None,
            "build_env": self._build_env_snapshot(),
            "capture_errors": [],
        }
        try:
            with self.buildroot.uid_manager:
                specs_safe = (
                    bool(specs_dir)
                    and os.path.exists(specs_dir)
                    and self.rpm_helper.path_stays_in_chroot(specs_dir)
                )
                if specs_dir and os.path.exists(specs_dir) and not specs_safe:
                    msg = "SPECS directory resolves outside the build chroot"
                    state["capture_errors"].append(msg)
                    self.buildroot.root_log.warning("[SBOM] %s", msg)
                elif specs_safe:
                    try:
                        with os.scandir(specs_dir) as entries:
                            for entry in entries:
                                if entry.is_symlink():
                                    self.buildroot.root_log.warning(
                                        "[SBOM] Skipping symlink in SPECS: %s",
                                        entry.path,
                                    )
                                    continue
                                if entry.name.endswith(".spec") and entry.is_file(
                                    follow_symlinks=False
                                ):
                                    self.buildroot.root_log.debug(
                                        "Parsing spec file for pre-build state: %s",
                                        entry.path,
                                    )
                                    try:
                                        metadata, sources = (
                                            self.rpm_helper.parse_spec_file(
                                                entry.path
                                            )
                                        )
                                        state["spec_metadata"] = metadata
                                        state["source_files"] = sources
                                        if not (metadata or {}).get("name"):
                                            msg = (
                                                "spec parse produced empty name "
                                                f"for {entry.path}"
                                            )
                                            state["capture_errors"].append(msg)
                                            self.buildroot.root_log.warning(
                                                "[SBOM] %s", msg
                                            )
                                    except Exception as exc:  # pylint: disable=broad-exception-caught
                                        msg = (
                                            f"Failed parsing spec {entry.path}: {exc}"
                                        )
                                        state["capture_errors"].append(msg)
                                        self.buildroot.root_log.warning(
                                            "[SBOM] %s", msg
                                        )
                                    break
                    except OSError as exc:
                        msg = f"Failed scanning SPECS directory: {exc}"
                        state["capture_errors"].append(msg)
                        self.buildroot.root_log.warning("[SBOM] %s", msg)
                else:
                    msg = "SPECS directory does not exist for pre-build capture"
                    state["capture_errors"].append(msg)
                    self.buildroot.root_log.warning("[SBOM] %s", msg)

                # Always attempt input-SRPM capture even if spec parsing failed.
                input_srpm = self._capture_input_srpm()
                if input_srpm:
                    state["input_srpm"] = input_srpm
                    sources = list(state.get("source_files") or [])
                    if not any(
                        e.get("source_type") == "source_rpm"
                        or (
                            e.get("role") == "input"
                            and (e.get("filename") or "").endswith(".src.rpm")
                        )
                        for e in sources
                    ):
                        sources.insert(0, input_srpm)
                        state["source_files"] = sources
                    self.buildroot.root_log.debug(
                        "[SBOM] Captured input SRPM %s (%s)",
                        input_srpm.get("filename"),
                        (input_srpm.get("digital_signature") or {}).get(
                            "signature_status", "unknown"
                        ),
                    )
                else:
                    # Spec-file builds often have no originals/ SRPM; only treat
                    # that as a capture gap when we also lack usable spec metadata.
                    if not (state.get("spec_metadata") or {}).get("name"):
                        msg = (
                            "No input SRPM found under the chroot originals/ directory"
                        )
                        state["capture_errors"].append(msg)
                        self.buildroot.root_log.warning("[SBOM] %s", msg)
                    else:
                        self.buildroot.root_log.debug(
                            "[SBOM] No input SRPM under originals/ "
                            "(spec-based build; skipping capture error)"
                        )

                os.makedirs(self.buildroot.resultdir, exist_ok=True)
                with open(self.prebuild_state_path, "w", encoding="utf-8") as handle:
                    json.dump(state, handle, indent=2)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.buildroot.root_log.warning(
                "Failed to capture pre-build state: %s", exc
            )
            # Still write a stub so postbuild can record the failure
            try:
                state["capture_errors"].append(str(exc))
                os.makedirs(self.buildroot.resultdir, exist_ok=True)
                with open(self.prebuild_state_path, "w", encoding="utf-8") as handle:
                    json.dump(state, handle, indent=2)
            except OSError:
                pass

    def _resolve_config_file(self):
        """Return the primary mock config *file* path (not the config directory)."""
        config = self.buildroot.config
        # Prefer the full list of loaded config files; last non-site file is usually
        # the chroot cfg the user selected.
        paths = list(config.get("config_paths") or [])
        for candidate in reversed(paths):
            if not candidate:
                continue
            base = os.path.basename(candidate)
            if base in ("site-defaults.cfg", "logging.ini"):
                continue
            if os.path.isfile(candidate):
                return candidate
        # Fallbacks
        for key in ("config_file", "chroot_name"):
            val = config.get(key)
            if val and os.path.isfile(str(val)):
                return str(val)
        # config_path is the search directory (/etc/mock) — only use if a matching
        # chroot cfg exists beneath it.
        config_dir = config.get("config_path")
        root = config.get("root") or config.get("chroot_name")
        if config_dir and root:
            candidate = os.path.join(str(config_dir), f"{root}.cfg")
            if os.path.isfile(candidate):
                return candidate
        return None

    def _build_env_snapshot(self):
        """Snapshot Mock network/isolation settings for the SBOM.

        Always records effective isolation / use_nspawn (resolved defaults),
        not only when the keys were explicitly set in config.
        """
        config = self.buildroot.config
        env = {
            "online": bool(config.get("online", True)),
            "rpmbuild_networking": bool(config.get("rpmbuild_networking", False)),
        }
        isolation = config.get("isolation")
        use_nspawn = config.get("use_nspawn")

        # Keep isolation and use_nspawn consistent. Explicit isolation wins;
        # only None/auto derive from Mock's resolved runtime backend.
        if isolation == "simple":
            use_nspawn = False
        elif isolation == "nspawn":
            use_nspawn = True
        else:
            # isolation is None or "auto"
            if use_nspawn is None:
                use_nspawn = bool(mockbuild.util.USE_NSPAWN)
            isolation = "nspawn" if use_nspawn else "simple"

        env["isolation"] = str(isolation)
        env["use_nspawn"] = bool(use_nspawn)
        return env

    def _append_build_env_args(self, cmd):
        """Forward live Mock network/isolation settings into the generator CLI."""
        env = self._build_env_snapshot()
        cmd.extend(["--online", "true" if env["online"] else "false"])
        cmd.extend([
            "--rpmbuild-networking",
            "true" if env["rpmbuild_networking"] else "false",
        ])
        cmd.extend(["--isolation", str(env["isolation"])])
        cmd.extend([
            "--use-nspawn",
            "true" if env["use_nspawn"] else "false",
        ])

    def _prebuild_json_path(self):
        """Return the prebuild JSON path, accepting the legacy hidden name."""
        if os.path.isfile(self.prebuild_state_path):
            return self.prebuild_state_path
        legacy = os.path.join(self.buildroot.resultdir, LEGACY_PREBUILD_STATE_FILENAME)
        if os.path.isfile(legacy):
            return legacy
        return None

    @traceLog()
    def _run_sbom_generator(self):
        """Invoke the standalone mock-sbom-generator executable."""
        if self.sbom_done or not self.sbom_enabled:
            return

        state_text = f"Generating {self.sbom_type.upper()} SBOM for built packages"
        self.state.start(state_text)
        try:
            cmd = [
                self.command,
                "--type",
                self.sbom_type,
                "--resultdir",
                self.buildroot.resultdir,
                "--root",
                self.buildroot.make_chroot_path(),
                "--builddir",
                self.buildroot.builddir,
            ]
            prebuild = self._prebuild_json_path()
            if prebuild:
                cmd.extend(["--prebuild-json", prebuild])

            for key in (
                "include_file_components",
                "include_file_dependencies",
                "include_debug_files",
                "include_man_pages",
                "include_source_dependencies",
                "include_toolchain_dependencies",
                "generate_cpe",
            ):
                if key in self.conf:
                    flag = "--" + key.replace("_", "-")
                    value = "true" if self.conf[key] else "false"
                    cmd.extend([flag, value])

            mock_version = self.buildroot.config.get("version")
            if mock_version:
                cmd.extend(["--mock-version", str(mock_version)])

            config_file = self._resolve_config_file()
            if config_file:
                cmd.extend(["--mock-config", config_file])

            # Critical build-environment datapoints for SBOM consumers
            self._append_build_env_args(cmd)

            self.buildroot.root_log.debug("Running SBOM generator: %s", " ".join(cmd))
            with self.buildroot.uid_manager:
                mockbuild.util.do(cmd, shell=False)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # Best-effort forensic step: never fail the Mock build over SBOM.
            self.buildroot.root_log.warning("SBOM generation failed: %s", exc)
        finally:
            self.sbom_done = True
            # Keep the prebuild snapshot as a forensic artifact in resultdir.
            self.state.finish(state_text)
