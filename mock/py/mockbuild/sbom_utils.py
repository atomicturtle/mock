# -*- coding: utf-8 -*-
# vim:expandtab:autoindent:tabstop=4:shiftwidth=4:filetype=python:textwidth=0:
# License: GPL2 or later see COPYING
# Written by Scott R. Shinn <scott@atomicorp.com>
# Copyright (C) 2026, Atomicorp, Inc.

import os
import re
import subprocess
import hashlib
import json
import traceback
import rpm
from datetime import datetime, timezone

"""
Utility functions for SBOM generation.

This module is a library (not a plugin).  Prefer host/bootstrap RPM via
doOutChroot() — same pattern as package_state and buildroot_lock — rather than
running rpm inside the target buildroot with doChroot().
"""


class RpmQueryHelper:
    # pylint: disable=broad-exception-caught
    """Helper class for querying RPM metadata."""

    def __init__(self, buildroot):
        """Initializes the helper with a buildroot for doOutChroot access."""
        self.buildroot = buildroot

    def _run_out_chroot(self, cmd, shell=False):
        """Run a command on the host or in the bootstrap chroot (not the target)."""
        if hasattr(self.buildroot, "doOutChroot"):
            return self.buildroot.doOutChroot(
                cmd, shell=shell, returnOutput=True, printOutput=False, returnStderr=False
            )
        # Standalone / test contexts without a full Buildroot
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        result = subprocess.run(
            cmd if not shell else cmd,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            env=env,
        )
        return result.stdout, result.returncode

    def _chroot_root(self):
        """Return the host path to the target chroot root."""
        if hasattr(self.buildroot, "make_chroot_path"):
            return self.buildroot.make_chroot_path()
        return getattr(self.buildroot, "rootdir", "/")

    def _from_chroot_path(self, path):
        """Standardizes from_chroot_path as a fallback for older mock versions."""
        if hasattr(self.buildroot, 'from_chroot_path'):
            return self.buildroot.from_chroot_path(path)

        # Fallback implementation
        rootdir = getattr(self.buildroot, 'rootdir', None)
        if not rootdir:
            return path
        if path.startswith(rootdir):
            rel_path = path[len(rootdir):]
            if not rel_path.startswith("/"):
                rel_path = "/" + rel_path
            return rel_path
        return path

    def _host_path(self, path):
        """Resolve a path to a host-visible filesystem location.

        Accepts either a host path or a chroot-relative path and returns a path
        that host/bootstrap tools (and python-rpm) can open directly.
        """
        if not path:
            return path
        if os.path.isfile(path) or os.path.isdir(path):
            return path

        # Chroot-relative path such as /builddir/build/RPMS/foo.rpm
        if hasattr(self.buildroot, "make_chroot_path"):
            candidate = self.buildroot.make_chroot_path(path.lstrip("/"))
            if os.path.exists(candidate):
                return candidate

        # Resultdir artifacts may also exist under the chroot build tree
        resultdir = getattr(self.buildroot, "resultdir", None)
        if resultdir and path.startswith(resultdir):
            filename = os.path.basename(path)
            search_paths = [
                "builddir/build/RPMS",
                "builddir/build/RPMS/x86_64",
                "builddir/build/RPMS/noarch",
                "builddir/build/SRPMS",
                "builddir/build/SOURCES",
            ]
            for search_path in search_paths:
                if hasattr(self.buildroot, "make_chroot_path"):
                    candidate = self.buildroot.make_chroot_path(search_path, filename)
                else:
                    candidate = os.path.join(self._chroot_root(), search_path, filename)
                if os.path.exists(candidate):
                    return candidate

        return path

    def generate_purl(self, package_name, version, distro_obj=None, arch=None,
                      epoch=None, distro_version=None):
        """Generates a Package URL (PURL) for an RPM package.

        Format: pkg:rpm/<namespace>/<name>@<version>?arch=&epoch=&distro=
        """
        clean_name = re.sub(r'[^a-zA-Z0-9.+_-]', '-', package_name)
        namespace = distro_obj or "rpm"
        purl = f"pkg:rpm/{namespace}/{clean_name}@{version}"
        qualifiers = []
        if arch and arch != "(none)":
            qualifiers.append(f"arch={arch}")
        if epoch not in (None, "", "(none)", "0"):
            qualifiers.append(f"epoch={epoch}")
        if distro_obj and distro_version:
            qualifiers.append(f"distro={distro_obj}-{distro_version}")
        elif distro_obj and distro_obj != "rpm":
            qualifiers.append(f"distro={distro_obj}")
        if qualifiers:
            purl += "?" + "&".join(qualifiers)
        return purl

    def generate_cpe(self, package_name, package_version, vendor=None):
        """Generate a heuristic CPE 2.3 identifier.

        These CPEs are fabricated from package metadata and are NOT looked up
        against the NVD dictionary. Callers must label them as heuristic.
        Returns (cpe_string, confidence) where confidence is 'heuristic'.
        """
        if not vendor or vendor == "(none)":
            vendor = "unknown"

        vendor = re.sub(r'[^a-zA-Z0-9._-]', '_', vendor.lower())
        product = re.sub(r'[^a-zA-Z0-9._-]', '_', package_name.lower())
        version = package_version
        if '-' in version:
            version = version.split('-')[0]

        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*:*"
        return cpe, "heuristic"

    def _empty_signature_info(self):
        """Return a blank signature info dict with evidence-backed defaults."""
        return {
            "signature_type": "unsigned",
            "signature_key": None,
            "signature_date": None,
            "signature_algorithm": None,
            # Tri-state: verified | present-unverified | unsigned
            "signature_status": "unsigned",
            # Kept for backwards compatibility; True only when cryptographically verified
            "signature_valid": False,
            "raw_signature_data": None,
            "build_date": None,
        }

    def _parse_signature_data(self, sig_data, signature_info=None):
        """Parse a raw RPM signature string without claiming validity.

        Presence of a signature string only proves the package is signed
        (status: present-unverified). Cryptographic verification is separate.
        """
        if signature_info is None:
            signature_info = self._empty_signature_info()

        if not sig_data or sig_data in ("(none)", ""):
            signature_info["signature_type"] = "unsigned"
            signature_info["signature_status"] = "unsigned"
            signature_info["signature_valid"] = False
            return signature_info

        signature_info["signature_type"] = "GPG"
        signature_info["signature_status"] = "present-unverified"
        signature_info["signature_valid"] = False
        signature_info["raw_signature_data"] = sig_data

        if "RSA/SHA256" in sig_data:
            signature_info["signature_algorithm"] = "RSA/SHA256"
        elif "DSA/SHA1" in sig_data:
            signature_info["signature_algorithm"] = "DSA/SHA1"
        elif "ECDSA/SHA256" in sig_data:
            signature_info["signature_algorithm"] = "ECDSA/SHA256"
        elif "Ed25519/SHA256" in sig_data:
            signature_info["signature_algorithm"] = "Ed25519/SHA256"

        key_id_match = re.search(r'Key ID ([0-9a-fA-F]+)', sig_data)
        if key_id_match:
            signature_info["signature_key"] = key_id_match.group(1)

        date_match = re.search(
            r'([A-Za-z]{3} [A-Za-z]{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4})',
            sig_data
        )
        if date_match:
            signature_info["signature_date"] = date_match.group(1)

        return signature_info

    def verify_rpm_signature(self, rpm_path):
        """Cryptographically verify an RPM signature via rpm/rpmkeys --checksig.

        Returns a signature_info dict with signature_status set to one of:
        verified, present-unverified, or unsigned.
        """
        host_path = self._host_path(rpm_path)
        info = self._empty_signature_info()
        if not os.path.isfile(host_path):
            return info

        raw = self.get_rpm_signature(host_path)
        self._parse_signature_data(raw, info)
        if info["signature_status"] == "unsigned":
            return info

        chrootpath = self._chroot_root()
        # Prefer verifying against the target chroot's keyring when available.
        cmd = ["rpm", "--checksig", host_path]
        if chrootpath and chrootpath != "/":
            cmd = ["rpm", "--root", chrootpath, "--checksig", host_path]

        try:
            output, rc = self._run_out_chroot(cmd)
            text = (output or "").strip()
            # rpm --checksig prints "digests signatures OK" on success.
            if rc == 0 and ("signatures OK" in text or "signature OK" in text.lower()):
                info["signature_status"] = "verified"
                info["signature_valid"] = True
            elif "NOKEY" in text or "NOT OK" in text or "MISSING" in text.upper():
                info["signature_status"] = "present-unverified"
                info["signature_valid"] = False
            else:
                info["signature_status"] = "present-unverified"
                info["signature_valid"] = False
            if text:
                info["raw_signature_data"] = info.get("raw_signature_data") or text
        except Exception as exc:
            self.buildroot.root_log.warning(
                "Signature verification failed for %s: %s", host_path, exc
            )
            info["signature_status"] = "present-unverified"
            info["signature_valid"] = False

        return info

    def get_rpm_metadata(self, rpm_path):
        """Extracts metadata from an RPM file via host-visible path + python-rpm."""
        host_path = self._host_path(rpm_path)
        if not os.path.isfile(host_path):
            self.buildroot.root_log.debug(f"RPM file not found: {rpm_path}")
            return {}

        self.buildroot.root_log.debug(f"[SBOM] Using host-native analysis for: {host_path}")
        return self._get_rpm_metadata_native(host_path)

    def _get_rpm_metadata_native(self, rpm_path):
        """Extracts metadata using native host bindings."""
        # pylint: disable=no-member
        try:
            ts = rpm.TransactionSet()
            with open(rpm_path, "rb") as f:
                hdr = ts.hdrFromFdno(f.fileno())

            tag_map = {
                "name": rpm.RPMTAG_NAME, "version": rpm.RPMTAG_VERSION,
                "release": rpm.RPMTAG_RELEASE, "arch": rpm.RPMTAG_ARCH,
                "epoch": rpm.RPMTAG_EPOCH, "summary": rpm.RPMTAG_SUMMARY,
                "license": rpm.RPMTAG_LICENSE, "vendor": rpm.RPMTAG_VENDOR,
                "url": rpm.RPMTAG_URL, "packager": rpm.RPMTAG_PACKAGER,
                "buildtime": rpm.RPMTAG_BUILDTIME, "buildhost": rpm.RPMTAG_BUILDHOST,
                "sourcerpm": rpm.RPMTAG_SOURCERPM, "group": rpm.RPMTAG_GROUP,
                "distribution": rpm.RPMTAG_DISTRIBUTION, "sha256": rpm.RPMTAG_SHA256HEADER
            }

            metadata = {}
            for field_name, tag in tag_map.items():
                value = hdr[tag]
                if field_name == "epoch" and value is None:
                    value = "0"
                elif value is None:
                    value = ""
                elif isinstance(value, bytes):
                    value = value.decode('utf-8', errors='replace')
                metadata[field_name] = str(value)
            return metadata
        except Exception:
            self.buildroot.root_log.debug(f"Failed to extract metadata via native bindings for {rpm_path}")
            return {}



    def get_rpm_file_info(self, rpm_path):
        """Extracts file hashes, ownership, and permissions from an RPM file."""
        host_path = self._host_path(rpm_path)
        if not os.path.isfile(host_path):
            return {}
        self.buildroot.root_log.debug(f"[SBOM] Using host-native file info for: {host_path}")
        return self._get_rpm_file_info_native(host_path)

    def _get_rpm_file_info_native(self, rpm_path):
        """Extracts file information using native host bindings."""
        # pylint: disable=no-member
        file_info = {}
        try:
            ts = rpm.TransactionSet()
            # pylint: disable=protected-access
            ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES | rpm._RPMVSF_NODIGESTS)
            with open(rpm_path, "rb") as f:
                hdr = ts.hdrFromFdno(f.fileno())

            basenames = hdr[rpm.RPMTAG_BASENAMES]
            dirnames = hdr[rpm.RPMTAG_DIRNAMES]
            dirindexes = hdr[rpm.RPMTAG_DIRINDEXES]
            filedigests = hdr[rpm.RPMTAG_FILEDIGESTS]
            filemodes = hdr[rpm.RPMTAG_FILEMODES]
            fileusernames = hdr[rpm.RPMTAG_FILEUSERNAME]
            filegroupnames = hdr[rpm.RPMTAG_FILEGROUPNAME]

            try:
                algo = hdr[rpm.RPMTAG_FILEDIGESTALGO]
            except (KeyError, IndexError):
                algo = 8

            file_info = {}
            for i, basename in enumerate(basenames):
                dirname = dirnames[dirindexes[i]]
                if isinstance(dirname, bytes):
                    dirname = dirname.decode('utf-8', 'replace')
                if isinstance(basename, bytes):
                    basename = basename.decode('utf-8', 'replace')
                filename = os.path.join(dirname, basename)

                digest = filedigests[i]
                if isinstance(digest, bytes):
                    digest = digest.decode('utf-8')

                file_info[filename] = {
                    "hash": digest if digest else None,
                    "algo": algo,
                    "permissions": f"0{filemodes[i]:o}",
                    "owner": fileusernames[i].decode('utf-8', 'replace') if isinstance(fileusernames[i], bytes) else fileusernames[i],
                    "group": filegroupnames[i].decode('utf-8', 'replace') if isinstance(filegroupnames[i], bytes) else filegroupnames[i]
                }
            return file_info
        except Exception:
            return {}

    def get_rpm_dependencies(self, rpm_path):
        """Extracts the list of dependencies from an RPM file."""
        host_path = self._host_path(rpm_path)
        if not os.path.isfile(host_path):
            return []
        self.buildroot.root_log.debug(f"[SBOM] Using host-native dependencies for: {host_path}")
        return self._get_rpm_dependencies_native(host_path)

    def _get_rpm_dependencies_native(self, rpm_path):
        """Extracts dependencies using native host bindings."""
        # pylint: disable=no-member
        try:
            ts = rpm.TransactionSet()
            with open(rpm_path, "rb") as f:
                hdr = ts.hdrFromFdno(f.fileno())

            requirements = hdr[rpm.RPMTAG_REQUIRENAME]
            if not requirements:
                return []

            return [r.decode('utf-8', 'replace') if isinstance(r, bytes) else str(r) for r in requirements]
        except Exception:  # pylint: disable=broad-exception-caught
            self.buildroot.root_log.debug(f"Failed to extract dependencies via native bindings for {rpm_path}")
            return []

    def get_rpm_signature(self, rpm_path):
        """Extract the GPG signature description for an RPM file.

        Prefers python-rpm header tags (SIGPGP / SIGGPG) over locale-dependent
        ``rpm -qip`` text parsing.
        """
        host_path = self._host_path(rpm_path)
        if not os.path.isfile(host_path):
            return None

        # Prefer header tags via python-rpm (locale-independent)
        try:
            ts = rpm.TransactionSet()
            ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES | rpm._RPMVSF_NODIGESTS)  # pylint: disable=protected-access
            with open(host_path, "rb") as handle:
                hdr = ts.hdrFromFdno(handle.fileno())
            # Binary blob presence indicates a signature; get printable form via rpm
            has_sig = False
            for tag_const in (
                getattr(rpm, "RPMTAG_SIGPGP", None),
                getattr(rpm, "RPMTAG_SIGGPG", None),
                getattr(rpm, "RPMTAG_RSAHEADER", None),
                getattr(rpm, "RPMTAG_DSAHEADER", None),
            ):
                if tag_const is None:
                    continue
                try:
                    val = hdr[tag_const]
                    if val:
                        has_sig = True
                        break
                except Exception:  # pylint: disable=broad-exception-caught
                    continue
            if has_sig:
                printable = self._get_rpm_signature_host(host_path)
                return printable or "GPG signature present"
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.buildroot.root_log.debug(
                "python-rpm signature read failed for %s: %s", host_path, exc
            )

        return self._get_rpm_signature_host(host_path)

    def _get_rpm_signature_host(self, rpm_path):
        """Extract printable signature via host rpm queryformat (LC_ALL=C)."""
        try:
            cmd = [
                "rpm", "-qp", "--queryformat",
                "%{SIGPGP:pgpsig}|%{SIGGPG:pgpsig}|%{RSAHEADER:pgpsig}|%{DSAHEADER:pgpsig}",
                rpm_path,
            ]
            output, _ = self._run_out_chroot(cmd)
            if output:
                for part in output.strip().split("|"):
                    part = part.strip()
                    if part and part != "(none)":
                        return part
            return None
        except Exception:  # pylint: disable=broad-exception-caught
            return None


    def hash_file(self, file_path):
        """Calculates the SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        # pylint: disable=broad-exception-caught
        except Exception as e:
            self.buildroot.root_log.debug(f"Failed to hash file {file_path}: {e}")
            return None

    def get_file_signature(self, file_path):
        """Detect a sidecar digital signature for a source/patch file."""
        try:
            for suffix in (".asc", ".sig"):
                sig_file = file_path + suffix
                if os.path.isfile(sig_file):
                    return "GPG signature file exists: " + os.path.basename(sig_file)
            if file_path.endswith(".asc") or file_path.endswith(".sig"):
                return "File is a signature file"
            return None
        except OSError as e:
            self.buildroot.root_log.debug(f"Failed to check signature for {file_path}: {e}")
            return None

    @staticmethod
    def merge_source_files(spec_sources, srpm_sources):
        """Merge SRPM header digests and signatures into spec-derived source entries."""
        if not srpm_sources:
            return list(spec_sources or [])
        if not spec_sources:
            return list(srpm_sources)

        srpm_by_name = {entry["filename"]: entry for entry in srpm_sources if entry.get("filename")}
        merged = []
        seen = set()
        for entry in spec_sources:
            filename = entry.get("filename")
            if not filename:
                continue
            srpm_entry = srpm_by_name.get(filename, {})
            merged.append({
                "filename": filename,
                "sha256": entry.get("sha256") or srpm_entry.get("sha256"),
                "digital_signature": entry.get("digital_signature") or srpm_entry.get("digital_signature"),
            })
            seen.add(filename)

        for srpm_entry in srpm_sources:
            filename = srpm_entry.get("filename")
            if filename and filename not in seen:
                merged.append(dict(srpm_entry))
        return merged

    @staticmethod
    def _source_file_signature(filename, file_set):
        """Return GPG companion-file status for a source archive or patch."""
        if filename.endswith(".asc") or filename.endswith(".sig"):
            return "File is a signature file"
        for ext in (".asc", ".sig"):
            if filename + ext in file_set:
                return f"GPG signature file exists: {filename}{ext}"
        return None

    def _extract_source_files_from_srpm_header(self, src_rpm_path):
        """Read per-file digests from an SRPM header via python-rpm."""
        # pylint: disable=no-member
        source_files = []
        ts = rpm.TransactionSet()
        with open(src_rpm_path, "rb") as f:
            hdr = ts.hdrFromFdno(f.fileno())

        basenames = hdr[rpm.RPMTAG_BASENAMES]
        digests = hdr[rpm.RPMTAG_FILEDIGESTS]
        file_set = set(basenames)

        for filename, sha256 in zip(basenames, digests):
            if isinstance(filename, bytes):
                filename = filename.decode("utf-8", "replace")
            if filename.endswith(".spec"):
                continue
            source_files.append({
                "filename": filename,
                "sha256": sha256.decode("utf-8", "replace") if isinstance(sha256, bytes) else sha256,
                "digital_signature": self._source_file_signature(filename, file_set),
            })
        return source_files

    def _extract_source_files_from_srpm_cli(self, src_rpm_path):
        """Read per-file digests from an SRPM using the host rpm binary."""
        source_files = []
        query_format = "[%{BASENAMES}|%{FILEDIGESTS}\n]"
        try:
            output = subprocess.check_output(
                ["rpm", "-qp", "--qf", query_format, src_rpm_path],
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except (subprocess.CalledProcessError, OSError) as e:
            self.buildroot.root_log.debug(f"rpm query failed for {src_rpm_path}: {e}")
            return source_files

        file_set = set()
        entries = []
        for line in output.splitlines():
            if "|" not in line:
                continue
            filename, sha256 = line.split("|", 1)
            if filename.endswith(".spec"):
                continue
            file_set.add(filename)
            entries.append((filename, sha256))

        for filename, sha256 in entries:
            source_files.append({
                "filename": filename,
                "sha256": sha256,
                "digital_signature": self._source_file_signature(filename, file_set),
            })
        return source_files

    def extract_source_files_from_srpm(self, src_rpm_path):
        """Extracts metadata for source files from a source RPM without full extraction."""
        self.buildroot.root_log.debug(f"Extracting source metadata from source RPM: {src_rpm_path}")
        if not os.path.isfile(src_rpm_path):
            return []

        for extractor in (
            self._extract_source_files_from_srpm_header,
            self._extract_source_files_from_srpm_cli,
        ):
            try:
                source_files = extractor(src_rpm_path)
                if source_files:
                    return source_files
            except Exception as e:
                self.buildroot.root_log.debug(
                    f"Source metadata extraction via {extractor.__name__} failed for {src_rpm_path}: {e}"
                )

        return []



    def _expand_simple_spec_macros(self, value, version=None):
        """Expand common unexpanded macros left by regex fallback parsing.

        Handles %{version}, %{dist}, and %{?dist}. Dist is derived from the
        *target chroot* os-release (e.g. .el9), not the host's RPM macros.
        """
        if not value or "%" not in str(value):
            return value
        result = str(value)
        if version:
            result = result.replace("%{version}", version)
            result = result.replace("%{VERSION}", version)

        dist = ""
        distro_id = self.detect_chroot_distribution() or ""
        ver = self.get_distribution_version() or ""
        major = ver.split(".", 1)[0] if ver else ""
        if distro_id in ("rhel", "centos", "rocky", "almalinux", "ol", "eurolinux") and major:
            dist = f".el{major}"
        elif distro_id == "fedora" and major:
            dist = f".fc{major}"

        if not dist:
            # Last resort: rpm --eval against the target chroot root
            try:
                chrootpath = self._chroot_root()
                cmd = ["rpm", "--eval", "%{?dist}"]
                if chrootpath and chrootpath != "/":
                    cmd = ["rpm", "--root", chrootpath, "--eval", "%{?dist}"]
                out, _ = self._run_out_chroot(cmd)
                dist = (out or "").strip()
            except Exception:  # pylint: disable=broad-exception-caught
                dist = ""

        if dist:
            result = result.replace("%{?dist}", dist)
            result = result.replace("%{dist}", dist)
        return result

    def _parse_spec_content_with_specfile(self, content, host_spec_path, metadata, sources):
        """Populate metadata/sources from expanded spec content via Specfile."""
        from specfile import Specfile

        spec = Specfile(content=content, sourcedir=os.path.dirname(host_spec_path))
        metadata.update({
            "name": spec.expanded_name,
            "version": spec.expanded_version,
            "release": spec.expanded_release,
            "license": spec.expanded_license,
        })
        try:
            br = spec.rpm_spec.sourceHeader[rpm.RPMTAG_REQUIRENAME]
            metadata["build_requires"] = [
                r.decode("utf-8", "replace") if isinstance(r, bytes) else str(r)
                for r in br
            ] if br else []
        except (AttributeError, KeyError):
            metadata["build_requires"] = []
        try:
            reqs = spec.rpm_spec.packages[0].header[rpm.RPMTAG_REQUIRENAME]
            metadata["requires"] = [
                req.decode("utf-8", "replace") if isinstance(req, bytes) else str(req)
                for req in reqs
            ] if reqs else []
        except (AttributeError, KeyError, IndexError):
            metadata["requires"] = []

        all_locs = []
        with spec.sources() as spec_sources:
            all_locs.extend(s.location for s in spec_sources if s.location)
        with spec.patches() as spec_patches:
            all_locs.extend(p.location for p in spec_patches if p.location)

        for loc in all_locs:
            filename, _, hash_value = loc.partition("#")
            actual_filename = os.path.basename(filename)
            build_dir = os.path.dirname(host_spec_path)
            sources_dir = os.path.join(os.path.dirname(build_dir), "SOURCES")
            file_path = os.path.join(sources_dir, actual_filename)
            actual_hash = None
            if os.path.isfile(file_path):
                actual_hash = self.hash_file(file_path)
            elif hash_value:
                actual_hash = hash_value
            signature = (
                self.get_file_signature(file_path) if os.path.isfile(file_path) else None
            )
            sources.append({
                "filename": actual_filename,
                "sha256": actual_hash,
                "digital_signature": signature,
            })
        if not metadata.get("name"):
            raise ValueError("Empty metadata from Specfile")

    def _parse_spec_content_with_regex(self, content, metadata, sources):
        """Regex fallback for when Specfile cannot parse the content."""
        name_match = (
            re.search(r"^Name:\s+(.+)$", content, re.MULTILINE)
            or re.search(r"^name\s*:\s*(.+)$", content, re.IGNORECASE | re.MULTILINE)
        )
        version_match = (
            re.search(r"^Version:\s+(.+)$", content, re.MULTILINE)
            or re.search(r"^version\s*:\s*(.+)$", content, re.IGNORECASE | re.MULTILINE)
        )
        release_match = (
            re.search(r"^Release:\s+(.+)$", content, re.MULTILINE)
            or re.search(r"^release\s*:\s*(.+)$", content, re.IGNORECASE | re.MULTILINE)
        )
        license_match = (
            re.search(r"^License:\s+(.+)$", content, re.MULTILINE)
            or re.search(r"^license\s*:\s*(.+)$", content, re.IGNORECASE | re.MULTILINE)
        )

        version = version_match.group(1).strip() if version_match else ""
        release = release_match.group(1).strip() if release_match else ""
        version = self._expand_simple_spec_macros(version)
        release = self._expand_simple_spec_macros(release, version=version)

        metadata["name"] = name_match.group(1).strip() if name_match else ""
        metadata["version"] = version
        metadata["release"] = release
        metadata["license"] = license_match.group(1).strip() if license_match else ""

        # Expand macros inside source/patch filenames too
        source_matches = re.finditer(
            r"^(Source|Patch)\d*:\s+(.+)$", content, re.MULTILINE
        )
        for sm in source_matches:
            loc = sm.group(2).strip()
            loc = self._expand_simple_spec_macros(loc, version=version)
            filename = os.path.basename(loc.partition("#")[0])
            if filename and not any(s["filename"] == filename for s in sources):
                sources.append({
                    "filename": filename,
                    "sha256": None,
                    "digital_signature": None,
                })

    def parse_spec_file(self, spec_path):
        """Parse a spec file for metadata and source/patch files.

        Prefers host-visible content. Tries ``rpmspec --parse`` via doOutChroot
        when useful, but always falls back to reading the host file and
        Specfile/regex parsing when bootstrap rpmspec fails (common for
        host paths that are not visible inside the bootstrap nspawn).
        """
        self.buildroot.root_log.debug("[SBOM] Parsing spec file: %s", spec_path)

        sources = []
        metadata = {
            "name": "",
            "version": "",
            "release": "",
            "license": "",
            "build_requires": [],
            "requires": [],
        }

        host_spec_path = self._host_path(spec_path)
        if not os.path.isfile(host_spec_path):
            self.buildroot.root_log.debug("Spec file not found: %s", host_spec_path)
            return metadata, sources

        # 1) Prefer reading host file first (always available for mock SPECS).
        file_content = ""
        try:
            with open(host_spec_path, "r", encoding="utf-8", errors="replace") as handle:
                file_content = handle.read()
        except OSError as exc:
            self.buildroot.root_log.warning(
                "Failed to read spec file %s: %s", host_spec_path, exc
            )
            return metadata, sources

        # 2) Best-effort macro expansion via rpmspec (may fail in bootstrap).
        result = None
        try:
            cmd = ["rpmspec", "--parse", host_spec_path]
            result, rc = self._run_out_chroot(cmd)
            if rc not in (0, None) or not (result or "").strip():
                result = None
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.buildroot.root_log.debug(
                "rpmspec --parse via doOutChroot failed for %s: %s; using host file",
                host_spec_path, exc,
            )
            result = None

        content = (result or "").strip() or file_content

        # 3) Specfile first, regex fallback second — never skip fallback on parse errors.
        try:
            self._parse_spec_content_with_specfile(
                content, host_spec_path, metadata, sources
            )
            self.buildroot.root_log.debug(
                "Extracted metadata %s and %s source/patch files from spec",
                metadata, len(sources),
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.buildroot.root_log.debug(
                "[SBOM] FALLBACK: Specfile library failed for %s, trying regex: %s",
                spec_path, exc,
            )
            sources.clear()
            self._parse_spec_content_with_regex(content, metadata, sources)
            # If expanded content still failed macros, try raw file content too
            if not metadata.get("name") and content != file_content:
                self._parse_spec_content_with_regex(file_content, metadata, sources)

        # Final safety: expand any remaining macros in name/version/release
        if metadata.get("version"):
            metadata["version"] = self._expand_simple_spec_macros(metadata["version"])
        if metadata.get("release"):
            metadata["release"] = self._expand_simple_spec_macros(
                metadata["release"], version=metadata.get("version")
            )
        for src in sources:
            src["filename"] = self._expand_simple_spec_macros(
                src.get("filename") or "", version=metadata.get("version")
            )

        return metadata, sources

    def detect_chroot_distribution(self):
        """Detects the distribution ID (e.g., 'fedora', 'centos', 'rhel') from inside the chroot."""
        try:
            import distro
            try:
                distro_id = distro.id(root_dir=self.buildroot.rootdir)
            except (TypeError, AttributeError):
                # Fallback for older python-distro versions (<1.6.0)
                os_release = os.path.join(self.buildroot.rootdir, "etc/os-release")
                distro_id = "unknown"
                if os.path.isfile(os_release):
                    with open(os_release, 'r') as f:
                        for line in f:
                            if line.startswith("ID="):
                                distro_id = line.split("=")[1].strip().strip('"').strip("'")
                                break
            
            if distro_id:
                return distro_id.lower()
            return "unknown"
        except Exception as e:
            self.buildroot.root_log.debug(f"Failed to detect chroot distribution: {e}")
            return "unknown"

    def _rpm_db_executor(self, cmd):
        """Run an rpm query against the chroot, trying alternate --dbpath values."""
        attempts = [list(cmd)]
        if "--root" in cmd and "--dbpath" not in cmd:
            for dbpath in ("/var/lib/rpm", "/usr/lib/sysimage/rpm"):
                alt = list(cmd)
                root_idx = alt.index("--root")
                alt[root_idx + 2:root_idx + 2] = ["--dbpath", dbpath]
                attempts.append(alt)

        last_error = None
        last_output = ""
        for attempt in attempts:
            try:
                output, rc = self._run_out_chroot(attempt)
                text = (output or "").strip()
                # Host rpm often can't open the default sysimage path; keep
                # trying alternate --dbpath values until we get a real result.
                if rc == 0 and text:
                    return output
                if text and "cannot open Packages database" not in text.lower():
                    # e.g. "package X is not installed" with wrong db — continue
                    if rc != 0 and "is not installed" in text.lower():
                        last_output = output
                        continue
                    if rc == 0:
                        return output
                    last_output = output
                elif text:
                    last_output = output
            except Exception as exc:  # pylint: disable=broad-exception-caught
                last_error = exc
                continue
        if last_error and not last_output:
            raise last_error
        return last_output or ""

    def _query_installed_signature_map(self, chrootpath):
        """Map installed package name -> printable GPG signature string.

        EL9+/Rocky often store signatures in RSAHEADER rather than SIGPGP.
        ``installed_packages.query_packages`` only reads ``%{sigpgp:pgpsig}``,
        which returns ``(none)`` on those distros — so we query both tags here.
        """
        cmd = ["rpm", "-qa"]
        if chrootpath and chrootpath != "/":
            cmd += ["--root", chrootpath]
        # name \\t sigpgp \\t rsa \\t dsa \\t siggpg
        cmd += [
            "--qf",
            "%{NAME}\t%{SIGPGP:pgpsig}\t%{RSAHEADER:pgpsig}\t"
            "%{DSAHEADER:pgpsig}\t%{SIGGPG:pgpsig}\n",
        ]
        try:
            output = self._rpm_db_executor(cmd)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.buildroot.root_log.debug(
                "Installed package signature query failed: %s", exc
            )
            return {}

        sig_map = {}
        for line in (output or "").splitlines():
            parts = line.split("\t")
            if not parts:
                continue
            name = parts[0].strip()
            if not name or name.startswith("gpg-pubkey"):
                continue
            raw = None
            for part in parts[1:]:
                part = (part or "").strip()
                if part and part != "(none)":
                    raw = part
                    break
            if raw:
                sig_map[name] = raw
        return sig_map

    def _chroot_trusted_key_ids(self, chrootpath):
        """Return lowercased GPG key IDs imported into the chroot RPM DB."""
        cmd = ["rpm", "-q", "gpg-pubkey", "--qf", "%{VERSION}\n"]
        if chrootpath and chrootpath != "/":
            cmd = ["rpm", "--root", chrootpath, "-q", "gpg-pubkey", "--qf", "%{VERSION}\n"]
        try:
            output = self._rpm_db_executor(cmd)
        except Exception:  # pylint: disable=broad-exception-caught
            return set()
        keys = set()
        for line in (output or "").splitlines():
            key = line.strip().lower()
            if key and key != "(none)" and "not installed" not in key:
                keys.add(key)
                # Also keep last-8 form for truncated comparisons
                if len(key) >= 8:
                    keys.add(key[-8:])
        return keys

    def _signature_info_from_installed(self, raw_sig, trusted_keys=None):
        """Build signature_info from an installed-package pgpsig string.

        If the signing key is present in the chroot keyring, mark verified —
        the package could not have been installed with an untrusted signature
        under normal rpm policy.
        """
        info = self._parse_signature_data(raw_sig)
        if info["signature_status"] == "unsigned":
            return info
        key = (info.get("signature_key") or "").lower()
        if trusted_keys and key:
            key_match = (
                key in trusted_keys
                or key[-8:] in trusted_keys
                or any(tk.endswith(key) or key.endswith(tk) for tk in trusted_keys if tk)
            )
            if key_match:
                info["signature_status"] = "verified"
                info["signature_valid"] = True
        return info

    def get_build_toolchain_packages(self, generate_cpe=False):
        """Return packages installed in the build chroot (the toolchain).

        Uses mockbuild.installed_packages.query_packages (same path as
        package_state / buildroot_lock) via doOutChroot, with a --dbpath
        fallback for older chroots whose RPM DB lives under /var/lib/rpm.

        Signature data is enriched via RSAHEADER/SIGPGP because modern
        EL/Rocky packages often have an empty SIGPGP tag.
        """
        from mockbuild.installed_packages import query_packages

        chrootpath = self._chroot_root()
        fields = [
            "name", "version", "release", "arch", "license", "epoch",
            "sigmd5", "signature", "buildtime", "sourcerpm", "sha256header",
        ]

        try:
            raw_packages = query_packages(fields, chrootpath, self._rpm_db_executor)
        except Exception as exc:
            self.buildroot.root_log.warning(
                "Failed to query build toolchain packages: %s", exc
            )
            return []

        # Best-effort download URLs via repoquery (same helper as buildroot_lock)
        try:
            from mockbuild.installed_packages import query_packages_location
            query_packages_location(raw_packages, chrootpath, self._rpm_db_executor)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.buildroot.root_log.debug(
                "Toolchain package URL lookup skipped: %s", exc
            )

        # Full signature strings (RSAHEADER fallback) + trusted keyring
        sig_map = self._query_installed_signature_map(chrootpath)
        trusted_keys = self._chroot_trusted_key_ids(chrootpath)

        packages = []
        cpe_vendor_default = self.detect_chroot_distribution() or "unknown"
        signed_count = 0
        for pkg in raw_packages:
            package_name = pkg.get("name") or ""
            if not package_name or package_name.startswith("gpg-pubkey"):
                continue

            version = pkg.get("version") or ""
            release = pkg.get("release") or ""
            package_version = f"{version}-{release}" if release else version
            package_arch = pkg.get("arch") or ""
            package_license = pkg.get("license") or ""
            build_time = pkg.get("buildtime") or ""
            source_rpm = pkg.get("sourcerpm")
            if source_rpm == "(none)":
                source_rpm = None
            package_checksum = pkg.get("sha256header")
            if package_checksum in (None, "(none)"):
                package_checksum = None

            raw_sig = sig_map.get(package_name)
            if raw_sig:
                digital_signature = self._signature_info_from_installed(
                    raw_sig, trusted_keys
                )
                if digital_signature.get("signature_status") != "unsigned":
                    signed_count += 1
            else:
                # Fallback: truncated 8-char key from query_packages "signature"
                sig_short = pkg.get("signature")
                digital_signature = self._empty_signature_info()
                if sig_short:
                    digital_signature["signature_type"] = "GPG"
                    digital_signature["signature_key"] = sig_short
                    digital_signature["signature_status"] = "present-unverified"
                    digital_signature["signature_valid"] = False
                    digital_signature["raw_signature_data"] = sig_short
                    if trusted_keys and (
                        sig_short.lower() in trusted_keys
                        or any(tk.endswith(sig_short.lower()) for tk in trusted_keys)
                    ):
                        digital_signature["signature_status"] = "verified"
                        digital_signature["signature_valid"] = True
                    signed_count += 1

            if build_time and str(build_time).isdigit():
                try:
                    dt = datetime.fromtimestamp(int(build_time), tz=timezone.utc)
                    digital_signature["build_date"] = dt.isoformat()
                except (ValueError, TypeError, OverflowError):
                    pass

            cpe = None
            cpe_confidence = None
            if generate_cpe:
                cpe, cpe_confidence = self.generate_cpe(
                    package_name, package_version, vendor=cpe_vendor_default
                )

            entry = {
                "name": package_name,
                "version": package_version,
                "arch": package_arch,
                "epoch": pkg.get("epoch"),
                "licenseDeclared": package_license,
                "digital_signature": digital_signature,
                "sourcerpm": source_rpm,
                "checksum": package_checksum,
                "url": pkg.get("url"),
            }
            if cpe:
                entry["cpe"] = cpe
                entry["cpe_confidence"] = cpe_confidence
            packages.append(entry)

        self.buildroot.root_log.info(
            "Found %s build toolchain packages (%s with signatures)",
            len(packages), signed_count,
        )
        return packages

    def get_distribution(self):
        """Detects the distribution from the chroot environment (human readable)."""
        try:
            os_release = os.path.join(self.buildroot.rootdir, "etc/os-release")
            distro_name = "Unknown"
            version = ""
            if os.path.isfile(os_release):
                with open(os_release, 'r') as f:
                    for line in f:
                        if line.startswith("NAME="):
                            distro_name = line.strip().split("=", 1)[1].strip('"')
                        elif line.startswith("VERSION_ID="):
                            version = line.strip().split("=", 1)[1].strip('"')
            if distro_name and version:
                return f"{distro_name} {version}"
            return distro_name or "Unknown"
        except OSError as e:
            return f"Unknown ({e})"

    def get_distribution_version(self):
        """Return VERSION_ID from the chroot os-release, or empty string."""
        try:
            os_release = os.path.join(self.buildroot.rootdir, "etc/os-release")
            if os.path.isfile(os_release):
                with open(os_release, 'r', encoding='utf-8') as handle:
                    for line in handle:
                        if line.startswith("VERSION_ID="):
                            return line.strip().split("=", 1)[1].strip('"').strip("'")
        except OSError:
            pass
        return ""

    def load_buildroot_lock(self):
        """Load buildroot_lock.json from the result directory when present."""
        resultdir = getattr(self.buildroot, "resultdir", None)
        if not resultdir:
            return None
        lock_path = os.path.join(resultdir, "buildroot_lock.json")
        if not os.path.isfile(lock_path):
            # Also check parent of resultdir (mock layout: .../el9/result vs .../el9/)
            parent = os.path.dirname(resultdir.rstrip("/"))
            alt = os.path.join(parent, "buildroot_lock.json")
            lock_path = alt if os.path.isfile(alt) else lock_path
        if not os.path.isfile(lock_path):
            return None
        try:
            with open(lock_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, ValueError) as exc:
            self.buildroot.root_log.warning(
                "Failed to read buildroot_lock.json: %s", exc
            )
            return None




