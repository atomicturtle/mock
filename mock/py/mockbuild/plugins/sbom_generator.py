# Copyright (C) 2025, Atomicorp, Inc.
# SPDX-License-Identifier: GPL-2.0-only

import os
import json
import subprocess
from mockbuild.trace_decorator import traceLog
import hashlib
import re
import socket

requires_api_version = "1.1"  # Ensure compatibility with mock API

# Plugin entry point
@traceLog()
def init(plugins, conf, buildroot):
    # Ensure configuration exists for the plugin
    if "sbom_generator_opts" not in conf:
        conf["sbom_generator_opts"] = {}
    SBOMGenerator(plugins, conf["sbom_generator_opts"], buildroot)

class SBOMGenerator(object):
    """Generates SBOM for the built packages."""
    # pylint: disable=too-few-public-methods
    @traceLog()
    def __init__(self, plugins, conf, buildroot):

        self.buildroot = buildroot
        self.state = buildroot.state
        self.rootdir = buildroot.rootdir
        self.builddir = buildroot.builddir
        self.conf = conf
        self.sbom_enabled = self.conf.get('generate_sbom', True)
        self.sbom_done = False
        plugins.add_hook("prebuild", self._listSPECSDirectory)
        plugins.add_hook("postbuild", self._generateSBOMPostBuildHook)

    @traceLog()
    def _listSPECSDirectory(self):
        """Lists the contents of the SPECS directory before building."""

        print("DEBUG: Listing contents of SPECS directory before building:")
        print(f"DEBUG: builddir is {self.buildroot.builddir}")
        print(f"DEBUG: rootdir is {self.rootdir}")
        print(f"DEBUG: resultsdir is {self.buildroot.resultdir}")

        # Look for spec file in the build directory
        build_dir = self.buildroot.builddir
        specs_dir = os.path.join(build_dir, "SPECS")
        print(f"DEBUG: spec dir is {specs_dir}")

        try:
            if os.path.exists(specs_dir):
                specs_files = os.listdir(specs_dir)
                print(f"Contents of SPECS directory: {specs_files}")
            else:
                print("SPECS directory does not exist.")
        except Exception as e:
            print(f"Failed to list contents of SPECS directory: {e}")

    @traceLog()
    def _generateSBOMPostBuildHook(self):
        if self.sbom_done or not self.sbom_enabled:
            return

        out_file = os.path.join(self.buildroot.resultdir, 'sbom.spdx.json')
        state_text = "Generating SBOM for built packages v0.8"
        self.state.start(state_text)

        try:
            build_dir = self.buildroot.resultdir
            # Filter out source RPMs from binary RPM processing
            rpm_files = [f for f in os.listdir(build_dir) if f.endswith('.rpm') and not f.endswith('.src.rpm')]
            src_rpm_files = [f for f in os.listdir(build_dir) if f.endswith('.src.rpm')]
            
            # Look for spec file in the build directory (during build process)
            build_build_dir = os.path.join(self.buildroot.rootdir, "builddir/build")
            spec_file = None
            if os.path.exists(build_build_dir):
                # Look for spec file in the build directory
                for root, dirs, files in os.walk(build_build_dir):
                    for file in files:
                        if file.endswith('.spec'):
                            spec_file = os.path.join(root, file)
                            break
                    if spec_file:
                        break

            if not rpm_files and not src_rpm_files and not spec_file:
                print("No RPM, source RPM, or spec file found for SBOM generation.")
                return

            # Gather SBOM document metadata
            sbom_metadata = {
                "sbom_format_version": "0.9",
                "created_by": "mock-sbom-generator 0.9",
                "created": self.get_iso_timestamp(),
                "build_host": socket.gethostname(),
                "distribution": self.get_distribution()
            }

            sbom = {
                "sbom_metadata": sbom_metadata,
                "SPDXVersion": "SPDX-2.3",
                "DataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "mock-build",
                "creator": "Mock-SBOM-Plugin",
                "created": self.get_iso_timestamp(),
                "packages": [],
                "source_package": {}
            }

            # Process spec file for sources and patches
            if spec_file:
                parsed_sources = self.parse_spec_file(spec_file)
                sbom["source_package"] = {
                    "spec_file": os.path.basename(spec_file),
                    "source_files": parsed_sources
                }
            elif src_rpm_files:
                sbom["source_package"] = {
                    "source_rpm": src_rpm_files[0],
                    "source_files": []
                }

            build_toolchain = self.get_build_toolchain_packages()

            # Process binary RPMs
            for rpm_file in rpm_files:
                rpm_path = os.path.join(build_dir, rpm_file)
                package_data = self.get_rpm_metadata(rpm_path)
                if package_data:
                    files_list = self.get_rpm_file_list(rpm_path)
                    file_info = self.get_rpm_file_info(rpm_path)
                    files_with_info = []
                    for file_path in files_list:
                        info = file_info.get(file_path, {})
                        files_with_info.append({
                            "path": file_path,
                            "sha256": info.get("sha256"),
                            "permissions": info.get("permissions"),
                            "owner": info.get("owner"),
                            "group": info.get("group")
                        })
                    dependencies = self.get_rpm_dependencies(rpm_path)
                    package_name = package_data.get("name")
                    package_version = package_data.get("version")
                    spdx_id = self.generate_spdx_id(package_name, package_version, "Package")
                    cpe = self.generate_cpe(package_name, package_version)
                    # Format originator according to SPDX standard
                    vendor = package_data.get("vendor")
                    if vendor and vendor != "(none)":
                        originator = f"Organization: {vendor}"
                    else:
                        originator = None
                    
                    sbom_package = {
                        "SPDXID": spdx_id,
                        "name": package_name,
                        "version": package_version,
                        "release": package_data.get("release"),
                        "licenseDeclared": package_data.get("license"),
                        "originator": originator,
                        "url": package_data.get("url"),
                        "packager": package_data.get("packager"),
                        "files": files_with_info,
                        "dependencies": dependencies,
                        "gpg_signature": None,
                        "cpe": cpe
                    }
                    sbom["packages"].append(sbom_package)

            sbom["build_toolchain"] = build_toolchain

            with open(out_file, "w") as f:
                json.dump(sbom, f, indent=4)

            print(f"SBOM successfully written to: {out_file}")
        except Exception as e:
            print(f"An error occurred during SBOM generation: {e}")
        finally:
            self.sbom_done = True
            self.state.finish(state_text)

    def parse_spec_file(self, spec_path):
        """Parses a spec file to extract source and patch files with their hashes and signatures."""
        print("Parsing spec file")
        if not os.path.isfile(spec_path):
            print(f"Spec file not found: {spec_path}")
            return []
        
        sources = []
        try:
            # Use rpmspec --parse to get expanded source and patch file names
            cmd = ["rpmspec", "--parse", spec_path]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
            
            for line in result.stdout.splitlines():
                line = line.strip()
                # Match lines like Source0: or Patch1:
                match = re.match(r'^(Source|Patch)[0-9]*:\s*(.+)$', line)
                if match:
                    source_file = match.group(2)
                    # Extract hash if present (format: filename#hash)
                    if '#' in source_file:
                        filename, hash_value = source_file.split('#', 1)
                    else:
                        filename = source_file
                        hash_value = None
                    
                    # Extract actual filename from URL if it's a URL
                    if filename.startswith('http'):
                        # Extract filename from URL (last part after /)
                        actual_filename = filename.split('/')[-1]
                    else:
                        actual_filename = filename
                    
                    # Try to find the actual file and calculate its hash
                    build_dir = os.path.dirname(spec_path)
                    # SOURCES directory is at the same level as SPECS, not inside SPECS
                    sources_dir = os.path.join(os.path.dirname(build_dir), "SOURCES")
                    file_path = os.path.join(sources_dir, actual_filename)
                    
                    actual_hash = None
                    if os.path.isfile(file_path):
                        actual_hash = self.hash_file(file_path)
                        print(f"Found source file {actual_filename} at {file_path}, hash: {actual_hash}")
                    elif hash_value:
                        actual_hash = hash_value
                        print(f"Using hash from spec file for {actual_filename}: {hash_value}")
                    else:
                        print(f"Source file {actual_filename} not found at {file_path}")
                    
                    # Check for digital signature (GPG signature)
                    signature = self.get_file_signature(file_path) if os.path.isfile(file_path) else None
                    
                    sources.append({
                        "filename": actual_filename,
                        "sha256": actual_hash,
                        "digital_signature": signature
                    })
            
            print(f"Extracted source and patch files from spec: {sources}")
        except Exception as e:
            print(f"Failed to parse spec file {spec_path}: {e}")
        return sources

    def get_file_signature(self, file_path):
        """Attempts to detect if a file has a digital signature."""
        try:
            # Check for .asc signature file
            asc_file = file_path + ".asc"
            if os.path.isfile(asc_file):
                return "GPG signature file exists: " + os.path.basename(asc_file)
            
            # Check for .sig signature file
            sig_file = file_path + ".sig"
            if os.path.isfile(sig_file):
                return "GPG signature file exists: " + os.path.basename(sig_file)
            
            # Check if the file itself is a signature
            if file_path.endswith('.asc') or file_path.endswith('.sig'):
                return "File is a signature file"
            
            return None
        except Exception as e:
            print(f"Failed to check signature for {file_path}: {e}")
            return None

    def get_iso_timestamp(self):
        """Returns the current time in ISO 8601 format."""
        from datetime import datetime
        return datetime.utcnow().isoformat() + "Z"

    def get_distribution(self):
        """Returns the distribution name and version from /etc/os-release."""
        try:
            distro = None
            version = None
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("NAME="):
                            distro = line.strip().split("=", 1)[1].strip('"')
                        elif line.startswith("VERSION_ID="):
                            version = line.strip().split("=", 1)[1].strip('"')
            if distro and version:
                return f"{distro} {version}"
            elif distro:
                return distro
            else:
                return "Unknown"
        except Exception as e:
            return f"Unknown ({e})"

    def generate_spdx_id(self, package_name, package_version, package_type="Package"):
        """Generates a unique SPDX ID for a package."""
        # Sanitize package name and version for SPDX ID format
        # SPDX IDs must start with a letter and contain only letters, numbers, dots, and hyphens
        sanitized_name = re.sub(r'[^a-zA-Z0-9.-]', '-', package_name)
        sanitized_version = re.sub(r'[^a-zA-Z0-9.-]', '-', package_version)
        
        # Ensure it starts with a letter
        if sanitized_name and not sanitized_name[0].isalpha():
            sanitized_name = "pkg-" + sanitized_name
        
        # Create the SPDX ID
        spdx_id = f"SPDXRef-{package_type}-{sanitized_name}-{sanitized_version}"
        return spdx_id

    def generate_cpe(self, package_name, package_version, vendor=None):
        """Generates a CPE identifier for a package."""
        # CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*:*
        
        # Default vendor if not provided
        if not vendor or vendor == "(none)":
            vendor = "fedora"
        
        # Clean up vendor name for CPE
        vendor = re.sub(r'[^a-zA-Z0-9._-]', '_', vendor.lower())
        
        # Clean up package name for CPE
        product = re.sub(r'[^a-zA-Z0-9._-]', '_', package_name.lower())
        
        # Clean up version for CPE (remove release part if present)
        version = package_version
        if '-' in version:
            version = version.split('-')[0]  # Remove release part
        
        # Handle special cases for common packages
        if package_name == "glibc":
            vendor = "gnu"
            product = "glibc"
        elif package_name == "openssl":
            vendor = "openssl"
            product = "openssl"
        elif package_name == "gcc":
            vendor = "gnu"
            product = "gcc"
        elif package_name == "make":
            vendor = "gnu"
            product = "make"
        elif package_name == "gettext":
            vendor = "gnu"
            product = "gettext"
        
        # Generate CPE
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*:*"
        return cpe

    def detect_chroot_distribution(self):
        """Detects the distribution name inside the chroot by reading /etc/os-release."""
        try:
            # Use buildroot's doChroot to cat /etc/os-release
            cmd = ["cat", "/etc/os-release"]
            output, _ = self.buildroot.doChroot(cmd, shell=False, returnOutput=True, printOutput=False)
            distro = None
            if output:
                for line in output.splitlines():
                    if line.startswith("ID="):
                        distro = line.strip().split("=", 1)[1].strip('"').lower()
                        break
            if distro:
                return distro
            else:
                return "unknown"
        except Exception as e:
            print(f"Failed to detect chroot distribution: {e}")
            return "unknown"

    def get_build_toolchain_packages(self):
        """Returns the list of packages installed in the build toolchain with detailed signature information."""
        try:
            # First get basic package info
            query = "%{NAME}|%{VERSION}-%{RELEASE}.%{ARCH}|%{LICENSE}|%{BUILDTIME}\n"
            cmd = ["rpm", "-qa", "--qf", query]
            output, _ = self.buildroot.doChroot(cmd, shell=False, returnOutput=True, printOutput=False)
            packages = []
            cpe_vendor_default = self.detect_chroot_distribution() or "unknown"
            import re
            import datetime
            
            for line in output.splitlines():
                parts = line.split("|", 3)
                if len(parts) < 3:
                    continue
                package_name = parts[0].strip()
                package_version = parts[1].strip()
                package_license = parts[2].strip()
                build_time = parts[3].strip() if len(parts) > 3 else None
                
                # Skip GPG keys and other non-package entries
                if package_name.startswith('gpg-pubkey') or package_name == '(none)' or not package_name:
                    continue
                
                # Get detailed signature info for this package
                digital_signature = self.get_package_signature_from_chroot(package_name)
                
                # Build date
                if build_time and build_time.isdigit():
                    try:
                        dt = datetime.datetime.utcfromtimestamp(int(build_time))
                        digital_signature["build_date"] = dt.isoformat() + "Z"
                    except Exception:
                        digital_signature["build_date"] = None
                
                spdx_id = self.generate_spdx_id(package_name, package_version, "BuildEnv")
                cpe = self.generate_cpe(package_name, package_version, vendor=cpe_vendor_default)
                packages.append({
                    "SPDXID": spdx_id,
                    "name": package_name,
                    "version": package_version,
                    "licenseDeclared": package_license,
                    "digital_signature": digital_signature,
                    "cpe": cpe
                })
            print(f"Found {len(packages)} build toolchain packages")
            return packages
        except Exception as e:
            print(f"Failed to get build environment packages: {e}")
            return []

    def get_package_signature_from_chroot(self, package_name):
        """Gets detailed signature information for a specific package from inside the chroot."""
        try:
            cmd = ["rpm", "-qi", package_name]
            output, _ = self.buildroot.doChroot(cmd, shell=False, returnOutput=True, printOutput=False)
            
            signature_info = {
                "signature_type": "unsigned",
                "signature_key": None,
                "signature_date": None,
                "signature_algorithm": None,
                "signature_valid": False,
                "raw_signature_data": None,
                "build_date": None
            }
            
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Signature"):
                    # Extract the signature data after the colon
                    sig_data = line.split(":", 1)[1].strip() if ":" in line else ""
                    signature_info["raw_signature_data"] = sig_data
                    
                    if sig_data and sig_data != "(none)" and sig_data != "":
                        signature_info["signature_type"] = "GPG"
                        signature_info["signature_valid"] = True
                        
                        # Parse signature line like: "RSA/SHA256, Fri 08 Nov 2024 03:56:24 AM EST, Key ID c8ac4916105ef944"
                        if "RSA/SHA256" in sig_data:
                            signature_info["signature_algorithm"] = "RSA/SHA256"
                        elif "DSA/SHA1" in sig_data:
                            signature_info["signature_algorithm"] = "DSA/SHA1"
                        elif "ECDSA/SHA256" in sig_data:
                            signature_info["signature_algorithm"] = "ECDSA/SHA256"
                        elif "Ed25519/SHA256" in sig_data:
                            signature_info["signature_algorithm"] = "Ed25519/SHA256"
                        
                        # Extract key ID
                        if "Key ID" in sig_data:
                            key_id_match = re.search(r'Key ID ([0-9a-fA-F]+)', sig_data)
                            if key_id_match:
                                signature_info["signature_key"] = key_id_match.group(1)
                        
                        # Extract date - handle various time formats including EST/EDT
                        date_match = re.search(r'([A-Za-z]{3} [A-Za-z]{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4})', sig_data)
                        if date_match:
                            signature_info["signature_date"] = date_match.group(1)
                    else:
                        signature_info["signature_type"] = "unsigned"
                        signature_info["signature_valid"] = False
                    break
            
            return signature_info
            
        except Exception as e:
            print(f"Failed to get signature for package {package_name}: {e}")
            return {
                "signature_type": "unknown",
                "signature_valid": False,
                "error": str(e)
            }

    def get_package_detailed_signature(self, package_name):
        """Gets detailed signature information for a specific package."""
        try:
            import subprocess
            import shlex
            # Try to use rpm --root to query from outside the chroot first
            # If that fails, fall back to running inside the chroot
            root_path = self.buildroot.rootdir
            cmd = f"rpm --root {shlex.quote(root_path)} -qi {shlex.quote(package_name)}"
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout
            
            # If host rpm command failed (empty output), try running inside chroot
            if not output.strip():
                print(f"Host RPM command failed for {package_name}, trying inside chroot...")
                # Use buildroot's doChroot method to run the command inside the chroot
                cmd = ["rpm", "-qi", package_name]
                output, _ = self.buildroot.doChroot(cmd, shell=False, returnOutput=True, printOutput=False)
                print(f"Chroot RPM output for {package_name}: {output[:200]}...")  # Debug output
            
            signature_info = {
                "signature_type": None,
                "signature_key": None,
                "signature_date": None,
                "signature_algorithm": None,
                "signature_valid": None,
                "raw_signature_data": None,
                "build_date": None
            }
            
            output_lines = output.splitlines()
            i = 0
            signature_found = False
            print(f"DEBUG: Processing {len(output_lines)} lines for package {package_name}")
            while i < len(output_lines):
                line = output_lines[i].strip()
                print(f"DEBUG: Line {i}: '{line}'")
                if line.startswith("Signature"):
                    signature_found = True
                    print(f"DEBUG: Found signature line: '{line}'")
                    # Extract the signature data after the colon
                    sig_data = line.split(":", 1)[1].strip() if ":" in line else ""
                    signature_info["raw_signature_data"] = sig_data
                    print(f"DEBUG: Extracted signature data: '{sig_data}'")
                    
                    if sig_data and sig_data != "(none)" and sig_data != "":
                        signature_info["signature_type"] = "GPG"
                        signature_info["signature_valid"] = True
                        
                        # Parse signature line like: "RSA/SHA256, Fri 08 Nov 2024 03:56:24 AM EST, Key ID c8ac4916105ef944"
                        if "RSA/SHA256" in sig_data:
                            signature_info["signature_algorithm"] = "RSA/SHA256"
                        elif "DSA/SHA1" in sig_data:
                            signature_info["signature_algorithm"] = "DSA/SHA1"
                        elif "ECDSA/SHA256" in sig_data:
                            signature_info["signature_algorithm"] = "ECDSA/SHA256"
                        elif "Ed25519/SHA256" in sig_data:
                            signature_info["signature_algorithm"] = "Ed25519/SHA256"
                        
                        # Extract key ID
                        if "Key ID" in sig_data:
                            key_id_match = re.search(r'Key ID ([0-9a-fA-F]+)', sig_data)
                            if key_id_match:
                                signature_info["signature_key"] = key_id_match.group(1)
                        
                        # Extract date - handle various time formats including EST/EDT
                        date_match = re.search(r'([A-Za-z]{3} [A-Za-z]{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4})', sig_data)
                        if date_match:
                            signature_info["signature_date"] = date_match.group(1)
                    else:
                        signature_info["signature_type"] = "unsigned"
                        signature_info["signature_valid"] = False
                    i += 1
                    continue
                
                if line.startswith("Build Date"):
                    # This can help verify the package build time
                    build_date = line.split(":", 1)[1].strip() if ":" in line else None
                    if build_date:
                        signature_info["build_date"] = build_date
                i += 1
            
            # If no signature line was found, mark as unsigned
            if not signature_found:
                signature_info["signature_type"] = "unsigned"
                signature_info["signature_valid"] = False
            
            return signature_info
            
        except Exception as e:
            print(f"Failed to get detailed signature for package {package_name}: {e}")
            return {
                "signature_type": "unknown",
                "signature_valid": False,
                "error": str(e)
            }

    def get_rpm_metadata(self, rpm_path):
        """Extracts metadata from an RPM file."""
        if not os.path.isfile(rpm_path):
            print(f"RPM file not found: {rpm_path}")
            return {}

        # Use individual rpm queries instead of trying to output JSON directly
        try:
            metadata = {}
            
            # Get each field individually
            fields = {
                "name": "%{NAME}",
                "version": "%{VERSION}",
                "release": "%{RELEASE}",
                "arch": "%{ARCH}",
                "summary": "%{SUMMARY}",
                "license": "%{LICENSE}",
                "vendor": "%{VENDOR}",
                "url": "%{URL}",
                "packager": "%{PACKAGER}"
            }
            
            for field_name, field_format in fields.items():
                cmd = ["rpm", "-qp", rpm_path, "--queryformat", field_format]
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
                metadata[field_name] = result.stdout.strip()
            
            print(f"RPM metadata extracted: {metadata}")
            return metadata
            
        except subprocess.CalledProcessError as e:
            print(f"RPM command failed for {rpm_path}: {e.stderr}")
            return {}
        except Exception as e:
            print(f"Failed to extract RPM metadata: {e}")
            return {}

    def get_rpm_file_list(self, rpm_path):
        """Extracts the list of files from an RPM file."""
        cmd = ["rpm", "-qpl", rpm_path]
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
            files = result.stdout.splitlines()
            print(f"Files in RPM {rpm_path}: {files}")
            return files
        except subprocess.CalledProcessError as e:
            print(f"Failed to get file list for {rpm_path}: {e.stderr}")
            return []

    def get_rpm_file_info(self, rpm_path):
        """Extracts file hashes, ownership, and permissions from an RPM file using 'rpm -qp --dump'."""
        cmd = ["rpm", "-qp", "--dump", rpm_path]
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
            file_info = {}
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 8:
                    file_path = parts[0]
                    sha256 = parts[3]
                    # If the hash is all zeroes, treat as None
                    if sha256 == "0" * 64 or sha256 == "0000000000000000000000000000000000000000000000000000000000000000":
                        sha256 = None
                    
                    # Parse permissions (field 4), owner (field 5), group (field 6)
                    permissions = parts[4] if len(parts) > 4 else None
                    owner = parts[5] if len(parts) > 5 else None
                    group = parts[6] if len(parts) > 6 else None
                    
                    file_info[file_path] = {
                        "sha256": sha256,
                        "permissions": permissions,
                        "owner": owner,
                        "group": group
                    }
            print(f"File info for RPM {rpm_path}: {file_info}")
            return file_info
        except subprocess.CalledProcessError as e:
            print(f"Failed to get file info for {rpm_path}: {e.stderr}")
            return {}

    def get_rpm_dependencies(self, rpm_path):
        """Extracts the list of dependencies from an RPM file."""
        cmd = ["rpm", "-qpR", rpm_path]
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
            dependencies = result.stdout.splitlines()
            print(f"Dependencies for RPM {rpm_path}: {dependencies}")
            return dependencies
        except subprocess.CalledProcessError as e:
            print(f"Failed to get dependencies for {rpm_path}: {e.stderr}")
            return []

    def get_rpm_signature(self, rpm_path):
        """Extracts the GPG signature of an RPM file."""
        cmd = ["rpm", "-qpi", rpm_path]
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
            for line in result.stdout.splitlines():
                if line.startswith("Signature"):
                    print(f"GPG Signature for {rpm_path}: {line}")
                    return line
            return None
        except subprocess.CalledProcessError as e:
            print(f"Failed to get GPG signature for {rpm_path}: {e.stderr}")
            return None

    def hash_file(self, file_path):
        """Calculates the SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            print(f"Failed to hash file {file_path}: {e}")
            return None

    def extract_source_files_from_srpm(self, src_rpm_path):
        """Extracts source files from a source RPM."""
        print(f"Extracting source files from source RPM: {src_rpm_path}")
        source_files = []
        try:
            # List contents of source RPM
            cmd = ["rpm", "-qpl", src_rpm_path]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
            
            for line in result.stdout.splitlines():
                if line.startswith('/'):
                    # This is a file in the source RPM
                    filename = os.path.basename(line)
                    
                    # Try to extract the file and calculate its hash
                    temp_dir = "/tmp/srpm_extract"
                    os.makedirs(temp_dir, exist_ok=True)
                    
                    try:
                        # Extract just this file from the RPM
                        extract_cmd = f"rpm2cpio {src_rpm_path} | cpio -id {filename} 2>/dev/null"
                        subprocess.run(extract_cmd, shell=True, cwd=temp_dir, check=True)
                        
                        file_path = os.path.join(temp_dir, filename)
                        if os.path.isfile(file_path):
                            sha256 = self.hash_file(file_path)
                            signature = self.get_file_signature(file_path)
                            
                            source_files.append({
                                "filename": filename,
                                "sha256": sha256,
                                "digital_signature": signature
                            })
                            
                            # Clean up
                            os.remove(file_path)
                    except Exception as e:
                        print(f"Failed to extract {filename} from source RPM: {e}")
                        # Add without hash if extraction fails
                        source_files.append({
                            "filename": filename,
                            "sha256": None,
                            "digital_signature": None
                        })
            
            # Clean up temp directory
            try:
                os.rmdir(temp_dir)
            except:
                pass
                
            print(f"Extracted source files from source RPM: {source_files}")
        except Exception as e:
            print(f"Failed to extract source files from source RPM {src_rpm_path}: {e}")
        
        return source_files
