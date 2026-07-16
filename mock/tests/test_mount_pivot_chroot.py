# -*- coding: utf-8 -*-
# vim:expandtab:autoindent:tabstop=4:shiftwidth=4:filetype=python:textwidth=0:
# License: GPL2 or later see COPYING

"""
Tests for pivot_root(2) chroot technique to enable user namespaces.
"""

import ctypes
import os
import shutil
import tempfile

import pytest

# Import constants from mockbuild.util
from mockbuild.util import MS_BIND, MNT_DETACH, condChrootPivotRoot

_libc = ctypes.cdll.LoadLibrary(None)
_libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                         ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
_libc.mount.restype = ctypes.c_int
_libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
_libc.umount2.restype = ctypes.c_int
_libc.unshare.argtypes = [ctypes.c_int]
_libc.unshare.restype = ctypes.c_int
_libc.syscall.restype = ctypes.c_long

CLONE_NEWNS  = 0x00020000
CLONE_NEWUSER = 0x10000000


def has_cap_sys_admin():
    """Check if we have CAP_SYS_ADMIN capability."""
    try:
        # Try to create a mount namespace - requires CAP_SYS_ADMIN
        test_dir = tempfile.mkdtemp()
        try:
            result = _libc.mount(test_dir.encode(), test_dir.encode(),
                               None, MS_BIND, None)
            if result == 0:
                # Cleanup the mount
                _libc.umount2(test_dir.encode(), MNT_DETACH)
                return True
        finally:
            os.rmdir(test_dir)
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    return False


@pytest.mark.skipif(not has_cap_sys_admin(),
                    reason="requires CAP_SYS_ADMIN (run in --privileged container or as root)")
def test_condChrootPivotRoot_function():
    """
    Test the condChrootPivotRoot() function directly.

    This test verifies that the actual Mock function works correctly.
    """
    chroot_dir = tempfile.mkdtemp(prefix="mock-test-chroot-")

    try:
        # Create minimal structure
        os.makedirs(os.path.join(chroot_dir, "bin"), exist_ok=True)
        os.makedirs(os.path.join(chroot_dir, "lib"), exist_ok=True)

        pid = os.fork()
        if pid == 0:
            # Child process
            try:
                # Use the Mock function (it handles making mounts private internally)
                condChrootPivotRoot(chroot_dir)

                # Try to create user namespace
                rc = _libc.unshare(CLONE_NEWUSER)

                os._exit(0 if rc == 0 else 1)

            except Exception:  # pylint: disable=broad-exception-caught
                os._exit(2)

        _, status = os.waitpid(pid, 0)
        assert os.WIFEXITED(status)
        exit_code = os.WEXITSTATUS(status)

        if exit_code == 1:
            pytest.fail("unshare(CLONE_NEWUSER) failed after condChrootPivotRoot")
        elif exit_code == 2:
            pytest.fail("Exception in condChrootPivotRoot")

        assert exit_code == 0

    finally:
        try:
            shutil.rmtree(chroot_dir)
        except IOError:
            pass


def test_condChrootPivotRoot_with_none():
    """
    Test that condChrootPivotRoot() handles None gracefully.

    This is a simple sanity test that doesn't require special privileges.
    """
    # Should not raise any exception
    condChrootPivotRoot(None)
