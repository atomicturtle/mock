New `pivot_root_chroot` configuration option uses `pivot_root(2)` inside a
private mount namespace to atomically swap the mount-namespace root to the
chroot path. This satisfies the kernel check that blocks
`unshare(CLONE_NEWUSER)` after plain `chroot()`, allowing tools like
pasta/passt that require user namespaces to work inside mock buildroots.
This is the same approach used by bubblewrap and other container runtimes.
Requires `CAP_SYS_ADMIN` (available in `--privileged` containers); falls back
to plain `chroot()` on failure.
Set `config_opts['pivot_root_chroot'] = True` to enable.
