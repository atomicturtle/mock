New `separate_check` config option to run %check as a separate rpmbuild
phase (-bk --short-circuit).  This prevents %check scripts from modifying
already built RPM artifacts.  Supported values: `off` (default),
`best_effort`, and `enforce`.
