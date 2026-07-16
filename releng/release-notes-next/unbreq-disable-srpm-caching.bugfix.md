The `unbreq` plugin now no longer caches the mapping of a source RPM file to its
`BuildRequires` fields, fixing a logic error where it would ignore later
automatically generated `BuildRequires` fields if `BuildRequires` autogeneration
is used.

The original reason for implementing caching was to avoid scanning the same
`src.rpm` file multiple times. This is not a performance issue though and the
simplest correct solution is to scan source RPMs after each installation of
`BuildRequires` fields.
