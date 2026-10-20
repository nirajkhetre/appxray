# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately with GitHub's **Report a vulnerability** button
on the repository's Security tab. Do not open a public issue.

Include the appxray version (`appxray --version`), your operating system, steps to reproduce
and, if relevant, a report produced with `--redact-paths`. Do not attach proprietary
binaries; describe them instead.

You will get an acknowledgement within 5 working days. Fixes are released as patch
versions and credited in the changelog unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes.

## Security model

appxray processes untrusted input: the files of installed applications. Its safeguards:

- **No execution.** Inspected applications are never run, loaded or modified. Binaries are read
  in bounded chunks and searched for fixed byte patterns; there is no general binary parser.
- **Bounded parsing.** Fuse wires, ASAR headers (64 MiB limit) and manifests (1 MiB limit) are
  size-checked before use; malformed data is ignored.
- **No network during scans.** Only `db update` makes requests, to the fixed public sources
  listed in `docs/how-it-works.md`, with size limits, timeouts and certificate validation by
  Node.js. A GitHub token, if provided, is sent only to `api.github.com`.
- **Database validation.** The vulnerability database is structurally validated before use; an
  invalid file stops the scan instead of producing an empty-looking report.
- **Optional external tools.** PowerShell or `reg.exe` (Windows registry) and REA (`--deep`
  only) are run without a shell, with fixed arguments, timeouts and output limits.
- **Report safety.** HTML reports escape all values, load no external resources and set a
  restrictive Content-Security-Policy.
- **Supply chain.** One required runtime dependency (`semver`) plus REA as an exact-pinned
  optional dependency, a committed lockfile, GitHub Actions pinned to commit SHAs, and npm
  publishing with provenance. REA runs as a separate process with fixed arguments, a time
  limit and an output limit, and its output is validated before use.
