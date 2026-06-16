# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅       |

## Reporting a Vulnerability

SYNTROPY is a meta-project that orchestrates K-Scanner, LinSpec, and S.I.R.E.N for Linux forensic analysis.

If you discover a security vulnerability in any component, please do NOT open a public issue.

Contact the maintainer directly at jefferson.antunes@gmail.com with details about the issue.

We commit to acknowledging receipt within 48 hours and providing a fix timeline within 7 days.

## Security Features

- Comprehensive .gitignore (125+ patterns covering secrets, keys, cloud configs)
- All forensic artifacts gitignored (dumps/, reports/, results/)
- Compiler hardening flags in all C subprojects (FORTIFY_SOURCE, PIE, RELRO, stack protector)
- No hardcoded secrets in any component

## Known Limitations

- Tools require root privileges for forensic operations
- Shell scripts may be subject to TOCTOU during submodule calls
