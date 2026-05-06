# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

FoxRecon is a security tool. If you discover a vulnerability in the platform itself:

1. **Do NOT open a public issue**
2. Email `f0xf0st3r` directly or use GitHub's private vulnerability reporting
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline
- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix**: Within 2-4 weeks depending on severity
- **Disclosure**: Coordinated with reporter

## Scope

This policy covers:
- FoxRecon core application
- API authentication mechanisms
- Data handling and storage
- Dependencies with known CVEs

Out of scope:
- The security tools FoxRecon orchestrates (nuclei, subfinder, etc.)
- Third-party services used by FoxRecon
