# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest (main) | Yes |
| Previous minor | Yes (for 90 days) |
| Older | No |

## Reporting a vulnerability

**Please do not report security vulnerabilities via public GitHub Issues.**

If you discover a security vulnerability in this project, open a [GitHub Security Advisory](https://github.com/enabled404/cvestate/security/advisories/new) or contact the maintainer directly via GitHub.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

You will receive an acknowledgment within **48 hours** and a resolution timeline within **7 days**.

## Security design notes

This server makes **outbound HTTPS requests only** to known security APIs. It does not:

- Open inbound network ports
- Execute code from external sources
- Store API keys in logs or cache
- Process user-supplied XML without `defusedxml` protection
- Query private/internal IP addresses via external APIs (blocked at the validation layer)

For full details see the [Security and Privacy](README.md#-security-and-privacy) section of the README.
