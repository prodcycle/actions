# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this GitHub Action, please report it responsibly.

**Do not open a public issue.**

Instead, email **security@prodcycle.com** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact

We will acknowledge your report within 2 business days and aim to provide a fix within 7 days for critical issues.

## Scope

This policy covers the `prodcycle/compliance-verification-action` GitHub Action code. For vulnerabilities in the ProdCycle API or platform, please report those separately at [prodcycle.com/security](https://prodcycle.com/security).

## API Key Security

- Never commit your `cvk_` API key to source code
- Always use [GitHub encrypted secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets) to store your ProdCycle API key
- The action automatically masks the API key in workflow logs
