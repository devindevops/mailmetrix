# Security Policy

MailMetrix is a self-hosted email infrastructure diagnostics application.

Because the application can interact with SMTP servers and process email-related data, security reports are taken seriously.

## Supported Versions

MailMetrix is under active development.

Until versioned releases and a formal support policy are established, please report security issues affecting the current default branch.

Older commits and unofficial builds may not receive security fixes.

## Reporting a Vulnerability

**Please do not disclose exploitable vulnerabilities in public GitHub issues.**

To report a security issue:

1. Open the MailMetrix repository on GitHub.
2. Check whether private vulnerability reporting is enabled under the repository's Security settings.
3. If available, use the private vulnerability reporting feature to submit your report.
4. If private reporting is unavailable, contact the repository maintainers through a private channel published in the organization's profile.

Repository:

https://github.com/devindevops/mailmetrix

Please do not include passwords, active SMTP credentials, API keys, private keys, or real users' email contents in a report.

## What to Include

When possible, provide:

- A clear description of the vulnerability.
- The affected component or endpoint.
- The conditions required to reproduce the issue.
- The potential security impact.
- Steps to reproduce the issue in a controlled environment.
- Suggested mitigations, if known.

Please use synthetic credentials and test data when demonstrating issues.

## Scope

Security reports related to the following areas are relevant:

- Exposure or unintended storage of SMTP credentials.
- Sensitive information appearing in application logs or error responses.
- Authentication or access-control weaknesses.
- Server-side request forgery or unsafe outbound connections.
- Injection vulnerabilities and insufficient input validation.
- Insecure handling of DKIM private keys or generated secrets.
- Container, deployment, or configuration weaknesses that expose the application.
- Denial-of-service risks affecting diagnostic endpoints.
- Unintended disclosure of submitted email headers or other sensitive data.

This list is not exhaustive.

## Disclosure

Please allow the maintainers reasonable time to investigate and address a reported vulnerability before publicly disclosing technical details.

The maintainers will assess the report, work to reproduce the issue, and determine an appropriate remediation and disclosure plan.

Submitting a report does not guarantee a particular response time or that a proposed fix will be accepted.

## Security Disclaimer

MailMetrix is provided for email infrastructure diagnostics and configuration assistance.

Self-hosting alone does not guarantee that credentials or other sensitive information cannot be exposed. Deployers remain responsible for access controls, network security, secret management, and the security of their hosting environment.