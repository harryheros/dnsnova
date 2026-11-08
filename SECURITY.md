# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report them privately through GitHub: open the repository's **Security**
tab and choose **Report a vulnerability**. Include the DNSNova version, how
to reproduce the problem and what you believe the impact is.

You can expect an acknowledgement within a few days. Once a fix is ready, a
release is published and the issue is described in the changelog, crediting
you if you wish.

## Supported versions

Until 1.0 is released, only the latest commit on `main` receives fixes.

## Scope

Of particular interest:

- crashes, hangs or memory growth caused by network input;
- ways to make DNSNova amplify traffic towards a third party;
- ways to bypass the access list in private mode;
- cache poisoning;
- configuration handling that could expose secrets.
