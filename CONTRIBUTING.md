# Contributing

Thank you for helping. Bug reports, ideas and questions are welcome as
GitHub issues; security problems go through SECURITY.md, privately.

## Before your first pull request: the CLA

DNSNova is published under the AGPL-3.0 and also licensed commercially
(COMMERCIAL.md). To include your code in both, contributions are accepted
under the **DNSNova Contributor License Agreement** (CLA.md). In short:

- you keep the copyright in what you write;
- you allow the maintainer to license it under other terms as well,
  including commercial ones;
- the maintainer promises it also stays available under the AGPL.

When you open your first pull request, a bot asks you to sign by posting a
comment; it takes a minute and covers all your later contributions. A pull
request cannot be merged until the CLA is signed. If your employer has
rights in your work, it needs to agree first: ask for the corporate
agreement through https://novaod.com/licensing.

Issues, comments and reviews need no CLA.

## Making a change

- Open an issue first for anything larger than a fix, so the approach can
  be agreed before you spend time on it.
- Every change comes with tests: show that they fail without the change and
  pass with it.
- Before submitting: `gofmt -l .` prints nothing, and `go vet ./...` and
  `go test -race ./...` pass.
- Keep dependencies to what is already used. A new one must have a
  permissive license (MIT, BSD, Apache-2.0, ISC) and be added, with its
  license text, to THIRD_PARTY_NOTICES.md; a test checks it is there.
  Code under GPL-family or other copyleft licenses cannot be accepted.
- Do not paste code from elsewhere unless its license is permissive, and
  say where it came from in the pull request.
- Note user-visible changes in CHANGELOG.md under "Unreleased".

## For the maintainer: setting up CLA signing

Use the CLA Assistant GitHub App (https://cla-assistant.io): connect the
repository, point it at CLA.md, and require its status check on `main` in
the branch protection rules. Signatures are recorded with the GitHub
account and date. Until it is set up, ask each contributor to post this on
their pull request, and keep the link:

> I have read the DNSNova Contributor License Agreement (CLA.md, version
> 1.0) and I agree to it for this and all my future contributions.
