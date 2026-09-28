# Security policy

SecMPro is a security product; reports about weaknesses in the protocol (SecMP/1), the client, the relay or the
build and supply chain are very welcome.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

Report privately through GitHub's private vulnerability reporting for this repository ("Security" tab →
"Report a vulnerability"; enabled when the repository becomes public — while it is private, collaborators report
to the owner directly). Please include the affected component and version or commit, the impact, and the
steps or proof of concept needed to reproduce it. Reports may be written in English or German.

A dedicated disclosure contact with an encryption key and an RFC 9116 `security.txt` will be published before
the first release (milestone M11, docs/07). Until then, GitHub's private reporting is the only channel.

## What to expect

* Acknowledgement of the report and a first assessment.
* Coordinated disclosure: a fix and an advisory are prepared privately; the reporter is credited unless they
  prefer otherwise.
* Security fixes are released as soon as they are ready; no embargo is imposed on reporters beyond a
  reasonable coordination period agreed with them.

## Scope

In scope: everything in this repository — the protocol specification (`docs/03-protocol-spec.md`), all crates,
the relay deployment (`deploy/`), the build, CI and release process. Known, accepted limits are listed in the
threat model (`docs/01-threat-model.md`, residual-risk register §7); a report showing that a stated property does
not hold is always in scope.

## Supported versions

There is no release yet (pre-1.0, implementation milestone M0). Once released, only the latest release receives
security fixes.
