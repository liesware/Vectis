# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| `0.8.x` | Yes |
| Earlier versions | No |

Vectis `0.8.x` is experimental. It has not completed an external security
audit, and its API and signed-config contracts may change before `1.0`.

## Reporting a Vulnerability

Report suspected vulnerabilities privately to
[liesware@protonmail.com](mailto:liesware@protonmail.com) with the subject
`Vectis security report`.

Include, where available:

- affected Vectis version or commit;
- impact and attack prerequisites;
- minimal reproduction steps or proof of concept;
- affected endpoint, configuration, storage backend, or artifact format; and
- any proposed mitigation.

Do not open a public issue for an unpatched vulnerability. Do not send
production secrets, plaintext records, API keys, unseal keys, private keys, or
full sensitive audit data. If protected exchange is needed, request an
appropriate channel in the initial report.

We aim to acknowledge reports within five business days and provide status
updates while investigating. This is not a guaranteed remediation SLA and
Vectis does not currently offer a bug bounty program.

## Scope

Security reports are welcome for:

- Vectis source code and official release artifacts;
- cryptographic primitives and protocol implementations;
- signed configuration, key material handling, storage, lifecycle, and
  authorization behavior;
- HTTP and CLI inputs, local artifact parsers, audit verification, and release
  supply-chain controls.

Reports about unsupported local modifications, hypothetical issues without a
plausible impact path, or availability problems requiring resources outside the
documented limits may receive lower priority. Good-faith reports with a clear
security impact are still welcome.

## Disclosure

Please allow time to investigate and prepare a fix before public disclosure.
When a report is resolved, Vectis will coordinate disclosure with the reporter
where practical. Reporter credit is given only with explicit permission.

Security fixes and advisories are recorded in release notes and
[CHANGELOG.md](CHANGELOG.md). Consult [README.md](README.md) and
[doc/ThreatModel.md](doc/ThreatModel.md) for current security boundaries and
known limitations.
