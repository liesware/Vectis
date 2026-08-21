# Contributing

Vectis welcomes focused bug fixes, tests, documentation, security hardening,
and features that fit its data-protection boundary.

## Start With Scope

Every proposal must answer:

> **Is this responsibility intrinsic to Vectis, or are we taking work away from
> a layer that already solves it well?**

Vectis follows the Unix philosophy: do one thing and do it well. Each pull
request should solve one concrete problem and preserve that boundary.

Discuss changes to cryptography, protocols, storage formats, trust boundaries,
or public contracts before implementing them.

## Keep Changes Small

Pull requests should be easy to understand and verify. As a guideline, keep
handwritten production-code changes within 128 added or removed lines. Tests,
documentation, lockfiles, and generated artifacts do not count toward this
limit.

Do not omit tests or documentation to make a change appear smaller. If a change
cannot be divided without leaving the system inconsistent or unsafe, discuss it
first and explain why it must remain atomic.

## AI-Assisted Contributions

Vectis does not prescribe how contributors work. AI-assisted contributions are
welcome, but the person submitting the pull request assumes full responsibility
for every proposed change, including its correctness, security, documentation,
and validation. Responsibility cannot be delegated to an AI tool.

*Vectis evaluates contributions by their quality, traceability, and supporting
evidence, not by the tools used to create them.*

The pull request must briefly disclose material use of AI and document the
concrete problem, rationale, supporting evidence, and tests performed. Broad
repository rewrites, speculative feature inventories, and changes produced
solely from open-ended prompts are not compatible with this project's review
and assurance model.

Start from a concrete problem and provide evidence that the solution works.

## Before Submitting

Run:

```sh
cargo fmt -- --check
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
git diff --check
```

Report suspected vulnerabilities privately through [SECURITY.md](SECURITY.md).
Do not publish details of an unpatched vulnerability in a public issue.
