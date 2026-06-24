# Vectis

> “Vectis” in Roman context means a lever, crowbar, handspike, or similar bar used to lift, pry, or move heavy objects. In Latin sources it’s a general term for a strong pole or bar used with leverage, and it could also refer to a bar for fastening a door or a carrying pole.

Vectis is an personal open source project for sensitive data lifecycle protection.

The goal is simple: explore how to reduce the exposure of sensitive data while it moves through applications, services, storage systems and internal infrastructure.

This is an early project and the first public version should be treated as a work in progress.

## Why Vectis?

Many systems already use TLS, encrypted disks, secrets managers, KMS, HSMs or vaults.

Those tools are important, but sensitive data can still appear in plaintext inside:

- application payloads
- logs
- queues
- databases
- backups
- internal APIs
- temporary processing steps

Vectis is an attempt to explore a different question:

> What if data would be protected during its life cycle?

## What Vectis is

Vectis aims to become a small, modular cryptographic layer for protecting sensitive data flows.

Possible areas of work include:

- encrypted payloads
- signed messages
- cryptographic metadata
- timestamping
- gateway-based protection
- integration with external key systems
- hybrid and post-quantum cryptography experiments

The project is being built in Rust because Rust is a good fit for security-oriented infrastructure where correctness, safety and performance matter.

## What Vectis is not

Vectis is not a replacement for:

- HashiCorp Vault
- cloud KMS services
- HSMs
- traditional DLP tools
- TLS
- database encryption
- access control systems

The intention is to complement existing security infrastructure, not replace it.

## Current status

Vectis is in a very early stage.

At this point, the project should be considered:

- experimental
- incomplete
- not audited
- not production-ready
- subject to major design changes

**Do not use Vectis to protect real sensitive data yet.**

## Example idea

A future Vectis flow may look like this:

```text
Application
    |
    | sensitive payload
    v
Vectis
    |
    | encrypted and signed payload
    v
Database / Queue / API / Storage
