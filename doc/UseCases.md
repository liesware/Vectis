# Vectis Use Cases

This guide maps each Vectis feature to a **real-world data-protection problem**.
For every feature it answers three questions in the same shape:

- **Problem** — the pain you are trying to solve.
- **Solution** — how the feature addresses it, and why.
- **Use cases** — concrete scenarios where it fits.

Each entry also includes a short example and a **When not to use it** note, because
several of these primitives look similar but solve different problems.

> **Status: experimental.** Vectis is a work in progress: incomplete, not audited,
> and not production-ready. **Do not use Vectis with real patient data, production
> secrets, financial records, or any other real sensitive data.** The scenarios
> below are illustrative, not deployment guidance. See
> [README.md](../README.md) and [doc/ThreatModel.md](ThreatModel.md).

Vectis's job is narrow: TLS protects the *connection*, but sensitive data keeps
moving through applications, queues, storage, logs, and workers after the
transport session ends. Vectis protects the **data object itself** once it leaves
the transport layer. It does not replace TLS, KMS, HSMs, databases, or access
control.

For the exact request/response schema of every endpoint, see
[doc/API.md](API.md); for the CLI, see [doc/CLI.md](CLI.md).

## How to choose

| If your problem is… | Use |
| --- | --- |
| Encrypt a value but keep its **format and length** (reversible) | **FPE** |
| Replace a value with a **random surrogate** you can reverse later | **Tokenization** |
| Detect **tampering** of a value (integrity + authenticity) | **MAC** |
| **Search** protected data by equality without storing plaintext | **Blind Index** |
| **Commit** to a value now and reveal it later (hiding + binding) | **Commitments** |
| Show only **part** of a value on screen (e.g. last 4 digits) | **Masking** |
| Move a record to **another service or organization** | **Protected Messages** |
| Protect a payload **locally at rest** | **Internal encrypt/decrypt** |
| Prove a document's **authenticity and time** | **Signatures** |

All field-level operations (FPE, Tokenization, MAC, Blind Index, Commitments,
Masking) are **profile-driven**: profiles live only in the operator-signed
`config.json` and requests select one by name. The request cannot smuggle in
algorithm parameters — those come from signed config.

---

## FPE — Format-Preserving Encryption

**Problem.** You must encrypt a value such as a credit-card number, but the systems
around it still expect the original *shape*: a fixed-length numeric string, a
validated column type, a field that passes a format check. Standard encryption
turns `4111111111111111` into a long binary blob that breaks those systems.

**Solution.** FPE (FF1) encrypts within an alphabet and length range defined by a
signed profile, so the ciphertext keeps the same format as the plaintext
(digits stay digits, length is preserved). It is reversible and **deterministic**
for the same key, profile, tweak, and plaintext. It does **not** authenticate the
data and does not replace message encryption.

**Use cases.**

- Store PANs, SSNs, or bank-account numbers in existing fixed-format columns.
- Protect identifiers that flow through legacy systems with strict format checks.
- Keep referential shape (same length, same character class) across a pipeline.

**Example.**

```sh
vectis fpe encrypt <kid> --json '{"ref":"reg1","profile":"patient-id-decimal-v1","plaintext":"123456"}'
# -> "ciphertext":"839201"   (same length, same alphabet)
```

**When not to use it.** If you don't need the original format preserved and would
rather keep the value out of the record entirely, use **Tokenization**. If you only
need to *display* a partial value, use **Masking**. FPE alone provides no tamper
detection — pair with a **MAC** if you need integrity.

---

## Tokenization — Reversible Random Tokens

**Problem.** You want to keep a sensitive value usable in analytics, logs, or a
lower environment, but you don't want the real value to appear there at all — and
you don't need it to keep any particular format.

**Solution.** Tokenization returns a **random** token (a configured prefix plus
random bytes) and stores the original plaintext encrypted in the database. The
database only ever sees `kid`, a hash id, and encrypted data — never the plaintext
or the visible token. Because tokens are random, the **same plaintext produces a
different token each time**. Detokenization happens only through Vectis.

**Use cases.**

- Swap sensitive fields for tokens before they reach analytics or data lakes.
- Share referentially-safe surrogates with lower environments or third parties.
- Remove real values from logs and event streams while keeping them recoverable.

**Example.**

```sh
vectis token encode <kid> --json '{"ref":"reg1","profile":"patient-id-token-v1","plaintext":"123456","metadata":{}}'
# -> "token":"tok_patient_vGqyEeXKcKz5QK1jwBQTyQ"
vectis token decode --json '{"ref":"reg1","kid":"<kid>","profile":"patient-id-token-v1","token":"tok_patient_vGqyEeXKcKz5QK1jwBQTyQ"}'
```

**When not to use it.** If downstream systems require the original *format*, use
**FPE**. If you never need to reverse the value and only want equality lookups, use
a **Blind Index**. Tokenization requires a datastore; FPE and MAC do not.

---

## MAC — Keyed Integrity and Authenticity

**Problem.** You need to detect whether a value or record has been tampered with,
and prove it was produced by a party holding the key — not by an attacker who can
write to your storage.

**Solution.** MAC computes a keyed tag over the value using HMAC or KMAC (chosen by
the operational key's hash algorithm) and a signed `context` label. Verifying
recomputes the tag and compares it in constant time. Any change to the value yields
a different tag.

**Use cases.**

- Detect tampering of a stored field or a record in transit between components.
- Bind a value to a purpose/tenant via the signed `context` label.
- Provide an integrity check alongside FPE or tokenized values.

**Example.**

```sh
vectis mac create <kid> --json '{"ref":"reg1","profile":"pan-blind-index-v1","plaintext":"4111111111111111"}'
# -> "digest":"<hex>"
vectis mac verify --json '{"ref":"reg1","kid":"<kid>","profile":"pan-blind-index-v1","plaintext":"4111111111111111","digest":"<hex>"}'
# -> "valid": true
```

**When not to use it.** MAC is a stateless check — it does not store anything. If
you want to *search* by the digest (membership/lookup), use a **Blind Index**,
which computes the same digest but persists it.

---

## Blind Index — Equality Search Over Protected Data

**Problem.** You've protected a field (encrypted, tokenized, or removed), but you
still need to answer "do we already have this SSN?" or "find the row for this
email" — without storing the plaintext to search on.

**Solution.** A blind index reuses a signed MAC profile: `/index` computes the
same deterministic digest that `/mac` would, and stores it in the local
`indexes` table. Storage keeps only `kid` and the digest — never the plaintext,
profile, metadata, or client `ref`. Because the digest is deterministic, equal
plaintexts produce equal digests, enabling equality lookups. Configure blind
index profiles with `vectis config mac`; there is no separate `config index`.

**Use cases.**

- Deduplicate records by a sensitive key without storing that key.
- Look up customers by SSN, email, or account number over protected data.
- Support equality joins across systems that never see the plaintext.

**Example.**

```sh
vectis index create <kid> --json '{"ref":"reg1","profile":"pan-index-v1","plaintext":"4111111111111111"}'
# -> "index":"<hex>"   (stored for later membership checks)
vectis index verify --json '{"ref":"reg1","kid":"<kid>","profile":"pan-index-v1","plaintext":"4111111111111111"}'
# -> "matched": true
```

**When not to use it.** If you need to recover the original value, use
**Tokenization** or **FPE** — a blind index is one-way. If you only need a
stateless integrity tag, use **MAC**. Deterministic digests reveal equality, so
choose the profile `context` deliberately.

---

## Commitments — Commit Now, Reveal Later

**Problem.** You want to prove that a value existed and was fixed at a certain time
— a sealed bid, a decision, an audit pledge — without revealing the value yet, and
without anyone (including you) being able to change it afterward.

**Solution.** A commitment is keyed, **hiding** (the commitment reveals nothing
about the value), and **binding** (you can't later open it to a different value).
Create generates a random `opening` and returns a commitment; it is stateless and
nothing is stored. Because the opening is random, **two commitments to the same
plaintext differ**. Later, verify recomputes the commitment from the plaintext,
opening, profile, KID, and signed context.

**Use cases.**

- Sealed-bid or first-price auctions: publish commitments, reveal openings later.
- Tamper-evident "this value existed at this time" pledges in an audit trail.
- Fair ordering / anti-front-running: commit to a choice before revealing it.

**Example.**

```sh
vectis commit create <kid> --json '{"ref":"reg1","profile":"pan-commitment-v1","plaintext":"4111111111111111"}'
# -> "commitment":"<hex>", "opening":"<base64url>"
vectis commit verify --json '{"ref":"reg1","kid":"<kid>","profile":"pan-commitment-v1","plaintext":"4111111111111111","opening":"<base64url>","commitment":"<hex>"}'
# -> "valid": true
```

**When not to use it.** If you want a stable tag that equal inputs always reproduce
(for lookup or integrity), use **MAC** or **Blind Index** — a commitment is
deliberately non-deterministic. Commitments are not encryption: they don't let you
recover the value, only verify it once revealed.

---

## Masking — Display-Only Redaction

**Problem.** A support agent or a UI needs to show *enough* of a value to recognize
it (the last four digits of a card) without exposing the whole thing, and logs
should never carry the full value.

**Solution.** Masking is a **display-only** transform. It does not encrypt,
tokenize, persist, or derive keys. A signed profile controls how many characters
stay visible at the start and end, and which single character masks the middle.

**Use cases.**

- Show `************1111` on customer-support and account screens.
- Redact values in logs and receipts while keeping them recognizable.
- Present partial identifiers in UIs that must not hold the full value.

**Example.**

```sh
vectis mask <kid> --json '{"ref":"row1","profile":"pan-display-v1","plaintext":"4111111111111111"}'
# -> "masked":"************1111"
```

**When not to use it.** Masking is **not reversible** and provides no
cryptographic protection — it's presentation only. To keep a recoverable value, use
**FPE** or **Tokenization**, and mask the recovered value for display.

---

## Protected Messages — Cross-Service / Cross-Org Exchange

**Problem.** A record must travel from one service or organization to another and
stay protected the whole way — including at the receiving end, where the local
application should not be handed the sender's plaintext directly.

**Solution.** Vectis protects the payload with hybrid post-quantum key
establishment (XECDH + ML-KEM), authenticated encryption, and **dual signatures**
(EdDSA + ML-DSA, both required to verify). The receiving Vectis verifies and
decrypts, then **re-encrypts locally** before delivery, so the receiving app must
ask its local Vectis to decrypt — it never gets remote plaintext directly. Peer
public keys come only from the operator-signed config (no trust-on-first-use).

**Use cases.**

- Exchange clinical or financial records between two organizations after TLS ends.
- Move sensitive payloads between internal services with end-to-end protection.
- Post-quantum-ready protection for data objects that outlive their transport.

**Example.**

```sh
vectis message send <sender_kid> --json '{"recipient_kid":"<recipient_kid>","message":"hello vectis"}'
vectis message decrypt --file encrypted-message.json
```

See the two-site clinical demo in [demo/message/README.md](../demo/message/README.md).

**When not to use it.** If the data never leaves the local node, you don't need the
network exchange — use **Internal encrypt/decrypt**. If you only need to prove a
document's authenticity (not confidentiality), use **Signatures**.

---

## Internal Encrypt/Decrypt — Local Data at Rest

**Problem.** You need to hold a sensitive blob locally — in a queue, cache, or
database — and decrypt it later, without running the full inter-instance exchange
flow.

**Solution.** Internal messages are encrypted and decrypted with the symmetric key
bound to a `kid`, using authenticated encryption. This is local protection for a
single node, not a network protocol.

**Use cases.**

- Encrypt a payload before putting it on an internal queue or cache.
- Protect a column or blob at rest and decrypt it on read through Vectis.
- Stage sensitive intermediate results during processing.

**Example.**

```sh
vectis message internal encrypt <kid> --file plaintext.json
vectis message internal decrypt --file internal-message.json
```

**When not to use it.** If the data must reach *another* Vectis instance or
organization, use **Protected Messages**, which adds peer key establishment,
signatures, and re-encryption at the boundary.

---

## Signatures — Authenticity and Timestamp

**Problem.** You need to prove that a document, config, or receipt is authentic and
existed at a given time, and that both a classical and a post-quantum signer vouch
for it.

**Solution.** `POST /sign/{kid}` signs a message hash with **both** EdDSA and
ML-DSA over canonical JSON, embedding a timestamp and signer info.
`POST /sign/verification` checks both signatures — verification succeeds only when
**both** are valid. The verifier can resolve the signer's public keys locally or
from a trusted peer in signed config, enabling cross-instance verification.

**Use cases.**

- Prove authenticity and time of a generated document, receipt, or export.
- Attach a post-quantum-ready signature to configuration or audit artifacts.
- Verify a signed artifact produced by a peer instance.

**Example.**

```sh
vectis sign <kid> --json '{"message_hash":{"alg":"SHA-256","hex":"<64 hex chars>"}}'
vectis sign verify --file token.json
# -> "valid": "ok"   (only when BOTH eddsa and ml-dsa verify)
```

**When not to use it.** Signatures prove authenticity, not confidentiality — they
don't hide the value. To keep the payload secret in transit, use **Protected
Messages**.

---

## Combining features: protecting a credit-card PAN end-to-end

The features compose rather than compete. A typical PAN workflow might use several
at once:

- **Store the value** with **FPE** (keep the numeric format for existing columns)
  *or* **Tokenization** (replace it with a random surrogate and store the original
  encrypted).
- **Search** for a card without storing plaintext with a **Blind Index** — e.g.
  "have we seen this PAN before?".
- **Display** the card on support screens with **Masking** (`************1111`).
- **Pledge** a value in an audit trail with a **Commitment**, revealing it only
  when needed.
- **Move** the record to another service or organization with **Protected
  Messages**, and prove artifacts with **Signatures**.

Each feature does one thing well; combining them covers store, search, display,
audit, and transfer without any single step exposing the raw value.
