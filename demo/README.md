# Vectis Clinical Data Exchange Demo

## The Problem

Healthcare systems often need to exchange patient records between different
clinical sites, applications, and operational boundaries. TLS protects the
network channel while the request is in transit, but the patient record itself
can still be exposed or mishandled after it leaves that channel:

- intermediate services may forward the payload;
- queues or workers may temporarily hold the record;
- final applications may receive data from a local service boundary;
- operational logs and debugging tools may accidentally capture payloads;
- different sites may use different local storage and delivery policies.

In that model, protecting only the connection is not enough. The clinical record
needs protection as a data object.

## The Solution

Vectis demonstrates **Data Lifecycle Protection**: the data is protected before
it leaves the sender's trusted boundary and remains protected until the receiver
explicitly unwraps it through its local Vectis instance.

This demo runs two local clinical sites:

- **Clinic A** owns a patient record JSON file.
- **Clinic B** receives the protected clinical record.
- **Vectis A** protects and sends the record.
- **Vectis B** verifies, opens, and re-protects the record for Clinic B's final
  application.

The demo does not replace TLS. In production, TLS should still be used. Vectis
adds object-level protection so the clinical record remains protected beyond the
transport session.

## What Vectis Protects

When Clinic A sends `personaldata.json`, Vectis applies:

- hybrid key establishment with XECDH + ML-KEM;
- authenticated encryption for the protected message;
- EdDSA and ML-DSA signatures over the protected payload;
- authenticated associated data that binds protocol version, message type,
  sender key, recipient key, KEM algorithm, cipher algorithm, and timestamp;
- local re-encryption before delivery to the receiver's final app.

The receiving final app does not get raw plaintext directly from the remote
site. It receives a local encrypted delivery and must call its local Vectis
`/message/decrypt` endpoint to recover the clinical record.

## End-To-End Flow

1. Clinic A starts its final app and enters a patient record file path:

   ```text
   clinic-a file: ../personaldata.json
   ```

2. Clinic A reads and validates the file as JSON.

3. Clinic A sends the clinical record to Vectis A:

   ```http
   POST /message/{clinic_a_kid}
   X-API-Key: <clinic-a client apikey>
   ```

   ```json
   {
     "recipient_kid": "<clinic-b-kid>",
     "message": "{...patient record JSON as a string...}"
   }
   ```

4. Vectis A resolves Clinic B's KID through the signed `remote_routes` section of
   `config.json` and uses the peer's `public_keys` registered there. The signed
   config is the only source of peer public keys; there is no runtime fetch.

5. Vectis A creates a protected message:

   - derives a hybrid shared secret;
   - derives a message key with HKDF;
   - encrypts the clinical record;
   - signs the protected payload with EdDSA and ML-DSA;
   - sends the protected message to Vectis B.

6. Vectis B receives the protected message:

   ```http
   POST /message
   ```

7. Vectis B validates the message schema, verifies the signatures, decapsulates
   ML-KEM, performs XECDH, derives the same message key, and decrypts the
   clinical record.

8. Vectis B re-encrypts the plaintext for Clinic B's local final app using
   Clinic B's local key material.

9. Clinic B's final app receives a local encrypted delivery:

   ```json
   {
     "sender_host": "127.0.0.1:3001",
     "sender_kid": "<clinic-a-kid>",
     "timestamp": "...",
     "message": {
       "ctx": "...",
       "nonce": "...",
       "aad": "...",
       "variant": "ChaCha20Poly1305"
     }
   }
   ```

10. Clinic B's final app calls local Vectis:

    ```http
    POST /message/decrypt
    X-API-Key: <clinic-b client apikey>
    ```

11. Clinic B prints the recovered clinical record.

## Demo Components

- `clinical_app.py`: terminal final app used by each clinic.
- `personaldata.json`: sample patient record.
- `site-a/`: Clinic A runtime state.
- `site-b/`: Clinic B runtime state.
- `setup.sh`: builds the Vectis binary and creates demo directories.
- `create-keys.sh`: initializes both sites and creates one operational key per
  clinic, then creates a non-root app API key for each clinic app.
- `configure-routes.sh`: builds and signs the unified `config.json` (routes,
  remote routes, and permissions) for each site.
- `start-vectis-a.sh`, `start-vectis-b.sh`: start each Vectis instance.
- `start-app-a.sh`, `start-app-b.sh`: start each clinic final app.

## Network Layout

| Component | Address |
| --- | --- |
| Vectis A | `127.0.0.1:3001` |
| Clinic A final app | `127.0.0.1:4001` |
| Vectis B | `127.0.0.1:3002` |
| Clinic B final app | `127.0.0.1:4002` |

## Prepare The Demo

Run these commands from the repository root:

```sh
bash demo/setup.sh
bash demo/create-keys.sh
bash demo/configure-routes.sh
```

The scripts create local demo state under `demo/site-a` and `demo/site-b`,
including encrypted `init.json`, `.unseal_key`, SQLite storage, and a unified
signed `config.json` (with `routes`, `remote_routes`, and `permissions`
sections) so each clinic app can only use `message` operations for its own
local KID.

## Run The Demo

Open four terminals.

Terminal 1:

```sh
bash demo/start-vectis-a.sh
```

Terminal 2:

```sh
bash demo/start-vectis-b.sh
```

Terminal 3:

```sh
bash demo/start-app-a.sh
```

Terminal 4:

```sh
bash demo/start-app-b.sh
```

In the Clinic A app terminal, send the sample patient record:

```text
clinic-a file: ../personaldata.json
```

Clinic B should print:

- the encrypted delivery received from local Vectis;
- the `/message/decrypt` step;
- the recovered patient record JSON.

You can also send a clinical JSON file from Clinic B to Clinic A by entering a
file path in the Clinic B terminal.

Use `/quit` to stop a clinical app.

## Expected Result

Clinic B shows a decrypted clinical payload similar to:

```text
Clinical record received from 127.0.0.1:3001
Patient: Wile E. Coyote
Decrypted clinical payload:
{
  "records": {
    ...
  }
}
```

That output confirms the full flow: file input, sender-side protection,
cross-instance delivery, receiver-side verification, local re-encryption, and
final app decryption.

## Important Notes

- This demo uses local loopback addresses for clarity.
- The generated `.unseal_key`, `.env`, databases, and route signatures are demo
  state and are ignored by `demo/.gitignore`.
- The root API key stays in each site's `.env` for administrative scripts.
  Clinic apps use separate client API keys from `app.env`; those keys are
  authorized by the `permissions` section of each site's signed `config.json`.
- The sample clinical record is fictional and should be replaced with synthetic
  test data for real demonstrations.
