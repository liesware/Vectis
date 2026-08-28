import json

from oracle import _parse


KID_HEX = "a" * 64
RECIPIENT_HEX = "b" * 64
INTERNAL_SEED_PLAINTEXT = "fuzz seed plaintext"
FPE_PROFILE = "fuzz-patient-id-decimal-v1"
FPE_PLAINTEXT = "1234567890"
FPE_BATCH_PLAINTEXTS = [FPE_PLAINTEXT, "9876543210"]
TOKENIZATION_PROFILE = "fuzz-patient-id-token-v1"
ONE_TIME_TOKENIZATION_PROFILE = "fuzz-one-time-token-v1"
TOKEN_PLAINTEXT = "fuzz token plaintext"
TOKEN_BATCH_PLAINTEXTS = [TOKEN_PLAINTEXT, "second fuzz token plaintext"]
MAC_PROFILE = "fuzz-pan-blind-index-v1"
MAC_PLAINTEXTS = ["4111111111111111", "5555555555554444"]
MASKING_PROFILE = "fuzz-pan-display-v1"
MASKING_PLAINTEXTS = ["4111111111111111", "5555555555554444"]
COMMITMENT_PROFILE = "fuzz-pan-commitment-v1"
COMMITMENT_PLAINTEXTS = ["4111111111111111", "5555555555554444"]
SHARING_PROFILE = "fuzz-customer-secret-3of5-v1"
SHARING_PLAINTEXT = "fuzz secret sharing plaintext"

LIFECYCLE_ERRORS = {
    "retired": "key is retired and can only be used for decrypt or verification",
    "disabled": "key is currently disabled",
    "compromised": "key is compromised and cannot be used for security reasons",
    "destroyed": "key is logically destroyed and cannot be used",
}


def token_semantic(sent_value, seed, status, body):
    if sent_value is None or sent_value == seed:
        return []
    if status != 200:
        return []
    parsed = _parse(body)
    if isinstance(parsed, dict) and parsed.get("valid") == "ok":
        return ["SEMANTIC: verification bypass (mutated token still valid=ok)"]
    return []


CRYPTO_MESSAGE_FIELDS = ("ctx", "nonce", "aad", "variant")


def internal_semantic(sent_value, seed, status, body):
    findings = []
    if status == 200:
        parsed = _parse(body)
        returned = parsed.get("plaintext") if isinstance(parsed, dict) else None
        if returned != INTERNAL_SEED_PLAINTEXT:
            findings.append(
                "SEMANTIC: decrypt returned unexpected plaintext for a 200 response"
            )
        if isinstance(sent_value, dict) and _crypto_fields_differ(sent_value, seed):
            findings.append(
                "SEMANTIC: AEAD bypass (mutated cipher field accepted with 200)"
            )
    return findings


def internal_encrypt_semantic(sent_value, seed, status, body):
    findings = []
    if status != 200:
        return findings
    parsed = _parse(body)
    message = parsed.get("message") if isinstance(parsed, dict) else None
    if not isinstance(message, dict):
        findings.append("SEMANTIC: internal encrypt 200 body is missing message")
        return findings
    if (
        isinstance(sent_value, dict)
        and sent_value == seed
        and message.get("ctx") == seed.get("plaintext")
    ):
        findings.append("SEMANTIC: internal encrypt returned plaintext as ciphertext")
    return findings


def _crypto_fields_differ(sent_value, seed):
    sent_msg = sent_value.get("message")
    seed_msg = seed.get("message")
    if not isinstance(sent_msg, dict) or not isinstance(seed_msg, dict):
        return True
    return any(sent_msg.get(field) != seed_msg.get(field) for field in CRYPTO_MESSAGE_FIELDS)


def _fields_differ(sent_value, seed, fields):
    if not isinstance(sent_value, dict) or not isinstance(seed, dict):
        return sent_value != seed
    return any(sent_value.get(field) != seed.get(field) for field in fields)


def _batch_item_fields_differ(sent_value, seed, fields):
    if not isinstance(sent_value, dict) or not isinstance(seed, dict):
        return sent_value != seed
    if _fields_differ(sent_value, seed, ("kid", "profile")):
        return True
    sent_items = sent_value.get("items")
    seed_items = seed.get("items")
    if not isinstance(sent_items, list) or not isinstance(seed_items, list):
        return sent_items != seed_items
    if len(sent_items) != len(seed_items):
        return True
    for sent_item, seed_item in zip(sent_items, seed_items):
        if not isinstance(sent_item, dict) or not isinstance(seed_item, dict):
            return sent_item != seed_item
        if any(sent_item.get(field) != seed_item.get(field) for field in fields):
            return True
    return False


CONFIG_LOADED_COUNTS = (
    "routes_loaded",
    "remote_routes_loaded",
    "clients_loaded",
    "fpe_profiles_loaded",
    "tokenization_profiles_loaded",
    "mac_profiles_loaded",
    "masking_profiles_loaded",
    "commitment_profiles_loaded",
    "sharing_profiles_loaded",
)


def config_semantic(status, body):
    # The baseline signed config is empty, so a legitimate 200 reload must load
    # zero content. Comparing raw bytes would false-positive on canonically
    # equivalent inputs (serde defaults, key order); comparing the observable
    # loaded counts catches a real integrity break: altered content accepted
    # under the baseline signature.
    if status != 200:
        return []
    parsed = _parse(body)
    if not isinstance(parsed, dict) or parsed.get("status") != "reloaded":
        return []
    if any(parsed.get(count) for count in CONFIG_LOADED_COUNTS):
        return ["SEMANTIC: config integrity bypass (altered content loaded under baseline signature)"]
    return []


def fpe_semantic(sent_value, seed, status, body):
    findings = []
    if status != 200:
        return findings
    parsed = _parse(body)
    if not isinstance(parsed, dict):
        return ["SEMANTIC: fpe 200 body is not JSON object"]

    if "plaintext" in seed:
        ciphertext = parsed.get("ciphertext")
        if ciphertext is None:
            findings.append("SEMANTIC: fpe encrypt 200 body is missing ciphertext")
        if (
            isinstance(sent_value, dict)
            and sent_value == seed
            and ciphertext == seed["plaintext"]
        ):
            findings.append("SEMANTIC: fpe encrypt returned plaintext as ciphertext")
        return findings

    if "ciphertext" in seed:
        plaintext = parsed.get("plaintext")
        if plaintext is None:
            findings.append("SEMANTIC: fpe decrypt 200 body is missing plaintext")
        if sent_value == seed and plaintext != FPE_PLAINTEXT:
            findings.append("SEMANTIC: fpe decrypt returned unexpected plaintext")
        if (
            _fields_differ(sent_value, seed, ("kid", "profile", "ciphertext"))
            and plaintext == FPE_PLAINTEXT
        ):
            findings.append(
                "SEMANTIC: fpe decrypt accepted mutated input as original plaintext"
            )
    return findings


def fpe_batch_semantic(sent_value, seed, status, body):
    findings = []
    if status != 200:
        return findings
    parsed = _parse(body)
    if not isinstance(parsed, dict):
        return ["SEMANTIC: fpe batch 200 body is not JSON object"]
    items = parsed.get("items")
    if not isinstance(items, list):
        return ["SEMANTIC: fpe batch 200 body is missing items list"]
    seed_items = seed.get("items") if isinstance(seed, dict) else None
    if not isinstance(seed_items, list) or not seed_items:
        return findings

    if "plaintext" in seed_items[0]:
        if sent_value == seed:
            if len(items) != len(seed_items):
                findings.append("SEMANTIC: fpe batch encrypt item count mismatch")
            for out_item, in_item in zip(items, seed_items):
                if isinstance(out_item, dict) and out_item.get("ciphertext") == in_item.get("plaintext"):
                    findings.append("SEMANTIC: fpe batch encrypt returned plaintext as ciphertext")
                    break
        return findings

    if "ciphertext" in seed_items[0]:
        returned = [it.get("plaintext") for it in items if isinstance(it, dict)]
        if sent_value == seed and returned != FPE_BATCH_PLAINTEXTS:
            findings.append("SEMANTIC: fpe batch decrypt returned unexpected plaintext")
        if (
            _batch_item_fields_differ(sent_value, seed, ("ciphertext",))
            and returned == FPE_BATCH_PLAINTEXTS
        ):
            findings.append(
                "SEMANTIC: fpe batch decrypt accepted mutated input as original plaintext"
            )
    return findings


def tokenization_semantic(sent_value, seed, status, body):
    findings = []
    if status != 200:
        return findings
    parsed = _parse(body)
    if not isinstance(parsed, dict):
        return ["SEMANTIC: token 200 body is not JSON object"]

    if "plaintext" in seed:
        token = parsed.get("token")
        if token is None:
            findings.append("SEMANTIC: token encode 200 body is missing token")
        elif isinstance(token, str) and TOKEN_PLAINTEXT in token:
            findings.append("SEMANTIC: token encode leaked plaintext in token")
        return findings

    if "token" in seed:
        returned = parsed.get("plaintext")
        if sent_value == seed and returned != TOKEN_PLAINTEXT:
            findings.append("SEMANTIC: token decode returned unexpected plaintext")
        if (
            _fields_differ(sent_value, seed, ("kid", "profile", "token"))
            and returned == TOKEN_PLAINTEXT
        ):
            findings.append(
                "SEMANTIC: token decode accepted mutated token as original plaintext"
            )
    return findings


def tokenization_batch_semantic(sent_value, seed, status, body):
    findings = []
    if status != 200:
        return findings
    parsed = _parse(body)
    if not isinstance(parsed, dict):
        return ["SEMANTIC: token batch 200 body is not JSON object"]
    items = parsed.get("items")
    if not isinstance(items, list):
        return ["SEMANTIC: token batch 200 body is missing items list"]
    seed_items = seed.get("items") if isinstance(seed, dict) else None
    if not isinstance(seed_items, list) or not seed_items:
        return findings

    if "plaintext" in seed_items[0]:
        if sent_value == seed:
            if len(items) != len(seed_items):
                findings.append("SEMANTIC: token batch encode item count mismatch")
            for out_item, in_item in zip(items, seed_items):
                token = out_item.get("token") if isinstance(out_item, dict) else None
                plaintext = in_item.get("plaintext") if isinstance(in_item, dict) else None
                if token is None:
                    findings.append("SEMANTIC: token batch encode item is missing token")
                    break
                if isinstance(token, str) and isinstance(plaintext, str) and plaintext in token:
                    findings.append("SEMANTIC: token batch encode leaked plaintext in token")
                    break
        return findings

    if "token" in seed_items[0]:
        returned = [it.get("plaintext") for it in items if isinstance(it, dict)]
        if sent_value == seed and returned != TOKEN_BATCH_PLAINTEXTS:
            findings.append("SEMANTIC: token batch decode returned unexpected plaintext")
        if (
            _batch_item_fields_differ(sent_value, seed, ("token",))
            and returned == TOKEN_BATCH_PLAINTEXTS
        ):
            findings.append(
                "SEMANTIC: token batch decode accepted mutated token as original plaintext"
            )
    return findings


def _response_items(response):
    """Return the `items` list from an (status, body) response tuple, or []."""
    parsed = _parse(response[1])
    items = parsed.get("items") if isinstance(parsed, dict) else None
    return items if isinstance(items, list) else []


def reject_malformed_body_semantic(sent_value, _seed_obj, status, _response):
    """Floor oracle for body endpoints that carry no richer semantic.

    Every Vectis write endpoint expects a JSON object body. `sent_value` is the
    body that actually reached the server (the parsed structured mutation, or the
    raw-mutated bytes parsed back — None when they were not valid JSON). If that
    body is not a JSON object, the request is malformed and the server must answer
    4xx; a 200 means it accepted non-JSON, a bare scalar/array, or null — a lenient
    parser or a body-ignoring handler. This claims only what is always true, so it
    never fires on a benign mutation that left a still-valid object.
    """
    if status == 200 and not isinstance(sent_value, dict):
        return ["SEMANTIC: endpoint accepted a non-object body with 200"]
    return []


def batch_output_contract(status, body, kid, profile, refs, required_fields):
    """Validate the shape and input order shared by successful batch responses."""
    if status != 200:
        return ["SEMANTIC: batch control did not return 200"]
    parsed = _parse(body)
    if not isinstance(parsed, dict):
        return ["SEMANTIC: batch control response is not a JSON object"]

    findings = []
    if parsed.get("kid") != kid:
        findings.append("SEMANTIC: batch control returned an unexpected kid")
    if parsed.get("profile") != profile:
        findings.append("SEMANTIC: batch control returned an unexpected profile")
    items = parsed.get("items")
    if not isinstance(items, list) or len(items) != len(refs):
        return [*findings, "SEMANTIC: batch control item count mismatch"]
    if [item.get("ref") if isinstance(item, dict) else None for item in items] != refs:
        findings.append("SEMANTIC: batch control did not preserve item order")
    # Enforce the exact key set, not a subset: an item that echoes an extra field
    # (e.g. a leaked "plaintext" on an encrypt result) or an unexpected internal
    # field must be caught, which a "required fields are present" check misses.
    allowed_keys = {"ref", *required_fields}
    if any(
        not isinstance(item, dict) or set(item.keys()) != allowed_keys
        for item in items
    ):
        findings.append("SEMANTIC: batch control item shape mismatch")
    return findings


def batch_duplicate_ref_rejection(status, body):
    """A duplicate ref must be an indexed 400 without partial batch output."""
    if status != 400:
        return ["SEMANTIC: duplicate batch ref was not rejected with 400"]
    parsed = _parse(body)
    if not isinstance(parsed, dict):
        return ["SEMANTIC: duplicate batch ref response is not a JSON object"]
    findings = []
    error = parsed.get("error")
    if not isinstance(error, str) or not error.startswith("batch item 1 failed:"):
        findings.append("SEMANTIC: duplicate batch ref error is not indexed")
    if "items" in parsed:
        findings.append("SEMANTIC: duplicate batch ref returned partial items")
    return findings


def fpe_batch_contract_semantic(case, context):
    refs = case["refs"]
    encrypt, decrypt, duplicate_encrypt, duplicate_decrypt = case["responses"]
    findings = []
    findings.extend(batch_output_contract(*encrypt, context["kid"], context["profile"], refs, ("ciphertext",)))
    findings.extend(batch_output_contract(*decrypt, context["kid"], context["profile"], refs, ("plaintext",)))
    decrypt_items = _response_items(decrypt)
    if [item.get("plaintext") if isinstance(item, dict) else None for item in decrypt_items] != case["plaintexts"]:
        findings.append("SEMANTIC: fpe batch decrypt returned unexpected plaintexts")
    findings.extend(batch_duplicate_ref_rejection(*duplicate_encrypt))
    findings.extend(batch_duplicate_ref_rejection(*duplicate_decrypt))
    return findings


def token_batch_contract_semantic(case, context):
    refs = case["refs"]
    encoded, decoded, duplicate_encode, duplicate_decode = case["responses"]
    findings = []
    findings.extend(batch_output_contract(*encoded, context["kid"], context["profile"], refs, ("token",)))
    findings.extend(batch_output_contract(*decoded, context["kid"], context["profile"], refs, ("plaintext", "metadata")))
    decoded_items = _response_items(decoded)
    if [item.get("plaintext") if isinstance(item, dict) else None for item in decoded_items] != case["plaintexts"]:
        findings.append("SEMANTIC: token batch decode returned unexpected plaintexts")
    if [item.get("metadata") if isinstance(item, dict) else None for item in decoded_items] != case["metadata"]:
        findings.append("SEMANTIC: token batch decode returned unexpected metadata")
    findings.extend(batch_duplicate_ref_rejection(*duplicate_encode))
    findings.extend(batch_duplicate_ref_rejection(*duplicate_decode))
    return findings


def mac_batch_contract_semantic(case, context):
    refs = case["refs"]
    created, verified, duplicate_create, duplicate_verify = case["responses"]
    findings = []
    findings.extend(batch_output_contract(*created, context["kid"], context["profile"], refs, ("digest",)))
    findings.extend(batch_output_contract(*verified, context["kid"], context["profile"], refs, ("valid",)))
    verified_items = _response_items(verified)
    if [item.get("valid") if isinstance(item, dict) else None for item in verified_items] != [True, True]:
        findings.append("SEMANTIC: valid mac batch did not verify every item")
    findings.extend(batch_duplicate_ref_rejection(*duplicate_create))
    findings.extend(batch_duplicate_ref_rejection(*duplicate_verify))
    return findings


def index_batch_transaction_semantic(case, context):
    refs = case["refs"]
    duplicate_create, missing, created, verified, duplicate_verify = case["responses"]
    findings = []
    findings.extend(batch_duplicate_ref_rejection(*duplicate_create))
    missing_status, missing_body = missing
    missing_output = _parse(missing_body)
    if (
        missing_status != 200
        or not isinstance(missing_output, dict)
        or missing_output.get("matched") is not False
    ):
        findings.append("SEMANTIC: invalid index batch persisted a partial index")
    findings.extend(batch_output_contract(*created, context["kid"], context["profile"], refs, ("index",)))
    findings.extend(batch_output_contract(*verified, context["kid"], context["profile"], refs, ("matched", "index")))
    verified_items = _response_items(verified)
    if [item.get("matched") if isinstance(item, dict) else None for item in verified_items] != [True, True]:
        findings.append("SEMANTIC: valid index batch did not persist every index")
    findings.extend(batch_duplicate_ref_rejection(*duplicate_verify))
    return findings


def masking_batch_contract_semantic(case, context):
    refs = case["refs"]
    masked, duplicate = case["responses"]
    findings = batch_output_contract(*masked, context["kid"], context["profile"], refs, ("masked",))
    masked_items = _response_items(masked)
    if [item.get("masked") if isinstance(item, dict) else None for item in masked_items] != case["masked"]:
        findings.append("SEMANTIC: masking batch returned unexpected policy output")
    findings.extend(batch_duplicate_ref_rejection(*duplicate))
    return findings


def commitment_batch_contract_semantic(case, context):
    refs = case["refs"]
    created, verified, duplicate_create, duplicate_verify = case["responses"]
    findings = []
    findings.extend(batch_output_contract(*created, context["kid"], context["profile"], refs, ("commitment", "opening")))
    findings.extend(batch_output_contract(*verified, context["kid"], context["profile"], refs, ("valid",)))
    verified_items = _response_items(verified)
    if [item.get("valid") if isinstance(item, dict) else None for item in verified_items] != [True, True]:
        findings.append("SEMANTIC: valid commitment batch did not verify every item")
    findings.extend(batch_duplicate_ref_rejection(*duplicate_create))
    findings.extend(batch_duplicate_ref_rejection(*duplicate_verify))
    return findings


def _encoded_token_present(encoded_status, encoded_body):
    """A well-formed encode is HTTP 200 with a non-empty token in the body.

    A malformed 200 (parse failure, or a body missing the token) is itself an
    anomaly: the encode step succeeded on the wire but produced nothing usable.
    Flagging it here keeps the real defect at the encode step instead of letting
    it surface later as a misleading "did not decode exactly once".
    """
    if encoded_status != 200:
        return False
    encoded = _parse(encoded_body)
    return isinstance(encoded, dict) and isinstance(encoded.get("token"), str) and bool(encoded["token"])


def _encoded_tokens_present(encoded_status, encoded_body, count):
    """A well-formed batch encode is HTTP 200 with `count` non-empty tokens."""
    if encoded_status != 200:
        return False
    encoded = _parse(encoded_body)
    if not isinstance(encoded, dict):
        return False
    items = encoded.get("items")
    if not isinstance(items, list) or len(items) != count:
        return False
    return all(isinstance(item, dict) and isinstance(item.get("token"), str) and item["token"] for item in items)


def one_time_single_semantic(results, plaintext):
    encoded_status, encoded_body = results[0]
    decoded_status, decoded_body = results[1]
    replay_status, replay_body = results[2]
    decoded = _parse(decoded_body)
    replay = _parse(replay_body)
    findings = []
    if not _encoded_token_present(encoded_status, encoded_body):
        findings.append("SEMANTIC: one-time token encode returned no usable token")
    if (
        encoded_status != 200
        or decoded_status != 200
        or not isinstance(decoded, dict)
        or decoded.get("plaintext") != plaintext
    ):
        findings.append("SEMANTIC: one-time token did not decode exactly once")
    if replay_status != 404 or not isinstance(replay, dict) or replay.get("error") != "token not found":
        findings.append("SEMANTIC: consumed one-time token replay was not rejected")
    if plaintext in replay_body:
        findings.append("SEMANTIC: one-time token replay leaked plaintext")
    return findings


def one_time_batch_semantic(results, plaintext, leaked_plaintexts=None):
    """`plaintext` is the survivor's expected value; `leaked_plaintexts`
    enumerates every plaintext that could leak in the failure body (both the
    survivor's and the already-consumed item's). Defaults to `[plaintext]`."""
    leaked_plaintexts = leaked_plaintexts if leaked_plaintexts is not None else [plaintext]
    encoded_status, encoded_body = results[0]
    consumed_status, _consumed_body = results[1]
    batch_status, batch_body = results[2]
    survivor_status, survivor_body = results[3]
    batch = _parse(batch_body)
    survivor = _parse(survivor_body)
    findings = []
    if not _encoded_tokens_present(encoded_status, encoded_body, 2):
        findings.append("SEMANTIC: one-time batch encode returned no usable tokens")
    # Atomicity: the batch must fail as a whole (404, token-not-found, no partial
    # output). Match the failure reason by substring rather than the exact string
    # so a wording or item-index change (0- vs 1-based) does not fake a finding.
    if (
        encoded_status != 200
        or consumed_status != 200
        or batch_status != 404
        or not isinstance(batch, dict)
        or "token not found" not in str(batch.get("error", ""))
        or "items" in batch
    ):
        findings.append("SEMANTIC: failed one-time batch was not atomic")
    if (
        survivor_status != 200
        or not isinstance(survivor, dict)
        or survivor.get("plaintext") != plaintext
    ):
        findings.append("SEMANTIC: failed one-time batch consumed an available token")
    if any(leaked in batch_body for leaked in leaked_plaintexts):
        findings.append("SEMANTIC: failed one-time batch leaked plaintext")
    return findings


def one_time_race_semantic(results, plaintext):
    encoded_status, _encoded_body = results[0]
    decoded = [(status, _parse(body), body) for status, body in results[1:]]
    winners = [body for status, body, _raw in decoded if status == 200 and isinstance(body, dict) and body.get("plaintext") == plaintext]
    losers = [body for status, body, _raw in decoded if status == 404 and isinstance(body, dict) and body.get("error") == "token not found"]
    findings = []
    if encoded_status != 200 or len(winners) != 1 or len(losers) != 1:
        findings.append("SEMANTIC: one-time token race did not produce exactly one winner")
    if any(plaintext in raw for status, _body, raw in decoded if status != 200):
        findings.append("SEMANTIC: one-time token race loser leaked plaintext")
    return findings


def token_batch_duplicate_policy_semantic(results, plaintext):
    one_time_encode_status, _one_time_encode_body = results[0]
    one_time_status, one_time_body = results[1]
    reusable_encode_status, _reusable_encode_body = results[2]
    reusable_status, reusable_body = results[3]
    one_time = _parse(one_time_body)
    reusable = _parse(reusable_body)
    findings = []
    if (
        one_time_encode_status != 200
        or one_time_status != 400
        or not isinstance(one_time, dict)
        or one_time.get("error") != "batch item 1 failed: token batch contains duplicated token"
        or "items" in one_time
    ):
        findings.append("SEMANTIC: one-time duplicate token batch was not rejected")
    reusable_items = reusable.get("items") if isinstance(reusable, dict) else None
    if (
        reusable_encode_status != 200
        or reusable_status != 200
        or not isinstance(reusable_items, list)
        or [item.get("ref") for item in reusable_items if isinstance(item, dict)] != ["reusable-duplicate-0", "reusable-duplicate-1"]
        or [item.get("plaintext") for item in reusable_items if isinstance(item, dict)] != [plaintext, plaintext]
    ):
        findings.append("SEMANTIC: reusable duplicate token batch was not accepted")
    return findings


def lifecycle_contract_semantic(records):
    """Validate the lifecycle matrix without retaining sensitive request data."""
    findings = []
    sensitive_fields = {"plaintext", "token", "ciphertext", "digest", "opening", "shares", "signature"}
    for record in records:
        status = record["status"]
        body = record["body"]
        operation = record["operation"]
        state = record["state"]
        expected = record["expected"]
        parsed = _parse(body)
        if expected == "rejected":
            if status != 403:
                findings.append(
                    f"SEMANTIC: {state} allowed lifecycle-blocked {operation}"
                )
                continue
            if not isinstance(parsed, dict) or parsed.get("error") != LIFECYCLE_ERRORS[state]:
                findings.append(
                    f"SEMANTIC: {state} returned an unexpected lifecycle rejection for {operation}"
                )
            elif sensitive_fields.intersection(parsed):
                findings.append(
                    f"SEMANTIC: {state} lifecycle rejection exposed operation output for {operation}"
                )
            continue

        if status != 200 or not isinstance(parsed, dict):
            findings.append(f"SEMANTIC: {state} did not allow {operation}")
            continue
        if operation == "fpe_decrypt" and parsed.get("plaintext") != FPE_PLAINTEXT:
            findings.append("SEMANTIC: retired fpe decrypt returned unexpected plaintext")
        elif operation == "token_decode" and parsed.get("plaintext") != TOKEN_PLAINTEXT:
            findings.append("SEMANTIC: retired token decode returned unexpected plaintext")
        elif operation in {"mac_verify", "commitment_verify"} and parsed.get("valid") is not True:
            findings.append(f"SEMANTIC: retired {operation} did not verify")
        elif operation == "index_verify" and parsed.get("matched") is not True:
            findings.append("SEMANTIC: retired index verify did not match")
        elif operation == "share_combine" and parsed.get("plaintext") != SHARING_PLAINTEXT:
            findings.append("SEMANTIC: retired share combine returned unexpected plaintext")
        elif operation == "sign_verify" and parsed.get("valid") != "ok":
            findings.append("SEMANTIC: retired sign verification did not succeed")
        elif operation == "internal_decrypt" and parsed.get("plaintext") != INTERNAL_SEED_PLAINTEXT:
            findings.append("SEMANTIC: retired internal decrypt returned unexpected plaintext")
        elif operation == "mask" and not isinstance(parsed.get("masked"), str):
            findings.append("SEMANTIC: retired masking did not return masked output")
    return findings


def _valid_false(status, body):
    parsed = _parse(body)
    return status == 200 and isinstance(parsed, dict) and parsed.get("valid") is False


def mac_determinism_semantic(case, context):
    first, second, verified, changed_plaintext, changed_digest = case["responses"]
    first_value, second_value = _parse(first[1]), _parse(second[1])
    findings = []
    if (
        first[0] != 200 or second[0] != 200
        or not isinstance(first_value, dict) or not isinstance(second_value, dict)
        or not isinstance(first_value.get("digest"), str) or not first_value["digest"]
        or first_value.get("digest") != second_value.get("digest")
    ):
        findings.append("SEMANTIC: MAC is not deterministic for identical plaintext")
    if not _valid_false(*changed_plaintext):
        findings.append("SEMANTIC: MAC verify accepted changed plaintext")
    if not _valid_false(*changed_digest):
        findings.append("SEMANTIC: MAC verify accepted changed digest")
    if not (verified[0] == 200 and isinstance(_parse(verified[1]), dict) and _parse(verified[1]).get("valid") is True):
        findings.append("SEMANTIC: MAC verify rejected matching digest")
    return findings


def index_determinism_semantic(case, context):
    first, second, matched, changed = case["responses"]
    first_value, second_value = _parse(first[1]), _parse(second[1])
    findings = []
    if (
        first[0] != 200 or second[0] != 200
        or not isinstance(first_value, dict) or not isinstance(second_value, dict)
        or not isinstance(first_value.get("index"), str) or not first_value["index"]
        or first_value.get("index") != second_value.get("index")
    ):
        findings.append("SEMANTIC: blind index is not deterministic for identical plaintext")
    for status, body, expected, label in (
        (*matched, True, "matching plaintext"),
        (*changed, False, "changed plaintext"),
    ):
        parsed = _parse(body)
        if status != 200 or not isinstance(parsed, dict) or parsed.get("matched") is not expected:
            findings.append(f"SEMANTIC: blind index verify returned wrong result for {label}")
    return findings


def masking_policy_semantic(case, context):
    response = case["response"]
    status, body, headers = response.status, response.body, response.headers or {}
    parsed = _parse(body)
    plaintext = case["plaintext"]
    expected = case["expected"]
    findings = []
    if status != 200 or not isinstance(parsed, dict) or parsed.get("masked") != expected:
        findings.append("SEMANTIC: masking output does not match the signed policy")
    if plaintext in body or any(plaintext in str(value) for value in headers.values()):
        findings.append("SEMANTIC: masking response leaked plaintext")
    return findings


def commitment_randomness_semantic(case, context):
    first, second, verified, changed_opening, changed_commitment = case["responses"]
    first_value, second_value = _parse(first[1]), _parse(second[1])
    findings = []
    if (
        first[0] != 200 or second[0] != 200
        or not isinstance(first_value, dict) or not isinstance(second_value, dict)
        or not isinstance(first_value.get("opening"), str) or not first_value["opening"]
        or not isinstance(first_value.get("commitment"), str) or not first_value["commitment"]
        or first_value.get("opening") == second_value.get("opening")
        or first_value.get("commitment") == second_value.get("commitment")
    ):
        findings.append("SEMANTIC: commitment creation did not use a fresh opening")
    if not (verified[0] == 200 and isinstance(_parse(verified[1]), dict) and _parse(verified[1]).get("valid") is True):
        findings.append("SEMANTIC: commitment verify rejected matching material")
    if not _valid_false(*changed_opening):
        findings.append("SEMANTIC: commitment verify accepted changed opening")
    if not _valid_false(*changed_commitment):
        findings.append("SEMANTIC: commitment verify accepted changed commitment")
    return findings


def sharing_integrity_semantic(case, context):
    control, threshold, duplicate, tampered, mixed = case["checks"]
    plaintext = case["plaintext"]
    findings = []
    control_value = _parse(control[1])
    if control[0] != 200 or not isinstance(control_value, dict) or control_value.get("plaintext") != plaintext:
        findings.append("SEMANTIC: threshold shares did not reconstruct the original secret")
    for label, (status, body) in (
        ("below threshold", threshold),
        ("duplicate share index", duplicate),
        ("tampered share tag", tampered),
        ("mixed share sets", mixed),
    ):
        parsed = _parse(body)
        if status != 400 or not isinstance(parsed, dict) or not isinstance(parsed.get("error"), str):
            findings.append(f"SEMANTIC: sharing {label} was not rejected")
        if plaintext in body:
            findings.append(f"SEMANTIC: sharing {label} leaked plaintext")
    return findings


def compact_signature_integrity_semantic(case, _context):
    """Validate hybrid verification order without retaining signature material."""
    expected = {
        "control": ("ok", "ok", "ok"),
        "header": ("fail", "not_checked", "fail"),
        "payload": ("fail", "not_checked", "fail"),
        "eddsa": ("ok", "fail", "fail"),
        "ml_dsa": ("fail", "not_checked", "fail"),
    }
    findings = []
    for label, signed_status, signed_body, verify_status, verify_body, signature in case["checks"]:
        parsed = _parse(verify_body)
        ml_dsa, eddsa, valid = expected[label]
        if signed_status != 200:
            findings.append(f"SEMANTIC: compact signature producer failed for {label}")
            continue
        status = parsed.get("status") if isinstance(parsed, dict) else None
        if (
            verify_status != 200
            or not isinstance(status, dict)
            or parsed.get("valid") != valid
            or status.get("ml-dsa") != ml_dsa
            or status.get("eddsa") != eddsa
        ):
            findings.append(f"SEMANTIC: compact signature verification state mismatch for {label}")
        # `signature` is None when the producer returned no signature or the
        # mutation could not be built; only scan for it when it is a real string
        # (`None in verify_body` would raise and abort the whole target).
        signature_leaked = isinstance(signature, str) and bool(signature) and signature in verify_body
        if signature_leaked or case["message_hash_hex"] in verify_body:
            findings.append(f"SEMANTIC: compact signature failure reflected sensitive input for {label}")
    return findings


def time_attest_source_unavailable_semantic(case):
    status, body = case["response"]
    parsed = _parse(body)
    findings = []
    if (
        status != 502
        or not isinstance(parsed, dict)
        or parsed != {"error": "time attestation source unavailable"}
    ):
        findings.append("SEMANTIC: unavailable time source did not return the fail-closed 502 contract")
    if case["ready_before"] != 200 or case["ready_after"] != 200:
        findings.append("SEMANTIC: time attestation source failure changed readiness")
    return findings
