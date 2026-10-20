"""Ordered, synthetic happy paths; no test-suite imports or hidden provisioning."""

import hashlib

from happy_lab import configuration
from happy_transport import batch_result, expect_fields, require, three_items

VALUES = ("001-234-567", "002-345-678", "003-456-789")


def items_for(prefix):
    return three_items([{"ref": f"{prefix}-{i}", "plaintext": value}
                        for i, value in enumerate(VALUES, 1)])


def prepare(lab, client):
    for path, state in (("startup", "started"), ("live", "ok"), ("ready", "ready")):
        client.call("GET", f"/healthz/{path}", check=expect_fields(status=state))
    key = client.call("POST", "/keys", {"tag": "manual-happy", "profile": "hybrid-standard-v1"})
    kid = key.get("kid")
    require(isinstance(kid, str) and len(kid) == 64, "key creation must return KID")
    lab.write_config(configuration(kid, lab.api_hash))
    client.call("POST", "/config/reload")
    client.call("POST", "/keys/reload")
    for path in ("/keys", "/keys/properties", f"/keys/properties/{kid}", "/routes",
                 "/remote-routes", "/permissions", "/self-test/init"):
        client.call("GET", path)
    lab.stop()
    lab.env["VECTIS_APIKEY_HASH"] = ""
    lab.start()
    client.out.write("\n## Scoped client (same API key; no root/admin)")
    client.call("GET", f"/self-test/keys/{kid}")
    client.call("GET", f"/pub/{kid}")
    return kid


def symmetric(client, kid, subject=None):
    path = f"/symmetric/encrypt/{kid}" + (f"/subject/{subject}" if subject else "")
    text = "Synthetic local payload"
    envelope = client.call("POST", path, {"plaintext": text})
    expect_fields(kid=kid, **({"subject": subject} if subject else {}))(envelope)
    client.call("POST", "/symmetric/decrypt", envelope, check=expect_fields(plaintext=text))


def reversible(client, kid, family, subject=None):
    """Single and three-item batch for FPE or either tokenization family."""
    mode = "stored" if subject else "none"
    slug, route, produced = {
        "fpe": ("fpe", "/fpe", "ciphertext"),
        "token": ("token", "/token", "token"),
        "det": ("det", "/token/deterministic", "token"),
    }[family]
    profile = f"manual-{slug}-{mode}"
    encode, decode = ("encrypt", "decrypt") if family == "fpe" else ("encode", "decode")
    suffix = f"/subject/{subject}" if subject else ""
    identity = {"kid": kid, "profile": profile, **({"subject": subject} if subject else {})}
    single = {"ref": f"{family}-{mode}-single", "profile": profile, "plaintext": VALUES[0]}
    if family == "token":
        single["metadata"] = {"source": "manual"}
    output = client.call("POST", f"{route}/{encode}/{kid}{suffix}", single)
    expect_fields(**identity, ref=single["ref"])(output)
    require(isinstance(output.get(produced), str) and output[produced], "missing encrypted output")
    request = {**identity, "ref": single["ref"], produced: output[produced]}
    if family == "fpe":
        require(isinstance(output.get("tag"), str), "authenticated FPE must return tag")
        request["tag"] = output["tag"]
    expected = {"plaintext": VALUES[0], "ref": single["ref"]}
    if family == "token":
        expected["metadata"] = single["metadata"]
    client.call("POST", f"{route}/{decode}", request, check=expect_fields(**expected))

    inputs = items_for(f"{family}-{mode}-batch")
    if family == "token":
        for item in inputs:
            item["metadata"] = {"source": "manual", "ref": item["ref"]}
    encoded = client.call("POST", f"{route}/{encode}/batch/{kid}{suffix}",
                          {"profile": profile, "items": inputs})
    expect_fields(**identity)(encoded)
    outputs = batch_result(encoded, inputs, kid, profile)
    decode_items = [{"ref": item["ref"], produced: item[produced],
                     **({"tag": item["tag"]} if family == "fpe" else {})} for item in outputs]

    def check_batch(payload):
        for original, recovered in zip(inputs, batch_result(payload, inputs, kid, profile)):
            fields = {key: original[key] for key in ("plaintext", "metadata") if key in original}
            expect_fields(**fields)(recovered)

    client.call("POST", f"{route}/{decode}/batch", {**identity, "items": decode_items}, check=check_batch)
    if family == "token":
        return request
    return None


def mac_or_index(client, kid, family):
    profile = "manual-mac"
    identity = {"kid": kid, "profile": profile}
    request = {"ref": f"{family}-single", "profile": profile, "plaintext": VALUES[0]}
    created = client.call("POST", f"/{family}/{kid}", request)
    expect_fields(**identity, ref=request["ref"])(created)
    field = "digest" if family == "mac" else "index"
    digest = created.get(field)
    require(isinstance(digest, str) and digest, "missing digest")
    verify = {**request, "kid": kid}
    if family == "mac":
        verify["digest"] = digest
    client.call("POST", f"/{family}/verify", verify,
                check=expect_fields(**({"valid": True} if family == "mac" else {"matched": True, "index": digest})))
    inputs = items_for(f"{family}-batch")
    created = client.call("POST", f"/{family}/batch/{kid}", {"profile": profile, "items": inputs})
    outputs = batch_result(created, inputs, kid, profile)
    verify_items = [{**item, **({"digest": result["digest"]} if family == "mac" else {})}
                    for item, result in zip(inputs, outputs)]

    def check(payload):
        for item, original in zip(batch_result(payload, inputs, kid, profile), outputs):
            expect_fields(**({"valid": True} if family == "mac" else
                             {"matched": True, "index": original["index"]}))(item)

    client.call("POST", f"/{family}/verify/batch", {**identity, "items": verify_items}, check=check)


def masking(client, kid):
    profile = "manual-mask"
    masked = lambda text: "*" * (len(text) - 4) + text[-4:]
    client.call("POST", f"/mask/{kid}", {"ref": "mask-single", "profile": profile, "plaintext": VALUES[0]},
                check=expect_fields(kid=kid, profile=profile, ref="mask-single", masked=masked(VALUES[0])))
    inputs = items_for("mask-batch")

    def check(payload):
        for original, output in zip(inputs, batch_result(payload, inputs, kid, profile)):
            expect_fields(masked=masked(original["plaintext"]))(output)

    client.call("POST", f"/mask/batch/{kid}", {"profile": profile, "items": inputs}, check=check)


def commitments(client, kid):
    profile = "manual-commit"
    single = {"ref": "commit-single", "profile": profile, "plaintext": VALUES[0]}
    output = client.call("POST", f"/commit/{kid}", single)
    expect_fields(kid=kid, profile=profile, ref=single["ref"])(output)
    client.call("POST", "/commit/verify", {**single, "kid": kid, "opening": output["opening"],
                                            "commitment": output["commitment"]}, check=expect_fields(valid=True))
    inputs = items_for("commit-batch")
    output = client.call("POST", f"/commit/batch/{kid}", {"profile": profile, "items": inputs})
    outputs = batch_result(output, inputs, kid, profile)
    verify = [{**item, "opening": result["opening"], "commitment": result["commitment"]}
              for item, result in zip(inputs, outputs)]

    def check(payload):
        for item in batch_result(payload, inputs, kid, profile):
            expect_fields(valid=True)(item)

    client.call("POST", "/commit/verify/batch", {"kid": kid, "profile": profile, "items": verify}, check=check)


def sharing_and_signatures(client, kid):
    secret = "Synthetic shared secret"
    output = client.call("POST", f"/shares/split/{kid}", {"profile": "manual-share", "plaintext": secret},
                         check=expect_fields(kid=kid, profile="manual-share", threshold=3))
    shares = output.get("shares")
    require(isinstance(shares, list) and len(shares) == len(set(shares)) == 5, "expected five unique shares")
    client.call("POST", "/shares/combine", {"kid": kid, "profile": "manual-share",
                                            "shares": [shares[0], shares[2], shares[4]]},
                check=expect_fields(kid=kid, profile="manual-share", set_id=output["set_id"], plaintext=secret))
    signature = client.call("POST", f"/sign/{kid}",
                            {"message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(b"manual synthetic document").hexdigest()}})
    client.call("POST", "/sign/verification", signature,
                check=expect_fields(valid="ok", status={"eddsa": "ok", "ml-dsa": "ok"}))


def time_attestation(payload):
    expect_fields(version="vectis-time-attestation-v1", provider="cloudflare")(payload)
    sources = payload.get("sources")
    require(isinstance(sources, dict) and set(sources) == {"system", "nts", "roughtime"}, "invalid time sources")
    require(isinstance(sources["system"].get("unix_us"), str), "invalid system time")
    require(sources["nts"].get("authenticated") is True, "NTS source must be authenticated")
    for name in ("server", "offset_us", "round_trip_us"):
        require(isinstance(sources["nts"].get(name), str) and sources["nts"][name], "incomplete NTS source")
    require(sources["roughtime"].get("verified") is True, "Roughtime source must be verified")
    for name in ("midpoint_us", "radius_us", "earliest_us", "latest_us", "nonce_b64", "response_b64"):
        require(isinstance(sources["roughtime"].get(name), str) and sources["roughtime"][name], "incomplete Roughtime source")
    clock = payload.get("server_clock")
    require(isinstance(clock, dict) and isinstance(clock.get("acceptable"), bool), "invalid server clock")
    require(isinstance(clock.get("max_allowed_skew_ms"), int), "invalid clock skew limit")
    require(isinstance(clock.get("local_vs_nts_skew_ms"), (int, float)), "invalid observed clock skew")
    require(all(isinstance(clock.get(name), bool) for name in
                ("local_within_roughtime_interval", "nts_within_roughtime_interval")), "invalid clock intervals")


def run(client, kid):
    subject_output = client.call("POST", f"/subject/{kid}",
                                 {"profile": "manual-token-stored", "subject_name": "synthetic-person"}, status=201,
                                 check=expect_fields(kid=kid, profile="manual-token-stored"))
    subject = subject_output.get("subject")
    require(isinstance(subject, str) and len(subject) == 64, "subject creation must return ID")
    deletions = []
    for scope in (None, subject):
        symmetric(client, kid, scope)
        for family in ("fpe", "token", "det"):
            token = reversible(client, kid, family, scope)
            if token:
                deletions.append(token)
    for family in ("mac", "index"):
        mac_or_index(client, kid, family)
    masking(client, kid)
    commitments(client, kid)
    sharing_and_signatures(client, kid)
    client.out.write("\n## Live time attestation (external sources required)")
    client.call("POST", "/time/attest", check=time_attestation)
    client.out.write("\n## Destructive operations (after all recoveries)")
    for token in deletions:
        client.call("POST", "/token/delete", token, check=expect_fields(ref=token["ref"], deleted=True))
    client.call("DELETE", f"/subject/{kid}/{subject}", status=204,
                check=lambda value: require(value is None, "subject delete must have an empty response"))
    client.call("POST", f"/lifecycle/{kid}", {"status": "retired", "reason": "manual happy path complete"},
                check=lambda payload: (expect_fields(kid=kid)(payload),
                                       expect_fields(status="retired")(payload.get("lifecycle"))))
