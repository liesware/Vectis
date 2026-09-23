"""Positive HTTP helpers for one capability domain."""

import base64
import hashlib
import json

from lib.assertions import require, require_hex
from lib.fixtures import FinalAppHandler
from lib.positive_support import MESSAGE, reload_config, write_test_remote_routes
from lib.casekit import CaseSet
from lib.results import CaseResult

from .positive_output import print_section, print_message, print_internal_message
from .positive_keys import validate_test_response, validate_pub_response, validate_message_response

cases = CaseSet()

def validate_final_app_delivery(delivery, sender_key_id, case):
    require(isinstance(delivery, dict), "final app delivery must be an object")
    require(delivery.get("sender_host"), "final app sender_host must be present")
    require(delivery.get("sender_kid") == sender_key_id, "final app sender_kid mismatch")
    require(isinstance(delivery.get("timestamp"), str) and delivery.get("timestamp"), "final app timestamp must be a non-empty string")

    message = delivery.get("message")
    require(isinstance(message, dict), "final app message must be an object")
    require_hex(message.get("ctx"), "final app message.ctx")
    require_hex(message.get("nonce"), "final app message.nonce")
    require(isinstance(message.get("aad"), str) and message.get("aad"), "final app message.aad must be a non-empty string")
    require(message.get("variant") == case["symmetric_algorithm"], "final app message.variant mismatch")


def decrypt_message(client, delivery, expected_plaintext):
    response = client.post("/message/decrypt", delivery, auth=True)
    require(response.get("plaintext") == expected_plaintext, "message decrypt plaintext mismatch")
    return response["plaintext"]


def validate_internal_message_output(response, key_id, case):
    require(response.get("timestamp"), "internal message response must include timestamp")
    require(response.get("kid") == key_id, "internal message kid mismatch")
    message = response.get("message")
    require(isinstance(message, dict), "internal message.message must be an object")
    require_hex(message.get("ctx"), "internal message.ctx")
    require_hex(message.get("nonce"), "internal message.nonce")
    require(isinstance(message.get("aad"), str) and message.get("aad"), "internal message.aad must be a non-empty string")
    require(message.get("variant") == case["symmetric_algorithm"], "internal message.variant mismatch")


def encrypt_internal_message(client, message_number, key_id, case):
    plaintext_message = f"{MESSAGE} internal {message_number}"
    encrypted = client.post(
        f"/message/internal/encrypt/{key_id}",
        {"plaintext": plaintext_message},
        auth=True,
    )
    validate_internal_message_output(encrypted, key_id, case)

    decrypted = client.post("/message/internal/decrypt", encrypted, auth=True)
    require(
        decrypted.get("plaintext") == plaintext_message,
        "internal message decrypt plaintext mismatch",
    )

    return {
        "timestamp": encrypted["timestamp"],
        "variant": encrypted["message"]["variant"],
        "ctx_hex_len": len(encrypted["message"]["ctx"]),
        "plaintext": decrypted["plaintext"],
    }



def send_message(
    client,
    message_number,
    sender_key_id,
    recipient_key_id,
    sender_case,
    recipient_case=None,
):
    if recipient_case is None:
        recipient_case = sender_case
    before = len(FinalAppHandler.deliveries)
    plaintext_message = MESSAGE + str(message_number)
    response = client.post(
        f"/message/{sender_key_id}",
        {
            "recipient_kid": recipient_key_id,
            "message": plaintext_message,
        },
        auth=True,
    )
    validate_message_response(response, sender_case)
    require(
        len(FinalAppHandler.deliveries) == before + 1,
        "final app must receive exactly one delivery",
    )
    delivery = FinalAppHandler.deliveries[-1]
    validate_final_app_delivery(delivery, sender_key_id, recipient_case)
    plaintext = decrypt_message(client, delivery, plaintext_message)

    return {
        "timestamp": delivery["timestamp"],
        "variant": delivery["message"]["variant"],
        "ctx_hex_len": len(delivery["message"]["ctx"]),
        "plaintext": plaintext,
    }


@cases('positive.messages')
def run_messages(ctx):
    client = ctx.client
    created = ctx.artifacts["positive.keys"]
    recipient_host = ctx.artifacts["positive.recipient_host"]

    test_rows = []
    pub_rows = []
    message_rows = []
    internal_message_rows = []

    for key_id, case in created:
        validate_test_response(client.get(f"/self-test/keys/{key_id}", auth=True), case)
        test_rows.append((key_id, "OK"))

        validate_pub_response(client.get(f"/pub/{key_id}"), case)
        pub_rows.append((key_id, "OK"))

        message_result = send_message(client, len(message_rows) + 1, key_id, key_id, case)
        message_rows.append(
            (
                key_id,
                message_result["timestamp"],
                message_result["variant"],
                message_result["ctx_hex_len"],
                message_result["plaintext"],
            )
        )

        internal_result = encrypt_internal_message(client, len(internal_message_rows) + 1, key_id, case)
        internal_message_rows.append(
            (
                key_id,
                internal_result["timestamp"],
                internal_result["variant"],
                internal_result["ctx_hex_len"],
                internal_result["plaintext"],
            )
        )

    write_test_remote_routes(ctx, [key_id for key_id, _ in created], wildcard=True)
    reload_config(ctx)
    wildcard_result = send_message(
        client,
        len(message_rows) + 1,
        created[-1][0],
        created[0][0],
        created[-1][1],
        created[0][1],
    )
    message_rows.append(
        (
            f"{created[-1][0]} -> {created[0][0]} wildcard",
            wildcard_result["timestamp"],
            wildcard_result["variant"],
            wildcard_result["ctx_hex_len"],
            wildcard_result["plaintext"],
        )
    )

    print_section("test key", test_rows)
    print_section("pub", pub_rows)
    print_message(message_rows)
    print_internal_message(internal_message_rows)
    return CaseResult(
        passed=len(test_rows) + len(pub_rows) + len(message_rows) + len(internal_message_rows)
    )


CASES = cases.tuple()
