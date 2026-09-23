"""Negative HTTP contract cases: message routing validation.

Reads key_id and disabled_key_id (produced by the authz
and lifecycle bootstraps). Each case is a plain function taking ctx.
"""

from lib.casekit import CaseSet
from lib.fixtures import host_from_base_url
from .negative_support import require_status, valid_message_request

cases = CaseSet()


@cases('negative.messages.message-without-auth')
def _(ctx):
    status, _ = ctx.http.post(
        f"/message/{ctx.fixtures.key_id}",
        valid_message_request(ctx.fixtures.key_id),
    )
    require_status("POST /message/{sender_kid} without auth", status, 401)


@cases('negative.messages.message-sender-id-not-hex')
def _(ctx):
    status, _ = ctx.http.post(
        "/message/not-hex",
        valid_message_request(ctx.fixtures.key_id),
        auth=True,
    )
    require_status("POST /message/{sender_kid} sender not hex", status, 400)


@cases('negative.messages.message-recipient-route-not-found')
def _(ctx):
    ctx.set_remote_routes([])
    status, _ = ctx.http.post("/config/reload", {}, auth=True)
    require_status("POST /config/reload empty", status, 200)
    status, _ = ctx.http.post(
        f"/message/{ctx.fixtures.key_id}",
        valid_message_request(ctx.fixtures.key_id),
        auth=True,
    )
    require_status("POST /message/{sender_kid} recipient route not found", status, 404)


@cases('negative.messages.message-recipient-route-disabled')
def _(ctx):
    ctx.set_remote_routes(
        [
            {
                "remote_kid": ctx.fixtures.key_id,
                "name": "disabled route",
                "remote_addr": host_from_base_url(ctx.base_url),
                "allowed_local_kids": [ctx.fixtures.key_id],
                "status": "disabled",
            }
        ]
    )
    status, _ = ctx.http.post("/config/reload", {}, auth=True)
    require_status("POST /config/reload disabled", status, 200)
    status, _ = ctx.http.post(
        f"/message/{ctx.fixtures.key_id}",
        valid_message_request(ctx.fixtures.key_id),
        auth=True,
    )
    require_status("POST /message/{sender_kid} recipient route disabled", status, 403)


@cases('negative.messages.message-sender-not-allowed-for-route')
def _(ctx):
    ctx.set_remote_routes(
        [
            {
                "remote_kid": ctx.fixtures.key_id,
                "name": "sender not allowed",
                "remote_addr": host_from_base_url(ctx.base_url),
                "allowed_local_kids": [ctx.fixtures.disabled_key],
                "status": "active",
            }
        ]
    )
    status, _ = ctx.http.post("/config/reload", {}, auth=True)
    require_status("POST /config/reload sender not allowed", status, 200)
    status, _ = ctx.http.post(
        f"/message/{ctx.fixtures.key_id}",
        valid_message_request(ctx.fixtures.key_id),
        auth=True,
    )
    require_status("POST /message/{sender_kid} sender not allowed for route", status, 403)


@cases('negative.messages.message-route-without-public-keys')
def _(ctx):
    ctx.set_remote_routes(
        [
            {
                "remote_kid": ctx.fixtures.key_id,
                "name": "no public keys",
                "remote_addr": host_from_base_url(ctx.base_url),
                "allowed_local_kids": [ctx.fixtures.key_id],
                "status": "active",
            }
        ]
    )
    status, _ = ctx.http.post("/config/reload", {}, auth=True)
    require_status("POST /config/reload no public keys", status, 200)
    status, _ = ctx.http.post(
        f"/message/{ctx.fixtures.key_id}",
        valid_message_request(ctx.fixtures.key_id),
        auth=True,
    )
    require_status("POST /message/{sender_kid} route without public keys", status, 403)


@cases('negative.messages.message-invalid-recipient-kid')
def _(ctx):
    request = valid_message_request(ctx.fixtures.key_id)
    request["recipient_kid"] = "not-hex"
    status, _ = ctx.http.post(
        f"/message/{ctx.fixtures.key_id}",
        request,
        auth=True,
    )
    require_status("POST /message/{sender_kid} invalid recipient kid", status, 400)


@cases('negative.messages.message-empty-message')
def _(ctx):
    request = valid_message_request(ctx.fixtures.key_id)
    request["message"] = ""
    status, _ = ctx.http.post(
        f"/message/{ctx.fixtures.key_id}",
        request,
        auth=True,
    )
    require_status("POST /message/{sender_kid} empty message", status, 400)


CASES = cases.tuple()
