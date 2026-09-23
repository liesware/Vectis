"""Negative HTTP contract cases: protocol contract.

Adding a case here is a plain function that takes ``ctx`` and asserts on a
request. No shared config and no fixtures: these cases only exercise the raw
transport contract (body-size limits, content type, method, request ids).
"""

from lib.casekit import CaseSet
from lib.client import raw_request
from lib.assertions import require_request_id

from .negative_support import CONTENT_TYPE_ERROR, HTTP_MAX_SIZE, OVERSIZE_ERROR

cases = CaseSet()


@cases("negative.protocol.oversized-body")
def _(ctx):
    before_status, before = ctx.http.get("/keys", auth=True)
    ctx.expect(before_status, 200, "GET /keys before oversized request")

    status, body, headers = ctx.http.post_with_headers(
        "/keys",
        {"padding": "a" * (HTTP_MAX_SIZE + 1)},
    )
    ctx.expect(status, 413, "POST /keys oversized request body")
    ctx.require(
        body == OVERSIZE_ERROR,
        f"oversized request must return the fixed JSON error, got {body!r}",
    )
    ctx.require(
        headers.get_content_type() == "application/json",
        "oversized request must return application/json",
    )
    require_request_id(headers)

    after_status, after = ctx.http.get("/keys", auth=True)
    ctx.expect(after_status, 200, "GET /keys after oversized request")
    ctx.require(after == before, "oversized request must not change key storage")


@cases("negative.protocol.http-contract")
def _(ctx):
    base = ctx.base_url
    verify = "/sign/verification"
    # A body of exactly the limit reaches the parser (a normal semantic
    # rejection), never 413; one byte over is the fixed 413.
    prefix, suffix = b'{"padding":"', b'"}'
    exact = prefix + b"a" * (HTTP_MAX_SIZE - len(prefix) - len(suffix)) + suffix
    ctx.require(len(exact) == HTTP_MAX_SIZE, "exact-limit body construction is wrong")
    status, _ = raw_request(base, "POST", verify, exact, "application/json")
    ctx.require(
        status != 413 and 400 <= status < 500,
        f"exact {HTTP_MAX_SIZE}-byte body must be a non-413 client error, got {status}",
    )
    over = prefix + b"a" * (HTTP_MAX_SIZE + 1 - len(prefix) - len(suffix)) + suffix
    status, body = raw_request(base, "POST", verify, over, "application/json")
    ctx.expect(status, 413, "POST /sign/verification body over the limit")
    ctx.require(body == OVERSIZE_ERROR, f"over-limit body must return the fixed 413 error, got {body!r}")

    # Content-Type contract: non-JSON and a missing header are 415.
    for label, content_type in (("text/plain", "text/plain"), ("missing header", None)):
        status, body = raw_request(base, "POST", verify, b'{"kid":"0"}', content_type)
        ctx.expect(status, 415, f"POST /sign/verification with {label}")
        ctx.require(body == CONTENT_TYPE_ERROR, f"{label} must return the fixed 415 error, got {body!r}")

    # Correct content type with an empty body is an ordinary 400.
    status, _ = raw_request(base, "POST", verify, b"", "application/json")
    ctx.expect(status, 400, "POST /sign/verification with an empty body")

    # A wrong method on a POST-only route is 405, never a body-dependent code.
    for method in ("GET", "PUT", "DELETE", "PATCH", "HEAD"):
        status, _ = raw_request(base, method, verify, None, None)
        ctx.expect(status, 405, f"{method} /sign/verification")

    live_status, _ = ctx.http.get("/healthz/live")
    ctx.expect(live_status, 200, "GET /healthz/live after protocol matrix")


CASES = cases.tuple()
