"""Generic HTTP response assertions with no endpoint semantics."""

from .client import WorkflowError


INTERNAL_KEYS_KID_HEX_LEN = 64


def require(condition, message):
    if not condition:
        raise WorkflowError(message)


def require_hex(value, field):
    require(isinstance(value, str), f"{field} must be a string")
    require(len(value) > 0, f"{field} must not be empty")
    try:
        int(value, 16)
    except ValueError as err:
        raise WorkflowError(f"{field} must be hex") from err


def require_kid(value, field):
    require_hex(value, field)
    require(len(value) == INTERNAL_KEYS_KID_HEX_LEN, f"{field} must be {INTERNAL_KEYS_KID_HEX_LEN} hex characters")


def require_request_id(headers):
    request_id = headers.get("X-Request-Id")
    require(isinstance(request_id, str), "response must include X-Request-Id")
    require(len(request_id) == 32, "X-Request-Id must be 32 hex characters")
    require_hex(request_id, "X-Request-Id")
