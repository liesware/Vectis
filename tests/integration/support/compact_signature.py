"""Shared compact-signature tamper helper.

Both the integration suite and the security-fuzz suite corrupt a compact
signature the same way: flip one Base64URL character in one of the four segments
without weakening the overall shape. Keeping the definition here means the two
suites cannot drift on what a "tampered" compact signature is.
"""

import base64

_BASE64URL_ALPHABET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _flip_base64url_char(value):
    if not isinstance(value, str) or not value:
        return value
    replacement = "B" if value[0] == "A" else "A"
    return replacement + value[1:]


def mutate_compact_signature_segment(signature, segment_index):
    """Change one Base64URL character without weakening the compact shape.

    Raises ValueError unless `signature` is four non-empty, canonical, unpadded
    base64url segments; callers that tolerate a missing/garbled signature catch
    that and treat the result as absent.
    """
    if not isinstance(signature, str) or segment_index not in range(4):
        raise ValueError("compact signature mutation requires a segment index from 0 through 3")
    segments = signature.split(".")
    if len(segments) != 4 or any(not segment or set(segment) - _BASE64URL_ALPHABET for segment in segments):
        raise ValueError("compact signature must contain four non-empty base64url segments")
    for segment in segments:
        try:
            decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        except ValueError as err:
            raise ValueError("compact signature contains invalid base64url") from err
        if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != segment:
            raise ValueError("compact signature contains non-canonical base64url")
    segments[segment_index] = _flip_base64url_char(segments[segment_index])
    return ".".join(segments)
