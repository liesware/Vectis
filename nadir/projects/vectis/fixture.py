"""Read-only local Vectis fixture and its declared runtime variables."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit

from nadir.engine import SetupFailure
from nadir.http import is_loopback_host


_RESERVED_OPTIONS = frozenset({"base_url", "kid", "api_key", "denied_api_key", "scoped_api_key", "required_variables"})


@dataclass(frozen=True)
class VectisFixture(AbstractContextManager["VectisFixture"]):
    base_url: str
    kid: str
    api_key: str | None
    denied_api_key: str | None
    scoped_api_key: str | None
    extra: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_options(cls, options: Mapping[str, object]) -> "VectisFixture":
        base_url, kid = options.get("base_url"), options.get("kid")
        required = options.get("required_variables", frozenset())
        if not isinstance(base_url, str) or not isinstance(kid, str) or not isinstance(required, frozenset):
            raise ValueError("Vectis fixture requires base_url and kid")
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.path not in {"", "/"}:
            raise ValueError("Vectis base_url must be an origin URL")
        if not is_loopback_host(parsed.hostname):
            raise ValueError("Nadir v1 accepts only loopback Vectis targets")
        if len(kid) != 64 or any(character not in "0123456789abcdefABCDEF" for character in kid):
            raise ValueError("Vectis kid must be 64 hexadecimal characters")
        api_key = None
        if "api_key" in required:
            configured_api_key = options.get("api_key")
            if not isinstance(configured_api_key, str) or not configured_api_key:
                raise SetupFailure("NADIR_API_KEY is required by the selected Vectis target")
            api_key = configured_api_key
        denied_api_key = None
        if "denied_api_key" in required:
            configured_denied_api_key = options.get("denied_api_key")
            if not isinstance(configured_denied_api_key, str) or not configured_denied_api_key:
                raise SetupFailure("NADIR_DENIED_API_KEY is required by the selected Vectis authorization target")
            denied_api_key = configured_denied_api_key
        scoped_api_key = None
        if "scoped_api_key" in required:
            configured_scoped_api_key = options.get("scoped_api_key")
            if not isinstance(configured_scoped_api_key, str) or not configured_scoped_api_key:
                raise SetupFailure("NADIR_SCOPED_API_KEY is required by the selected Vectis scoped authorization target")
            scoped_api_key = configured_scoped_api_key
        # Any other NADIR_* value (e.g. digest) flows through as a template variable
        # so target specs stay free of hardcoded literals.
        extra = tuple((name, value) for name, value in options.items() if name not in _RESERVED_OPTIONS and isinstance(value, str))
        return cls(base_url.rstrip("/"), kid, api_key, denied_api_key, scoped_api_key, extra)

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        return None

    def variables(self) -> dict[str, object]:
        values: dict[str, object] = {"base_url": self.base_url, "kid": self.kid}
        if self.api_key is not None:
            values["api_key"] = self.api_key
        if self.denied_api_key is not None:
            values["denied_api_key"] = self.denied_api_key
        if self.scoped_api_key is not None:
            values["scoped_api_key"] = self.scoped_api_key
        values.update(self.extra)
        return values
