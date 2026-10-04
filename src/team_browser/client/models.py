"""Public, secret-free local workspace contracts."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import struct
import zlib
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)


IconPreset = Literal["browser", "facebook", "google_ads", "youtube", "custom"]
MAX_ICON_BYTES = 128 * 1024
MAX_ICON_DIMENSION = 1024
MAX_ICON_DATA_URL_LENGTH = 4 * ((MAX_ICON_BYTES + 2) // 3) + 32


def printable_label(value: str) -> str:
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Labels must not contain control characters")
    return value


def _raster_dimensions(mime: str, raw: bytes) -> tuple[int, int]:
    """Check bounded raster containers without installing an image decoder.

    These are format/header checks, not a claim of complete codec validation.
    Only image data URLs reach the UI; SVG, HTML, remote URLs and paths do not.
    """
    if mime == "png" and raw.startswith(b"\x89PNG\r\n\x1a\n"):
        offset, dimensions, has_data = 8, None, False
        while offset + 12 <= len(raw):
            length = int.from_bytes(raw[offset : offset + 4], "big")
            kind = raw[offset + 4 : offset + 8]
            end = offset + 12 + length
            if end > len(raw):
                break
            chunk = raw[offset + 4 : end - 4]
            if zlib.crc32(chunk) != int.from_bytes(raw[end - 4 : end], "big"):
                break
            if offset == 8:
                if kind != b"IHDR" or length != 13:
                    break
                dimensions = struct.unpack(">II", raw[offset + 8 : offset + 16])
            elif kind == b"IHDR" or kind in {b"acTL", b"fcTL", b"fdAT"}:
                break  # Static icons only; no animated frame dimensions to trust.
            if kind == b"IDAT":
                has_data = True
            if kind == b"IEND":
                if end == len(raw) and length == 0 and dimensions and has_data:
                    return dimensions
                break
            offset = end
    elif mime == "jpeg" and raw.startswith(b"\xff\xd8") and raw.endswith(b"\xff\xd9"):
        offset = 2
        dimensions = None
        while offset + 4 <= len(raw):
            if raw[offset] != 0xFF:
                break
            while offset < len(raw) and raw[offset] == 0xFF:
                offset += 1
            if offset + 3 > len(raw):
                break
            marker = raw[offset]
            length = int.from_bytes(raw[offset + 1 : offset + 3], "big")
            if length < 2 or offset + 1 + length > len(raw):
                break
            if marker in {0xC0, 0xC1, 0xC2} and length >= 8:
                height, width = struct.unpack(">HH", raw[offset + 4 : offset + 8])
                dimensions = (width, height)
            if marker == 0xDA:
                if dimensions:
                    return dimensions
                break
            offset += 1 + length
    elif (
        mime == "webp"
        and len(raw) >= 26
        and raw[:4] == b"RIFF"
        and raw[8:12] == b"WEBP"
        and int.from_bytes(raw[4:8], "little") + 8 == len(raw)
    ):
        offset, canvas, dimensions = 12, None, None
        while offset + 8 <= len(raw):
            kind = raw[offset : offset + 4]
            length = int.from_bytes(raw[offset + 4 : offset + 8], "little")
            end = offset + 8 + length + (length % 2)
            if end > len(raw) or kind in {b"ANIM", b"ANMF"}:
                break
            chunk = raw[offset + 8 : offset + 8 + length]
            if kind == b"VP8X":
                if offset != 12 or length != 10 or chunk[0] & 0x02:
                    break
                canvas = (
                    int.from_bytes(chunk[4:7], "little") + 1,
                    int.from_bytes(chunk[7:10], "little") + 1,
                )
            elif kind in {b"VP8 ", b"VP8L"}:
                if dimensions is not None:
                    break
                if kind == b"VP8 " and length >= 10 and chunk[3:6] == b"\x9d\x01\x2a":
                    dimensions = tuple(
                        value & 0x3FFF for value in struct.unpack("<HH", chunk[6:10])
                    )
                elif kind == b"VP8L" and length >= 5 and chunk[0] == 0x2F:
                    bits = int.from_bytes(chunk[1:5], "little")
                    dimensions = (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
                else:
                    break
            offset = end
        else:
            if offset == len(raw) and dimensions and (canvas is None or canvas == dimensions):
                return dimensions
    raise ValueError("Use a valid static PNG, JPEG or WebP icon")


def validate_icon_data_url(value: str) -> str:
    if not value:
        return value
    match = re.fullmatch(r"data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})", value)
    if not match:
        raise ValueError("Use a base64 PNG, JPEG or WebP icon, not a URL or SVG")
    try:
        raw = base64.b64decode(match.group(2), validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Invalid icon encoding") from None
    if not 0 < len(raw) <= MAX_ICON_BYTES:
        raise ValueError("Icons must be no larger than 128 KiB")
    width, height = _raster_dimensions(match.group(1), raw)
    if not (1 <= width <= MAX_ICON_DIMENSION and 1 <= height <= MAX_ICON_DIMENSION):
        raise ValueError("Icon dimensions must be between 1 and 1024 pixels")
    return value


class ProxyConfig(InputModel):
    """Untrusted connection metadata. It cannot enable or verify a proxy route."""

    protocol: Literal["http", "https", "socks5"]
    hostname: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    label: str = Field(default="", max_length=120)

    _printable_label = field_validator("label")(printable_label)

    @field_validator("hostname")
    @classmethod
    def host_only(cls, value: str) -> str:
        # No credentials, URLs, paths, query strings, ports or scoped IPv6.
        if "%" in value:
            raise ValueError("Use a hostname or IP address without credentials or a URL")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
        labels = (value[:-1] if value.endswith(".") else value).split(".")
        if not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x) for x in labels
        ):
            raise ValueError("Use a hostname or IP address without credentials or a URL")
        return value.lower()


class ProfileCreate(InputModel):
    name: str = Field(min_length=1, max_length=120)
    preset_id: str = Field(default="standard", min_length=1, max_length=64)
    favorite: bool = False
    network_policy: Literal["unconfigured", "local_direct", "verified_proxy"] = "unconfigured"
    icon_preset: IconPreset = "browser"
    custom_icon_data_url: str = Field(default="", max_length=MAX_ICON_DATA_URL_LENGTH)
    assignment_label: str = Field(default="", max_length=120)
    proxy_config: ProxyConfig | None = None

    _printable_label = field_validator("assignment_label")(printable_label)
    _raster_icon = field_validator("custom_icon_data_url")(validate_icon_data_url)

    @model_validator(mode="after")
    def coherent_metadata(self) -> ProfileCreate:
        if (self.icon_preset == "custom") != bool(self.custom_icon_data_url):
            raise ValueError("A custom icon requires the custom preset and image together")
        if self.proxy_config is not None and self.network_policy != "verified_proxy":
            raise ValueError("Saved proxy details require the explicit verified-proxy policy")
        return self

    @field_validator("name")
    @classmethod
    def printable_name(cls, value: str) -> str:
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Profile names must not contain control characters")
        return value


class ProfilePatch(InputModel):
    expected_revision: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=120)
    preset_id: str | None = Field(default=None, min_length=1, max_length=64)
    favorite: bool | None = None
    network_policy: Literal["unconfigured", "local_direct", "verified_proxy"] | None = None
    icon_preset: IconPreset | None = None
    custom_icon_data_url: str | None = Field(default=None, max_length=MAX_ICON_DATA_URL_LENGTH)
    assignment_label: str | None = Field(default=None, max_length=120)
    proxy_config: ProxyConfig | None = None

    @model_validator(mode="after")
    def nonempty_patch(self) -> ProfilePatch:
        changes = self.model_fields_set - {"expected_revision"}
        if not changes or any(getattr(self, key) is None for key in changes - {"proxy_config"}):
            raise ValueError("Provide at least one non-null profile change")
        if self.name is not None:
            ProfileCreate.printable_name(self.name)
        if self.assignment_label is not None:
            printable_label(self.assignment_label)
        if self.custom_icon_data_url is not None:
            validate_icon_data_url(self.custom_icon_data_url)
        return self


class ProfileAction(InputModel):
    action: Literal["select", "start", "stop", "cancel"]
    expected_revision: int | None = Field(default=None, ge=1)
    idempotency_key: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{8,100}$")
    intent: Literal["gmail"] | None = None

    @model_validator(mode="after")
    def bind_native_intent(self) -> ProfileAction:
        if self.intent is not None and (self.action != "start" or self.expected_revision is None):
            raise ValueError("Gmail open requires action=start and the expected profile revision")
        return self


class SettingsPatch(InputModel):
    expected_revision: int = Field(ge=1)
    max_warm_profiles: int | None = Field(default=None, ge=1, le=16)
    memory_budget_mb: int | None = Field(default=None, ge=256, le=65536)
    estimated_profile_mb: int | None = Field(default=None, ge=128, le=8192)
    profile_navigation: Literal["sidebar", "grid"] | None = None
    tab_navigation: Literal["top", "side"] | None = None
    mirror_same_origin: bool | None = None

    @model_validator(mode="after")
    def nonempty_patch(self) -> SettingsPatch:
        changes = self.model_fields_set - {"expected_revision"}
        if not changes or any(getattr(self, key) is None for key in changes):
            raise ValueError("Provide at least one non-null resource setting")
        return self


class ManagedConnectionPut(InputModel):
    expected_revision: int = Field(ge=1)
    server_url: str | None = Field(default=None, max_length=2048)

    @field_validator("server_url")
    @classmethod
    def metadata_url_only(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
            or any(c.isspace() or ord(c) < 32 for c in value)
        ):
            raise ValueError("Use an HTTPS server origin without credentials, path or query")
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("Invalid server port") from exc
        return value.rstrip("/")


class ManagedNativeAction(InputModel):
    action: Literal[
        "prepare", "recover", "sign_in", "cancel_sign_in", "refresh_records", "sign_out"
    ]


class TabFocus(InputModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=False)
    tab_id: str = Field(min_length=36, max_length=36, pattern=r"^tab_[a-f0-9]{32}$")
    generation: int = Field(ge=1)
    expected_revision: int = Field(ge=1)
