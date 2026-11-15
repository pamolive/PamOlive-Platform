"""Explicit immutable caller expectations, never loaded from proof documents."""

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

from ._codec import fail, integer, public_call

_DATE = re.compile(
    r"(?P<year>\d{4})-(?P<month>\d{1,2})-(?P<day>\d{1,2})"
    r"[T ](?P<hour>\d{1,2}):(?P<minute>\d{1,2})"
    r"(?::(?P<second>\d{1,2})(?:[.,](?P<microsecond>\d{1,6})\d{0,6})?)?"
    r"\s*(?P<tzinfo>Z|[+-]\d{2}(?::?\d{2})?)?$"
)


def timestamp(value):
    if type(value) is not str:
        fail()
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        match = _DATE.match(value)
        if match is None:
            fail()
        fields = match.groupdict()
        fields["microsecond"] = fields["microsecond"] and fields["microsecond"].ljust(6, "0")
        offset = fields.pop("tzinfo")
        zone = None
        if offset == "Z":
            zone = UTC
        elif offset is not None:
            minutes = int(offset[-2:]) if len(offset) > 3 else 0
            minutes += 60 * int(offset[1:3])
            if offset[0] == "-":
                minutes = -minutes
            zone = timezone(timedelta(minutes=minutes))
        fields = {name: int(number) for name, number in fields.items() if number is not None}
        result = datetime(**fields, tzinfo=zone)
    if result.tzinfo is None or result.utcoffset() is None:
        fail()
    return result


def uuid(value):
    return type(value) is str and len(value) == 36 and str(UUID(value)) == value


def opaque(value):
    if type(value) is not str or not 0 < len(value) <= 128 or not value.strip():
        return False
    value.encode("utf-8")
    return True


@dataclass(frozen=True, slots=True)
class ExternalKey:
    key_id: str
    public_key: bytes
    active: bool = True
    not_before: str = ""
    not_after: str = ""
    revoked_at: str = ""

    def __post_init__(self):
        public_call(_key, self)


def _key(value):
    if type(value) is not ExternalKey or not opaque(value.key_id):
        fail()
    if (
        type(value.public_key) is not bytes
        or len(value.public_key) != 32
        or type(value.active) is not bool
    ):
        fail()
    for period in (value.not_before, value.not_after, value.revoked_at):
        if type(period) is not str or len(period) > 128:
            fail()
        if period:
            timestamp(period)
    if (
        value.not_before
        and value.not_after
        and timestamp(value.not_before) >= timestamp(value.not_after)
    ):
        fail()


def _keys(values):
    if type(values) is not tuple or not 1 <= len(values) <= 64:
        fail()
    seen = set()
    for key in values:
        _key(key)
        if key.key_id in seen:
            fail()
        seen.add(key.key_id)


@dataclass(frozen=True, slots=True)
class HistoricalContext:
    installation: str
    organization: str
    generation: str
    revision: int
    registry_hash: str
    commissioning_keys: tuple[ExternalKey, ...]

    def __post_init__(self):
        public_call(validate_context, self, False)


@dataclass(frozen=True, slots=True)
class CurrentContext:
    installation: str
    organization: str
    generation: str
    revision: int
    registry_hash: str
    commissioning_keys: tuple[ExternalKey, ...]
    checkpoint_keys: tuple[ExternalKey, ...]
    now_utc: str
    registry_max_seconds: int = 86400
    checkpoint_max_seconds: int = 60

    def __post_init__(self):
        public_call(validate_context, self, True)


def validate_context(value, current):
    if type(value) is not (CurrentContext if current else HistoricalContext):
        fail()
    if not opaque(value.installation) or not uuid(value.organization) or not uuid(value.generation):
        fail()
    if (
        not integer(value.revision)
        or type(value.registry_hash) is not str
        or not re.fullmatch("[0-9a-f]{64}", value.registry_hash)
    ):
        fail()
    _keys(value.commissioning_keys)
    if current:
        _keys(value.checkpoint_keys)
        if (
            type(value.now_utc) is not str
            or len(value.now_utc) > 128
            or timestamp(value.now_utc).utcoffset() != timedelta(0)
        ):
            fail()
        if not integer(value.registry_max_seconds, maximum=86400) or not integer(
            value.checkpoint_max_seconds, maximum=60
        ):
            fail()


def external_key(keys, key_id, signed_at, *, historical):
    matches = [key for key in keys if key.key_id == key_id]
    if len(matches) != 1:
        fail()
    value = matches[0]
    if not historical and not value.active:
        fail()
    if value.not_before and signed_at < timestamp(value.not_before):
        fail()
    if value.not_after and signed_at >= timestamp(value.not_after):
        fail()
    if value.revoked_at and signed_at >= timestamp(value.revoked_at):
        fail()
    return value.public_key
