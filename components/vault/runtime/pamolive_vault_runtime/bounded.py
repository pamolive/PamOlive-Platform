"""Closed public errors and small strict administrative/request encodings."""

import base64
import hashlib
import json
import re
from uuid import UUID


class Refusal(Exception):
    def __init__(self, code="invalid_request", status=400):
        codes = {
            "invalid_request": 400,
            "unavailable": 503,
            "caller_refused": 403,
            "context_refused": 403,
            "idempotency_conflict": 409,
            "quota_exceeded": 429,
            "reservation_expired": 410,
        }
        if type(code) is not str or type(status) is not int or codes.get(code) != status:
            code, status = "unavailable", 503
        self.code, self.status = code, status
        super().__init__(code)


def need(value, code="invalid_request", status=400):
    if not value:
        raise Refusal(code, status)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def uuid(value):
    need(type(value) is str and len(value) == 36)
    try:
        need(str(UUID(value)) == value)
    except ValueError:
        raise Refusal from None
    return value


def digest(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None)
    return value


def integer(value, minimum=1, maximum=2**63 - 1):
    need(type(value) is int and minimum <= value <= maximum)
    return value


def service(value):
    need(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", value))
    return value


def closed(value, keys):
    need(type(value) is dict and set(value) == set(keys))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def _no_float(value):
    raise Refusal


def _pre_json(raw):
    """Constant-space budget scan, NOT a JSON parser or syntax validator.

    Count containers, quoted strings (including keys) and scalar token starts.
    Ignore punctuation/escapes inside strings. Root depth is zero, matching the
    post-decode walk. Invalid syntax still belongs exclusively to json.loads.
    """
    nodes = nesting = 0
    quoted = escaped = scalar = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
            continue
        if byte == 34:
            need(nesting <= 12)
            nodes += 1
            quoted, scalar = True, False
        elif byte in (91, 123):
            need(nesting <= 12)
            nodes += 1
            nesting += 1
            scalar = False
        elif byte in (93, 125):
            nesting -= 1
            need(nesting >= 0)
            scalar = False
        elif byte in (9, 10, 13, 32, 44, 58):
            scalar = False
        elif not scalar:
            need(nesting <= 12)
            nodes += 1
            scalar = True
        need(nodes <= 8192)


def json_object(raw, maximum):
    need(type(raw) is bytes and 0 < len(raw) <= maximum)
    _pre_json(raw)  # Before UTF-8 decoding or any full JSON object allocation.
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_no_float,
            parse_float=_no_float,
        )
        pending, count = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            count += 1
            need(depth <= 12 and count <= 8192)
            if type(item) is dict:
                need(count + len(pending) + 2 * len(item) <= 8192)
                pending.extend((child, depth + 1) for pair in item.items() for child in pair)
            elif type(item) is list:
                need(count + len(pending) + len(item) <= 8192)
                pending.extend((child, depth + 1) for child in item)
            elif type(item) is str:
                need(len(item) <= maximum and "\0" not in item)
                item.encode("utf-8")
            elif type(item) not in (int, bool, type(None)):
                raise Refusal
        need(type(value) is dict)
        return value
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise Refusal from None


def b64decode(value, maximum):
    need(type(value) is str and 0 < len(value) <= (maximum * 4 + 2) // 3)
    need(re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        raise Refusal from None
    need(len(raw) <= maximum and base64.urlsafe_b64encode(raw).decode().rstrip("=") == value)
    return raw
