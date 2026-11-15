"""Bounded V1 JSON; no Unicode, timestamp or signed-value normalization."""

import json
import math

ERROR = "Invalid public PAM trust materials."
DOCUMENT_BYTES = 2 * 1024 * 1024
CHAIN_BYTES = 32 * 1024 * 1024
CHECKPOINT_BYTES = 65536
MAX_DEPTH = 16
MAX_NODES = 8192
MAX_STRING = 65536
MIN_INT, MAX_INT = -(1 << 63), (1 << 63) - 1


class InvalidMaterials(ValueError):
    """Constant public failure; no input contents or chained parser exception."""

    def __init__(self):
        super().__init__(ERROR)


def fail():
    raise InvalidMaterials()


def public_call(function, *args):
    failed = False
    try:
        value = function(*args)
    except Exception:
        failed = True
    if failed:
        # Outside the except block: even __context__ must not retain raw errors.
        raise InvalidMaterials() from None
    return value


def integer(value, minimum=1, maximum=MAX_INT):
    return type(value) is int and minimum <= value <= maximum


def _int(value):
    if len(value) > 20:
        fail()
    number = int(value)
    if not MIN_INT <= number <= MAX_INT:
        fail()
    return number


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        fail()
    return number


def _constant(_):
    fail()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result


def _pre_depth(raw):
    depth = 0
    quoted = escaped = False
    for value in raw:
        if quoted:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                quoted = False
        elif value == 34:
            quoted = True
        elif value in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                fail()
        elif value in (93, 125):
            depth -= 1
            if depth < 0:
                fail()


def shape(value):
    pending = [(value, 1)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_NODES:
            fail()
        if type(item) is dict:
            if depth > MAX_DEPTH or nodes + len(pending) + 2 * len(item) > MAX_NODES:
                fail()
            for key, child in item.items():
                if type(key) is not str or len(key) > MAX_STRING:
                    fail()
                nodes += 1
                if nodes > MAX_NODES:
                    fail()
                pending.append((child, depth + 1))
        elif type(item) is list:
            if depth > MAX_DEPTH or nodes + len(pending) + len(item) > MAX_NODES:
                fail()
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            if len(item) > MAX_STRING:
                fail()
        elif type(item) is int:
            if not MIN_INT <= item <= MAX_INT:
                fail()
        elif type(item) is float:
            if not math.isfinite(item):
                fail()
        elif item is not None and type(item) is not bool:
            fail()


def parse(raw, maximum=DOCUMENT_BYTES):
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        fail()
    _pre_depth(raw)
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_pairs,
        parse_int=_int,
        parse_float=_float,
        parse_constant=_constant,
    )
    shape(value)
    return value


def canonical(value, maximum=DOCUMENT_BYTES):
    shape(value)
    encoder = json.JSONEncoder(
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    chunks = []
    retained = 0
    for text in encoder.iterencode(value):
        # shape bounded every input string first; encode each bounded chunk only.
        chunk = text.encode("utf-8")
        if len(chunk) > maximum - retained:
            fail()
        retained += len(chunk)
        chunks.append(chunk)
    return b"".join(chunks)


def chain_input(raw):
    if type(raw) is not tuple or not 1 <= len(raw) <= 256:
        fail()
    total = 0
    for envelope in raw:
        if type(envelope) is not bytes or not 0 < len(envelope) <= DOCUMENT_BYTES:
            fail()
        total += len(envelope)
        if total > CHAIN_BYTES:
            fail()
