"""Bounded synthetic inputs. No XML parser/native module is imported here."""

INPUT_CAP = 512 * 1024
OUTPUT_CAP = 2 * 1024**2
CASES = (
    "utf8",
    "latin1",
    "charrefs",
    "quadratic",
    "attributes",
    "entities",
    "external",
    "capsule-first",
    "capsule-last",
)


def payload(name):
    if name == "utf8":
        raw = ("<r>" + "\u20ac\U0001f642" * 16384 + "</r>").encode()
    elif name == "latin1":
        raw = b'<?xml version="1.0" encoding="ISO-8859-1"?><r>' + b"\xe9" * 131072 + b"</r>"
    elif name == "charrefs":
        raw = b"<r>" + b"&#x20ac;" * 16384 + b"</r>"
    elif name == "quadratic":
        raw = b"<r a='" + b"x" * 131072 + b"'/>"
    elif name == "attributes":
        raw = b"<r " + b" ".join(f"a{i}='x'".encode() for i in range(16384)) + b"/>"
    elif name == "entities":
        raw = b"<!DOCTYPE r [<!ENTITY a 'content' ><!ENTITY b '&a;&a;&a;&a;'>]><r>&b;</r>"
    else:
        raise ValueError("unknown_payload")
    if not 0 < len(raw) <= INPUT_CAP:
        raise ValueError("input_cap")
    return raw
