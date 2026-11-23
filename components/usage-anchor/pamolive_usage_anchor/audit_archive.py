"""Bounded export and offline verification against an independently held audit head."""

from dataclasses import asdict, dataclass

from .codec import b64, closed, digest, encode, integer, need, parse, sha, unb64, uuid

SCHEMA = "pamolive.vault.usage-audit-archive-page/1"
AUDIT_DOMAIN = b"pamolive.vault.usage-audit.v1\0"
GENESIS_SHA256 = "0" * 64
MAX_EVENT_BYTES = 4096
MAX_PAGE_EVENTS = 128
MAX_ENCODED_EVENT = (MAX_EVENT_BYTES * 4 + 2) // 3
MAX_PAGE_BYTES = MAX_PAGE_EVENTS * (MAX_ENCODED_EVENT + 256) + 1024
PAGE_PROFILE = {"string": MAX_ENCODED_EVENT}
ENTRY_KEYS = {"seq", "previous_sha256", "event_sha256"}
PAGE_KEYS = {"schema", "checkpoint", "after_seq", "previous_sha256", "limit", "entries"}
COMMITTED_EVENTS = {"activated", "bound", "consumed_no_release", "refused_no_release"}
EMPTY_DIGEST_EVENTS = {"activation_challenge", "activation_revoked", "closed_and_fenced"}


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """An expected audit head obtained independently of the archive being checked."""

    context_id: str
    slot_sha256: str
    organization_id: str
    installation_id: str
    last_seq: int
    head_sha256: str

    def __post_init__(self):
        uuid(self.context_id)
        digest(self.slot_sha256)
        uuid(self.organization_id)
        uuid(self.installation_id)
        integer(self.last_seq, 0)
        digest(self.head_sha256)
        need((self.last_seq == 0) == (self.head_sha256 == GENESIS_SHA256))

    def require_slot(self, slot):
        expected = slot.expected()
        need(
            self.context_id == slot.context_id
            and self.slot_sha256 == slot.source_sha256
            and self.organization_id == expected["organization_id"]
            and self.installation_id == expected["installation_id"],
            "context_refused",
            403,
        )


def _page_count(checkpoint, after_seq, previous_sha256, limit):
    need(type(checkpoint) is Checkpoint)
    integer(after_seq, 0, checkpoint.last_seq)
    digest(previous_sha256)
    integer(limit, 1, MAX_PAGE_EVENTS)
    if after_seq == 0:
        need(previous_sha256 == GENESIS_SHA256)
    need(after_seq < checkpoint.last_seq or checkpoint.last_seq == 0)
    return min(limit, checkpoint.last_seq - after_seq)


def _event(checkpoint, raw):
    value = parse(raw, MAX_EVENT_BYTES)
    closed(value, {"event", "operation_id", "at", "digest"})
    event = value["event"]
    need(type(event) is str and event in COMMITTED_EVENTS | EMPTY_DIGEST_EVENTS)
    integer(value["at"])
    subject = value["operation_id"]
    if event == "activation_revoked":
        digest(subject)
    else:
        uuid(subject)
    if event == "closed_and_fenced":
        need(subject == checkpoint.context_id)
    if event in COMMITTED_EVENTS:
        digest(value["digest"])
    else:
        need(value["digest"] == "")


def _verify_chain(checkpoint, after_seq, previous_sha256, rows, limit):
    expected_count = _page_count(checkpoint, after_seq, previous_sha256, limit)
    need(type(rows) in (list, tuple) and len(rows) == expected_count)
    for seq, row in enumerate(rows, after_seq + 1):
        closed(row, ENTRY_KEYS | {"event_bytes"})
        need(integer(row["seq"]) == seq and digest(row["previous_sha256"]) == previous_sha256)
        raw = row["event_bytes"]
        _event(checkpoint, raw)
        computed = sha(AUDIT_DOMAIN + bytes.fromhex(previous_sha256) + raw)
        need(digest(row["event_sha256"]) == computed)
        previous_sha256 = computed
    last_seq = after_seq + expected_count
    if last_seq == checkpoint.last_seq:
        need(previous_sha256 == checkpoint.head_sha256)
    return last_seq, previous_sha256


def encode_archive_page(checkpoint, after_seq, previous_sha256, rows, *, limit):
    """Emit a canonical page with the original audit bytes and no additional fields."""
    _verify_chain(checkpoint, after_seq, previous_sha256, rows, limit)
    entries = [
        {
            "seq": row["seq"],
            "previous_sha256": row["previous_sha256"],
            "event_sha256": row["event_sha256"],
            "event_b64": b64(row["event_bytes"]),
        }
        for row in rows
    ]
    return encode(
        {
            "schema": SCHEMA,
            "checkpoint": asdict(checkpoint),
            "after_seq": after_seq,
            "previous_sha256": previous_sha256,
            "limit": limit,
            "entries": entries,
        },
        MAX_PAGE_BYTES,
        **PAGE_PROFILE,
    )


class ArchiveVerifier:
    """Prove chain integrity up to the supplied head, with no signing or I/O."""

    def __init__(self, checkpoint):
        need(type(checkpoint) is Checkpoint)
        self._checkpoint = checkpoint
        self._after_seq = 0
        self._head_sha256 = GENESIS_SHA256
        self._accepted_page = False

    @property
    def after_seq(self):
        return self._after_seq

    @property
    def head_sha256(self):
        return self._head_sha256

    def accept(self, raw):
        checkpoint = self._checkpoint
        need(self.after_seq < checkpoint.last_seq or not self._accepted_page)
        page = parse(raw, MAX_PAGE_BYTES, **PAGE_PROFILE)
        closed(page, PAGE_KEYS)
        need(page["schema"] == SCHEMA)
        expected = asdict(checkpoint)
        closed(page["checkpoint"], expected)
        need(Checkpoint(**page["checkpoint"]) == checkpoint)
        need(page["after_seq"] == self.after_seq and page["previous_sha256"] == self.head_sha256)
        count = _page_count(checkpoint, page["after_seq"], page["previous_sha256"], page["limit"])
        entries = page["entries"]
        need(type(entries) is list and len(entries) == count)
        rows = []
        for entry in entries:
            closed(entry, ENTRY_KEYS | {"event_b64"})
            rows.append(
                {
                    "seq": entry["seq"],
                    "previous_sha256": entry["previous_sha256"],
                    "event_sha256": entry["event_sha256"],
                    "event_bytes": unb64(entry["event_b64"], MAX_EVENT_BYTES),
                }
            )
        self._after_seq, self._head_sha256 = _verify_chain(
            checkpoint, self.after_seq, self.head_sha256, rows, page["limit"]
        )
        self._accepted_page = True

    def finish(self):
        """Require the entire chain to reach the independent expected checkpoint."""
        need(
            self.after_seq == self._checkpoint.last_seq
            and self.head_sha256 == self._checkpoint.head_sha256
        )
        return self._checkpoint
