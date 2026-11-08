"""Read-only TeamViewer connection reporting. No account/identity inference or writes.

Contract: official Web API Connections_Get and TeamViewerPS at
a15ec4e55af7d17ce338aa9b4dbcce4db9e81eeb. Bounds apply to completion time:
do not send from_date, which filters start time and would lose long sessions.
"""

import http.client
import json
import ssl
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlencode

from .scim import IntegrationFailure, PinnedHTTPSConnection, destination, resolve_destination

BASE_URL = "https://webapi.teamviewer.com/api/v1"
MAX_BODY = 2 * 1024 * 1024


def _json(content):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    return json.loads(
        content,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
    )


def _text(value, maximum=180):
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise IntegrationFailure("teamviewer_invalid_record")
    return value


def _time(value):
    if not isinstance(value, str) or len(value) > 50:
        raise IntegrationFailure("teamviewer_invalid_timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.utcoffset() is None:
            raise ValueError
        return result.astimezone(UTC)
    except ValueError:
        raise IntegrationFailure("teamviewer_invalid_timestamp") from None


@dataclass(frozen=True)
class ConnectionReport:
    id: str
    account_ref: str | None
    device_ref: str | None
    started_at: datetime
    ended_at: datetime
    notes: str

    @classmethod
    def parse(cls, value):
        if not isinstance(value, dict):
            raise IntegrationFailure("teamviewer_invalid_record")
        try:
            identifier = str(uuid.UUID(value["id"]))
            start, end = _time(value["start_date"]), _time(value["end_date"])
            if start > end:
                raise ValueError
            # Notes are a source declaration, never a verified ticket or privilege.
            notes = value.get("notes")
            if notes is None:
                notes = ""
            if not isinstance(notes, str) or len(notes) > 16384:
                raise ValueError
            return cls(
                identifier,
                _text(value.get("userid")),
                _text(value.get("deviceid")),
                start,
                end,
                notes,
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            raise IntegrationFailure("teamviewer_invalid_record") from None


@dataclass(frozen=True)
class ReportBatch:
    reports: tuple[ConnectionReport, ...]
    pages: int
    pagination_complete: bool
    code: str


class TeamViewerClient:
    def __init__(self, token, *, base_url=BASE_URL):
        self.host, self.port, self.path = destination(base_url)
        if (
            not isinstance(token, str)
            or not 1 <= len(token) <= 4096
            or any(ord(c) < 33 or ord(c) > 126 for c in token)
        ):
            raise IntegrationFailure("teamviewer_invalid_token")
        self.token = token

    def request_page(self, *, until, offset=None):
        # Never follow a URL returned by the API. Only an opaque validated cursor
        # can influence a request to the same configured/pinned HTTPS destination.
        from django.conf import settings

        values = {"to_date": until.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}
        if offset:
            values["offset_id"] = str(uuid.UUID(offset))
        connection = None
        try:
            selected = resolve_destination(self.host, self.port)
            context = ssl.create_default_context(cafile=settings.CONNECTOR_CA_BUNDLE or None)
            connection = PinnedHTTPSConnection(self.host, self.port, selected, context)
            connection.request(
                "GET",
                self.path + "/reports/connections?" + urlencode(values),
                headers={"Authorization": "Bearer " + self.token, "Accept": "application/json"},
            )
            response = connection.getresponse()
            if response.status != 200:
                raise IntegrationFailure(
                    "teamviewer_http_" + str(response.status),
                    retryable=response.status in (429, 502, 503, 504),
                )
            content = response.read(MAX_BODY + 1)
            if len(content) > MAX_BODY:
                raise IntegrationFailure("teamviewer_response_too_large")
            result = _json(content)
            if not isinstance(result, dict):
                raise ValueError
            return result
        except IntegrationFailure:
            raise
        except ssl.SSLError:
            raise IntegrationFailure("tls_verification_failed") from None
        except (OSError, http.client.HTTPException):
            raise IntegrationFailure("teamviewer_unavailable", retryable=True) from None
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise IntegrationFailure("teamviewer_invalid_response") from None
        finally:
            if connection is not None:
                connection.close()

    def fetch_completed(self, since, until, *, max_pages=5, max_records=5000):
        if (
            not isinstance(since, datetime)
            or not isinstance(until, datetime)
            or since.utcoffset() is None
            or until.utcoffset() is None
            or since.microsecond
            or until.microsecond
            or not since < until <= datetime.now(UTC)
            or type(max_pages) is not int
            or not 1 <= max_pages <= 50
            or type(max_records) is not int
            or not 1 <= max_records <= 50000
        ):
            raise IntegrationFailure("teamviewer_invalid_window_or_limit")
        found, seen, offset, cursors = {}, None, None, set()
        for page in range(1, max_pages + 1):
            try:
                body = self.request_page(until=until, offset=offset)
                records = body.get("records")
                remaining = body.get("records_remaining")
                if (
                    not isinstance(records, list)
                    or len(records) > 1000
                    or (remaining is not None and (type(remaining) is not int or remaining < 0))
                ):
                    raise IntegrationFailure("teamviewer_invalid_page")
                parsed = tuple(ConnectionReport.parse(item) for item in records)
                previous = seen
                checked = dict(found)
                for record in parsed:
                    if record.ended_at >= until or (previous and record.ended_at > previous):
                        raise IntegrationFailure("teamviewer_inconsistent_order_or_window")
                    previous = record.ended_at
                    if record.id in checked and checked[record.id] != record:
                        raise IntegrationFailure("teamviewer_conflicting_report")
                    checked[record.id] = record
                cursor = body.get("next_offset")
                if cursor:
                    if not isinstance(cursor, str) or len(cursor) > 36:
                        raise ValueError
                    cursor = str(uuid.UUID(cursor))
                    if cursor in cursors or not parsed:
                        raise IntegrationFailure("teamviewer_repeated_or_empty_cursor")
                if remaining and not cursor:
                    raise IntegrationFailure("teamviewer_missing_cursor")
                if cursor and remaining == 0:
                    raise IntegrationFailure("teamviewer_inconsistent_pagination")
                for record in parsed:
                    if record.ended_at >= since:
                        if record.id not in found and len(found) >= max_records:
                            return ReportBatch(tuple(found.values()), page, False, "record_limit")
                        found[record.id] = record
                if parsed:
                    seen = parsed[-1].ended_at
                # End-time ordering proves older pages cannot contain this window.
                if not cursor or (seen is not None and seen < since):
                    return ReportBatch(tuple(found.values()), page, True, "pagination_finished")
                cursors.add(cursor)
                offset = cursor
            except IntegrationFailure as error:
                return ReportBatch(tuple(found.values()), page, False, error.code)
            except (ValueError, AttributeError, TypeError):
                return ReportBatch(tuple(found.values()), page, False, "teamviewer_invalid_page")
        return ReportBatch(tuple(found.values()), max_pages, False, "page_limit")
