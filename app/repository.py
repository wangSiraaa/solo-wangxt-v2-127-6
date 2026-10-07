"""Repository interfaces used by the service layer.

Two implementations exist: :mod:`app.pg_repository` (PostgreSQL) and
:mod:`app.memory_repository` (tests / ephemeral runs). The API only depends on
this interface, so business logic is testable without a database.
"""
from __future__ import annotations

from typing import Any, Protocol, Sequence

from app.parser.models import ParsedMessage


class Repository(Protocol):
    def init_schema(self) -> None: ...

    def save_ingest(
        self,
        parsed: ParsedMessage,
        *,
        raw_relpath: str | None,
        stored_attachments: Sequence[tuple[Any, str]],
        source_name: str | None,
        status: str,
        fatal_error: str | None,
    ) -> dict[str, Any]:
        """Persist one EML (headers, parts, attachments metadata, defects).

        Returns ``{"ingest_id": int, "message_id": int | None}``. Failed parses
        get an ingest row with message_id=None.
        """
        ...

    def rebuild_threads(self) -> dict[str, Any]:
        """Recompute all thread assignments from stored headers."""
        ...

    def get_message(self, message_pk: int) -> dict[str, Any] | None: ...
    def get_ingest(self, ingest_id: int) -> dict[str, Any] | None: ...
    def list_messages(self, limit: int, offset: int) -> list[dict[str, Any]]: ...
    def search_messages(self, query: str, limit: int, offset: int) -> dict[str, Any]: ...
    def get_thread(self, thread_key: str) -> dict[str, Any] | None: ...
    def list_threads(self, limit: int, offset: int) -> list[dict[str, Any]]: ...
    def list_failures(self, limit: int, offset: int) -> list[dict[str, Any]]: ...
    def get_attachment(self, attachment_id: int) -> dict[str, Any] | None: ...
    def get_attachment_by_message(self, message_pk: int, attachment_id: int) -> dict[str, Any] | None: ...

    # -- integrity inspection (read-only over evidence) -----------------------
    def list_ingest_file_refs(self, ingest_ids: Sequence[int] | None = None) -> list[dict[str, Any]]:
        """Per-ingest file references needed for an integrity run:
        ``{ingest_id, status, raw_sha256, raw_size, raw_path, messages,
        attachments}`` where messages carry ``{id, raw_sha256}`` and
        attachments carry ``{id, message_pk, mime_path, byte_size,
        checksum_sha256, storage_path, stored}``. ``None`` means all ingests.
        """
        ...

    def save_inspection(self, run: dict[str, Any], items: Sequence[dict[str, Any]]) -> dict[str, Any]:
        """Persist one inspection run and its per-item results (append-only).

        Returns the run dict including its new ``id``.
        """
        ...

    def list_inspections(self, limit: int, offset: int) -> list[dict[str, Any]]: ...
    def get_inspection(self, run_id: int) -> dict[str, Any] | None: ...
    def list_inspection_failures(self, run_id: int | None, limit: int, offset: int) -> list[dict[str, Any]]: ...
