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

    # -- integrity patrol --------------------------------------------------
    def integrity_targets(
        self, ingest_ids: Sequence[int] | None
    ) -> list[dict[str, Any]]:
        """Return every stored raw/attachment reference to be re-read.

        With ``ingest_ids=None`` the scope is the whole archive; otherwise only
        ingests whose id is in the list. Each row describes one stored blob:
        raw ingests (even failed ones) and every attachment marked ``stored``.
        """
        ...

    def create_integrity_run(
        self, *, scope: str, scope_ingest_ids: Sequence[int], ingest_count: int
    ) -> int:
        """Open a patrol run (status ``running``); returns its id."""
        ...

    def add_integrity_items(self, run_id: int, items: Sequence[dict[str, Any]]) -> None:
        """Append per-item results to a run."""
        ...

    def complete_integrity_run(
        self, run_id: int, *, item_count: int, passed: int, failed: int, skipped: int
    ) -> None: ...

    def get_integrity_run(self, run_id: int) -> dict[str, Any] | None: ...

    def list_integrity_runs(self, limit: int, offset: int) -> list[dict[str, Any]]: ...

    def list_integrity_items(
        self, run_id: int, *, status: str | None = None, limit: int = 500, offset: int = 0
    ) -> list[dict[str, Any]]: ...
