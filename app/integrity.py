"""Read-only integrity patrols over the controlled storage roots.

The archivist periodically needs evidence that the *bytes* still match the
facts recorded at ingest time. A patrol:

* walks every ingest batch (or an explicitly selected set of ingests),
* re-reads the stored raw EML and each stored attachment from the controlled
  directories,
* compares the on-disk byte size and SHA-256 with the recorded values,
* persists the run (time, scope, counters) and one item row per reference.

Hard guarantees:

* **Read-only.** The patrol only opens files for reading. It never repairs,
  overwrites, moves or deletes evidence; nothing is written into either
  storage root.
* **Fault isolation.** One missing/corrupt file produces one ``failed`` item;
  the rest of the batch is still re-read and the run completes.
* **Locatable failures.** Every item carries the ingest id, the message
  primary key, the RFC Message-ID, subject and the MIME path (``1.3.2`` …),
  so a failed attachment points straight at the mail and the part.
* **Repeatable.** Each invocation appends a new run; history is retained.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Sequence

from app.storage import ControlledStorage

log = logging.getLogger("emlarchive.integrity")


class UnknownIngestsError(ValueError):
    """Raised when a patrol explicitly scopes ingest ids that do not exist."""

    def __init__(self, missing: Sequence[int]) -> None:
        self.missing = list(missing)
        super().__init__(f"unknown ingest ids: {self.missing}")


class IntegrityService:
    def __init__(
        self,
        repo: Any,
        raw_storage: ControlledStorage,
        attachment_storage: ControlledStorage,
    ) -> None:
        self._repo = repo
        self._raw = raw_storage
        self._att = attachment_storage

    def run_patrol(self, ingest_ids: Sequence[int] | None = None) -> dict[str, Any]:
        """Re-read stored blobs and persist one integrity run with items.

        ``ingest_ids=None`` patrols the whole archive; otherwise only the
        listed ingest batches. Unknown ids raise :class:`UnknownIngestsError`.
        """
        scope = "all"
        ids: list[int] | None = None
        if ingest_ids is not None:
            ids = sorted({int(i) for i in ingest_ids})
            missing = [i for i in ids if self._repo.get_ingest(i) is None]
            if missing:
                raise UnknownIngestsError(missing)
            scope = "ingests"

        targets = self._repo.integrity_targets(ids)
        ingest_count = len({t["ingest_id"] for t in targets})
        run_id = self._repo.create_integrity_run(
            scope=scope, scope_ingest_ids=ids or [], ingest_count=ingest_count
        )

        items: list[dict[str, Any]] = []
        for target in targets:
            try:
                item = self._verify(run_id, target)
            except Exception as exc:  # defensive: never abort the whole batch
                log.error(
                    "integrity check crashed ingest=%s type=%s path=%r: %s",
                    target.get("ingest_id"),
                    target.get("target_type"),
                    target.get("storage_path"),
                    exc,
                )
                item = self._base_item(run_id, target)
                item.update(
                    status="failed",
                    error_code="unreadable",
                    error_detail=f"check raised {type(exc).__name__}: {exc}",
                )
            items.append(item)
            if item["status"] == "failed":
                # Metadata only — never file content.
                log.warning(
                    "integrity failure run=%d ingest=%s message_pk=%s mime=%s code=%s",
                    run_id,
                    item["ingest_id"],
                    item["message_pk"],
                    item["mime_path"],
                    item["error_code"],
                )

        passed = sum(1 for i in items if i["status"] == "passed")
        failed = sum(1 for i in items if i["status"] == "failed")
        skipped = sum(1 for i in items if i["status"] == "skipped")
        self._repo.add_integrity_items(run_id, items)
        self._repo.complete_integrity_run(
            run_id, item_count=len(items), passed=passed, failed=failed, skipped=skipped
        )
        return self._repo.get_integrity_run(run_id)

    # -- internals ---------------------------------------------------------
    def _verify(self, run_id: int, target: dict[str, Any]) -> dict[str, Any]:
        item = self._base_item(run_id, target)

        # Reference known to be dangling since ingest time (nothing was stored,
        # e.g. a storage write failure). Recorded as skipped, not failed: the
        # patrol cannot read bytes that never existed, but the reference row is
        # still surfaced and locatable.
        if not target.get("stored") or not target.get("storage_path"):
            item.update(status="skipped", error_code="not_stored")
            return item

        storage = self._att if target["target_type"] == "attachment" else self._raw
        result = storage.verify_file(
            target["storage_path"],
            int(target["expected_size"]),
            target["expected_sha256"],
        )
        if result.get("ok"):
            item.update(
                status="passed",
                actual_size=result["byte_size"],
                actual_sha256=result["sha256"],
            )
            return item

        detail = result["error"]
        if result["error"] == "size_mismatch":
            detail = (
                f"size mismatch: expected {result['expected_size']} bytes, "
                f"read {result['actual_size']} bytes"
            )
        elif result["error"] == "sha256_mismatch":
            detail = (
                f"sha256 mismatch: expected {result['expected_sha256']}, "
                f"read {result['actual_sha256']} ({result['actual_size']} bytes)"
            )
        elif result.get("detail"):
            detail = f"{result['error']}: {result['detail']}"
        item.update(
            status="failed",
            error_code=result["error"],
            error_detail=detail,
            actual_size=result.get("actual_size"),
            actual_sha256=result.get("actual_sha256"),
        )
        return item

    def _base_item(self, run_id: int, t: dict[str, Any]) -> dict[str, Any]:
        return {
            "run_id": run_id,
            "ingest_id": t["ingest_id"],
            "message_pk": t.get("message_pk"),
            "attachment_id": t.get("attachment_id"),
            "message_id": t.get("message_id"),
            "subject": t.get("subject"),
            "mime_path": t.get("mime_path"),
            "target_type": t["target_type"],
            "storage_path": t.get("storage_path"),
            "expected_sha256": t.get("expected_sha256"),
            "expected_size": t.get("expected_size"),
            "actual_sha256": None,
            "actual_size": None,
            "status": "passed",
            "error_code": None,
            "error_detail": None,
            "checked_at": datetime.now(timezone.utc),
        }
