"""Read-only integrity inspection (巡检) of the controlled storage.

An archivist can periodically re-verify that the raw EML bytes and attachment
bytes held in the controlled directories still match what was recorded at
ingest time (size, SHA-256) and that the reference relationships are intact
(ingest → raw file, message → ingest digest, attachment → message / stored
flag).

Guarantees:

* **Read-only**: evidence files are only opened for reading and persistence
  writes go to dedicated inspection tables. An inspection never modifies,
  overwrites or deletes evidence rows or files.
* **Fault isolation**: one missing/corrupt/unreadable file yields exactly one
  failed item; the rest of the batch is still inspected to completion.
* **Locatable**: every item carries the ingest id, message pk and MIME path,
  so a failure points back to the exact mail and MIME part.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from app.repository import Repository
from app.storage import ControlledStorage, StorageError

log = logging.getLogger("emlarchive.integrity")

_CHUNK = 1024 * 1024


def _hash_file(path: Path) -> tuple[int, str]:
    """Stream a file's bytes into a SHA-256; returns (size, hexdigest)."""
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
            size += len(chunk)
    return size, h.hexdigest()


class IntegrityService:
    def __init__(
        self,
        repo: Repository,
        raw_storage: ControlledStorage,
        attachment_storage: ControlledStorage,
    ) -> None:
        self._repo = repo
        self._raw = raw_storage
        self._att = attachment_storage

    # -- item construction ---------------------------------------------------
    @staticmethod
    def _item(
        ingest_id: int | None,
        message_pk: int | None,
        item_kind: str,
        *,
        status: str,
        mime_path: str | None = None,
        storage_path: str | None = None,
        expected_size: int | None = None,
        actual_size: int | None = None,
        expected_sha256: str | None = None,
        actual_sha256: str | None = None,
        detail: str | None = None,
    ) -> dict[str, Any]:
        return {
            "ingest_id": ingest_id,
            "message_pk": message_pk,
            "item_kind": item_kind,
            "mime_path": mime_path,
            "storage_path": storage_path,
            "expected_size": expected_size,
            "actual_size": actual_size,
            "expected_sha256": expected_sha256,
            "actual_sha256": actual_sha256,
            "status": status,
            "detail": detail,
        }

    # -- individual checks (never raise) --------------------------------------
    def _check_file(
        self,
        *,
        storage: ControlledStorage,
        kind: str,
        ingest_id: int,
        message_pk: int | None,
        mime_path: str | None,
        relpath: str,
        expected_size: int,
        expected_sha256: str,
    ) -> dict[str, Any]:
        base = dict(
            ingest_id=ingest_id,
            message_pk=message_pk,
            item_kind=kind,
            mime_path=mime_path,
            storage_path=relpath,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
        )
        try:
            path = storage.resolve(relpath)
        except StorageError as exc:
            return self._item(**base, status="failed", detail=f"stored path rejected: {exc}")
        try:
            actual_size, actual_sha = _hash_file(path)
        except FileNotFoundError:
            return self._item(**base, status="failed", detail="file missing on disk")
        except OSError as exc:
            return self._item(**base, status="failed", detail=f"file unreadable: {exc}")
        problems: list[str] = []
        if actual_size != expected_size:
            problems.append(f"size mismatch (expected {expected_size}, found {actual_size})")
        if actual_sha != expected_sha256:
            problems.append("sha256 mismatch")
        return self._item(
            **base,
            actual_size=actual_size,
            actual_sha256=actual_sha,
            status="failed" if problems else "ok",
            detail="; ".join(problems) if problems else None,
        )

    def _check_attachment(
        self, ingest_id: int, msg_pks: set[int], att: dict[str, Any]
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        mpk = att["message_pk"]
        mime = att["mime_path"]
        if mpk not in msg_pks:
            items.append(
                self._item(
                    ingest_id,
                    mpk,
                    "reference",
                    mime_path=mime,
                    status="failed",
                    detail=f"attachment {att['id']} references message {mpk} outside ingest {ingest_id}",
                )
            )
            return items
        relpath = att["storage_path"]
        if not relpath:
            # Consistent only when ingest already recorded it as not stored.
            ok = not att["stored"]
            items.append(
                self._item(
                    ingest_id,
                    mpk,
                    "reference",
                    mime_path=mime,
                    status="ok" if ok else "failed",
                    detail=(
                        "attachment not stored at ingest time"
                        if ok
                        else "attachment marked stored but has no storage_path"
                    ),
                )
            )
            return items
        if not att["stored"]:
            items.append(
                self._item(
                    ingest_id,
                    mpk,
                    "reference",
                    mime_path=mime,
                    storage_path=relpath,
                    status="failed",
                    detail="storage_path present but stored flag is false",
                )
            )
        items.append(
            self._check_file(
                storage=self._att,
                kind="attachment",
                ingest_id=ingest_id,
                message_pk=mpk,
                mime_path=mime,
                relpath=relpath,
                expected_size=att["byte_size"],
                expected_sha256=att["checksum_sha256"],
            )
        )
        return items

    def _check_ingest(self, ref: dict[str, Any]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        ingest_id = ref["ingest_id"]

        # 1. raw EML bytes vs recorded digest/size
        raw_path = ref["raw_path"]
        if raw_path:
            items.append(
                self._check_file(
                    storage=self._raw,
                    kind="raw",
                    ingest_id=ingest_id,
                    message_pk=None,
                    mime_path=None,
                    relpath=raw_path,
                    expected_size=ref["raw_size"],
                    expected_sha256=ref["raw_sha256"],
                )
            )
        else:
            # Failed ingests legitimately have no stored raw file.
            ok = ref["status"] == "failed"
            items.append(
                self._item(
                    ingest_id,
                    None,
                    "reference",
                    status="ok" if ok else "failed",
                    detail=(
                        "raw eml intentionally not stored (ingest failed)"
                        if ok
                        else "raw_path missing although ingest parsed"
                    ),
                )
            )

        # 2. message rows must reference the same digest as their ingest
        msg_pks: set[int] = set()
        for m in ref["messages"]:
            msg_pks.add(m["id"])
            ok = m["raw_sha256"] == ref["raw_sha256"]
            items.append(
                self._item(
                    ingest_id,
                    m["id"],
                    "reference",
                    expected_sha256=ref["raw_sha256"],
                    actual_sha256=m["raw_sha256"],
                    status="ok" if ok else "failed",
                    detail=None if ok else "message raw digest does not match its ingest",
                )
            )

        # 3. every attachment: relationship flags + bytes on disk
        for att in ref["attachments"]:
            items.extend(self._check_attachment(ingest_id, msg_pks, att))
        return items

    # -- public API ------------------------------------------------------------
    def run_inspection(self, ingest_ids: Sequence[int] | None = None) -> dict[str, Any]:
        """Inspect one batch of ingests (default: all) and persist the run.

        Read-only with respect to evidence; one corrupt file never aborts the
        batch. Returns the persisted run summary (without items).
        """
        started = datetime.now(timezone.utc)
        refs = self._repo.list_ingest_file_refs(ingest_ids)
        items: list[dict[str, Any]] = []
        for ref in refs:
            try:
                items.extend(self._check_ingest(ref))
            except Exception as exc:  # a single bad record must not abort the batch
                log.exception("inspection of ingest %s failed unexpectedly", ref.get("ingest_id"))
                items.append(
                    self._item(
                        ref.get("ingest_id"),
                        None,
                        "reference",
                        status="failed",
                        detail=f"inspection error: {exc}",
                    )
                )
        finished = datetime.now(timezone.utc)
        failed = sum(1 for i in items if i["status"] == "failed")
        run = {
            "started_at": started,
            "finished_at": finished,
            "scope": {"all": True} if ingest_ids is None else {"ingest_ids": sorted(set(ingest_ids))},
            "ingests_checked": len(refs),
            "items_checked": len(items),
            "items_ok": len(items) - failed,
            "items_failed": failed,
            "status": "failed" if failed else "ok",
        }
        saved = self._repo.save_inspection(run, items)
        log.info(
            "integrity run id=%s ingests=%d items=%d failed=%d",
            saved["id"],
            run["ingests_checked"],
            run["items_checked"],
            failed,
        )
        for item in items:
            if item["status"] == "failed":
                # Metadata only — never file contents.
                log.warning(
                    "integrity failure run=%s kind=%s ingest=%s message=%s mime=%s path=%s: %s",
                    saved["id"],
                    item["item_kind"],
                    item["ingest_id"],
                    item["message_pk"],
                    item["mime_path"],
                    item["storage_path"],
                    item["detail"],
                )
        return saved
