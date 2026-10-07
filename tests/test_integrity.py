"""Read-only integrity patrol tests.

The same scenarios run against both repositories: the default memory backend
and, under the ``pg`` mark (EMLARCH_RUN_PG_TESTS=1), real PostgreSQL — the two
repositories must behave identically.
"""
import pytest

from conftest import SAMPLES


def _post(client, name, data=None, **params):
    if data is None:
        data = (SAMPLES / name).read_bytes()
    return client.post(
        "/ingest",
        files={"file": (name, data, "message/rfc822")},
        params=params,
    )


@pytest.fixture(params=["memory", "pg"])
def backend(request, client, pg_client):
    return client if request.param == "memory" else pg_client


def test_patrol_clean_archive_all_items_pass(backend):
    c, arch = backend
    ing = _post(c, "01_multibyte.eml").json()
    _post(c, "08_traversal.eml")

    run = c.post("/integrity/patrol", json={}).json()
    assert run["status"] == "completed"
    assert run["scope"] == "all"
    assert run["scope_ingest_ids"] == []
    assert run["ingest_count"] == 2
    # 2 raw EMLs + 2 (gif+pdf) + 1 (traversal payload) attachments = 5 items
    assert run["item_count"] == 5
    assert run["passed_count"] == 5
    assert run["failed_count"] == 0
    assert run["skipped_count"] == 0
    assert run["started_at"] and run["finished_at"]
    types = {i["target_type"] for i in run["items"]}
    assert types == {"raw", "attachment"}
    # every checked item persisted expected + actual facts
    for item in run["items"]:
        assert item["status"] == "passed"
        assert item["actual_size"] == item["expected_size"]
        assert item["actual_sha256"] == item["expected_sha256"]
        assert item["checked_at"]

    # raw item references the ingest; attachment items reference the message
    raw = next(i for i in run["items"] if i["target_type"] == "raw")
    assert raw["ingest_id"] == ing["ingest_id"]
    att = next(
        i
        for i in run["items"]
        if i["target_type"] == "attachment" and i["mime_path"] == "3"
    )
    assert att["message_pk"] == ing["message_pk"]
    assert att["attachment_id"]
    assert att["message_id"] == "multi-01@example.com"
    assert att["subject"]


def test_patrol_locates_removed_attachment_but_keeps_metadata(backend):
    c, arch = backend
    ing = _post(c, "01_multibyte.eml").json()
    pk = ing["message_pk"]
    meta = c.get(f"/messages/{pk}").json()
    victim = next(a for a in meta["attachments"] if a["content_type"] == "application/pdf")

    # Archivist discovers the bytes have vanished from controlled storage.
    path = arch.attachment_storage.resolve(victim["storage_path"])
    path.unlink()
    assert not arch.attachment_storage.exists(victim["storage_path"])

    run = c.post("/integrity/patrol", json={}).json()
    assert run["failed_count"] == 1
    assert run["passed_count"] == run["item_count"] - 1

    # failure detail query locates mail + MIME path
    failures = c.get(f"/integrity/runs/{run['id']}/failures").json()
    assert len(failures) == 1
    fail = failures[0]
    assert fail["status"] == "failed"
    assert fail["error_code"] == "missing"
    assert fail["message_pk"] == pk
    assert fail["message_id"] == "multi-01@example.com"
    assert fail["mime_path"] == victim["mime_path"] == "3"
    assert fail["attachment_id"] == victim["id"]
    assert fail["ingest_id"] == ing["ingest_id"]
    assert fail["subject"]
    assert fail["storage_path"] == victim["storage_path"]

    # filter by status also works
    failed_items = c.get(
        f"/integrity/runs/{run['id']}/items", params={"status": "failed"}
    ).json()
    assert [i["id"] for i in failed_items] == [fail["id"]]
    passed_items = c.get(
        f"/integrity/runs/{run['id']}/items", params={"status": "passed"}
    ).json()
    assert len(passed_items) == run["passed_count"]

    # original message metadata remains fully queryable (facts do not depend
    # on the bytes being on disk)
    detail = c.get(f"/messages/{pk}").json()
    assert detail["message_id"] == "multi-01@example.com"
    assert detail["raw_sha256"] == ing["raw_sha256"]
    assert any(a["id"] == victim["id"] for a in detail["attachments"])
    assert c.get(f"/ingests/{ing['ingest_id']}").status_code == 200

    # downloading the damaged attachment still fails explicitly (no auto fix)
    dl = c.get(f"/messages/{pk}/attachments/{victim['id']}/download")
    assert dl.status_code == 410


def test_repeated_patrols_append_separate_runs(backend):
    c, _ = backend
    _post(c, "01_multibyte.eml")

    first = c.post("/integrity/patrol", json={}).json()
    second = c.post("/integrity/patrol", json={}).json()
    assert first["id"] != second["id"]

    runs = c.get("/integrity/runs").json()
    ids = [r["id"] for r in runs]
    assert first["id"] in ids and second["id"] in ids
    # newest first
    assert ids[0] == second["id"]
    assert c.get(f"/integrity/runs/{first['id']}").json()["item_count"] == 3
    assert c.get(f"/integrity/runs/{second['id']}").json()["item_count"] == 3

    # failure lists are per-run; the first run is an immutable historical record
    assert c.get(f"/integrity/runs/{first['id']}/failures").json() == []
    assert c.get("/integrity/runs/9999").status_code == 404
    assert c.get("/integrity/runs/9999/failures").status_code == 404


def test_patrol_is_read_only_and_fault_isolating(backend):
    c, arch = backend
    _post(c, "01_multibyte.eml")
    _post(c, "08_traversal.eml")

    # corrupt one attachment's bytes (size + hash change) and remove another
    msgs = c.get("/messages").json()
    att_rows = []
    for m in msgs:
        d = c.get(f"/messages/{m['id']}").json()
        att_rows.extend(d["attachments"])
    target = arch.attachment_storage.resolve(att_rows[0]["storage_path"])
    before = target.read_bytes()
    target.write_bytes(b"X" * (len(before) + 7))
    arch.attachment_storage.resolve(att_rows[1]["storage_path"]).unlink()

    run = c.post("/integrity/patrol", json={}).json()
    # the batch completed despite two damaged files...
    assert run["status"] == "completed"
    assert run["failed_count"] == 2
    codes = {
        i["error_code"]
        for i in c.get(f"/integrity/runs/{run['id']}/failures").json()
    }
    assert codes == {"size_mismatch", "missing"}
    # ...raw EMLs and the third attachment were still checked
    assert run["passed_count"] == run["item_count"] - 2

    # the corrupted file is left exactly as-is (no overwrite/repair/delete)
    assert target.read_bytes() == b"X" * (len(before) + 7)

    # size_mismatch failure records actual facts
    size_fail = next(
        i
        for i in c.get(f"/integrity/runs/{run['id']}/failures").json()
        if i["error_code"] == "size_mismatch"
    )
    assert size_fail["actual_size"] == len(before) + 7
    assert size_fail["actual_sha256"] != size_fail["expected_sha256"]


def test_patrol_scoped_to_ingest_batch(backend):
    c, arch = backend
    first = _post(c, "01_multibyte.eml").json()
    second = _post(c, "08_traversal.eml").json()

    # remove the second batch's attachment — patrolling only the first is green
    second_pk = second["message_pk"]
    att = c.get(f"/messages/{second_pk}").json()["attachments"][0]
    arch.attachment_storage.resolve(att["storage_path"]).unlink()

    run = c.post(
        "/integrity/patrol", json={"ingest_ids": [first["ingest_id"]]}
    ).json()
    assert run["scope"] == "ingests"
    assert run["scope_ingest_ids"] == [first["ingest_id"]]
    assert run["ingest_count"] == 1
    assert run["failed_count"] == 0

    # unknown ingest ids are rejected explicitly
    bad = c.post("/integrity/patrol", json={"ingest_ids": [9999]})
    assert bad.status_code == 400
    # nothing was recorded for the rejected request
    assert len(c.get("/integrity/runs").json()) == 1


def test_patrol_empty_archive_records_run(backend):
    c, _ = backend
    run = c.post("/integrity/patrol", json={}).json()
    assert run["status"] == "completed"
    assert run["item_count"] == 0
    assert run["ingest_count"] == 0
