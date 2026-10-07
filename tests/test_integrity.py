"""Read-only integrity inspection (巡检) tests — memory backend.

Acceptance covered here:
* healthy samples all pass;
* a removed attachment is reported with its message and MIME path while the
  message metadata stays queryable and the download keeps failing clearly;
* repeated inspections persist separate runs;
* one corrupt file never aborts the batch and the inspection never writes to
  or deletes evidence.
"""
from conftest import SAMPLES


def _post(c, name, **params):
    return c.post(
        "/ingest",
        files={"file": (name, (SAMPLES / name).read_bytes(), "message/rfc822")},
        params=params,
    )


def _ingest_batch(c):
    out = {}
    for n in ["01_multibyte.eml", "03_missing_id.eml", "06_corrupt_boundary.eml", "09_html_xss.eml"]:
        r = _post(c, n)
        assert r.status_code == 201, r.text
        out[n] = r.json()
    return out


def test_healthy_archive_passes(client):
    c, _ = client
    ingested = _ingest_batch(c)
    r = c.post("/inspections")
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["status"] == "ok"
    assert run["items_failed"] == 0
    assert run["items_checked"] == run["items_ok"] > 0
    assert run["ingests_checked"] == len(ingested)
    assert run["scope"] == {"all": True}
    assert run["started_at"] and run["finished_at"]

    runs = c.get("/inspections").json()
    assert [r["id"] for r in runs] == [run["id"]]

    detail = c.get(f"/inspections/{run['id']}").json()
    assert len(detail["items"]) == run["items_checked"]
    assert all(i["status"] == "ok" for i in detail["items"])
    assert {i["item_kind"] for i in detail["items"]} == {"raw", "attachment", "reference"}
    # every ingest got its raw file re-hashed
    assert {i["ingest_id"] for i in detail["items"] if i["item_kind"] == "raw"} == {
        v["ingest_id"] for v in ingested.values()
    }
    assert c.get(f"/inspections/{run['id']}/failures").json() == []


def test_missing_attachment_located_and_message_survives(client):
    c, arch = client
    r = _post(c, "01_multibyte.eml").json()
    pk = r["message_pk"]
    msg = c.get(f"/messages/{pk}").json()
    victim = msg["attachments"][0]
    # archivist-level damage: the bytes vanish from controlled storage
    arch.attachment_storage.resolve(victim["storage_path"]).unlink()

    run = c.post("/inspections").json()
    assert run["status"] == "failed"
    assert run["items_failed"] == 1

    failures = c.get(f"/inspections/{run['id']}/failures").json()
    assert len(failures) == 1
    f = failures[0]
    # located: exact mail and MIME path
    assert f["item_kind"] == "attachment"
    assert f["ingest_id"] == r["ingest_id"]
    assert f["message_pk"] == pk
    assert f["mime_path"] == victim["mime_path"]
    assert f["storage_path"] == victim["storage_path"]
    assert "missing" in f["detail"]

    # the original message metadata is still queryable
    again = c.get(f"/messages/{pk}")
    assert again.status_code == 200
    assert again.json()["subject"] == msg["subject"]
    assert again.json()["attachments"][0]["checksum_sha256"] == victim["checksum_sha256"]

    # downloading the damaged attachment still fails clearly
    dl = c.get(f"/messages/{pk}/attachments/{victim['id']}/download")
    assert dl.status_code == 410


def test_repeated_inspections_leave_separate_records(client):
    c, _ = client
    _post(c, "01_multibyte.eml")
    r1 = c.post("/inspections").json()
    r2 = c.post("/inspections").json()
    assert r1["id"] != r2["id"]
    runs = c.get("/inspections").json()
    assert {r["id"] for r in runs} == {r1["id"], r2["id"]}
    # each run keeps its own item set
    d1 = c.get(f"/inspections/{r1['id']}").json()
    d2 = c.get(f"/inspections/{r2['id']}").json()
    assert d1["items"] and d2["items"]
    assert all(i["run_id"] == r1["id"] for i in d1["items"])
    assert all(i["run_id"] == r2["id"] for i in d2["items"])


def test_corrupted_raw_eml_detected(client):
    c, arch = client
    r = _post(c, "09_html_xss.eml").json()
    ing = c.get(f"/ingests/{r['ingest_id']}").json()
    raw_file = arch.raw_storage.resolve(ing["raw_path"])
    raw_file.write_bytes(raw_file.read_bytes() + b"tampered")  # simulate bit rot

    run = c.post("/inspections").json()
    assert run["status"] == "failed"
    failures = c.get(f"/inspections/{run['id']}/failures").json()
    raw_items = [f for f in failures if f["item_kind"] == "raw"]
    assert len(raw_items) == 1
    assert raw_items[0]["ingest_id"] == r["ingest_id"]
    assert raw_items[0]["expected_sha256"] == r["raw_sha256"]
    assert raw_items[0]["actual_sha256"] != r["raw_sha256"]
    assert "sha256 mismatch" in raw_items[0]["detail"]
    assert "size mismatch" in raw_items[0]["detail"]


def test_one_corrupt_file_does_not_abort_batch(client):
    c, arch = client
    ingested = _ingest_batch(c)
    pk = ingested["01_multibyte.eml"]["message_pk"]
    att = c.get(f"/messages/{pk}").json()["attachments"][0]
    arch.attachment_storage.resolve(att["storage_path"]).unlink()

    run = c.post("/inspections").json()
    assert run["status"] == "failed"
    # the whole batch was still inspected
    assert run["ingests_checked"] == len(ingested)
    detail = c.get(f"/inspections/{run['id']}").json()
    raw_ingests = {i["ingest_id"] for i in detail["items"] if i["item_kind"] == "raw"}
    assert raw_ingests == {v["ingest_id"] for v in ingested.values()}
    # everything except the one removed attachment verified fine
    assert run["items_failed"] == 1
    assert run["items_ok"] == run["items_checked"] - 1


def test_inspection_is_read_only(client):
    c, arch = client
    _post(c, "01_multibyte.eml")
    _post(c, "07_bad_cte.eml")
    before_msgs = [c.get(f"/messages/{m['id']}").json() for m in c.get("/messages").json()]
    before_files = {}
    for root in (arch.raw_storage.root, arch.attachment_storage.root):
        for p in sorted(root.rglob("*")):
            if p.is_file():
                before_files[p] = p.read_bytes()

    c.post("/inspections")

    after_msgs = [c.get(f"/messages/{m['id']}").json() for m in c.get("/messages").json()]
    assert before_msgs == after_msgs  # evidence rows untouched
    for p, data in before_files.items():
        assert p.read_bytes() == data  # evidence bytes untouched
    for root in (arch.raw_storage.root, arch.attachment_storage.root):
        assert {p for p in root.rglob("*") if p.is_file()} <= set(before_files)


def test_scope_limited_to_selected_ingests(client):
    c, _ = client
    a = _post(c, "01_multibyte.eml").json()
    _post(c, "09_html_xss.eml")
    run = c.post("/inspections", params={"ingest_ids": [a["ingest_id"]]}).json()
    assert run["ingests_checked"] == 1
    assert run["scope"] == {"ingest_ids": [a["ingest_id"]]}
    detail = c.get(f"/inspections/{run['id']}").json()
    assert {i["ingest_id"] for i in detail["items"]} == {a["ingest_id"]}
    # the recorded scope survives re-reading
    assert c.get(f"/inspections/{run['id']}").json()["scope"] == {"ingest_ids": [a["ingest_id"]]}


def test_failed_ingest_without_raw_file_is_not_a_false_positive(client):
    c, _ = client
    r = c.post("/ingest", files={"file": ("bad.eml", b"\x00\xff\xfe" * 40, "message/rfc822")})
    assert r.status_code == 201
    run = c.post("/inspections").json()
    # failed ingests legitimately have no raw file; that is not corruption
    assert run["status"] == "ok"
    assert run["items_failed"] == 0


def test_unknown_inspection_run_is_404(client):
    c, _ = client
    assert c.get("/inspections/999").status_code == 404
    assert c.get("/inspections/999/failures").status_code == 404
