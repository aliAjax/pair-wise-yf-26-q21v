import base64
import hashlib
import sqlite3
import tempfile
import threading
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from app import AUDIT_RETENTION_YEARS, BusinessError, PreservationStore


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PreservationStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.archive = self.store.create_archive("owner", "城市测绘档案", (date.today() + timedelta(days=3650)).isoformat())
        self.raw = b"<record><id>1</id></record>"
        self.version = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "records/one.xml", "content_b64": base64.b64encode(self.raw).decode()},
            {"path": "README.txt", "content_b64": base64.b64encode(b"archive readme").decode()},
        ])
        self.copy1 = self.store.add_copy("owner", self.version["id"], "offline-disk-a")["id"]
        self.copy2 = self.store.add_copy("owner", self.version["id"], "offline-disk-b")["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_integrity_repair_and_format_migration(self):
        self.store.simulate_corruption("owner", self.copy1, "records/one.xml")
        result = self.store.verify_copy("owner", self.copy1)
        self.assertEqual(result["state"], "healthy")
        self.assertTrue(result["repaired"])
        self.assertEqual(result["corrupt_paths"], ["records/one.xml"])
        migrated = self.store.migrate(
            "owner", self.version["id"], "records/one.xml", "records/one.html", "html",
            base64.b64encode(b"<html><body><p>1</p></body></html>").decode(),
        )
        detail = self.store.get_version("owner", migrated["id"])
        self.assertEqual(detail["version"]["version"], 2)
        self.assertTrue(any(f["path"] == "records/one.html" for f in detail["files"]))
        status = self.store.archive_status("owner", self.archive["id"])
        self.assertGreater(status["days_remaining"], 3000)

    def test_restricted_access_and_invalid_manifest_are_rejected(self):
        with self.assertRaises(BusinessError) as ctx:
            self.store.get_version("outsider", self.version["id"])
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.ingest_version("owner", self.archive["id"], [{"path": "../escape.txt", "content_b64": "eA=="}])
        self.assertEqual(ctx.exception.code, "unsafe_path")
        with self.assertRaises(BusinessError) as ctx:
            self.store.add_copy("owner", self.version["id"], "offline-disk-a")
        self.assertEqual(ctx.exception.code, "copy_exists")

    def _expire_archive(self):
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE archives SET retention_until=? WHERE id=?",
                ((date.today() - timedelta(days=1)).isoformat(), self.archive["id"]),
            )

    def test_expired_disposal_partial_failure_and_retry(self):
        with self.assertRaises(BusinessError) as ctx:
            self.store.enter_pending_disposal("owner", self.archive["id"])
        self.assertEqual(ctx.exception.code, "not_expired")

        self._expire_archive()
        self.store.grant("owner", self.archive["id"], "archivist", "write")
        self.store.grant("owner", self.archive["id"], "auditor", "read")
        entered = self.store.enter_pending_disposal("owner", self.archive["id"])
        self.assertEqual(entered["disposal_state"], "pending_disposal")
        again = self.store.enter_pending_disposal("archivist", self.archive["id"])
        self.assertFalse(again["changed"])

        hold = self.store.create_hold("archivist", self.archive["id"], None, "涉诉证据保全")
        with self.assertRaises(BusinessError) as ctx:
            self.store.start_disposal("owner", self.archive["id"])
        self.assertEqual(ctx.exception.code, "hold_active")
        released = self.store.release_hold("owner", hold["id"])
        self.assertEqual(released["status"], "released")
        self.assertFalse(self.store.release_hold("owner", hold["id"])["changed"])

        started = self.store.start_disposal("owner", self.archive["id"], {"offline-disk-b"})
        self.assertEqual(started["status"], "partial_failed")
        self.assertEqual(started["archive_state"], "pending_disposal")
        self.assertEqual(started["purged"], 1)
        self.assertEqual(started["failures"][0]["location"], "offline-disk-b")

        status = self.store.disposal_status("auditor", self.archive["id"])
        self.assertEqual(status["disposal_state"], "pending_disposal")
        self.assertEqual(status["audit_retention_years"], 10)
        results = {c["location"]: c for c in status["tasks"][0]["copies"]}
        self.assertEqual(results["offline-disk-a"]["status"], "purged")
        self.assertEqual(results["offline-disk-b"]["status"], "failed")
        self.assertTrue(results["offline-disk-b"]["error"])
        remaining = self.store.get_version("owner", self.version["id"])["copies"]
        self.assertEqual([c["location"] for c in remaining], ["offline-disk-b"])

        task_id = started["task_id"]
        still_failing = self.store.retry_disposal("owner", task_id, {"offline-disk-b"})
        self.assertEqual(still_failing["status"], "partial_failed")
        self.assertEqual(still_failing["purged"], 0)
        self.assertEqual(still_failing["failed"], 1)

        done = self.store.retry_disposal("owner", task_id)
        self.assertEqual(done["status"], "completed")
        self.assertEqual(done["archive_state"], "disposed")
        self.assertEqual(done["purged"], 1)
        self.assertEqual(self.store.get_version("owner", self.version["id"])["copies"], [])
        self.assertFalse(self.store.retry_disposal("owner", task_id)["changed"])

        with self.assertRaises(BusinessError) as ctx:
            self.store.create_hold("owner", self.archive["id"], None, "处置后再申请")
        self.assertEqual(ctx.exception.code, "disposal_already_started")
        with self.assertRaises(BusinessError) as ctx:
            self.store.add_copy("owner", self.version["id"], "offline-disk-c")
        self.assertEqual(ctx.exception.code, "archive_in_disposal")

    def test_disposal_and_hold_first_writer_wins(self):
        self._expire_archive()
        self.store.grant("owner", self.archive["id"], "archivist", "write")
        self.store.grant("owner", self.archive["id"], "auditor", "read")
        self.store.enter_pending_disposal("owner", self.archive["id"])
        barrier = threading.Barrier(2)
        outcome = {}

        def start():
            barrier.wait()
            try:
                outcome["disposal"] = self.store.start_disposal("owner", self.archive["id"])
            except BusinessError as exc:
                outcome["disposal"] = exc

        def hold():
            barrier.wait()
            try:
                outcome["hold"] = self.store.create_hold("archivist", self.archive["id"], None, "诉讼保全")
            except BusinessError as exc:
                outcome["hold"] = exc

        threads = [threading.Thread(target=start), threading.Thread(target=hold)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        disposal, hold = outcome["disposal"], outcome["hold"]
        # 先写入状态的一方生效，后到请求按现状 409 返回，二者必居其一
        self.assertTrue(isinstance(disposal, dict) != isinstance(hold, dict))
        loser = disposal if isinstance(hold, dict) else hold
        self.assertEqual(loser.status, 409)
        status = self.store.disposal_status("auditor", self.archive["id"])
        active_holds = [h for h in status["holds"] if h["status"] == "active"]
        if isinstance(hold, dict):
            self.assertEqual(len(active_holds), 1)
            self.assertNotEqual(status["disposal_state"], "disposed")
            self.assertEqual(len(self.store.get_version("owner", self.version["id"])["copies"]), 2)
        else:
            self.assertEqual(active_holds, [])
            self.assertEqual(status["disposal_state"], "disposed")

    def test_migration_inherits_retention_holds_and_lineage(self):
        self.store.grant("owner", self.archive["id"], "auditor", "read")
        hold = self.store.create_hold("owner", self.archive["id"], self.version["id"], "版本级保全")
        migrated = self.store.migrate(
            "owner", self.version["id"], "records/one.xml", "records/one.html", "html",
            base64.b64encode(b"<html><body><p>1</p></body></html>").decode(),
        )
        self.assertEqual(migrated["retention_until"], self.archive["retention_until"])
        self.assertEqual(migrated["inherited_holds"], 1)

        detail = self.store.get_version("owner", migrated["id"])
        self.assertEqual(detail["version"]["effective_retention_until"], self.archive["retention_until"])
        self.assertEqual([h["version_id"] for h in detail["active_holds"]], [migrated["id"]])
        self.assertEqual(detail["active_holds"][0]["reason"], "版本级保全")

        lineage = self.store.version_lineage("auditor", migrated["id"])["lineage"]
        self.assertEqual(len(lineage), 1)
        self.assertEqual(lineage[0]["source_version_id"], self.version["id"])
        self.assertEqual(lineage[0]["source_path"], "records/one.xml")
        self.assertEqual(lineage[0]["target_path"], "records/one.html")
        self.assertEqual(self.store.version_lineage("auditor", self.version["id"])["lineage"], [])

        # 旧数据没有版本级保留期（NULL）时回退档案级保留期，仍可查可校验
        with self.store.connect() as conn:
            conn.execute("UPDATE archive_versions SET retention_until=NULL WHERE id=?", (migrated["id"],))
        detail = self.store.get_version("owner", migrated["id"])
        self.assertEqual(detail["version"]["effective_retention_until"], self.archive["retention_until"])
        copy_id = self.store.add_copy("owner", migrated["id"], "offline-disk-c")["id"]
        self.assertEqual(self.store.verify_copy("owner", copy_id)["state"], "healthy")

    def test_audit_retention_ten_years(self):
        old_ts = (datetime.now(timezone.utc) - timedelta(days=365 * (AUDIT_RETENTION_YEARS + 1))).isoformat(timespec="seconds")
        with self.store.connect() as conn:
            conn.execute(
                "INSERT INTO audit_log(archive_id,actor_id,action,detail,created_at) VALUES(?,?,?,?,?)",
                (self.archive["id"], "owner", "legacy.old", "{}", old_ts),
            )
        before = len(self.store.archive_status("owner", self.archive["id"])["audit"])
        result = self.store.prune_audit()
        self.assertEqual(result["deleted"], 1)
        after = self.store.archive_status("owner", self.archive["id"])["audit"]
        self.assertEqual(len(after), before - 1)
        self.assertTrue(all(a["action"] != "legacy.old" for a in after))


LEGACY_SCHEMA = """
CREATE TABLE users(
    id TEXT PRIMARY KEY, name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner','archivist','auditor'))
);
CREATE TABLE archives(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    owner_id TEXT NOT NULL REFERENCES users(id),
    retention_until TEXT NOT NULL,
    restricted INTEGER NOT NULL DEFAULT 1 CHECK(restricted IN (0,1)),
    created_at TEXT NOT NULL
);
CREATE TABLE archive_members(
    archive_id INTEGER NOT NULL REFERENCES archives(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    permission TEXT NOT NULL CHECK(permission IN ('read','write')),
    PRIMARY KEY(archive_id,user_id)
);
CREATE TABLE archive_versions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    archive_id INTEGER NOT NULL REFERENCES archives(id),
    version INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'verified' CHECK(state IN ('verified','degraded')),
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    UNIQUE(archive_id,version)
);
CREATE TABLE archive_files(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    content BLOB NOT NULL,
    UNIQUE(version_id,path)
);
CREATE TABLE copies(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
    location TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'healthy' CHECK(state IN ('healthy','corrupt','degraded')),
    created_at TEXT NOT NULL,
    last_verified_at TEXT,
    UNIQUE(version_id,location)
);
CREATE TABLE copy_files(
    copy_id INTEGER NOT NULL REFERENCES copies(id),
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    content BLOB NOT NULL,
    PRIMARY KEY(copy_id,path)
);
CREATE TABLE migrations(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_version_id INTEGER NOT NULL REFERENCES archive_versions(id),
    target_version_id INTEGER NOT NULL UNIQUE REFERENCES archive_versions(id),
    source_path TEXT NOT NULL,
    target_path TEXT NOT NULL,
    target_format TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);
CREATE TABLE audit_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    archive_id INTEGER NOT NULL REFERENCES archives(id),
    actor_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class LegacyUpgradeTests(unittest.TestCase):
    """旧版本库在线升级：只加列建表、不回填，旧数据可查、可校验、可处置。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "legacy.db"
        raw = b"<record><id>7</id></record>"
        digest = hashlib.sha256(raw).hexdigest()
        conn = sqlite3.connect(self.db)
        conn.executescript(LEGACY_SCHEMA)
        conn.execute("INSERT INTO users(id,name,role) VALUES('owner','负责人','owner')")
        conn.execute(
            "INSERT INTO archives(name,owner_id,retention_until,restricted,created_at) VALUES(?,?,?,?,?)",
            ("旧档案", "owner", (date.today() - timedelta(days=1)).isoformat(), 1, "2020-01-01T00:00:00+00:00"),
        )
        conn.execute("INSERT INTO archive_members(archive_id,user_id,permission) VALUES(1,'owner','write')")
        conn.execute(
            "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(1,1,'owner','2020-01-01T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(1,'records/old.xml',?,?,?)",
            (digest, len(raw), raw),
        )
        conn.execute("INSERT INTO copies(version_id,location,created_at) VALUES(1,'legacy-tape','2020-01-01T00:00:00+00:00')")
        conn.execute(
            "INSERT INTO copy_files(copy_id,path,sha256,size,content) VALUES(1,'records/old.xml',?,?,?)",
            (digest, len(raw), raw),
        )
        conn.commit()
        conn.close()
        self.store = PreservationStore(self.db)
        self.store.init_schema()  # 在线升级，不要求停机回填

    def tearDown(self):
        self.tmp.cleanup()

    def test_legacy_rows_queryable_verifiable_and_disposable(self):
        detail = self.store.get_version("owner", 1)
        self.assertEqual(detail["archive"]["disposal_state"], "active")
        self.assertEqual(detail["version"]["retention_until"], None)
        self.assertEqual(
            detail["version"]["effective_retention_until"],
            (date.today() - timedelta(days=1)).isoformat(),
        )
        self.assertEqual(detail["files"][0]["path"], "records/old.xml")
        self.assertEqual(self.store.verify_copy("owner", 1)["state"], "healthy")
        self.assertEqual(self.store.version_lineage("owner", 1)["lineage"], [])

        entered = self.store.enter_pending_disposal("owner", 1)
        self.assertEqual(entered["disposal_state"], "pending_disposal")
        done = self.store.start_disposal("owner", 1)
        self.assertEqual(done["status"], "completed")
        status = self.store.disposal_status("owner", 1)
        self.assertEqual(status["disposal_state"], "disposed")
        self.assertEqual(status["tasks"][0]["copies"][0]["location"], "legacy-tape")
        self.assertEqual(status["tasks"][0]["copies"][0]["status"], "purged")


if __name__ == "__main__":
    unittest.main()
