import base64
import hashlib
import tempfile
import threading
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, PreservationStore

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


class DisposalHoldTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PreservationStore(Path(self.tmp.name) / "test.db")
        self.store.seed()

    def tearDown(self):
        self.tmp.cleanup()

    def _make_archive(self, name="到期处置档案", retention=None):
        retention = retention or (date.today() + timedelta(days=3650)).isoformat()
        archive = self.store.create_archive("owner", name, retention)
        version = self.store.ingest_version("owner", archive["id"], [
            {"path": "records/one.xml", "content_b64": base64.b64encode(b"<record><id>1</id></record>").decode()},
            {"path": "README.txt", "content_b64": base64.b64encode(b"archive readme").decode()},
        ])
        copy1 = self.store.add_copy("owner", version["id"], "offline-disk-a")["id"]
        copy2 = self.store.add_copy("owner", version["id"], "offline-disk-b")["id"]
        return archive, version, copy1, copy2

    def test_disposal_deletes_copies_and_marks_archive_disposed(self):
        archive, version, copy1, copy2 = self._make_archive()
        self.store.enter_disposal("owner", archive["id"])
        result = self.store.start_disposal("owner", archive["id"])
        self.assertTrue(result["started"])
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["archive_status"], "disposed")
        self.assertTrue(all(r["status"] == "deleted" for r in result["records"]))
        status = self.store.disposal_status("owner", archive["id"])
        self.assertEqual(status["archive"]["status"], "disposed")
        self.assertEqual(len(status["remaining_copies"]), 0)
        # 副本已删，但档案版本与文件清单仍可查
        detail = self.store.get_version("owner", version["id"])
        self.assertEqual(len(detail["files"]), 2)

    def test_archive_level_hold_blocks_disposal(self):
        archive, version, copy1, copy2 = self._make_archive()
        self.store.enter_disposal("owner", archive["id"])
        hold = self.store.apply_hold("owner", archive["id"], None, "诉讼保全需要")
        self.assertIsNone(hold["hold"]["version_id"])
        result = self.store.start_disposal("owner", archive["id"])
        self.assertFalse(result["started"])
        self.assertEqual(result["state"], "held")
        self.assertEqual(len(result["holds"]), 1)
        status = self.store.disposal_status("owner", archive["id"])
        self.assertEqual(status["archive"]["status"], "pending_disposal")
        self.assertEqual(len(status["remaining_copies"]), 2)

    def test_version_level_hold_blocks_disposal(self):
        archive, version, copy1, copy2 = self._make_archive()
        self.store.enter_disposal("owner", archive["id"])
        self.store.apply_hold("owner", archive["id"], version["id"], "版本保全")
        result = self.store.start_disposal("owner", archive["id"])
        self.assertFalse(result["started"])
        self.assertEqual(result["state"], "held")
        status = self.store.disposal_status("owner", archive["id"])
        self.assertEqual(len(status["remaining_copies"]), 2)

    def test_hold_applied_after_task_start_still_protects_remaining_copies(self):
        archive, version, copy1, copy2 = self._make_archive()
        self.store.enter_disposal("owner", archive["id"])
        # 模拟处置任务已启动（写入 running 状态）
        conn = self.store.connect()
        cur = conn.execute(
            "INSERT INTO disposal_tasks(archive_id,status,started_by,started_at,total_count) VALUES(?,?,?,?,?)",
            (archive["id"], "running", "owner", "2026-01-01T00:00:00+00:00", 2),
        )
        task_id = cur.lastrowid
        conn.execute("UPDATE archives SET status='disposing' WHERE id=?", (archive["id"],))
        conn.commit()
        conn.close()
        # 处置进行中另一个人提交保全
        self.store.apply_hold("owner", archive["id"], None, "事后保全")
        result = self.store._run_disposal(task_id, archive["id"])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["archive_status"], "pending_disposal")
        self.assertTrue(all(r["status"] == "held" for r in result["records"]))
        status = self.store.disposal_status("owner", archive["id"])
        self.assertEqual(len(status["remaining_copies"]), 2)

    def test_failed_copy_is_recorded_and_retry_only_processes_incomplete(self):
        archive, version, copy1, copy2 = self._make_archive()
        self.store.enter_disposal("owner", archive["id"])
        self.store.simulate_disposal_failure("owner", copy1, True)
        result = self.store.start_disposal("owner", archive["id"])
        self.assertEqual(result["state"], "failed")
        by_copy = {r["copy_id"]: r["status"] for r in result["records"]}
        self.assertEqual(by_copy[copy1], "failed")
        self.assertEqual(by_copy[copy2], "deleted")
        status = self.store.disposal_status("owner", archive["id"])
        self.assertEqual(status["archive"]["status"], "pending_disposal")
        self.assertEqual(len(status["remaining_copies"]), 1)
        # 排除故障后重试：只处理未完成副本
        self.store.simulate_disposal_failure("owner", copy1, False)
        retry = self.store.start_disposal("owner", archive["id"])
        self.assertEqual(retry["state"], "completed")
        self.assertTrue(all(r["status"] == "deleted" for r in retry["records"]))
        status = self.store.disposal_status("owner", archive["id"])
        self.assertEqual(status["archive"]["status"], "disposed")

    def test_concurrent_hold_and_disposal_first_writer_wins(self):
        archive, version, copy1, copy2 = self._make_archive()
        for i in range(20):
            self.store.add_copy("owner", version["id"], f"disk-extra-{i}")
        self.store.enter_disposal("owner", archive["id"])
        results = {}

        def do_dispose():
            results["dispose"] = self.store.start_disposal("owner", archive["id"])

        def do_hold():
            results["hold"] = self.store.apply_hold("owner", archive["id"], None, "并发保全")

        t1 = threading.Thread(target=do_dispose)
        t2 = threading.Thread(target=do_hold)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        dispose = results["dispose"]
        hold = results["hold"]
        # 先写入状态的一方生效：处置先写则任务继续，保全先写则处置按现状返回
        if dispose["started"]:
            self.assertEqual(hold["hold"]["status"], "active")
            status = self.store.disposal_status("owner", archive["id"])
            self.assertIn(status["archive"]["status"], ("disposed", "pending_disposal"))
        else:
            self.assertEqual(dispose["state"], "held")
            status = self.store.disposal_status("owner", archive["id"])
            self.assertEqual(status["archive"]["status"], "pending_disposal")
            self.assertEqual(len(status["remaining_copies"]), 22)

    def test_migrated_version_inherits_holds(self):
        archive, version, copy1, copy2 = self._make_archive()
        self.store.enter_disposal("owner", archive["id"])
        self.store.apply_hold("owner", archive["id"], None, "整份保全")
        migrated = self.store.migrate(
            "owner", version["id"], "records/one.xml", "records/one.html", "html",
            base64.b64encode(b"<html><body>1</body></html>").decode(),
        )
        detail = self.store.get_version("owner", migrated["id"])
        self.assertTrue(any("迁移继承" in h["reason"] for h in detail["holds"]))
        self.assertIsNotNone(detail["migrated_from"])
        self.assertEqual(detail["migrated_from"]["source_version_id"], version["id"])
        # 新版本同样受保全保护，不能被清退
        result = self.store.start_disposal("owner", archive["id"])
        self.assertFalse(result["started"])
        self.assertEqual(result["state"], "held")

    def test_hold_release_allows_disposal(self):
        archive, version, copy1, copy2 = self._make_archive()
        self.store.enter_disposal("owner", archive["id"])
        hold = self.store.apply_hold("owner", archive["id"], None, "临时保全")
        self.store.release_hold("owner", hold["hold"]["id"])
        result = self.store.start_disposal("owner", archive["id"])
        self.assertTrue(result["started"])
        self.assertEqual(result["state"], "completed")

    def test_audit_records_keep_ten_year_retention(self):
        archive, version, copy1, copy2 = self._make_archive()
        status = self.store.archive_status("owner", archive["id"])
        self.assertTrue(all(r.get("retain_until") for r in status["audit"]))

    def test_outsider_cannot_apply_hold_or_dispose(self):
        archive, version, copy1, copy2 = self._make_archive()
        self.store.enter_disposal("owner", archive["id"])
        with self.assertRaises(BusinessError) as ctx:
            self.store.apply_hold("outsider", archive["id"], None, "越权保全")
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.start_disposal("outsider", archive["id"])
        self.assertEqual(ctx.exception.status, 403)


if __name__ == "__main__":
    unittest.main()
