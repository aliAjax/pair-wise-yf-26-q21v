"""数字档案长期保存服务：SQLite 多副本、哈希校验、修复与迁移。"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sqlite3
import threading
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "preservation.db"
MAX_FILE_SIZE = 10 * 1024 * 1024


class BusinessError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "bad_request"):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def verify_manifest(files: object) -> list[dict]:
    if not isinstance(files, list) or not files:
        raise BusinessError("files 必须是非空数组", 422, "invalid_manifest")
    result, seen = [], set()
    for item in files:
        if not isinstance(item, dict):
            raise BusinessError("文件条目必须是对象", 422, "invalid_manifest")
        raw_path = str(item.get("path", "")).strip().replace("\\", "/")
        pure = PurePosixPath(raw_path)
        if not raw_path or pure.is_absolute() or ".." in pure.parts or pure.name in {"", ".", ".."}:
            raise BusinessError(f"档案路径不安全: {raw_path}", 422, "unsafe_path")
        if raw_path in seen:
            raise BusinessError(f"档案路径重复: {raw_path}", 409, "duplicate_path")
        seen.add(raw_path)
        encoded = item.get("content_b64")
        if not isinstance(encoded, str):
            raise BusinessError(f"{raw_path} 缺少 content_b64", 422, "content_required")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise BusinessError(f"{raw_path} 不是合法 Base64", 422, "invalid_base64")
        if len(content) > MAX_FILE_SIZE:
            raise BusinessError(f"{raw_path} 超过单文件大小限制", 413, "file_too_large")
        result.append(
            {"path": raw_path, "content": content, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        )
    return result


class PreservationStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = str(db_path)
        self._lock = threading.Lock()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def init_schema(self) -> None:
        with self._lock, self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('owner','archivist','auditor'))
                );
                CREATE TABLE IF NOT EXISTS archives(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    owner_id TEXT NOT NULL REFERENCES users(id),
                    retention_until TEXT NOT NULL,
                    restricted INTEGER NOT NULL DEFAULT 1 CHECK(restricted IN (0,1)),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS archive_members(
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    user_id TEXT NOT NULL REFERENCES users(id),
                    permission TEXT NOT NULL CHECK(permission IN ('read','write')),
                    PRIMARY KEY(archive_id,user_id)
                );
                CREATE TABLE IF NOT EXISTS archive_versions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    version INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'verified' CHECK(state IN ('verified','degraded')),
                    created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    UNIQUE(archive_id,version)
                );
                CREATE TABLE IF NOT EXISTS archive_files(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content BLOB NOT NULL,
                    UNIQUE(version_id,path)
                );
                CREATE TABLE IF NOT EXISTS copies(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    location TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'healthy' CHECK(state IN ('healthy','corrupt','degraded')),
                    created_at TEXT NOT NULL,
                    last_verified_at TEXT,
                    UNIQUE(version_id,location)
                );
                CREATE TABLE IF NOT EXISTS copy_files(
                    copy_id INTEGER NOT NULL REFERENCES copies(id),
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content BLOB NOT NULL,
                    PRIMARY KEY(copy_id,path)
                );
                CREATE TABLE IF NOT EXISTS migrations(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    target_version_id INTEGER NOT NULL UNIQUE REFERENCES archive_versions(id),
                    source_path TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    target_format TEXT NOT NULL,
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    retain_until TEXT
                );
                CREATE TABLE IF NOT EXISTS legal_holds(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    version_id INTEGER REFERENCES archive_versions(id),
                    applicant_id TEXT NOT NULL REFERENCES users(id),
                    reason TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','released')),
                    created_at TEXT NOT NULL,
                    released_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_legal_holds_archive ON legal_holds(archive_id,status);
                CREATE INDEX IF NOT EXISTS idx_legal_holds_version ON legal_holds(version_id,status);
                CREATE TABLE IF NOT EXISTS disposal_tasks(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('running','completed','failed','blocked')),
                    started_by TEXT NOT NULL REFERENCES users(id),
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    total_count INTEGER NOT NULL DEFAULT 0,
                    deleted_count INTEGER NOT NULL DEFAULT 0,
                    failed_count INTEGER NOT NULL DEFAULT 0,
                    held_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_disposal_tasks_archive ON disposal_tasks(archive_id,id);
                CREATE TABLE IF NOT EXISTS disposal_records(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id INTEGER NOT NULL REFERENCES disposal_tasks(id),
                    copy_id INTEGER NOT NULL,
                    location TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending','deleted','failed','held')),
                    error TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_disposal_records_task ON disposal_records(task_id);
                CREATE INDEX IF NOT EXISTS idx_disposal_records_copy ON disposal_records(copy_id,status);
                """
            )
            # 兼容旧库：只做增量加列，不要求停机回填；旧数据沿用默认状态即可查、可校验
            for table, column, ddl in [
                ("archives", "status", "ALTER TABLE archives ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','pending_disposal','disposing','disposed'))"),
                ("copies", "disposal_failed", "ALTER TABLE copies ADD COLUMN disposal_failed INTEGER NOT NULL DEFAULT 0 CHECK(disposal_failed IN (0,1))"),
                ("audit_log", "retain_until", "ALTER TABLE audit_log ADD COLUMN retain_until TEXT"),
            ]:
                cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
                if column not in cols:
                    conn.execute(ddl)

    def seed(self) -> None:
        self.init_schema()
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO users(id,name,role) VALUES(?,?,?)",
                [
                    ("owner", "机构档案负责人", "owner"),
                    ("archivist", "档案管理员", "archivist"),
                    ("auditor", "独立审计员", "auditor"),
                    ("outsider", "未授权访客", "auditor"),
                ],
            )

    def _user(self, conn, user_id: str | None, roles: set[str] | None = None) -> sqlite3.Row:
        if not user_id:
            raise BusinessError("缺少 X-User-Id", 401, "authentication_required")
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            raise BusinessError("用户不存在", 401, "unknown_user")
        if roles and user["role"] not in roles:
            raise BusinessError("当前角色无权执行此操作", 403, "forbidden")
        return user

    def _access(self, conn, archive_id: int, user: sqlite3.Row, require_write: bool = False) -> None:
        archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
        if not archive:
            raise BusinessError("档案不存在", 404, "not_found")
        if archive["owner_id"] == user["id"]:
            return
        row = conn.execute(
            "SELECT permission FROM archive_members WHERE archive_id=? AND user_id=?", (archive_id, user["id"])
        ).fetchone()
        if not row or (require_write and row["permission"] != "write"):
            raise BusinessError("没有该受限档案的访问权限", 403, "forbidden")

    def _audit(self, conn, archive_id: int, actor: str, action: str, detail: dict) -> None:
        # 审计记录保留十年：写入时即确定 retain_until，到期前不删除
        retain_until = (datetime.now(timezone.utc) + timedelta(days=3650)).isoformat(timespec="seconds")
        conn.execute(
            "INSERT INTO audit_log(archive_id,actor_id,action,detail,created_at,retain_until) VALUES(?,?,?,?,?,?)",
            (archive_id, actor, action, json.dumps(detail, ensure_ascii=False, sort_keys=True), now(), retain_until),
        )

    def create_archive(self, user_id: str, name: str, retention_until: str, restricted: bool = True) -> dict:
        name = name.strip()
        if len(name) < 2:
            raise BusinessError("档案名称至少 2 字", 422, "invalid_name")
        try:
            deadline = date.fromisoformat(retention_until)
        except ValueError:
            raise BusinessError("retention_until 必须是 YYYY-MM-DD", 422, "invalid_retention")
        if deadline < date.today():
            raise BusinessError("保留期限不能早于今天", 422, "retention_in_past")
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            try:
                cur = conn.execute(
                    "INSERT INTO archives(name,owner_id,retention_until,restricted,created_at) VALUES(?,?,?,?,?)",
                    (name, user_id, retention_until, int(bool(restricted)), now()),
                )
            except sqlite3.IntegrityError:
                raise BusinessError("档案名称已存在", 409, "archive_exists")
            archive_id = cur.lastrowid
            conn.execute(
                "INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,'write')", (archive_id, user_id)
            )
            self._audit(conn, archive_id, user_id, "archive.create", {"retention_until": retention_until, "restricted": restricted})
            return {"id": archive_id, "name": name, "retention_until": retention_until, "restricted": restricted}

    def grant(self, actor_id: str, archive_id: int, user_id: str, permission: str) -> dict:
        if permission not in {"read", "write"}:
            raise BusinessError("permission 必须是 read 或 write", 422, "invalid_permission")
        with self.connect() as conn:
            actor = self._user(conn, actor_id)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            if archive["owner_id"] != actor_id:
                raise BusinessError("只有档案所有者可以授权", 403, "forbidden")
            self._user(conn, user_id)
            conn.execute(
                """INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,?)
                   ON CONFLICT(archive_id,user_id) DO UPDATE SET permission=excluded.permission""",
                (archive_id, user_id, permission),
            )
            self._audit(conn, archive_id, actor_id, "access.grant", {"user_id": user_id, "permission": permission})
            return {"archive_id": archive_id, "user_id": user_id, "permission": permission}

    def ingest_version(self, actor_id: str, archive_id: int, files: object) -> dict:
        manifest = verify_manifest(files)
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            self._access(conn, archive_id, actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (archive_id,)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (archive_id, version_no, actor_id, now()),
                )
                version_id = cur.lastrowid
                for item in manifest:
                    conn.execute(
                        "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                        (version_id, item["path"], item["sha256"], item["size"], item["content"]),
                    )
                self._audit(
                    conn, archive_id, actor_id, "version.ingest",
                    {"version_id": version_id, "version": version_no, "files": len(manifest),
                     "manifest": [{"path": x["path"], "sha256": x["sha256"], "size": x["size"]} for x in manifest]},
                )
                return {"id": version_id, "archive_id": archive_id, "version": version_no, "file_count": len(manifest)}
            except Exception:
                conn.rollback()
                raise

    def add_copy(self, actor_id: str, version_id: int, location: str) -> dict:
        location = location.strip()
        if len(location) < 2:
            raise BusinessError("副本位置不能为空", 422, "invalid_location")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "INSERT INTO copies(version_id,location,created_at,last_verified_at) VALUES(?,?,?,?)",
                    (version_id, location, now(), now()),
                )
                copy_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?""",
                    (copy_id, version_id),
                )
                self._audit(conn, version["archive_id"], actor_id, "copy.create", {"copy_id": copy_id, "version_id": version_id, "location": location})
                return {"id": copy_id, "version_id": version_id, "location": location, "state": "healthy"}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("该版本的副本位置已存在", 409, "copy_exists")
            except Exception:
                conn.rollback()
                raise

    def get_version(self, user_id: str, version_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], user)
            files = conn.execute(
                "SELECT path,sha256,size FROM archive_files WHERE version_id=? ORDER BY path", (version_id,)
            ).fetchall()
            copies = conn.execute(
                "SELECT id,location,state,last_verified_at FROM copies WHERE version_id=? ORDER BY id", (version_id,)
            ).fetchall()
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
            holds = conn.execute(
                """SELECT * FROM legal_holds WHERE archive_id=? AND status='active'
                   AND (version_id IS NULL OR version_id=?) ORDER BY id""",
                (version["archive_id"], version_id),
            ).fetchall()
            migrated_from = conn.execute(
                "SELECT * FROM migrations WHERE target_version_id=? ORDER BY id DESC LIMIT 1", (version_id,)
            ).fetchone()
            migrated_to = conn.execute(
                "SELECT * FROM migrations WHERE source_version_id=? ORDER BY id", (version_id,)
            ).fetchall()
            return {"version": dict(version), "archive": dict(archive), "files": [dict(x) for x in files],
                    "copies": [dict(x) for x in copies], "holds": [dict(h) for h in holds],
                    "migrated_from": dict(migrated_from) if migrated_from else None,
                    "migrated_to": [dict(migrated_to)] if migrated_to else []}

    def verify_copy(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], user)
                stored = conn.execute(
                    "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (copy_id,)
                ).fetchall()
                corrupt_paths = [r["path"] for r in stored if hashlib.sha256(r["content"]).hexdigest() != r["sha256"] or len(r["content"]) != r["size"]]
                repaired = False
                if not corrupt_paths:
                    conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                    result_state = "healthy"
                else:
                    conn.execute("UPDATE copies SET state='corrupt',last_verified_at=? WHERE id=?", (now(), copy_id))
                    healthy = conn.execute(
                        "SELECT id FROM copies WHERE version_id=? AND id<>? AND state='healthy' ORDER BY last_verified_at DESC LIMIT 1",
                        (copy["version_id"], copy_id),
                    ).fetchone()
                    result_state = "degraded"
                    if healthy:
                        donor = conn.execute(
                            "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (healthy["id"],)
                        ).fetchall()
                        donor_by_path = {r["path"]: r for r in donor}
                        expected = {r["path"]: r for r in conn.execute(
                            "SELECT path,sha256,size FROM archive_files WHERE version_id=?", (copy["version_id"],)
                        ).fetchall()}
                        if set(donor_by_path) == set(expected) and all(
                            hashlib.sha256(donor_by_path[p]["content"]).hexdigest() == expected[p]["sha256"] for p in expected
                        ):
                            conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy_id,))
                            conn.execute(
                                """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                                   SELECT ?,path,sha256,size,content FROM copy_files WHERE copy_id=?""",
                                (copy_id, healthy["id"]),
                            )
                            conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                            repaired, result_state = True, "healthy"
                    if result_state == "degraded":
                        conn.execute("UPDATE archive_versions SET state='degraded' WHERE id=?", (copy["version_id"],))
                self._audit(
                    conn, version["archive_id"], user_id, "copy.verify",
                    {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths, "repaired": repaired},
                )
                return {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths, "repaired": repaired}
            except Exception:
                conn.rollback()
                raise

    def simulate_corruption(self, user_id: str, copy_id: int, path: str) -> dict:
        """仅用于演示和测试，在受控环境中模拟底层介质损坏。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], user, require_write=True)
            row = conn.execute("SELECT content FROM copy_files WHERE copy_id=? AND path=?", (copy_id, path)).fetchone()
            if not row:
                raise BusinessError("副本文件不存在", 404, "not_found")
            damaged = bytes([row["content"][0] ^ 0xFF]) + row["content"][1:] if row["content"] else b"corrupt"
            conn.execute("UPDATE copy_files SET content=? WHERE copy_id=? AND path=?", (damaged, copy_id, path))
            conn.execute("UPDATE copies SET state='corrupt' WHERE id=?", (copy_id,))
            self._audit(conn, version["archive_id"], user_id, "copy.simulate_corruption", {"copy_id": copy_id, "path": path})
            return {"copy_id": copy_id, "path": path, "state": "corrupt"}

    def migrate(self, actor_id: str, version_id: int, source_path: str, target_path: str, target_format: str, content_b64: str) -> dict:
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            source_version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not source_version:
                raise BusinessError("源档案版本不存在", 404, "not_found")
            self._access(conn, source_version["archive_id"], actor, require_write=True)
            source = conn.execute(
                "SELECT * FROM archive_files WHERE version_id=? AND path=?", (version_id, source_path)
            ).fetchone()
            if not source:
                raise BusinessError("源文件不存在", 404, "source_not_found")
            converted = verify_manifest([{"path": target_path, "content_b64": content_b64}])[0]
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (source_version["archive_id"],)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (source_version["archive_id"], version_no, actor_id, now()),
                )
                target_version_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO archive_files(version_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files
                       WHERE version_id=? AND path<>?""",
                    (target_version_id, version_id, source_path),
                )
                conn.execute(
                    "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                    (target_version_id, converted["path"], converted["sha256"], converted["size"], converted["content"]),
                )
                conn.execute(
                    "INSERT INTO migrations(source_version_id,target_version_id,source_path,target_path,target_format,actor_id,created_at) VALUES(?,?,?,?,?,?,?)",
                    (version_id, target_version_id, source_path, converted["path"], target_format.strip(), actor_id, now()),
                )
                # 新版本继承源版本的保全关系：覆盖源版本的生效保全（整份级或版本级）
                # 均派生为目标版本上的版本级保全，保留来源链路，可按原路径追溯
                source_holds = conn.execute(
                    """SELECT * FROM legal_holds WHERE archive_id=? AND status='active'
                       AND (version_id IS NULL OR version_id=?)""",
                    (source_version["archive_id"], version_id),
                ).fetchall()
                for h in source_holds:
                    scope = "整份档案级" if h["version_id"] is None else f"版本 #{h['version_id']} 级"
                    conn.execute(
                        """INSERT INTO legal_holds(archive_id,version_id,applicant_id,reason,status,created_at)
                           VALUES(?,?,?,?, 'active',?)""",
                        (source_version["archive_id"], target_version_id, actor_id,
                         f"迁移继承自保全 #{h['id']}（{scope}）", now()),
                    )
                self._audit(
                    conn, source_version["archive_id"], actor_id, "format.migrate",
                    {"source_version_id": version_id, "target_version_id": target_version_id,
                     "source_path": source_path, "target_path": converted["path"], "target_format": target_format.strip(),
                     "inherited_holds": [h["id"] for h in source_holds]},
                )
                return {"id": target_version_id, "version": version_no, "source_version_id": version_id, "target_path": converted["path"]}
            except Exception:
                conn.rollback()
                raise

    def archive_status(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            self._access(conn, archive_id, user)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            versions = conn.execute("SELECT id,version,state,created_at FROM archive_versions WHERE archive_id=? ORDER BY version", (archive_id,)).fetchall()
            deadline = date.fromisoformat(archive["retention_until"])
            active_holds = conn.execute(
                "SELECT * FROM legal_holds WHERE archive_id=? AND status='active' ORDER BY id", (archive_id,)
            ).fetchall()
            latest_task = conn.execute(
                "SELECT * FROM disposal_tasks WHERE archive_id=? ORDER BY id DESC LIMIT 1", (archive_id,)
            ).fetchone()
            return {
                "archive": dict(archive),
                "days_remaining": (deadline - date.today()).days,
                "versions": [dict(v) | {"file_count": conn.execute("SELECT COUNT(*) FROM archive_files WHERE version_id=?", (v["id"],)).fetchone()[0],
                                         "copy_count": conn.execute("SELECT COUNT(*) FROM copies WHERE version_id=?", (v["id"],)).fetchone()[0]}
                             for v in versions],
                "active_holds": [dict(h) for h in active_holds],
                "disposal": {"latest_task": dict(latest_task) if latest_task else None},
                "audit": [dict(r) | {"detail": json.loads(r["detail"])} for r in conn.execute("SELECT * FROM audit_log WHERE archive_id=? ORDER BY id", (archive_id,)).fetchall()],
            }

    # ---------- 到期处置与法定保全 ----------

    def _active_holds_for_copy(self, conn, archive_id: int, version_id: int) -> list[sqlite3.Row]:
        return conn.execute(
            """SELECT * FROM legal_holds
               WHERE archive_id=? AND status='active'
                 AND (version_id IS NULL OR version_id=?)
               ORDER BY id""",
            (archive_id, version_id),
        ).fetchall()

    def enter_disposal(self, actor_id: str, archive_id: int) -> dict:
        """档案进入待处置区。到期（retention_until 已过）或机构主动转入均可。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            self._access(conn, archive_id, actor, require_write=True)
            if archive["status"] == "disposed":
                raise BusinessError("档案已处置完成，不能再进入待处置区", 409, "already_disposed")
            if archive["status"] == "disposing":
                raise BusinessError("处置任务进行中，请先查询处置状态", 409, "disposal_running")
            if archive["status"] == "pending_disposal":
                return {"id": archive_id, "status": "pending_disposal", "changed": False}
            conn.execute("UPDATE archives SET status='pending_disposal' WHERE id=?", (archive_id,))
            self._audit(conn, archive_id, actor_id, "disposal.enter", {})
            return {"id": archive_id, "status": "pending_disposal", "changed": True}

    def start_disposal(self, actor_id: str, archive_id: int) -> dict:
        """启动处置任务。

        与保全申请并发时由 SQLite BEGIN IMMEDIATE 串行化：先写入状态的一方生效。
        - 档案不在待处置区 -> 报错；
        - 已有进行中的任务 -> 按现状返回当前任务；
        - 存在生效保全 -> 不启动清退，按现状返回保全信息；
        - 否则建立任务并逐副本清退，每个副本删除前重新校验保全状态，后到的保全不被覆盖。
        """
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            self._access(conn, archive_id, actor, require_write=True)
            if archive["status"] == "active":
                raise BusinessError("档案尚未进入待处置区", 409, "not_in_disposal_area")
            if archive["status"] == "disposed":
                raise BusinessError("档案已处置完成", 409, "already_disposed")
            if archive["status"] == "disposing":
                task = conn.execute(
                    "SELECT * FROM disposal_tasks WHERE archive_id=? ORDER BY id DESC LIMIT 1", (archive_id,)
                ).fetchone()
                return {"started": False, "state": "disposing", "archive_status": "disposing",
                        "task": dict(task) if task else None}
            # 待处置区：先查保全，保全先生效则清退不启动
            holds = conn.execute(
                "SELECT * FROM legal_holds WHERE archive_id=? AND status='active' ORDER BY id", (archive_id,)
            ).fetchall()
            if holds:
                return {"started": False, "state": "held", "archive_status": "pending_disposal",
                        "holds": [dict(h) for h in holds]}
            copies = conn.execute(
                """SELECT c.* FROM copies c JOIN archive_versions v ON c.version_id=v.id
                   WHERE v.archive_id=? ORDER BY c.id""",
                (archive_id,),
            ).fetchall()
            cur = conn.execute(
                "INSERT INTO disposal_tasks(archive_id,status,started_by,started_at,total_count) VALUES(?,?,?,?,?)",
                (archive_id, "running", actor_id, now(), len(copies)),
            )
            task_id = cur.lastrowid
            conn.execute("UPDATE archives SET status='disposing' WHERE id=?", (archive_id,))
            self._audit(conn, archive_id, actor_id, "disposal.start",
                        {"task_id": task_id, "total_count": len(copies)})
        result = self._run_disposal(task_id, archive_id)
        return {"started": True, "state": result["status"], "archive_status": result["archive_status"],
                "task_id": task_id, "task": result["task"], "records": result["records"]}

    def _run_disposal(self, task_id: int, archive_id: int) -> dict:
        """逐副本清退。每个副本独立事务，删除前重新校验保全，确保后到的保全不被覆盖。"""
        with self.connect() as conn:
            task = conn.execute("SELECT * FROM disposal_tasks WHERE id=?", (task_id,)).fetchone()
            copies = conn.execute(
                """SELECT c.* FROM copies c JOIN archive_versions v ON c.version_id=v.id
                   WHERE v.archive_id=? ORDER BY c.id""",
                (archive_id,),
            ).fetchall()
        deleted = failed = held = 0
        records: list[dict] = []
        for copy in copies:
            with self.connect() as conn:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    block = conn.execute(
                        """SELECT id FROM legal_holds WHERE archive_id=? AND status='active'
                           AND (version_id IS NULL OR version_id=?) LIMIT 1""",
                        (archive_id, copy["version_id"]),
                    ).fetchone()
                    if block:
                        conn.execute(
                            "INSERT INTO disposal_records(task_id,copy_id,location,status,updated_at) VALUES(?,?,?,?,?)",
                            (task_id, copy["id"], copy["location"], "held", now()),
                        )
                        conn.commit()
                        held += 1
                        records.append({"copy_id": copy["id"], "location": copy["location"], "status": "held"})
                        continue
                    if copy["disposal_failed"]:
                        conn.execute(
                            "INSERT INTO disposal_records(task_id,copy_id,location,status,error,updated_at) VALUES(?,?,?,?,?,?)",
                            (task_id, copy["id"], copy["location"], "failed", "simulated_storage_error", now()),
                        )
                        conn.commit()
                        failed += 1
                        records.append({"copy_id": copy["id"], "location": copy["location"], "status": "failed",
                                         "error": "simulated_storage_error"})
                        continue
                    conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy["id"],))
                    conn.execute("DELETE FROM copies WHERE id=?", (copy["id"],))
                    conn.execute(
                        "INSERT INTO disposal_records(task_id,copy_id,location,status,updated_at) VALUES(?,?,?,?,?)",
                        (task_id, copy["id"], copy["location"], "deleted", now()),
                    )
                    conn.commit()
                    deleted += 1
                    records.append({"copy_id": copy["id"], "location": copy["location"], "status": "deleted"})
                except Exception:
                    conn.rollback()
                    raise
        with self.connect() as conn:
            if failed:
                status = "failed"
            elif held:
                status = "blocked"
            else:
                status = "completed"
            archive_status = "disposed" if status == "completed" else "pending_disposal"
            conn.execute(
                """UPDATE disposal_tasks SET status=?,finished_at=?,deleted_count=?,failed_count=?,held_count=?
                   WHERE id=?""",
                (status, now(), deleted, failed, held, task_id),
            )
            conn.execute("UPDATE archives SET status=? WHERE id=?", (archive_status, archive_id))
            starter = conn.execute("SELECT started_by FROM disposal_tasks WHERE id=?", (task_id,)).fetchone()
            self._audit(conn, archive_id, starter["started_by"], "disposal.finish",
                        {"task_id": task_id, "status": status, "deleted": deleted, "failed": failed, "held": held})
            task = conn.execute("SELECT * FROM disposal_tasks WHERE id=?", (task_id,)).fetchone()
        return {"status": status, "archive_status": archive_status, "task": dict(task), "records": records}

    def retry_disposal(self, actor_id: str, archive_id: int) -> dict:
        """重试清退：只处理尚未删除的副本（已有 deleted 记录的副本不再处理）。"""
        return self.start_disposal(actor_id, archive_id)

    def disposal_status(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            self._access(conn, archive_id, user)
            tasks = conn.execute(
                "SELECT * FROM disposal_tasks WHERE archive_id=? ORDER BY id", (archive_id,)
            ).fetchall()
            records: list[sqlite3.Row] = []
            task_ids = [t["id"] for t in tasks]
            if task_ids:
                placeholders = ",".join("?" * len(task_ids))
                records = conn.execute(
                    f"SELECT * FROM disposal_records WHERE task_id IN ({placeholders}) ORDER BY id", task_ids
                ).fetchall()
            holds = conn.execute(
                "SELECT * FROM legal_holds WHERE archive_id=? AND status='active' ORDER BY id", (archive_id,)
            ).fetchall()
            remaining = conn.execute(
                """SELECT c.id,c.location,c.state,c.disposal_failed,v.version
                   FROM copies c JOIN archive_versions v ON c.version_id=v.id
                   WHERE v.archive_id=? ORDER BY c.id""",
                (archive_id,),
            ).fetchall()
            return {
                "archive": dict(archive),
                "tasks": [dict(t) for t in tasks],
                "records": [dict(r) for r in records],
                "active_holds": [dict(h) for h in holds],
                "remaining_copies": [dict(r) for r in remaining],
            }

    def apply_hold(self, actor_id: str, archive_id: int, version_id: int | None = None, reason: str = "") -> dict:
        """申请法定保全。version_id 为 None 时为整份档案保全，否则为版本保全。

        与处置任务并发时由 BEGIN IMMEDIATE 串行化：若处置已先写入状态，保全仍登记（法律事实），
        由清退循环在删除前校验，后到的保全不被覆盖；响应按现状返回。
        """
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            self._access(conn, archive_id, actor, require_write=True)
            if version_id is not None:
                version = conn.execute(
                    "SELECT id FROM archive_versions WHERE id=? AND archive_id=?", (version_id, archive_id)
                ).fetchone()
                if not version:
                    raise BusinessError("版本不存在或不属于该档案", 404, "not_found")
            reason = reason.strip()
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                """INSERT INTO legal_holds(archive_id,version_id,applicant_id,reason,status,created_at)
                   VALUES(?,?,?,?,'active',?)""",
                (archive_id, version_id, actor_id, reason, now()),
            )
            hold_id = cur.lastrowid
            self._audit(conn, archive_id, actor_id, "hold.apply",
                        {"hold_id": hold_id, "version_id": version_id, "reason": reason})
            hold = conn.execute("SELECT * FROM legal_holds WHERE id=?", (hold_id,)).fetchone()
            running = conn.execute(
                "SELECT * FROM disposal_tasks WHERE archive_id=? AND status='running' ORDER BY id DESC LIMIT 1",
                (archive_id,),
            ).fetchone()
            return {"hold": dict(hold), "archive_status": archive["status"],
                    "disposal_task": dict(running) if running else None}

    def release_hold(self, actor_id: str, hold_id: int) -> dict:
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            hold = conn.execute("SELECT * FROM legal_holds WHERE id=?", (hold_id,)).fetchone()
            if not hold:
                raise BusinessError("保全不存在", 404, "not_found")
            self._access(conn, hold["archive_id"], actor, require_write=True)
            if hold["status"] != "active":
                return {"hold": dict(hold), "changed": False}
            conn.execute("UPDATE legal_holds SET status='released',released_at=? WHERE id=?", (now(), hold_id))
            self._audit(conn, hold["archive_id"], actor_id, "hold.release", {"hold_id": hold_id})
            return {"hold": dict(conn.execute("SELECT * FROM legal_holds WHERE id=?", (hold_id,)).fetchone()),
                    "changed": True}

    def list_holds(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            self._access(conn, archive_id, user)
            holds = conn.execute(
                "SELECT * FROM legal_holds WHERE archive_id=? ORDER BY id", (archive_id,)
            ).fetchall()
            return {"holds": [dict(h) for h in holds]}

    def simulate_disposal_failure(self, user_id: str, copy_id: int, fail: bool = True) -> dict:
        """仅用于演示/测试：标记副本清退时模拟存储失败。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], user, require_write=True)
            conn.execute("UPDATE copies SET disposal_failed=? WHERE id=?", (int(bool(fail)), copy_id))
            self._audit(conn, version["archive_id"], user_id, "copy.simulate_disposal_failure",
                        {"copy_id": copy_id, "disposal_failed": bool(fail)})
            return {"copy_id": copy_id, "disposal_failed": bool(fail)}

    def due_disposals(self, user_id: str) -> dict:
        """已过保留期但尚未处置完成的档案（到期清单）。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            rows = conn.execute(
                """SELECT a.* FROM archives a
                   WHERE a.status != 'disposed' AND a.retention_until < date('now')
                   ORDER BY a.retention_until"""
            ).fetchall()
            return {"archives": [dict(r) for r in rows]}


class Handler(BaseHTTPRequestHandler):
    server_version = "Preservation/1.0"

    def _store(self):
        return self.server.store  # type: ignore[attr-defined]

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise BusinessError("请求体必须是合法 JSON", 400, "invalid_json")
        if not isinstance(data, dict):
            raise BusinessError("JSON 顶层必须是对象", 422, "invalid_json")
        return data

    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method: str) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        parts = [p for p in path.split("/") if p]
        user = self.headers.get("X-User-Id", "")
        if method == "GET" and path == "/":
            body = (BASE_DIR / "web" / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if method == "GET" and path == "/health":
            return self._send(200, {"ok": True})
        store = self._store()
        if parts == ["api", "archives"] and method == "POST":
            d = self._body()
            return self._send(201, store.create_archive(user, d.get("name", ""), d.get("retention_until", ""), bool(d.get("restricted", True))))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and method == "POST":
            archive_id = int(parts[2])
            if parts[3] == "versions":
                d = self._body()
                return self._send(201, store.ingest_version(user, archive_id, d.get("files")))
            if parts[3] == "members":
                d = self._body()
                return self._send(201, store.grant(user, archive_id, d.get("user_id", ""), d.get("permission", "")))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "status" and method == "GET":
            return self._send(200, store.archive_status(user, int(parts[2])))
        if len(parts) == 5 and parts[:2] == ["api", "archives"] and parts[3] == "disposal" and method == "POST":
            archive_id = int(parts[2])
            if parts[4] == "enter":
                return self._send(200, store.enter_disposal(user, archive_id))
            if parts[4] == "start":
                return self._send(200, store.start_disposal(user, archive_id))
            if parts[4] == "retry":
                return self._send(200, store.retry_disposal(user, archive_id))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "disposal" and method == "GET":
            return self._send(200, store.disposal_status(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "holds" and method == "POST":
            d = self._body()
            version_id = d.get("version_id")
            return self._send(201, store.apply_hold(user, int(parts[2]), version_id, d.get("reason", "")))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "holds" and method == "GET":
            return self._send(200, store.list_holds(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "holds"] and parts[3] == "release" and method == "POST":
            return self._send(200, store.release_hold(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "simulate-disposal-failure" and method == "POST":
            d = self._body()
            return self._send(200, store.simulate_disposal_failure(user, int(parts[2]), bool(d.get("fail", True))))
        if parts == ["api", "disposal", "due"] and method == "GET":
            return self._send(200, store.due_disposals(user))
        if len(parts) == 3 and parts[:2] == ["api", "versions"] and method == "GET":
            return self._send(200, store.get_version(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "copies" and method == "POST":
            d = self._body()
            return self._send(201, store.add_copy(user, int(parts[2]), d.get("location", "")))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "migrate" and method == "POST":
            d = self._body()
            return self._send(201, store.migrate(user, int(parts[2]), d.get("source_path", ""), d.get("target_path", ""), d.get("target_format", ""), d.get("content_b64", "")))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "verify" and method == "POST":
            return self._send(200, store.verify_copy(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "simulate-corruption" and method == "POST":
            d = self._body()
            return self._send(200, store.simulate_corruption(user, int(parts[2]), d.get("path", "")))
        raise BusinessError("接口不存在", 404, "not_found")

    def _handle(self, method: str) -> None:
        try:
            self._dispatch(method)
        except BusinessError as exc:
            self._send(exc.status, {"error": {"code": exc.code, "message": exc.message}})
        except (ValueError, TypeError):
            self._send(400, {"error": {"code": "invalid_path", "message": "路径参数格式错误"}})
        except Exception as exc:
            self._send(500, {"error": {"code": "internal_error", "message": str(exc)}})

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_DELETE(self): self._handle("DELETE")
    def log_message(self, fmt, *args): print(f"{self.address_string()} - {fmt % args}")


class PreservationServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, store):
        self.store = store
        super().__init__(address, Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="数字档案长期保存服务")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--port", type=int, default=8102)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    store = PreservationStore(args.db)
    store.init_schema()
    if args.seed:
        store.seed()
    if args.init or args.seed:
        print(f"数据库已初始化: {args.db}")
        return
    print(f"数字档案服务运行于 http://127.0.0.1:{args.port}")
    server = PreservationServer(("127.0.0.1", args.port), store)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
