"""数字档案长期保存服务：SQLite 多副本、哈希校验、修复与迁移、到期处置与法定保全。"""
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
AUDIT_RETENTION_YEARS = 10


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
                    disposal_state TEXT NOT NULL DEFAULT 'active'
                        CHECK(disposal_state IN ('active','pending_disposal','disposing','disposed')),
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
                    retention_until TEXT,
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
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS legal_holds(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    version_id INTEGER REFERENCES archive_versions(id),
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','released')),
                    requested_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    released_by TEXT REFERENCES users(id),
                    released_at TEXT
                );
                CREATE TABLE IF NOT EXISTS disposal_tasks(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    status TEXT NOT NULL DEFAULT 'in_progress'
                        CHECK(status IN ('in_progress','completed','partial_failed')),
                    started_by TEXT NOT NULL REFERENCES users(id),
                    started_at TEXT NOT NULL,
                    finished_at TEXT
                );
                CREATE TABLE IF NOT EXISTS disposal_copy_results(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id INTEGER NOT NULL REFERENCES disposal_tasks(id),
                    copy_id INTEGER NOT NULL,
                    version_id INTEGER NOT NULL,
                    location TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','purged','failed')),
                    error TEXT,
                    updated_at TEXT NOT NULL,
                    UNIQUE(task_id,copy_id)
                );
                """
            )
            # 旧库在线升级：只加列、不重建表、不回填，旧行靠默认值和读取时回退即可用
            archive_cols = {r[1] for r in conn.execute("PRAGMA table_info(archives)")}
            if "disposal_state" not in archive_cols:
                conn.execute(
                    "ALTER TABLE archives ADD COLUMN disposal_state TEXT NOT NULL DEFAULT 'active'"
                    " CHECK(disposal_state IN ('active','pending_disposal','disposing','disposed'))"
                )
            version_cols = {r[1] for r in conn.execute("PRAGMA table_info(archive_versions)")}
            if "retention_until" not in version_cols:
                conn.execute("ALTER TABLE archive_versions ADD COLUMN retention_until TEXT")

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
        conn.execute(
            "INSERT INTO audit_log(archive_id,actor_id,action,detail,created_at) VALUES(?,?,?,?,?)",
            (archive_id, actor, action, json.dumps(detail, ensure_ascii=False, sort_keys=True), now()),
        )

    def _archive_row(self, conn, archive_id: int) -> sqlite3.Row:
        archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
        if not archive:
            raise BusinessError("档案不存在", 404, "not_found")
        return archive

    def _ensure_mutable(self, conn, archive_id: int) -> None:
        """处置中或已处置的档案禁止再写入版本、副本或迁移。"""
        state = self._archive_row(conn, archive_id)["disposal_state"]
        if state in ("disposing", "disposed"):
            raise BusinessError(f"档案正在处置或已处置，禁止写入；当前状态: {state}", 409, "archive_in_disposal")

    def _ensure_no_active_hold(self, conn, archive_id: int) -> None:
        """存在生效中的法定保全（整份档案或任一版本）时，副本一律不能删。"""
        holds = conn.execute(
            "SELECT COUNT(*) FROM legal_holds WHERE archive_id=? AND status='active'", (archive_id,)
        ).fetchone()[0]
        if holds:
            raise BusinessError(f"存在 {holds} 条生效中的法定保全，不能清退副本", 409, "hold_active")

    @staticmethod
    def _effective_retention(version: sqlite3.Row, archive: sqlite3.Row) -> str:
        """旧数据版本行没有 retention_until，读取时回退到档案级保留期，无需回填。"""
        return version["retention_until"] or archive["retention_until"]

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
            self._ensure_mutable(conn, archive_id)
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (archive_id,)
                ).fetchone()[0]
                retention = conn.execute("SELECT retention_until FROM archives WHERE id=?", (archive_id,)).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at,retention_until) VALUES(?,?,?,?,?)",
                    (archive_id, version_no, actor_id, now(), retention),
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
            self._ensure_mutable(conn, version["archive_id"])
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
                """SELECT id,version_id,reason,requested_by,created_at FROM legal_holds
                   WHERE archive_id=? AND status='active' AND (version_id IS NULL OR version_id=?) ORDER BY id""",
                (version["archive_id"], version_id),
            ).fetchall()
            return {
                "version": dict(version) | {"effective_retention_until": self._effective_retention(version, archive)},
                "archive": dict(archive),
                "files": [dict(x) for x in files],
                "copies": [dict(x) for x in copies],
                "active_holds": [dict(x) for x in holds],
            }

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
            self._ensure_mutable(conn, source_version["archive_id"])
            source = conn.execute(
                "SELECT * FROM archive_files WHERE version_id=? AND path=?", (version_id, source_path)
            ).fetchone()
            if not source:
                raise BusinessError("源文件不存在", 404, "source_not_found")
            converted = verify_manifest([{"path": target_path, "content_b64": content_b64}])[0]
            try:
                conn.execute("BEGIN IMMEDIATE")
                archive = self._archive_row(conn, source_version["archive_id"])
                inherited_retention = self._effective_retention(source_version, archive)
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (source_version["archive_id"],)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at,retention_until) VALUES(?,?,?,?,?)",
                    (source_version["archive_id"], version_no, actor_id, now(), inherited_retention),
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
                # 新版本继承源版本生效中的版本级保全；档案级保全天然覆盖全部版本
                inherited_holds = conn.execute(
                    """INSERT INTO legal_holds(archive_id,version_id,reason,status,requested_by,created_at)
                       SELECT archive_id, ?, reason, 'active', requested_by, ?
                       FROM legal_holds WHERE version_id=? AND status='active'""",
                    (target_version_id, now(), version_id),
                ).rowcount
                self._audit(
                    conn, source_version["archive_id"], actor_id, "format.migrate",
                    {"source_version_id": version_id, "target_version_id": target_version_id,
                     "source_path": source_path, "target_path": converted["path"], "target_format": target_format.strip(),
                     "retention_until": inherited_retention, "inherited_holds": inherited_holds},
                )
                return {"id": target_version_id, "version": version_no, "source_version_id": version_id,
                        "target_path": converted["path"], "retention_until": inherited_retention,
                        "inherited_holds": inherited_holds}
            except Exception:
                conn.rollback()
                raise

    def enter_pending_disposal(self, actor_id: str, archive_id: int) -> dict:
        """保留期到期后把档案移入待处置区；重复进入或状态已推进时按现状返回。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            self._access(conn, archive_id, actor, require_write=True)
            archive = self._archive_row(conn, archive_id)
            if date.fromisoformat(archive["retention_until"]) >= date.today():
                raise BusinessError("保留期未到期，不能进入待处置区", 409, "not_expired")
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "UPDATE archives SET disposal_state='pending_disposal' WHERE id=? AND disposal_state='active'",
                    (archive_id,),
                )
                changed = cur.rowcount == 1
                state = conn.execute("SELECT disposal_state FROM archives WHERE id=?", (archive_id,)).fetchone()[0]
                if changed:
                    self._audit(conn, archive_id, actor_id, "disposal.enter", {"disposal_state": state})
                return {"archive_id": archive_id, "disposal_state": state, "changed": changed}
            except Exception:
                conn.rollback()
                raise

    def create_hold(self, actor_id: str, archive_id: int, version_id: int | None, reason: str) -> dict:
        """按整份档案或单个版本申请法定保全；处置已开始时按现状拒绝，先写入的一方生效。"""
        reason = reason.strip()
        if len(reason) < 2:
            raise BusinessError("保全理由至少 2 字", 422, "invalid_reason")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            self._access(conn, archive_id, actor, require_write=True)
            if version_id is not None:
                row = conn.execute(
                    "SELECT id FROM archive_versions WHERE id=? AND archive_id=?", (version_id, archive_id)
                ).fetchone()
                if not row:
                    raise BusinessError("版本不存在或不属于该档案", 404, "not_found")
            try:
                conn.execute("BEGIN IMMEDIATE")
                state = self._archive_row(conn, archive_id)["disposal_state"]
                if state in ("disposing", "disposed"):
                    raise BusinessError(f"处置流程已启动，保全未生效；当前状态: {state}", 409, "disposal_already_started")
                cur = conn.execute(
                    "INSERT INTO legal_holds(archive_id,version_id,reason,requested_by,created_at) VALUES(?,?,?,?,?)",
                    (archive_id, version_id, reason, actor_id, now()),
                )
                hold_id = cur.lastrowid
                self._audit(conn, archive_id, actor_id, "hold.create",
                            {"hold_id": hold_id, "version_id": version_id, "reason": reason})
                return {"id": hold_id, "archive_id": archive_id, "version_id": version_id,
                        "status": "active", "reason": reason}
            except Exception:
                conn.rollback()
                raise

    def release_hold(self, actor_id: str, hold_id: int) -> dict:
        """解除保全；已解除的重复请求按现状返回。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            hold = conn.execute("SELECT * FROM legal_holds WHERE id=?", (hold_id,)).fetchone()
            if not hold:
                raise BusinessError("保全记录不存在", 404, "not_found")
            self._access(conn, hold["archive_id"], actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "UPDATE legal_holds SET status='released',released_by=?,released_at=? WHERE id=? AND status='active'",
                    (actor_id, now(), hold_id),
                )
                changed = cur.rowcount == 1
                status = conn.execute("SELECT status FROM legal_holds WHERE id=?", (hold_id,)).fetchone()[0]
                if changed:
                    self._audit(conn, hold["archive_id"], actor_id, "hold.release", {"hold_id": hold_id})
                return {"id": hold_id, "status": status, "changed": changed}
            except Exception:
                conn.rollback()
                raise

    def _purge_copies(self, conn, task_id: int, fail_locations: set[str]) -> dict:
        """逐副本清退：单个失败记录位置并继续其余副本；fail_locations 仅用于演示/测试注入介质故障。"""
        rows = conn.execute(
            "SELECT * FROM disposal_copy_results WHERE task_id=? AND status<>'purged' ORDER BY id", (task_id,)
        ).fetchall()
        purged, failures = 0, []
        for row in rows:
            conn.execute("SAVEPOINT purge_copy")
            try:
                if row["location"] in fail_locations:
                    raise OSError("离线介质不可达，清退失败")
                conn.execute("DELETE FROM copy_files WHERE copy_id=?", (row["copy_id"],))
                conn.execute("DELETE FROM copies WHERE id=?", (row["copy_id"],))
                conn.execute(
                    "UPDATE disposal_copy_results SET status='purged',error=NULL,updated_at=? WHERE id=?",
                    (now(), row["id"]),
                )
                conn.execute("RELEASE purge_copy")
                purged += 1
            except Exception as exc:
                conn.execute("ROLLBACK TO purge_copy")
                conn.execute("RELEASE purge_copy")
                conn.execute(
                    "UPDATE disposal_copy_results SET status='failed',error=?,updated_at=? WHERE id=?",
                    (str(exc), now(), row["id"]),
                )
                failures.append({"copy_id": row["copy_id"], "location": row["location"], "error": str(exc)})
        return {"purged": purged, "failed": len(failures), "failures": failures}

    def _finish_task(self, conn, archive_id: int, task_id: int, summary: dict) -> tuple[str, str]:
        """全部清退则档案处置完成；有失败则档案留在待处置区等待重试。"""
        final = "completed" if summary["failed"] == 0 else "partial_failed"
        conn.execute(
            "UPDATE disposal_tasks SET status=?,finished_at=? WHERE id=?",
            (final, now() if final == "completed" else None, task_id),
        )
        state = "disposed" if final == "completed" else "pending_disposal"
        conn.execute("UPDATE archives SET disposal_state=? WHERE id=?", (state, archive_id))
        return final, state

    def start_disposal(self, actor_id: str, archive_id: int, simulate_fail_locations: set[str] | None = None) -> dict:
        """启动处置任务：先写状态者生效，生效保全或并发冲突按现状拒绝。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            self._access(conn, archive_id, actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                archive = self._archive_row(conn, archive_id)
                if archive["disposal_state"] != "pending_disposal":
                    raise BusinessError(
                        f"档案不在待处置区，当前状态: {archive['disposal_state']}", 409, "invalid_state")
                self._ensure_no_active_hold(conn, archive_id)
                cur = conn.execute(
                    "UPDATE archives SET disposal_state='disposing' WHERE id=? AND disposal_state='pending_disposal'",
                    (archive_id,),
                )
                if cur.rowcount == 0:
                    state = self._archive_row(conn, archive_id)["disposal_state"]
                    raise BusinessError(f"处置状态已被并发请求改变，当前状态: {state}", 409, "state_conflict")
                task_id = conn.execute(
                    "INSERT INTO disposal_tasks(archive_id,started_by,started_at) VALUES(?,?,?)",
                    (archive_id, actor_id, now()),
                ).lastrowid
                copies = conn.execute(
                    """SELECT c.id,c.version_id,c.location FROM copies c
                       JOIN archive_versions v ON v.id=c.version_id WHERE v.archive_id=? ORDER BY c.id""",
                    (archive_id,),
                ).fetchall()
                for c in copies:
                    conn.execute(
                        "INSERT INTO disposal_copy_results(task_id,copy_id,version_id,location,updated_at) VALUES(?,?,?,?,?)",
                        (task_id, c["id"], c["version_id"], c["location"], now()),
                    )
                summary = self._purge_copies(conn, task_id, set(simulate_fail_locations or ()))
                final, state = self._finish_task(conn, archive_id, task_id, summary)
                self._audit(conn, archive_id, actor_id, "disposal.start", {"task_id": task_id, **summary})
                return {"task_id": task_id, "status": final, "archive_state": state, **summary}
            except Exception:
                conn.rollback()
                raise

    def retry_disposal(self, actor_id: str, task_id: int, simulate_fail_locations: set[str] | None = None) -> dict:
        """重试只处理未完成的副本；已完成任务按现状返回，生效保全阻止继续清退。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            task = conn.execute("SELECT * FROM disposal_tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise BusinessError("处置任务不存在", 404, "not_found")
            archive_id = task["archive_id"]
            self._access(conn, archive_id, actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                status = conn.execute("SELECT status FROM disposal_tasks WHERE id=?", (task_id,)).fetchone()[0]
                if status == "completed":
                    return {"task_id": task_id, "status": "completed", "changed": False}
                self._ensure_no_active_hold(conn, archive_id)
                cur = conn.execute(
                    "UPDATE archives SET disposal_state='disposing' WHERE id=? AND disposal_state='pending_disposal'",
                    (archive_id,),
                )
                if cur.rowcount == 0:
                    state = self._archive_row(conn, archive_id)["disposal_state"]
                    raise BusinessError(f"档案当前不在待处置区，当前状态: {state}", 409, "state_conflict")
                summary = self._purge_copies(conn, task_id, set(simulate_fail_locations or ()))
                final, state = self._finish_task(conn, archive_id, task_id, summary)
                self._audit(conn, archive_id, actor_id, "disposal.retry", {"task_id": task_id, **summary})
                return {"task_id": task_id, "status": final, "archive_state": state, "changed": True, **summary}
            except Exception:
                conn.rollback()
                raise

    def disposal_status(self, user_id: str, archive_id: int) -> dict:
        """处置状态与逐副本结果查询，含保全记录；审计保留十年。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            self._access(conn, archive_id, user)
            archive = self._archive_row(conn, archive_id)
            holds = conn.execute(
                "SELECT * FROM legal_holds WHERE archive_id=? ORDER BY id", (archive_id,)
            ).fetchall()
            tasks = conn.execute(
                "SELECT * FROM disposal_tasks WHERE archive_id=? ORDER BY id", (archive_id,)
            ).fetchall()
            return {
                "archive_id": archive_id,
                "disposal_state": archive["disposal_state"],
                "retention_until": archive["retention_until"],
                "audit_retention_years": AUDIT_RETENTION_YEARS,
                "holds": [dict(h) for h in holds],
                "tasks": [
                    dict(t) | {"copies": [dict(r) for r in conn.execute(
                        "SELECT copy_id,version_id,location,status,error,updated_at FROM disposal_copy_results WHERE task_id=? ORDER BY id",
                        (t["id"],),
                    ).fetchall()]}
                    for t in tasks
                ],
            }

    def version_lineage(self, user_id: str, version_id: int) -> dict:
        """沿迁移记录回溯来源链路，可按原路径追溯到最早版本。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], user)
            chain, current, seen = [], version_id, set()
            while True:
                m = conn.execute("SELECT * FROM migrations WHERE target_version_id=?", (current,)).fetchone()
                if not m or m["id"] in seen:
                    break
                seen.add(m["id"])
                chain.append(dict(m))
                current = m["source_version_id"]
            chain.reverse()
            return {"version_id": version_id, "archive_id": version["archive_id"], "lineage": chain}

    def prune_audit(self) -> dict:
        """审计保留十年：仅清理十年前的记录。"""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=365 * AUDIT_RETENTION_YEARS)).isoformat(timespec="seconds")
        with self.connect() as conn:
            deleted = conn.execute("DELETE FROM audit_log WHERE created_at < ?", (cutoff,)).rowcount
            return {"cutoff": cutoff, "deleted": deleted}

    def archive_status(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            self._access(conn, archive_id, user)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            versions = conn.execute("SELECT id,version,state,created_at FROM archive_versions WHERE archive_id=? ORDER BY version", (archive_id,)).fetchall()
            deadline = date.fromisoformat(archive["retention_until"])
            return {
                "archive": dict(archive),
                "days_remaining": (deadline - date.today()).days,
                "active_holds": conn.execute(
                    "SELECT COUNT(*) FROM legal_holds WHERE archive_id=? AND status='active'", (archive_id,)
                ).fetchone()[0],
                "audit_retention_years": AUDIT_RETENTION_YEARS,
                "versions": [dict(v) | {"file_count": conn.execute("SELECT COUNT(*) FROM archive_files WHERE version_id=?", (v["id"],)).fetchone()[0],
                                         "copy_count": conn.execute("SELECT COUNT(*) FROM copies WHERE version_id=?", (v["id"],)).fetchone()[0]}
                             for v in versions],
                "audit": [dict(r) | {"detail": json.loads(r["detail"])} for r in conn.execute("SELECT * FROM audit_log WHERE archive_id=? ORDER BY id", (archive_id,)).fetchall()],
            }


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
            if parts[3] == "enter-disposal":
                return self._send(200, store.enter_pending_disposal(user, archive_id))
            if parts[3] == "holds":
                d = self._body()
                version_id = d.get("version_id")
                return self._send(201, store.create_hold(user, archive_id, int(version_id) if version_id is not None else None, d.get("reason", "")))
        if len(parts) == 5 and parts[:2] == ["api", "archives"] and parts[3:] == ["disposal", "start"] and method == "POST":
            d = self._body()
            return self._send(201, store.start_disposal(user, int(parts[2]), set(d.get("simulate_fail_locations") or ())))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "status" and method == "GET":
            return self._send(200, store.archive_status(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "disposal" and method == "GET":
            return self._send(200, store.disposal_status(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "holds"] and parts[3] == "release" and method == "POST":
            return self._send(200, store.release_hold(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "disposal-tasks"] and parts[3] == "retry" and method == "POST":
            d = self._body()
            return self._send(200, store.retry_disposal(user, int(parts[2]), set(d.get("simulate_fail_locations") or ())))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "lineage" and method == "GET":
            return self._send(200, store.version_lineage(user, int(parts[2])))
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
