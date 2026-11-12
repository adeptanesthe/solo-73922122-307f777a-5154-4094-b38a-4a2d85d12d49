"""SQLite 持久层。

三类持久数据：
* state：已确认规则（当前白名单），整套服务重启后据此先恢复再开放网页；
* changes：每次“应用”产生的变更单，含应用前快照与完整生命周期状态；
* audit_chain：结案审计链。确认 / 超时回退 / 应用失败三类终态与对应
  审计记录必须在**同一个 SQLite 事务**中落库（本文件内所有终态函数
  均满足），记录变更 ID、前后端口、结果与时间，并以连续序号 +
  SHA-256 前项摘要串成只能追加的哈希链。

另存 witness_receipts：本地见证服务回执的缓存（仅加速展示，丢回执时
由投递进程向见证服务补拉，核验一律以见证服务的最新回执为准）。

Web 进程、看护进程、投递进程各自打开连接，通过 WAL + BEGIN IMMEDIATE
串行化写入。
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator

import audit_chain
from config import DB_PATH

# 变更单状态机
PENDING = "pending"      # 已应用、等待确认
CONFIRMED = "confirmed"  # 已在窗口内确认
EXPIRED = "expired"      # 超时未确认，看护进程已回退
FAILED = "failed"        # 应用失败（规则未生效，旧规则保留）

STATE_CONFIRMED_PORTS = "confirmed_ports"


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS state (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS changes (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                requested_ports    TEXT NOT NULL,  -- JSON 数组：本次请求的白名单
                previous_ports     TEXT NOT NULL,  -- JSON 数组：应用前已确认快照
                status             TEXT NOT NULL,
                created_at         REAL NOT NULL,  -- 应用生效时刻（epoch 秒）
                expires_at         REAL NOT NULL,  -- 确认截止时刻
                confirmed_at       REAL,
                finalized_at       REAL,
                detail             TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_changes_status ON changes(status);
            -- 跨进程硬约束：任意时刻最多一张待确认(pending)变更单。
            -- 进程内锁之外的第二道防线：并发应用时后到者直接被数据库拒绝。
            CREATE TRIGGER IF NOT EXISTS trg_changes_one_pending
            BEFORE INSERT ON changes
            WHEN NEW.status = 'pending'
                 AND EXISTS (SELECT 1 FROM changes WHERE status = 'pending')
            BEGIN
                SELECT RAISE(ABORT, 'already has a pending change');
            END;
            -- 结案审计链：只能追加，序号连续，prev_hash 指向上一条的 hash
            CREATE TABLE IF NOT EXISTS audit_chain (
                seq             INTEGER PRIMARY KEY,  -- 连续序号，从 1 开始
                change_id       INTEGER NOT NULL,     -- 变更单 ID
                previous_ports  TEXT NOT NULL,        -- 规范 JSON：变更前端口
                requested_ports TEXT NOT NULL,        -- 规范 JSON：本次目标端口
                result          TEXT NOT NULL,        -- confirmed / expired / failed
                happened_at     REAL NOT NULL,        -- 结案时刻（epoch 秒）
                detail          TEXT,
                prev_hash       TEXT NOT NULL,        -- 上一条记录的 SHA-256
                hash            TEXT NOT NULL         -- 本条内容的 SHA-256
            );
            -- 见证回执的本地缓存（见证服务才是回执的权威存储）
            CREATE TABLE IF NOT EXISTS witness_receipts (
                seq       INTEGER PRIMARY KEY,
                receipt   TEXT NOT NULL,  -- 见证服务返回的回执 JSON
                stored_at REAL NOT NULL
            );
            """
        )
        conn.commit()


# ---------------------------------------------------------------------------
# 已确认规则
# ---------------------------------------------------------------------------

def get_confirmed_ports() -> list[int] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM state WHERE key = ?", (STATE_CONFIRMED_PORTS,)
        ).fetchone()
    if row is None:
        return None
    return json.loads(row["value"])


def set_confirmed_ports(ports: list[int]) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO state(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (STATE_CONFIRMED_PORTS, json.dumps(sorted(set(ports)))),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# 变更单
# ---------------------------------------------------------------------------

def get_pending_change() -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM changes WHERE status = ? ORDER BY id DESC LIMIT 1",
            (PENDING,),
        ).fetchone()
    return dict(row) if row else None


def insert_change(
    requested_ports: list[int],
    previous_ports: list[int],
    created_at: float,
    expires_at: float,
    status: str,
    detail: str | None = None,
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO changes(requested_ports, previous_ports, status, "
            "created_at, expires_at, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (
                json.dumps(sorted(set(requested_ports))),
                json.dumps(sorted(set(previous_ports))),
                status,
                created_at,
                expires_at,
                detail,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def get_change(change_id: int) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM changes WHERE id = ?", (change_id,)
        ).fetchone()
    return dict(row) if row else None


def list_recent_changes(limit: int = 10) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM changes ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# 终态收口：状态变更与审计记录在同一事务中落库
# ---------------------------------------------------------------------------

def _append_audit_locked(
    conn: sqlite3.Connection,
    change_id: int,
    previous_ports_json: str,
    requested_ports_json: str,
    result: str,
    happened_at: float,
    detail: str | None,
) -> dict[str, Any]:
    """在当前事务内追加一条审计链记录（调用方须已 BEGIN IMMEDIATE）。

    序号与 prev_hash 取自链尾；由于所有写链路径都持有 BEGIN IMMEDIATE
    写锁，序号的连续性由数据库串行化保证。
    """
    tail = conn.execute(
        "SELECT seq, hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    if tail is None:
        seq, prev_hash = 1, audit_chain.GENESIS_HASH
    else:
        seq, prev_hash = int(tail["seq"]) + 1, tail["hash"]
    record = audit_chain.build_record(
        seq=seq,
        change_id=change_id,
        previous_ports=json.loads(previous_ports_json),
        requested_ports=json.loads(requested_ports_json),
        result=result,
        happened_at=happened_at,
        detail=detail,
        prev_hash=prev_hash,
    )
    conn.execute(
        "INSERT INTO audit_chain(seq, change_id, previous_ports, requested_ports, "
        "result, happened_at, detail, prev_hash, hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            record["seq"],
            record["change_id"],
            audit_chain.ports_to_text(record["previous_ports"]),
            audit_chain.ports_to_text(record["requested_ports"]),
            record["result"],
            record["happened_at"],
            record["detail"],
            record["prev_hash"],
            record["hash"],
        ),
    )
    return record


def confirm_change(
    change_id: int, when: float, new_confirmed_ports: list[int] | None = None
) -> bool:
    """仅当变更单仍为 pending 时确认成功（行锁内完成，避免与看护进程竞争）。

    确认终态、审计记录、新的已确认白名单在同一事务提交。
    """
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM changes WHERE id = ?", (change_id,)
        ).fetchone()
        if row is None or row["status"] != PENDING:
            conn.rollback()
            return False
        conn.execute(
            "UPDATE changes SET status = ?, confirmed_at = ?, finalized_at = ? "
            "WHERE id = ?",
            (CONFIRMED, when, when, change_id),
        )
        _append_audit_locked(
            conn,
            change_id,
            row["previous_ports"],
            row["requested_ports"],
            CONFIRMED,
            when,
            "确认窗口内确认，白名单固化",
        )
        if new_confirmed_ports is not None:
            conn.execute(
                "INSERT INTO state(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (STATE_CONFIRMED_PORTS, json.dumps(sorted(set(new_confirmed_ports)))),
            )
        conn.commit()
        return True


def mark_expired_if_pending(change_id: int, when: float, detail: str) -> bool:
    """仅当单子仍为 pending 时标记 expired（与确认路径竞争时的安全收口）。

    回退终态与审计记录在同一事务提交。返回 True 表示本调用赢得了状态机；
    False 表示单子已被确认，回退方必须放弃覆盖并把 nft 恢复为已确认基线。
    """
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM changes WHERE id = ?", (change_id,)
        ).fetchone()
        if row is None or row["status"] != PENDING:
            conn.rollback()
            return False
        conn.execute(
            "UPDATE changes SET status = ?, finalized_at = ?, detail = ? WHERE id = ?",
            (EXPIRED, when, detail, change_id),
        )
        _append_audit_locked(
            conn,
            change_id,
            row["previous_ports"],
            row["requested_ports"],
            EXPIRED,
            when,
            detail,
        )
        conn.commit()
        return True


def mark_failed(change_id: int, when: float | None = None, detail: str | None = None) -> bool:
    """应用失败的终态收口：状态与审计记录在同一事务提交。"""
    happened_at = when if when is not None else time.time()
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM changes WHERE id = ?", (change_id,)
        ).fetchone()
        if row is None or row["status"] != PENDING:
            conn.rollback()
            return False
        conn.execute(
            "UPDATE changes SET status = ?, finalized_at = ?, "
            "detail = COALESCE(?, detail) WHERE id = ?",
            (FAILED, happened_at, detail, change_id),
        )
        _append_audit_locked(
            conn,
            change_id,
            row["previous_ports"],
            row["requested_ports"],
            FAILED,
            happened_at,
            detail,
        )
        conn.commit()
        return True


def expire_all_pending(reason: str, when: float) -> list[int]:
    """启动恢复时使用：把所有遗留 pending 单标记为 expired，返回其 id 列表。

    每张单子的终态与各自审计记录都在同一个事务中提交。
    """
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            "SELECT * FROM changes WHERE status = ? ORDER BY id", (PENDING,)
        ).fetchall()
        ids = [int(r["id"]) for r in rows]
        for row in rows:
            conn.execute(
                "UPDATE changes SET status = ?, finalized_at = ?, detail = ? "
                "WHERE id = ?",
                (EXPIRED, when, reason, row["id"]),
            )
            _append_audit_locked(
                conn,
                row["id"],
                row["previous_ports"],
                row["requested_ports"],
                EXPIRED,
                when,
                reason,
            )
        conn.commit()
    return ids


# ---------------------------------------------------------------------------
# 审计链读取（投递进程与核验页使用）
# ---------------------------------------------------------------------------

def _audit_row_to_record(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "seq": int(row["seq"]),
        "change_id": int(row["change_id"]),
        "previous_ports": audit_chain.ports_from_text(row["previous_ports"]),
        "requested_ports": audit_chain.ports_from_text(row["requested_ports"]),
        "result": row["result"],
        "happened_at": float(row["happened_at"]),
        "detail": row["detail"],
        "prev_hash": row["prev_hash"],
        "hash": row["hash"],
    }


def list_audit_chain() -> list[dict[str, Any]]:
    """整条审计链（按序号升序）。审计链只追加，任一快照都是一致前缀。"""
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM audit_chain ORDER BY seq ASC").fetchall()
    return [_audit_row_to_record(r) for r in rows]


def list_audit_after(seq: int, limit: int = 500) -> list[dict[str, Any]]:
    """序号大于 seq 的审计记录（升序），供投递进程续投。"""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_chain WHERE seq > ? ORDER BY seq ASC LIMIT ?",
            (seq, limit),
        ).fetchall()
    return [_audit_row_to_record(r) for r in rows]


# ---------------------------------------------------------------------------
# 见证回执的本地缓存
# ---------------------------------------------------------------------------

def store_receipt(seq: int, receipt: dict[str, Any]) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO witness_receipts(seq, receipt, stored_at) VALUES (?, ?, ?) "
            "ON CONFLICT(seq) DO UPDATE SET receipt = excluded.receipt, "
            "stored_at = excluded.stored_at",
            (int(seq), json.dumps(receipt, ensure_ascii=False, sort_keys=True), time.time()),
        )
        conn.commit()


def get_receipt_seqs() -> set[int]:
    with get_conn() as conn:
        rows = conn.execute("SELECT seq FROM witness_receipts").fetchall()
    return {int(r["seq"]) for r in rows}


def missing_receipt_seqs(upto_seq: int, limit: int = 200) -> list[int]:
    """1..upto_seq 中本地缺失回执缓存的序号（丢回执后的补拉清单）。"""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT seq FROM witness_receipts WHERE seq <= ?", (upto_seq,)
        ).fetchall()
    have = {int(r["seq"]) for r in rows}
    missing = [s for s in range(1, upto_seq + 1) if s not in have]
    return missing[:limit]
