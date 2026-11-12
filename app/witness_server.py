"""本地见证服务（独立容器、独立存储；威胁模型中唯一可信方）。

职责：
* 按序接收结案审计记录并**持久保存记录与回执**（独立 SQLite 卷）；
* 幂等：同序号同内容 -> 返回**原回执**（首次保存时生成的那个）；
* 拒绝：同序号异内容、序号跳跃/乱序、前项摘要不符、记录摘要与内容不符；
* 提供最新回执与指定序号回执的查询，供网页核验与投递进程补拉。

仅依赖标准库 + audit_chain（摘要规范化），不 import 业务模块，
保持可信计算基最小。记录与回执的写入在同一个 SQLite 事务中提交。
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import audit_chain

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [witness] %(levelname)s %(message)s",
)
log = logging.getLogger("witness")

PORT = int(os.getenv("WITNESS_PORT", "9000"))
DB_PATH = os.getenv("WITNESS_DB_PATH", "/witness-data/witness.db")
# 演示钩子：人为放慢见证响应，验证“慢见证不拖住 30 秒回退”
DELAY_SECONDS = float(os.getenv("WITNESS_DELAY_SECONDS", "0"))

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS records (
                seq         INTEGER PRIMARY KEY,
                payload     TEXT NOT NULL,   -- 记录的规范 JSON 全文
                hash        TEXT NOT NULL,   -- 记录摘要（链头）
                received_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS receipts (
                seq        INTEGER PRIMARY KEY,
                receipt    TEXT NOT NULL,    -- 回执 JSON（含序号与记录摘要）
                created_at REAL NOT NULL
            );
            """
        )
        conn.commit()
        _conn = conn
    return _conn


def _latest_seq(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(seq) AS m FROM records").fetchone()
    return int(row["m"] or 0)


def _make_receipt(seq: int, record_hash: str) -> dict:
    return {
        "seq": seq,
        "record_hash": record_hash,
        "witnessed_at": time.time(),
        "witness": "local-witness",
    }


def accept_record(body: dict) -> tuple[int, dict]:
    """接收一条审计记录。返回 (HTTP 状态码, 响应体)。"""
    # 1. 字段与类型校验
    try:
        record = audit_chain.build_record(
            seq=body["seq"],
            change_id=body["change_id"],
            previous_ports=body["previous_ports"],
            requested_ports=body["requested_ports"],
            result=body["result"],
            happened_at=body["happened_at"],
            detail=body.get("detail"),
            prev_hash=body["prev_hash"],
        )
        submitted_hash = str(body["hash"])
    except (KeyError, TypeError, ValueError) as exc:
        return 400, {"ok": False, "error": f"记录字段缺失或类型错误: {exc}"}

    # 2. 记录摘要必须与内容一致（防“内容改了摘要没重算/乱算”）
    if record["hash"] != submitted_hash:
        return 400, {"ok": False, "error": "记录摘要与内容不符，拒绝"}

    seq = record["seq"]
    with _lock:
        conn = _db()
        # 3. 同序号：同内容 -> 返回原回执（幂等）；异内容 -> 拒绝
        existing = conn.execute(
            "SELECT hash FROM records WHERE seq = ?", (seq,)
        ).fetchone()
        if existing is not None:
            if existing["hash"] == record["hash"]:
                row = conn.execute(
                    "SELECT receipt FROM receipts WHERE seq = ?", (seq,)
                ).fetchone()
                receipt = json.loads(row["receipt"]) if row else _make_receipt(seq, record["hash"])
                return 200, {"ok": True, "duplicate": True, "receipt": receipt}
            return 409, {
                "ok": False,
                "error": f"seq {seq} 已保存不同内容（本地链与见证不一致），拒绝",
            }

        # 4. 必须严格按序：只接受 下一条 = 当前最大序号 + 1
        last = _latest_seq(conn)
        if seq != last + 1:
            return 409, {
                "ok": False,
                "error": f"序号不连续：期望 {last + 1}，收到 {seq}，拒绝",
            }

        # 5. 前项摘要必须与已保存的链尾一致
        if seq == 1:
            if record["prev_hash"] != audit_chain.GENESIS_HASH:
                return 409, {"ok": False, "error": "首条记录的前项摘要不是创世值，拒绝"}
        else:
            prev = conn.execute(
                "SELECT hash FROM records WHERE seq = ?", (seq - 1,)
            ).fetchone()
            if prev is None or prev["hash"] != record["prev_hash"]:
                return 409, {"ok": False, "error": "前项摘要与已保存链尾不符，拒绝"}

        # 6. 记录与回执在同一事务中持久化
        receipt = _make_receipt(seq, record["hash"])
        now = time.time()
        conn.execute(
            "INSERT INTO records(seq, payload, hash, received_at) VALUES (?, ?, ?, ?)",
            (seq, audit_chain.canonical_json(record), record["hash"], now),
        )
        conn.execute(
            "INSERT INTO receipts(seq, receipt, created_at) VALUES (?, ?, ?)",
            (seq, json.dumps(receipt, ensure_ascii=False, sort_keys=True), now),
        )
        conn.commit()
        log.info("已见证审计记录 seq=%d（变更单 #%s, %s）", seq, record["change_id"], record["result"])
        return 200, {"ok": True, "duplicate": False, "receipt": receipt}


def latest_receipt() -> dict:
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT receipt FROM receipts ORDER BY seq DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return {"seq": 0, "record_hash": None, "witnessed_at": None, "witness": "local-witness"}
    return json.loads(row["receipt"])


def receipt_at(seq: int) -> dict | None:
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT receipt FROM receipts WHERE seq = ?", (seq,)
        ).fetchone()
    return json.loads(row["receipt"]) if row else None


class Handler(BaseHTTPRequestHandler):
    server_version = "LocalWitness/1.0"

    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _maybe_delay(self) -> None:
        if DELAY_SECONDS > 0:
            time.sleep(DELAY_SECONDS)

    def do_POST(self) -> None:  # noqa: N802 - stdlib 命名
        self._maybe_delay()
        if self.path != "/witness/records":
            self._send(404, {"ok": False, "error": "未知路径"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"ok": False, "error": f"请求体不是合法 JSON: {exc}"})
            return
        status, payload = accept_record(body)
        self._send(status, payload)

    def do_GET(self) -> None:  # noqa: N802 - stdlib 命名
        self._maybe_delay()
        if self.path == "/health":
            self._send(200, {"ok": True})
            return
        if self.path == "/witness/latest":
            self._send(200, latest_receipt())
            return
        if self.path.startswith("/witness/receipts/"):
            try:
                seq = int(self.path.rsplit("/", 1)[1])
            except ValueError:
                self._send(400, {"ok": False, "error": "序号必须是整数"})
                return
            receipt = receipt_at(seq)
            if receipt is None:
                self._send(404, {"ok": False, "error": f"seq {seq} 不存在"})
            else:
                self._send(200, receipt)
            return
        self._send(404, {"ok": False, "error": "未知路径"})

    def log_message(self, fmt: str, *args) -> None:  # 安静一点
        log.debug("%s %s", self.address_string(), fmt % args)


def main() -> None:
    _db()  # 启动即初始化独立存储
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log.info("本地见证服务启动：0.0.0.0:%d，存储 %s", PORT, DB_PATH)
    # 可选的停止文件（运维/测试钩子）：文件出现即干净退出
    stop_file = os.environ.get("WITNESS_STOP_FILE")
    if stop_file:
        def _watch() -> None:
            while True:
                if os.path.exists(stop_file):
                    log.info("检测到停止文件 %s，退出", stop_file)
                    server.shutdown()
                    return
                time.sleep(0.5)

        threading.Thread(target=_watch, daemon=True).start()
    server.serve_forever()


if __name__ == "__main__":
    main()
