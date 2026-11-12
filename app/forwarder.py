"""独立投递进程：把本地结案审计链按序送往本地见证服务。

设计要点（对应需求）：
* **按序送往**：严格按 seq 升序逐条投递，见证服务也只接受顺序记录；
* **续投**：投递进度以见证服务的最新回执为准（可信方），本进程或任一
  服务重启后，从“见证最新序号 + 1”继续，绝不依赖易失状态；
* **丢回执**：见证已保存而回执丢失（网络中断/进程被杀/本地缓存被清）时，
  重发同一条记录会拿到**原回执**（见证幂等）；本地回执缓存缺失的序号
  会周期性向见证补拉；
* **解耦回退**：本进程与看护进程、Web 进程完全独立，见证再慢甚至不可达
  也只影响投递，绝不拖住 30 秒确认窗口与超时回退；
* **永不退出**：任何单轮错误都只记录日志并退避重试。
"""
from __future__ import annotations

import json
import logging
import os
import signal
import time
import urllib.error
import urllib.request

import db
from config import FORWARDER_INTERVAL_SECONDS, WITNESS_TIMEOUT_SECONDS, WITNESS_URL

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [forwarder] %(levelname)s %(message)s",
)
log = logging.getLogger("forwarder")

BATCH_SIZE = 500

_running = True


def _stop(signum, _frame) -> None:  # pragma: no cover - 信号路径
    global _running
    _running = False
    log.info("收到信号 %s，准备退出", signum)


class WitnessRejected(RuntimeError):
    """见证服务拒绝了记录（本地链与见证不一致，核验页会显示异常）。"""


def _http(method: str, url: str, payload: dict | None = None) -> tuple[int, dict]:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=WITNESS_TIMEOUT_SECONDS) as resp:
            raw = resp.read() or b"{}"
            return resp.status, json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads((exc.read() or b"{}").decode("utf-8"))
        except Exception:
            body = {}
        return exc.code, body


def _repair_receipts(witness_seq: int) -> None:
    """补拉本地缺失的回执缓存（见证保存后丢回执的恢复路径）。"""
    if witness_seq <= 0:
        return
    for seq in db.missing_receipt_seqs(witness_seq):
        status, body = _http("GET", f"{WITNESS_URL}/witness/receipts/{seq}")
        if status == 200 and body.get("seq") == seq:
            db.store_receipt(seq, body)
            log.info("已补拉回执 seq=%d", seq)
        else:
            log.warning("回执补拉失败 seq=%d：HTTP %s %s", seq, status, body)


def run_cycle() -> None:
    """单轮投递：对齐见证进度 -> 补拉回执 -> 按序投递新记录。"""
    status, latest = _http("GET", f"{WITNESS_URL}/witness/latest")
    if status != 200:
        raise RuntimeError(f"获取见证最新回执失败：HTTP {status} {latest}")
    witness_seq = int(latest.get("seq") or 0)

    _repair_receipts(witness_seq)

    rows = db.list_audit_after(witness_seq, limit=BATCH_SIZE)
    expected = witness_seq + 1
    for row in rows:
        if row["seq"] != expected:
            # 本地链出现缺口（可能被删改）：停止投递，核验页负责告警
            log.error(
                "本地审计链序号不连续：期望 %d，实为 %d；暂停投递，等待核查",
                expected,
                row["seq"],
            )
            return
        record = {
            "seq": row["seq"],
            "change_id": row["change_id"],
            "previous_ports": row["previous_ports"],
            "requested_ports": row["requested_ports"],
            "result": row["result"],
            "happened_at": row["happened_at"],
            "detail": row["detail"],
            "prev_hash": row["prev_hash"],
            "hash": row["hash"],
        }
        status, body = _http("POST", f"{WITNESS_URL}/witness/records", record)
        if status == 200 and body.get("ok"):
            db.store_receipt(row["seq"], body["receipt"])
            if not body.get("duplicate"):
                log.info(
                    "审计记录 seq=%d（变更单 #%s, %s）已见证",
                    row["seq"], row["change_id"], row["result"],
                )
            expected += 1
        else:
            raise WitnessRejected(
                f"seq {row['seq']} 被见证拒绝：HTTP {status} {body.get('error') or body}"
            )


def main() -> None:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    db.init_db()
    log.info(
        "投递进程启动：见证服务 %s，轮询间隔 %.1fs",
        WITNESS_URL,
        FORWARDER_INTERVAL_SECONDS,
    )

    backoff = FORWARDER_INTERVAL_SECONDS
    while _running:
        stop_file = os.environ.get("FORWARDER_STOP_FILE")
        if stop_file and os.path.exists(stop_file):
            log.info("检测到停止文件 %s，退出", stop_file)
            break
        try:
            run_cycle()
            backoff = FORWARDER_INTERVAL_SECONDS
        except WitnessRejected as exc:
            # 本地链与见证不一致：持续重试无意义，放慢轮询，核验页会显示异常
            log.error("%s（将持续观察，暂不投递后续记录）", exc)
            backoff = min(30.0, max(5.0, backoff * 2))
        except Exception as exc:  # 见证不可达/重启/慢响应等：退避后重试
            log.error("投递失败（将重试续投）: %s", exc)
            backoff = min(30.0, max(2.0, backoff * 2))
        deadline = time.time() + backoff
        while _running and time.time() < deadline:
            time.sleep(min(0.2, max(0.0, deadline - time.time())))

    log.info("投递进程退出")


if __name__ == "__main__":
    main()
