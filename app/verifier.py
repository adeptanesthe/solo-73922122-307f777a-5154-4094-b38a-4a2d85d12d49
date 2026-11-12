"""网页侧核验：取得见证服务最新回执，核对本地结案审计链。

判定口径（对应需求）：
* **已见证前缀是否完整**：本地链 1..W（W = 见证最新回执序号）逐条连续、
  摘要自洽，且 seq W 处的本地摘要与见证回执一致；
  - 删除已见证尾部 -> 本地缺失已见证序号 -> 不完整；
  - 篡改后重算本地摘要 -> 链头摘要与见证回执不符 -> 不完整；
* **尚未见证条数**：本地链中序号 > W 的记录数（异步投递的正常中间态，
  不算异常）；
* **异常原因**：逐条列出序号不连续 / 前项摘要不符 / 摘要与内容不符 /
  缺失已见证记录 / 链头与回执不符等。

防误报关键：先取见证回执、再读本地链。本地链只追加，见证内容又只能
来自本地链，因此该顺序下“见证序号 > 本地长度”在诚实运行中不可能发生，
并发结案（确认/回退与核验同时发生）不会造成误报。

威胁模型：仅本地数据库可能被改；见证服务及其独立存储可信。
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any

import audit_chain
import db
from config import WITNESS_TIMEOUT_SECONDS, WITNESS_URL

log = logging.getLogger("verifier")


def _fetch_latest_receipt() -> tuple[dict[str, Any] | None, str | None]:
    """从见证服务取最新回执。返回 (回执, 错误信息)。"""
    req = urllib.request.Request(f"{WITNESS_URL}/witness/latest", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=WITNESS_TIMEOUT_SECONDS) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def verify() -> dict[str, Any]:
    now = time.time()

    # 1. 先取见证最新回执（可信方），再读本地链 —— 顺序保证并发结案不误报
    receipt, witness_error = _fetch_latest_receipt()
    rows = db.list_audit_chain()
    receipt_seqs = db.get_receipt_seqs()

    # 2. 本地链内部一致性：序号连续、前项摘要衔接、摘要与内容相符
    anomalies: list[dict[str, Any]] = []
    by_seq: dict[int, dict[str, Any]] = {}
    expected = 1
    prev_hash = audit_chain.GENESIS_HASH
    for row in rows:
        seq = row["seq"]
        if seq != expected:
            anomalies.append({
                "seq": seq,
                "reason": f"序号不连续：期望 {expected}，实际 {seq}（本地链可能被删改）",
            })
            expected = seq  # 重新对齐，继续检查后续记录
        if row["prev_hash"] != prev_hash:
            anomalies.append({
                "seq": seq,
                "reason": f"seq {seq} 的前项摘要与上一条记录的摘要不符",
            })
        if audit_chain.hash_record(row) != row["hash"]:
            anomalies.append({
                "seq": seq,
                "reason": f"seq {seq} 的记录摘要与内容不符（本地记录疑似被篡改）",
            })
        by_seq[seq] = row
        prev_hash = row["hash"]
        expected = seq + 1

    # 3. 与见证回执比对
    witness_seq = 0
    witnessed_prefix_complete: bool | None = None  # None = 见证不可达，无法判定
    unwitnessed_count: int | None = None
    if receipt is not None:
        witness_seq = int(receipt.get("seq") or 0)
        receipt_hash = receipt.get("record_hash")
        prefix_broken = any(
            a["seq"] is not None and a["seq"] <= witness_seq for a in anomalies
        )
        if witness_seq > 0:
            row_w = by_seq.get(witness_seq)
            if row_w is None:
                anomalies.append({
                    "seq": witness_seq,
                    "reason": (
                        f"本地缺失已见证记录 seq {witness_seq}"
                        "（已见证尾部被删除或本地库被重置）"
                    ),
                })
                prefix_broken = True
            elif row_w["hash"] != receipt_hash:
                anomalies.append({
                    "seq": witness_seq,
                    "reason": (
                        f"已见证前缀末端 seq {witness_seq} 的本地摘要与见证回执不符"
                        "（本地链疑似被篡改后重算）"
                    ),
                })
                prefix_broken = True
        witnessed_prefix_complete = not prefix_broken
        unwitnessed_count = sum(1 for r in rows if r["seq"] > witness_seq)

    # 4. 汇总判定
    if anomalies:
        verdict = "anomaly"
    elif receipt is None:
        verdict = "witness_unreachable"
    elif not rows and witness_seq == 0:
        verdict = "empty"
    elif unwitnessed_count and unwitnessed_count > 0:
        verdict = "pending"
    else:
        verdict = "ok"

    local_head = rows[-1]["hash"] if rows else None
    recent = [
        {
            "seq": r["seq"],
            "change_id": r["change_id"],
            "result": r["result"],
            "happened_at": r["happened_at"],
            "hash": r["hash"],
            "witnessed": (r["seq"] <= witness_seq) if receipt is not None else None,
            "receipt_cached": r["seq"] in receipt_seqs,
        }
        for r in rows[-10:][::-1]
    ]

    return {
        "now": now,
        "verdict": verdict,
        "witness": {
            "url": WITNESS_URL,
            "reachable": receipt is not None,
            "error": witness_error,
            "latest": receipt,
        },
        "local": {
            "length": len(rows),
            "head_hash": local_head,
            "receipts_cached": len(receipt_seqs),
        },
        "witnessed_prefix": {
            "seq": witness_seq,
            "complete": witnessed_prefix_complete,
        },
        "unwitnessed_count": unwitnessed_count,
        "anomalies": anomalies,
        "recent_audit": recent,
    }
