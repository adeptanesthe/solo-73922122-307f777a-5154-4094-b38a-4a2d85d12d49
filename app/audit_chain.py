"""结案审计链：记录规范化与 SHA-256 摘要计算（纯标准库）。

Web 进程（写链/核验）、独立投递进程、本地见证服务三方共用同一套
规范化规则，确保同一记录在任何一处算出的摘要完全一致。

链式结构：每条结案记录携带连续序号 ``seq`` 与前一条记录的摘要
``prev_hash``，并对自身内容（含 prev_hash）计算 SHA-256 得到 ``hash``，
串成只能追加的哈希链；首条记录的 ``prev_hash`` 固定为 ``GENESIS_HASH``。
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

# 首条记录的前项摘要（创世）
GENESIS_HASH = "0" * 64

# 参与摘要计算的内容字段（不含 hash 本身）
RECORD_FIELDS = (
    "seq",
    "change_id",
    "previous_ports",
    "requested_ports",
    "result",
    "happened_at",
    "detail",
    "prev_hash",
)


def canonical_json(obj: Any) -> str:
    """确定性 JSON 序列化：键排序、紧凑分隔符、UTF-8 原文。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canon_ports(ports: Iterable[int]) -> list[int]:
    """端口列表规范化：去重、转 int、升序。"""
    return sorted({int(p) for p in ports})


def ports_to_text(ports: Iterable[int]) -> str:
    """端口列表的规范存储文本（审计表中的存储格式）。"""
    return canonical_json(canon_ports(ports))


def ports_from_text(text: str) -> list[int]:
    return canon_ports(json.loads(text))


def hash_record(record: dict[str, Any]) -> str:
    """对记录内容字段（含 prev_hash，不含 hash）计算 SHA-256 摘要。"""
    content = {k: record[k] for k in RECORD_FIELDS}
    return hashlib.sha256(canonical_json(content).encode("utf-8")).hexdigest()


def build_record(
    seq: int,
    change_id: int,
    previous_ports: Iterable[int],
    requested_ports: Iterable[int],
    result: str,
    happened_at: float,
    detail: str | None,
    prev_hash: str,
) -> dict[str, Any]:
    """构造一条规范化审计记录（含 hash 字段）。"""
    record: dict[str, Any] = {
        "seq": int(seq),
        "change_id": int(change_id),
        "previous_ports": canon_ports(previous_ports),
        "requested_ports": canon_ports(requested_ports),
        "result": str(result),
        "happened_at": float(happened_at),
        "detail": None if detail is None else str(detail),
        "prev_hash": str(prev_hash),
    }
    record["hash"] = hash_record(record)
    return record
