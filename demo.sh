#!/usr/bin/env bash
# 端到端演示脚本（在能访问已发布端口的机器上运行，容器宿主即可）
# 用法: ./demo.sh
# 可选: TAMPER_DEMO=1 ./demo.sh   末尾追加“篡改本地库 -> 核验报异常”演示（会留下异常状态，重置见 README）
set -u
WEB="${WEB:-http://127.0.0.1:8080}"
ECHO="${ECHO:-http://127.0.0.1:8090}"
WITNESS="${WITNESS:-http://127.0.0.1:9000}"
WINDOW="${WINDOW:-30}"

hr() { printf '\n========== %s ==========\n' "$1"; }

hr "0. 初始状态：网页与回显服务均在白名单内"
curl -s "$WEB/api/config"; echo
curl -s "$WEB/api/status" | python3 -m json.tool | sed -n '1,20p'
curl -s "$ECHO/hello" | head -5

hr "1. 应用新白名单（仅回显端口 8090，移除网页端口 8080）——模拟误封管理网页"
APPLY=$(curl -s -X POST "$WEB/api/apply" -H 'Content-Type: application/json' -d '{"ports":[8090]}')
echo "$APPLY" | python3 -m json.tool
CID=$(echo "$APPLY" | python3 -c 'import sys,json;print(json.load(sys.stdin)["change_id"])')

hr "2. 规则已生效：网页失联（2 秒超时即失败），回显服务仍可通"
curl -s --max-time 2 "$WEB/api/status" && echo "网页仍可访问（异常）" || echo ">>> 网页已失联（预期行为）"
curl -s --max-time 3 "$ECHO/hello" | head -3

hr "3. 等待看护进程在 ${WINDOW}s 窗口到期后自动回退（多等 3 秒）…"
sleep $((WINDOW + 3))

hr "4. 网页自动恢复访问，白名单回到应用前快照"
curl -s "$WEB/api/status" | python3 -m json.tool | sed -n '1,12p'

hr "5. 再来一次并在窗口内确认（演示确认保留）"
APPLY=$(curl -s -X POST "$WEB/api/apply" -H 'Content-Type: application/json' -d '{"ports":[8080,8090,9000]}')
CID=$(echo "$APPLY" | python3 -c 'import sys,json;print(json.load(sys.stdin)["change_id"])')
echo "变更单 #$CID 已应用，立即确认："
curl -s -X POST "$WEB/api/confirm" -H 'Content-Type: application/json' \
  -d "{\"change_id\":$CID}" | python3 -m json.tool

hr "6. 待确认期间拒绝新变更 / 旧单确认无效 的校验"
curl -s -X POST "$WEB/api/apply" -H 'Content-Type: application/json' -d '{"ports":[22]}' | python3 -m json.tool
curl -s -X POST "$WEB/api/confirm" -H 'Content-Type: application/json' -d "{\"change_id\":$CID}" | python3 -m json.tool

hr "7. 结案审计链核验：回退与确认均已记账并送往本地见证服务"
sleep 2   # 留给投递进程一点补投时间（异步投递，正常）
curl -s "$WEB/api/audit/verify" | python3 -m json.tool

hr "8. 见证服务最新回执（独立容器、独立存储，威胁模型中可信）"
curl -s "$WITNESS/witness/latest" | python3 -m json.tool

if [ "${TAMPER_DEMO:-0}" = "1" ]; then
  hr "9. 篡改演示（威胁模型：仅本地数据库被改）：删除已见证尾部 + 篡改后重算本地摘要"
  MODE="${TAMPER_MODE:-delete_tail}"
  docker compose exec -T port-mgmt python - "$MODE" <<'PY'
import json, sqlite3, sys, os
sys.path.insert(0, "/app")
import audit_chain
mode = sys.argv[1]
conn = sqlite3.connect(os.environ.get("DB_PATH", "/data/mgmt.db"))
conn.row_factory = sqlite3.Row
rows = [dict(r) for r in conn.execute("SELECT * FROM audit_chain ORDER BY seq")]
if not rows:
    print("审计链为空，先跑前面的演示步骤"); sys.exit(0)
if mode == "delete_tail":
    victim = rows[-1]["seq"]
    conn.execute("DELETE FROM audit_chain WHERE seq = ?", (victim,))
    conn.execute("DELETE FROM witness_receipts WHERE seq = ?", (victim,))
    conn.commit()
    print(f">>> 已删除本地已见证的尾部记录 seq={victim}（并清掉本地回执缓存）")
else:
    # 篡改中间一条记录的结果，并重算其后所有本地摘要（攻击者全覆盖）
    victim = rows[len(rows)//2]["seq"]
    conn.execute("UPDATE audit_chain SET result = 'confirmed' WHERE seq = ?", (victim,))
    rows = [dict(r) for r in conn.execute("SELECT * FROM audit_chain ORDER BY seq")]
    prev = audit_chain.GENESIS_HASH
    for r in rows:
        rec = {"seq": r["seq"], "change_id": r["change_id"],
               "previous_ports": json.loads(r["previous_ports"]),
               "requested_ports": json.loads(r["requested_ports"]),
               "result": r["result"], "happened_at": r["happened_at"],
               "detail": r["detail"], "prev_hash": prev}
        h = audit_chain.hash_record(rec)
        conn.execute("UPDATE audit_chain SET prev_hash = ?, hash = ? WHERE seq = ?",
                     (prev, h, r["seq"]))
        prev = h
    conn.commit()
    print(f">>> 已篡改 seq={victim} 的结果并重算全部本地摘要（本地链内部完全自洽）")
PY
  sleep 2
  echo "--- 篡改后核验结果（应报异常，已见证前缀不完整）---"
  curl -s "$WEB/api/audit/verify" | python3 -m json.tool
  echo
  echo ">>> 演示结束：本地库已被篡改，核验将持续报异常。"
  echo ">>> 重置演示环境：docker compose down -v && docker compose up --build"
fi

hr "完成。浏览器打开 $WEB 可使用图形界面重复以上流程（含结案记录核验卡片）。"
