"""Approval + audit dashboard (FastAPI). Run: agent-firewall dashboard --config firewall.yaml"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .audit import AuditLog


def create_app(db_path: str) -> FastAPI:
    audit = AuditLog(db_path)
    app = FastAPI(title="agent-firewall dashboard")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return PAGE

    @app.get("/api/stats")
    def stats() -> dict:
        return audit.stats()

    @app.get("/api/events")
    def events(limit: int = 200) -> list[dict]:
        return audit.events(limit=limit)

    @app.get("/api/approvals")
    def approvals(status: str | None = None) -> list[dict]:
        return audit.approvals(status=status)

    @app.post("/api/approvals/{aid}/{verdict}")
    def decide(aid: str, verdict: str) -> dict:
        if verdict not in ("approve", "deny"):
            raise HTTPException(400, "verdict must be approve or deny")
        if not audit.decide(aid, verdict == "approve", by="dashboard"):
            raise HTTPException(409, "approval not pending (already decided or expired)")
        return {"id": aid, "status": "approved" if verdict == "approve" else "denied"}

    return app


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>agent-firewall</title>
<style>
:root{--bg:#0f1115;--panel:#171a21;--line:#262b36;--text:#e6e8ee;--muted:#8b93a7;--ok:#3fb68b;--warn:#e0a63a;--bad:#e5534b;--accent:#6c8cff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
header{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px}
header h1{font-size:17px;margin:0;font-weight:600}header .dot{width:9px;height:9px;border-radius:50%;background:var(--ok)}
main{padding:20px 24px;max-width:1200px;margin:0 auto}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:22px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile .n{font-size:24px;font-weight:650}.tile .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
h2{font-size:14px;margin:22px 0 10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.card{background:var(--panel);border:1px solid var(--warn);border-radius:10px;padding:14px;margin-bottom:10px}
.card .tool{font-weight:650;font-size:15px}.card pre{background:#0b0d11;border-radius:6px;padding:8px;overflow:auto;max-height:160px;margin:8px 0}
button{border:0;border-radius:7px;padding:7px 14px;font-weight:600;cursor:pointer;margin-right:8px}
.approve{background:var(--ok);color:#06140e}.deny{background:var(--bad);color:#1a0505}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:500;font-size:12px}
tr.ev{cursor:pointer}tr.ev:hover{background:#1c2029}tr.det td{background:#0b0d11}tr.det pre{margin:0;white-space:pre-wrap;word-break:break-word;max-height:300px;overflow:auto}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600}
.allow,.pass,.approved{background:#173a2d;color:var(--ok)}.block,.denied,.blocked_output{background:#3d1a19;color:var(--bad)}
.sanitized,.approval_required{background:#3b2f14;color:var(--warn)}
.t-clean{color:var(--ok)}.t-untrusted{color:var(--warn)}.t-compromised{color:var(--bad);font-weight:650}
.muted{color:var(--muted)}.empty{color:var(--muted);padding:12px 0}
@media(max-width:700px){main{padding:14px}td:nth-child(1),th:nth-child(1){display:none}}
</style></head><body>
<header><span class="dot"></span><h1>agent-firewall</h1><span class="muted" id="upd"></span></header>
<main>
<div class="tiles" id="tiles"></div>
<h2>Pending approvals</h2><div id="approvals"><div class="empty">Nothing waiting.</div></div>
<h2>Audit log</h2>
<table><thead><tr><th>Time</th><th>Kind</th><th>Tool</th><th>Decision</th><th>Risk</th><th>Session taint</th><th>Reason</th></tr></thead><tbody id="events"></tbody></table>
</main>
<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const t=ts=>new Date(ts*1000).toLocaleTimeString();
const open=new Set();
async function j(u,o){const r=await fetch(u,o);return r.json()}
async function decide(id,v){await fetch(`/api/approvals/${id}/${v}`,{method:'POST'});refresh()}
function toggle(id){open.has(id)?open.delete(id):open.add(id);refresh()}
async function refresh(){
  const [s,ap,ev]=await Promise.all([j('/api/stats'),j('/api/approvals?status=pending'),j('/api/events?limit=150')]);
  const d=s.by_decision||{};const tile=(n,l)=>`<div class="tile"><div class="n">${n}</div><div class="l">${l}</div></div>`;
  document.getElementById('tiles').innerHTML=tile(s.pending_approvals,'Pending approvals')+tile((d.block||0),'Calls blocked')+
    tile((d.sanitized||0)+(d.blocked_output||0),'Injections caught')+tile((d.denied||0),'Denied / timed out')+tile((d.allow||0)+(d.approved||0),'Calls allowed');
  document.getElementById('approvals').innerHTML=ap.length?ap.map(a=>`<div class="card">
    <div class="tool">${esc(a.tool)} <span class="muted">via ${esc(a.server)}</span></div>
    <div>${esc(a.reason)} &middot; risk <b>${esc(a.risk)}</b> &middot; session <span class="t-${esc(a.taint)}">${esc(a.taint)}</span></div>
    <pre>${esc(JSON.stringify(a.args,null,2))}</pre>
    ${a.context&&a.context.sources&&a.context.sources.length?`<div class="muted">Untrusted content seen this session: ${a.context.sources.map(x=>esc(x.tool)+' ('+esc(x.label)+')').join(', ')}</div>`:''}
    <div style="margin-top:10px"><button class="approve" onclick="decide('${a.id}','approve')">Approve</button><button class="deny" onclick="decide('${a.id}','deny')">Deny</button></div></div>`).join(''):'<div class="empty">Nothing waiting.</div>';
  document.getElementById('events').innerHTML=ev.map(e=>`<tr class="ev" onclick="toggle(${e.id})"><td class="muted">${t(e.ts)}</td><td>${esc(e.kind)}</td><td>${esc(e.tool||'')}</td>
    <td><span class="pill ${esc(e.decision)}">${esc(e.decision)}</span></td><td>${esc(e.risk||'')}</td><td class="t-${esc(e.taint)}">${esc(e.taint||'')}</td><td>${esc(e.reason||'')}</td></tr>`+
    (open.has(e.id)?`<tr class="det"><td colspan="7"><pre>${esc(JSON.stringify(e.detail,null,2))}</pre></td></tr>`:'')).join('');
  document.getElementById('upd').textContent='updated '+new Date().toLocaleTimeString();
}
refresh();setInterval(refresh,1500);
</script></body></html>"""
