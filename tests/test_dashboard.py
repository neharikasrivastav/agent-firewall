from fastapi.testclient import TestClient

from agent_firewall.audit import AuditLog
from agent_firewall.dashboard import create_app


def test_dashboard_lists_and_decides(tmp_path):
    db = str(tmp_path / "a.db")
    audit = AuditLog(db)
    aid = audit.create_approval(session_id="s", server="w", tool="send_email", args={"to": "a@b.c"}, risk="egress",
                                taint="untrusted", reason="test")
    audit.log(session_id="s", kind="tool_call", decision="approval_required", tool="send_email")
    c = TestClient(create_app(db))
    assert "agent-firewall" in c.get("/").text
    assert c.get("/api/approvals?status=pending").json()[0]["id"] == aid
    assert c.post(f"/api/approvals/{aid}/approve").json()["status"] == "approved"
    assert c.post(f"/api/approvals/{aid}/deny").status_code == 409
    assert audit.approval_status(aid) == "approved"
    assert c.get("/api/stats").json()["by_decision"]["approval_required"] == 1
