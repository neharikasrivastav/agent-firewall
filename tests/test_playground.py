from fastapi.testclient import TestClient

from agent_firewall.playground import create_app

c = TestClient(create_app())
PRESETS = {p["id"]: p for p in c.get("/api/presets").json()}


def _run(p):
    r = c.post("/api/simulate", json={"source_tool": p["source_tool"], "content": p["content"],
                                      "call_tool": p["call"]["tool"], "call_args": p["call"]["args"]})
    assert r.status_code == 200
    return r.json()


def test_page_and_health():
    assert "agent-firewall" in c.get("/").text
    assert c.get("/healthz").json() == {"ok": True}


def test_attack_presets_never_execute():
    for p in PRESETS.values():
        if p["kind"] == "attack":
            d = _run(p)
            assert d["verdict"]["label"] == "injection", p["id"]
            assert d["decision"]["action"] == "block", p["id"]
            assert d["sanitized_changed"], p["id"]


def test_benign_presets_are_not_blocked():
    for p in PRESETS.values():
        if p["kind"] == "benign":
            d = _run(p)
            assert d["verdict"]["label"] != "injection", p["id"]
            assert d["decision"]["action"] != "block", p["id"]
    assert _run(PRESETS["boss"])["decision"]["action"] == "allow"


def test_rejects_unknown_tools_and_oversized_input():
    assert c.post("/api/simulate", json={"source_tool": "rm", "content": "x"}).status_code == 400
    assert c.post("/api/simulate", json={"call_tool": "exec", "content": "x"}).status_code == 400
    assert c.post("/api/simulate", json={"content": "a" * 20_001}).status_code == 422
