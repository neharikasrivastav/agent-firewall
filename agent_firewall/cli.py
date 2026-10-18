"""Command line: agent-firewall {run, dashboard, scan, eval}"""

from __future__ import annotations

import argparse
import json
import sys

import anyio


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="agent-firewall", description="Prompt-injection firewall for MCP agents")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the firewall as an MCP server over stdio (point your agent at this)")
    r.add_argument("--config", "-c", default="firewall.yaml")
    r.add_argument("--approval-mode", choices=["dashboard", "deny", "allow"], help="override approvals.mode")
    r.add_argument("--db", help="override audit.db_path")

    d = sub.add_parser("dashboard", help="start the approval + audit dashboard")
    d.add_argument("--config", "-c", default="firewall.yaml")
    d.add_argument("--db", help="override audit.db_path")
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=8787)

    pg = sub.add_parser("playground", help="start the public web playground (no real tools, no state)")
    pg.add_argument("--host", default="127.0.0.1")
    pg.add_argument("--port", type=int, default=8000)

    s = sub.add_parser("scan", help="scan text (file or stdin) with the detector and print the verdict")
    s.add_argument("file", nargs="?", help="file to scan (default: stdin)")
    s.add_argument("--sanitize", action="store_true", help="also print the sanitized text")

    e = sub.add_parser("eval", help="run the attack/benign evaluation and write a report")
    e.add_argument("--dataset", default="evals/dataset.jsonl")
    e.add_argument("--out", default="reports/eval_report.md")
    e.add_argument("--judge", action="store_true", help="enable the LLM judge (needs ANTHROPIC_API_KEY)")

    a = p.parse_args(argv)

    if a.cmd == "run":
        from .policy import FirewallConfig
        from .proxy import serve_stdio

        cfg = FirewallConfig.load(a.config)
        if a.approval_mode:
            cfg.approval_mode = a.approval_mode
        if a.db:
            cfg.db_path = a.db
        anyio.run(serve_stdio, cfg)

    elif a.cmd == "dashboard":
        import uvicorn

        from .dashboard import create_app
        from .policy import FirewallConfig

        db = a.db or FirewallConfig.load(a.config).db_path
        print(f"agent-firewall dashboard on http://{a.host}:{a.port}  (db: {db})")
        uvicorn.run(create_app(db), host=a.host, port=a.port, log_level="warning")

    elif a.cmd == "playground":
        import uvicorn

        print(f"agent-firewall playground on http://{a.host}:{a.port}")
        uvicorn.run("agent_firewall.playground:app", host=a.host, port=a.port, log_level="warning")

    elif a.cmd == "scan":
        from .detector import Detector

        text = open(a.file, encoding="utf-8").read() if a.file else sys.stdin.read()
        det = Detector()
        print(json.dumps(det.scan(text).to_dict(), indent=2, ensure_ascii=False))
        if a.sanitize:
            print("\n--- sanitized ---\n" + det.sanitize(text))

    elif a.cmd == "eval":
        from .evaluate import run_eval_cli

        anyio.run(run_eval_cli, a.dataset, a.out, a.judge)


if __name__ == "__main__":
    main()
