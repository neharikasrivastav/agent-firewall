"""A deliberately vulnerable MCP server for demos and evals.

Every side effect is SIMULATED: "sending" an email or "deleting" a file only appends a
record to a JSONL file in the state directory, so you can safely see what an attacker
would have achieved.

Tools: fetch_url, read_inbox, list_files, read_file (untrusted sources)
       send_email, http_post (egress), delete_file (destructive), save_note (write)
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"


@dataclass
class VictimWorld:
    pages: dict[str, str] = field(default_factory=dict)       # url -> html/text
    inbox: list[dict] = field(default_factory=list)            # {from, subject, body}
    files: dict[str, str] = field(default_factory=dict)        # path -> content
    state_dir: Path | None = None
    actions: list[dict] = field(default_factory=list)          # side effects that "happened"

    def record(self, kind: str, **data) -> None:
        entry = {"ts": time.time(), "action": kind, **data}
        self.actions.append(entry)
        if self.state_dir:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            with open(self.state_dir / "side_effects.jsonl", "a") as f:
                f.write(json.dumps(entry) + "\n")

    @classmethod
    def from_fixtures(cls, root: Path = FIXTURES, state_dir: Path | None = None) -> "VictimWorld":
        pages = {}
        index = json.loads((root / "web" / "index.json").read_text())
        for url, fname in index.items():
            pages[url] = (root / "web" / fname).read_text()
        inbox = [json.loads(p.read_text()) for p in sorted((root / "inbox").glob("*.json"))]
        files = {p.name: p.read_text() for p in sorted((root / "files").glob("*")) if p.is_file()}
        return cls(pages=pages, inbox=inbox, files=files, state_dir=state_dir)


def create_victim_server(world: VictimWorld) -> MCPServer:
    mcp = MCPServer("victim-workspace", instructions="Demo workspace: web, email, files. Side effects are simulated.")

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=True))
    def fetch_url(url: str) -> str:
        """Fetch a web page and return its raw HTML/text."""
        world.record("network_request", url=url)
        return world.pages.get(url, f"404 Not Found: {url}")

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    def read_inbox(limit: int = 10) -> str:
        """Read the most recent emails in the user's inbox."""
        out = []
        for i, m in enumerate(world.inbox[:limit]):
            out.append(f"--- Email {i + 1} ---\nFrom: {m['from']}\nSubject: {m['subject']}\n\n{m['body']}")
        return "\n\n".join(out) or "Inbox is empty."

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    def list_files() -> str:
        """List files in the user's workspace."""
        return "\n".join(sorted(world.files)) or "(no files)"

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    def read_file(path: str) -> str:
        """Read a file from the user's workspace."""
        return world.files.get(path, f"File not found: {path}")

    @mcp.tool(annotations=ToolAnnotations(destructive_hint=False, open_world_hint=True))
    def send_email(to: str, subject: str, body: str) -> str:
        """Send an email on the user's behalf."""
        world.record("send_email", to=to, subject=subject, body=body[:2000])
        return f"Email sent to {to}."

    @mcp.tool(annotations=ToolAnnotations(open_world_hint=True))
    def http_post(url: str, data: str) -> str:
        """POST data to a URL."""
        world.record("http_post", url=url, data=data[:2000])
        return f"POST {url}: 200 OK"

    @mcp.tool(annotations=ToolAnnotations(destructive_hint=True))
    def delete_file(path: str) -> str:
        """Delete a file from the user's workspace."""
        world.record("delete_file", path=path)
        world.files.pop(path, None)
        return f"Deleted {path}."

    @mcp.tool()
    def save_note(title: str, content: str) -> str:
        """Save a note to the user's workspace."""
        world.record("save_note", title=title)
        world.files[f"{title}.md"] = content
        return f"Saved note '{title}'."

    return mcp


def main() -> None:
    state = Path(os.environ.get("VICTIM_STATE_DIR", HERE / "state"))
    world = VictimWorld.from_fixtures(state_dir=state)
    print(f"[victim] {len(world.pages)} pages, {len(world.inbox)} emails, {len(world.files)} files; "
          f"side effects -> {state / 'side_effects.jsonl'}", file=sys.stderr)
    create_victim_server(world).run("stdio")


if __name__ == "__main__":
    main()
