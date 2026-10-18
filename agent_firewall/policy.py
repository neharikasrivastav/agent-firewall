"""Policy engine: tool risk classification, session taint tracking and call decisions.

Core idea (information-flow control, in the spirit of CaMeL / FIDES-style designs):
  * Every tool output from an *untrusted source* (web, email, files) taints the session.
  * If the detector flags an output as an injection, the session becomes *compromised*.
  * Risky actions (writes, egress, destructive) are allowed / sent for approval / blocked
    depending on the risk level x taint level matrix in the config.
  * "Tainted arguments": if a call's destination (email, URL host) first appeared inside
    untrusted content, the agent is probably being steered, so we escalate.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

RISK_LEVELS = ("read", "write", "egress", "destructive")
TAINT_LEVELS = ("clean", "untrusted", "compromised")
ACTIONS = ("allow", "approve", "block")

EMAIL_RX = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
# Credential-looking values (DLP). Deliberately specific to keep false positives low.
SECRET_RX = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{12,}|sk-ant-[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
    r"|\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*\S{4,}",
    re.IGNORECASE,
)
URL_RX = re.compile(r"https?://([\w.-]+)(?::\d+)?[^\s\"'<>)]*", re.IGNORECASE)

DEFAULT_MATRIX = {
    "read": {"clean": "allow", "untrusted": "allow", "compromised": "allow"},
    "write": {"clean": "allow", "untrusted": "approve", "compromised": "approve"},
    "egress": {"clean": "allow", "untrusted": "approve", "compromised": "block"},
    "destructive": {"clean": "approve", "untrusted": "approve", "compromised": "block"},
}


# --------------------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------------------


@dataclass
class UpstreamConfig:
    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    url: str | None = None  # streamable HTTP upstream
    cwd: str | None = None
    inherit_env: bool = True  # pass the firewall's environment through to the upstream process


@dataclass
class FirewallConfig:
    upstreams: list[UpstreamConfig] = field(default_factory=list)
    injection_threshold: float = 0.5
    suspicious_threshold: float = 0.25
    llm_judge: bool = False
    judge_model: str | None = None
    on_injection: str = "sanitize"  # sanitize | block | warn
    untrusted_sources: list[str] = field(default_factory=lambda: ["fetch*", "read_*", "search*", "browse*", "get_*"])
    tool_rules: list[dict] = field(default_factory=list)
    default_risk: str = "write"
    matrix: dict = field(default_factory=lambda: {k: dict(v) for k, v in DEFAULT_MATRIX.items()})
    egress_allowlist: list[str] = field(default_factory=list)
    block_tainted_arguments: bool = True
    approval_mode: str = "dashboard"  # dashboard | deny | allow
    approval_timeout: float = 120.0
    db_path: str = "agent_firewall.db"

    @classmethod
    def load(cls, path: str | Path) -> "FirewallConfig":
        raw = yaml.safe_load(Path(path).read_text()) or {}
        return cls.from_dict(raw, base_dir=Path(path).resolve().parent)

    @classmethod
    def from_dict(cls, raw: dict, base_dir: Path | None = None) -> "FirewallConfig":
        cfg = cls()
        cfg.upstreams = [UpstreamConfig(**u) for u in raw.get("upstreams", [])]
        for u in cfg.upstreams:  # relative paths in a config are relative to the config file
            if base_dir and not u.cwd:
                u.cwd = str(base_dir)
        det = raw.get("detector", {})
        cfg.injection_threshold = det.get("injection_threshold", cfg.injection_threshold)
        cfg.suspicious_threshold = det.get("suspicious_threshold", cfg.suspicious_threshold)
        cfg.llm_judge = det.get("llm_judge", cfg.llm_judge)
        cfg.judge_model = det.get("judge_model")
        cfg.on_injection = det.get("on_injection", cfg.on_injection)
        tools = raw.get("tools", {})
        cfg.untrusted_sources = tools.get("untrusted_sources", cfg.untrusted_sources)
        cfg.tool_rules = tools.get("rules", [])
        cfg.default_risk = tools.get("default_risk", cfg.default_risk)
        pol = raw.get("policy", {})
        for risk in RISK_LEVELS:
            if risk in pol:
                cfg.matrix[risk].update(pol[risk])
        cfg.egress_allowlist = pol.get("egress_allowlist", [])
        cfg.block_tainted_arguments = pol.get("block_tainted_arguments", True)
        appr = raw.get("approvals", {})
        cfg.approval_mode = appr.get("mode", cfg.approval_mode)
        cfg.approval_timeout = float(appr.get("timeout_seconds", cfg.approval_timeout))
        db = raw.get("audit", {}).get("db_path", cfg.db_path)
        cfg.db_path = str((base_dir / db) if base_dir and db != ":memory:" and not Path(db).is_absolute() else db)
        cfg.validate()
        return cfg

    def validate(self) -> None:
        assert self.on_injection in ("sanitize", "block", "warn"), "detector.on_injection must be sanitize|block|warn"
        assert self.approval_mode in ("dashboard", "deny", "allow"), "approvals.mode must be dashboard|deny|allow"
        assert self.default_risk in RISK_LEVELS
        for risk, row in self.matrix.items():
            for taint, action in row.items():
                assert taint in TAINT_LEVELS and action in ACTIONS, f"bad policy entry {risk}.{taint}={action}"


# --------------------------------------------------------------------------------------
# Session taint
# --------------------------------------------------------------------------------------


@dataclass
class TaintState:
    level: str = "clean"
    sources: list[dict] = field(default_factory=list)  # [{tool, label, score, snippet}]
    # destination tokens (emails / hosts) that appeared in untrusted content -> was the content flagged?
    tokens: dict[str, bool] = field(default_factory=dict)

    def raise_to(self, level: str) -> None:
        if TAINT_LEVELS.index(level) > TAINT_LEVELS.index(self.level):
            self.level = level

    def to_dict(self) -> dict:
        return {"level": self.level, "sources": self.sources[-10:], "tainted_destinations": sorted(self.tokens)[:50]}


@dataclass
class Decision:
    action: str  # allow | approve | block
    risk: str
    reason: str
    tainted_args: list[str] = field(default_factory=list)


def extract_destinations(text: str) -> set[str]:
    out = {e.lower() for e in EMAIL_RX.findall(text)}
    out |= {h.lower() for h in URL_RX.findall(text)}
    return out


def _flatten(obj: Any) -> str:
    if isinstance(obj, dict):
        return " ".join(_flatten(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten(v) for v in obj)
    return str(obj)


class PolicyEngine:
    def __init__(self, config: FirewallConfig):
        self.cfg = config

    # ---- classification ----------------------------------------------------------------

    def classify(self, tool: str, annotations: Any = None) -> str:
        for rule in self.cfg.tool_rules:
            if fnmatch.fnmatch(tool, rule["match"]):
                return rule["risk"]
        if annotations is not None:
            if getattr(annotations, "destructive_hint", None):
                return "destructive"
            if getattr(annotations, "read_only_hint", None):
                return "read"
        return self.cfg.default_risk

    def is_untrusted_source(self, tool: str) -> bool:
        return any(fnmatch.fnmatch(tool, p) for p in self.cfg.untrusted_sources)

    def allowlisted(self, dest: str) -> bool:
        d = dest.lower()
        for a in self.cfg.egress_allowlist:
            a = a.lower()
            if a.startswith("@") and d.endswith(a):
                return True
            if a.startswith("http"):
                host = URL_RX.match(a)
                if host and (d == host.group(1) or d.endswith("." + host.group(1))):
                    return True
            elif d == a or d.endswith("." + a) or d.endswith("@" + a):
                return True
        return False

    # ---- taint updates -------------------------------------------------------------------

    def observe_output(self, taint: TaintState, tool: str, text: str, verdict) -> None:
        untrusted = self.is_untrusted_source(tool)
        if verdict.is_injection:
            taint.raise_to("compromised")
        elif untrusted or verdict.is_suspicious:
            taint.raise_to("untrusted")
        else:
            return
        taint.sources.append({"tool": tool, "label": verdict.label, "score": round(verdict.score, 2),
                              "signals": [s.name for s in verdict.signals][:6]})
        for dest in extract_destinations(text):
            if not self.allowlisted(dest):
                taint.tokens[dest] = taint.tokens.get(dest, False) or verdict.is_injection

    # ---- call decisions --------------------------------------------------------------------

    def evaluate_call(self, tool: str, args: dict | None, taint: TaintState, annotations: Any = None) -> Decision:
        risk = self.classify(tool, annotations)
        action = self.cfg.matrix[risk][taint.level]
        reason = f"{risk} tool while session is {taint.level}"
        arg_text = _flatten(args or {})
        dests = extract_destinations(arg_text)

        # Egress to allowlisted destinations only is fine unless the session is compromised.
        # (If it IS compromised, a human confirms instead of a hard block.)
        if risk == "egress" and dests and all(self.allowlisted(d) for d in dests):
            if taint.level == "compromised":
                action, reason = "approve", "egress to allowlisted destination, but session saw an injection attempt"
            else:
                action, reason = "allow", "egress to allowlisted destination(s) only"

        # DLP: credentials leaving to a destination that isn't allowlisted -> block, whatever the taint.
        secrets = SECRET_RX.findall(arg_text)
        if secrets and any(not self.allowlisted(d) for d in dests):
            return Decision("block", risk, "credential-like value in arguments sent to a non-allowlisted destination (DLP)",
                            sorted(d for d in dests if not self.allowlisted(d)))

        # Tainted arguments: the destination was introduced by untrusted content.
        tainted = sorted(d for d in dests if d in taint.tokens and not self.allowlisted(d))
        if tainted and self.cfg.block_tainted_arguments:
            from_flagged = any(taint.tokens[d] for d in tainted)
            if from_flagged or taint.level == "compromised":
                action = "block"
                reason = f"destination {', '.join(tainted)} came from flagged untrusted content (likely injection-steered)"
            elif action == "allow":
                action = "approve"
                reason = f"destination {', '.join(tainted)} came from untrusted content"
        return Decision(action, risk, reason, tainted)
