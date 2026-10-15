"""Deterministic keyword router -- the fallback that keeps the demo alive.

Keystone works with no API key at all. If Gemini is unavailable, rate-limited or
simply not configured, questions still get answered: this module picks a tool
from keywords and resolves entity names *through the graph* rather than guessing.

It is not a language model and does not pretend to be. It exists because a live
demo that dies on a 429 is worse than one that answers slightly more rigidly.
"""
import re
from typing import Any

from ..graph.queries import find_entity
from .tools import call

# Ordered: the first pattern that matches wins, so the most specific
# intents are listed before the broader ones.
RULES: list[tuple[str, str]] = [
    (
        r"\b(schema|overview|what data|what is in the|whats in the|in the graph"
        r"|how many|how big|stats|summar)",
        "graph_schema",
    ),
    (
        r"\b(blast radius|if .*(hack|phish|compromis|breach)|what if|were compromised)",
        "compromise_blast_radius",
    ),
    (
        r"\b(xz|hijack|takeover|take over|abandoned|unmaintained|stale|neglected|single maintainer|solo)",
        "hijack_candidates",
    ),
    (
        r"\b(co-?maintain|shared (publish|rights|access)|correlated|work together|same people)",
        "correlated_risk",
    ),
    (r"\b(cve|vulnerab|advisor|exploit|patched|security issue)", "vulnerability_overlay"),
    (
        r"\b(path|how does|how do|prove|trace|route|reach my|chain)",
        "trust_path",
    ),
    (
        r"\b(who|keystone|most|biggest|top|control|risk|single point|depend on one)",
        "keystone_maintainers",
    ),
]

# Words that look like entity names but are just English.
_STOPWORDS = {
    "who", "what", "which", "the", "my", "of", "in", "is", "are", "and", "to",
    "a", "an", "most", "tree", "package", "packages", "maintainer",
    "maintainers", "person", "people", "app", "code", "dependency",
    "dependencies", "controls", "control", "if", "was", "were", "gets",
    "account", "npm", "me", "show", "list", "how", "many", "much", "does",
    "do", "i", "it", "that", "this", "for", "on", "by", "from", "with",
}


def _candidate_tokens(question: str) -> list[str]:
    """Words from the question that might name a package or a person."""
    raw = re.findall(r"[A-Za-z0-9@/._-]{2,}", question)
    return [t for t in raw if t.lower() not in _STOPWORDS]


def resolve_entity(graph, question: str) -> tuple[str | None, str | None]:
    """Find a person or package named in the question, using the graph itself.

    Returns (username, exact_package_name). Resolution runs against the
    full-text indexes, so "sindre" resolves to sindresorhus the same way it
    would for a human typing in the UI -- no hardcoded lists.

    People are matched fuzzily (users type partial names), but packages are
    returned ONLY on an exact match. Fuzzy package matching silently wrecked
    broad questions: "any known CVEs?" had a leftover token fuzzy-match a
    package and filtered the whole answer down to it, reporting zero.
    """
    person = pkg = None
    for tok in _candidate_tokens(question):
        hit = find_entity(graph, tok, limit=3)["answer"]
        if not person and hit["people"]:
            exact = [p for p in hit["people"] if p["username"].lower() == tok.lower()]
            person = (exact or hit["people"])[0]["username"]
        if not pkg:
            exact = [p for p in hit["packages"] if p["name"].lower() == tok.lower()]
            if exact:
                pkg = exact[0]["name"]
        if person:
            break  # a named human is the strongest signal available
    return person, pkg


def route(graph, question: str) -> dict[str, Any]:
    """Pick a tool and run it. Always returns a tool result."""
    q = question.lower()
    tool = next((t for pat, t in RULES if re.search(pat, q)), "keystone_maintainers")

    args: dict[str, Any] = {}
    if tool in ("trust_path", "compromise_blast_radius"):
        person, _ = resolve_entity(graph, question)
        if not person:
            # Asked for a path but named nobody: the ranking is the useful
            # answer, and it tells the user who they could ask about.
            tool = "keystone_maintainers"
        else:
            args["username"] = person
    elif tool == "vulnerability_overlay":
        _, pkg = resolve_entity(graph, question)
        if pkg:
            args["package"] = pkg

    result = call(graph, tool, args)
    result["tool"] = tool
    result["tool_args"] = args
    result["engine"] = "deterministic-router"
    return result
