"""HTTP API for the Keystone UI.

Thin by design: every endpoint delegates to the same tools the agent and the MCP
server use, so the web page cannot show a number the agent cannot explain.

Run:
    uvicorn keystone.api.main:app --reload --port 8000
"""
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from ..agent import router
from ..agent.loop import ask as agent_ask
from ..config import ROOT, STALE_DAYS
from ..graph import queries as Q
from ..graph.db import GraphUnavailable, connect, count, read

app = FastAPI(title="Keystone", version="1.0")
WEB = ROOT / "web"


class Question(BaseModel):
    question: str
    use_llm: bool = True


def _graph():
    """Fresh handle per request. There is no fallback if the graph is down."""
    return connect()


@app.exception_handler(GraphUnavailable)
async def _graph_down(_request, exc: GraphUnavailable):
    """503 with the real reason.

    Keystone deliberately has no degraded mode: if FalkorDB is gone, the product
    is gone. Surfacing that honestly is the point of the removal test.
    """
    return JSONResponse(
        status_code=503,
        content={"error": "graph_unavailable", "detail": str(exc)},
    )


@app.get("/api/health")
def health() -> dict[str, Any]:
    try:
        g = _graph()
        n = count(g, "Package")
        return {"ok": True, "packages": n}
    except GraphUnavailable as exc:
        return {"ok": False, "detail": str(exc)}


@app.get("/api/overview")
def overview(top_n: int = 10) -> dict[str, Any]:
    """Everything the landing view needs, in one round trip."""
    g = _graph()
    schema = Q.graph_schema(g)
    keystones = Q.keystone_maintainers(g, top_n=top_n)

    total = keystones["answer"]["total_packages"]
    solo = read(
        g, "MATCH (p:Package) WHERE p.maintainer_count = 1 RETURN count(p)"
    )[0][0]
    # Counted, not len() of a LIMITed result -- the headline figure must be the
    # true total, otherwise the page reports the page size back as a finding.
    hijack_count = read(
        g,
        """MATCH (p:Package)
           WHERE p.maintainer_count = 1 AND p.stale_days > $stale
           RETURN count(DISTINCT p)""",
        {"stale": STALE_DAYS},
    )[0][0]

    # A cited path per ranked maintainer: the ranking is only trustworthy if
    # each row can show the route by which that person reaches the app.
    rows = keystones["answer"]["maintainers"]
    for r in rows:
        tp = Q.trust_path(g, r["username"])
        r["path"] = tp["answer"]["chain"] if tp["answer"] else []
        r["hops"] = tp["answer"]["hops"] if tp["answer"] else None

    return {
        "app": schema["answer"]["app"],
        "counts": schema["answer"]["nodes"],
        "edges": schema["answer"]["edges"],
        "total_packages": total,
        "solo_maintainer_packages": solo,
        "solo_maintainer_pct": round(100.0 * solo / total, 1) if total else 0,
        "hijack_count": hijack_count,
        "stale_threshold_days": STALE_DAYS,
        "keystones": rows,
        "cypher": {
            "keystones": keystones["cypher"],
            "trust_path": Q._TRUST_PATH.strip(),
            "hijack": Q._HIJACK.strip(),
        },
    }


@app.get("/api/hijack")
def hijack(limit: int = 15) -> dict[str, Any]:
    return Q.hijack_candidates(_graph(), limit=limit)


@app.get("/api/path/{username}")
def path(username: str) -> dict[str, Any]:
    return Q.trust_path(_graph(), username)


@app.get("/api/blast/{username}")
def blast(username: str) -> dict[str, Any]:
    return Q.compromise_blast_radius(_graph(), username)


@app.get("/api/correlated")
def correlated(limit: int = 12) -> dict[str, Any]:
    return Q.correlated_risk(_graph(), limit=limit)


@app.get("/api/vulnerabilities")
def vulnerabilities() -> dict[str, Any]:
    return Q.vulnerability_overlay(_graph())


@app.post("/api/ask")
def ask(q: Question) -> dict[str, Any]:
    """Natural-language question -> tool choice -> cited answer."""
    if q.use_llm:
        return agent_ask(q.question, use_llm=True)
    return router.route(_graph(), q.question)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB / "index.html")
