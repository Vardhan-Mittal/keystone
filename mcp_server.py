"""Keystone as an MCP server.

Exposes the same eight graph tools the Gemini agent uses, over stdio, so any MCP
client (Claude Code, Claude Desktop, Cursor) can reason over the supply-chain
graph directly. Because agent/tools.py is the single registry, the tools cannot
drift between the two front ends.

Register with Claude Code:

    claude mcp add keystone -- python mcp_server.py

Then ask: "use keystone to find who controls the most of my dependency tree"
"""
from typing import Any

from mcp.server.mcpserver import MCPServer

from keystone.agent.tools import call
from keystone.graph.db import GraphUnavailable, connect

server = MCPServer(
    name="keystone",
    instructions=(
        "Keystone maps the HUMAN attack surface of an npm dependency tree: which "
        "individual maintainer accounts can publish code into the application, "
        "ranked by transitive graph reach rather than by package count. Every "
        "answer can be backed by a cited dependency path. Start with "
        "graph_schema for orientation, keystone_maintainers for the headline "
        "ranking, and trust_path to prove any claim about a named person."
    ),
)

# Connection is lazy and cached: the MCP client may start this process before
# FalkorDB is up, and a failure must surface as a tool error the model can read
# rather than killing the server at import time.
_graph: Any = None


def _g() -> Any:
    global _graph
    if _graph is None:
        _graph = connect()
    return _graph


def _run(name: str, **args: Any) -> dict[str, Any]:
    """Dispatch, converting an unavailable graph into a readable tool error.

    There is deliberately no degraded mode: if FalkorDB is down, Keystone says
    so instead of answering from some lesser source.
    """
    try:
        return call(_g(), name, args)
    except GraphUnavailable as exc:
        return {
            "error": str(exc),
            "summary": "FalkorDB is unavailable; Keystone cannot answer without it.",
        }


@server.tool(
    description=(
        "Overview of the supply-chain graph: which application is under "
        "analysis, and how many packages, maintainers and edges it holds. "
        "Call first for orientation."
    )
)
def graph_schema() -> dict[str, Any]:
    return _run("graph_schema")


@server.tool(
    description=(
        "Resolve a partial package name or maintainer username to exact matches. "
        "Use before tools that need an exact name."
    )
)
def find_entity(name: str) -> dict[str, Any]:
    return _run("find_entity", name=name)


@server.tool(
    description=(
        "Rank individual people by how much of the dependency tree they can "
        "influence, by transitive graph reach rather than packages owned. The "
        "headline analysis: answers 'who is the biggest single point of failure'."
    )
)
def keystone_maintainers(top_n: int = 10) -> dict[str, Any]:
    return _run("keystone_maintainers", top_n=top_n)


@server.tool(
    description=(
        "The cited dependency chain from the application to a specific "
        "maintainer -- the route by which their code reaches production. Use to "
        "prove any claim about a named person."
    )
)
def trust_path(username: str) -> dict[str, Any]:
    return _run("trust_path", username=username)


@server.tool(
    description=(
        "Packages matching the xz-utils pattern: one maintainer, no release in "
        "years, real transitive reach, weak repo process. Takeover risks that no "
        "CVE feed can report because nothing has been disclosed yet."
    )
)
def hijack_candidates(stale_days: int = 730, limit: int = 15) -> dict[str, Any]:
    return _run("hijack_candidates", stale_days=stale_days, limit=limit)


@server.tool(
    description=(
        "What becomes reachable if one maintainer's account is compromised: how "
        "many packages, how many of the application's direct dependencies, and "
        "at what depth."
    )
)
def compromise_blast_radius(username: str) -> dict[str, Any]:
    return _run("compromise_blast_radius", username=username)


@server.tool(
    description=(
        "Pairs of maintainer accounts with publish rights to the same packages, "
        "so compromising either reaches all of them."
    )
)
def correlated_risk(limit: int = 12) -> dict[str, Any]:
    return _run("correlated_risk", limit=limit)


@server.tool(
    description=(
        "Published advisories affecting packages in the tree, joined to the "
        "maintainers of each affected package."
    )
)
def vulnerability_overlay(package: str | None = None) -> dict[str, Any]:
    return _run("vulnerability_overlay", package=package)


if __name__ == "__main__":
    server.run(transport="stdio")
