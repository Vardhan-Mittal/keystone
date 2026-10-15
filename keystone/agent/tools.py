"""One tool registry, three consumers.

The Gemini agent loop, the MCP server and the deterministic router all read the
specs below. Declaring tools once means a tool cannot drift between the agent
and MCP, and it is why exposing Keystone inside an MCP client costs almost
nothing extra.

Each spec is deliberately explicit about *when* to use the tool. That text is
the only thing steering tool selection, so it carries the real weight.
"""
from typing import Any

from ..graph import queries as Q

SPECS: list[dict[str, Any]] = [
    {
        "name": "graph_schema",
        "description": (
            "Overview of the graph: which application is under analysis and how "
            "many packages, maintainers and edges it holds. Call this first when "
            "you need orientation or the user asks what data is available."
        ),
        "params": {},
        "required": [],
    },
    {
        "name": "find_entity",
        "description": (
            "Resolve a partial or fuzzy name to packages and maintainers. Use "
            "this to turn a name the user typed (like 'babel' or 'sindre') into "
            "an exact package name or maintainer username before calling a tool "
            "that needs one."
        ),
        "params": {
            "name": {
                "type": "string",
                "description": "Partial package name or maintainer username.",
            }
        },
        "required": ["name"],
    },
    {
        "name": "keystone_maintainers",
        "description": (
            "THE headline tool. Ranks individual people by how much of the "
            "dependency tree they can influence, measured by transitive graph "
            "reach rather than by how many packages they own. Use for questions "
            "like 'who controls the most of my tree', 'who is the biggest "
            "single point of failure', 'which maintainer matters most'."
        ),
        "params": {
            "top_n": {
                "type": "integer",
                "description": "How many maintainers to return. Default 10.",
            }
        },
        "required": [],
    },
    {
        "name": "trust_path",
        "description": (
            "The cited chain of dependencies from the application to a specific "
            "maintainer -- the route by which that person's code reaches "
            "production. Use whenever the user asks 'how', 'why', 'prove it', or "
            "'what is the path to X'. Always call this to back up a claim about "
            "a named person."
        ),
        "params": {
            "username": {
                "type": "string",
                "description": "Exact npm maintainer username.",
            }
        },
        "required": ["username"],
    },
    {
        "name": "hijack_candidates",
        "description": (
            "Packages matching the xz-utils pattern: exactly one maintainer, no "
            "release in years, real transitive reach, and weak repository "
            "process. These are takeover risks that no CVE feed can report, "
            "because no vulnerability has been disclosed yet. Use for "
            "'what should I worry about', 'abandoned packages', 'takeover risk'."
        ),
        "params": {
            "stale_days": {
                "type": "integer",
                "description": "Staleness threshold in days. Default 730.",
            },
            "limit": {
                "type": "integer",
                "description": "Max rows. Default 15.",
            },
        },
        "required": [],
    },
    {
        "name": "compromise_blast_radius",
        "description": (
            "What becomes reachable if one named maintainer's account is "
            "compromised: how many packages, how many of the application's own "
            "direct dependencies, and at what depth. Use for 'what if X is "
            "hacked/phished', 'blast radius of X', 'impact if X is compromised'."
        ),
        "params": {
            "username": {
                "type": "string",
                "description": "Exact npm maintainer username.",
            }
        },
        "required": ["username"],
    },
    {
        "name": "correlated_risk",
        "description": (
            "Pairs of maintainer accounts that can both publish to the same "
            "packages, so compromising either one reaches all of them. Use for "
            "'correlated risk', 'who works together', 'shared publish rights'."
        ),
        "params": {
            "limit": {"type": "integer", "description": "Max pairs. Default 12."}
        },
        "required": [],
    },
    {
        "name": "vulnerability_overlay",
        "description": (
            "Known published advisories affecting packages in the tree, joined "
            "to the maintainers of the affected package. Use only when the user "
            "asks specifically about CVEs, advisories or disclosed "
            "vulnerabilities -- for structural risk prefer the other tools."
        ),
        "params": {
            "package": {
                "type": "string",
                "description": "Optional exact package name to filter to.",
            }
        },
        "required": [],
    },
]

BY_NAME = {s["name"]: s for s in SPECS}


def call(graph, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    """Dispatch a tool call against the graph.

    Unknown names and bad arguments come back as structured errors rather than
    exceptions, because the caller is often a model that should be given the
    chance to correct itself.
    """
    args = {k: v for k, v in (args or {}).items() if v is not None}
    fn = Q.TOOLS.get(name)
    if fn is None:
        return {
            "answer": None,
            "path": [],
            "cypher": "",
            "summary": f"No such tool {name!r}. Available: {', '.join(Q.TOOLS)}.",
        }
    try:
        return fn(graph, **args)
    except TypeError as exc:
        spec = BY_NAME.get(name, {})
        return {
            "answer": None,
            "path": [],
            "cypher": "",
            "summary": (
                f"Bad arguments for {name}: {exc}. "
                f"Expected: {list(spec.get('params', {}))}."
            ),
        }


def gemini_declarations() -> list[dict[str, Any]]:
    """SPECS rendered as Gemini function declarations."""
    out = []
    for s in SPECS:
        decl: dict[str, Any] = {"name": s["name"], "description": s["description"]}
        if s["params"]:
            decl["parameters"] = {
                "type": "object",
                "properties": {
                    k: {"type": v["type"], "description": v["description"]}
                    for k, v in s["params"].items()
                },
                "required": s["required"],
            }
        out.append(decl)
    return out
