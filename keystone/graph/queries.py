"""The eight tools Keystone answers questions with.

Every tool returns a dict shaped:

    {"answer": ..., "path": [...], "cypher": "...", "summary": "..."}

`cypher` is returned deliberately. The product's claim is that the graph does the
work, so each answer ships the traversal that produced it -- the agent cites it,
the UI renders it, and a judge can paste it into FalkorDB Browser and re-run it.

Conventions enforced throughout:
  * relationships are always aliased and referenced (FalkorDB only guarantees
    "at least one match exists" otherwise, which silently breaks count())
  * filters are positive (=, >, <) because FalkorDB indexes do not serve `<>`
  * reads go through ro_query, so no tool can mutate the graph
"""
from typing import Any

from ..config import MAX_HOPS, STALE_DAYS
from .db import count, count_rel, read

# Traversal from the app down to a human: dependency edges then the maintainer
# edge. This single relationship union is what joins the two graphs -- the
# dependency graph and the maintainer graph -- and the join is the product.
TRUST = "DEPENDS_ON|MAINTAINED_BY"


def _d(rows: list, keys: list[str]) -> list[dict]:
    return [dict(zip(keys, r)) for r in rows]


# ----------------------------------------------------------------- 1. schema --

def graph_schema(graph) -> dict[str, Any]:
    """What is in the graph. Lets an agent orient itself before querying."""
    counts = {}
    for label in ("App", "Package", "Person", "Project", "CVE"):
        counts[label] = count(graph, label)
    rels = {}
    for rel in (
        "DEPENDS_ON",
        "MAINTAINED_BY",
        "HOSTED_AT",
        "AFFECTED_BY",
        "CONTROLS",
        "CO_MAINTAINS_WITH",
    ):
        rels[rel] = count_rel(graph, rel)
    app = read(graph, "MATCH (a:App) RETURN a.name, a.version")
    return {
        "answer": {"app": app[0] if app else None, "nodes": counts, "edges": rels},
        "path": [],
        "cypher": "MATCH (n:<Label>) RETURN count(n)",
        "summary": (
            f"Analysing {app[0][0]}@{app[0][1]} -- {counts['Package']} packages, "
            f"{counts['Person']} maintainers, {rels['DEPENDS_ON']} dependency edges."
            if app
            else "Graph is empty."
        ),
    }


# ----------------------------------------------------------- 2. find_entity --

_FIND_PKG = """
CALL db.idx.fulltext.queryNodes('Package', $q) YIELD node AS p
RETURN p.name, p.version, p.maintainer_count, p.stale_days
LIMIT $limit
"""

_FIND_PERSON = """
CALL db.idx.fulltext.queryNodes('Person', $q) YIELD node AS x
OPTIONAL MATCH (x)-[c:CONTROLS]->(:App)
RETURN x.username, x.registry_total, c.owned, c.reach
LIMIT $limit
"""


_FIND_PKG_FALLBACK = """
MATCH (p:Package)
WHERE toLower(p.name) CONTAINS toLower($q)
RETURN p.name, p.version, p.maintainer_count, p.stale_days
LIMIT $limit
"""

_FIND_PERSON_FALLBACK = """
MATCH (x:Person)
WHERE toLower(x.username) CONTAINS toLower($q)
OPTIONAL MATCH (x)-[c:CONTROLS]->(:App)
RETURN x.username, x.registry_total, c.owned, c.reach
LIMIT $limit
"""

# RediSearch reserves these; an unescaped one is a syntax error, so a raw
# "@babel/core" cannot be handed to the full-text index directly.
_RESERVED = set(",.<>{}[]\"':;!@#$%^&*()-+=~/\\|?")


def _ft_terms(name: str) -> str:
    """Turn user input into a safe RediSearch prefix query.

    Two things learned from the live index: bare terms do NOT match on prefix
    ("sindre" finds nothing, "sindre*" finds sindresorhus), and reserved
    characters raise a syntax error rather than being ignored. So strip the
    reserved set, then prefix-match every surviving token -- "@babel/core"
    becomes "babel* core*", which matches.
    """
    cleaned = "".join(" " if ch in _RESERVED else ch for ch in name)
    tokens = [t for t in cleaned.split() if t]
    return " ".join(f"{t}*" for t in tokens)


def find_entity(graph, name: str, limit: int = 8) -> dict[str, Any]:
    """Resolve a fuzzy name to packages and people via the full-text indexes.

    Users type "babel" or "sindre", not "@babel/core@7.28.4". Falls back to a
    CONTAINS scan if the full-text query still cannot be parsed -- 1265 nodes
    is small enough that a scan is an acceptable safety net, and returning
    something beats returning an error.
    """
    q = _ft_terms(name)
    pkg_keys = ["name", "version", "maintainer_count", "stale_days"]
    person_keys = ["username", "registry_total", "owned", "reach"]
    used_fallback = False

    if q:
        try:
            pkgs = _d(read(graph, _FIND_PKG, {"q": q, "limit": limit}), pkg_keys)
            people = _d(
                read(graph, _FIND_PERSON, {"q": q, "limit": limit}), person_keys
            )
        except Exception:  # noqa: BLE001 - any parse failure falls back
            used_fallback = True
            pkgs, people = [], []
    else:
        used_fallback = True
        pkgs, people = [], []

    if used_fallback or (not pkgs and not people):
        used_fallback = True
        pkgs = _d(
            read(graph, _FIND_PKG_FALLBACK, {"q": name, "limit": limit}), pkg_keys
        )
        people = _d(
            read(graph, _FIND_PERSON_FALLBACK, {"q": name, "limit": limit}),
            person_keys,
        )

    return {
        "answer": {"packages": pkgs, "people": people},
        "path": [],
        "cypher": (_FIND_PKG_FALLBACK if used_fallback else _FIND_PKG).strip(),
        "summary": (
            f"{len(pkgs)} package(s) and {len(people)} person(s) match {name!r}"
            + (" (via CONTAINS fallback)." if used_fallback else ".")
        ),
    }


# --------------------------------------------------- 3. keystone_maintainers --

_KEYSTONE = """
MATCH (x:Person)-[c:CONTROLS]->(a:App)
RETURN x.username, x.email, c.owned, c.reach, c.reach_pct,
       c.amplification, x.registry_total
ORDER BY c.reach DESC
LIMIT $top_n
"""


def keystone_maintainers(graph, top_n: int = 10) -> dict[str, Any]:
    """THE headline. People ranked by how much of the tree they can influence.

    Ranked by graph reach, not by how many packages they own -- those two orders
    genuinely disagree, which is the clearest evidence the traversal matters.
    """
    keys = [
        "username",
        "email",
        "owned",
        "reach",
        "reach_pct",
        "amplification",
        "registry_total",
    ]
    rows = _d(read(graph, _KEYSTONE, {"top_n": top_n}), keys)
    total = read(graph, "MATCH (p:Package) RETURN count(p)")[0][0]

    # Does ownership-order disagree with reach-order? If so, say so explicitly:
    # it is the strongest single argument for the graph being load-bearing.
    by_owned = sorted(rows, key=lambda r: -(r["owned"] or 0))
    disagrees = [r["username"] for r in rows[:5]] != [
        r["username"] for r in by_owned[:5]
    ]

    top = rows[0] if rows else None
    return {
        "answer": {"maintainers": rows, "total_packages": total},
        "path": [],
        "cypher": _KEYSTONE.strip(),
        "summary": (
            f"{top['username']} can publish to {top['owned']} packages but reaches "
            f"{top['reach']} of {total} ({top['reach_pct']}% of the tree). "
            + (
                "Ranking by packages owned gives a different top 5 than ranking by "
                "graph reach, so the traversal is doing real work."
                if disagrees
                else ""
            )
            if top
            else "No CONTROLS edges -- run: python -m keystone.graph.derive"
        ),
    }


# ------------------------------------------------------------- 4. trust_path --

_TRUST_PATH = f"""
MATCH (a:App), (x:Person {{username:$u}})
WITH a, x, shortestPath((a)-[:{TRUST}*1..{MAX_HOPS * 2}]->(x)) AS p
WHERE p IS NOT NULL
RETURN length(p) AS hops,
       [n IN nodes(p) | coalesce(n.name, n.username)] AS chain,
       [n IN nodes(p) | labels(n)[0]] AS kinds
"""


def trust_path(graph, username: str) -> dict[str, Any]:
    """The cited chain from the application to a person.

    This is the explainability artifact: not a score, but the actual route by
    which this human's code reaches production.

    Note the shortestPath placement -- FalkorDB permits it only in WITH/RETURN,
    never inside MATCH.
    """
    rows = read(graph, _TRUST_PATH, {"u": username})
    if not rows:
        return {
            "answer": None,
            "path": [],
            "cypher": _TRUST_PATH.strip(),
            "summary": f"No trust path from the app to {username!r}.",
        }
    hops, chain, kinds = rows[0]
    return {
        "answer": {"hops": hops, "chain": chain, "kinds": kinds},
        "path": [{"name": c, "kind": k} for c, k in zip(chain, kinds)],
        "cypher": _TRUST_PATH.strip(),
        "summary": f"{hops} hops: " + " -> ".join(chain),
    }


# ------------------------------------------------------ 5. hijack_candidates --

# Ordered by the PACKAGE's own transitive dependents, not its maintainer's
# overall reach. Ranking by the maintainer made every package belonging to a
# prolific maintainer report an identical figure, which read as if each one
# reached the whole set.
_HIJACK = """
MATCH (p:Package)-[m:MAINTAINED_BY]->(x:Person)-[c:CONTROLS]->(:App)
WHERE p.maintainer_count = 1 AND p.stale_days > $stale
OPTIONAL MATCH (p)-[h:HOSTED_AT]->(pr:Project)
RETURN p.name, p.version, p.stale_days, p.dependents, x.username,
       c.reach, pr.scorecard, pr.code_review
ORDER BY p.dependents DESC, p.stale_days DESC
LIMIT $limit
"""


def hijack_candidates(
    graph, stale_days: int = STALE_DAYS, limit: int = 15
) -> dict[str, Any]:
    """The xz pattern, as a graph query.

    One maintainer, no release in years, high transitive reach, and weak repo
    process. That combination is what made xz-utils possible, and it is a
    structural property of the graph -- not something a CVE feed can report,
    because no CVE exists yet. This is the "find it before it happens" tool.
    """
    keys = [
        "package",
        "version",
        "stale_days",
        "dependents",
        "maintainer",
        "maintainer_reach",
        "scorecard",
        "code_review",
    ]
    rows = _d(
        read(graph, _HIJACK, {"stale": stale_days, "limit": limit}), keys
    )
    for r in rows:
        r["stale_years"] = round((r["stale_days"] or 0) / 365.0, 1)
        if r["scorecard"] is not None and r["scorecard"] < 0:
            r["scorecard"] = None  # -1 is our "unknown" sentinel
    return {
        "answer": {"candidates": rows, "stale_threshold_days": stale_days},
        "path": [],
        "cypher": _HIJACK.strip(),
        "summary": (
            f"{len(rows)} packages match the xz pattern: a single maintainer, no "
            f"release in over {stale_days // 365} years, and packages still "
            f"depending on them."
            + (
                f" Worst: {rows[0]['package']} -- {rows[0]['stale_years']}y without "
                f"a release, one maintainer ({rows[0]['maintainer']}), and "
                f"{rows[0]['dependents']} packages in this tree depend on it."
                if rows
                else ""
            )
        ),
    }


# ------------------------------------------------ 6. compromise_blast_radius --

_OWNED = """
MATCH (:Person {username:$u})<-[m:MAINTAINED_BY]-(p:Package)
RETURN collect(DISTINCT p.id) AS owned
"""

_STEP = """
MATCH (d:Package)-[e:DEPENDS_ON]->(o:Package)
WHERE o.id IN $frontier
RETURN collect(DISTINCT d.id) AS nxt
"""

_DIRECT_HITS = """
MATCH (a:App)-[e:DEPENDS_ON]->(dep:Package)
WHERE dep.id IN $ids
RETURN dep.name, dep.version
ORDER BY dep.name
"""


def compromise_blast_radius(graph, username: str) -> dict[str, Any]:
    """If this one account is phished tomorrow, what is reachable?

    Expands one hop at a time on purpose. The natural formulation --
    (d)-[:DEPENDS_ON*1..8]->(owned) -- times out, because variable-length
    matching enumerates paths (combinatorial) rather than reachable nodes
    (small). One hop per step is ~5 ms instead of a timeout.
    """
    owned = read(graph, _OWNED, {"u": username})[0][0] or []
    if not owned:
        return {
            "answer": None,
            "path": [],
            "cypher": _OWNED.strip(),
            "summary": f"{username!r} maintains nothing in this tree.",
        }

    visited = set(owned)
    frontier = list(owned)
    depth = 0
    while frontier and depth < MAX_HOPS:
        nxt = read(graph, _STEP, {"frontier": frontier})[0][0] or []
        frontier = [x for x in nxt if x not in visited]
        visited.update(frontier)
        depth += 1

    direct = _d(
        read(graph, _DIRECT_HITS, {"ids": list(visited)}), ["name", "version"]
    )
    total = read(graph, "MATCH (p:Package) RETURN count(p)")[0][0]
    n_direct = read(graph, "MATCH (:App)-[e:DEPENDS_ON]->(p) RETURN count(p)")[0][0]
    path = trust_path(graph, username)

    return {
        "answer": {
            "maintainer": username,
            "owns": len(owned),
            "reach": len(visited),
            "reach_pct": round(100.0 * len(visited) / total, 1),
            "depth": depth,
            "direct_dependencies_hit": direct,
            "direct_total": n_direct,
            "owned_packages": sorted(owned)[:25],
        },
        "path": path["path"],
        "cypher": _STEP.strip(),
        "summary": (
            f"Compromising {username} reaches {len(visited)} of {total} packages "
            f"({round(100.0 * len(visited) / total, 1)}%) in {depth} hops, including "
            f"{len(direct)} of your {n_direct} direct dependencies. "
            f"Trust path: {path['summary']}"
        ),
    }


# -------------------------------------------------------- 7. correlated_risk --

_CORRELATED = """
MATCH (a:Person)-[e:CO_MAINTAINS_WITH]->(b:Person)
MATCH (a)-[ca:CONTROLS]->(:App)
MATCH (b)-[cb:CONTROLS]->(:App)
RETURN a.username, b.username, e.count, ca.reach, cb.reach
ORDER BY e.count DESC
LIMIT $limit
"""


def correlated_risk(graph, limit: int = 12) -> dict[str, Any]:
    """Pairs of accounts that publish to the same packages.

    Shared publish rights mean correlated failure: phishing either account
    reaches every package they share. Counting these pairs needs the maintainer
    graph, and CO_MAINTAINS_WITH was derived by traversal, not ingested.
    """
    keys = ["a", "b", "shared_packages", "a_reach", "b_reach"]
    rows = _d(read(graph, _CORRELATED, {"limit": limit}), keys)
    return {
        "answer": {"pairs": rows},
        "path": [],
        "cypher": _CORRELATED.strip(),
        "summary": (
            f"Top co-maintainer pair: {rows[0]['a']} and {rows[0]['b']} share "
            f"{rows[0]['shared_packages']} packages -- compromising either reaches "
            f"all of them."
            if rows
            else "No co-maintained packages found."
        ),
    }


# ---------------------------------------------------- 8. vulnerability_overlay --

_VULN = """
MATCH (p:Package)-[e:AFFECTED_BY]->(c:CVE)
OPTIONAL MATCH (p)-[m:MAINTAINED_BY]->(x:Person)
RETURN c.id, c.title, c.cvss, c.url, p.name, p.version,
       collect(DISTINCT x.username) AS maintainers
ORDER BY c.cvss DESC
"""

_VULN_ONE = """
MATCH (p:Package)-[e:AFFECTED_BY]->(c:CVE)
WHERE p.name = $name
OPTIONAL MATCH (p)-[m:MAINTAINED_BY]->(x:Person)
RETURN c.id, c.title, c.cvss, c.url, p.name, p.version,
       collect(DISTINCT x.username) AS maintainers
ORDER BY c.cvss DESC
"""


def vulnerability_overlay(graph, package: str | None = None) -> dict[str, Any]:
    """Known advisories, joined to the humans who maintain the affected package.

    Deliberately secondary. A CVE scanner already tells you about disclosed
    vulnerabilities; the point here is the join -- who could introduce the next
    one, and do they also hold other packages in the tree.
    """
    keys = ["cve", "title", "cvss", "url", "package", "version", "maintainers"]
    if package:
        rows = _d(read(graph, _VULN_ONE, {"name": package}), keys)
        cypher = _VULN_ONE
    else:
        rows = _d(read(graph, _VULN), keys)
        cypher = _VULN
    for r in rows:
        if r["cvss"] is not None and r["cvss"] < 0:
            r["cvss"] = None
    return {
        "answer": {"vulnerabilities": rows},
        "path": [],
        "cypher": cypher.strip(),
        "summary": (
            f"{len(rows)} advisory/package pair(s)."
            + (
                f" Highest: {rows[0]['cve']} on {rows[0]['package']} "
                f"(CVSS {rows[0]['cvss']})."
                if rows and rows[0]["cvss"]
                else ""
            )
        ),
    }


# ---------------------------------------------------------------- registry ----

TOOLS = {
    "graph_schema": graph_schema,
    "find_entity": find_entity,
    "keystone_maintainers": keystone_maintainers,
    "trust_path": trust_path,
    "hijack_candidates": hijack_candidates,
    "compromise_blast_radius": compromise_blast_radius,
    "correlated_risk": correlated_risk,
    "vulnerability_overlay": vulnerability_overlay,
}
