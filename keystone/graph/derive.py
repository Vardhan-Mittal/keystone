"""Compute risk edges and write them back into the graph.

This is the step that makes FalkorDB the compute substrate rather than a filing
cabinet: nothing here is ingested from an API. CONTROLS and CO_MAINTAINS_WITH
are *derived* by traversal and then persisted as first-class edges, so the agent
can query a conclusion the graph itself worked out.

Two implementation notes worth knowing (both learned the hard way):

1. The obvious formulation -- OPTIONAL MATCH (d)-[:DEPENDS_ON*1..8]->(owned) --
   TIMES OUT. Variable-length matching enumerates *paths*, and in a dependency
   DAG the number of paths is combinatorial while the number of reachable
   *nodes* is small. Expanding one level at a time and letting FalkorDB do each
   hop turns a timeout into ~5 ms per person.

2. Ownership count is a *bad* proxy for influence, which is the whole reason
   this traversal has to exist. Measured on gatsby: tootallnate can publish to
   only 8 packages but reaches 121, while jonschlinkert holds 37 and reaches 82.
   Ranking by ownership gets the order wrong.

Usage:
    python -m keystone.graph.derive
"""
import time

from ..config import MAX_HOPS
from .db import connect, read, write

# One hop of reverse dependency expansion. `e` is aliased deliberately: FalkorDB
# only guarantees "at least one matching relationship exists" when a
# relationship is left unreferenced, so aliasing keeps the semantics explicit.
_STEP = """
MATCH (d:Package)-[e:DEPENDS_ON]->(o:Package)
WHERE o.id IN $frontier
RETURN collect(DISTINCT d.id) AS nxt
"""

_OWNED = """
MATCH (:Person {username:$u})<-[m:MAINTAINED_BY]-(p:Package)
RETURN collect(DISTINCT p.id) AS owned
"""

_PEOPLE = "MATCH (x:Person) RETURN x.username ORDER BY x.username"


def reach_set(graph, username: str) -> tuple[set[str], int, int]:
    """Packages whose code this person can influence, by reverse traversal.

    Returns (reachable ids, owned count, traversal depth). The set is every
    package that transitively depends on something they can publish to, plus
    those packages themselves -- i.e. the blast radius of this one account.
    """
    owned = read(graph, _OWNED, {"u": username})[0][0] or []
    visited: set[str] = set(owned)
    frontier = list(owned)
    depth = 0
    while frontier and depth < MAX_HOPS:
        nxt = read(graph, _STEP, {"frontier": frontier})[0][0] or []
        frontier = [x for x in nxt if x not in visited]
        visited.update(frontier)
        depth += 1
    return visited, len(owned), depth


def derive_controls(graph, total_packages: int) -> int:
    """Person-[:CONTROLS]->App, carrying reach and amplification."""
    people = [r[0] for r in read(graph, _PEOPLE)]
    rows = []
    for u in people:
        reachable, owned, depth = reach_set(graph, u)
        if not owned:
            continue
        rows.append(
            {
                "u": u,
                "owned": owned,
                "reach": len(reachable),
                "reach_pct": round(100.0 * len(reachable) / total_packages, 2),
                # How much the dependency graph multiplies this account's
                # footprint. High amplification is the interesting signal: it
                # means a small maintainer sits at a structural choke point.
                "amplification": round(len(reachable) / owned, 2),
                "depth": depth,
            }
        )
    write(
        graph,
        """UNWIND $rows AS r
           MATCH (x:Person {username:r.u}), (a:App)
           MERGE (x)-[c:CONTROLS]->(a)
           SET c.owned=r.owned, c.reach=r.reach, c.reach_pct=r.reach_pct,
               c.amplification=r.amplification, c.depth=r.depth""",
        {"rows": rows},
    )
    return len(rows)


_ALL_PACKAGES = "MATCH (p:Package) RETURN p.id ORDER BY p.id"


def derive_package_dependents(graph) -> int:
    """Package.dependents -- how many packages transitively depend on this one.

    Distinct from a maintainer's reach, and the correct weight for ranking a
    single *package* as a takeover target. Ordering hijack candidates by their
    maintainer's reach instead made every row of a prolific maintainer's
    packages report the same number, which read as though each package reached
    the whole set.

    Same one-hop-per-level expansion as reach_set, for the same reason.
    """
    ids = [r[0] for r in read(graph, _ALL_PACKAGES)]
    rows = []
    for pid in ids:
        visited: set[str] = set()
        frontier = [pid]
        depth = 0
        while frontier and depth < MAX_HOPS:
            nxt = read(graph, _STEP, {"frontier": frontier})[0][0] or []
            frontier = [x for x in nxt if x not in visited and x != pid]
            visited.update(frontier)
            depth += 1
        rows.append({"id": pid, "n": len(visited)})
    write(
        graph,
        """UNWIND $rows AS r
           MATCH (p:Package {id:r.id})
           SET p.dependents = r.n""",
        {"rows": rows},
    )
    try:
        write(graph, "CREATE INDEX FOR (p:Package) ON (p.dependents)")
    except Exception as exc:  # noqa: BLE001
        if "already indexed" not in str(exc).lower():
            raise
    return len(rows)


def derive_co_maintains(graph, min_shared: int = 2) -> int:
    """Person-[:CO_MAINTAINS_WITH]->Person for people sharing packages.

    This is the shared-account surface: when two accounts both publish to the
    same several packages, compromising either one reaches all of them. Stored
    once per unordered pair (a.username < b.username) so the edge is not
    duplicated in both directions.
    """
    write(
        graph,
        """MATCH (a:Person)<-[m1:MAINTAINED_BY]-(p:Package)-[m2:MAINTAINED_BY]->(b:Person)
           WHERE a.username < b.username
           WITH a, b, count(DISTINCT p) AS shared
           WHERE shared >= $min_shared
           MERGE (a)-[e:CO_MAINTAINS_WITH]->(b)
           SET e.count = shared""",
        {"min_shared": min_shared},
    )
    # Report the total, not relationships_created: MERGE is idempotent, so a
    # re-run creates nothing and "0 edges" would read as a failure.
    return read(graph, "MATCH ()-[e:CO_MAINTAINS_WITH]->() RETURN count(e)")[0][0]


def main() -> None:
    graph = connect()
    total = read(graph, "MATCH (p:Package) RETURN count(p)")[0][0]
    if not total:
        raise SystemExit("graph is empty -- run: python -m keystone.graph.loader")

    t = time.monotonic()
    n_controls = derive_controls(graph, total)
    t_controls = time.monotonic() - t

    t = time.monotonic()
    n_co = derive_co_maintains(graph)
    t_co = time.monotonic() - t

    t = time.monotonic()
    n_pkg = derive_package_dependents(graph)
    t_pkg = time.monotonic() - t

    print(f"  CONTROLS:          {n_controls} edges  [{t_controls:.1f}s]")
    print(f"  CO_MAINTAINS_WITH: {n_co} edges  [{t_co:.1f}s]")
    print(f"  Package.dependents:{n_pkg} packages  [{t_pkg:.1f}s]")

    print("\n  top keystone maintainers by graph reach:")
    rows = read(
        graph,
        """MATCH (x:Person)-[c:CONTROLS]->(:App)
           RETURN x.username, c.owned, c.reach, c.reach_pct, c.amplification,
                  x.registry_total
           ORDER BY c.reach DESC LIMIT 10""",
    )
    print(f"    {'maintainer':20} {'owns':>5} {'reach':>6} {'% tree':>7} {'amp':>6} {'registry':>9}")
    for u, owned, reach, pct, amp, reg in rows:
        reg_s = "unknown" if reg is None or reg < 0 else str(reg)
        print(f"    {u:20} {owned:5} {reach:6} {pct:6.1f}% {amp:6.1f} {reg_s:>9}")

    print("\n  highest amplification (small footprint, structural choke point):")
    rows = read(
        graph,
        """MATCH (x:Person)-[c:CONTROLS]->(:App)
           WHERE c.owned <= 10 AND c.reach >= 50
           RETURN x.username, c.owned, c.reach, c.amplification
           ORDER BY c.amplification DESC LIMIT 8""",
    )
    for u, owned, reach, amp in rows:
        print(f"    {u:20} owns {owned:3} -> reaches {reach:5}  ({amp:.0f}x)")


if __name__ == "__main__":
    main()
