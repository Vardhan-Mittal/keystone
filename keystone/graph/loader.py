"""Load an ingest bundle into FalkorDB.

Every write is a batched UNWIND. Per-row queries over ~1100 packages and ~2800
edges take minutes; batching takes seconds.

Usage:
    python -m keystone.graph.loader
"""
import datetime as dt
import json
from collections import Counter
from typing import Any, Iterable

from ..config import ROOT, WRITE_CHUNK
from . import schema
from .db import clear, connect, count, read, write

BUNDLE = ROOT / "data" / "bundle.json"
NOW = dt.datetime.now(dt.timezone.utc)


def _chunks(rows: list[Any], n: int = WRITE_CHUNK) -> Iterable[list[Any]]:
    for i in range(0, len(rows), n):
        yield rows[i : i + n]


def _stale_days(published_at: str) -> int:
    """Days since this version was published. -1 when unknown.

    Stored as a number rather than computed at query time so that the staleness
    filter can use a range index -- FalkorDB indexes cannot serve the kind of
    expression a date subtraction would produce.
    """
    if not published_at:
        return -1
    try:
        d = dt.datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    except ValueError:
        return -1
    return (NOW - d).days


def _dedupe(rows: list[dict], *keys: str) -> list[dict]:
    """Collapse rows sharing the same key tuple.

    deps.dev emits the same resolved package once per path that reaches it --
    semver@6.3.1 arrives as 12 separate nodes because 12 parents depend on it.
    Collapsing them is the correct modelling: that is one package with twelve
    incoming edges. It is also what turns the dependency *tree* into the DAG the
    reach queries actually traverse. Deduping here rather than relying on MERGE
    keeps the reported counts honest and cuts the write volume.
    """
    seen, out = set(), []
    for r in rows:
        k = tuple(r[key] for key in keys)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


def _run_batched(graph, cypher: str, rows: list[dict], label: str) -> None:
    if not rows:
        print(f"    {label}: 0 (skipped)")
        return
    for batch in _chunks(rows):
        write(graph, cypher, {"rows": batch})
    print(f"    {label}: {len(rows)}")


def load(bundle: dict[str, Any], graph) -> dict[str, int]:
    app = bundle["app"]
    nodes = bundle["nodes"]
    edges = bundle["edges"]
    vmeta = {(v["name"], v["version"]): v for v in bundle["version_meta"]}
    pkgs = {p["name"]: p for p in bundle["packages"]}
    foot = {f["username"]: f for f in bundle["footprints"]}

    def pid(n: dict) -> str:
        return f"{n['name']}@{n['version']}"

    # ---- nodes ---------------------------------------------------------------
    # Index 0 is the analysed application itself (relation SELF); it becomes the
    # :App node rather than a :Package, so "the app" and "a dependency" stay
    # distinguishable in every traversal.
    root_idx = next(
        (i for i, n in enumerate(nodes) if n.get("relation") == "SELF"), 0
    )

    pkg_rows = []
    for i, n in enumerate(nodes):
        if i == root_idx:
            continue
        meta = vmeta.get((n["name"], n["version"]), {})
        reg = pkgs.get(n["name"], {})
        pkg_rows.append(
            {
                "id": pid(n),
                "name": n["name"],
                "version": n["version"],
                "relation": n["relation"],
                "published_at": meta.get("published_at", ""),
                "stale_days": _stale_days(meta.get("published_at", "")),
                "is_deprecated": bool(meta.get("is_deprecated")) or bool(reg.get("deprecated")),
                "licenses": meta.get("licenses") or [],
                "maintainer_count": len(reg.get("maintainers") or []),
                "last_publisher": reg.get("last_publisher", ""),
            }
        )

    in_tree = Counter()
    for n in nodes:
        for m in (pkgs.get(n["name"], {}).get("maintainers") or []):
            in_tree[m["username"]] += 1

    person_rows = []
    seen_person = set()
    for p in pkgs.values():
        for m in p.get("maintainers") or []:
            u = m["username"]
            if u in seen_person:
                continue
            seen_person.add(u)
            f = foot.get(u) or {}
            person_rows.append(
                {
                    "username": u,
                    "email": m.get("email", ""),
                    # -1 means "not looked up" (outside the capped top-N), which
                    # queries must treat as unknown rather than as zero.
                    "registry_total": f.get("total", -1),
                    "in_tree_count": in_tree.get(u, 0),
                }
            )

    project_rows = [
        {
            "id": pr["id"],
            "stars": pr["stars"],
            "forks": pr["forks"],
            "open_issues": pr["open_issues"],
            "description": pr["description"],
            # None -> -1 so the property stays numeric and range-indexable.
            "scorecard": pr["scorecard"] if pr.get("scorecard") is not None else -1.0,
            "maintained": (pr.get("checks") or {}).get("Maintained", -1),
            "code_review": (pr.get("checks") or {}).get("Code-Review", -1),
            "branch_protection": (pr.get("checks") or {}).get("Branch-Protection", -1),
        }
        for pr in bundle["projects"]
    ]

    cve_rows = [
        {
            "id": a["id"],
            "title": a["title"],
            "aliases": a["aliases"],
            "cvss": a["cvss"] if a.get("cvss") is not None else -1.0,
            "url": a["url"],
        }
        for a in bundle["advisories"]
    ]

    # ---- edges ---------------------------------------------------------------
    app_dep_rows, dep_rows = [], []
    for e in edges:
        a, b = e["from"], e["to"]
        if b == root_idx:
            continue  # an edge back into the root is not meaningful here
        if a == root_idx:
            app_dep_rows.append({"to": pid(nodes[b]), "requirement": e["requirement"]})
        else:
            dep_rows.append(
                {
                    "from": pid(nodes[a]),
                    "to": pid(nodes[b]),
                    "requirement": e["requirement"],
                }
            )

    maint_rows = [
        {"pkg": pid(n), "user": m["username"]}
        for i, n in enumerate(nodes)
        if i != root_idx
        for m in (pkgs.get(n["name"], {}).get("maintainers") or [])
    ]

    project_ids = {pr["id"] for pr in project_rows}
    host_rows = [
        {"pkg": pid(n), "project": vmeta[(n["name"], n["version"])]["repo"]}
        for i, n in enumerate(nodes)
        if i != root_idx
        and vmeta.get((n["name"], n["version"]), {}).get("repo") in project_ids
    ]

    cve_ids = {c["id"] for c in cve_rows}
    affect_rows = [
        {"pkg": pid(n), "cve": adv}
        for i, n in enumerate(nodes)
        if i != root_idx
        for adv in vmeta.get((n["name"], n["version"]), {}).get("advisories", [])
        if adv in cve_ids
    ]

    # Collapse multi-path duplicates so written counts equal stored counts.
    pkg_rows = _dedupe(pkg_rows, "id")
    project_rows = _dedupe(project_rows, "id")
    dep_rows = _dedupe(dep_rows, "from", "to")
    app_dep_rows = _dedupe(app_dep_rows, "to")
    maint_rows = _dedupe(maint_rows, "pkg", "user")
    host_rows = _dedupe(host_rows, "pkg", "project")
    affect_rows = _dedupe(affect_rows, "pkg", "cve")

    # ---- write ---------------------------------------------------------------
    print(f"  wiping graph and rebuilding")
    clear(graph)
    print(f"  indexes: {len(schema.ensure(graph))} ensured")

    write(
        graph,
        "MERGE (a:App {name:$name}) SET a.version=$version",
        {"name": app["name"], "version": app["version"]},
    )

    _run_batched(
        graph,
        """UNWIND $rows AS r
           MERGE (p:Package {id:r.id})
           SET p.name=r.name, p.version=r.version, p.relation=r.relation,
               p.published_at=r.published_at, p.stale_days=r.stale_days,
               p.is_deprecated=r.is_deprecated, p.licenses=r.licenses,
               p.maintainer_count=r.maintainer_count,
               p.last_publisher=r.last_publisher""",
        pkg_rows,
        "Package",
    )
    _run_batched(
        graph,
        """UNWIND $rows AS r
           MERGE (x:Person {username:r.username})
           SET x.email=r.email, x.registry_total=r.registry_total,
               x.in_tree_count=r.in_tree_count""",
        person_rows,
        "Person",
    )
    _run_batched(
        graph,
        """UNWIND $rows AS r
           MERGE (pr:Project {id:r.id})
           SET pr.stars=r.stars, pr.forks=r.forks, pr.open_issues=r.open_issues,
               pr.description=r.description, pr.scorecard=r.scorecard,
               pr.maintained=r.maintained, pr.code_review=r.code_review,
               pr.branch_protection=r.branch_protection""",
        project_rows,
        "Project",
    )
    _run_batched(
        graph,
        """UNWIND $rows AS r
           MERGE (c:CVE {id:r.id})
           SET c.title=r.title, c.aliases=r.aliases, c.cvss=r.cvss, c.url=r.url""",
        cve_rows,
        "CVE",
    )
    _run_batched(
        graph,
        """UNWIND $rows AS r
           MATCH (a:App {name:r.app}), (p:Package {id:r.to})
           MERGE (a)-[e:DEPENDS_ON]->(p)
           SET e.direct=true, e.requirement=r.requirement""",
        [{**r, "app": app["name"]} for r in app_dep_rows],
        "App-DEPENDS_ON->Package",
    )
    _run_batched(
        graph,
        """UNWIND $rows AS r
           MATCH (a:Package {id:r.from}), (b:Package {id:r.to})
           MERGE (a)-[e:DEPENDS_ON]->(b)
           SET e.direct=false, e.requirement=r.requirement""",
        dep_rows,
        "Package-DEPENDS_ON->Package",
    )
    _run_batched(
        graph,
        """UNWIND $rows AS r
           MATCH (p:Package {id:r.pkg}), (x:Person {username:r.user})
           MERGE (p)-[:MAINTAINED_BY]->(x)""",
        maint_rows,
        "MAINTAINED_BY",
    )
    _run_batched(
        graph,
        """UNWIND $rows AS r
           MATCH (p:Package {id:r.pkg}), (pr:Project {id:r.project})
           MERGE (p)-[:HOSTED_AT]->(pr)""",
        host_rows,
        "HOSTED_AT",
    )
    _run_batched(
        graph,
        """UNWIND $rows AS r
           MATCH (p:Package {id:r.pkg}), (c:CVE {id:r.cve})
           MERGE (p)-[:AFFECTED_BY]->(c)""",
        affect_rows,
        "AFFECTED_BY",
    )

    return {
        "packages": len(pkg_rows),
        "people": len(person_rows),
        "projects": len(project_rows),
        "cves": len(cve_rows),
        "dep_edges": len(dep_rows) + len(app_dep_rows),
        "maintained_by": len(maint_rows),
    }


def wait_for_indexes(graph, timeout_s: float = 60.0) -> bool:
    """Block until every index reports OPERATIONAL.

    FalkorDB builds indexes asynchronously, so a traversal issued immediately
    after a bulk load can contend with the build and time out. Running derive
    straight after load failed exactly once this way and then succeeded on a
    retry -- a race, not a bug in the query. Waiting here removes it.
    """
    import time as _t

    deadline = _t.monotonic() + timeout_s
    while _t.monotonic() < deadline:
        try:
            rows = graph.list_indices().result_set
        except Exception:  # noqa: BLE001 - no indexes yet is fine
            return True
        statuses = [r[7] for r in rows if len(r) > 7]
        if all(s == "OPERATIONAL" for s in statuses):
            return True
        _t.sleep(0.5)
    return False


def main() -> None:
    if not BUNDLE.exists():
        raise SystemExit(
            f"{BUNDLE} missing -- run: python -m keystone.scripts.ingest --app gatsby"
        )
    bundle = json.loads(BUNDLE.read_text(encoding="utf-8"))
    graph = connect()
    counts = load(bundle, graph)
    ready = wait_for_indexes(graph)
    print("\n  loaded:", ", ".join(f"{v} {k}" for k, v in counts.items()))
    print(f"  indexes {'operational' if ready else 'STILL BUILDING (derive may be slow)'}")

    # Sanity counts straight back out of the graph. Relationships are aliased
    # and referenced in the RETURN on purpose: FalkorDB only guarantees "at
    # least one match exists" for an unreferenced relationship, which would make
    # these counts silently wrong.
    for label in ("App", "Package", "Person", "Project", "CVE"):
        n = read(graph, f"MATCH (n:{label}) RETURN count(n)")[0][0]
        print(f"    {label:9} {n}")
    for rel in ("DEPENDS_ON", "MAINTAINED_BY", "HOSTED_AT", "AFFECTED_BY"):
        n = read(graph, f"MATCH ()-[e:{rel}]->() RETURN count(e)")[0][0]
        print(f"    {rel:14} {n}")


if __name__ == "__main__":
    main()
