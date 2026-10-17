"""Check every number the README publishes against the live graph.

The README makes specific, checkable claims. Rather than asking anyone to trust
them, this re-derives each one and fails loudly on a mismatch. Run it before
submitting, after any re-ingest, and before recording the demo.

Usage:
    python -m keystone.scripts.verify_claims
"""
import sys

from ..graph import queries as Q
from ..graph.db import connect, count, count_rel, read

FAIL: list[str] = []
WARN: list[str] = []


def check(label: str, actual, expected, *, exact: bool = True) -> None:
    ok = actual == expected if exact else actual >= expected
    op = "==" if exact else ">="
    print(f"  [{'ok ' if ok else 'FAIL'}] {label:46} {actual} {op} {expected}")
    if not ok:
        FAIL.append(f"{label}: got {actual}, README says {expected}")


def soft(label: str, actual, expected) -> None:
    """A claim that can drift legitimately (ties, re-ingest) -- warn, don't fail."""
    ok = actual == expected
    print(f"  [{'ok ' if ok else 'warn'}] {label:46} {actual} (README: {expected})")
    if not ok:
        WARN.append(f"{label}: got {actual}, README says {expected}")


def main() -> None:
    g = connect()
    print("Verifying the claims in README.md against the live graph.\n")

    print("Graph shape")
    check("packages", count(g, "Package"), 1265)
    check("maintainers", count(g, "Person"), 841)
    check("projects", count(g, "Project"), 820)
    check("CVEs", count(g, "CVE"), 25)
    rels = sum(
        count_rel(g, r)
        for r in (
            "DEPENDS_ON",
            "MAINTAINED_BY",
            "HOSTED_AT",
            "AFFECTED_BY",
            "CONTROLS",
            "CO_MAINTAINS_WITH",
        )
    )
    check("total relationships", rels, 10544)

    print("\nHeadline findings")
    top = Q.keystone_maintainers(g, top_n=1)["answer"]["maintainers"][0]
    check("top maintainer is sindresorhus", top["username"], "sindresorhus")
    check("  owns", top["owned"], 153)
    check("  reaches", top["reach"], 264)
    check("  reach_pct rounds to 20.9", round(top["reach_pct"], 1), 20.9)

    solo = read(
        g, "MATCH (p:Package) WHERE p.maintainer_count = 1 RETURN count(p)"
    )[0][0]
    check("single-maintainer packages", solo, 696)
    check("  as a percentage", round(100 * solo / count(g, "Package")), 55)

    dormant = read(
        g,
        """MATCH (p:Package)
           WHERE p.maintainer_count = 1 AND p.stale_days > 730
           RETURN count(DISTINCT p)""",
    )[0][0]
    # Measured from load day, so it drifts upward: 498 as of 2026-10-18 (see README).
    check("solo + dormant 2y+ packages", dormant, 498)

    print("\nThe qix result")
    rows = Q.keystone_maintainers(g, top_n=10)["answer"]["maintainers"]
    qix = next((r for r in rows if r["username"] == "qix"), None)
    check("qix is in the top 10", qix is not None, True)
    if qix:
        check("  owns", qix["owned"], 11)
        check("  reaches", qix["reach"], 152)
        check("  amplification rounds to 13.8", round(qix["amplification"], 1), 13.8)
    path = Q.trust_path(g, "qix")["answer"]
    check("  trust path is 2 hops", path["hops"], 2)
    soft("  via debug", "debug" in path["chain"], True)

    cc = read(
        g,
        """MATCH (p:Package {name:'color-convert'})-[m:MAINTAINED_BY]->(x:Person)
           RETURN x.username, p.maintainer_count, p.dependents
           ORDER BY p.dependents DESC LIMIT 1""",
    )
    check("color-convert sole maintainer is qix", cc[0][0] if cc else None, "qix")
    check("  has one maintainer", cc[0][1] if cc else None, 1)

    print("\nNamed dormant packages")
    for name, years, deps in [("es-errors", 2, 106), ("util-deprecate", 11, 23)]:
        r = read(
            g,
            "MATCH (p:Package {name:$n}) RETURN p.stale_days, p.dependents "
            "ORDER BY p.dependents DESC LIMIT 1",
            {"n": name},
        )
        check(f"{name} dependents", r[0][1] if r else None, deps)
        check(
            f"{name} dormant >= {years}y",
            (r[0][0] if r else 0) >= years * 365,
            True,
        )

    print("\nThe claim the project rests on")
    by_reach = [r["username"] for r in rows[:10]]
    by_owned = [
        x[0]
        for x in read(
            g,
            "MATCH (x:Person)-[c:CONTROLS]->(:App) RETURN x.username "
            "ORDER BY c.owned DESC LIMIT 10",
        )
    ]
    check("owned-order differs from reach-order", by_reach != by_owned, True)
    amplified = read(
        g,
        """MATCH (x:Person)-[c:CONTROLS]->(:App)
           WHERE c.amplification >= 5.0 AND c.reach >= 50
           RETURN count(x)""",
    )[0][0]
    check("maintainers amplified 5x+ with reach 50+", amplified, 1, exact=False)

    print()
    if WARN:
        print(f"{len(WARN)} soft mismatch(es) -- these can drift legitimately:")
        for w in WARN:
            print(f"  - {w}")
    if FAIL:
        print(f"\n{len(FAIL)} CLAIM(S) IN THE README ARE WRONG:")
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)
    print("All README claims verified against the live graph.")


if __name__ == "__main__":
    main()
