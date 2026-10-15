"""Latency for the traversals Keystone actually runs.

Reports p50/p95 per tool on a warm graph. Numbers in the README come from this
script -- run it yourself rather than taking them on trust.

Usage:
    python -m keystone.scripts.benchmark
"""
import statistics
import time

from ..graph.db import connect, read
from ..graph.queries import TOOLS

RUNS = 30

CASES: list[tuple[str, dict]] = [
    ("graph_schema", {}),
    ("find_entity", {"name": "sindre"}),
    ("keystone_maintainers", {"top_n": 10}),
    ("trust_path", {"username": "qix"}),
    ("hijack_candidates", {"limit": 15}),
    ("compromise_blast_radius", {"username": "qix"}),
    ("correlated_risk", {"limit": 12}),
    ("vulnerability_overlay", {}),
]


def main() -> None:
    graph = connect()
    n = read(graph, "MATCH (p:Package) RETURN count(p)")[0][0]
    e = read(graph, "MATCH ()-[r]->() RETURN count(r)")[0][0]
    print(f"graph: {n} packages, {e} relationships | {RUNS} runs per tool\n")
    print(f"  {'tool':26} {'p50':>9} {'p95':>9} {'max':>9}")

    for name, args in CASES:
        fn = TOOLS[name]
        fn(graph, **args)  # warm: first call pays for query-plan caching
        times = []
        for _ in range(RUNS):
            t = time.perf_counter()
            fn(graph, **args)
            times.append((time.perf_counter() - t) * 1000)
        times.sort()
        p50 = statistics.median(times)
        p95 = times[int(len(times) * 0.95) - 1]
        print(f"  {name:26} {p50:7.2f}ms {p95:7.2f}ms {max(times):7.2f}ms")

    print(
        "\nNote: compromise_blast_radius is the expensive one -- it is a real\n"
        "multi-level traversal, not a property lookup. The variable-length\n"
        "formulation of the same question does not appear here because it does\n"
        "not finish: it times out."
    )


if __name__ == "__main__":
    main()
