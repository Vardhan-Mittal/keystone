"""Wait for FalkorDB, then build the graph if it is empty.

Lets `docker compose up` produce a working system from a clean checkout with no
manual steps and no network access: the committed bundle is loaded and the
derived edges computed on first start. On later starts the graph is already
populated, so this exits immediately.

Usage:
    python -m keystone.scripts.bootstrap
"""
import sys
import time

from ..config import FALKOR_HOST, FALKOR_PORT
from ..graph import derive, loader
from ..graph.db import GraphUnavailable, connect, count, count_rel, read


def wait_for_falkordb(timeout_s: float = 90.0):
    """Poll until FalkorDB accepts connections, or give up loudly."""
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while time.monotonic() < deadline:
        try:
            return connect()
        except GraphUnavailable:
            attempt += 1
            if attempt % 5 == 1:
                print(f"  waiting for FalkorDB at {FALKOR_HOST}:{FALKOR_PORT}…")
            time.sleep(2)
    raise SystemExit(
        f"FalkorDB never came up at {FALKOR_HOST}:{FALKOR_PORT} after {timeout_s:.0f}s"
    )


def main() -> None:
    graph = wait_for_falkordb()

    packages = count(graph, "Package")
    if packages:
        controls = count_rel(graph, "CONTROLS")
        print(f"  graph already populated: {packages} packages, {controls} CONTROLS")
        if controls:
            return
        print("  CONTROLS missing -- deriving")
    else:
        if not loader.BUNDLE.exists():
            raise SystemExit(
                f"{loader.BUNDLE} missing. Run:\n"
                "  python -m keystone.scripts.ingest --app gatsby"
            )
        print("  empty graph -- loading the committed bundle")
        import json

        bundle = json.loads(loader.BUNDLE.read_text(encoding="utf-8"))
        counts = loader.load(bundle, graph)
        loader.wait_for_indexes(graph)
        print("  loaded:", ", ".join(f"{v} {k}" for k, v in counts.items()))

    total = count(graph, "Package")
    print("  deriving risk edges…")
    n_controls = derive.derive_controls(graph, total)
    n_co = derive.derive_co_maintains(graph)
    n_pkg = derive.derive_package_dependents(graph)
    print(
        f"  derived: {n_controls} CONTROLS, {n_co} CO_MAINTAINS_WITH, "
        f"{n_pkg} package dependent counts"
    )
    print("  ready")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        raise
