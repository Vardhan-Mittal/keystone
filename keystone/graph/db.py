"""FalkorDB connection.

Deliberately offers no fallback. If FalkorDB is unreachable, Keystone must fail
loudly rather than degrade to some lesser answer -- the graph is the product, and
a silent fallback would make the removal test meaningless.
"""
from falkordb import FalkorDB

from ..config import FALKOR_HOST, FALKOR_PORT, GRAPH_NAME


class GraphUnavailable(RuntimeError):
    """FalkorDB is not reachable. There is no degraded mode on purpose."""


def connect(name: str | None = None):
    try:
        db = FalkorDB(host=FALKOR_HOST, port=FALKOR_PORT)
        db.connection.ping()
    except Exception as exc:  # noqa: BLE001 - any failure here is fatal by design
        raise GraphUnavailable(
            f"FalkorDB unreachable at {FALKOR_HOST}:{FALKOR_PORT} ({exc}). "
            "Keystone cannot answer anything without the graph -- "
            "start it with: docker compose up -d"
        ) from exc
    return db.select_graph(name or GRAPH_NAME)


def read(graph, cypher: str, params: dict | None = None):
    """Read-only query.

    ro_query is a hard guarantee at the server level that a query cannot mutate
    the graph, which matters because the agent can reach a raw-Cypher tool.
    """
    return graph.ro_query(cypher, params or {}).result_set


def write(graph, cypher: str, params: dict | None = None):
    return graph.query(cypher, params or {})


def _is_empty_key(exc: Exception) -> bool:
    return "empty key" in str(exc).lower()


def count(graph, label: str) -> int:
    """Count nodes of a label, treating a not-yet-created graph as empty.

    FalkorDB raises "Invalid graph operation on empty key" when the graph key
    does not exist at all -- which is the normal state on a fresh volume, not an
    error. Without this, the very first `docker compose up` fails on a clean
    checkout. Any other error still propagates.
    """
    try:
        return read(graph, f"MATCH (n:{label}) RETURN count(n)")[0][0]
    except Exception as exc:  # noqa: BLE001
        if _is_empty_key(exc):
            return 0
        raise


def count_rel(graph, rel: str) -> int:
    """Same tolerance, for relationship counts."""
    try:
        return read(graph, f"MATCH ()-[e:{rel}]->() RETURN count(e)")[0][0]
    except Exception as exc:  # noqa: BLE001
        if _is_empty_key(exc):
            return 0
        raise


def clear(graph) -> None:
    """Delete everything, tolerating a graph that does not exist yet."""
    try:
        write(graph, "MATCH (n) DETACH DELETE n")
    except Exception as exc:  # noqa: BLE001
        if not _is_empty_key(exc):
            raise
