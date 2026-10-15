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
