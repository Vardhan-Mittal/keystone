"""Smoke tests over a loaded graph.

Not exhaustive -- these assert the properties the submission actually claims, so
that a regression in any of them is caught before it reaches a demo:

  * the graph has the shape the README describes
  * every tool returns the documented contract
  * the ordering inversion that justifies the whole project still holds
  * the router picks the right tool for the questions in the UI

Run:  python -m pytest tests/ -q
Requires FalkorDB up and the graph loaded (docker compose up -d && bootstrap).
"""
import pytest

from keystone.agent import router
from keystone.agent.tools import SPECS, call
from keystone.graph import queries as Q
from keystone.graph.db import GraphUnavailable, connect, read


@pytest.fixture(scope="module")
def graph():
    try:
        g = connect()
    except GraphUnavailable as exc:
        pytest.skip(f"FalkorDB not available: {exc}")
    if not read(g, "MATCH (p:Package) RETURN count(p)")[0][0]:
        pytest.skip("graph is empty -- run: python -m keystone.scripts.bootstrap")
    return g


# ----------------------------------------------------------------- shape ----

def test_graph_has_expected_labels(graph):
    for label in ("App", "Package", "Person"):
        assert read(graph, f"MATCH (n:{label}) RETURN count(n)")[0][0] > 0


def test_derived_edges_exist(graph):
    """CONTROLS and CO_MAINTAINS_WITH are computed, not ingested."""
    assert read(graph, "MATCH ()-[c:CONTROLS]->() RETURN count(c)")[0][0] > 0
    assert read(graph, "MATCH ()-[e:CO_MAINTAINS_WITH]->() RETURN count(e)")[0][0] > 0


def test_every_package_has_a_dependents_count(graph):
    missing = read(
        graph, "MATCH (p:Package) WHERE p.dependents IS NULL RETURN count(p)"
    )[0][0]
    assert missing == 0, f"{missing} packages missing Package.dependents"


def test_app_reaches_a_person(graph):
    """The headline traversal must actually exist in the data."""
    rows = read(
        graph,
        """MATCH (a:App), (x:Person)
           WITH a, x, shortestPath((a)-[:DEPENDS_ON|MAINTAINED_BY*1..16]->(x)) AS p
           WHERE p IS NOT NULL
           RETURN count(x)""",
    )
    assert rows[0][0] > 0


# ----------------------------------------------------------------- tools ----

@pytest.mark.parametrize("name", sorted(Q.TOOLS))
def test_tool_returns_contract(graph, name):
    """Every tool returns answer/path/cypher/summary."""
    args = {}
    if name in ("trust_path", "compromise_blast_radius"):
        args = {"username": _any_person(graph)}
    elif name == "find_entity":
        args = {"name": "babel"}
    out = Q.TOOLS[name](graph, **args)
    assert set(out) >= {"answer", "path", "cypher", "summary"}
    assert isinstance(out["summary"], str) and out["summary"]


def _any_person(graph) -> str:
    return read(
        graph,
        "MATCH (x:Person)-[c:CONTROLS]->(:App) RETURN x.username ORDER BY c.reach DESC LIMIT 1",
    )[0][0]


def test_trust_path_is_a_real_chain(graph):
    out = Q.trust_path(graph, _any_person(graph))
    chain = out["answer"]["chain"]
    assert len(chain) >= 2, "a trust path must have at least an app and a person"
    assert out["answer"]["hops"] == len(chain) - 1
    assert "->" in out["summary"]


def test_reach_is_never_less_than_owned(graph):
    """Reach includes the owned packages themselves, so it cannot be smaller."""
    bad = read(
        graph,
        """MATCH (x:Person)-[c:CONTROLS]->(:App)
           WHERE c.reach < c.owned
           RETURN count(x)""",
    )[0][0]
    assert bad == 0


def test_ordering_by_owned_disagrees_with_ordering_by_reach(graph):
    """The claim the whole project rests on.

    If these two orderings ever agree, counting packages would be sufficient and
    the traversal would be decoration. Measured on gatsby they disagree.
    """
    by_reach = [
        r[0]
        for r in read(
            graph,
            "MATCH (x:Person)-[c:CONTROLS]->(:App) RETURN x.username ORDER BY c.reach DESC LIMIT 10",
        )
    ]
    by_owned = [
        r[0]
        for r in read(
            graph,
            "MATCH (x:Person)-[c:CONTROLS]->(:App) RETURN x.username ORDER BY c.owned DESC LIMIT 10",
        )
    ]
    assert by_reach != by_owned


def test_some_maintainer_is_amplified(graph):
    """At least one account reaches far more than it owns -- the key finding."""
    rows = read(
        graph,
        """MATCH (x:Person)-[c:CONTROLS]->(:App)
           WHERE c.amplification >= 5.0 AND c.reach >= 50
           RETURN count(x)""",
    )
    assert rows[0][0] > 0


def test_hijack_candidates_are_solo_and_stale(graph):
    out = Q.hijack_candidates(graph, limit=20)
    for c in out["answer"]["candidates"]:
        assert c["stale_days"] > out["answer"]["stale_threshold_days"]
        assert c["dependents"] is not None


def test_find_entity_handles_reserved_characters(graph):
    """Scoped names contain RediSearch reserved characters."""
    for q in ("@babel/core", "sindre", "lodash"):
        out = Q.find_entity(graph, q)
        assert "answer" in out  # must not raise


# ---------------------------------------------------------------- router ----

@pytest.mark.parametrize(
    "question,expected",
    [
        ("who controls the most of my dependency tree?", "keystone_maintainers"),
        ("which packages look like the xz backdoor?", "hijack_candidates"),
        ("who has shared publish rights?", "correlated_risk"),
        ("any known CVEs?", "vulnerability_overlay"),
        ("what is in the graph?", "graph_schema"),
    ],
)
def test_router_picks_the_right_tool(graph, question, expected):
    assert router.route(graph, question)["tool"] == expected


def test_router_resolves_a_named_person(graph):
    person = _any_person(graph)
    out = router.route(graph, f"what if {person} gets phished?")
    assert out["tool"] == "compromise_blast_radius"
    assert out["tool_args"]["username"] == person


def test_router_without_a_name_falls_back_to_the_ranking(graph):
    """Asking for a path but naming nobody should still answer usefully."""
    out = router.route(graph, "show me the path to whoever matters most")
    assert out["tool"] in ("keystone_maintainers", "trust_path")


# --------------------------------------------------------------- registry ---

def test_every_spec_maps_to_a_tool():
    assert {s["name"] for s in SPECS} == set(Q.TOOLS)


def test_unknown_tool_returns_an_error_not_an_exception(graph):
    out = call(graph, "no_such_tool", {})
    assert out["answer"] is None and "No such tool" in out["summary"]


def test_bad_arguments_return_an_error_not_an_exception(graph):
    out = call(graph, "trust_path", {"wrong_kwarg": 1})
    assert out["answer"] is None and "Bad arguments" in out["summary"]
