"""Index definitions.

Indexes are created BEFORE bulk insert. Creating them afterwards means every
MERGE during load does a label scan, which turns a seconds-long load into a
minutes-long one.

Note on index limitations (verified in FalkorDB's docs): indexes serve equality,
range and string-prefix predicates only -- they do NOT serve `<>`. Every query
in queries.py is written to filter positively for that reason.
"""
from .db import write

# Range indexes back the MERGE/MATCH keys used during load and traversal.
RANGE_INDEXES = [
    ("Package", "id"),
    ("Package", "name"),
    ("Package", "stale_days"),
    ("Package", "maintainer_count"),
    ("Person", "username"),
    ("Project", "id"),
    ("CVE", "id"),
    ("App", "name"),
]

# Full-text indexes power fuzzy entity resolution: users type "babel" or
# "sindre", not "@babel/core@7.28.4".
FULLTEXT_INDEXES = [
    ("Package", "name"),
    ("Person", "username"),
]


def ensure(graph) -> list[str]:
    """Create every index, tolerating ones that already exist."""
    created = []
    for label, prop in RANGE_INDEXES:
        try:
            write(graph, f"CREATE INDEX FOR (n:{label}) ON (n.{prop})")
            created.append(f"range {label}.{prop}")
        except Exception as exc:  # noqa: BLE001
            if "already indexed" not in str(exc).lower():
                raise
    for label, prop in FULLTEXT_INDEXES:
        try:
            write(graph, f"CREATE FULLTEXT INDEX FOR (n:{label}) ON (n.{prop})")
            created.append(f"fulltext {label}.{prop}")
        except Exception as exc:  # noqa: BLE001
            if "already indexed" not in str(exc).lower():
                raise
    return created
