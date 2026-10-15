"""Central configuration. Everything tunable lives here, not scattered in call sites."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / "data" / "cache"

# --- FalkorDB -----------------------------------------------------------------
FALKOR_HOST = os.getenv("FALKOR_HOST", "localhost")
FALKOR_PORT = int(os.getenv("FALKOR_PORT", "6379"))
GRAPH_NAME = os.getenv("KEYSTONE_GRAPH", "keystone")

# --- External APIs (all public, keyless) --------------------------------------
DEPSDEV = "https://api.deps.dev/v3alpha"
NPM_REGISTRY = "https://registry.npmjs.org"
OSV = "https://api.osv.dev/v1"

# --- Ingestion tuning ---------------------------------------------------------
# Concurrency against npm. Measured: 20 sustained triggers HTTP 429 on the
# registry and loses ~35% of maintainer rosters; 8 converges cleanly.
HTTP_CONCURRENCY = int(os.getenv("KEYSTONE_CONCURRENCY", "8"))
HTTP_TIMEOUT = 30.0

# The scaling trap: reverse-looking-up every maintainer turns 2 minutes into an
# hour for zero demo value. Only the highest-reach people get the treatment.
REVERSE_LOOKUP_TOP_N = int(os.getenv("KEYSTONE_REVERSE_TOP_N", "100"))

# Write batches. Per-row queries over thousands of packages take minutes.
WRITE_CHUNK = 1000

# Max hops used by traversal queries. npm trees are deep but not unbounded.
MAX_HOPS = 8

# Set KEYSTONE_OFFLINE=1 to force cache-only operation. Used to prove the demo
# cannot be broken by a rate limit or an outage.
OFFLINE = os.getenv("KEYSTONE_OFFLINE", "") == "1"

# A package with one maintainer and no release in this long is the xz pattern.
STALE_DAYS = 730
