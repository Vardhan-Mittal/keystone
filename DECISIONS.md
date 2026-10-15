# Decisions

Why Keystone is built the way it is. Each entry is a judgment call that could reasonably have
gone the other way.

---

## 1. Measure people, not packages

Vulnerability scanning is solved. The unsolved question the last three years of real incidents
turned on — xz-utils, the September 2025 npm compromise — is *who can publish into my tree.*

That reframe is the whole project. It also happens to be irreducibly graph-shaped: the answer
lives in the join between the dependency graph and the maintainer graph, and in a person's
*position*, not their row count.

## 2. Derive `CONTROLS`, `CO_MAINTAINS_WITH` and `Package.dependents` — don't ingest them

These three could have been computed in Python and stored as plain numbers. They are instead
computed **by traversal in FalkorDB and written back as first-class graph objects**.

Reasons, in order of weight:

1. **It is the honest version of the claim.** The project asserts the graph does the real work.
   Computing reach in a Python loop over an adjacency list and calling the database a store would
   make that claim false.
2. **Derived edges are queryable.** `(x:Person)-[c:CONTROLS]->(:App)` can be filtered, ordered and
   joined to anything else. A Python dict cannot.
3. **The agent can reach a conclusion the graph worked out**, rather than recomputing it per
   question.

## 3. Expand one hop at a time instead of using variable-length matching

The natural formulation times out:

```cypher
OPTIONAL MATCH (d:Package)-[:DEPENDS_ON*1..8]->(owned)   -- never finishes
```

**Why:** variable-length matching enumerates *paths*. In a dependency DAG the number of paths is
combinatorial, while the number of reachable *nodes* is small — `semver@6.3.1` is reached from 12
distinct parents, and those multiply along every level. The reachable set is ~200 nodes; the path
count is astronomically larger.

**Fix:** a single-hop `MATCH` per level, with the frontier tracked by the caller. ~5 ms per
maintainer; all 841 in about 5 seconds.

This is still the graph doing the traversal — each level is a graph query against an indexed
property. Only the loop control lives outside, which is how BFS over a graph database is normally
driven.

## 4. Rank hijack candidates by the package's reach, not its maintainer's

**This was a real analytical bug, caught by looking at the rendered table.**

The first version ordered by `c.reach` — the *maintainer's* total reach. Every package belonging
to a prolific maintainer therefore reported the same number (264 for all of `sindresorhus`'s),
which read as though each individual package reached the whole set. It was wrong, and
convincingly wrong, which is worse.

A single package's takeover risk is *how many packages depend on that package*. So
`Package.dependents` is derived per package by the same level-BFS and used for ranking. The
table immediately became meaningful: `define-data-property`, 2.7 years dormant, one maintainer,
52 dependents.

## 4b. Batch deps.dev versions 100 at a time, not 500

**The most dangerous bug in the project, because it failed silently.**

`versionbatch` documents a 5000-request limit, so batching 500 looked conservative. It is not: the
endpoint returns **at most 100 responses** and hands back a `nextPageToken` for the remainder.
Sending 500 therefore returned 100 and discarded the rest without erroring.

The damage was invisible from the outside. Publish dates resolved for **290 of 1,384** packages, so
`stale_days` was `-1` for the other ~1,000 and the entire staleness analysis quietly ran on a fifth
of the tree. Every number it produced was *real* — just drawn from a fraction of the data. Nothing
crashed and nothing looked wrong.

Paging turned out to be worse than avoiding it: `pageToken` as a query parameter returns the
identical page, and in the request body it returns an overlapping one. At `chunk=100` every request
comes back complete with no token at all.

Recovered by the fix: version metadata **290 → 1,266**, advisories **4 → 25**, projects
**685 → 820**, and the top hijack candidate changed from `define-data-property` (52 dependents) to
`es-errors` (**106 dependents**) — a choke point twice the size that the truncated data never saw.

**The lesson:** an API that silently truncates is more dangerous than one that errors. Coverage is
now printed at every ingest step (`1266/1384 resolved`) precisely so this class of gap is visible
rather than assumed.

## 5. npm only

deps.dev resolves transitive dependencies for npm, Cargo, Maven and PyPI. Only npm exposes **both**
a public maintainer roster **and** a reverse maintainer lookup, and both are needed — the roster
for `MAINTAINED_BY`, the reverse lookup for registry-wide footprint. PyPI does not expose
maintainers usably.

Supporting a second ecosystem with half the data would have weakened the central claim rather than
broadened it.

## 6. `/{pkg}/latest`, not the full registry document

Three endpoints could supply maintainers. Measured:

| Endpoint | Size | Has `maintainers` |
|---|---|---|
| `/{pkg}` (full document) | **~1.6 MB** | yes |
| `/{pkg}` abbreviated (corgi `Accept`) | ~700 KB | **no** |
| `/{pkg}/latest` | **~3 KB** | yes, plus `_npmUser` |

Full documents would have meant ~1.4 GB across this tree. The latest-version manifest is ~500×
smaller, and additionally carries `_npmUser` — the account that actually published the release,
a sharper signal than the roster alone. Total ingest traffic: about 4 MB.

## 7. Cap the reverse lookup at 100 maintainers

Registry-wide footprint needs one search call per account; 841 accounts is slow and mostly
uninteresting. Capped at the top 100 by in-tree package count.

**The honest caveat:** in-tree count is a *proxy*, and §4 is precisely the argument that it is a
flawed one — a maintainer of a single deeply-depended-on package could be excluded. It is used
only to decide *whose registry-wide footprint to fetch*, never to rank. Accounts outside the cap
store `registry_total = -1`, which queries must read as **unknown, not zero**.

## 8. `size=20` on the reverse lookup, not the documented maximum of 250

At `size=250`, npm's search endpoint returned HTTP 429 for exactly the accounts that matter most —
`substack`, `feross`, `gaearon`, `sindresorhus` — losing 44 of 100 lookups. The prolific
maintainers have the largest result sets and get throttled hardest.

`total` is authoritative regardless of page size, and 20 names are plenty for a sample. Combined
with exponential backoff and a concurrency of 4 on that endpoint: 100 of 100.

## 9. Global concurrency 8, with gap-fill passes

Measured: 20 concurrent requests against the npm registry triggers 429s and loses ~35% of
maintainer rosters. 8 converges. Successes are cached, so gap-fill passes only retry what is
still missing — 1133/1133 rosters.

## 10. Cache every response to disk

Not an optimisation. Two reasons: development iteration becomes instant, and **a live demo cannot
be broken by a rate limit or an upstream outage.** `KEYSTONE_OFFLINE=1` refuses network access
entirely and replays from cache, which is also the test that proves it.

## 11. No degraded mode, anywhere

`keystone/graph/db.py` raises `GraphUnavailable` and nothing catches it to substitute an answer.
The API returns 503; the UI says so; the MCP server returns a readable tool error.

This is a deliberate response to the hackathon's central rule. A fallback cache or a secondary
data path would make the removal test unfalsifiable — and the removal test is the strongest
evidence that the graph is load-bearing.

## 12. Separate ingestion from loading

`scripts/ingest.py` writes `data/bundle.json`; `graph/loader.py` reads it. The graph can be
rebuilt without re-fetching, the offline replay test is clean, and a loader bug costs seconds
instead of minutes.

## 13. Dedupe before writing, rather than relying on MERGE

deps.dev emits the same resolved package once per path that reaches it. Deduping in the loader
keeps reported counts equal to stored counts — the first run claimed 1,383 packages written and
1,265 stored, which looked like data loss and was not.

Collapsing those duplicates is also what turns the dependency *tree* into the DAG the reach
queries traverse. Packages are keyed `name@version`, so 114 names legitimately present at multiple
versions stay distinct.

## 14. Skip vector indexes

FalkorDB supports them, and semantic search over package descriptions would demo well. It is
deliberately out of scope: traversal is the entire story here, and an embeddings pass would
consume time that the graph model, the derived edges and the removal test deserved more.

## 15. Charts chosen by data job, not by preference

- **Single ratio → meter, not a pie or donut.** A two-slice pie is a stat tile with extra steps.
- **Maintainers are nominal → one colour for every bar.** A darker-where-bigger ramp would
  double-encode bar length as hue and burn the only free channel.
- **Owned vs reached → dumbbell**, one hue in two validated shades. This is the chart that carries
  the thesis, so it gets the clearest form for before/after per item.
- **No force-directed node graph.** 1,265 nodes is a hairball that communicates nothing. The real
  graph is shown in FalkorDB Browser, where exploring it is the point.
- Palette shades were run through a contrast/CVD validator for both light and dark surfaces rather
  than eyeballed.

## 16. Naming a real person in the output

`qix` appears in the demo because the graph ranked him top-10 independently, and because his
account really was phished in September 2025 — which makes the result verifiable rather than
anecdotal.

The framing is load-bearing: the tool measures **structural position, never trustworthiness**. He
was the victim of that attack. Both the README and the UI footer say so explicitly, and the
agent's system prompt instructs it to describe maintainers as concentrations of risk rather than
as suspects.
