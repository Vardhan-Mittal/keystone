# Keystone

**Every dependency scanner looks for broken packages. This one looks for the people.**

Built for [Graph Hacks: Context for AI Agents](https://www.wemakedevs.org/hackathons/falkordb)
(WeMakeDevs × FalkorDB) — **Track 01, Agents That Act on Connected Data**.

---

## The problem

Supply-chain tools answer *"which of my packages have known vulnerabilities?"* That question has
a dozen good answers already.

Nobody answers the question the last three years of real attacks actually turned on:

> **Which individual human beings can push code into my application, and how do they reach it?**

That is not a property of a package. It is a property of a *person's position in a graph* — and
it is invisible to a CVE feed, because when a maintainer account is phished there is no CVE yet.

Keystone loads a real application's resolved npm dependency tree into FalkorDB, adds the human
accounts that hold publish rights on every package in it, and traverses the join between those
two graphs.

## What it found

Pointed at `gatsby@5.16.1` — **1,265 packages, 841 maintainers, 10,544 relationships**:

| Finding | |
|---|---|
| One account (`sindresorhus`) can publish to 153 packages, whose code reaches **264 of 1,265** | **20.9% of the tree** |
| Packages with exactly **one** maintainer | **696 (55%)** |
| Single-maintainer packages, dormant 2+ years, still depended on | **497** |
| `es-errors` — 2.7y without a release, one maintainer | **106 packages depend on it** |
| `js-tokens` — 8.7y without a release, one maintainer | 80 packages depend on it |
| `util-deprecate` — **11 years** without a release, one maintainer, OSSF score 2.3 | 23 packages depend on it |

### The result that validates the whole approach

Keystone ranks **`qix`** in the top 10 — owns 11 packages, reaches 152, an amplification of
**13.8×** — with the shortest trust path `gatsby → debug → qix`.

`qix` is Josh Junon, whose npm account was **compromised by phishing on 8 September 2025**.
Attackers published poisoned versions of 18 packages — including `debug` and `chalk`, the exact
package named in that path — totalling roughly 2 billion weekly downloads, with an estimated
blast radius of **~34% of the npm ecosystem**.

It goes further. Among the dormant single-maintainer packages Keystone flags is **`color-convert`**
— 7.2 years without a release, sole maintainer `qix`, 49 packages in this tree depending on it.
`color-convert` was one of the packages actually poisoned in that attack.

Keystone was pointed at a tree with no connection to that incident and surfaced both the account
that was hijacked and one of the packages it was used to poison, by structure alone. He was the
*victim* of that attack. The tool measures **position in a graph, never a person's
trustworthiness.**

---

## Why this is a graph problem, not a table

**Ranking by packages owned gives a different — and wrong — answer than ranking by graph reach.**

| Maintainer | Can publish to | Actually reaches | |
|---|---|---|---|
| `jonschlinkert` | 37 packages | 82 | |
| `tootallnate` | **8 packages** | **121** | 15× amplification |
| `qix` | 11 packages | 152 | 13.8× |
| `alexeyraspopov` | **1 package** | **104** | 104× |

A maintainer with one package can outrank one with thirty-seven, because influence depends on
*where* their packages sit in the dependency graph. Counting rows cannot discover that; only a
traversal can. The ordering inversion **is** the product.

### The removal test

The hackathon rule: *if the product still works once FalkorDB is removed, the graph is decoration.*

Keystone has **no degraded mode, deliberately**. Try it:

```bash
docker compose stop          # stop FalkorDB
curl localhost:8000/api/overview
# {"error":"graph_unavailable","detail":"FalkorDB unreachable at localhost:6379 ...
#  Keystone cannot answer anything without the graph"}
```

The UI shows the same failure. There is no cache to fall back to and no second data path —
`keystone/graph/db.py` raises `GraphUnavailable` and nothing catches it to substitute an answer.

---

## Graph model

```
(:App)-[:DEPENDS_ON {direct:true}]->(:Package)
(:Package)-[:DEPENDS_ON {requirement}]->(:Package)     resolved transitive tree
(:Package)-[:MAINTAINED_BY]->(:Person)                 ← the human pivot
(:Package)-[:HOSTED_AT]->(:Project)                    OSSF Scorecard
(:Package)-[:AFFECTED_BY]->(:CVE)
(:Person)-[:CO_MAINTAINS_WITH {count}]->(:Person)      DERIVED by traversal
(:Person)-[:CONTROLS {reach, reach_pct, amplification}]->(:App)   DERIVED by traversal
```

| Label | Count | Key properties |
|---|---|---|
| `:App` | 1 | `name`, `version` |
| `:Package` | 1,265 | `name`, `version`, `stale_days`, `maintainer_count`, `dependents` |
| `:Person` | 841 | `username`, `registry_total`, `in_tree_count` |
| `:Project` | 820 | `scorecard`, `stars`, `maintained`, `code_review` |
| `:CVE` | 25 | `id`, `cvss`, `aliases` |

`CONTROLS`, `CO_MAINTAINS_WITH` and `Package.dependents` are **not ingested from any API** — they
are computed by traversal and written back. The graph is the compute substrate, not storage.

### The Cypher the product depends on

**The headline ranking** (`keystone_maintainers`):

```cypher
MATCH (x:Person)-[c:CONTROLS]->(a:App)
RETURN x.username, c.owned, c.reach, c.reach_pct, c.amplification, x.registry_total
ORDER BY c.reach DESC
LIMIT $top_n
```

**The cited trust path** (`trust_path`) — note the `shortestPath` placement:

```cypher
MATCH (a:App), (x:Person {username:$u})
WITH a, x, shortestPath((a)-[:DEPENDS_ON|MAINTAINED_BY*1..16]->(x)) AS p
WHERE p IS NOT NULL
RETURN length(p) AS hops,
       [n IN nodes(p) | coalesce(n.name, n.username)] AS chain
```

**The xz pattern** (`hijack_candidates`) — structural risk with no CVE attached:

```cypher
MATCH (p:Package)-[m:MAINTAINED_BY]->(x:Person)-[c:CONTROLS]->(:App)
WHERE p.maintainer_count = 1 AND p.stale_days > $stale
OPTIONAL MATCH (p)-[h:HOSTED_AT]->(pr:Project)
RETURN p.name, p.version, p.stale_days, p.dependents, x.username, pr.scorecard
ORDER BY p.dependents DESC, p.stale_days DESC
```

**One hop of reach expansion** (`derive.py`) — run level by level, see *Performance* below:

```cypher
MATCH (d:Package)-[e:DEPENDS_ON]->(o:Package)
WHERE o.id IN $frontier
RETURN collect(DISTINCT d.id) AS nxt
```

---

## Performance

`python -m keystone.scripts.benchmark` — 30 runs each, warm graph, 1,265 packages / 10,544 relationships:

| Tool | p50 | p95 |
|---|---|---|
| `find_entity` | 1.17 ms | 2.30 ms |
| `vulnerability_overlay` | 1.33 ms | 1.49 ms |
| `keystone_maintainers` | 2.20 ms | 2.85 ms |
| `trust_path` | 2.37 ms | 3.11 ms |
| `hijack_candidates` | 5.75 ms | 7.47 ms |
| `graph_schema` | 8.04 ms | 14.93 ms |
| `correlated_risk` | 8.67 ms | 10.56 ms |
| `compromise_blast_radius` | 8.89 ms | 14.70 ms |

**The performance lesson worth repeating.** The natural way to write reach is:

```cypher
OPTIONAL MATCH (d:Package)-[:DEPENDS_ON*1..8]->(owned)   -- times out
```

It **times out** on this graph. Variable-length matching enumerates *paths*, and in a dependency
DAG the number of paths is combinatorial while the number of reachable *nodes* is small
(`semver@6.3.1` alone is reached by 12 different parents). Expanding one hop at a time turns a
timeout into **~5 ms per maintainer** — all 841 in 5 seconds.

---

## Running it

### One command (what you probably want)

```bash
docker compose up
```

Then open **localhost:8000**. That is the whole thing.

Nothing else is needed and **no network access is required**: `data/bundle.json` is committed, so on
first start the app loads it into FalkorDB and derives the risk edges itself (~30 s), then serves.
Restarts skip straight to serving. FalkorDB Browser is at **localhost:3000** if you want to walk the
graph by hand.

Verified from a clean volume (`docker compose down -v`), which is also how the one real
packaging bug was found — see DECISIONS §17.

### Local development

Requires Python 3.11+.

```bash
docker compose up -d falkordb             # :6379 server, :3000 browser
pip install -r requirements.txt

python -m keystone.scripts.bootstrap      # load the committed bundle + derive
python -m uvicorn keystone.api.main:app --port 8000

python -m keystone.agent.loop "what if qix gets phished?"
python -m pytest tests/ -q                # 28 smoke tests
```

To rebuild the graph from the live APIs instead of the committed bundle:

```bash
python -m keystone.scripts.ingest --app gatsby   # ~1-8 min cold, instant cached
python -m keystone.graph.loader                  # ~5 s
python -m keystone.graph.derive                  # ~13 s
```

**Point it at your own app:** `python -m keystone.scripts.ingest --app <any-npm-package>`.

### Optional: the agent

Set `GEMINI_API_KEY` for natural-language tool selection. **Without a key everything still
works** — a deterministic router (`keystone/agent/router.py`) picks the tool from keywords and
resolves entity names through the graph's own full-text indexes. That is not a shortcut; it is
so a live demo cannot be killed by a rate limit.

```bash
export GEMINI_API_KEY=...
python -m keystone.agent.loop "who controls the most of my dependency tree?" -v
python -m keystone.agent.loop --no-llm "..."     # force the router
```

### Optional: MCP

The same eight tools over MCP stdio, so any MCP client can reason over the graph:

```bash
claude mcp add keystone -- python mcp_server.py
```

### Troubleshooting

If `docker pull` fails with `httpReadSeeker: failed open ... EOF`, Docker Hub's CDN is
unreachable from your network. Pull through Google's mirror instead:

```bash
docker pull mirror.gcr.io/falkordb/falkordb:latest
docker tag mirror.gcr.io/falkordb/falkordb:latest falkordb/falkordb:latest
```

---

## Data sources — all public, all keyless

No credentials, no private data, nothing behind a login — as the hackathon rules require.

| Source | Gives |
|---|---|
| [deps.dev](https://docs.deps.dev/api/v3alpha/) `GetDependencies` | the entire resolved transitive tree, in **one call** |
| deps.dev `GetVersionBatch` | publish dates + advisories + source repos, 500 at a time |
| deps.dev `GetProject` | OSSF Scorecard, stars, archived flag |
| [npm registry](https://github.com/npm/registry) `/{pkg}/latest` | **maintainer roster** + `_npmUser` |
| npm `/-/v1/search?text=maintainer:<user>` | reverse lookup: packages per account |

Every response is cached to `data/cache/`, so re-ingestion is instant and a demo cannot be broken
by an outage. `KEYSTONE_OFFLINE=1` forces cache-only operation and proves it.

---

## Honest limitations

- **npm only.** deps.dev resolves transitive trees for Cargo, Maven and PyPI too, but npm is the
  only ecosystem exposing both a public maintainer roster *and* a reverse maintainer lookup.
  PyPI does not. This is a deliberate scope decision, not an oversight.
- **npm documents `maintainers` as "informational, not authoritative."** It is the publish-
  permission roster, which is exactly the right signal for this threat model — but it is not a
  cryptographic attestation of who pushed what.
- **The registry-wide footprint is capped** at the top 100 in-tree maintainers. Ranking for that
  cap uses in-tree package count, a proxy that the graph then corrects. Accounts outside the cap
  show `registry_total` as unknown rather than zero.
- **Reach counts packages, not bytes or risk.** A reachable package is not necessarily an
  executed one; `devDependencies` and optional deps are included as deps.dev resolves them.
- **`:Project` ≠ `:Package`.** 820 projects cover 1,265 packages because monorepos publish many
  packages from one repo, so Scorecard data is sparser than package count suggests.
- **A high reach number is not an accusation.** It describes ecosystem concentration. Several
  ranked accounts are themselves past victims.

---

## AI assistance disclosure

Required by the hackathon rules, and stated specifically rather than vaguely.

**Claude Code (Claude Opus) was used as a coding assistant** for scaffolding, boilerplate, the API
adapters, and the UI rendering code.

**What I own and can defend:** the graph model and why each edge exists; the decision to derive
`CONTROLS` / `CO_MAINTAINS_WITH` / `Package.dependents` by traversal and write them back rather
than ingest them; the eight tool queries; the choice of npm as the only viable ecosystem; and the
diagnosis of the two substantive bugs below. Rationale for every judgment call is in
[DECISIONS.md](DECISIONS.md).

Two problems found by testing rather than by reading code, both documented there: the
variable-length reach query that timed out, and hijack candidates being ranked by their
*maintainer's* reach instead of the *package's* — which made every row of a prolific maintainer
report an identical figure.

## Layout

```
keystone/
  config.py      tunables          sources.py    the four public APIs
  fetch.py       cached async HTTP
  graph/
    db.py        connection (no fallback by design)
    schema.py    range + full-text indexes
    loader.py    batched UNWIND writes
    derive.py    CONTROLS, CO_MAINTAINS_WITH, Package.dependents
    queries.py   the 8 tools
  agent/
    tools.py     one registry, three consumers
    router.py    deterministic fallback
    loop.py      Gemini function calling
  api/main.py    FastAPI
  scripts/       ingest.py, benchmark.py
mcp_server.py    the same 8 tools over MCP stdio
web/index.html   the UI
```

MIT licensed.
