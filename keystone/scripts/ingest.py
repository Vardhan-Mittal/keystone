"""Fetch everything Keystone needs and write it to a single bundle on disk.

Ingestion (network) is deliberately separate from loading (FalkorDB). That means
the graph can be rebuilt without re-fetching, and it makes the offline replay
test honest: KEYSTONE_OFFLINE=1 proves the demo survives an API outage.

Usage:
    python -m keystone.scripts.ingest --app gatsby
    python -m keystone.scripts.ingest --app eslint --version 9.0.0
"""
import argparse
import asyncio
import json
import time
from collections import Counter
from typing import Any

import httpx

from .. import sources as S
from ..config import HTTP_CONCURRENCY, REVERSE_LOOKUP_TOP_N, ROOT

BUNDLE = ROOT / "data" / "bundle.json"


def _ok(results: list[Any]) -> list[Any]:
    """Drop failures and Nones from a gather() batch."""
    return [r for r in results if r and not isinstance(r, BaseException)]


async def build(app_name: str, version: str | None, reverse_top_n: int) -> dict[str, Any]:
    t0 = time.monotonic()
    limits = httpx.Limits(
        max_connections=HTTP_CONCURRENCY * 2,
        max_keepalive_connections=HTTP_CONCURRENCY,
    )
    async with httpx.AsyncClient(limits=limits, follow_redirects=True) as client:
        # 1. Resolve the version a fresh install would get.
        if not version:
            version = await S.default_version(client, app_name)
            if not version:
                raise SystemExit(f"could not resolve a version for {app_name!r}")
        print(f"[1/6] target: {app_name}@{version}")

        # 2. The entire resolved transitive tree -- one single call.
        dg = await S.dependency_graph(client, app_name, version)
        if not dg or not dg.get("nodes"):
            raise SystemExit(f"no dependency graph returned for {app_name}@{version}")
        nodes, edges = dg["nodes"], dg["edges"]
        rel = Counter(n["relation"] for n in nodes)
        print(
            f"[2/6] tree: {len(nodes)} packages, {len(edges)} edges "
            f"({rel.get('DIRECT', 0)} direct, {rel.get('INDIRECT', 0)} indirect)"
        )

        # 3. Publish dates + advisories + source repos, batched.
        keys = [(n["name"], n["version"]) for n in nodes]
        vmeta = await S.version_batch(client, keys)
        print(f"[3/6] version metadata: {len(vmeta)}/{len(keys)} resolved")

        # 4. Maintainer rosters. This is the human pivot -- the whole point.
        names = sorted({n["name"] for n in nodes})
        latest = _ok(await S.gather(S.package_latest(client, n) for n in names))
        by_name = {r["name"]: r for r in latest}

        # Gap-fill passes. npm throttles in bursts, so a handful of packages lose
        # the race even at modest concurrency. Successes are already cached, so
        # each pass only retries what is still missing and converges quickly.
        for attempt in range(3):
            missing = [n for n in names if n not in by_name]
            if not missing:
                break
            print(f"      gap-fill pass {attempt + 1}: retrying {len(missing)}")
            await asyncio.sleep(3)
            for i in range(0, len(missing), 4):
                for r in _ok(
                    await S.gather(
                        S.package_latest(client, n) for n in missing[i : i + 4]
                    )
                ):
                    by_name[r["name"]] = r
        print(f"[4/6] maintainer rosters: {len(by_name)}/{len(names)} packages")

        # 5. Reverse lookup, capped. Ranking by in-tree package count is a cheap
        #    proxy for reach -- real reach needs the graph, which does not exist
        #    yet. Honest limitation: a maintainer of one deeply-depended-on
        #    package can out-rank one holding several leaves, and this proxy
        #    would miss them. The graph corrects the ranking after load; this
        #    only decides whose registry-wide footprint we bother to fetch.
        in_tree = Counter()
        for rec in by_name.values():
            for m in rec["maintainers"]:
                in_tree[m["username"]] += 1
        top = [u for u, _ in in_tree.most_common(reverse_top_n)]
        # Deliberately throttled below the global concurrency: npm's search
        # endpoint rejects bursts, and these are only ~100 calls, so trading a
        # few seconds for a complete result set is the right call.
        foot = []
        for i in range(0, len(top), 4):
            foot += _ok(
                await S.gather(
                    S.maintainer_footprint(client, u) for u in top[i : i + 4]
                )
            )
        print(
            f"[5/6] registry footprint: {len(foot)} of {len(in_tree)} maintainers "
            f"(capped at {reverse_top_n})"
        )

        # 6. Advisory detail + source-project scorecards.
        adv_ids = sorted({a for v in vmeta.values() for a in v["advisories"]})
        repos = sorted(
            {v["repo"] for v in vmeta.values() if v.get("repo")}
            | {
                r["repo_url"].replace("git+", "").replace(".git", "")
                .replace("https://", "").replace("ssh://git@", "")
                for r in by_name.values()
                if r.get("repo_url", "").startswith(("git+https://github.com", "https://github.com"))
            }
        )
        repos = [r for r in repos if r.count("/") == 2 and r.startswith("github.com/")]
        advisories, projects = await asyncio.gather(
            S.gather(S.advisory(client, a) for a in adv_ids),
            S.gather(S.project(client, r) for r in repos),
        )
        advisories, projects = _ok(advisories), _ok(projects)
        print(
            f"[6/6] advisories: {len(advisories)} | projects: {len(projects)} "
            f"(of {len(repos)} repos)"
        )

    bundle = {
        "app": {"name": app_name, "version": version},
        "nodes": nodes,
        "edges": edges,
        "version_meta": [
            {"name": k[0], "version": k[1], **v} for k, v in vmeta.items()
        ],
        "packages": list(by_name.values()),
        "footprints": foot,
        "advisories": advisories,
        "projects": projects,
        "ingested_in_seconds": round(time.monotonic() - t0, 1),
    }
    return bundle


def main() -> None:
    ap = argparse.ArgumentParser(description="Ingest an npm app's supply chain.")
    ap.add_argument("--app", required=True, help="npm package to analyse, e.g. gatsby")
    ap.add_argument("--version", default=None, help="defaults to the registry default")
    ap.add_argument("--reverse-top-n", type=int, default=REVERSE_LOOKUP_TOP_N)
    args = ap.parse_args()

    bundle = asyncio.run(build(args.app, args.version, args.reverse_top_n))
    BUNDLE.parent.mkdir(parents=True, exist_ok=True)
    BUNDLE.write_text(json.dumps(bundle), encoding="utf-8")
    mb = BUNDLE.stat().st_size / 1048576
    print(
        f"\nwrote {BUNDLE.relative_to(ROOT)} ({mb:.1f} MB) "
        f"in {bundle['ingested_in_seconds']}s"
    )


if __name__ == "__main__":
    main()
