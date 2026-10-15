"""Adapters over the public APIs Keystone ingests.

Every response shape here was verified empirically against the live APIs before
being coded against -- see DECISIONS.md. All of them are public and keyless.
"""
import asyncio
import hashlib
import json
import urllib.parse
from typing import Any, Iterable

import httpx

from .config import DEPSDEV, NPM_REGISTRY
from .fetch import get_json, post_json


def _q(s: str) -> str:
    """URL-encode a package name. Scoped npm names (@babel/core) need both the
    at-sign and the slash escaped, or deps.dev routes the path wrongly."""
    return urllib.parse.quote(s, safe="")


# ---------------------------------------------------------------- deps.dev ----

async def default_version(client: httpx.AsyncClient, name: str) -> str | None:
    """The version deps.dev marks default -- what a fresh install resolves to."""
    data = await get_json(
        client,
        f"{DEPSDEV}/systems/npm/packages/{_q(name)}",
        kind="depsdev_package",
        key=name,
        extract=lambda d: [
            {"version": v["versionKey"]["version"], "isDefault": v.get("isDefault")}
            for v in d.get("versions", [])
        ],
    )
    if not data:
        return None
    for v in data:
        if v.get("isDefault"):
            return v["version"]
    return data[-1]["version"] if data else None


async def dependency_graph(
    client: httpx.AsyncClient, name: str, version: str
) -> dict[str, Any] | None:
    """The whole resolved transitive dependency graph, in a single call.

    Returns nodes as [{name, version, relation}] and edges as
    [{from, to, requirement}] where endpoints are indices into nodes.
    `relation` is SELF for the root, then DIRECT or INDIRECT -- which is how we
    tell the app's own dependencies from everything dragged in beneath them.
    """
    return await get_json(
        client,
        f"{DEPSDEV}/systems/npm/packages/{_q(name)}/versions/{_q(version)}:dependencies",
        kind="depsdev_deps",
        key=f"{name}@{version}",
        extract=lambda d: {
            "nodes": [
                {
                    "name": n["versionKey"]["name"],
                    "version": n["versionKey"]["version"],
                    "relation": n.get("relation", "INDIRECT"),
                }
                for n in d.get("nodes", [])
            ],
            "edges": [
                {
                    "from": e["fromNode"],
                    "to": e["toNode"],
                    "requirement": e.get("requirement", ""),
                }
                for e in d.get("edges", [])
            ],
        },
    )


def _reduce_version(v: dict[str, Any]) -> dict[str, Any]:
    """Keep only the fields the graph needs from a deps.dev version record."""
    repo = ""
    for rp in v.get("relatedProjects") or []:
        pid = (rp.get("projectKey") or {}).get("id", "")
        if not pid:
            continue
        if rp.get("relationType") == "SOURCE_REPO":
            repo = pid
            break
        if not repo:
            repo = pid
    return {
        "name": v["versionKey"]["name"],
        "version": v["versionKey"]["version"],
        "published_at": v.get("publishedAt") or "",
        "is_deprecated": bool(v.get("isDeprecated")),
        "licenses": v.get("licenses") or [],
        "advisories": [a["id"] for a in (v.get("advisoryKeys") or [])],
        "repo": repo,
    }


async def version_batch(
    client: httpx.AsyncClient, keys: list[tuple[str, str]], chunk: int = 500
) -> dict[tuple[str, str], dict[str, Any]]:
    """Publish dates, advisories and source repos for many versions at once.

    deps.dev accepts up to 5000 per request; we chunk at 500 to keep each cached
    payload small and each failure cheap. This single endpoint replaces both a
    per-package date lookup and a separate vulnerability pass.
    """
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for i in range(0, len(keys), chunk):
        batch = keys[i : i + chunk]
        payload = {
            "requests": [
                {"versionKey": {"system": "NPM", "name": n, "version": v}}
                for n, v in batch
            ]
        }
        digest = hashlib.sha256(json.dumps(sorted(batch)).encode()).hexdigest()[:16]
        data = await post_json(
            client,
            f"{DEPSDEV}/versionbatch",
            payload,
            kind="depsdev_versionbatch",
            key=f"chunk-{len(batch)}-{digest}",
        )
        for resp in (data or {}).get("responses", []):
            ver = resp.get("version")
            if not ver:
                continue  # deps.dev knows the name but not that exact version
            rec = _reduce_version(ver)
            out[(rec["name"], rec["version"])] = rec
    return out


async def project(client: httpx.AsyncClient, project_id: str) -> dict[str, Any] | None:
    """Source-project facts, including the OSSF Scorecard.

    Scorecard is the weak-process risk signal: a package can have a healthy
    maintainer count and still have no code review or branch protection.
    """
    return await get_json(
        client,
        f"{DEPSDEV}/projects/{_q(project_id)}",
        kind="depsdev_project",
        key=project_id,
        extract=lambda d: {
            "id": (d.get("projectKey") or {}).get("id", project_id),
            "stars": d.get("starsCount") or 0,
            "forks": d.get("forksCount") or 0,
            "open_issues": d.get("openIssuesCount") or 0,
            "description": (d.get("description") or "")[:300],
            "scorecard": (d.get("scorecard") or {}).get("overallScore"),
            "checks": {
                c.get("name"): c.get("score")
                for c in ((d.get("scorecard") or {}).get("checks") or [])
            },
        },
    )


async def advisory(client: httpx.AsyncClient, adv_id: str) -> dict[str, Any] | None:
    """Advisory detail: title, CVE aliases, CVSS score."""
    return await get_json(
        client,
        f"{DEPSDEV}/advisories/{_q(adv_id)}",
        kind="depsdev_advisory",
        key=adv_id,
        extract=lambda d: {
            "id": (d.get("advisoryKey") or {}).get("id", adv_id),
            "title": (d.get("title") or "")[:300],
            "aliases": d.get("aliases") or [],
            "cvss": d.get("cvss3Score"),
            "url": d.get("url") or "",
        },
    )


# ------------------------------------------------------------------- npm ------

async def package_latest(client: httpx.AsyncClient, name: str) -> dict[str, Any] | None:
    """Maintainer roster for a package, from its latest version manifest.

    Why this endpoint: the full registry document carries `maintainers` but runs
    ~1.6 MB per package (~1.4 GB across this tree). The abbreviated document is
    smaller but drops `maintainers` entirely. The latest-version manifest is
    ~3 KB and keeps both the roster and `_npmUser` -- the account that actually
    published the release, a sharper signal than the roster alone.
    """
    def extract(d: dict[str, Any]) -> dict[str, Any]:
        repo = d.get("repository")
        repo_url = ""
        if isinstance(repo, dict):
            repo_url = repo.get("url") or ""
        elif isinstance(repo, str):
            repo_url = repo
        return {
            "name": d.get("name") or name,
            "version": d.get("version") or "",
            "maintainers": [
                {"username": m.get("name") or "", "email": m.get("email") or ""}
                for m in (d.get("maintainers") or [])
                if m.get("name")
            ],
            "last_publisher": (d.get("_npmUser") or {}).get("name") or "",
            "repo_url": repo_url,
            "deprecated": bool(d.get("deprecated")),
        }

    return await get_json(
        client,
        f"{NPM_REGISTRY}/{_q(name)}/latest",
        kind="npm_latest",
        key=name,
        extract=extract,
    )


async def maintainer_footprint(
    client: httpx.AsyncClient, username: str
) -> dict[str, Any] | None:
    """How many npm packages this person can publish to, registry-wide.

    The reverse of the roster lookup, and the reason the ALSO_MAINTAINS pivot is
    cheap: `total` alone gives the headline ("this account can publish to 412
    packages") without enumerating them all.

    size=20 rather than the 250 maximum: npm's search endpoint throttles large
    result sets hard, and the prolific maintainers who matter most here are
    exactly the ones whose 250-item responses get rejected. A 20-item sample
    plus the authoritative `total` carries the same signal and survives.
    """
    url = (
        f"{NPM_REGISTRY}/-/v1/search"
        f"?text=maintainer:{urllib.parse.quote(username)}&size=20"
    )
    return await get_json(
        client,
        url,
        kind="npm_maintainer",
        key=username,
        extract=lambda d: {
            "username": username,
            "total": d.get("total") or 0,
            "packages": [
                o["package"]["name"]
                for o in (d.get("objects") or [])
                if o.get("package", {}).get("name")
            ],
        },
    )


async def gather(coros: Iterable[Any]) -> list[Any]:
    """asyncio.gather that tolerates individual failures.

    One dead package must not abort a 1400-package ingest, so exceptions come
    back as values and the caller skips them.
    """
    return await asyncio.gather(*coros, return_exceptions=True)
