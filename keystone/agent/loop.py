"""The agent: Gemini choosing graph tools, and required to cite its traversal.

Falls back to the deterministic router (router.py) when no API key is set or
Gemini errors out, so the product always answers.

Usage:
    python -m keystone.agent.loop "who controls the most of my dependency tree?"
    python -m keystone.agent.loop --no-llm "what if qix is phished?"
"""
import argparse
import json
import os
import sys
from typing import Any

from ..graph.db import connect
from . import router
from .tools import call, gemini_declarations

# gemini-2.5-flash is closed to new API keys, so new deployments 404 on it.
MODEL = os.getenv("KEYSTONE_MODEL", "gemini-3.8-flash")
MAX_STEPS = 6

SYSTEM = """You are Keystone, an analyst for software supply-chain risk.

You answer questions about ONE application's npm dependency tree using a
FalkorDB graph. The graph links the application to its packages, those packages
to each other, and each package to the human accounts that can publish it.

Your single most important rule: EVERY claim you make about a person or package
must be backed by a traversal you actually ran. Call trust_path (or
compromise_blast_radius, which includes a path) before asserting that someone
can reach the application, and quote the resulting chain in your answer using
the form: gatsby -> debug -> qix

Guidance:
- Prefer graph reach over package counts. A maintainer owning 8 packages can
  outrank one owning 37, because reach depends on position in the graph. If you
  report a ranking, say which measure you used.
- Resolve fuzzy names with find_entity before calling a tool that needs an
  exact username or package name.
- Be precise with numbers and never invent one. If a tool did not return a
  figure, say you do not have it.
- Describe people as occupying a structural position, never as untrustworthy.
  A maintainer with high reach is a concentration of risk in the graph, not a
  suspect. Several are themselves past victims of phishing.
- Keep answers short: the finding, the cited path, then why it matters.
"""


def _client():
    key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not key:
        return None
    try:
        from google import genai

        return genai.Client(api_key=key)
    except Exception as exc:  # noqa: BLE001
        print(f"  (gemini unavailable: {exc})", file=sys.stderr)
        return None


def ask(question: str, *, use_llm: bool = True, verbose: bool = False) -> dict[str, Any]:
    graph = connect()  # raises GraphUnavailable if FalkorDB is down, by design
    client = _client() if use_llm else None
    if client is None:
        return router.route(graph, question)

    from google.genai import types

    config = types.GenerateContentConfig(
        system_instruction=SYSTEM,
        tools=[types.Tool(function_declarations=gemini_declarations())],
        # No temperature override: Gemini 3 is tuned for the default, and Google
        # warns that lowering it can make tool-calling loops repeat themselves.
    )
    contents: list[Any] = [
        types.Content(role="user", parts=[types.Part(text=question)])
    ]
    trace: list[dict[str, Any]] = []

    try:
        for _ in range(MAX_STEPS):
            resp = client.models.generate_content(
                model=MODEL, contents=contents, config=config
            )
            cand = (resp.candidates or [None])[0]
            if cand is None or not cand.content or not cand.content.parts:
                break

            calls = [p.function_call for p in cand.content.parts if p.function_call]
            if not calls:
                text = "".join(p.text or "" for p in cand.content.parts).strip()
                return {
                    "answer": text,
                    "summary": text,
                    "trace": trace,
                    "engine": f"gemini:{MODEL}",
                    "path": trace[-1]["result"].get("path", []) if trace else [],
                    "cypher": trace[-1]["result"].get("cypher", "") if trace else "",
                }

            # The model's turn goes back verbatim: Gemini 3 attaches thought
            # signatures to it and rejects a follow-up that drops them.
            contents.append(cand.content)
            responses = []
            for fc in calls:
                args = dict(fc.args or {})
                result = call(graph, fc.name, args)
                if verbose:
                    print(f"  -> {fc.name}({args}): {result['summary'][:150]}")
                trace.append({"tool": fc.name, "args": args, "result": result})
                responses.append(
                    types.Part.from_function_response(
                        name=fc.name,
                        # The model gets the summary and the path, not whole
                        # result sets: a 1265-row payload wastes the context
                        # window and degrades the answer.
                        response={
                            "summary": result["summary"],
                            "data": _trim(result.get("answer")),
                            "cypher": result.get("cypher", ""),
                        },
                    )
                )
            # Parallel calls are answered together, in one turn.
            contents.append(types.Content(role="user", parts=responses))
    except Exception as exc:  # noqa: BLE001 - any API failure falls back
        print(f"  (gemini failed, using router: {exc})", file=sys.stderr)
        out = router.route(graph, question)
        out["engine"] = "deterministic-router (gemini failed)"
        # Surfaced so a failure is diagnosable from the response, not only from
        # server logs. API errors carry a status and message, never the key.
        out["llm_error"] = str(exc)[:240]
        return out

    out = router.route(graph, question)
    out["engine"] = "deterministic-router (agent did not converge)"
    return out


def _trim(answer: Any, limit: int = 12) -> Any:
    """Shrink tool payloads before handing them to the model."""
    if isinstance(answer, dict):
        return {
            k: (v[:limit] if isinstance(v, list) else v) for k, v in answer.items()
        }
    if isinstance(answer, list):
        return answer[:limit]
    return answer


def main() -> None:
    ap = argparse.ArgumentParser(description="Ask Keystone a question.")
    ap.add_argument("question", nargs="+")
    ap.add_argument(
        "--no-llm",
        action="store_true",
        help="force the deterministic router (no API key needed)",
    )
    ap.add_argument("--json", action="store_true", help="emit raw JSON")
    ap.add_argument("-v", "--verbose", action="store_true", help="show tool calls")
    args = ap.parse_args()

    q = " ".join(args.question)
    out = ask(q, use_llm=not args.no_llm, verbose=args.verbose)

    if args.json:
        print(json.dumps(out, indent=2, default=str))
        return

    print(f"\nQ: {q}")
    print(f"   [engine: {out.get('engine')}", end="")
    if out.get("tool"):
        print(f" | tool: {out['tool']}", end="")
    print("]\n")
    print(out.get("summary") or out.get("answer") or "(no answer)")
    if out.get("path"):
        chain = " -> ".join(
            p["name"] if isinstance(p, dict) else str(p) for p in out["path"]
        )
        print(f"\ncited path: {chain}")
    if out.get("cypher"):
        print("\ncypher that produced this:")
        for line in out["cypher"].splitlines():
            print(f"    {line}")


if __name__ == "__main__":
    main()
