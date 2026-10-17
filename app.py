"""Vercel entrypoint. Vercel's FastAPI support looks for an `app` in app.py.

The graph does not run here: point FALKOR_HOST/PORT/USERNAME/PASSWORD at a
FalkorDB Cloud instance. See DEPLOY.md.
"""
from keystone.api.main import app  # noqa: F401
