# Deploying Keystone

The hackathon prefers a live deployment. Local `docker compose up` is fully supported and is the
better development setup, but a public URL needs **one container exposing one port** — which is
what `Dockerfile.allinone` is for.

## What the all-in-one image does

`Dockerfile.allinone` builds FalkorDB **and** the app into a single image. On start, `entrypoint.sh`:

1. launches FalkorDB (`redis-server` + `falkordb.so`) in the background,
2. runs `keystone.scripts.bootstrap`, which loads the committed `data/bundle.json` and derives the
   risk edges (~30 s),
3. serves the app on `$PORT`.

It is **stateless on purpose**: no volume, so every restart rebuilds the graph from the committed
bundle. For a demo that is a feature — the deployment is reproducible and cannot drift, and there is
no persistence to misconfigure.

Verified locally:

```bash
docker build -f Dockerfile.allinone -t keystone-allinone .
docker run -d -p 8080:8000 keystone-allinone
# -> localhost:8080, graph built, 1265 packages
```

## Render (easiest free option)

`render.yaml` is a blueprint. Push the repo, then on render.com: **New + → Blueprint → pick this
repo**. It reads the file and builds `Dockerfile.allinone` on the free plan, health-checking
`/api/health`.

Set `GEMINI_API_KEY` in the dashboard if you want the LLM agent; without it the deterministic
router answers.

**Free-tier caveat:** the service sleeps after inactivity, and a cold start re-runs bootstrap, so
the first request after a sleep takes ~40 s. Warm it up before demoing.

## Fly.io

```bash
fly launch --no-deploy --copy-config
fly deploy
```

`fly.toml` requests 1 GB — FalkorDB plus Python needs headroom at boot, and 256 MB is not enough.
Change `primary_region` to the one nearest you.

## Vercel + FalkorDB Cloud

Vercel runs only serverless functions, so FalkorDB cannot live there. The app goes on Vercel
(`app.py` is the entrypoint, `vercel.json` routes every path to it) and the graph lives on a
FalkorDB Cloud instance.

1. Create a free instance on FalkorDB Cloud. Pick AWS `us-east-1`, close to Vercel's default
   function region, because each page load makes about a dozen graph round trips.
2. Add its connection details to the Vercel project (production):
   `FALKOR_HOST`, `FALKOR_PORT`, `FALKOR_USERNAME`, `FALKOR_PASSWORD`, plus `FALKOR_SSL=1` if the
   instance requires TLS. Optionally `GEMINI_API_KEY`.
3. Build the graph once from your machine against that instance:

```bash
vercel env pull .env.local
set -a; . ./.env.local; set +a; python -m keystone.scripts.bootstrap
```

4. `vercel deploy --prod`.

## FalkorDB Cloud + any app host

If you would rather use managed FalkorDB (the rules allow it), skip the all-in-one image: deploy the
plain `Dockerfile` and point it at your instance.

```bash
FALKOR_HOST=<your-instance-host>
FALKOR_PORT=<port>
```

Then run `python -m keystone.scripts.bootstrap` once against it to build the graph.

## Checks after deploying

```bash
curl https://<your-url>/api/health      # {"ok":true,"packages":1265}
curl https://<your-url>/api/overview    # hijack_count should be 498 (as of 18 Oct; see README)
```

Then open the root URL: the hero should read **20.9%** and the dumbbell's top row **qix at 13.8×**.
