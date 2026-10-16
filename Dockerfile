# Keystone app image. FalkorDB runs as its own service -- see docker-compose.yml.
FROM python:3.12-slim

WORKDIR /app

# Dependencies first so edits to the source do not bust the layer cache.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY keystone/ ./keystone/
COPY web/ ./web/
COPY mcp_server.py .
# The committed bundle is what lets a clean checkout build the graph offline.
COPY data/bundle.json ./data/bundle.json

ENV PYTHONUNBUFFERED=1 \
    FALKOR_HOST=falkordb \
    FALKOR_PORT=6379

EXPOSE 8000

# Build the graph if it is empty, then serve. Idempotent: on a restart the
# bootstrap sees a populated graph and exits straight away.
CMD ["sh", "-c", "python -m keystone.scripts.bootstrap && python -m uvicorn keystone.api.main:app --host 0.0.0.0 --port 8000"]
