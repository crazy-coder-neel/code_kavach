# Phase 1 local deployment

With Docker installed, run from the workspace root:

```bash
docker compose -f deploy/compose.yml up --build -d
curl --fail http://127.0.0.1:8000/readyz
curl --fail http://127.0.0.1:8000/v1/guard -H 'Content-Type: application/json' -d '{"code":"value = 1"}'
```

The container runs as UID 10001 with a read-only filesystem, writable temporary audit storage, dropped capabilities and a readiness health check. Audit data in tmpfs is temporary; durable tamper-evident storage arrives in Phase 7. The image uses the existing Uvicorn dependency and one worker for its one-CPU allocation. Gunicorn/uvloop/httptools and the production worker model require licence review and measured comparison in the deployment/performance phase.

Docker and Azure CLI are absent in the current workspace, so the image build and cloud deployment have **not** been verified. Local HTTP smoke tests use the Python environment directly. Do not claim the localhost URL as the organizer-facing endpoint. Azure resource provisioning, Supabase, TLS and public ingress remain pending.

For Python-only development, use `bash scripts/start-local.sh`; this starts API and frontend together after dependencies are installed. Vite is a development server, not the production console host.
