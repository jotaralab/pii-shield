# pii-server on Kubernetes

`pii-server` is the HTTP/JSON + MCP Streamable HTTP front end for
`pii-core`. One image (`pii-shield:<tag>`) runs either as a standalone
Deployment behind a ClusterIP Service, or as a localhost sidecar.

## Files

| File | Purpose |
|---|---|
| `namespace.yaml` | `pii-shield` namespace |
| `configmap.yaml` | Non-secret env vars (`PII_BIND_ADDR`, `PII_TOKEN_FORMAT`, `PII_LOG_FORMAT`) |
| `secret.example.yaml` | Placeholder `PII_SEAL_KEY` secret — replace/rotate; use SealedSecrets/SOPS/ESO in production |
| `deployment.yaml` | Standalone Deployment (2 replicas, hardened securityContext, probes, resource bounds) |
| `service.yaml` | ClusterIP Service `pii-server:80 -> 8080` |
| `sidecar-example.yaml` | Pod template running `pii-server` bound to `127.0.0.1:8080` next to an app container |

## Configuration (environment)

| Variable | Default | Notes |
|---|---|---|
| `PII_BIND_ADDR` | `0.0.0.0:8080` | `127.0.0.1:8080` for sidecars |
| `PII_TOKEN_FORMAT` | `stateless-sealed` | `redis` requires `PII_REDIS_URL` |
| `PII_SEAL_KEY` | — | **Required.** 64-char hex (32-byte key). Generate: `openssl rand -hex 32`. The redis store also seals entries with this key, so it must be stable across pods. |
| `PII_REDIS_URL` | — | Required when `PII_TOKEN_FORMAT=redis` (e.g. `redis://redis:6379`) |
| `PII_MAX_BODY_BYTES` | `1048576` | Max request body; larger bodies get `413` |
| `PII_LOG_FORMAT` | `json` | `json` or `pretty` |

Invalid configuration fails fast at startup with a non-zero exit code.

## Endpoints

- `GET /healthz` — liveness, always `200` while the process lives.
- `GET /readyz` — readiness; pings Redis in `redis` mode, `503` when not ready.
- `GET /metrics` — Prometheus text format (`pii_requests_total`,
  `pii_request_duration_seconds`, `pii_detections_total`).
- `POST /v1/redact` — `{"text": "...", "session_id": "..."}` →
  `{"redacted_text": "...", "entities": [...]}`.
- `POST /v1/rehydrate` — `{"text": "...", "session_id": "..."}` → `{"text": "..."}`.
- `POST|GET /mcp` — MCP Streamable HTTP (JSON-RPC 2.0) exposing
  `redact_text` / `rehydrate_text` tools; `GET` upgrades to SSE.

The server drains in-flight requests on SIGTERM/SIGINT (exit code 0).

## Deploying

```sh
kubectl create namespace pii-shield
kubectl -n pii-shield create secret generic pii-server-seal-key \
  --from-literal=PII_SEAL_KEY="$(openssl rand -hex 32)"
kubectl apply -f deploy/k8s/
kubectl -n pii-shield rollout status deployment/pii-server
```

## Sidecar usage

See `sidecar-example.yaml`. The app container talks to
`http://127.0.0.1:8080`; because the sidecar binds loopback only, no Service
is required and PII never leaves the pod.
