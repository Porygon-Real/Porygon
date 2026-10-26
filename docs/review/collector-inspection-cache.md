# Collector inspection cache

Repeated Docker exec notifications reuse a container snapshot for up to 30 seconds. Lifecycle and network events refresh inspection immediately, including rename, update, pause, unpause, connect and disconnect. Event identity, command attributes, raw evidence and durable outbox checkpoints retain their existing behavior.

Cache entries are scoped by Docker host and container ID. Existing unscoped entries remain readable through the legacy store API but are not trusted by the host-aware normalizer. Startup warming writes host-scoped entries. A failed refresh can use the last known identity without renewing its freshness. Destroy events retain the last known identity for replay after an interrupted outbox write. A clock rollback forces refresh.

## Verification

A deterministic 1,000-event exec burst previously issued 1,000 container inspections and 1,000 image inspections. With the cache, the same burst issues one of each while retaining 1,000 distinct event IDs. This measures inspection calls, not production throughput.

A separate check against a real disposable Docker container normalized 100 distinct events with one container inspection and one image inspection.

The collector suite includes expiry, clock rollback, lifecycle/network refresh, restart persistence, cross-host isolation, failed-refresh freshness and destroy replay tests.

```sh
docker compose exec -T collector pytest -p no:cacheprovider
```

Changes are confined to collector normalization, its existing SQLite cache methods, startup warming and collector tests. No database migration or scoring contract change is required.
