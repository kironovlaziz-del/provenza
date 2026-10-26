# Monitoring the installation

Three things watch a Provenza server: the **Observability** page in the
UI, **Grafana** with the full dashboard, and **Prometheus + Alertmanager**,
which turn a problem into a notification. All of them read the same
metrics, served by the API at `backend:8000/metrics` inside the container
network (Caddy does not route `/metrics`).

## The Observability page

Settings → **Observability**, for the server's operator: the
administrators of the organization that runs it (the first one, made by
`create-admin`). Administrators of organizations created later by public
sign-up do not see it - the metrics cover every organization.

The page answers "is everything working" first:

| Check | OK when |
|---|---|
| API | under 1 % of requests answer 5xx; p95 response time beside it |
| Database and queue | PostgreSQL and Redis answer |
| Background jobs | a worker answers and the scheduler beat is recent |
| Egress sensors | every active sensor reports (offline: three missed heartbeats, at least 5 minutes) |
| Audit evidence | every audit record is under a signed checkpoint |
| Data retention | the hourly prune of sensor data ran and did not fail |

Each check that is not ok says what to do. Below: API traffic, response
time (p50 / p95 / p99, without `/system/health`, which waits 1.5 s for
the workers by design), sensor events and the busiest endpoints, over
15 minutes to 24 hours. The page refreshes every 15 seconds, Prometheus'
scrape interval, and pauses while its tab is hidden.

## Grafana

Grafana listens on the server only, `127.0.0.1:3001`. From your machine:

```bash
ssh -L 3001:127.0.0.1:3001 user@server
```

then open http://localhost:3001. The **Provenza — Backend** dashboard opens without
a login (anonymous viewer); editing takes `admin` and `GRAFANA_PASSWORD`
from `deploy/.env`. Rows: Health, API, Egress sensors, Audit & retention.
Dashboards and the data source are provisioned from the repository, so
`provenza rebuild` or `provenza upgrade` keeps them current.

## Alerts

Prometheus (`127.0.0.1:9090`, 30 days of data) evaluates the rules in
`deploy/observability/prometheus/rules/`:

| Alert | Fires when |
|---|---|
| `AuditUnsealedRecords` | the oldest audit record outside a signed checkpoint has waited over 15 minutes (a few minutes between two checkpoints is normal) |
| `AuditCheckpointsMissing` | an organization has audit records and no checkpoint for 30 minutes |
| `AuditLogGrowingFast` | the audit log grew by over 100 000 records in 24 hours (info) |
| `RetentionPruneFailed` | the last prune of sensor activity or violations failed |
| `RetentionPruneStale` | no successful prune for three hours |

Alertmanager (`127.0.0.1:9093`) sends them to the backend, authenticated
with `ALERTMANAGER_SECRET`; the backend sends each alert that names an
organization to that organization's notification channels subscribed to
`alert` (Settings → Notifications). A silent sensor is reported directly,
not through Prometheus: subscribe to `egress_sensor_offline`.

To add a rule, put a `.yml` file next to the others and run
`provenza restart prometheus`; `promtool check rules` validates it first.
