# SIEM export

A SIEM or SOAR pulls the egress sensor events - violations (blocked or
observed connections) and the sample of allowed connections - from one
feed, with a read-only key of the organization.

## Make a key

Settings → **SIEM export** → **New key** (administrators). The key starts
with `pvx_` and is shown once; Provenza keeps only its SHA-256. The list
shows each key's first characters, when it was last used, and lets you
revoke it: a revoked key stops working at once and stays listed, and both
creating and revoking are in the audit log.

A key reads this feed of its own organization and nothing else.

## Read the feed

```bash
curl -H "X-Export-Key: pvx_..." "https://provenza.example.com/api/v1/egress-sensor/events?limit=500"
```

```json
{
  "events": [
    {"event_type": "violation", "id": 812, "sensor_id": 3, "workload_id": 7,
     "action": "blocked", "kind": "connect", "protocol": "tcp",
     "dst_ip": "203.0.113.9", "dst_port": 443, "dst_name": "api.example.net",
     "comm": "python3", "cgroup": "/kubepods/...", "isolated": false,
     "count": 1, "created_at": "2026-10-18T05:21:54.120Z"}
  ],
  "next_cursor": "eyJ0Ijoi..."
}
```

| Parameter | |
|---|---|
| `limit` | 1-2000, default 500 |
| `cursor` | `next_cursor` of the previous page |
| `since`, `until` | ISO 8601; `since` inclusive, `until` exclusive |
| `event_type` | `all` (default), `violation`, `activity` |
| `sensor_id` | one sensor |

Events come newest first. While the answer has `next_cursor`, pass it back
as `?cursor=` for the next page; without it you have everything. The order
is total - time, then violations before activity, then id - so paging never
repeats or skips an event, even when many share one time.

To poll, keep the `created_at` of the newest event you have and ask with
`since=` that time; drop the events you already hold (the same `event_type`
and `id`).

An administrator's session (`Authorization: Bearer ...`) reads the same
feed; a wrong or revoked key gets `401 export_key.invalid`.
