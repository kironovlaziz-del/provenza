"""/metrics (app/core/metrics.py): counters of the API processes plus the
gauges each scrape computes from the database."""

from app.core import metrics as m


def test_scrape_gauges_export_only_what_this_scrape_set():
    m.sensors_offline.labels(org_id="999001").set(3)
    out = m.render().decode()
    assert 'sensors_offline{org_id="999001"} 3.0' in out

    # the next scrape starts empty: a sensor or organization that is gone
    # does not keep its last value forever
    for g in m._SCRAPE_GAUGES:
        g.clear()
    out = m.render().decode()
    assert 'org_id="999001"' not in out
    assert "# TYPE sensors_offline gauge" in out


async def test_metrics_endpoint_serves_counters_and_gauges(client):
    await client.get("/health")
    r = await client.get("/metrics")
    assert r.status_code == 200, r.text
    assert "http_requests_total" in r.text
    assert "# TYPE audit_unsealed_records gauge" in r.text
    assert "# TYPE audit_oldest_unsealed_age_seconds gauge" in r.text
