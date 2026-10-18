"""HTTP metrics label each request with its full route template (main.py
_route_template), so a dashboard can tell which API a path belongs to."""


async def test_http_metrics_label_the_full_route_template(client):
    # "/config" alone says nothing: the label carries the router's prefix
    await client.get("/api/v1/egress-sensor/config")  # no key: 401, still a matched route
    await client.get("/api/v1/egress-sensor/sensors/12345")  # a path parameter
    r = await client.get("/metrics")
    assert r.status_code == 200
    assert 'path="/api/v1/egress-sensor/config"' in r.text
    assert 'path="/api/v1/egress-sensor/sensors/{sensor_id}"' in r.text
    assert 'path="/config"' not in r.text
