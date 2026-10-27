"""C7 metrics: a closed label set, route templates, and a loopback listener.

The claim under test is not "there are numbers" but "a scrape cannot carry
tenant data". Every label value is either a registered route template or a
member of a closed enum, and the exposition is generated from those values
alone.
"""
from __future__ import annotations

import pytest

from interlock.cloud import metrics
from interlock.cloud.app import CloudApp
from interlock.cloud.config import CloudConfig
from tests._c4_helpers import call, make_app

CONFIG_SECRET = "s" * 32


@pytest.fixture(autouse=True)
def _clean_metrics():
    metrics.reset()
    yield
    metrics.reset()


def _text_app(*, on_app=True):
    return CloudApp(
        CloudConfig(session_secret=CONFIG_SECRET, metrics_on_app=on_app),
        ping=lambda _dsn: True,
    )


# -- the closed contract ------------------------------------------------

def test_every_metric_has_help_and_a_single_kind():
    assert set(metrics.METRIC_LABELS) == (
        set(metrics.COUNTERS) | set(metrics.GAUGES) | set(metrics.HISTOGRAMS))
    assert not (metrics.COUNTERS & metrics.GAUGES)
    assert metrics.HISTOGRAMS == {"il_http_duration_seconds"}
    assert not (metrics.HISTOGRAMS & (metrics.COUNTERS | metrics.GAUGES))
    rendered = metrics.render_metrics()
    for name in metrics.METRIC_LABELS:
        assert "# HELP {}".format(name) in rendered
        assert "# TYPE {}".format(name) in rendered


def test_no_metric_has_a_tenant_identifying_label_name():
    forbidden = {"org", "org_id", "host", "host_id", "review", "review_id",
                 "user", "user_id", "key", "policy_id", "url", "path", "ip"}
    for name, labels in metrics.METRIC_LABELS.items():
        assert not (set(labels) & forbidden), name


def test_every_closed_label_value_is_a_small_enum():
    for label, values in metrics.CLOSED_VALUES.items():
        assert 0 < len(values) <= 32, label
        assert all(isinstance(value, str) for value in values)


def test_a_label_value_outside_its_enum_is_refused():
    with pytest.raises(metrics.MetricsError):
        metrics.inc("il_http_requests_total", route="/healthz",
                    method="BREW", status="200")
    with pytest.raises(metrics.MetricsError):
        metrics.inc("il_http_requests_total", route="/healthz",
                    method="GET", status="418")
    with pytest.raises(metrics.MetricsError):
        metrics.inc("il_webhook_deliveries_total", outcome="maybe")


def test_an_unknown_metric_unknown_label_or_concrete_route_is_refused():
    with pytest.raises(metrics.MetricsError):
        metrics.inc("il_tenant_requests_total")
    with pytest.raises(metrics.MetricsError):
        metrics.inc("il_http_requests_total", route="/healthz", method="GET",
                    status="200", org_id="org-1")
    with pytest.raises(metrics.MetricsError):
        metrics.inc("il_http_requests_total", route="/healthz?org=1",
                    method="GET", status="200")
    with pytest.raises(metrics.MetricsError):
        metrics.inc("il_grants_issued_total", route="/healthz")


def test_a_counter_renders_and_a_gauge_is_last_write_wins():
    metrics.inc("il_http_requests_total", route="/healthz", method="GET",
                status="200")
    metrics.inc("il_http_requests_total", route="/healthz", method="GET",
                status="200")
    metrics.set_gauge("il_reviews_pending", 4)
    metrics.set_gauge("il_reviews_pending", 3)
    rendered = metrics.render_metrics()
    assert ('il_http_requests_total{method="GET",route="/healthz",'
            'status="200"} 2') in rendered
    assert "il_reviews_pending 3" in rendered


def test_a_histogram_renders_cumulative_buckets_sum_and_count():
    metrics.observe("il_http_duration_seconds", 0.25, route="/healthz",
                    method="GET")
    metrics.observe("il_http_duration_seconds", 0.75, route="/healthz",
                    method="GET")
    rendered = metrics.render_metrics()
    assert 'il_http_duration_seconds_bucket{method="GET",route="/healthz",le="0.025"} 0' in rendered
    assert 'il_http_duration_seconds_bucket{method="GET",route="/healthz",le="0.25"} 1' in rendered
    assert 'il_http_duration_seconds_bucket{method="GET",route="/healthz",le="1"} 2' in rendered
    assert 'il_http_duration_seconds_bucket{method="GET",route="/healthz",le="+Inf"} 2' in rendered
    assert 'il_http_duration_seconds_count{method="GET",route="/healthz"} 2' in rendered
    assert 'il_http_duration_seconds_sum{method="GET",route="/healthz"} 1' in rendered


def test_set_gauge_refuses_a_counter_and_observe_refuses_a_gauge():
    with pytest.raises(metrics.MetricsError):
        metrics.set_gauge("il_grants_issued_total", 1)
    with pytest.raises(metrics.MetricsError):
        metrics.observe("il_reviews_pending", 0.1)


def test_reset_drops_values_and_seen_labels():
    metrics.inc("il_webhook_deliveries_total", outcome="delivered")
    assert metrics.seen_labels()
    metrics.reset()
    assert metrics.seen_labels() == {}
    assert "il_grants_issued_total 0" in metrics.render_metrics()


# -- the main app records route templates -------------------------------

def test_requests_are_recorded_under_the_registered_template():
    env = make_app()
    call(env.app, "/healthz")
    call(env.app, "/v1/webhooks/wh_concrete_123/deliveries",
         headers=env.headers)
    call(env.app, "/definitely/tenant-secret-999")

    seen = metrics.seen_labels()
    assert "/healthz" in seen["route"]
    assert "/v1/webhooks/{id}/deliveries" in seen["route"]
    assert "unmatched" in seen["route"]

    rendered = metrics.render_metrics()
    assert "wh_concrete_123" not in rendered
    assert "tenant-secret-999" not in rendered
    assert 'route="/v1/webhooks/{id}/deliveries"' in rendered


def test_a_404_and_a_403_are_counted_with_closed_status_labels():
    env = make_app(role="auditor")
    call(env.app, "/definitely/not/a/route")
    call(env.app, "/v1/org", method="DELETE", headers=env.headers,
         body=b'{"confirm":"acme"}')
    rendered = metrics.render_metrics()
    assert 'status="403"' in rendered
    assert 'status="404"' in rendered


# -- the two ways to expose the endpoint --------------------------------

def test_metrics_are_not_reachable_on_the_main_app_by_default():
    app = _text_app(on_app=False)
    status, _headers, body, _raw = call(app, "/metrics")
    assert status == 404
    assert body["error"]["code"] == "not_found"


def test_metrics_on_the_main_app_are_plain_text_prometheus():
    app = _text_app(on_app=True)
    metrics.inc("il_grants_issued_total")
    status, headers, _body, raw = call(app, "/metrics")
    assert status == 200
    assert headers["content-type"].startswith("text/plain")
    assert "il_grants_issued_total 1" in raw.decode("utf-8")


def test_the_dedicated_listener_serves_only_metrics_and_health():
    app = metrics.MetricsApp()
    metrics.inc("il_receipts_ingested_total", 2)

    status, headers, _body, raw = call(app, "/metrics")
    assert status == 200
    assert headers["content-type"].startswith("text/plain")
    assert "il_receipts_ingested_total 2" in raw.decode("utf-8")

    for path in ("/healthz", "/readyz"):
        status, _headers, _body, raw = call(app, path)
        assert status == 200 and raw == b"ok"
    status, _headers, _body, _raw = call(app, "/v1/org")
    assert status == 404
    status, _headers, _body, _raw = call(app, "/metrics", method="POST")
    assert status == 404


def test_metrics_config_defaults_to_loopback_and_parses_the_env():
    assert CloudConfig().metrics_host == "127.0.0.1"
    assert CloudConfig().metrics_port == 9101
    assert CloudConfig().metrics_on_app is False
    config = CloudConfig.from_env({
        "IL_CLOUD_METRICS_BIND": "0.0.0.0",
        "IL_CLOUD_METRICS_PORT": "9200",
        "IL_CLOUD_METRICS_ON_APP": "1",
    })
    assert config.metrics_host == "0.0.0.0"
    assert config.metrics_port == 9200
    assert config.metrics_on_app is True


def test_a_public_metrics_bind_requires_an_https_public_url():
    from interlock.cloud.config import ConfigError

    with pytest.raises(ConfigError) as exc:
        CloudConfig(dsn="postgresql://db/interlock",
                    session_secret=CONFIG_SECRET,
                    metrics_host="0.0.0.0",
                    public_url="http://cloud.example").validate()
    assert "IL_CLOUD_METRICS_BIND" in str(exc.value)
    CloudConfig(dsn="postgresql://db/interlock",
                session_secret=CONFIG_SECRET,
                metrics_host="0.0.0.0",
                public_url="https://cloud.example").validate()
