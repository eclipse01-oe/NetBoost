from app.routing.selector import AdaptiveRouteSelector
from app.routing.state import MetricsStore


def test_new_site_starts_direct(tmp_path):
    store = MetricsStore(tmp_path / "state.json")
    selector = AdaptiveRouteSelector(store)
    route, reason = selector.choose("first.example")
    assert route == "direct"
    assert "first visit" in reason


def test_site_uses_vps_after_direct_failure_and_vps_success(tmp_path):
    store = MetricsStore(tmp_path / "state.json")
    store.record_attempt("slow.example", "direct", outcome="failure", connect_ms=4000,
                         reason="setup_failed: TimeoutError")
    store.record_attempt("slow.example", "vps", outcome="success", connect_ms=80,
                         first_byte_ms=220)
    route, reason = AdaptiveRouteSelector(store).choose("slow.example")
    assert route == "vps"
    assert "selected vps" in reason


def test_site_prefers_vps_when_live_vps_measurements_are_materially_better(tmp_path):
    store = MetricsStore(tmp_path / "state.json")
    store.record_attempt("cdn.example", "direct", outcome="success", connect_ms=350,
                         first_byte_ms=900)
    store.record_attempt("cdn.example", "direct", outcome="success", connect_ms=360,
                         first_byte_ms=850)
    store.record_attempt("cdn.example", "vps", outcome="success", connect_ms=80,
                         first_byte_ms=180)
    store.record_attempt("cdn.example", "vps", outcome="success", connect_ms=75,
                         first_byte_ms=190)
    route, _reason = AdaptiveRouteSelector(store).choose("cdn.example")
    assert route == "vps"


def test_recent_failure_switches_to_unmeasured_alternative_on_next_visit(tmp_path):
    store = MetricsStore(tmp_path / "state.json")
    store.record_attempt("unstable.example", "direct", outcome="failure", connect_ms=4000,
                         reason="first_byte_timeout")
    route, reason = AdaptiveRouteSelector(store).choose("unstable.example")
    assert route == "vps"
    assert "unmeasured vps" in reason
