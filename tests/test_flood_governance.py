"""报警洪泛治理：归波、首出、折叠、收敛与安全级直通。"""

from __future__ import annotations

import copy
import json
import urllib.error
import urllib.request

import pytest

from glassmelt.audit.flood import FloodPolicy, govern
from glassmelt.console.api import ConsoleAPI
from glassmelt.console.server import ConsoleServer


def _rec(
    ts: float,
    action: str,
    *,
    severity: str = "warning",
    component: str = "temp",
    subject: str = "anneal_temp",
) -> dict:
    return {
        "record_id": f"{action}-{ts}",
        "ts": float(ts),
        "component": component,
        "action": action,
        "subject": subject,
        "severity": severity,
        "detail": {},
    }


def _get(url: str) -> tuple[int, dict]:
    with urllib.request.urlopen(url, timeout=5.0) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def _post(url: str, payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload or {}).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def test_one_disturbance_folds_into_a_single_wave_with_first_out():
    records = [
        _rec(100.0, "anneal_alarm_set", severity="alarm"),
        _rec(104.0, "anneal_latch_set", subject="anneal_latch"),
        _rec(109.0, "gate_rejected", component="forehearth", subject="forehearth_gate"),
    ]
    view = govern(records, now=120.0, policy=FloodPolicy())
    assert view["totals"]["waves"] == 1
    wave = view["waves"][0]
    assert wave["state"] == "active"
    assert wave["records"] == 3
    assert wave["first_out"]["action"] == "anneal_alarm_set"
    assert wave["first_out"]["safety"] is True
    assert [item["first_out"] for item in wave["safety"]] == [True]
    assert all(not item["first_out"] for item in wave["members"])


def test_repeated_records_are_counted_not_listed():
    records = [
        _rec(100.0 + index * 2.0, "charge_rejected", component="batch", subject="charger")
        for index in range(5)
    ]
    view = govern(records, now=120.0, policy=FloodPolicy())
    wave = view["waves"][0]
    assert len(wave["members"]) == 1
    member = wave["members"][0]
    assert member["occurrences"] == 5
    assert member["first_ts"] == 100.0
    assert member["last_ts"] == 108.0
    assert wave["records"] == 5
    assert wave["suppressed"] == 4
    assert view["totals"]["suppressed"] == 4


def test_waves_split_when_the_gap_exceeds_the_window():
    records = [_rec(100.0, "cut_early", subject="shear"), _rec(200.0, "cut_early", subject="shear")]
    policy = FloodPolicy(group_window_s=30.0, converge_quiet_s=300.0)
    view = govern(records, now=210.0, policy=policy)
    assert view["totals"]["waves"] == 2
    assert view["waves"][0]["wave_id"] == 1
    assert view["waves"][1]["first_out"]["action"] == "cut_early"


def test_recovery_records_converge_the_wave():
    records = [
        _rec(100.0, "anneal_alarm_set", severity="alarm"),
        _rec(104.0, "anneal_latch_set", subject="anneal_latch"),
        _rec(110.0, "anneal_alarm_clear", severity="notice"),
        _rec(111.0, "anneal_latch_released", severity="notice", subject="anneal_latch"),
    ]
    view = govern(records, now=112.0, policy=FloodPolicy())
    wave = view["waves"][0]
    assert wave["state"] == "converged"
    assert wave["converged_by"] == "recovery"
    assert all(item["recovered"] for item in wave["members"] + wave["safety"])
    assert view["totals"]["safety_open"] == 0


def test_recovery_before_the_alarm_does_not_count():
    records = [
        _rec(100.0, "charged", severity="notice", component="batch", subject="charger"),
        _rec(105.0, "charge_rejected", component="batch", subject="charger"),
    ]
    view = govern(records, now=106.0, policy=FloodPolicy())
    wave = view["waves"][0]
    assert wave["members"][0]["recovered"] is False
    assert wave["state"] == "active"


def test_quiet_period_converges_the_wave_without_recovery():
    records = [_rec(100.0, "charge_rejected", component="batch", subject="charger")]
    view = govern(records, now=191.0, policy=FloodPolicy(converge_quiet_s=90.0))
    wave = view["waves"][0]
    assert wave["state"] == "converged"
    assert wave["converged_by"] == "quiet"
    assert wave["members"][0]["recovered"] is False


def test_safety_alarms_are_never_folded():
    records = [
        _rec(100.0 + index, "trip_activated", severity="alarm", subject="trip_interlock")
        for index in range(3)
    ]
    view = govern(records, now=104.0, policy=FloodPolicy())
    wave = view["waves"][0]
    assert len(wave["safety"]) == 3
    assert all(item["occurrences"] == 1 for item in wave["safety"])
    assert wave["suppressed"] == 0
    assert view["totals"]["safety_open"] == 3
    assert [item["wave_id"] for item in view["safety_open"]] == [1, 1, 1]


def test_unrecovered_safety_stays_pinned_after_quiet_convergence():
    records = [_rec(100.0, "trip_activated", severity="alarm", subject="trip_interlock")]
    view = govern(records, now=1000.0, policy=FloodPolicy())
    wave = view["waves"][0]
    assert wave["state"] == "converged"
    assert wave["converged_by"] == "quiet"
    assert view["totals"]["safety_open"] == 1
    assert view["safety_open"][0]["action"] == "trip_activated"


def test_safety_recovers_only_with_matching_notice():
    records = [
        _rec(100.0, "trip_activated", severity="alarm", subject="trip_interlock"),
        _rec(150.0, "trip_reset", severity="notice", subject="trip_interlock"),
    ]
    view = govern(records, now=151.0, policy=FloodPolicy())
    wave = view["waves"][0]
    assert wave["safety"][0]["recovered"] is True
    assert wave["converged_by"] == "recovery"
    assert view["totals"]["safety_open"] == 0


def test_govern_does_not_touch_the_input_records():
    records = [_rec(100.0, "cut_early", subject="shear"), _rec(101.0, "cut_early", subject="shear")]
    snapshot = copy.deepcopy(records)
    govern(records, now=200.0, policy=FloodPolicy())
    assert records == snapshot


def test_empty_records_yield_an_empty_view():
    view = govern([], now=1.0, policy=FloodPolicy())
    assert view["waves"] == []
    assert view["totals"]["alarm_records"] == 0
    assert view["totals"]["safety_open"] == 0


def test_policy_rejects_invalid_windows():
    with pytest.raises(ValueError):
        FloodPolicy(group_window_s=0.0)
    with pytest.raises(ValueError):
        FloodPolicy(converge_quiet_s=-1.0)
    with pytest.raises(ValueError):
        FloodPolicy(safety_severity="fatal")


def test_disturbance_wave_converges_after_recovery(running):
    running.clock.advance(60.0)
    api = ConsoleAPI(running)
    running.evaluate_anneal(running.config.temp.anneal_alarm_c + 8.0)
    for _ in range(6):
        running.clock.advance(2.0)
        rejected = api.start_batch({"path": "resume"})
        assert rejected["ok"] is False

    raw_count = len(running.audit.alarms())
    view = running.flood.view()
    assert view["totals"]["alarm_records"] == raw_count
    wave = view["waves"][-1]
    assert wave["state"] == "active"
    assert wave["first_out"]["action"] == "anneal_alarm_set"
    assert wave["first_out"]["safety"] is True
    assert [item["action"] for item in wave["safety"]] == ["anneal_alarm_set"]
    folded = {item["action"]: item for item in wave["members"]}
    assert folded["error"]["occurrences"] == 6
    assert folded["anneal_latch_set"]["occurrences"] == 1
    assert wave["suppressed"] == 5

    running.reset_lehr("治理测试")
    view = running.flood.view()
    wave = view["waves"][-1]
    assert wave["state"] == "active"
    assert wave["safety"][0]["recovered"] is True
    assert view["totals"]["safety_open"] == 0

    running.clock.advance(200.0)
    view = running.flood.view()
    wave = view["waves"][-1]
    assert wave["state"] == "converged"
    assert wave["converged_by"] == "quiet"
    assert len(running.audit.alarms()) == raw_count


def test_status_and_console_carry_the_governed_view(running):
    status = running.status()
    assert set(status["flood"]) == {"waves", "active_waves", "suppressed", "safety_open"}
    payload = ConsoleAPI(running).alarms()
    assert payload["count"] == len(running.audit.alarms())
    governed = payload["governed"]
    assert governed["totals"]["alarm_records"] == payload["count"]
    assert "waves" in governed
    assert "safety_open" in governed


def test_alarms_endpoint_exposes_governed_view_over_http(platform):
    server = ConsoleServer(platform)
    base = server.start()
    try:
        status, payload = _get(f"{base}/api/alarms")
        assert status == 200
        assert payload["governed"]["totals"]["waves"] == 0
        status, started = _post(f"{base}/api/start")
        assert started["ok"] is True
        status, payload = _get(f"{base}/api/alarms")
        assert status == 200
        assert payload["count"] == payload["governed"]["totals"]["alarm_records"]
    finally:
        server.stop()
