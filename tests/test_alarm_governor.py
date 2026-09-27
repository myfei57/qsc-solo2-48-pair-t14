"""报警治理：扰动归波、首出置顶、重复折叠、恢复收敛与安全级保护。"""

from __future__ import annotations

import json
import urllib.request

import pytest

from glassmelt.alarm.governor import AlarmGovernor, RecoverySignals
from glassmelt.app import CycleInputs
from glassmelt.eventbus import Event, EventBus


@pytest.fixture()
def governor(clock) -> AlarmGovernor:
    return AlarmGovernor(
        clock,
        EventBus(),
        window_s=15.0,
        linger_s=30.0,
        safety_linger_s=300.0,
        settle_s=5.0,
        reopen_gap_s=60.0,
    )


def _publish(clock, bus, component, action, severity, subject, **detail):
    clock.advance(0.5)
    bus.publish(
        Event.of(component, component, action, subject=subject, severity=severity, **detail)
    )


def test_disturbance_is_grouped_into_one_wave_with_first_out(clock, governor):
    _publish(clock, governor._bus, "temp", "anneal_alarm_set", "alarm", "anneal_temp")
    for _ in range(10):
        _publish(clock, governor._bus, "batch", "charge_rejected", "warning", "charger")
    _publish(clock, governor._bus, "mold", "blow_rejected", "warning", "blow_station")

    view = governor.view()
    assert view["active_wave_count"] == 1
    wave = view["waves"][0]
    # 真正的第一条（首出）不允许被后续刷屏压到下面。
    assert wave["first_out"]["subject"] == "anneal_temp"
    assert wave["first_out"]["action"] == "anneal_alarm_set"
    assert wave["first_out"]["first_out"] is True
    first_rows = [row for row in view["rows"] if row["first_out"]]
    assert len(first_rows) == 1


def test_repeated_points_are_collapsed_but_raw_records_remain(clock, governor):
    _publish(clock, governor._bus, "batch", "charge_rejected", "warning", "charger")
    for _ in range(11):
        _publish(clock, governor._bus, "batch", "charge_rejected", "warning", "charger")

    view = governor.view()
    charger_rows = [
        row for row in view["rows"] if row["action"] == "charge_rejected"
    ]
    assert len(charger_rows) == 1
    assert charger_rows[0]["count"] == 12
    assert charger_rows[0]["suppressed_count"] == 11
    assert view["suppressed_count"] == 11
    assert view["visible_row_count"] == 1


def test_waves_are_sorted_by_first_out_not_by_latest(clock, governor):
    _publish(clock, governor._bus, "furnace", "draft_low", "alarm", "draft_fan")
    clock.advance(20.0)
    _publish(clock, governor._bus, "batch", "charge_rejected", "warning", "charger")
    _publish(clock, governor._bus, "batch", "charge_rejected", "warning", "charger")

    view = governor.view()
    assert view["active_wave_count"] == 2
    # 活动波按首出时间正序，后到的波不会顶到第一波前面。
    assert view["waves"][0]["first_out"]["subject"] == "draft_fan"
    assert view["waves"][1]["first_out"]["subject"] == "charger"


def test_wave_converges_after_all_points_recover(clock, governor):
    _publish(clock, governor._bus, "batch", "charge_rejected", "warning", "charger")
    _publish(clock, governor._bus, "mold", "blow_rejected", "warning", "blow_station")
    clock.advance(2.0)
    _publish(clock, governor._bus, "batch", "charge_resumed", "notice", "charger")
    _publish(clock, governor._bus, "mold", "mold_reset", "notice", "blow_station")

    # 刚恢复还在 settle 宽限内，不立即收敛。
    assert governor.view()["active_wave_count"] == 1
    clock.advance(6.0)
    view = governor.view()
    assert view["active_wave_count"] == 0
    assert view["converged_wave_count"] == 1
    assert view["waves"][0]["status"] == "converged"
    assert view["waves"][0]["converged_ts"] is not None


def test_momentary_interlock_converges_after_linger(clock, governor):
    # 联锁拒绝类报警没有对应恢复事件，静默超过 linger 后自动收敛。
    _publish(clock, governor._bus, "feeder", "shear_rejected", "warning", "shear")
    clock.advance(20.0)
    assert governor.view()["active_wave_count"] == 1
    clock.advance(16.0)
    assert governor.view()["active_wave_count"] == 0


def test_recovery_without_subject_falls_back_to_component(clock, governor):
    # 恢复事件没有点号（subject 回落成组件名）时按组件兜底恢复。
    _publish(clock, governor._bus, "batch", "charge_rejected", "warning", "charger")
    _publish(clock, governor._bus, "batch", "level_high", "warning", "level_probe")
    clock.advance(1.0)
    _publish(clock, governor._bus, "batch", "batch_reset", "notice", "batch")
    clock.advance(6.0)
    assert governor.view()["active_wave_count"] == 0


def test_point_specific_recovery_does_not_clear_sibling_points(clock, governor):
    _publish(clock, governor._bus, "batch", "charge_rejected", "warning", "charger")
    _publish(clock, governor._bus, "batch", "level_high", "warning", "level_probe")
    clock.advance(1.0)
    _publish(clock, governor._bus, "batch", "charger_reset", "notice", "charger")
    clock.advance(6.0)
    view = governor.view()
    assert view["active_wave_count"] == 1
    assert view["waves"][0]["open_point_count"] == 1
    open_rows = [row for row in view["rows"] if row["open"]]
    assert len(open_rows) == 1
    assert open_rows[0]["subject"] == "level_probe"


def test_safety_alarms_are_never_collapsed(clock, governor):
    _publish(clock, governor._bus, "temp", "trip_activated", "alarm", "trip_interlock", zone="zone-1")
    _publish(clock, governor._bus, "temp", "trip_activated", "alarm", "trip_interlock", zone="zone-2")
    _publish(clock, governor._bus, "burner", "flame_failed", "alarm", "burner-2")

    view = governor.view()
    safety_rows = [row for row in view["rows"] if row["safety"]]
    assert len(safety_rows) == 3
    assert all(row["suppressed_count"] == 0 for row in safety_rows)
    # 同一安全点位来两次，明细也要保留两条（zone 可核对）。
    trip_rows = [row for row in safety_rows if row["action"] == "trip_activated"]
    assert len(trip_rows) == 2
    assert {row["detail"]["zone"] for row in trip_rows} == {"zone-1", "zone-2"}
    assert view["open_safety_count"] == 2  # 按点位计：trip + flame


def test_wave_with_safety_alarm_waits_for_safety_recovery(clock, governor):
    _publish(clock, governor._bus, "temp", "anneal_alarm_set", "alarm", "anneal_temp")
    _publish(clock, governor._bus, "batch", "charge_rejected", "warning", "charger")
    clock.advance(2.0)
    # 普通点位先恢复、普通 linger 也过了，安全点位没恢复 -> 不允许收敛。
    _publish(clock, governor._bus, "batch", "charge_resumed", "notice", "charger")
    clock.advance(40.0)
    assert governor.view()["active_wave_count"] == 1

    # 安全点位恢复后再过 settle，才收敛。
    _publish(clock, governor._bus, "temp", "anneal_alarm_clear", "notice", "anneal_temp")
    clock.advance(6.0)
    view = governor.view()
    assert view["active_wave_count"] == 0
    assert view["waves"][0]["has_safety"] is True


def test_safety_silence_uses_longer_linger(clock, governor):
    _publish(clock, governor._bus, "temp", "trip_activated", "alarm", "trip_interlock")
    clock.advance(40.0)  # 超过普通 linger(30)+settle，但安全点位没有恢复事件
    assert governor.view()["active_wave_count"] == 1
    clock.advance(266.0)  # 超过安全 linger(300)+settle
    assert governor.view()["active_wave_count"] == 0


def test_reopened_wave_merges_repeat_within_reopen_gap(clock, governor):
    _publish(clock, governor._bus, "feeder", "shear_rejected", "warning", "shear")
    clock.advance(36.0)
    assert governor.view()["converged_wave_count"] == 1
    # 静默没好透（距上次上报 40.5s < reopen_gap 60s），同点位再报重开同一波。
    clock.advance(4.5)
    _publish(clock, governor._bus, "feeder", "shear_rejected", "warning", "shear")
    view = governor.view()
    assert view["active_wave_count"] == 1
    assert view["waves"][0]["reopened_count"] == 1
    assert view["waves"][0]["total_count"] == 2


def test_alarm_after_reopen_gap_starts_a_new_wave(clock, governor):
    _publish(clock, governor._bus, "feeder", "shear_rejected", "warning", "shear")
    clock.advance(36.0)
    assert governor.view()["converged_wave_count"] == 1
    clock.advance(30.0)  # 距上次上报 66.5s > reopen_gap
    _publish(clock, governor._bus, "feeder", "shear_rejected", "warning", "shear")
    view = governor.view()
    assert view["active_wave_count"] == 1
    assert view["waves"][0]["reopened_count"] == 0


def test_old_wave_never_absorbs_alarm_beyond_max_window(clock):
    bus = EventBus()
    opened: list[str] = []
    bus.subscribe(
        "alarm",
        lambda event: opened.append(event.action)
        if event.action == "alarm_wave_opened"
        else None,
    )
    governor = AlarmGovernor(
        clock, bus, window_s=15.0, max_window_s=100.0, linger_s=30.0,
        safety_linger_s=300.0, settle_s=5.0, reopen_gap_s=60.0,
    )
    _publish(clock, bus, "furnace", "draft_low", "alarm", "draft_fan")
    clock.advance(120.0)
    _publish(clock, bus, "furnace", "draft_low", "alarm", "draft_fan")
    # 老波超过 max_window 已不能承接新事件，第二个安全事件必须另起一波。
    assert len(opened) == 2
    view = governor.view()
    new_wave = view["waves"][0]
    assert new_wave["status"] == "open"
    assert new_wave["started_ts"] == new_wave["last_ts"]
    assert new_wave["total_count"] == 1


def test_non_alarm_severity_events_are_ignored_unless_recovery(clock, governor):
    _publish(clock, governor._bus, "furnace", "level_observed", "info", "probe")
    _publish(clock, governor._bus, "furnace", "gate_opened", "notice", "gate")
    view = governor.view()
    assert view["active_wave_count"] == 0
    assert view["visible_row_count"] == 0


def test_acknowledge_only_allowed_for_converged_wave(clock, governor):
    _publish(clock, governor._bus, "batch", "charge_rejected", "warning", "charger")
    wave_id = governor.view()["waves"][0]["wave_id"]
    assert governor.acknowledge_wave(wave_id, "确认") is False
    clock.advance(36.0)
    assert governor.view()["converged_wave_count"] == 1
    assert governor.acknowledge_wave(wave_id, "复盘确认") is True
    assert governor.view()["converged_wave_count"] == 0


def test_governor_does_not_recurse_on_its_own_events(clock, governor):
    _publish(clock, governor._bus, "batch", "charge_rejected", "warning", "charger")
    clock.advance(36.0)
    governor.view()
    # 治理器自身发布的 opened/converged 事件不得再开波。
    view = governor.view()
    assert all(
        row["component"] != "alarm" for wave in view["waves"] for row in wave["rows"]
    )


def test_recovery_signal_rules():
    recovery = RecoverySignals()
    assert recovery.is_recovery("temp", "anneal_alarm_clear")
    assert recovery.is_recovery("temp", "trip_reset")
    assert recovery.is_recovery("temp", "anneal_latch_released")
    assert recovery.is_recovery("furnace", "draft_recovered")
    assert recovery.is_recovery("burner", "flame_established")  # 精确匹配
    assert not recovery.is_recovery("batch", "charge_rejected")
    assert not recovery.is_recovery("mold", "blow_rejected")


# ---------------------------------------------------------------- 平台集成

def test_excursion_wave_converges_after_console_reset(running, clock):
    running.evaluate_anneal(running.config.temp.anneal_alarm_c + 8.0)
    view = running.alarm_board.view()
    assert view["active_wave_count"] == 1
    assert view["waves"][0]["first_out"]["action"] == "anneal_alarm_set"
    assert view["open_safety_count"] == 1

    running.reset_lehr("现场复位")
    clock.advance(6.0)
    view = running.alarm_board.view()
    assert view["active_wave_count"] == 0
    assert view["converged_wave_count"] == 1
    # 治理只折叠展示，原始审计一条都不能少。
    raw = running.audit.alarms()
    assert any(item["action"] == "anneal_alarm_set" for item in raw)


def test_cycle_sweep_converges_recovered_waves(running, clock):
    running.evaluate_anneal(running.config.temp.anneal_alarm_c + 6.0)
    running.reset_lehr("复位")
    clock.advance(running.config.alarm_governance.settle_s + 1.0)
    result = running.cycle(CycleInputs(load=0.8, pull_rate=1.0, gob_mass_g=186.0, dt=1.0))
    assert result["alarm_governance"]["converged"]
    assert running.alarm_board.view()["active_wave_count"] == 0


def test_state_snapshot_carries_governance_summary(running):
    running.evaluate_anneal(running.config.temp.anneal_alarm_c + 6.0)
    summary = running.status()["alarm_governance"]
    assert summary["active_wave_count"] == 1
    assert summary["open_safety_count"] == 1


# ---------------------------------------------------------------- HTTP 接口

def test_alarms_endpoint_serves_governed_and_raw_views(running):
    from glassmelt.console.server import ConsoleServer

    running.evaluate_anneal(running.config.temp.anneal_alarm_c + 5.0)
    server = ConsoleServer(running)
    base = server.start()
    try:
        with urllib.request.urlopen(f"{base}/api/alarms", timeout=5) as response:
            governed = json.loads(response.read())
        assert governed["view"] == "governed"
        assert governed["waves"][0]["first_out"]["subject"] == "anneal_temp"
        with urllib.request.urlopen(f"{base}/api/alarms?view=raw", timeout=5) as response:
            raw = json.loads(response.read())
        assert raw["view"] == "raw"
        assert raw["count"] >= 1
    finally:
        server.stop()
