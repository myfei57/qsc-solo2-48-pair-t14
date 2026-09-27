"""报警洪泛治理。

扰动一来，联锁拒绝、保护动作与错误落账会在几秒内刷出几十条告警记录，
真正的首出被压在列表下面；扰动过去之后，面板上的条目也不会自己收掉。
本模块在现有审计记录之上做一层治理投影：归波时间窗内的同一波归成一组
并标出首出，同一条报警的重复只累计次数不再占位；波次匹配到恢复记录或
静默超时后自动收敛。安全级（alarm）记录不参与折叠——逐条保留，未恢复
的一律在视图顶层置顶。治理层只读原始记录，不改写、不删除，停炉复盘仍
能拿到完整现场。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..clock import Clock
from .log import AuditLog
from .record import SEVERITY_ORDER

#: 治理视图读取的审计内存窗口，与 audit.log 的内存留存对齐。
_SOURCE_LIMIT = 2000

#: 进入治理视图的最低严重度（warning 及以上算报警）。
_ALARM_FLOOR = SEVERITY_ORDER["warning"]


@dataclass(frozen=True)
class FloodPolicy:
    """洪泛治理的时间窗与安全级约定。"""

    group_window_s: float = 30.0
    converge_quiet_s: float = 90.0
    safety_severity: str = "alarm"

    def __post_init__(self) -> None:
        if self.group_window_s <= 0:
            raise ValueError("归波时间窗必须为正")
        if self.converge_quiet_s <= 0:
            raise ValueError("静默收敛时间必须为正")
        if self.safety_severity not in SEVERITY_ORDER:
            raise ValueError(f"未知的安全级别: {self.safety_severity}")

    def is_alarm_class(self, severity: str) -> bool:
        """该严重度是否进入治理视图（warning 及以上）。"""

        return SEVERITY_ORDER.get(severity, 0) >= _ALARM_FLOOR

    def is_safety(self, severity: str) -> bool:
        """该严重度是否属于安全级（不折叠、未恢复时置顶）。"""

        return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER[self.safety_severity]


def _new_entry(record: dict, ts: float, *, safety: bool) -> dict:
    return {
        "component": record.get("component"),
        "action": record.get("action"),
        "subject": record.get("subject"),
        "severity": record.get("severity"),
        "safety": safety,
        "occurrences": 1,
        "first_ts": round(ts, 3),
        "last_ts": round(ts, 3),
        "recovered": False,
        "first_out": False,
        "detail": record.get("detail") or {},
    }


def _new_wave(wave_id: int, ts: float) -> dict:
    return {
        "wave_id": wave_id,
        "state": "active",
        "converged_by": None,
        "start_ts": round(ts, 3),
        "last_ts": round(ts, 3),
        "records": 0,
        "suppressed": 0,
        "first_out": None,
        "members": [],
        "safety": [],
    }


def _first_out_brief(entry: dict) -> dict:
    return {
        "component": entry["component"],
        "action": entry["action"],
        "subject": entry["subject"],
        "severity": entry["severity"],
        "safety": entry["safety"],
        "ts": entry["first_ts"],
    }


def _has_recovery(recoveries: dict[str, list[float]], subject: str, last_ts: float) -> bool:
    """同一对象在报警之后出现过低于告警级的记录，视为已恢复。"""

    return any(ts >= last_ts - 1e-9 for ts in recoveries.get(subject, ()))


def govern(records: list[dict], now: float, policy: FloodPolicy | None = None) -> dict:
    """把审计记录投影成治理视图。纯函数，不改写输入，落盘回放同样适用。"""

    policy = policy or FloodPolicy()
    ordered = sorted(
        (
            record
            for record in records
            if isinstance(record.get("ts"), (int, float))
        ),
        key=lambda record: float(record["ts"]),
    )
    recoveries: dict[str, list[float]] = {}
    for record in ordered:
        if not policy.is_alarm_class(str(record.get("severity", "info"))):
            recoveries.setdefault(str(record.get("subject", "")), []).append(
                float(record["ts"])
            )

    waves: list[dict] = []
    current: dict | None = None
    members_by_key: dict[tuple[str, str, str], dict] = {}
    for record in ordered:
        severity = str(record.get("severity", "info"))
        if not policy.is_alarm_class(severity):
            continue
        ts = float(record["ts"])
        if current is None or ts - current["last_ts"] > policy.group_window_s:
            current = _new_wave(len(waves) + 1, ts)
            waves.append(current)
            members_by_key = {}
        current["last_ts"] = round(ts, 3)
        current["records"] += 1
        if policy.is_safety(severity):
            entry = _new_entry(record, ts, safety=True)
            current["safety"].append(entry)
        else:
            key = (
                str(record.get("component", "")),
                str(record.get("action", "")),
                str(record.get("subject", "")),
            )
            entry = members_by_key.get(key)
            if entry is not None:
                entry["occurrences"] += 1
                entry["last_ts"] = round(ts, 3)
                current["suppressed"] += 1
                continue
            entry = _new_entry(record, ts, safety=False)
            members_by_key[key] = entry
            current["members"].append(entry)
        if current["first_out"] is None:
            entry["first_out"] = True
            current["first_out"] = _first_out_brief(entry)

    safety_open: list[dict] = []
    for wave in waves:
        entries = wave["members"] + wave["safety"]
        for entry in entries:
            entry["recovered"] = _has_recovery(
                recoveries, str(entry["subject"]), entry["last_ts"]
            )
        if all(entry["recovered"] for entry in entries):
            wave["state"] = "converged"
            wave["converged_by"] = "recovery"
        elif float(now) - wave["last_ts"] > policy.converge_quiet_s:
            wave["state"] = "converged"
            wave["converged_by"] = "quiet"
        for entry in wave["safety"]:
            if not entry["recovered"]:
                safety_open.append({**entry, "wave_id": wave["wave_id"]})

    return {
        "now": round(float(now), 3),
        "policy": {
            "group_window_s": policy.group_window_s,
            "converge_quiet_s": policy.converge_quiet_s,
            "safety_severity": policy.safety_severity,
        },
        "totals": {
            "records": len(ordered),
            "alarm_records": sum(wave["records"] for wave in waves),
            "suppressed": sum(wave["suppressed"] for wave in waves),
            "waves": len(waves),
            "active_waves": sum(1 for wave in waves if wave["state"] == "active"),
            "safety_open": len(safety_open),
        },
        "safety_open": safety_open,
        "waves": waves,
    }


class FloodGovernor:
    """报警面板的治理视图：在现有审计记录上做投影，原始条目一条不动。"""

    def __init__(
        self, clock: Clock, audit: AuditLog, policy: FloodPolicy | None = None
    ) -> None:
        self._clock = clock
        self._audit = audit
        self._policy = policy or FloodPolicy()

    def view(self) -> dict:
        """当前治理视图：波次、首出、折叠计数、收敛状态与置顶安全级。"""

        records = self._audit.entries(limit=_SOURCE_LIMIT)
        return govern(records, now=self._clock.now(), policy=self._policy)

    def summary(self) -> dict:
        """治理概览：嵌进平台状态快照，供控制台与巡检读取。"""

        totals = self.view()["totals"]
        return {
            "waves": totals["waves"],
            "active_waves": totals["active_waves"],
            "suppressed": totals["suppressed"],
            "safety_open": totals["safety_open"],
        }
