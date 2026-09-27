"""报警波次治理器。

治理器订阅事件总线的全量事件，只处理面板级别（warning 及以上）的报警，把一
次扰动期间的报警归成"波"（wave）：

* **首出**：波内第一条报警，面板按首出时间排序，真正的第一条永远在最上面；
* **压重**：同一指纹（组件＋对象＋动作）在同一波内的重复上报折叠成
  ``suppressed_count``，原始记录仍逐条留在审计日志里，随时可展开核对；
* **收敛**：点位恢复（clear/reset/release 等恢复事件）后波自动收敛；没有
  恢复事件的瞬时联锁报警，静默超过 linger 秒后也自动收敛，避免恢复后堆一屏；
* **安全级**：severity=alarm 的报警永不折叠，每一条都单独成行；含安全报警
  的波必须等安全点位全部恢复（或安全事件静默超过安全 linger）才允许收敛，
  不会因为普通点位先好就把波提前收掉。

治理器是只读派生层：它不改事件、不改审计、不参与控制，只回答
"面板现在该显示什么"。
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field

from ..eventbus import Event, EventBus

#: 面板关注的严重度；info/notice 属于过程信息，不进报警治理。
PANEL_SEVERITIES = ("warning", "alarm")
SAFE_SEVERITY = "alarm"
GOVERNOR_COMPONENT = "alarm"


@dataclass(frozen=True)
class RecoverySignals:
    """恢复事件的识别规则。

    ``action_keywords``：动作名命中任一关键字即视为恢复事件；
    ``recovered_actions``：组件+动作的精确匹配，用于动作名不带恢复关键字、
    但语义上就是恢复（例如重新点火成功）的情况。
    """

    action_keywords: tuple[str, ...] = (
        "clear",
        "reset",
        "released",
        "restored",
        "resumed",
        "recover",
    )
    recovered_actions: tuple[tuple[str, str], ...] = (
        ("burner", "flame_established"),
    )

    def is_recovery(self, component: str, action: str) -> bool:
        if (component, action) in self.recovered_actions:
            return True
        return any(word in action for word in self.action_keywords)


@dataclass
class _Occurrence:
    """同一点位（指纹）在一波内的上报聚合。"""

    key: str
    component: str
    action: str
    subject: str
    severity: str
    first_ts: float
    last_ts: float
    count: int = 1
    safety: bool = False
    open: bool = True
    recovered_ts: float | None = None
    safety_rows: list[dict] = field(default_factory=list)

    def recover(self, moment: float) -> None:
        if self.open:
            self.open = False
            self.recovered_ts = moment

    def reopen(self, moment: float) -> None:
        self.open = True
        self.recovered_ts = None
        self.last_ts = moment

    def resolve_time(self, linger_s: float, safety_linger_s: float) -> float:
        """该点位被视为已恢复的时刻（真实恢复时刻或静默超时时刻）。"""

        if not self.open:
            return self.recovered_ts if self.recovered_ts is not None else self.last_ts
        return self.last_ts + (safety_linger_s if self.safety else linger_s)

    def as_row(self, wave_id: str, first_out: bool) -> dict:
        return {
            "wave_id": wave_id,
            "component": self.component,
            "action": self.action,
            "subject": self.subject,
            "severity": self.severity,
            "first_out": first_out,
            "safety": self.safety,
            "open": self.open,
            "count": self.count,
            "suppressed_count": self.count - 1,
            "first_ts": round(self.first_ts, 3),
            "last_ts": round(self.last_ts, 3),
            "recovered_ts": round(self.recovered_ts, 3) if self.recovered_ts else None,
        }


@dataclass
class _Wave:
    """一波扰动。"""

    wave_id: str
    started_ts: float
    last_ts: float
    occurrences: dict[str, _Occurrence] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    converged: bool = False
    converged_ts: float | None = None
    reopened_count: int = 0

    @property
    def first_key(self) -> str:
        return self.order[0]

    def has_safety(self) -> bool:
        return any(item.safety for item in self.occurrences.values())


class AlarmGovernor:
    """把总线报警事件治理成波次视图。"""

    def __init__(
        self,
        clock,
        bus: EventBus,
        *,
        window_s: float = 15.0,
        max_window_s: float = 300.0,
        linger_s: float = 30.0,
        safety_linger_s: float = 300.0,
        settle_s: float = 5.0,
        reopen_gap_s: float = 60.0,
        wave_limit: int = 200,
        recovery: RecoverySignals | None = None,
    ) -> None:
        self._clock = clock
        self._bus = bus
        self._window_s = float(window_s)
        self._max_window_s = float(max_window_s)
        self._linger_s = float(linger_s)
        self._safety_linger_s = float(safety_linger_s)
        self._settle_s = float(settle_s)
        self._reopen_gap_s = float(reopen_gap_s)
        self._wave_limit = int(wave_limit)
        self._recovery = recovery or RecoverySignals()
        self._waves: list[_Wave] = []
        self._ids = itertools.count(1)
        self._lock = threading.RLock()
        bus.subscribe("*", self._on_event)

    # ------------------------------------------------------------------ 事件

    def _on_event(self, event: Event) -> None:
        # 治理器自己发布的事件不回流处理，避免递归与自我计数。
        if event.component == GOVERNOR_COMPONENT:
            return
        moment = self._clock.now()
        # 恢复事件多为 notice/info 级别，必须在严重度过滤之前识别，否则波
        # 永远等不到恢复信号。
        if self._recovery.is_recovery(event.component, event.action):
            with self._lock:
                self._apply_recovery(event, moment)
            return
        severity = str(event.payload.get("severity", "info"))
        if severity not in PANEL_SEVERITIES:
            return
        with self._lock:
            self._apply_alarm(event, severity, moment)

    @staticmethod
    def fingerprint(component: str, action: str, subject: str) -> str:
        return f"{component}|{subject}|{action}"

    def _apply_alarm(self, event: Event, severity: str, moment: float) -> None:
        subject = str(event.payload.get("subject", event.component))
        key = self.fingerprint(event.component, event.action, subject)
        safety = severity == SAFE_SEVERITY

        wave = self._locate_wave(key, moment)
        created = wave is None
        reopened = bool(wave and wave.converged)
        if wave is None:
            wave = _Wave(
                wave_id=f"wave-{next(self._ids)}",
                started_ts=moment,
                last_ts=moment,
            )
            self._waves.append(wave)

        occurrence = wave.occurrences.get(key)
        if occurrence is None:
            occurrence = _Occurrence(
                key=key,
                component=event.component,
                action=event.action,
                subject=subject,
                severity=severity,
                first_ts=moment,
                last_ts=moment,
                safety=safety,
            )
            wave.occurrences[key] = occurrence
            wave.order.append(key)
        else:
            occurrence.count += 1
            occurrence.severity = severity
            if not occurrence.open:
                occurrence.reopen(moment)
            else:
                occurrence.last_ts = moment

        # 安全级不允许被归并吃掉：每一条都留下独立明细，视图逐行展开。
        if safety:
            occurrence.safety_rows.append(
                {
                    "ts": round(moment, 3),
                    "detail": {
                        name: value
                        for name, value in event.payload.items()
                        if name not in ("severity", "subject")
                    },
                }
            )

        wave.last_ts = moment
        if wave.converged:
            wave.converged = False
            wave.converged_ts = None
            wave.reopened_count += 1

        if created:
            self._publish(
                "alarm_wave_opened",
                safety=safety,
                first_component=event.component,
                first_subject=subject,
                first_action=event.action,
            )
        elif reopened:
            self._publish(
                "alarm_wave_reopened",
                wave_id=wave.wave_id,
                alarm_subject=subject,
                alarm_action=event.action,
                safety=safety,
            )

    def _apply_recovery(self, event: Event, moment: float) -> None:
        subject = str(event.payload.get("subject", event.component))
        open_occurrences = [
            occurrence
            for wave in self._waves
            if not wave.converged
            for occurrence in wave.occurrences.values()
            if occurrence.component == event.component and occurrence.open
        ]
        same_subject = [
            occurrence for occurrence in open_occurrences if occurrence.subject == subject
        ]
        if same_subject:
            targets = same_subject
        elif subject == event.component:
            # 恢复事件没带具体对象（subject 回落成了组件名），才允许组件级
            # 兜底；带明确对象的恢复不能清掉同一组件的其它点位。
            targets = open_occurrences
        else:
            targets = []
        recovered = False
        for occurrence in targets:
            occurrence.recover(moment)
            recovered = True
        if recovered:
            self.sweep()

    def _locate_wave(self, key: str, moment: float) -> _Wave | None:
        """定位这条报警归入的波。

        优先回到同指纹、静默不超过 reopen_gap 的波（恢复没好透又报）；否则
        归入最近一个仍在归并时间窗内的活动波；都不满足则另起一波。超过
        max_window 的老波一律不再承接新事件，避免一波无限拉长吞掉后续扰动。
        """

        recent: _Wave | None = None
        for wave in reversed(self._waves):
            age = moment - wave.started_ts
            if age > self._max_window_s:
                break
            gap = moment - wave.last_ts
            if key in wave.occurrences and gap <= self._reopen_gap_s:
                return wave
            if not wave.converged and gap <= self._window_s and recent is None:
                recent = wave
        return recent

    # ------------------------------------------------------------------ 收敛

    def _converge_ready(self, moment: float) -> list[_Wave]:
        """把已全部恢复（或静默超时）且过了 settle 宽限的波收敛。"""

        ready: list[_Wave] = []
        for wave in self._waves:
            if wave.converged:
                continue
            resolved_at = [
                item.resolve_time(self._linger_s, self._safety_linger_s)
                for item in wave.occurrences.values()
            ]
            if moment < max(resolved_at) + self._settle_s:
                continue
            wave.converged = True
            wave.converged_ts = moment
            ready.append(wave)
        if len(self._waves) > self._wave_limit:
            del self._waves[: len(self._waves) - self._wave_limit]
        return ready

    def sweep(self) -> dict:
        """按当前时钟结算到期应收敛的波，可由控制周期或视图刷新驱动。"""

        moment = self._clock.now()
        with self._lock:
            ready = self._converge_ready(moment)
            wave_ids = [wave.wave_id for wave in ready]
            safety = {wave.wave_id: wave.has_safety() for wave in ready}
        for wave_id in wave_ids:
            self._publish(
                "alarm_wave_converged",
                wave_id=wave_id,
                safety=safety[wave_id],
            )
        return {"converged": wave_ids, "now": round(moment, 3)}

    # ------------------------------------------------------------------ 查询

    def view(self, *, include_converged: bool = True, limit: int = 50) -> dict:
        """返回面板视图：波次摘要、首出、折叠后的行与全局计数。"""

        moment = self._clock.now()
        with self._lock:
            ready = self._converge_ready(moment)
            converged_now = [wave.wave_id for wave in ready]
            safety_now = {wave.wave_id: wave.has_safety() for wave in ready}
            waves = list(self._waves)
        for wave_id in converged_now:
            self._publish(
                "alarm_wave_converged",
                wave_id=wave_id,
                safety=safety_now[wave_id],
            )

        active = [wave for wave in waves if not wave.converged]
        settled = [wave for wave in waves if wave.converged]
        # 活动波按首出时间正序：真正的第一条永远排在最上面。
        active.sort(key=lambda item: item.started_ts)
        settled.sort(key=lambda item: item.converged_ts or item.last_ts, reverse=True)
        ordered = active + settled
        if not include_converged:
            ordered = active

        rows: list[dict] = []
        summaries: list[dict] = []
        suppressed_total = 0
        open_safety = 0
        for wave in ordered:
            members, suppressed, safety_open = self._wave_rows(wave)
            rows.extend(members)
            suppressed_total += suppressed
            open_safety += safety_open
            summaries.append(self._wave_summary(wave, members))
        visible = len(rows)
        if limit > 0:
            rows = rows[:limit]
        return {
            "generated_at": round(moment, 3),
            "active_wave_count": len(active),
            "converged_wave_count": len(settled),
            "open_safety_count": open_safety,
            "suppressed_count": suppressed_total,
            "visible_row_count": visible,
            "waves": summaries,
            "rows": rows,
        }

    def _wave_rows(self, wave: _Wave) -> tuple[list[dict], int, int]:
        rows: list[dict] = []
        suppressed = 0
        open_safety = 0
        first = wave.first_key
        for key in wave.order:
            occurrence = wave.occurrences[key]
            first_out = key == first
            if occurrence.safety:
                if occurrence.open:
                    open_safety += 1
                # 安全级逐条展开，绝不折叠；suppressed_count 恒为 0。
                for index, item in enumerate(occurrence.safety_rows):
                    rows.append(
                        {
                            "wave_id": wave.wave_id,
                            "component": occurrence.component,
                            "action": occurrence.action,
                            "subject": occurrence.subject,
                            "severity": SAFE_SEVERITY,
                            "first_out": first_out and index == 0,
                            "safety": True,
                            "open": occurrence.open,
                            "count": 1,
                            "suppressed_count": 0,
                            "first_ts": item["ts"],
                            "last_ts": item["ts"],
                            "recovered_ts": round(occurrence.recovered_ts, 3)
                            if occurrence.recovered_ts
                            else None,
                            "detail": item["detail"],
                        }
                    )
                continue
            rows.append(occurrence.as_row(wave.wave_id, first_out=first_out))
            suppressed += occurrence.count - 1
        return rows, suppressed, open_safety

    def _wave_summary(self, wave: _Wave, members: list[dict]) -> dict:
        return {
            "wave_id": wave.wave_id,
            "status": "open" if not wave.converged else "converged",
            "first_out": wave.occurrences[wave.first_key].as_row(wave.wave_id, True),
            "started_ts": round(wave.started_ts, 3),
            "last_ts": round(wave.last_ts, 3),
            "converged_ts": round(wave.converged_ts, 3) if wave.converged_ts else None,
            "point_count": len(wave.occurrences),
            "row_count": len(members),
            "rows": members,
            "total_count": sum(item.count for item in wave.occurrences.values()),
            "open_point_count": sum(
                1 for item in wave.occurrences.values() if item.open
            ),
            "has_safety": wave.has_safety(),
            "reopened_count": wave.reopened_count,
        }

    def snapshot(self) -> dict:
        """状态快照里的精简治理摘要（只看活动波，避免快照无限增长）。"""

        view = self.view(include_converged=False, limit=0)
        return {
            "active_wave_count": view["active_wave_count"],
            "open_safety_count": view["open_safety_count"],
            "suppressed_count": view["suppressed_count"],
        }

    def acknowledge_wave(self, wave_id: str, reason: str) -> bool:
        """人工确认一个已收敛的波并从视图移除；未收敛的波不允许确认。"""

        with self._lock:
            for wave in self._waves:
                if wave.wave_id != wave_id:
                    continue
                if not wave.converged:
                    return False
                self._waves.remove(wave)
                break
            else:
                return False
        self._publish("alarm_wave_acknowledged", wave_id=wave_id, reason=reason)
        return True

    # ------------------------------------------------------------------ 发布

    def _publish(self, action: str, **payload: object) -> None:
        self._bus.publish(
            Event.of(
                "alarm",
                GOVERNOR_COMPONENT,
                action,
                subject="alarm_governor",
                severity="notice",
                **payload,
            )
        )
