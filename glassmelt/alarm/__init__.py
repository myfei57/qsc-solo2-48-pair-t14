"""报警治理。

在原始报警记录之上加一层只影响展示的治理：短时间同一波扰动归成一组（wave）
并标出首出（first-out），同一点位的重复上报在面板里折叠成计数，恢复后自动
收敛。原始记录仍由审计日志逐条落盘，治理层只提供"面板视图"，不删数据、不
参与任何控制联锁。

安全级别（severity=alarm）的报警不允许被归并吃掉：每一条都单独成行，即使它
属于某个波；含安全报警的波也必须等安全点位本身恢复后才允许收敛。
"""

from .governor import AlarmGovernor, RecoverySignals

__all__ = ["AlarmGovernor", "RecoverySignals"]
