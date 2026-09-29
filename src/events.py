"""责任链事件与只追加事件存储。

所有状态变化都以事件形式按序追加到 JSONL，服务重启后重放即可恢复；
审计时同样通过重放在历史时点重现决定。事件一经追加不可修改或删除。
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def canonical_hash(payload: dict[str, Any]) -> str:
    """与键顺序无关的载荷摘要，作为证据指纹。"""
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Event:
    seq: int
    timestamp: float
    kind: str
    payload: dict[str, Any]
    source: str = "system"
    fingerprint: str = field(default="")

    def to_line(self) -> str:
        return json.dumps(
            {
                "seq": self.seq,
                "timestamp": self.timestamp,
                "kind": self.kind,
                "source": self.source,
                "fingerprint": self.fingerprint,
                "payload": self.payload,
            },
            ensure_ascii=False,
        )

    @staticmethod
    def from_line(line: str) -> "Event":
        data = json.loads(line)
        return Event(
            seq=data["seq"],
            timestamp=data["timestamp"],
            kind=data["kind"],
            source=data.get("source", "system"),
            fingerprint=data.get("fingerprint", ""),
            payload=data["payload"],
        )


class EventStore:
    """JSONL 只追加存储；顺序号严格递增，禁止断号重号。"""

    def __init__(self, path: Path | None = None, *, clock=time.time):
        self._path = path
        self._clock = clock
        self._events: list[Event] = []
        if path is not None and path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    self._events.append(Event.from_line(line))

    @property
    def events(self) -> tuple[Event, ...]:
        return tuple(self._events)

    def append(self, kind: str, payload: dict[str, Any], *, source: str = "system") -> Event:
        seq = len(self._events) + 1
        event = Event(
            seq=seq,
            timestamp=self._clock(),
            kind=kind,
            payload=payload,
            source=source,
            fingerprint=canonical_hash(payload),
        )
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(event.to_line() + "\n")
                handle.flush()
        self._events.append(event)
        return event

    def replay(
        self,
        builder,
        *,
        at_time: float | None = None,
        at_seq: int | None = None,
        initial: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """把事件喂给 builder（接受 state/event 两个参数），可截到历史时点。"""
        state: dict[str, Any] = {} if initial is None else initial
        for event in self._events:
            if at_time is not None and event.timestamp > at_time:
                break
            if at_seq is not None and event.seq > at_seq:
                break
            builder(state, event)
        return state
