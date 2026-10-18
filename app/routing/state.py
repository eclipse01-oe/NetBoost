from __future__ import annotations

import json
import statistics
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROUTES = ("direct", "vps")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class MetricsStore:
    """Small persistent store for observations made during real browsing."""

    def __init__(self, path: str | Path = "data/route_state.json") -> None:
        self.path = Path(path)
        self.state: dict[str, Any] = {
            "version": 1,
            "domains": {},
            "routes": {name: [] for name in ROUTES},
            "events": [],
        }
        self._last_save_at = 0.0
        self._dirty = False
        self.load()

    def load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("version") != 1:
                return
            data.setdefault("domains", {})
            data.setdefault("routes", {name: [] for name in ROUTES})
            for name in ROUTES:
                data["routes"].setdefault(name, [])
            data.setdefault("events", [])
            self.state = data
        except (FileNotFoundError, json.JSONDecodeError, OSError, AttributeError):
            return

    def save(self, force: bool = False) -> None:
        self._dirty = True
        now = time.monotonic()
        # Browser pages can open many parallel connections. Coalesce writes to
        # avoid turning the metrics log into a source of browsing latency.
        if not force and now - self._last_save_at < 0.5:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.path.parent,
                prefix=f".{self.path.name}.", suffix=".tmp", delete=False
            ) as temp_file:
                json.dump(self.state, temp_file, indent=2)
                temp_file.write("\n")
                temp_name = temp_file.name
            Path(temp_name).replace(self.path)
            self._last_save_at = time.monotonic()
            self._dirty = False
        finally:
            if temp_name and Path(temp_name).exists():
                Path(temp_name).unlink(missing_ok=True)

    def flush(self) -> None:
        if self._dirty:
            self.save(force=True)

    @staticmethod
    def normalize_host(host: str) -> str:
        return host.strip().rstrip(".").lower() or "unknown"

    def add_event(self, kind: str, message: str, host: str | None = None,
                  route: str | None = None, **details: Any) -> None:
        event = {
            "id": uuid.uuid4().hex[:12],
            "at": utc_now(),
            "kind": kind,
            "message": message,
            "host": self.normalize_host(host) if host else None,
            "route": route,
            "details": details,
        }
        self.state["events"].append(event)
        self.state["events"] = self.state["events"][-250:]
        self.save()

    def record_attempt(self, host: str, route: str, *, outcome: str,
                       connect_ms: float | None = None,
                       first_byte_ms: float | None = None,
                       reason: str = "", up_bytes: int = 0,
                       down_bytes: int = 0, duration_ms: float = 0.0) -> str:
        host = self.normalize_host(host)
        if route not in ROUTES:
            raise ValueError(f"Unknown route: {route}")
        record = {
            "id": uuid.uuid4().hex,
            "at": utc_now(),
            "epoch": time.time(),
            "route": route,
            "outcome": outcome,
            "connect_ms": round(connect_ms, 2) if connect_ms is not None else None,
            "first_byte_ms": round(first_byte_ms, 2) if first_byte_ms is not None else None,
            "reason": reason,
            "up_bytes": int(up_bytes),
            "down_bytes": int(down_bytes),
            "duration_ms": round(duration_ms, 2),
        }
        domain_routes = self.state["domains"].setdefault(host, {name: [] for name in ROUTES})
        for name in ROUTES:
            domain_routes.setdefault(name, [])
        domain_routes[route].append(record)
        domain_routes[route] = domain_routes[route][-40:]
        self.state["routes"][route].append({**record, "host": host})
        self.state["routes"][route] = self.state["routes"][route][-300:]
        self.save()
        return record["id"]

    def complete_attempt(self, record_id: str, *, up_bytes: int,
                         down_bytes: int, duration_ms: float) -> None:
        changed = False
        for records in self.state["routes"].values():
            for record in records:
                if record.get("id") == record_id:
                    record["up_bytes"] = int(up_bytes)
                    record["down_bytes"] = int(down_bytes)
                    record["duration_ms"] = round(duration_ms, 2)
                    changed = True
        for domain_routes in self.state["domains"].values():
            for records in domain_routes.values():
                for record in records:
                    if record.get("id") == record_id:
                        record["up_bytes"] = int(up_bytes)
                        record["down_bytes"] = int(down_bytes)
                        record["duration_ms"] = round(duration_ms, 2)
                        changed = True
        if changed:
            self.save()

    def domain_records(self, host: str, route: str, max_age_seconds: int = 900) -> list[dict[str, Any]]:
        host = self.normalize_host(host)
        records = self.state["domains"].get(host, {}).get(route, [])
        cutoff = time.time() - max_age_seconds
        return [r for r in records if float(r.get("epoch", 0)) >= cutoff]

    def global_records(self, route: str, max_age_seconds: int = 900) -> list[dict[str, Any]]:
        cutoff = time.time() - max_age_seconds
        return [r for r in self.state["routes"].get(route, []) if float(r.get("epoch", 0)) >= cutoff]

    def route_summary(self, route: str, max_age_seconds: int = 900) -> dict[str, Any]:
        records = self.global_records(route, max_age_seconds)
        successes = [r for r in records if r.get("outcome") == "success"]
        latency = [
            float(r.get("connect_ms") or 0) + float(r.get("first_byte_ms") or 0)
            for r in successes
            if r.get("connect_ms") is not None or r.get("first_byte_ms") is not None
        ]
        return {
            "route": route,
            "observations": len(records),
            "successes": len(successes),
            "failures": len(records) - len(successes),
            "success_rate": round(len(successes) / len(records), 3) if records else None,
            "median_response_ms": round(statistics.median(latency), 2) if latency else None,
            "bytes_down": sum(int(r.get("down_bytes", 0)) for r in records),
            "last_observation": max((r.get("at") for r in records), default=None),
        }

    def domain_summary(self, host: str) -> dict[str, Any]:
        host = self.normalize_host(host)
        routes = self.state["domains"].get(host, {})
        result: dict[str, Any] = {"host": host}
        for route in ROUTES:
            records = routes.get(route, [])[-10:]
            successes = [r for r in records if r.get("outcome") == "success"]
            latencies = [
                float(r.get("connect_ms") or 0) + float(r.get("first_byte_ms") or 0)
                for r in successes
                if r.get("connect_ms") is not None or r.get("first_byte_ms") is not None
            ]
            result[route] = {
                "observations": len(records),
                "successes": len(successes),
                "failures": len(records) - len(successes),
                "median_response_ms": round(statistics.median(latencies), 2) if latencies else None,
                "last_observation": max((r.get("at") for r in records), default=None),
            }
        return result

    def all_domain_summaries(self) -> list[dict[str, Any]]:
        result = [self.domain_summary(host) for host in self.state["domains"]]
        result.sort(key=lambda item: max(
            (item.get(route, {}).get("last_observation") or "" for route in ROUTES), default=""
        ), reverse=True)
        return result

    def recent_events(self, limit: int = 40) -> list[dict[str, Any]]:
        return list(reversed(self.state["events"][-limit:]))
