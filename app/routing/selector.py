from __future__ import annotations

import statistics
import time
from typing import Any

from app.routing.state import MetricsStore, ROUTES


class AdaptiveRouteSelector:
    """Select direct or VPS using recent observations from actual browser traffic."""

    def __init__(self, store: MetricsStore) -> None:
        self.store = store

    @staticmethod
    def _score(records: list[dict[str, Any]]) -> float | None:
        if not records:
            return None
        successes = [record for record in records if record.get("outcome") == "success"]
        latencies = [
            float(record.get("connect_ms") or 0) + float(record.get("first_byte_ms") or 0)
            for record in successes
            if record.get("connect_ms") is not None or record.get("first_byte_ms") is not None
        ]
        # No successful sample means this route is currently a poor bet.
        median_latency = statistics.median(latencies) if latencies else 12000.0
        failure_rate = (len(records) - len(successes)) / len(records)
        score = median_latency + failure_rate * 8000.0
        most_recent = max(records, key=lambda record: float(record.get("epoch", 0)))
        if most_recent.get("outcome") != "success" and time.time() - float(most_recent.get("epoch", 0)) < 60:
            score += 1000.0
        return score

    def choose(self, host: str) -> tuple[str, str]:
        host = self.store.normalize_host(host)
        # Keep only a small recent sample so a network change (for example 4G -> E)
        # can change the choice after a few real requests instead of being hidden by
        # an entire session of older fast observations.
        domain = {route: self.store.domain_records(host, route, max_age_seconds=900)[-6:]
                  for route in ROUTES}
        global_stats = {route: self.store.global_records(route, max_age_seconds=600)[-8:]
                        for route in ROUTES}
        global_scores = {route: self._score(global_stats[route]) for route in ROUTES}

        # Site-specific evidence takes priority once both routes have been observed.
        if domain["direct"] and domain["vps"]:
            scores = {route: self._score(domain[route]) for route in ROUTES}
            selected = self._prefer_lower_score(scores, minimum_improvement=0.08)
            reason = self._comparison_reason("recent observations for this site", scores, selected)
        elif domain["direct"] or domain["vps"]:
            known = "direct" if domain["direct"] else "vps"
            other = "vps" if known == "direct" else "direct"
            known_score = self._score(domain[known])
            # Reuse route-wide observations for an unobserved alternative. Do not
            # explore a second route unless real traffic has already provided evidence.
            other_global = global_scores[other] if len(global_stats[other]) >= 2 else None
            known_successes = sum(r.get("outcome") == "success" for r in domain[known])
            known_failures = len(domain[known]) - known_successes
            latest_known = max(domain[known], key=lambda record: float(record.get("epoch", 0)))
            if latest_known.get("outcome") != "success":
                selected = other
                if other_global is not None:
                    reason = f"this site's last {known} attempt failed; recent {other} traffic provides an alternative"
                else:
                    reason = f"this site's last {known} attempt failed; try the unmeasured {other} route on the next request"
            elif other_global is not None and known_failures and not known_successes:
                selected, reason = other, f"this site's {known} route recently failed; recent {other} traffic succeeded"
            elif (other_global is not None and known_score is not None
                  and known_score > other_global * 1.25 and other_global < 7000):
                selected, reason = other, f"recent {other} observations look materially better than this site's {known} observations"
            else:
                selected = known
                reason = f"using the only route with recent observations for this site ({known})"
        elif len(global_stats["direct"]) >= 3 and len(global_stats["vps"]) >= 3:
            selected = self._prefer_lower_score(global_scores, minimum_improvement=0.15)
            reason = self._comparison_reason("recent live traffic across sites", global_scores, selected)
        else:
            selected = "direct"
            reason = "first visit / insufficient route history; start direct and learn from real traffic"

        self.store.add_event("decision", f"Selected {selected}: {reason}", host, selected,
                             direct_score=self._rounded(self._score(domain["direct"]) if domain["direct"] else global_scores["direct"]),
                             vps_score=self._rounded(self._score(domain["vps"]) if domain["vps"] else global_scores["vps"]))
        return selected, reason

    @staticmethod
    def _rounded(value: float | None) -> float | None:
        return round(value, 2) if value is not None else None

    @staticmethod
    def _prefer_lower_score(scores: dict[str, float | None], minimum_improvement: float) -> str:
        direct, vps = scores.get("direct"), scores.get("vps")
        if direct is None and vps is None:
            return "direct"
        if direct is None:
            return "vps"
        if vps is None:
            return "direct"
        # Prefer direct on near-ties because it avoids the extra tunnel hop.
        if vps < direct * (1 - minimum_improvement):
            return "vps"
        return "direct"

    def _comparison_reason(self, source: str, scores: dict[str, float | None], selected: str) -> str:
        direct, vps = scores.get("direct"), scores.get("vps")
        return (f"{source}; direct score={self._rounded(direct)} ms, "
                f"VPS score={self._rounded(vps)} ms; selected {selected}")
