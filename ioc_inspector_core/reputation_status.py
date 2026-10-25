"""Stable status fields for optional reputation enrichment."""

from collections import Counter

LookupStatuses = dict[str, dict[str, str]]


def record(statuses: LookupStatuses | None, indicator: str, status: str, reason: str = "") -> None:
    if statuses is not None:
        statuses[indicator] = {"status": status, "reason": reason}


def summarize(statuses: LookupStatuses, reason: str = "") -> dict:
    counts = Counter(item["status"] for item in statuses.values())
    if reason or not statuses:
        status = "skipped"
    elif len(counts) == 1:
        status = next(iter(counts))
    else:
        status = "partial"
    if status == "skipped" and statuses and not reason:
        reason = next(iter(statuses.values()))["reason"]
    return {
        "status": status,
        "reason": reason,
        "total": len(statuses),
        "succeeded": counts["success"],
        "failed": counts["failed"],
        "not_found": counts["not_found"],
        "skipped": counts["skipped"],
        "indicators": statuses,
    }
