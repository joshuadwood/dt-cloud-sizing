#!/usr/bin/env python3
"""
dt_sizing_common.py -- provider-neutral Dynatrace DPS sizing units, rules and banding.

Shared by dt_aws_sizing.py and dt_azure_sizing.py so both express their findings in the
same units and get the same opinion about how large an account is.

Unit-of-measure rules are from docs.dynatrace.com; list prices are from the public pricing
page and exist only as a reference point (real rate cards are contractual).
"""

from __future__ import annotations

import sys
import textwrap

GIB = 1024 ** 3
SECONDS_PER_DAY = 86400
INTERVALS_PER_DAY = 96          # 15-minute billing intervals
HOST_EQUIV_GIB_HR = 16 * 24     # one 16 GiB host running 24h == 384 GiB-hr


def enable_utf8():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# --------------------------------------------------------------------------------------
# Dynatrace DPS consumption rules
# --------------------------------------------------------------------------------------

DPS_RULES = {
    "host_mem_rounding_gib": 0.25,   # RAM rounded UP to next multiple of 0.25 GiB
    "host_mem_min_gib": 4.0,         # 4 GiB minimum per physical/virtual host
    "host_interval_hours": 0.25,     # monitored time rounded up to 15-minute intervals
    "fullstack_dp_per_gib_per_interval": 900,
    "infra_dp_per_host_per_interval": 1500,
    "histogram_dp_weight": 10,
}

LIST_PRICES = {
    "log_ingest_per_gib": 0.20,
    "metric_dp_per_100k": 0.15,
    "fullstack_per_gib_hour": 0.01,
    "infra_per_host_hour": 0.04,
}


def dps_billable_host_gib(mem_gib: float) -> float:
    """Apply DPS Full-Stack memory rules: round up to 0.25 GiB, enforce the 4 GiB minimum."""
    step = DPS_RULES["host_mem_rounding_gib"]
    rounded = -(-mem_gib // step) * step
    return max(rounded, DPS_RULES["host_mem_min_gib"])


def dps_billable_hours(hours: float) -> float:
    """Round monitored time up to whole 15-minute intervals."""
    iv = DPS_RULES["host_interval_hours"]
    if hours <= 0:
        return 0.0
    return -(-hours // iv) * iv


def allowance_netting(raw_dp_per_day: float, gib_hr_per_day: float) -> dict:
    """Net CloudWatch/Azure Monitor data points against the included Full-Stack allowance.

    Full-Stack hosts earn 900 custom metric data points per charged GiB per 15-minute
    interval. Unused allowance does not carry over, so the comparison is per interval.
    """
    allowance_per_day = (gib_hr_per_day * 4) * DPS_RULES["fullstack_dp_per_gib_per_interval"]
    excess = max(0.0, (raw_dp_per_day / INTERVALS_PER_DAY)
                 - (allowance_per_day / INTERVALS_PER_DAY))
    billable = excess * INTERVALS_PER_DAY
    covers = (100.0 if raw_dp_per_day == 0
              else min(100.0, 100.0 * (1 - billable / raw_dp_per_day)))
    return {
        "included_dp_allowance_per_day": allowance_per_day,
        "billable_dp_per_day_after_allowance": billable,
        "allowance_covers_pct": covers,
    }


# --------------------------------------------------------------------------------------
# T-shirt sizing
# --------------------------------------------------------------------------------------

SIZE_ORDER = ["XS", "S", "M", "L", "XL", "XXL"]

BANDS = {
    "logs": [("XS", 1), ("S", 10), ("M", 100), ("L", 500), ("XL", 2000), ("XXL", float("inf"))],
    "metrics": [("XS", 1e6), ("S", 1e7), ("M", 1e8), ("L", 5e8), ("XL", 2e9),
                ("XXL", float("inf"))],
    "hosts": [("XS", 5 * 384), ("S", 25 * 384), ("M", 100 * 384), ("L", 400 * 384),
              ("XL", 1500 * 384), ("XXL", float("inf"))],
}

SIZE_LABEL = {
    "XS": "Extra Small -- sandbox / personal dev account",
    "S":  "Small -- single team, non-production or light production",
    "M":  "Medium -- real production workload for a business unit",
    "L":  "Large -- significant production estate",
    "XL": "Extra Large -- major production estate, enterprise scale",
    "XXL": "Hyperscale -- top-percentile estate; size with an architect, not a script",
}


def band_for(kind: str, value: float) -> str:
    for name, upper in BANDS[kind]:
        if value < upper:
            return name
    return "XXL"


def size_dimensions(log_gib_per_day, metric_dp_per_day, host_gib_hr_per_day):
    """Band each dimension, then form an opinion about the account as a whole.

    The overall size is the median of the three, pulled up one step if any single
    dimension sits two or more bands above that median -- one runaway dimension still
    drives the deal.
    """
    sizes = {
        "logs": band_for("logs", log_gib_per_day),
        "metrics": band_for("metrics", metric_dp_per_day),
        "hosts": band_for("hosts", host_gib_hr_per_day),
    }
    idx = {k: SIZE_ORDER.index(v) for k, v in sizes.items()}
    ordered = sorted(idx.values())
    overall_i = ordered[1]
    if ordered[2] - overall_i >= 2:
        overall_i += 1
    overall = SIZE_ORDER[overall_i]

    dominant = max(idx, key=lambda k: idx[k])
    spread = ordered[2] - ordered[0]
    if spread == 0:
        shape = "balanced -- logs, metrics and hosts all land in the same band"
    elif spread >= 2:
        shape = f"lopsided -- {dominant}-dominated; the other two dimensions are much smaller"
    else:
        shape = f"{dominant}-leaning, otherwise even"

    return {"per_dimension": sizes, "overall": overall, "overall_label": SIZE_LABEL[overall],
            "shape": shape, "dominant_dimension": dominant}


def indicative_cost(log_gib_per_day, billable_dp_per_day, gib_hr_per_day,
                    host_hr_per_day, rates=None):
    r = {**LIST_PRICES, **(rates or {})}
    c = {
        "log_ingest_per_day": log_gib_per_day * r["log_ingest_per_gib"],
        "metrics_per_day": (billable_dp_per_day / 100_000.0) * r["metric_dp_per_100k"],
        "fullstack_per_day": gib_hr_per_day * r["fullstack_per_gib_hour"],
        "infra_alternative_per_day": host_hr_per_day * r["infra_per_host_hour"],
    }
    c["total_per_day"] = (c["log_ingest_per_day"] + c["metrics_per_day"] + c["fullstack_per_day"])
    c["total_per_month"] = c["total_per_day"] * 30.44
    c["total_per_year"] = c["total_per_day"] * 365
    c["rates_used"] = r
    return c


def rule(title=""):
    if title:
        return "\n" + title + "\n" + "-" * max(len(title), 60)
    return "-" * 72


def wrap_into(out, text, width=84, indent="  "):
    out.extend(indent + ln for ln in textwrap.wrap(text, width))


SHARED_ASSUMPTIONS = [
    "Full-Stack memory follows DPS rules: RAM rounded up to the next 0.25 GiB with a 4 GiB "
    "per-host minimum, and monitored time rounded up to 15-minute intervals. There is no "
    "16 GiB cap under DPS -- that was the legacy host-unit model.",
    "Included allowance modelled at 900 custom metric data points per charged GiB per "
    "15-minute interval, with no carry-over between intervals.",
    "List prices are from the public Dynatrace pricing page and are a reference point only; "
    "real DPS rate cards are contractual and usually discounted.",
]
