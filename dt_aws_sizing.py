#!/usr/bin/env python3
"""
dt_aws_sizing.py -- Size an AWS account for Dynatrace Platform Subscription (DPS) SKUs.

Measures three things across every enabled region of an AWS account and converts
them into the units Dynatrace actually bills in:

  1. LOGS      -> GiB/day of log ingest       (CloudWatch Logs IncomingBytes, +Firehose, +S3 log buckets)
  2. METRICS   -> metric data points / day    (CloudWatch time series x polling frequency)
  3. HOSTS     -> GiB-hr/day of host memory   (EC2 instance memory x observed running hours)

It then renders an opinionated t-shirt size for the account.

Read-only. Makes no changes to the AWS account.

Usage:
    python dt_aws_sizing.py --creds-file aws-creds.txt
    python dt_aws_sizing.py --regions us-east-1,us-west-2 --days 14 --json out.json --markdown report.md

See --help for all options.
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import datetime as dt
import json
import os
import sys
import textwrap
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict

try:
    import boto3
    import botocore
    from botocore.config import Config
except ImportError:
    sys.exit("boto3 is required.  pip install boto3")

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

GIB = 1024 ** 3
SECONDS_PER_DAY = 86400

# --------------------------------------------------------------------------------------
# Dynatrace AWS-integration namespace classification
# --------------------------------------------------------------------------------------
# Dynatrace's AWS cloud integration pulls CloudWatch metrics for a supported service list.
# For sizing we split namespaces into three buckets, because counting *every* CloudWatch
# series wildly overstates what Dynatrace would actually ingest.

# Services in Dynatrace's default / most-commonly-enabled AWS integration set.
DT_DEFAULT_NS = {
    "AWS/EC2", "AWS/EBS", "AWS/AutoScaling",
    "AWS/ELB", "AWS/ApplicationELB", "AWS/NetworkELB", "AWS/GatewayELB",
    "AWS/Lambda", "AWS/RDS", "AWS/DynamoDB", "AWS/S3",
    "AWS/SQS", "AWS/SNS", "AWS/ECS", "AWS/EKS", "AWS/ElastiCache",
    "AWS/ApiGateway", "AWS/CloudFront", "AWS/Route53", "AWS/EFS",
    "AWS/Kinesis", "AWS/Firehose", "AWS/States", "AWS/Redshift",
    "AWS/NATGateway", "AWS/ES", "AWS/AmazonMQ", "AWS/DocDB",
    "AWS/Events", "AWS/Logs", "ContainerInsights", "ECS/ContainerInsights",
}

# Namespaces Dynatrace's AWS integration does not ingest: AWS account-meta / advisory
# / billing telemetry that has no Dynatrace entity to attach to.
EXCLUDED_NS = {
    "AWS/Usage", "AWS/TrustedAdvisor", "AWS/Billing", "AWS/CloudWatch",
    "AWS/Config", "AWS/ServiceQuotas", "AWS/Health", "AWS/CertificateManager",
}

# Dimension names that identify a CloudWatch *rollup* series rather than a per-entity
# series. Dynatrace ingests per-entity, so rollups would be double counting.
ROLLUP_ONLY_DIMS = {
    "AWS/EC2": {"InstanceType", "ImageId", "AutoScalingGroupName"},
    "AWS/EBS": set(),
    "AWS/S3": {"StorageType"},
}

# Bucket-name / prefix hints for S3 buckets that are likely to hold logs
S3_LOG_HINTS = (
    "log", "logs", "cloudtrail", "flowlog", "flow-log", "accesslog", "access-log",
    "alb-", "elb-", "cloudfront", "waf", "audit", "s3-access",
)

# --------------------------------------------------------------------------------------
# T-shirt sizing bands.  Ordered low -> high; a value falls in the first band it is under.
# --------------------------------------------------------------------------------------
SIZE_ORDER = ["XS", "S", "M", "L", "XL", "XXL"]

BANDS = {
    # GiB/day of log ingest
    "logs": [("XS", 1), ("S", 10), ("M", 100), ("L", 500), ("XL", 2000), ("XXL", float("inf"))],
    # metric data points / day
    "metrics": [("XS", 1e6), ("S", 1e7), ("M", 1e8), ("L", 5e8), ("XL", 2e9), ("XXL", float("inf"))],
    # GiB-hr/day of monitored host memory (384 GiB-hr/day == one 16 GiB host running 24x7)
    "hosts": [("XS", 5 * 384), ("S", 25 * 384), ("M", 100 * 384), ("L", 400 * 384),
              ("XL", 1500 * 384), ("XXL", float("inf"))],
}

HOST_EQUIV_GIB_HR = 16 * 24  # one 16 GiB host running 24h == 384 GiB-hr


def band_for(kind: str, value: float) -> str:
    for name, upper in BANDS[kind]:
        if value < upper:
            return name
    return "XXL"


# --------------------------------------------------------------------------------------
# Session / plumbing
# --------------------------------------------------------------------------------------
BOTO_CFG = Config(retries={"max_attempts": 8, "mode": "adaptive"}, connect_timeout=10, read_timeout=60)

_VERBOSE = True


def log(msg: str) -> None:
    if _VERBOSE:
        print(msg, file=sys.stderr, flush=True)


def make_session(args) -> boto3.Session:
    """Build a session from --creds-file, a named profile, or the ambient environment."""
    if args.creds_file:
        path = os.path.abspath(args.creds_file)
        if not os.path.exists(path):
            sys.exit(f"credentials file not found: {path}")
        os.environ["AWS_SHARED_CREDENTIALS_FILE"] = path
    kwargs = {}
    if args.profile:
        kwargs["profile_name"] = args.profile
    elif args.creds_file:
        kwargs["profile_name"] = args.creds_profile
    return boto3.Session(**kwargs)


def discover_regions(session: boto3.Session, requested: str) -> list[str]:
    if requested and requested.lower() != "all":
        return [r.strip() for r in requested.split(",") if r.strip()]
    ec2 = session.client("ec2", region_name="us-east-1", config=BOTO_CFG)
    resp = ec2.describe_regions(AllRegions=False)
    return sorted(r["RegionName"] for r in resp["Regions"])


def safe(fn, *a, default=None, **kw):
    """Call an AWS API, swallowing access/endpoint errors that are normal on a partial scan."""
    try:
        return fn(*a, **kw)
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                    "AuthFailure", "OptInRequired", "InvalidClientTokenId",
                    "SubscriptionRequiredException", "UnrecognizedClientException"):
            return default
        raise
    except (botocore.exceptions.EndpointConnectionError,
            botocore.exceptions.ConnectTimeoutError,
            botocore.exceptions.ReadTimeoutError,
            botocore.exceptions.ConnectionClosedError):
        return default
    except botocore.exceptions.NoRegionError:
        return default


def chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def metric_data(cw, queries, start, end):
    """Run GetMetricData in batches of 500, returning {Id: MetricDataResult}."""
    out = {}
    for batch in chunked(queries, 500):
        token = None
        while True:
            kw = dict(MetricDataQueries=batch, StartTime=start, EndTime=end,
                      ScanBy="TimestampAscending")
            if token:
                kw["NextToken"] = token
            resp = cw.get_metric_data(**kw)
            for r in resp["MetricDataResults"]:
                prev = out.setdefault(r["Id"], {"Timestamps": [], "Values": []})
                prev["Timestamps"].extend(r["Timestamps"])
                prev["Values"].extend(r["Values"])
            token = resp.get("NextToken")
            if not token:
                break
    return out


# --------------------------------------------------------------------------------------
# Dynatrace DPS consumption rules
# --------------------------------------------------------------------------------------
# Unit-of-measure rules are from docs.dynatrace.com (see REPORT/README for citations).
# List prices are from the public pricing page and are only a reference point -- real
# rate cards are contractual and usually discounted.  Override them with --rate-*.

DPS_RULES = {
    # Full-Stack Monitoring
    "host_mem_rounding_gib": 0.25,   # RAM rounded UP to next multiple of 0.25 GiB
    "host_mem_min_gib": 4.0,         # 4 GiB minimum per physical/virtual host
    "host_interval_hours": 0.25,     # monitored time rounded up to 15-minute intervals
    # Included custom-metric-data-point allowance, per 15-min interval
    "fullstack_dp_per_gib_per_interval": 900,
    "infra_dp_per_host_per_interval": 1500,
    # Histogram metrics weigh 10 data points; CloudWatch gauges/counters weigh 1
    "histogram_dp_weight": 10,
}

LIST_PRICES = {
    "log_ingest_per_gib": 0.20,          # $/GiB ingested
    "metric_dp_per_100k": 0.15,          # $/100,000 data points ingested
    "fullstack_per_gib_hour": 0.01,      # $/memory-GiB-hour
    "infra_per_host_hour": 0.04,         # $/host-hour
}

INTERVALS_PER_DAY = 96  # 15-minute intervals


def dps_billable_host_gib(mem_gib: float) -> float:
    """Apply DPS Full-Stack memory rules: round up to 0.25 GiB, enforce 4 GiB minimum."""
    step = DPS_RULES["host_mem_rounding_gib"]
    rounded = -(-mem_gib // step) * step          # ceil to nearest 0.25
    return max(rounded, DPS_RULES["host_mem_min_gib"])


def dps_billable_hours(hours: float) -> float:
    """Round monitored time up to whole 15-minute intervals."""
    iv = DPS_RULES["host_interval_hours"]
    if hours <= 0:
        return 0.0
    return -(-hours // iv) * iv


# --------------------------------------------------------------------------------------
# Collectors
# --------------------------------------------------------------------------------------

@dataclass
class LogFinding:
    region: str
    log_groups: int = 0
    log_groups_with_traffic: int = 0
    log_streams: int = 0
    active_log_streams: int = 0
    stored_bytes: int = 0
    incoming_gib_per_day: float = 0.0
    fallback_gib_per_day: float = 0.0
    fallback_groups: int = 0
    incoming_gib_per_day_by_group: dict = field(default_factory=dict)
    firehose_gib_per_day: float = 0.0
    firehose_streams: int = 0
    s3_log_gib_per_day: float = 0.0
    s3_log_buckets: dict = field(default_factory=dict)
    stream_counts_exact: bool = True
    access_denied: bool = False
    notes: list = field(default_factory=list)


def collect_logs(session, region, start, end, days, count_streams, stream_group_cap,
                 want_s3, want_fallback=True):
    f = LogFinding(region=region)
    logs = session.client("logs", region_name=region, config=BOTO_CFG)
    cw = session.client("cloudwatch", region_name=region, config=BOTO_CFG)

    groups = []
    pg = safe(lambda: list(logs.get_paginator("describe_log_groups").paginate()), default=None)
    if pg is None:
        f.access_denied = True
        f.notes.append("no access to CloudWatch Logs")
        return f
    for page in pg:
        groups.extend(page["logGroups"])
    f.log_groups = len(groups)
    f.stored_bytes = sum(g.get("storedBytes", 0) or 0 for g in groups)

    # ---- Per-log-group ingest from the AWS/Logs IncomingBytes metric --------------------
    series = []
    ml = safe(lambda: list(cw.get_paginator("list_metrics").paginate(
        Namespace="AWS/Logs", MetricName="IncomingBytes")), default=[])
    for page in ml:
        for m in page["Metrics"]:
            dims = {d["Name"]: d["Value"] for d in m["Dimensions"]}
            if "LogGroupName" in dims:      # skip the region-wide rollup series
                series.append((dims["LogGroupName"], m))

    if series:
        queries = [{"Id": f"lg{i}",
                    "MetricStat": {"Metric": m, "Period": SECONDS_PER_DAY, "Stat": "Sum"},
                    "ReturnData": True}
                   for i, (_, m) in enumerate(series)]
        res = safe(metric_data, cw, queries, start, end, default={}) or {}
        for i, (name, _) in enumerate(series):
            vals = res.get(f"lg{i}", {}).get("Values", [])
            total = sum(vals)
            if total > 0:
                gpd = total / GIB / days
                f.incoming_gib_per_day_by_group[name] = gpd
                f.incoming_gib_per_day += gpd
                f.log_groups_with_traffic += 1

    # ---- Fall back to storedBytes/retention for groups that report no IncomingBytes -----
    # (AWS/Logs metrics are only emitted for groups with recent traffic; a group with
    #  stored data but no metric still represents real ingest.)
    fallback = 0.0
    fallback_groups = 0
    for g in groups:
        name = g["logGroupName"]
        if name in f.incoming_gib_per_day_by_group:
            continue
        sb = g.get("storedBytes", 0) or 0
        if sb <= 0:
            continue
        ret = g.get("retentionInDays")
        window = ret if ret else 90        # never-expire groups: assume a 90-day spread
        fallback += sb / GIB / max(window, 1)
        fallback_groups += 1
    if fallback > 0 and want_fallback:
        f.fallback_gib_per_day = fallback
        f.fallback_groups = fallback_groups
        f.notes.append(
            f"{fallback_groups} log group(s) hold stored data but emit no IncomingBytes "
            f"metric; estimated {fallback:.4f} GiB/day from storedBytes/retention "
            f"(LOW CONFIDENCE -- these groups may be dormant)")
        f.incoming_gib_per_day += fallback

    # ---- Log stream counts -------------------------------------------------------------
    if count_streams and groups:
        cutoff_ms = int(start.timestamp() * 1000)
        todo = groups if len(groups) <= stream_group_cap else groups[:stream_group_cap]
        if len(todo) < len(groups):
            f.stream_counts_exact = False
            f.notes.append(f"stream counting capped at {stream_group_cap} of {len(groups)} groups")

        def count_one(g):
            total = active = 0
            try:
                for page in logs.get_paginator("describe_log_streams").paginate(
                        logGroupName=g["logGroupName"],
                        PaginationConfig={"PageSize": 50}):
                    for s in page["logStreams"]:
                        total += 1
                        if (s.get("lastEventTimestamp") or 0) >= cutoff_ms:
                            active += 1
            except botocore.exceptions.ClientError:
                pass
            return total, active

        with futures.ThreadPoolExecutor(max_workers=8) as ex:
            for t, a in ex.map(count_one, todo):
                f.log_streams += t
                f.active_log_streams += a

    # ---- Kinesis Data Firehose: the usual path for shipping AWS logs off-platform -------
    fh_series = safe(lambda: list(cw.get_paginator("list_metrics").paginate(
        Namespace="AWS/Firehose", MetricName="IncomingBytes")), default=[]) or []
    fh = []
    for page in fh_series:
        for m in page["Metrics"]:
            dims = {d["Name"]: d["Value"] for d in m["Dimensions"]}
            if "DeliveryStreamName" in dims:
                fh.append(m)
    if fh:
        f.firehose_streams = len(fh)
        q = [{"Id": f"fh{i}", "MetricStat": {"Metric": m, "Period": SECONDS_PER_DAY, "Stat": "Sum"},
              "ReturnData": True} for i, m in enumerate(fh)]
        res = safe(metric_data, cw, q, start, end, default={}) or {}
        f.firehose_gib_per_day = sum(sum(r.get("Values", [])) for r in res.values()) / GIB / days

    # ---- S3 buckets that look like log destinations -------------------------------------
    if want_s3:
        collect_s3_logs(session, region, cw, f, start, end, days)

    return f


def collect_s3_logs(session, region, cw, f, start, end, days):
    """Estimate daily growth of log-looking S3 buckets from AWS/S3 BucketSizeBytes.

    BucketSizeBytes is a daily storage metric, so day-over-day growth approximates the
    write rate.  Buckets with lifecycle expiry will understate; this is a rough signal for
    log volume that never touches CloudWatch Logs (VPC flow logs, ALB/CloudTrail to S3).
    """
    ml = safe(lambda: list(cw.get_paginator("list_metrics").paginate(
        Namespace="AWS/S3", MetricName="BucketSizeBytes")), default=[]) or []
    cands = []
    for page in ml:
        for m in page["Metrics"]:
            dims = {d["Name"]: d["Value"] for d in m["Dimensions"]}
            b = dims.get("BucketName", "")
            if dims.get("StorageType") != "StandardStorage":
                continue
            if any(h in b.lower() for h in S3_LOG_HINTS):
                cands.append((b, m))
    if not cands:
        return
    q = [{"Id": f"s3{i}", "MetricStat": {"Metric": m, "Period": SECONDS_PER_DAY, "Stat": "Average"},
          "ReturnData": True} for i, (_, m) in enumerate(cands)]
    res = safe(metric_data, cw, q, start, end, default={}) or {}
    for i, (bucket, _) in enumerate(cands):
        vals = res.get(f"s3{i}", {}).get("Values", [])
        if len(vals) < 2:
            continue
        growth = (vals[-1] - vals[0]) / GIB
        span_days = max(len(vals) - 1, 1)
        per_day = growth / span_days
        if per_day > 0.0001:
            f.s3_log_buckets[bucket] = per_day
            f.s3_log_gib_per_day += per_day


@dataclass
class MetricFinding:
    region: str
    series_listed: int = 0            # any data in the last 14 days
    series_active: int = 0            # data in the last 3 hours
    series_billable: int = 0          # active, in a Dynatrace-ingested namespace, non-rollup
    rollups_dropped: int = 0
    excluded_dropped: int = 0
    optin_series: int = 0             # DT-supported but not in the default integration set
    custom_ns_series: int = 0         # non-AWS/* namespaces (customer-published)
    access_denied: bool = False
    by_namespace: dict = field(default_factory=dict)
    billable_by_namespace: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)


def is_rollup(namespace, dims):
    """True if this dimension set is a CloudWatch aggregate rather than a per-entity series."""
    if not dims:
        return True                       # namespace-wide rollup
    names = {d["Name"] for d in dims}
    bad = ROLLUP_ONLY_DIMS.get(namespace)
    if bad and names and names.issubset(bad):
        return True
    return False


def collect_metrics(session, region, scope):
    f = MetricFinding(region=region)
    cw = session.client("cloudwatch", region_name=region, config=BOTO_CFG)

    listed = safe(lambda: list(cw.get_paginator("list_metrics").paginate()), default=None)
    if listed is None:
        f.access_denied = True
        f.notes.append("no access to CloudWatch metrics")
        return f
    for page in listed:
        for m in page["Metrics"]:
            f.series_listed += 1
            f.by_namespace[m["Namespace"]] = f.by_namespace.get(m["Namespace"], 0) + 1

    # RecentlyActive=PT3H is the only server-side liveness filter CloudWatch offers and is
    # a far better proxy for "what Dynatrace would poll right now" than the 14-day list.
    active = safe(lambda: list(cw.get_paginator("list_metrics").paginate(RecentlyActive="PT3H")),
                  default=[]) or []
    for page in active:
        for m in page["Metrics"]:
            ns, dims = m["Namespace"], m["Dimensions"]
            f.series_active += 1

            if ns in EXCLUDED_NS:
                f.excluded_dropped += 1
                if scope != "all":          # 'all' means all, meta namespaces included
                    continue
            if is_rollup(ns, dims):
                f.rollups_dropped += 1
                if scope != "all":
                    continue

            is_aws = ns.startswith("AWS/") or ns in DT_DEFAULT_NS
            if not is_aws:
                f.custom_ns_series += 1
            elif ns not in DT_DEFAULT_NS:
                f.optin_series += 1

            if scope == "all":
                keep = True
            elif scope == "dt-supported":
                keep = True                                   # everything not excluded
            else:                                             # dt-default
                keep = (ns in DT_DEFAULT_NS) or (not is_aws)  # default services + custom ns
            if keep:
                f.series_billable += 1
                f.billable_by_namespace[ns] = f.billable_by_namespace.get(ns, 0) + 1
    return f


@dataclass
class HostFinding:
    region: str
    instances_total: int = 0
    instances_running: int = 0
    instances_stopped: int = 0
    running_mem_gib: float = 0.0            # raw RAM of currently-running instances
    billable_mem_gib: float = 0.0           # after DPS 0.25 GiB rounding + 4 GiB minimum
    gib_hr_per_day_observed: float = 0.0    # DPS-billable, from measured uptime
    gib_hr_per_day_24x7: float = 0.0        # DPS-billable, if everything ran 24x7
    host_hr_per_day_observed: float = 0.0   # for the Infrastructure Monitoring comparison
    by_type: dict = field(default_factory=dict)
    instances: list = field(default_factory=list)
    eks_clusters: int = 0
    eks_fargate_profiles: int = 0
    ecs_clusters: int = 0
    ecs_fargate_tasks: int = 0
    ecs_ec2_tasks: int = 0
    rds_instances: int = 0
    lambda_functions: int = 0
    access_denied: bool = False
    notes: list = field(default_factory=list)


_TYPE_MEM_CACHE: dict[str, float] = {}


def instance_type_memory(ec2, types):
    """Resolve instance type -> RAM in GiB, memoised across regions."""
    missing = [t for t in types if t not in _TYPE_MEM_CACHE]
    for batch in chunked(missing, 100):
        resp = safe(ec2.describe_instance_types, InstanceTypes=batch, default=None)
        if not resp:
            continue
        for t in resp["InstanceTypes"]:
            _TYPE_MEM_CACHE[t["InstanceType"]] = t["MemoryInfo"]["SizeInMiB"] / 1024.0
    return {t: _TYPE_MEM_CACHE.get(t) for t in types}


def collect_hosts(session, region, start, end, days, include_stopped):
    f = HostFinding(region=region)
    ec2 = session.client("ec2", region_name=region, config=BOTO_CFG)
    cw = session.client("cloudwatch", region_name=region, config=BOTO_CFG)

    pages = safe(lambda: list(ec2.get_paginator("describe_instances").paginate()), default=None)
    if pages is None:
        f.access_denied = True
        f.notes.append("no access to EC2")
        return f
    insts = [i for page in pages for r in page["Reservations"] for i in r["Instances"]
             if i["State"]["Name"] not in ("terminated", "shutting-down")]

    f.instances_total = len(insts)
    types = sorted({i["InstanceType"] for i in insts})
    mem = instance_type_memory(ec2, types) if types else {}
    unknown = [t for t, v in mem.items() if v is None]
    if unknown:
        f.notes.append(f"could not resolve RAM for instance types: {', '.join(unknown)}")

    # ---- Observed running hours, from hourly CloudWatch CPUUtilization coverage ---------
    # An instance only emits CPUUtilization while it is running, so the number of hourly
    # buckets containing a datapoint is a direct measure of running hours in the window.
    queries = []
    for idx, i in enumerate(insts):
        queries.append({
            "Id": f"h{idx}",
            "MetricStat": {
                "Metric": {"Namespace": "AWS/EC2", "MetricName": "CPUUtilization",
                           "Dimensions": [{"Name": "InstanceId", "Value": i["InstanceId"]}]},
                "Period": 3600, "Stat": "Maximum"},
            "ReturnData": True})
    res = safe(metric_data, cw, queries, start, end, default={}) or {} if queries else {}

    for idx, i in enumerate(insts):
        state = i["State"]["Name"]
        itype = i["InstanceType"]
        raw = mem.get(itype)
        running = state == "running"
        f.instances_running += 1 if running else 0
        f.instances_stopped += 1 if state == "stopped" else 0

        observed_hours = len(res.get(f"h{idx}", {}).get("Values", []))
        hours_per_day = min(observed_hours / days, 24.0) if days else 0.0

        if raw is None:
            continue
        billable_gib = dps_billable_host_gib(raw)

        if running:
            f.running_mem_gib += raw
            f.billable_mem_gib += billable_gib

        # 24x7 projection only counts hosts you would actually deploy OneAgent on
        counts_for_24x7 = running or include_stopped
        if counts_for_24x7:
            f.gib_hr_per_day_24x7 += billable_gib * 24

        # Observed: bill the measured uptime, rounded up to 15-minute intervals per day
        if hours_per_day > 0:
            f.gib_hr_per_day_observed += billable_gib * dps_billable_hours(hours_per_day)
            f.host_hr_per_day_observed += dps_billable_hours(hours_per_day)

        f.by_type[itype] = f.by_type.get(itype, 0) + 1
        f.instances.append({
            "instance_id": i["InstanceId"], "region": region, "type": itype, "state": state,
            "platform": i.get("PlatformDetails", "Linux/UNIX"),
            "detailed_monitoring": i["Monitoring"]["State"] == "enabled",
            "ram_gib": raw, "dps_billable_gib": billable_gib,
            "observed_hours_per_day": round(hours_per_day, 2),
            "gib_hr_per_day_observed": round(billable_gib * dps_billable_hours(hours_per_day), 2),
            "name": next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), ""),
        })

    # ---- Context: container platforms, managed DBs, serverless -------------------------
    eks = session.client("eks", region_name=region, config=BOTO_CFG)
    clusters = safe(lambda: [c for p in eks.get_paginator("list_clusters").paginate()
                             for c in p["clusters"]], default=[]) or []
    f.eks_clusters = len(clusters)
    for c in clusters:
        profs = safe(lambda: eks.list_fargate_profiles(clusterName=c), default=None)
        if profs:
            f.eks_fargate_profiles += len(profs.get("fargateProfileNames", []))

    ecs = session.client("ecs", region_name=region, config=BOTO_CFG)
    ecs_clusters = safe(lambda: [a for p in ecs.get_paginator("list_clusters").paginate()
                                 for a in p["clusterArns"]], default=[]) or []
    f.ecs_clusters = len(ecs_clusters)
    for arn in ecs_clusters:
        for launch in ("FARGATE", "EC2"):
            arns = safe(lambda: [a for p in ecs.get_paginator("list_tasks").paginate(
                cluster=arn, launchType=launch) for a in p["taskArns"]], default=[]) or []
            if launch == "FARGATE":
                f.ecs_fargate_tasks += len(arns)
            else:
                f.ecs_ec2_tasks += len(arns)

    rds = session.client("rds", region_name=region, config=BOTO_CFG)
    f.rds_instances = len(safe(lambda: [d for p in rds.get_paginator("describe_db_instances")
                                        .paginate() for d in p["DBInstances"]], default=[]) or [])

    lam = session.client("lambda", region_name=region, config=BOTO_CFG)
    f.lambda_functions = len(safe(lambda: [fn for p in lam.get_paginator("list_functions")
                                           .paginate() for fn in p["Functions"]], default=[]) or [])
    return f


# --------------------------------------------------------------------------------------
# Aggregation and DPS conversion
# --------------------------------------------------------------------------------------

def build_summary(account, regions, logs, metrics, hosts, args):
    days = args.days
    poll = args.poll_interval
    dp_per_series_per_day = SECONDS_PER_DAY / poll

    L = {
        "cloudwatch_logs_gib_per_day": sum(f.incoming_gib_per_day for f in logs),
        "firehose_gib_per_day": sum(f.firehose_gib_per_day for f in logs),
        "s3_log_bucket_gib_per_day": sum(f.s3_log_gib_per_day for f in logs),
        "storedbytes_fallback_gib_per_day": sum(f.fallback_gib_per_day for f in logs),
        "storedbytes_fallback_groups": sum(f.fallback_groups for f in logs),
        "log_groups": sum(f.log_groups for f in logs),
        "log_groups_with_traffic": sum(f.log_groups_with_traffic for f in logs),
        "log_streams": sum(f.log_streams for f in logs),
        "active_log_streams": sum(f.active_log_streams for f in logs),
        "stored_gib": sum(f.stored_bytes for f in logs) / GIB,
    }
    # Primary figure = CloudWatch Logs. Firehose usually *carries* those same logs to a
    # third party, so counting both would double count; it is reported as an upper bound.
    L["dt_log_ingest_gib_per_day"] = L["cloudwatch_logs_gib_per_day"] * args.log_overhead
    L["dt_log_ingest_gib_per_day_upper"] = (
        (L["cloudwatch_logs_gib_per_day"] + L["s3_log_bucket_gib_per_day"]) * args.log_overhead
        + (L["firehose_gib_per_day"] if args.count_firehose else 0.0))

    M = {
        "series_listed_14d": sum(f.series_listed for f in metrics),
        "series_active_3h": sum(f.series_active for f in metrics),
        "series_billable": sum(f.series_billable for f in metrics),
        "rollups_dropped": sum(f.rollups_dropped for f in metrics),
        "excluded_dropped": sum(f.excluded_dropped for f in metrics),
        "optin_series": sum(f.optin_series for f in metrics),
        "custom_ns_series": sum(f.custom_ns_series for f in metrics),
        "poll_interval_seconds": poll,
    }
    ns_tot = Counter()
    for f in metrics:
        for k, v in f.billable_by_namespace.items():
            ns_tot[k] += v
    M["billable_by_namespace"] = dict(ns_tot.most_common())
    M["raw_dp_per_day"] = M["series_billable"] * dp_per_series_per_day
    M["raw_dp_per_day_at_5min"] = M["series_billable"] * (SECONDS_PER_DAY / 300)
    M["raw_dp_per_month"] = M["raw_dp_per_day"] * 30.44
    M["raw_dp_per_year"] = M["raw_dp_per_day"] * 365

    H = {
        "instances_total": sum(f.instances_total for f in hosts),
        "instances_running": sum(f.instances_running for f in hosts),
        "instances_stopped": sum(f.instances_stopped for f in hosts),
        "running_ram_gib_raw": sum(f.running_mem_gib for f in hosts),
        "running_ram_gib_dps_billable": sum(f.billable_mem_gib for f in hosts),
        "gib_hr_per_day_observed": sum(f.gib_hr_per_day_observed for f in hosts),
        "gib_hr_per_day_24x7": sum(f.gib_hr_per_day_24x7 for f in hosts),
        "host_hr_per_day_observed": sum(f.host_hr_per_day_observed for f in hosts),
        "eks_clusters": sum(f.eks_clusters for f in hosts),
        "eks_fargate_profiles": sum(f.eks_fargate_profiles for f in hosts),
        "ecs_clusters": sum(f.ecs_clusters for f in hosts),
        "ecs_fargate_tasks": sum(f.ecs_fargate_tasks for f in hosts),
        "ecs_ec2_tasks": sum(f.ecs_ec2_tasks for f in hosts),
        "rds_instances": sum(f.rds_instances for f in hosts),
        "lambda_functions": sum(f.lambda_functions for f in hosts),
    }
    tcount = Counter()
    for f in hosts:
        for k, v in f.by_type.items():
            tcount[k] += v
    H["by_instance_type"] = dict(tcount.most_common())

    headline_gib_hr = (H["gib_hr_per_day_24x7"] if args.host_uptime == "assume-24x7"
                       else H["gib_hr_per_day_observed"])
    H["gib_hr_per_day"] = headline_gib_hr
    H["host_equivalents_16gib"] = headline_gib_hr / HOST_EQUIV_GIB_HR
    H["hosts_in_projection"] = (
        (H["instances_running"] + (H["instances_stopped"] if args.include_stopped_hosts else 0))
        if args.host_uptime == "assume-24x7" else H["instances_running"])

    # ---- Included custom-metric-DP allowance earned by Full-Stack hosts -----------------
    # 900 DP per charged GiB per 15-min interval; unused allowance does not carry over,
    # so compare per interval rather than per day.
    monitored_intervals_per_day = (H["host_hr_per_day_observed"] * 4
                                   if args.host_uptime == "observed"
                                   else H["instances_running"] * 96)
    # allowance = billable GiB x 900 per interval, over the intervals each host is monitored
    allowance_per_day = (headline_gib_hr * 4) * DPS_RULES["fullstack_dp_per_gib_per_interval"]
    allowance_per_interval = allowance_per_day / INTERVALS_PER_DAY
    dp_per_interval = M["raw_dp_per_day"] / INTERVALS_PER_DAY
    excess_per_interval = max(0.0, dp_per_interval - allowance_per_interval)
    M["included_dp_allowance_per_day"] = allowance_per_day
    M["billable_dp_per_day_after_allowance"] = excess_per_interval * INTERVALS_PER_DAY
    M["allowance_covers_pct"] = (
        100.0 if M["raw_dp_per_day"] == 0
        else min(100.0, 100.0 * (1 - M["billable_dp_per_day_after_allowance"] / M["raw_dp_per_day"])))
    M["monitored_intervals_per_day"] = monitored_intervals_per_day

    # ---- Indicative list-price consumption ---------------------------------------------
    rates = {**LIST_PRICES}
    if args.rate_log_ingest is not None:
        rates["log_ingest_per_gib"] = args.rate_log_ingest
    if args.rate_metric_dp is not None:
        rates["metric_dp_per_100k"] = args.rate_metric_dp
    if args.rate_fullstack is not None:
        rates["fullstack_per_gib_hour"] = args.rate_fullstack
    if args.rate_infra is not None:
        rates["infra_per_host_hour"] = args.rate_infra

    cost = {
        "log_ingest_per_day": L["dt_log_ingest_gib_per_day"] * rates["log_ingest_per_gib"],
        "metrics_per_day": (M["billable_dp_per_day_after_allowance"] / 100_000.0)
                           * rates["metric_dp_per_100k"],
        "fullstack_per_day": headline_gib_hr * rates["fullstack_per_gib_hour"],
        "infra_alternative_per_day": H["host_hr_per_day_observed"] * rates["infra_per_host_hour"],
    }
    cost["total_per_day"] = (cost["log_ingest_per_day"] + cost["metrics_per_day"]
                             + cost["fullstack_per_day"])
    cost["total_per_month"] = cost["total_per_day"] * 30.44
    cost["total_per_year"] = cost["total_per_day"] * 365
    cost["rates_used"] = rates

    denied = {
        "logs": sorted(f.region for f in logs if f.access_denied),
        "metrics": sorted(f.region for f in metrics if f.access_denied),
        "hosts": sorted(f.region for f in hosts if f.access_denied),
    }
    fully_covered = sorted(set(regions) - set(denied["logs"]) - set(denied["metrics"])
                           - set(denied["hosts"]))
    coverage = {
        "regions_requested": len(regions),
        "regions_fully_covered": fully_covered,
        "denied_by_collector": denied,
        "partial": bool(denied["logs"] or denied["metrics"] or denied["hosts"]),
    }

    return {
        "coverage": coverage,
        "account": account, "regions_scanned": regions, "window_days": days,
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "logs": L, "metrics": M, "hosts": H, "indicative_cost_usd": cost,
        "verdict": verdict(L, M, H, coverage),
    }


# --------------------------------------------------------------------------------------
# The opinionated part
# --------------------------------------------------------------------------------------

SIZE_LABEL = {
    "XS": "Extra Small -- sandbox / personal dev account",
    "S":  "Small -- single team, non-production or light production",
    "M":  "Medium -- real production workload for a business unit",
    "L":  "Large -- significant production estate",
    "XL": "Extra Large -- major production estate, enterprise scale",
    "XXL": "Hyperscale -- top-percentile estate; size with an architect, not a script",
}


def verdict(L, M, H, coverage):
    sizes = {
        "logs": band_for("logs", L["dt_log_ingest_gib_per_day"]),
        "metrics": band_for("metrics", M["raw_dp_per_day"]),
        "hosts": band_for("hosts", H["gib_hr_per_day"]),
    }
    idx = {k: SIZE_ORDER.index(v) for k, v in sizes.items()}
    ordered = sorted(idx.values())
    # Opinion: take the median of the three, then pull up one step if any single dimension
    # is two or more sizes above it -- one runaway dimension still drives the deal.
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

    reasons = [
        f"Logs: {L['dt_log_ingest_gib_per_day']:.3f} GiB/day across "
        f"{L['log_groups_with_traffic']} active log group(s) of {L['log_groups']} -> {sizes['logs']}",
        f"Metrics: {M['series_billable']:,} billable active series x "
        f"{SECONDS_PER_DAY // M['poll_interval_seconds']:,} polls/day = "
        f"{M['raw_dp_per_day']:,.0f} data points/day -> {sizes['metrics']}",
        f"Hosts: {H['hosts_in_projection']} monitored instance(s), "
        f"{H['gib_hr_per_day']:,.0f} GiB-hr/day "
        f"(= {H['host_equivalents_16gib']:.1f} x 16 GiB hosts running 24x7) -> {sizes['hosts']}",
    ]

    calls = []
    if coverage["partial"]:
        d = coverage["denied_by_collector"]
        worst = max(len(d["logs"]), len(d["metrics"]), len(d["hosts"]))
        calls.append(
            f"COVERAGE IS PARTIAL. Up to {worst} of "
            f"{coverage['regions_requested']} regions could not be read -- access denied "
            f"or the scan failed "
            f"(logs: {len(d['logs'])}, metrics: {len(d['metrics'])}, hosts: {len(d['hosts'])}). "
            f"Only {len(coverage['regions_fully_covered'])} region(s) were fully readable: "
            f"{', '.join(coverage['regions_fully_covered']) or 'none'}. "
            "Every number below is a FLOOR, not a total -- re-run with a role that can read "
            "all regions before quoting.")
    if H["instances_stopped"] > H["instances_running"]:
        calls.append(
            f"{H['instances_stopped']} of {H['instances_total']} EC2 instances are stopped. "
            "This account looks like a lab or a graveyard of old builds, not steady-state "
            "production. Size on running hosts, but confirm whether the stopped fleet is "
            "genuinely dead before quoting.")
    if M["excluded_dropped"] > M["series_billable"]:
        calls.append(
            f"{M['excluded_dropped']:,} of {M['series_active_3h']:,} active CloudWatch series "
            "are AWS account-meta namespaces (Usage / TrustedAdvisor / Billing / Config) that "
            "the Dynatrace AWS integration does not ingest. A naive list-metrics count would "
            f"have overstated metric volume by "
            f"{M['series_active_3h'] / max(M['series_billable'], 1):.1f}x "
            f"({M['series_active_3h']:,} active series -> {M['series_billable']:,} billable); "
            f"counting the full 14-day list instead would overstate it by "
            f"{M['series_listed_14d'] / max(M['series_billable'], 1):.1f}x.")
    if M["allowance_covers_pct"] >= 99.9 and M["raw_dp_per_day"] > 0:
        calls.append(
            "Every CloudWatch data point is absorbed by the included Full-Stack metric "
            f"allowance ({M['included_dp_allowance_per_day']:,.0f} DP/day earned by the "
            "monitored hosts). Metrics should cost nothing extra here -- do not quote a "
            "separate custom-metrics line.")
    elif M["allowance_covers_pct"] > 0:
        calls.append(
            f"The Full-Stack host allowance absorbs {M['allowance_covers_pct']:.0f}% of "
            f"CloudWatch data points; only {M['billable_dp_per_day_after_allowance']:,.0f} "
            "DP/day are actually billable.")
    if H["gib_hr_per_day"] > 0 and H["gib_hr_per_day_24x7"] > H["gib_hr_per_day"] * 1.25:
        calls.append(
            f"Measured uptime is well below 24x7: {H['gib_hr_per_day']:,.0f} GiB-hr/day observed "
            f"vs {H['gib_hr_per_day_24x7']:,.0f} GiB-hr/day if everything ran continuously. "
            "Quoting on nameplate capacity would overshoot by "
            f"{H['gib_hr_per_day_24x7'] / max(H['gib_hr_per_day'], 1):.1f}x.")
    if H["eks_clusters"] or H["ecs_fargate_tasks"]:
        calls.append(
            f"{H['eks_clusters']} EKS cluster(s) and {H['ecs_fargate_tasks']} Fargate task(s) "
            "are present. Kubernetes nodes are already counted as EC2 hosts, but Fargate has "
            "no host to put OneAgent on -- it needs application-only or Kubernetes-native "
            "monitoring, which is a separate SKU line this script does not size.")
    if L["dt_log_ingest_gib_per_day"] > 0 and L["s3_log_bucket_gib_per_day"] > \
            L["cloudwatch_logs_gib_per_day"]:
        calls.append(
            f"S3 log buckets are growing {L['s3_log_bucket_gib_per_day']:.2f} GiB/day, more than "
            "CloudWatch Logs itself. If those S3 logs are in scope, log ingest is materially "
            "larger than the headline figure.")

    return {
        "overall": overall, "overall_label": SIZE_LABEL[overall],
        "per_dimension": sizes, "shape": shape, "dominant_dimension": dominant,
        "reasoning": reasons, "judgement_calls": calls,
    }


# --------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------

def rule(title=""):
    if title:
        return "\n" + title + "\n" + "-" * max(len(title), 60)
    return "-" * 72


def render_text(s, args):
    L, M, H, V, C = s["logs"], s["metrics"], s["hosts"], s["verdict"], s["indicative_cost_usd"]
    o = []
    o.append("=" * 72)
    o.append(f"  DYNATRACE SIZING -- AWS ACCOUNT {s['account']['Account']}")
    cov = s["coverage"]
    o.append(f"  {len(cov['regions_fully_covered'])} of {cov['regions_requested']} region(s) "
             f"fully readable | {s['window_days']}-day observation window")
    o.append(f"  generated {s['generated_utc']}")
    o.append("=" * 72)
    if cov["partial"]:
        o.append("")
        o.append("  !! PARTIAL COVERAGE -- these credentials could not read every region.")
        o.append("     The figures below are a FLOOR for this account, not a total.")

    o.append(rule("VERDICT"))
    o.append(f"  ACCOUNT SIZE:  {V['overall']}  --  {V['overall_label']}")
    o.append(f"  Shape:         {V['shape']}")
    o.append(f"  Per dimension: logs={V['per_dimension']['logs']}  "
             f"metrics={V['per_dimension']['metrics']}  hosts={V['per_dimension']['hosts']}")
    o.append("")
    for r in V["reasoning"]:
        o.append("   * " + r)

    o.append(rule("SKU SIZING (the three numbers to quote)"))
    o.append("  1. Log Management -- Ingest & Process")
    o.append(f"       {L['dt_log_ingest_gib_per_day']:>14,.4f}  GiB/day")
    o.append(f"       {L['dt_log_ingest_gib_per_day'] * 30.44:>14,.2f}  GiB/month")
    o.append(f"       {L['dt_log_ingest_gib_per_day'] * 365:>14,.2f}  GiB/year")
    o.append(f"       upper bound incl. Firehose + S3 log buckets: "
             f"{L['dt_log_ingest_gib_per_day_upper']:,.4f} GiB/day")
    o.append("")
    o.append(f"  2. Metrics -- Ingest (custom metric data points @ "
             f"{M['poll_interval_seconds']}s polling)")
    o.append(f"       {M['raw_dp_per_day']:>14,.0f}  raw data points/day")
    o.append(f"       {M['raw_dp_per_month']:>14,.0f}  raw data points/month")
    o.append(f"       {M['raw_dp_per_year']:>14,.0f}  raw data points/year")
    o.append(f"       from {M['series_billable']:,} billable active time series")
    o.append(f"       included Full-Stack allowance: {M['included_dp_allowance_per_day']:>,.0f} "
             f"DP/day  (covers {M['allowance_covers_pct']:.1f}%)")
    o.append(f"       NET BILLABLE: {M['billable_dp_per_day_after_allowance']:,.0f} DP/day")
    o.append(f"       for reference, at Dynatrace default 5-min polling: "
             f"{M['raw_dp_per_day_at_5min']:,.0f} DP/day")
    o.append("")
    o.append("  3. Full-Stack Monitoring -- host memory")
    o.append(f"       {H['gib_hr_per_day']:>14,.2f}  GiB-hr/day  ({args.host_uptime})")
    o.append(f"       {H['gib_hr_per_day'] * 30.44:>14,.2f}  GiB-hr/month")
    o.append(f"       {H['gib_hr_per_day'] * 365:>14,.2f}  GiB-hr/year")
    o.append(f"       {H['hosts_in_projection']} host(s) in this projection "
             f"({H['instances_running']} running, "
             f"{H['hosts_in_projection'] - H['instances_running']} stopped-but-included)")
    o.append(f"       running hosts: {H['running_ram_gib_raw']:.1f} GiB raw RAM -> "
             f"{H['running_ram_gib_dps_billable']:.2f} GiB DPS-billable "
             f"(0.25 GiB round-up, 4 GiB floor)")
    o.append(f"       equivalent to {H['host_equivalents_16gib']:.2f} x 16 GiB hosts at 24x7")

    o.append(rule("LOGS -- detail"))
    o.append(f"  Log groups:              {L['log_groups']:,}  "
             f"({L['log_groups_with_traffic']:,} with measured traffic)")
    o.append(f"  Log streams:             {L['log_streams']:,}  "
             f"({L['active_log_streams']:,} active in window)")
    o.append(f"  Stored (compressed):     {L['stored_gib']:,.2f} GiB")
    o.append(f"  CloudWatch Logs ingest:  {L['cloudwatch_logs_gib_per_day']:,.4f} GiB/day")
    o.append(f"  Firehose IncomingBytes:  {L['firehose_gib_per_day']:,.4f} GiB/day "
             f"(may re-carry the same logs)")
    o.append(f"  S3 log-bucket growth:    {L['s3_log_bucket_gib_per_day']:,.4f} GiB/day")
    if L["storedbytes_fallback_gib_per_day"] > 0:
        o.append(f"  ...of the CloudWatch figure, "
                 f"{L['storedbytes_fallback_gib_per_day']:,.4f} GiB/day is a LOW-CONFIDENCE "
                 f"storedBytes/retention estimate")
        o.append(f"     for {L['storedbytes_fallback_groups']} group(s) with stored data but "
                 f"no IncomingBytes metric. Re-run with --no-storedbytes-fallback to exclude.")
    o.append(rule("COVERAGE"))
    d = cov["denied_by_collector"]
    o.append(f"  Regions requested:      {cov['regions_requested']}")
    o.append(f"  Fully readable:         {len(cov['regions_fully_covered'])} "
             f"({', '.join(cov['regions_fully_covered']) or 'none'})")
    o.append(f"  Unreadable (denied or failed) -- logs:    {len(d['logs'])} region(s)")
    o.append(f"  Unreadable (denied or failed) -- metrics: {len(d['metrics'])} region(s)")
    o.append(f"  Unreadable (denied or failed) -- hosts:   {len(d['hosts'])} region(s)")
    notes = sorted({f"[{f.region}] {n}"
                    for coll in ("_logs_raw", "_metrics_raw", "_hosts_raw")
                    for f in s[coll] for n in f.notes
                    if not n.startswith("no access")})
    if notes:
        o.append("")
        o.append("  Collector notes (excluding routine access denials):")
        for n in notes:
            o.extend("     " + ln for ln in textwrap.wrap(n, 80))

    top_lg = sorted(
        ((n, v) for f in s["_logs_raw"] for n, v in f.incoming_gib_per_day_by_group.items()),
        key=lambda x: -x[1])[:args.top]
    if top_lg:
        o.append("")
        o.append(f"  Top {len(top_lg)} log groups by ingest:")
        for n, v in top_lg:
            o.append(f"     {v:>10.4f} GiB/day  {n[:58]}")

    o.append(rule("METRICS -- detail"))
    o.append(f"  Series listed (14d):     {M['series_listed_14d']:,}")
    o.append(f"  Series active (3h):      {M['series_active_3h']:,}")
    o.append(f"  - dropped, not ingested by Dynatrace: {M['excluded_dropped']:,}")
    o.append(f"  - dropped, CloudWatch rollups:        {M['rollups_dropped']:,}")
    o.append(f"  = BILLABLE SERIES:       {M['series_billable']:,}   (scope: {args.metric_scope})")
    o.append(f"     of which opt-in AWS services: {M['optin_series']:,}")
    o.append(f"     of which custom namespaces:   {M['custom_ns_series']:,}")
    o.append("")
    o.append(f"  Billable series by namespace (top {args.top}):")
    for ns, c in list(M["billable_by_namespace"].items())[:args.top]:
        o.append(f"     {c:>7,}  {ns}")

    o.append(rule("HOSTS -- detail"))
    o.append(f"  EC2 instances:  {H['instances_total']:,} total | "
             f"{H['instances_running']:,} running | {H['instances_stopped']:,} stopped")
    o.append(f"  GiB-hr/day observed: {H['gib_hr_per_day_observed']:,.2f}   "
             f"if 24x7: {H['gib_hr_per_day_24x7']:,.2f}")
    o.append(f"  Host-hr/day (Infrastructure Monitoring alternative): "
             f"{H['host_hr_per_day_observed']:,.2f}")
    o.append(f"  EKS clusters: {H['eks_clusters']} ({H['eks_fargate_profiles']} Fargate profiles)"
             f" | ECS clusters: {H['ecs_clusters']} "
             f"({H['ecs_fargate_tasks']} Fargate / {H['ecs_ec2_tasks']} EC2 tasks)")
    o.append(f"  Not full-stack hosts: {H['rds_instances']} RDS instance(s), "
             f"{H['lambda_functions']} Lambda function(s)")
    if H["by_instance_type"]:
        o.append("")
        o.append("  Instance types:")
        for t, c in list(H["by_instance_type"].items())[:args.top]:
            o.append(f"     {c:>4} x {t}")
    rows = sorted((i for f in s["_hosts_raw"] for i in f.instances),
                  key=lambda x: -x["gib_hr_per_day_observed"])[:args.top]
    if rows:
        o.append("")
        o.append(f"  {'instance':<21}{'region':<13}{'type':<14}{'state':<9}"
                 f"{'RAM':>6}{'bill':>7}{'hr/d':>7}{'GiB-hr/d':>10}")
        for i in rows:
            o.append(f"  {i['instance_id']:<21}{i['region']:<13}{i['type']:<14}{i['state']:<9}"
                     f"{i['ram_gib']:>6.1f}{i['dps_billable_gib']:>7.2f}"
                     f"{i['observed_hours_per_day']:>7.1f}{i['gib_hr_per_day_observed']:>10.2f}")

    o.append(rule("JUDGEMENT CALLS"))
    if V["judgement_calls"]:
        for c in V["judgement_calls"]:
            o.extend("  " + ln for ln in textwrap.wrap(c, 84))
            o.append("")
    else:
        o.append("  Nothing unusual -- the numbers speak for themselves.")

    o.append(rule("INDICATIVE CONSUMPTION AT PUBLIC LIST PRICE"))
    o.append("  Reference only. Real DPS rate cards are contractual and usually discounted.")
    o.append(f"  Log ingest        ${C['log_ingest_per_day']:>10,.2f}/day  "
             f"@ ${C['rates_used']['log_ingest_per_gib']}/GiB")
    o.append(f"  Metric DP (net)   ${C['metrics_per_day']:>10,.2f}/day  "
             f"@ ${C['rates_used']['metric_dp_per_100k']}/100k DP")
    o.append(f"  Full-Stack hosts  ${C['fullstack_per_day']:>10,.2f}/day  "
             f"@ ${C['rates_used']['fullstack_per_gib_hour']}/GiB-hr")
    o.append("  " + " " * 16 + "-" * 14)
    o.append(f"  TOTAL             ${C['total_per_day']:>10,.2f}/day   "
             f"${C['total_per_month']:,.2f}/month   ${C['total_per_year']:,.2f}/year")
    o.append(f"  (Infrastructure Monitoring instead of Full-Stack: "
             f"${C['infra_alternative_per_day']:,.2f}/day)")

    o.append(rule("ASSUMPTIONS"))
    for a in assumptions(args):
        o.extend("  " + ln for ln in textwrap.wrap(a, 84))
    o.append("")
    return "\n".join(o)


def assumptions(args):
    return [
        f"* Observation window: last {args.days} days. Short windows miss weekly peaks; "
        "14 days is the CloudWatch list-metrics horizon and a sensible default.",
        f"* Metric polling assumed at {args.poll_interval}s "
        f"({SECONDS_PER_DAY // args.poll_interval} polls/day/series). Dynatrace's AWS "
        "integration actually polls CloudWatch every 5 minutes by default, so the headline "
        "data-point figure is a 5x-conservative upper bound unless 1-minute ingestion is "
        "explicitly configured.",
        f"* Metric scope '{args.metric_scope}': billable series exclude AWS account-meta "
        "namespaces (Usage, TrustedAdvisor, Billing, Config, ServiceQuotas, Health) which "
        "the Dynatrace AWS integration does not ingest, and exclude CloudWatch rollup series "
        "that would double count per-entity metrics.",
        "* Metric liveness uses CloudWatch RecentlyActive=PT3H. A series reporting less "
        "often than every 3 hours is missed, and bursty workloads are under-counted. "
        "Compare series_active_3h against series_listed_14d to gauge this.",
        "* Log ingest is CloudWatch Logs IncomingBytes -- raw, uncompressed, pre-enrichment, "
        "the same basis Dynatrace bills log ingest on. Log groups with stored data but no "
        "IncomingBytes metric are estimated from storedBytes/retention.",
        "* Firehose and S3 log-bucket volumes are reported separately because they usually "
        "re-carry logs already counted in CloudWatch Logs. Only the upper bound adds them.",
        f"* Host uptime mode '{args.host_uptime}': observed uptime is derived from hourly "
        "AWS/EC2 CPUUtilization coverage, since an instance only emits it while running.",
        "* Full-Stack memory follows DPS rules: RAM rounded up to the next 0.25 GiB with a "
        "4 GiB per-host minimum, and monitored time rounded up to 15-minute intervals. "
        "There is no 16 GiB cap under DPS -- that was the legacy host-unit model.",
        "* Included allowance modelled at 900 custom metric data points per charged GiB per "
        "15-minute interval, with no carry-over between intervals.",
        "* Non-EC2 compute (Fargate, Lambda, RDS) is counted for context but not sized: it "
        "has no host for OneAgent and bills under different SKUs.",
        "* Only what these credentials can see is counted. Other accounts in the "
        "organisation, and regions that are not opted in, are invisible to this run.",
    ]


def render_markdown(s, args):
    L, M, H, V, C = s["logs"], s["metrics"], s["hosts"], s["verdict"], s["indicative_cost_usd"]
    m = []
    m.append(f"# Dynatrace sizing -- AWS account `{s['account']['Account']}`")
    m.append("")
    cov = s["coverage"]
    m.append(f"*{len(cov['regions_fully_covered'])} of {cov['regions_requested']} regions fully "
             f"readable | {s['window_days']}-day window | generated {s['generated_utc']}*")
    m.append("")
    if cov["partial"]:
        m.append("> **Partial coverage.** These credentials could not read every region, so "
                 "every figure below is a floor for this account, not a total. Fully readable: "
                 f"{', '.join(cov['regions_fully_covered']) or 'none'}.")
        m.append("")
    m.append(f"## Verdict: **{V['overall']}**")
    m.append("")
    m.append(f"{V['overall_label']}")
    m.append("")
    m.append(f"Shape: {V['shape']}")
    m.append("")
    m.append("| Dimension | Size | Measured |")
    m.append("|---|---|---|")
    m.append(f"| Logs | {V['per_dimension']['logs']} | "
             f"{L['dt_log_ingest_gib_per_day']:,.4f} GiB/day |")
    m.append(f"| Metrics | {V['per_dimension']['metrics']} | "
             f"{M['raw_dp_per_day']:,.0f} data points/day |")
    m.append(f"| Hosts | {V['per_dimension']['hosts']} | "
             f"{H['gib_hr_per_day']:,.2f} GiB-hr/day |")
    m.append("")
    m.append("## SKU sizing")
    m.append("")
    m.append("| SKU | Unit | Per day | Per month | Per year |")
    m.append("|---|---|---:|---:|---:|")
    m.append(f"| Log Management - Ingest & Process | GiB | "
             f"{L['dt_log_ingest_gib_per_day']:,.4f} | "
             f"{L['dt_log_ingest_gib_per_day'] * 30.44:,.2f} | "
             f"{L['dt_log_ingest_gib_per_day'] * 365:,.2f} |")
    m.append(f"| Metrics - Ingest (raw, {M['poll_interval_seconds']}s poll) | data points | "
             f"{M['raw_dp_per_day']:,.0f} | {M['raw_dp_per_month']:,.0f} | "
             f"{M['raw_dp_per_year']:,.0f} |")
    m.append(f"| Metrics - Ingest (net of host allowance) | data points | "
             f"{M['billable_dp_per_day_after_allowance']:,.0f} | "
             f"{M['billable_dp_per_day_after_allowance'] * 30.44:,.0f} | "
             f"{M['billable_dp_per_day_after_allowance'] * 365:,.0f} |")
    m.append(f"| Full-Stack Monitoring | GiB-hr | {H['gib_hr_per_day']:,.2f} | "
             f"{H['gib_hr_per_day'] * 30.44:,.2f} | {H['gib_hr_per_day'] * 365:,.2f} |")
    m.append("")
    m.append("## Judgement calls")
    m.append("")
    for c in V["judgement_calls"] or ["Nothing unusual."]:
        m.append(f"- {c}")
    m.append("")
    m.append("## Indicative consumption at public list price")
    m.append("")
    m.append("Reference only -- real DPS rate cards are contractual and usually discounted.")
    m.append("")
    m.append("| Line | Rate | $/day | $/month | $/year |")
    m.append("|---|---|---:|---:|---:|")
    m.append(f"| Log ingest | ${C['rates_used']['log_ingest_per_gib']}/GiB | "
             f"{C['log_ingest_per_day']:,.2f} | {C['log_ingest_per_day'] * 30.44:,.2f} | "
             f"{C['log_ingest_per_day'] * 365:,.2f} |")
    m.append(f"| Metric data points | ${C['rates_used']['metric_dp_per_100k']}/100k | "
             f"{C['metrics_per_day']:,.2f} | {C['metrics_per_day'] * 30.44:,.2f} | "
             f"{C['metrics_per_day'] * 365:,.2f} |")
    m.append(f"| Full-Stack | ${C['rates_used']['fullstack_per_gib_hour']}/GiB-hr | "
             f"{C['fullstack_per_day']:,.2f} | {C['fullstack_per_day'] * 30.44:,.2f} | "
             f"{C['fullstack_per_day'] * 365:,.2f} |")
    m.append(f"| **Total** | | **{C['total_per_day']:,.2f}** | "
             f"**{C['total_per_month']:,.2f}** | **{C['total_per_year']:,.2f}** |")
    m.append("")
    m.append("## Assumptions")
    m.append("")
    for a in assumptions(args):
        m.append("- " + a.lstrip("* "))
    m.append("")
    return "\n".join(m)


def write_csvs(s, outdir):
    import csv
    os.makedirs(outdir, exist_ok=True)
    hosts = [i for f in s["_hosts_raw"] for i in f.instances]
    if hosts:
        with open(os.path.join(outdir, "hosts.csv"), "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(hosts[0].keys()))
            w.writeheader()
            w.writerows(hosts)
    with open(os.path.join(outdir, "log_groups.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["region", "log_group", "gib_per_day"])
        for f in s["_logs_raw"]:
            for n, v in sorted(f.incoming_gib_per_day_by_group.items(), key=lambda x: -x[1]):
                w.writerow([f.region, n, f"{v:.6f}"])
    with open(os.path.join(outdir, "metric_namespaces.csv"), "w", newline="",
              encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["region", "namespace", "billable_active_series"])
        for f in s["_metrics_raw"]:
            for ns, c in sorted(f.billable_by_namespace.items(), key=lambda x: -x[1]):
                w.writerow([f.region, ns, c])
    return outdir


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="dt_aws_sizing.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Size an AWS account for Dynatrace DPS: log ingest (GiB/day), custom "
                    "metric data points/day, and Full-Stack host monitoring (GiB-hr/day).",
        epilog=textwrap.dedent("""\
            examples:
              python dt_aws_sizing.py --creds-file aws-creds.txt
              python dt_aws_sizing.py --regions us-east-1,us-west-2 --days 7 --top 30
              python dt_aws_sizing.py --profile prod --json size.json --markdown size.md
              python dt_aws_sizing.py --poll-interval 300 --metric-scope all
        """))
    src = p.add_argument_group("credentials")
    src.add_argument("--creds-file", default="aws-creds.txt",
                     help="AWS shared-credentials-format file (default: aws-creds.txt; "
                          "pass '' to use the ambient environment)")
    src.add_argument("--creds-profile", default="default",
                     help="profile inside --creds-file (default: default)")
    src.add_argument("--profile", help="use a named profile from the standard AWS config")

    scope = p.add_argument_group("scope")
    scope.add_argument("--regions", default="all",
                       help="'all' (default) or a comma-separated list")
    scope.add_argument("--days", type=int, default=14,
                       help="observation window in days (default: 14)")
    scope.add_argument("--max-workers", type=int, default=10,
                       help="parallel region workers (default: 10)")

    tune = p.add_argument_group("sizing assumptions")
    tune.add_argument("--poll-interval", type=int, default=60, metavar="SECONDS",
                      help="assumed metric polling interval (default: 60 = 1/min). "
                           "Dynatrace's AWS integration defaults to 300.")
    tune.add_argument("--metric-scope", choices=["dt-default", "dt-supported", "all"],
                      default="dt-default",
                      help="which CloudWatch namespaces count as billable "
                           "(default: dt-default)")
    tune.add_argument("--host-uptime", choices=["observed", "assume-24x7"], default="observed",
                      help="bill measured uptime or assume everything runs 24x7 "
                           "(default: observed)")
    tune.add_argument("--include-stopped-hosts", action="store_true",
                      help="include stopped instances in the 24x7 projection")
    tune.add_argument("--log-overhead", type=float, default=1.0, metavar="FACTOR",
                      help="multiplier on log ingest for pipeline overhead (default: 1.0)")
    tune.add_argument("--count-firehose", action="store_true",
                      help="add Firehose IncomingBytes to the headline log figure "
                           "(off by default: usually double counts)")
    tune.add_argument("--no-storedbytes-fallback", action="store_true",
                      help="do not estimate ingest for log groups that have stored data "
                           "but no IncomingBytes metric")
    tune.add_argument("--no-s3-logs", action="store_true",
                      help="skip the S3 log-bucket growth estimate")
    tune.add_argument("--no-stream-counts", action="store_true",
                      help="skip per-log-group stream enumeration (much faster)")
    tune.add_argument("--stream-group-cap", type=int, default=400,
                      help="max log groups to enumerate streams for (default: 400)")

    rates = p.add_argument_group("rate card overrides (defaults are public list prices)")
    rates.add_argument("--rate-log-ingest", type=float, metavar="USD_PER_GIB")
    rates.add_argument("--rate-metric-dp", type=float, metavar="USD_PER_100K_DP")
    rates.add_argument("--rate-fullstack", type=float, metavar="USD_PER_GIB_HOUR")
    rates.add_argument("--rate-infra", type=float, metavar="USD_PER_HOST_HOUR")

    out = p.add_argument_group("output")
    out.add_argument("--json", metavar="PATH", help="write the full result as JSON")
    out.add_argument("--markdown", metavar="PATH", help="write a markdown report")
    out.add_argument("--csv-dir", metavar="DIR", help="write hosts/log-groups/namespaces CSVs")
    out.add_argument("--top", type=int, default=15, help="rows in top-N tables (default: 15)")
    out.add_argument("--quiet", action="store_true", help="suppress progress on stderr")
    return p.parse_args(argv)


def main(argv=None):
    global _VERBOSE
    args = parse_args(argv)
    _VERBOSE = not args.quiet
    if args.poll_interval <= 0:
        sys.exit("--poll-interval must be positive")
    if args.days <= 0:
        sys.exit("--days must be positive")

    session = make_session(args)
    sts = session.client("sts", region_name="us-east-1", config=BOTO_CFG)
    try:
        account = sts.get_caller_identity()
    except botocore.exceptions.ClientError as e:
        sys.exit(f"credentials are not usable: {e}")
    account.pop("ResponseMetadata", None)
    log(f"account {account['Account']} as {account['Arn']}")

    summary = run_scan(session, account, args)
    print(render_text(summary, args))

    if args.json:
        payload = {k: v for k, v in summary.items() if not k.startswith("_")}
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        log(f"wrote {args.json}")
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(summary, args))
        log(f"wrote {args.markdown}")
    if args.csv_dir:
        write_csvs(summary, args.csv_dir)
        log(f"wrote CSVs to {args.csv_dir}")
    return 0


def run_scan(session, account, args):
    """Scan every requested region and return the summary dict. Reusable by the driver."""
    regions = discover_regions(session, args.regions)
    log(f"scanning {len(regions)} region(s)")

    end = dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = end - dt.timedelta(days=args.days)

    logs_out, metrics_out, hosts_out = [], [], []

    def work(region):
        try:
            lf = collect_logs(session, region, start, end, args.days,
                              not args.no_stream_counts, args.stream_group_cap,
                              not args.no_s3_logs, not args.no_storedbytes_fallback)
            mf = collect_metrics(session, region, args.metric_scope)
            hf = collect_hosts(session, region, start, end, args.days,
                               args.include_stopped_hosts)
            return region, lf, mf, hf, None
        except Exception as e:                                   # noqa: BLE001
            # A hard failure means the region was never read. Mark every collector
            # unreadable so it is reported as missing coverage, not as "zero resources".
            lf, mf, hf = LogFinding(region), MetricFinding(region), HostFinding(region)
            for finding in (lf, mf, hf):
                finding.access_denied = True
                finding.notes.append(f"region scan failed: {type(e).__name__}: {e}")
            return region, lf, mf, hf, e

    done = 0
    with futures.ThreadPoolExecutor(max_workers=args.max_workers) as ex:
        for region, lf, mf, hf, err in ex.map(work, regions):
            done += 1
            if err:
                log(f"  [{done}/{len(regions)}] {region}: FAILED -- {err}")
            else:
                log(f"  [{done}/{len(regions)}] {region}: "
                    f"{hf.instances_running} running host(s), {lf.log_groups} log group(s), "
                    f"{mf.series_active} active series")
            logs_out.append(lf)
            metrics_out.append(mf)
            hosts_out.append(hf)

    summary = build_summary(account, regions, logs_out, metrics_out, hosts_out, args)
    summary["_logs_raw"] = logs_out
    summary["_metrics_raw"] = metrics_out
    summary["_hosts_raw"] = hosts_out
    summary["per_region"] = {
        r: {"logs": asdict(l), "metrics": asdict(m), "hosts": asdict(h)}
        for r, l, m, h in zip(regions, logs_out, metrics_out, hosts_out)
    }

    return summary


if __name__ == "__main__":
    sys.exit(main())
