#!/usr/bin/env python3
"""
dt_cloud_sizing.py -- Size a portfolio of AWS accounts and Azure subscriptions for
Dynatrace DPS, driven by a CSV account list.

The CSV needs a provider column and an account-id column; a name column is optional:

    provider,account_id,name,enabled
    aws,157931419999,Josh sandbox,true
    aws,446130280781,Demo estate,true
    azure,7a91e8b3-ee09-4906-91a2-f357b77a61fd,Sales-Engineering/NORAM,true

Validation:
  * AWS  account IDs must be exactly 12 digits.
  * Azure subscription IDs must be a UUID (8-4-4-4-12 hex).

Produces a per-account breakdown plus a portfolio roll-up in the three DPS units:
log ingest GiB/day, metric data points/day, and Full-Stack GiB-hr/day.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import textwrap

from dt_sizing_common import (
    SECONDS_PER_DAY, HOST_EQUIV_GIB_HR, SHARED_ASSUMPTIONS,
    size_dimensions, indicative_cost, allowance_netting, rule, wrap_into, enable_utf8,
)

enable_utf8()

AWS_ID_RE = re.compile(r"^\d{12}$")
AZURE_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                         r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
PROVIDERS = ("aws", "azure")
TRUTHY = {"1", "true", "yes", "y", "on", ""}


class AccountSpecError(ValueError):
    pass


def validate_account(provider, account_id):
    provider = (provider or "").strip().lower()
    account_id = (account_id or "").strip()
    if provider not in PROVIDERS:
        raise AccountSpecError(
            f"unknown provider '{provider}' (expected one of: {', '.join(PROVIDERS)})")
    if not account_id:
        raise AccountSpecError("missing account id")
    if provider == "aws" and not AWS_ID_RE.match(account_id):
        raise AccountSpecError(
            f"AWS account id '{account_id}' is not 12 digits")
    if provider == "azure" and not AZURE_ID_RE.match(account_id):
        raise AccountSpecError(
            f"Azure subscription id '{account_id}' is not a UUID "
            "(expected 8-4-4-4-12 hex)")
    return provider, account_id


def read_accounts(path):
    """Parse the account CSV, tolerating column-name variants and comment lines."""
    if not os.path.exists(path):
        sys.exit(f"account list not found: {path}")
    accounts, errors = [], []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        rows = [r for r in fh if r.strip() and not r.lstrip().startswith("#")]
    reader = csv.DictReader(rows)
    if not reader.fieldnames:
        sys.exit(f"{path} is empty")
    norm = {(f or "").strip().lower().replace(" ", "_").replace("-", "_"): f
            for f in reader.fieldnames}

    def pick(row, *names, default=""):
        for n in names:
            if n in norm:
                v = row.get(norm[n])
                if v is not None and str(v).strip():
                    return str(v).strip()
        return default

    for lineno, row in enumerate(reader, start=2):
        provider = pick(row, "provider", "cloud", "cloud_provider", "platform")
        account_id = pick(row, "account_id", "account", "id", "subscription_id",
                          "account_uuid", "uuid", "subscription")
        name = pick(row, "name", "account_name", "description", "label")
        enabled = pick(row, "enabled", "active", "include", default="true").lower()
        if enabled not in TRUTHY:
            continue
        try:
            provider, account_id = validate_account(provider, account_id)
        except AccountSpecError as e:
            errors.append(f"  line {lineno}: {e}")
            continue
        accounts.append({"provider": provider, "account_id": account_id,
                         "name": name or account_id})
    if errors:
        print(f"Rejected {len(errors)} row(s) in {path}:", file=sys.stderr)
        for e in errors:
            print(e, file=sys.stderr)
    if not accounts:
        sys.exit(f"no valid, enabled accounts in {path}")
    dupes = {}
    for a in accounts:
        dupes.setdefault((a["provider"], a["account_id"]), 0)
        dupes[(a["provider"], a["account_id"])] += 1
    for key, n in dupes.items():
        if n > 1:
            print(f"warning: {key[0]} {key[1]} listed {n} times; sizing it once",
                  file=sys.stderr)
    seen, unique = set(), []
    for a in accounts:
        k = (a["provider"], a["account_id"])
        if k not in seen:
            seen.add(k)
            unique.append(a)
    return unique


# --------------------------------------------------------------------------------------
# Provider dispatch -- each provider returns a summary in the common shape
# --------------------------------------------------------------------------------------

def size_aws(account, args):
    import dt_aws_sizing as aws
    ns = argparse.Namespace(
        creds_file=args.aws_creds_file, creds_profile=args.aws_creds_profile,
        profile=None, regions=args.aws_regions, days=args.days,
        max_workers=args.max_workers, poll_interval=args.poll_interval,
        metric_scope=args.aws_metric_scope, host_uptime=args.host_uptime,
        include_stopped_hosts=False, log_overhead=args.log_overhead,
        count_firehose=False, no_s3_logs=args.fast, no_stream_counts=args.fast,
        no_storedbytes_fallback=False, stream_group_cap=400,
        rate_log_ingest=None, rate_metric_dp=None, rate_fullstack=None, rate_infra=None,
        json=None, markdown=None, csv_dir=None, top=args.top, quiet=args.quiet)
    aws._VERBOSE = not args.quiet

    session = aws.make_session(ns)
    sts = session.client("sts", region_name="us-east-1", config=aws.BOTO_CFG)
    ident = sts.get_caller_identity()
    ident.pop("ResponseMetadata", None)
    if ident["Account"] != account["account_id"]:
        raise RuntimeError(
            f"credentials are for AWS account {ident['Account']}, but the CSV asked for "
            f"{account['account_id']}. Point --aws-creds-file at the right credentials.")

    summary = aws.run_scan(session, ident, ns)
    return normalize_aws(summary, account)


def size_azure(account, args):
    import dt_azure_sizing as az
    ns = argparse.Namespace(
        days=args.days, poll_interval=args.poll_interval,
        dimension_factor=args.azure_dimension_factor, host_uptime=args.host_uptime,
        no_uptime=args.fast, no_eventhub=args.fast, no_storage=args.fast,
        count_eventhub=False, log_overhead=args.log_overhead,
        max_workers=args.max_workers, top=args.top, json=None, quiet=args.quiet,
        rates={})
    az._VERBOSE = not args.quiet
    summary = az.size_subscription(account["account_id"], account["name"], ns)
    return normalize_azure(summary, account)


def normalize_aws(s, account):
    L, M, H = s["logs"], s["metrics"], s["hosts"]
    readable = len(s["coverage"]["regions_fully_covered"])
    return {
        "provider": "aws", "account_id": account["account_id"],
        "name": account["name"],
        # Zero readable regions means "we learned nothing", not "the account is empty".
        "sized": readable > 0,
        "coverage": s["coverage"],
        "log_gib_per_day": L["dt_log_ingest_gib_per_day"],
        "log_gib_per_day_upper": L["dt_log_ingest_gib_per_day_upper"],
        "log_containers": L["log_groups"],
        "log_streams": L["log_streams"],
        "metric_series": M["series_billable"],
        "raw_dp_per_day": M["raw_dp_per_day"],
        "included_dp_allowance_per_day": M["included_dp_allowance_per_day"],
        "billable_dp_per_day": M["billable_dp_per_day_after_allowance"],
        "hosts_monitored": H["hosts_in_projection"],
        "host_ram_gib_billable": H["running_ram_gib_dps_billable"],
        "gib_hr_per_day": H["gib_hr_per_day"],
        "host_hr_per_day": H["host_hr_per_day_observed"],
        "verdict": s["verdict"], "detail": s,
    }


def normalize_azure(s, account):
    L, M, H = s["logs"], s["metrics"], s["hosts"]
    return {
        "provider": "azure", "account_id": account["account_id"],
        "name": account["name"], "sized": s["coverage"]["auth_ok"],
        "coverage": s["coverage"],
        "log_gib_per_day": L["ingest_gib_per_day"],
        "log_gib_per_day_upper": L["ingest_gib_per_day_upper"],
        "log_containers": L["workspaces"],
        "log_streams": L["tables"],
        "metric_series": M["series_billable"],
        "raw_dp_per_day": M["raw_dp_per_day"],
        "included_dp_allowance_per_day": M["included_dp_allowance_per_day"],
        "billable_dp_per_day": M["billable_dp_per_day_after_allowance"],
        "hosts_monitored": H["monitored_units"],
        "host_ram_gib_billable": H["running_ram_gib_dps_billable"],
        "gib_hr_per_day": H["gib_hr_per_day"],
        "host_hr_per_day": H["host_hr_per_day_observed"],
        "verdict": s["verdict"], "detail": s,
    }


# --------------------------------------------------------------------------------------
# Portfolio roll-up
# --------------------------------------------------------------------------------------

def rollup(results, args):
    sized = [r for r in results if r["sized"]]
    skipped = [r for r in results if not r["sized"]]

    tot = {k: sum(r[k] for r in sized) for k in
           ("log_gib_per_day", "log_gib_per_day_upper", "log_containers", "log_streams",
            "metric_series", "raw_dp_per_day", "hosts_monitored",
            "host_ram_gib_billable", "gib_hr_per_day", "host_hr_per_day")}

    # Allowance is re-netted at portfolio level: hosts in one account earn allowance that
    # can absorb metric volume anywhere in the same Dynatrace tenant.
    tot.update(allowance_netting(tot["raw_dp_per_day"], tot["gib_hr_per_day"]))
    tot["host_equivalents_16gib"] = tot["gib_hr_per_day"] / HOST_EQUIV_GIB_HR

    if not sized:
        sizing = {"per_dimension": {"logs": "--", "metrics": "--", "hosts": "--"},
                  "overall": "NO DATA",
                  "overall_label": "nothing could be measured -- no account was readable",
                  "shape": "unknown", "dominant_dimension": "none"}
    else:
        sizing = size_dimensions(tot["log_gib_per_day"], tot["raw_dp_per_day"],
                                 tot["gib_hr_per_day"])
    cost = indicative_cost(tot["log_gib_per_day"], tot["billable_dp_per_day_after_allowance"],
                           tot["gib_hr_per_day"], tot["host_hr_per_day"])

    by_provider = {}
    for r in sized:
        p = by_provider.setdefault(r["provider"], {"accounts": 0, "log_gib_per_day": 0.0,
                                                   "raw_dp_per_day": 0.0,
                                                   "gib_hr_per_day": 0.0,
                                                   "hosts_monitored": 0})
        p["accounts"] += 1
        for k in ("log_gib_per_day", "raw_dp_per_day", "gib_hr_per_day", "hosts_monitored"):
            p[k] += r[k]

    calls = []
    if skipped and not sized:
        calls.append(
            "NOTHING WAS MEASURED. Every account in the list failed on credentials, so "
            "there is no portfolio total to report. Refresh the AWS credentials file and "
            "run 'az login' for Azure, then re-run.")
    if skipped:
        calls.append(
            f"{len(skipped)} of {len(results)} account(s) could NOT be sized: "
            + "; ".join(f"{r['provider']} {r['name']}" for r in skipped)
            + ". The portfolio totals below exclude them entirely.")
    partial = [r for r in sized if r["coverage"].get("partial")]
    if partial:
        calls.append(
            f"{len(partial)} sized account(s) had partial coverage: "
            + "; ".join(r["name"] for r in partial)
            + ". Their contribution is a floor, so the portfolio total is too.")
    if tot["allowance_covers_pct"] >= 99.9 and tot["raw_dp_per_day"] > 0:
        calls.append(
            "Across the portfolio, the Full-Stack host allowance "
            f"({tot['included_dp_allowance_per_day']:,.0f} DP/day) absorbs every cloud metric "
            "data point. Metrics add nothing to the quote.")
    if sized:
        top = max(sized, key=lambda r: r["gib_hr_per_day"])
        if tot["gib_hr_per_day"] > 0 and top["gib_hr_per_day"] / tot["gib_hr_per_day"] > 0.6:
            calls.append(
                f"'{top['name']}' alone is "
                f"{100 * top['gib_hr_per_day'] / tot['gib_hr_per_day']:.0f}% of portfolio host "
                "footprint. The whole quote hinges on that one account being right.")

    verdict = dict(sizing)
    verdict["judgement_calls"] = calls
    return {"totals": tot, "by_provider": by_provider, "indicative_cost_usd": cost,
            "verdict": verdict, "accounts_sized": len(sized), "accounts_skipped": len(skipped)}


def render_portfolio(results, roll, args):
    T, V, C = roll["totals"], roll["verdict"], roll["indicative_cost_usd"]
    o = []
    o.append("=" * 96)
    o.append("  DYNATRACE PORTFOLIO SIZING")
    o.append(f"  {roll['accounts_sized']} account(s) sized, {roll['accounts_skipped']} skipped "
             f"| {args.days}-day window")
    o.append("=" * 96)

    o.append(rule("PORTFOLIO VERDICT"))
    o.append(f"  OVERALL SIZE:  {V['overall']}  --  {V['overall_label']}")
    o.append(f"  Shape:         {V['shape']}")
    o.append(f"  Per dimension: logs={V['per_dimension']['logs']}  "
             f"metrics={V['per_dimension']['metrics']}  hosts={V['per_dimension']['hosts']}")

    o.append(rule("PER ACCOUNT"))
    o.append(f"  {'provider':<9}{'account':<38}{'size':<6}{'logs GiB/d':>12}"
             f"{'metric DP/d':>16}{'GiB-hr/d':>12}{'hosts':>8}")
    o.append("  " + "-" * 94)
    for r in sorted(results, key=lambda x: -x["gib_hr_per_day"]):
        if not r["sized"]:
            why = (r.get("coverage") or {}).get("auth_error") or "no readable data"
            short = "expired/invalid credentials" if "xpired" in why or "AADSTS" in why                 else why[:44]
            o.append(f"  {r['provider']:<9}{r['name'][:36]:<38}{'--':<6}"
                     f"{('NOT SIZED: ' + short):>48}")
            continue
        flag = "*" if r["coverage"].get("partial") else " "
        o.append(f"  {r['provider']:<9}{(r['name'][:35] + flag):<38}"
                 f"{r['verdict']['overall']:<6}{r['log_gib_per_day']:>12,.3f}"
                 f"{r['raw_dp_per_day']:>16,.0f}{r['gib_hr_per_day']:>12,.0f}"
                 f"{r['hosts_monitored']:>8,}")
    o.append("  " + "-" * 94)
    o.append(f"  {'TOTAL':<9}{'':<38}{V['overall']:<6}{T['log_gib_per_day']:>12,.3f}"
             f"{T['raw_dp_per_day']:>16,.0f}{T['gib_hr_per_day']:>12,.0f}"
             f"{T['hosts_monitored']:>8,}")
    if any(r["sized"] and r["coverage"].get("partial") for r in results):
        o.append("  * partial coverage -- this account's figures are a floor")

    o.append(rule("PORTFOLIO SKU TOTALS"))
    o.append("  1. Log Management -- Ingest & Process")
    o.append(f"       {T['log_gib_per_day']:>16,.4f}  GiB/day")
    o.append(f"       {T['log_gib_per_day'] * 30.44:>16,.2f}  GiB/month")
    o.append(f"       {T['log_gib_per_day'] * 365:>16,.2f}  GiB/year")
    o.append(f"       across {T['log_containers']:,.0f} log container(s) / "
             f"{T['log_streams']:,.0f} stream(s)")
    o.append("")
    o.append(f"  2. Metrics -- Ingest @ {args.poll_interval}s polling")
    o.append(f"       {T['raw_dp_per_day']:>16,.0f}  raw data points/day")
    o.append(f"       {T['raw_dp_per_day'] * 30.44:>16,.0f}  raw data points/month")
    o.append(f"       {T['raw_dp_per_day'] * 365:>16,.0f}  raw data points/year")
    o.append(f"       from {T['metric_series']:,.0f} time series")
    o.append(f"       included allowance: {T['included_dp_allowance_per_day']:,.0f} DP/day "
             f"(covers {T['allowance_covers_pct']:.1f}%)")
    o.append(f"       NET BILLABLE: {T['billable_dp_per_day_after_allowance']:,.0f} DP/day")
    o.append("")
    o.append("  3. Full-Stack Monitoring -- host memory")
    o.append(f"       {T['gib_hr_per_day']:>16,.2f}  GiB-hr/day")
    o.append(f"       {T['gib_hr_per_day'] * 30.44:>16,.2f}  GiB-hr/month")
    o.append(f"       {T['gib_hr_per_day'] * 365:>16,.2f}  GiB-hr/year")
    o.append(f"       {T['hosts_monitored']:,.0f} monitored unit(s), "
             f"{T['host_ram_gib_billable']:,.2f} GiB DPS-billable RAM")
    o.append(f"       equivalent to {T['host_equivalents_16gib']:,.1f} x 16 GiB hosts at 24x7")

    if roll["by_provider"]:
        o.append(rule("BY PROVIDER"))
        o.append(f"  {'provider':<10}{'accts':>7}{'logs GiB/d':>14}{'metric DP/d':>18}"
                 f"{'GiB-hr/d':>14}{'hosts':>9}")
        for p, v in sorted(roll["by_provider"].items()):
            o.append(f"  {p:<10}{v['accounts']:>7,}{v['log_gib_per_day']:>14,.3f}"
                     f"{v['raw_dp_per_day']:>18,.0f}{v['gib_hr_per_day']:>14,.0f}"
                     f"{v['hosts_monitored']:>9,}")

    o.append(rule("JUDGEMENT CALLS"))
    if V["judgement_calls"]:
        for c in V["judgement_calls"]:
            wrap_into(o, c, 90)
            o.append("")
    else:
        o.append("  Nothing unusual across the portfolio.")

    o.append(rule("INDICATIVE CONSUMPTION AT PUBLIC LIST PRICE"))
    o.append("  Reference only. Real DPS rate cards are contractual and usually discounted.")
    o.append(f"  Log ingest        ${C['log_ingest_per_day']:>12,.2f}/day")
    o.append(f"  Metric DP (net)   ${C['metrics_per_day']:>12,.2f}/day")
    o.append(f"  Full-Stack hosts  ${C['fullstack_per_day']:>12,.2f}/day")
    o.append("  " + " " * 16 + "-" * 16)
    o.append(f"  TOTAL             ${C['total_per_day']:>12,.2f}/day   "
             f"${C['total_per_month']:,.2f}/month   ${C['total_per_year']:,.2f}/year")

    o.append(rule("ASSUMPTIONS"))
    for a in SHARED_ASSUMPTIONS:
        wrap_into(o, "* " + a, 90)
    wrap_into(o, f"* Metric polling assumed at {args.poll_interval}s "
                 f"({SECONDS_PER_DAY // args.poll_interval} polls/day/series). Provider "
                 "defaults differ: Dynatrace polls AWS CloudWatch every 5 minutes, while "
                 "Azure Monitor platform metrics are natively 1-minute.", 90)
    wrap_into(o, "* Provider-specific assumptions are in each account's own report; run "
                 "dt_aws_sizing.py or dt_azure_sizing.py directly for the full detail.", 90)
    o.append("")
    return "\n".join(o)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="dt_cloud_sizing.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Size a CSV list of AWS accounts and Azure subscriptions for Dynatrace DPS.",
        epilog=textwrap.dedent("""\
            csv format (header required; name and enabled optional):
              provider,account_id,name,enabled
              aws,157931419999,Josh sandbox,true
              azure,7a91e8b3-ee09-4906-91a2-f357b77a61fd,NORAM,true

            examples:
              python dt_cloud_sizing.py --accounts accounts.csv
              python dt_cloud_sizing.py --accounts accounts.csv --fast --json portfolio.json
              python dt_cloud_sizing.py --accounts accounts.csv --validate-only
        """))
    p.add_argument("--accounts", default="accounts.csv",
                   help="CSV of provider,account_id (default: accounts.csv)")
    p.add_argument("--validate-only", action="store_true",
                   help="parse and validate the CSV, then exit without calling any cloud API")
    p.add_argument("--days", type=int, default=14)
    p.add_argument("--poll-interval", type=int, default=60, metavar="SECONDS")
    p.add_argument("--host-uptime", choices=["observed", "assume-24x7"], default="observed")
    p.add_argument("--log-overhead", type=float, default=1.0)
    p.add_argument("--fast", action="store_true",
                   help="skip the slow extras (log stream counts, S3/storage sinks, "
                        "per-VM uptime probes)")
    p.add_argument("--max-workers", type=int, default=10)
    p.add_argument("--top", type=int, default=15)
    p.add_argument("--per-account-detail", action="store_true",
                   help="print each account's full provider report as well as the roll-up")
    p.add_argument("--json", metavar="PATH", help="write the full portfolio result as JSON")
    p.add_argument("--quiet", action="store_true")

    a = p.add_argument_group("aws")
    a.add_argument("--aws-creds-file", default="aws-creds.txt")
    a.add_argument("--aws-creds-profile", default="default")
    a.add_argument("--aws-regions", default="all")
    a.add_argument("--aws-metric-scope", choices=["dt-default", "dt-supported", "all"],
                   default="dt-default")

    z = p.add_argument_group("azure")
    z.add_argument("--azure-dimension-factor", type=float, default=1.0,
                   help="multiplier for dimensioned Azure metrics (default: 1.0 = lower bound)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    accounts = read_accounts(args.accounts)

    if args.validate_only:
        print(f"{len(accounts)} valid account(s) in {args.accounts}:")
        for a in accounts:
            print(f"  {a['provider']:<6} {a['account_id']:<40} {a['name']}")
        return 0

    results = []
    for acct in accounts:
        label = f"{acct['provider']} {acct['account_id']} ({acct['name']})"
        if not args.quiet:
            print(f"\n>>> sizing {label}", file=sys.stderr, flush=True)
        try:
            if acct["provider"] == "aws":
                r = size_aws(acct, args)
            else:
                r = size_azure(acct, args)
        except Exception as e:                                   # noqa: BLE001
            print(f"    FAILED: {type(e).__name__}: {e}", file=sys.stderr)
            r = {"provider": acct["provider"], "account_id": acct["account_id"],
                 "name": acct["name"], "sized": False,
                 "coverage": {"partial": True, "auth_ok": False, "auth_error": str(e)},
                 "log_gib_per_day": 0.0, "log_gib_per_day_upper": 0.0, "log_containers": 0,
                 "log_streams": 0, "metric_series": 0, "raw_dp_per_day": 0.0,
                 "included_dp_allowance_per_day": 0.0, "billable_dp_per_day": 0.0,
                 "hosts_monitored": 0, "host_ram_gib_billable": 0.0, "gib_hr_per_day": 0.0,
                 "host_hr_per_day": 0.0, "verdict": {"overall": "--"}, "detail": None}
        results.append(r)
        if args.per_account_detail and r.get("detail"):
            if r["provider"] == "aws":
                import dt_aws_sizing as aws
                print(aws.render_text(r["detail"], _aws_ns(args)))
            else:
                import dt_azure_sizing as az
                print(az.render_text(r["detail"], _azure_ns(args), args.top))

    roll = rollup(results, args)
    print(render_portfolio(results, roll, args))

    if args.json:
        payload = {
            "generated_utc": roll["totals"] and None,
            "accounts": [{k: v for k, v in r.items() if k != "detail"} for r in results],
            "portfolio": roll,
        }
        payload.pop("generated_utc")
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


def _aws_ns(args):
    return argparse.Namespace(host_uptime=args.host_uptime, top=args.top,
                              metric_scope=args.aws_metric_scope, days=args.days,
                              poll_interval=args.poll_interval)


def _azure_ns(args):
    return argparse.Namespace(host_uptime=args.host_uptime, days=args.days,
                              poll_interval=args.poll_interval)


if __name__ == "__main__":
    sys.exit(main())
