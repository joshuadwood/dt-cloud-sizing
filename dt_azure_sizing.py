#!/usr/bin/env python3
"""
dt_azure_sizing.py -- Size an Azure subscription for Dynatrace DPS SKUs, via the az CLI.

Produces the same three numbers as the AWS sizer, in the same units:

  1. LOGS    -> GiB/day   Log Analytics workspace ingest (Usage table), + Event Hub, + storage
  2. METRICS -> DP/day    Azure Monitor time series x polling frequency
  3. HOSTS   -> GiB-hr/day  VM / VM Scale Set / App Service Plan memory x running hours

Requires only the core `az` CLI (no extensions) and an active `az login`.
Read-only: every call is a list/show/query.
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import datetime as dt
import json
import os
import shutil
import tempfile
import subprocess
import sys
import textwrap
from collections import Counter
from dataclasses import dataclass, field, asdict

from dt_sizing_common import (
    GIB, SECONDS_PER_DAY, HOST_EQUIV_GIB_HR, SHARED_ASSUMPTIONS,
    dps_billable_host_gib, dps_billable_hours, allowance_netting,
    size_dimensions, indicative_cost, rule, wrap_into, enable_utf8,
)

enable_utf8()

_VERBOSE = True


def log(msg):
    if _VERBOSE:
        print(msg, file=sys.stderr, flush=True)


class AzureAuthError(RuntimeError):
    """The az CLI has no usable credentials for this subscription."""


_AUTH_MARKERS = ("AADSTS", "az login", "Please run 'az login'", "ExpiredToken",
                 "refresh token has expired", "no longer valid", "AuthenticationFailed")


def _az_executable():
    """Resolve the az CLI. On Windows it is az.cmd, which bare subprocess cannot find."""
    for cand in ("az", "az.cmd", "az.bat", "az.exe"):
        found = shutil.which(cand)
        if found:
            return found
    return None


_AZ_BIN = None


def _kill_tree(pid):
    """Force-kill a process and every descendant it spawned.

    On Windows, az.cmd is a batch file: our subprocess call actually spawns
    python -> cmd.exe -> az's own python.exe. Popen.kill() on timeout only kills the
    immediate cmd.exe child; the grandchild survives, keeps stdout/stderr open, and the
    stdlib's post-timeout communicate() then blocks FOREVER waiting for those pipes to
    close. taskkill /T kills the whole tree so that never happens.
    """
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                       capture_output=True, timeout=15)
    else:
        import signal
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except Exception:
            pass


def az(args, timeout=300, allow_fail=True):
    """Run an `az` command and return parsed JSON, or None if it failed.

    Raises AzureAuthError on credential failures so a whole subscription can be
    abandoned immediately instead of retrying every subsequent call.
    """
    global _AZ_BIN
    if _AZ_BIN is None:
        _AZ_BIN = _az_executable()
        if _AZ_BIN is None:
            sys.exit("the 'az' CLI is not installed or not on PATH")
    cmd = [_AZ_BIN, *args, "-o", "json"]
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace",
                                creationflags=creationflags)
    except FileNotFoundError:
        sys.exit("the 'az' CLI is not installed or not on PATH")
    try:
        out, err = proc.communicate(timeout=timeout)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        _kill_tree(proc.pid)
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        return None
    p = argparse.Namespace(returncode=rc, stdout=out, stderr=err)

    if p.returncode != 0:
        err = (p.stderr or "")
        if any(m in err for m in _AUTH_MARKERS):
            raise AzureAuthError(err.strip().splitlines()[0] if err.strip() else "auth failed")
        if not allow_fail:
            raise RuntimeError(f"az {' '.join(args[:3])} failed: {err.strip()[:300]}")
        return None
    out = (p.stdout or "").strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------------------
# Azure reference data
# --------------------------------------------------------------------------------------

# App Service Plan / Functions / Logic Apps SKU -> RAM in GiB.
APPSERVICE_SKU_GIB = {
    "F1": 1.0, "D1": 1.0,
    "B1": 1.75, "B2": 3.5, "B3": 7.0,
    "S1": 1.75, "S2": 3.5, "S3": 7.0,
    "P1": 1.75, "P2": 3.5, "P3": 7.0,
    "P1V2": 3.5, "P2V2": 7.0, "P3V2": 14.0,
    "P0V3": 4.0, "P1V3": 8.0, "P2V3": 16.0, "P3V3": 32.0,
    "P1MV3": 12.0, "P2MV3": 24.0, "P3MV3": 48.0, "P4MV3": 96.0, "P5MV3": 192.0,
    "I1": 3.5, "I2": 7.0, "I3": 14.0,
    "I1V2": 8.0, "I2V2": 16.0, "I3V2": 32.0, "I4V2": 64.0, "I5V2": 128.0,
    "EP1": 3.5, "EP2": 7.0, "EP3": 14.0,
    "WS1": 3.5, "WS2": 7.0, "WS3": 14.0,
    "Y1": 1.5,  # Consumption plan -- serverless, sized for context only
}

# Resource types with no Azure Monitor metrics worth polling, or that Dynatrace's Azure
# integration does not ingest. Types not listed here are resolved dynamically by asking
# Azure for their metric definitions, so this list only suppresses known noise.
EXCLUDED_TYPES = {
    "microsoft.resources/deployments", "microsoft.resources/deploymentscripts",
    "microsoft.authorization/roleassignments", "microsoft.authorization/policyassignments",
    "microsoft.portal/dashboards", "microsoft.insights/actiongroups",
    "microsoft.insights/alertrules", "microsoft.insights/metricalerts",
    "microsoft.insights/scheduledqueryrules", "microsoft.insights/activitylogalerts",
    "microsoft.insights/workbooks", "microsoft.insights/datacollectionrules",
    "microsoft.insights/datacollectionendpoints", "microsoft.insights/privatelinkscopes",
    "microsoft.operationsmanagement/solutions", "microsoft.security/automations",
    "microsoft.managedidentity/userassignedidentities",
    "microsoft.network/networkwatchers", "microsoft.network/networksecuritygroups",
    "microsoft.network/routetables", "microsoft.network/networkinterfaces",
    "microsoft.network/privatednszones", "microsoft.network/privateendpoints",
    "microsoft.compute/disks", "microsoft.compute/snapshots", "microsoft.compute/images",
    "microsoft.compute/sshpublickeys", "microsoft.compute/availabilitysets",
    "microsoft.compute/restorepointcollections", "microsoft.compute/galleries",
    "microsoft.web/certificates", "microsoft.web/connections",
    "microsoft.keyvault/vaults/secrets", "microsoft.alertsmanagement/smartdetectoralertrules",
    "microsoft.storage/storageaccounts/blobservices",
    "microsoft.operationalinsights/querypacks", "microsoft.maintenance/maintenanceconfigurations",
}

# Storage-account name hints suggesting a log/diagnostics sink
STORAGE_LOG_HINTS = ("log", "diag", "audit", "archive", "insights", "flow", "nsg")

# Log Analytics tables that Dynatrace would not normally re-ingest as logs (they are
# Azure Monitor's own metering/heartbeat plumbing).
LA_NON_LOG_TABLES = {"Usage", "Heartbeat", "Operation", "AzureMetrics"}


# --------------------------------------------------------------------------------------
# Hosts: VMs, VM Scale Sets, App Service Plans
# --------------------------------------------------------------------------------------

@dataclass
class AzureHosts:
    vms_total: int = 0
    vms_running: int = 0
    vms_stopped: int = 0
    vmss_count: int = 0
    vmss_instances: int = 0
    aks_clusters: int = 0
    aks_node_count: int = 0
    appservice_plans: int = 0
    appservice_instances: int = 0
    appservice_sites: int = 0
    container_instances: int = 0
    sql_databases: int = 0
    functions: int = 0
    running_mem_gib: float = 0.0
    billable_mem_gib: float = 0.0
    gib_hr_per_day_observed: float = 0.0
    gib_hr_per_day_24x7: float = 0.0
    host_hr_per_day_observed: float = 0.0
    by_size: dict = field(default_factory=dict)
    hosts: list = field(default_factory=list)
    notes: list = field(default_factory=list)


_SIZE_MEM_CACHE: dict[tuple, float] = {}


def vm_size_memory(sub, location, sizes_needed):
    """Resolve VM size -> RAM in GiB for one location, memoised."""
    missing = [s for s in sizes_needed if (location, s) not in _SIZE_MEM_CACHE]
    if not missing:
        return
    data = az(["vm", "list-sizes", "-l", location, "--subscription", sub])
    if not data:
        return
    for entry in data:
        mb = entry.get("memoryInMB", entry.get("memoryInMb"))
        if mb is not None:
            _SIZE_MEM_CACHE[(location, entry["name"])] = mb / 1024.0


def appservice_sku_gib(sku):
    """RAM for an App Service Plan SKU, tolerating name variants (P1v3 / P1V3 / PremiumV3)."""
    if not sku:
        return None
    return APPSERVICE_SKU_GIB.get(str(sku).upper())


def vm_uptime_hours_per_day(sub, resource_id, start_iso, end_iso, days):
    """Observed running hours/day from hourly 'Percentage CPU' coverage.

    An Azure VM only emits Percentage CPU while running, so the count of hourly buckets
    that carry a value measures uptime the same way CPUUtilization does on EC2.
    """
    data = az(["monitor", "metrics", "list", "--resource", resource_id,
               "--subscription", sub, "--metric", "Percentage CPU",
               "--interval", "PT1H", "--aggregation", "Maximum",
               "--start-time", start_iso, "--end-time", end_iso], timeout=120)
    if not data:
        return None
    try:
        series = data["value"][0]["timeseries"]
        if not series:
            return 0.0
        points = [p for p in series[0]["data"] if p.get("maximum") is not None]
        return min(len(points) / days, 24.0)
    except (KeyError, IndexError, TypeError):
        return None


def collect_hosts(sub, start_iso, end_iso, days, measure_uptime, max_workers):
    h = AzureHosts()

    # ---- Virtual machines --------------------------------------------------------------
    vms = az(["vm", "list", "-d", "--subscription", sub], timeout=600) or []
    h.vms_total = len(vms)
    by_loc = {}
    for vm in vms:
        by_loc.setdefault(vm["location"], set()).add(vm["hardwareProfile"]["vmSize"])
    for loc, sizes in by_loc.items():
        vm_size_memory(sub, loc, sizes)

    uptimes = {}
    if measure_uptime and vms:
        def one(vm):
            return vm["id"], vm_uptime_hours_per_day(sub, vm["id"], start_iso, end_iso, days)
        with futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            for rid, hrs in ex.map(one, vms):
                uptimes[rid] = hrs

    for vm in vms:
        size = vm["hardwareProfile"]["vmSize"]
        loc = vm["location"]
        raw = _SIZE_MEM_CACHE.get((loc, size))
        power = (vm.get("powerState") or "").lower()
        running = "running" in power
        h.vms_running += 1 if running else 0
        h.vms_stopped += 1 if not running else 0
        h.by_size[size] = h.by_size.get(size, 0) + 1
        if raw is None:
            h.notes.append(f"unknown RAM for VM size {size} in {loc}")
            continue
        billable = dps_billable_host_gib(raw)
        if running:
            h.running_mem_gib += raw
            h.billable_mem_gib += billable
            h.gib_hr_per_day_24x7 += billable * 24
        hrs = uptimes.get(vm["id"])
        if hrs is None:
            hrs = 24.0 if running else 0.0
        if hrs > 0:
            h.gib_hr_per_day_observed += billable * dps_billable_hours(hrs)
            h.host_hr_per_day_observed += dps_billable_hours(hrs)
        h.hosts.append({
            "kind": "vm", "name": vm["name"], "location": loc, "size": size,
            "power_state": vm.get("powerState", ""), "ram_gib": raw,
            "dps_billable_gib": billable, "observed_hours_per_day": round(hrs, 2),
            "gib_hr_per_day": round(billable * dps_billable_hours(hrs), 2),
        })
    # ---- VM Scale Sets (this is also where AKS node pools live) -------------------------
    vmss = az(["vmss", "list", "--subscription", sub], timeout=600) or []
    h.vmss_count = len(vmss)
    for ss in vmss:
        sku = ss.get("sku") or {}
        size, cap = sku.get("name"), int(sku.get("capacity") or 0)
        loc = ss["location"]
        if not size or cap <= 0:
            continue
        vm_size_memory(sub, loc, {size})
        raw = _SIZE_MEM_CACHE.get((loc, size))
        h.vmss_instances += cap
        h.by_size[size] = h.by_size.get(size, 0) + cap
        if raw is None:
            h.notes.append(f"unknown RAM for VMSS size {size} in {loc}")
            continue
        billable = dps_billable_host_gib(raw)
        # Scale-set instances are assumed running: capacity is the live instance count.
        h.running_mem_gib += raw * cap
        h.billable_mem_gib += billable * cap
        h.gib_hr_per_day_24x7 += billable * 24 * cap
        h.gib_hr_per_day_observed += billable * 24 * cap
        h.host_hr_per_day_observed += 24 * cap
        h.hosts.append({
            "kind": "vmss", "name": ss["name"], "location": loc, "size": size,
            "power_state": f"capacity={cap}", "ram_gib": raw * cap,
            "dps_billable_gib": billable * cap, "observed_hours_per_day": 24.0,
            "gib_hr_per_day": round(billable * 24 * cap, 2),
        })

    aks = az(["aks", "list", "--subscription", sub], timeout=300) or []
    h.aks_clusters = len(aks)
    for c in aks:
        for pool in (c.get("agentPoolProfiles") or []):
            h.aks_node_count += int(pool.get("count") or 0)

    # ---- App Service Plans -------------------------------------------------------------
    # Dynatrace monitors App Service via the site extension; the plan's SKU memory x
    # instance count is the Full-Stack-equivalent footprint.
    plans = az(["appservice", "plan", "list", "--subscription", sub], timeout=300) or []
    h.appservice_plans = len(plans)
    for p in plans:
        sku = (p.get("sku") or {})
        name = sku.get("name")
        cap = int(sku.get("capacity") or 0)
        sites = int(p.get("numberOfSites") or 0)
        h.appservice_sites += sites
        raw = appservice_sku_gib(name)
        if cap <= 0 or sites == 0:
            continue                      # an empty plan has nothing to instrument
        h.appservice_instances += cap
        if raw is None:
            h.notes.append(f"unknown RAM for App Service SKU {name}")
            continue
        billable = dps_billable_host_gib(raw)
        h.running_mem_gib += raw * cap
        h.billable_mem_gib += billable * cap
        h.gib_hr_per_day_24x7 += billable * 24 * cap
        h.gib_hr_per_day_observed += billable * 24 * cap
        h.host_hr_per_day_observed += 24 * cap
        h.hosts.append({
            "kind": "appservice-plan", "name": p["name"], "location": p.get("location", ""),
            "size": name, "power_state": f"instances={cap}, sites={sites}",
            "ram_gib": raw * cap, "dps_billable_gib": billable * cap,
            "observed_hours_per_day": 24.0, "gib_hr_per_day": round(billable * 24 * cap, 2),
        })
    return h


# --------------------------------------------------------------------------------------
# Logs: Log Analytics workspaces, Event Hubs, storage log sinks
# --------------------------------------------------------------------------------------

@dataclass
class AzureLogs:
    workspaces: int = 0
    workspaces_with_traffic: int = 0
    tables: int = 0
    active_tables: int = 0
    ingest_gib_per_day: float = 0.0
    billable_gib_per_day: float = 0.0
    by_workspace: dict = field(default_factory=dict)
    by_table: dict = field(default_factory=dict)
    eventhub_namespaces: int = 0
    eventhub_gib_per_day: float = 0.0
    storage_log_accounts: int = 0
    retention_days: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    access_denied: bool = False


def la_query(sub, workspace_guid, kusto, timeout=60):
    """Run a KQL query against a Log Analytics workspace via `az rest`.

    Deliberately uses `az rest` rather than `az monitor log-analytics query` so the tool
    needs no az extensions.

    KQL is full of '|' pipe characters. On Windows, az is az.cmd, a batch file, so our
    subprocess call is actually routed through cmd.exe -- and cmd.exe treats an unescaped
    '|' in a command-line argument as its OWN pipe operator, no matter how the argv list
    was quoted for CreateProcess. That silently mangles the query and makes the call hang
    waiting on a nonexistent second pipeline stage. Writing the JSON body to a temp file
    and passing --body @file keeps every KQL metacharacter out of the command line
    entirely, which sidesteps the problem on every platform.
    """
    body = json.dumps({"query": kusto})
    fd, path = tempfile.mkstemp(suffix=".json", prefix="dt_la_query_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        data = az(["rest", "--method", "post",
                   "--url", f"https://api.loganalytics.io/v1/workspaces/{workspace_guid}/query",
                   "--resource", "https://api.loganalytics.io",
                   "--subscription", sub,
                   "--headers", "Content-Type=application/json",
                   "--body", f"@{path}"], timeout=timeout)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    if not data or "tables" not in data or not data["tables"]:
        return []
    table = data["tables"][0]
    cols = [c["name"] for c in table["columns"]]
    return [dict(zip(cols, row)) for row in table["rows"]]


def collect_logs(sub, days, want_eventhub, want_storage):
    lg = AzureLogs()

    workspaces = az(["monitor", "log-analytics", "workspace", "list",
                     "--subscription", sub], timeout=300)
    if workspaces is None:
        lg.access_denied = True
        lg.notes.append("could not list Log Analytics workspaces")
        workspaces = []
    lg.workspaces = len(workspaces)

    # The Usage table is Azure's own billing meter for ingest: Quantity is in MB and
    # IsBillable marks what actually counts. This is the closest analogue to CloudWatch
    # Logs IncomingBytes and matches how Dynatrace measures log ingest (raw, pre-parse).
    kusto = (f"Usage | where TimeGenerated > ago({days}d) "
             f"| summarize TotalMB=sum(Quantity), "
             f"BillableMB=sumif(Quantity, IsBillable == true) by DataType "
             f"| order by TotalMB desc")
    for i, ws in enumerate(workspaces, start=1):
        guid = ws.get("customerId")
        name = ws.get("name", "?")
        if ws.get("retentionInDays") is not None:
            lg.retention_days[name] = ws["retentionInDays"]
        if not guid:
            continue
        log(f"    workspace {i}/{len(workspaces)}: {name}")
        rows = la_query(sub, guid, kusto)
        if not rows:
            lg.notes.append(f"workspace '{name}': no Usage data returned "
                            f"(empty, or no Log Analytics Reader permission)")
            continue
        ws_total = 0.0
        for r in rows:
            table_name = r.get("DataType", "?")
            gib = (r.get("TotalMB") or 0) / 1024.0 / days
            billable_gib = (r.get("BillableMB") or 0) / 1024.0 / days
            lg.tables += 1
            if gib > 0:
                lg.active_tables += 1
            if table_name in LA_NON_LOG_TABLES:
                continue          # Azure Monitor plumbing, not customer log content
            ws_total += gib
            lg.ingest_gib_per_day += gib
            lg.billable_gib_per_day += billable_gib
            lg.by_table[table_name] = lg.by_table.get(table_name, 0.0) + gib
        if ws_total > 0:
            lg.workspaces_with_traffic += 1
            lg.by_workspace[name] = ws_total
    return lg

    # ---- Event Hubs: the usual transport for Azure diagnostic logs to a third party -----
    if want_eventhub:
        ns = az(["eventhubs", "namespace", "list", "--subscription", sub], timeout=300) or []
        lg.eventhub_namespaces = len(ns)
        for n in ns:
            data = az(["monitor", "metrics", "list", "--resource", n["id"],
                       "--subscription", sub, "--metric", "IncomingBytes",
                       "--interval", "P1D", "--aggregation", "Total",
                       "--offset", f"{days}d"], timeout=120)
            try:
                pts = data["value"][0]["timeseries"][0]["data"]
                total = sum(p.get("total") or 0 for p in pts)
                lg.eventhub_gib_per_day += total / GIB / days
            except (KeyError, IndexError, TypeError):
                continue

    # ---- Storage accounts that look like diagnostic/log sinks --------------------------
    if want_storage:
        accts = az(["storage", "account", "list", "--subscription", sub], timeout=300) or []
        lg.storage_log_accounts = sum(
            1 for a in accts if any(hint in a["name"].lower() for hint in STORAGE_LOG_HINTS))
    return lg


# --------------------------------------------------------------------------------------
# Metrics: Azure Monitor time series
# --------------------------------------------------------------------------------------

@dataclass
class AzureMetrics:
    resources_total: int = 0
    resources_metricable: int = 0
    types_seen: int = 0
    types_excluded: int = 0
    definitions_per_type: dict = field(default_factory=dict)
    series_billable: int = 0
    dimensioned_metrics: int = 0
    by_type: dict = field(default_factory=dict)
    by_namespace: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    access_denied: bool = False


_DEF_CACHE: dict[str, list] = {}


def metric_definitions(sub, sample_resource_id, rtype):
    """Metric definitions for a resource type.

    Definitions are identical for every instance of a type, so one representative
    resource is enough -- this turns an O(resources) problem into O(types).
    """
    if rtype in _DEF_CACHE:
        return _DEF_CACHE[rtype]
    data = az(["monitor", "metrics", "list-definitions", "--resource", sample_resource_id,
               "--subscription", sub], timeout=120)
    defs = data if isinstance(data, list) else []
    _DEF_CACHE[rtype] = defs
    return defs


def collect_metrics(sub, dimension_factor, max_workers):
    m = AzureMetrics()
    resources = az(["resource", "list", "--subscription", sub], timeout=900)
    if resources is None:
        m.access_denied = True
        m.notes.append("could not list resources")
        return m
    m.resources_total = len(resources)

    by_type: dict[str, list] = {}
    for r in resources:
        by_type.setdefault(r["type"].lower(), []).append(r)
    m.types_seen = len(by_type)

    todo = []
    for rtype, items in by_type.items():
        if rtype in EXCLUDED_TYPES:
            m.types_excluded += 1
            continue
        todo.append((rtype, items))

    def resolve(pair):
        rtype, items = pair
        return rtype, items, metric_definitions(sub, items[0]["id"], rtype)

    with futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for rtype, items, defs in ex.map(resolve, todo):
            if not defs:
                continue
            n_defs = len(defs)
            dimensioned = sum(1 for d in defs if d.get("dimensions"))
            m.definitions_per_type[rtype] = n_defs
            m.dimensioned_metrics += dimensioned * len(items)
            series = int(round(n_defs * len(items) * dimension_factor))
            m.series_billable += series
            m.resources_metricable += len(items)
            m.by_type[rtype] = series
            ns = rtype.split("/")[0]
            m.by_namespace[ns] = m.by_namespace.get(ns, 0) + series
    m.by_type = dict(sorted(m.by_type.items(), key=lambda x: -x[1]))
    m.by_namespace = dict(sorted(m.by_namespace.items(), key=lambda x: -x[1]))
    return m


# --------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------

def build_summary(sub_id, sub_name, lg, mt, hs, args, auth_error=None):
    days, poll = args.days, args.poll_interval
    dp_per_series_per_day = SECONDS_PER_DAY / poll

    headline_gib_hr = (hs.gib_hr_per_day_24x7 if args.host_uptime == "assume-24x7"
                       else hs.gib_hr_per_day_observed)

    L = {
        "ingest_gib_per_day": lg.ingest_gib_per_day * args.log_overhead,
        "billable_gib_per_day": lg.billable_gib_per_day,
        "eventhub_gib_per_day": lg.eventhub_gib_per_day,
        "workspaces": lg.workspaces,
        "workspaces_with_traffic": lg.workspaces_with_traffic,
        "tables": lg.tables,
        "active_tables": lg.active_tables,
        "storage_log_accounts": lg.storage_log_accounts,
        "eventhub_namespaces": lg.eventhub_namespaces,
        "by_workspace": lg.by_workspace,
        "by_table": dict(sorted(lg.by_table.items(), key=lambda x: -x[1])),
        "retention_days": lg.retention_days,
    }
    L["ingest_gib_per_day_upper"] = (
        L["ingest_gib_per_day"] + (lg.eventhub_gib_per_day if args.count_eventhub else 0.0))

    M = {
        "resources_total": mt.resources_total,
        "resources_metricable": mt.resources_metricable,
        "types_seen": mt.types_seen,
        "types_excluded": mt.types_excluded,
        "series_billable": mt.series_billable,
        "dimensioned_metrics": mt.dimensioned_metrics,
        "dimension_factor": args.dimension_factor,
        "poll_interval_seconds": poll,
        "by_type": mt.by_type,
        "by_namespace": mt.by_namespace,
    }
    M["raw_dp_per_day"] = mt.series_billable * dp_per_series_per_day
    M["raw_dp_per_month"] = M["raw_dp_per_day"] * 30.44
    M["raw_dp_per_year"] = M["raw_dp_per_day"] * 365
    M["raw_dp_per_day_at_5min"] = mt.series_billable * (SECONDS_PER_DAY / 300)
    M.update(allowance_netting(M["raw_dp_per_day"], headline_gib_hr))

    H = {
        "vms_total": hs.vms_total, "vms_running": hs.vms_running, "vms_stopped": hs.vms_stopped,
        "vmss_count": hs.vmss_count, "vmss_instances": hs.vmss_instances,
        "aks_clusters": hs.aks_clusters, "aks_node_count": hs.aks_node_count,
        "appservice_plans": hs.appservice_plans,
        "appservice_instances": hs.appservice_instances,
        "appservice_sites": hs.appservice_sites,
        "running_ram_gib_raw": hs.running_mem_gib,
        "running_ram_gib_dps_billable": hs.billable_mem_gib,
        "gib_hr_per_day_observed": hs.gib_hr_per_day_observed,
        "gib_hr_per_day_24x7": hs.gib_hr_per_day_24x7,
        "host_hr_per_day_observed": hs.host_hr_per_day_observed,
        "gib_hr_per_day": headline_gib_hr,
        "host_equivalents_16gib": headline_gib_hr / HOST_EQUIV_GIB_HR,
        "by_size": dict(sorted(hs.by_size.items(), key=lambda x: -x[1])),
        "monitored_units": hs.vms_running + hs.vmss_instances + hs.appservice_instances,
    }

    sizing = size_dimensions(L["ingest_gib_per_day"], M["raw_dp_per_day"], H["gib_hr_per_day"])
    cost = indicative_cost(L["ingest_gib_per_day"], M["billable_dp_per_day_after_allowance"],
                           H["gib_hr_per_day"], H["host_hr_per_day_observed"], args.rates)

    coverage = {
        "auth_ok": auth_error is None,
        "auth_error": str(auth_error) if auth_error else None,
        "logs_readable": not lg.access_denied,
        "metrics_readable": not mt.access_denied,
        "partial": bool(auth_error or lg.access_denied or mt.access_denied),
    }

    verdict = dict(sizing)
    verdict["reasoning"] = [
        f"Logs: {L['ingest_gib_per_day']:.3f} GiB/day across "
        f"{L['workspaces_with_traffic']} active workspace(s) of {L['workspaces']} "
        f"-> {sizing['per_dimension']['logs']}",
        f"Metrics: {M['series_billable']:,} time series x "
        f"{SECONDS_PER_DAY // poll:,} polls/day = {M['raw_dp_per_day']:,.0f} data points/day "
        f"-> {sizing['per_dimension']['metrics']}",
        f"Hosts: {H['monitored_units']} monitored unit(s), {H['gib_hr_per_day']:,.0f} GiB-hr/day "
        f"(= {H['host_equivalents_16gib']:.1f} x 16 GiB hosts running 24x7) "
        f"-> {sizing['per_dimension']['hosts']}",
    ]
    verdict["judgement_calls"] = judgement_calls(L, M, H, coverage, lg, mt, hs)

    return {
        "provider": "azure", "account_id": sub_id, "account_name": sub_name,
        "window_days": days,
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "coverage": coverage, "logs": L, "metrics": M, "hosts": H,
        "indicative_cost_usd": cost, "verdict": verdict,
    }


def judgement_calls(L, M, H, coverage, lg, mt, hs):
    calls = []
    if not coverage["auth_ok"]:
        calls.append(
            "NOT SIZED -- the az CLI had no usable credentials for this subscription. "
            f"Azure said: {coverage['auth_error']}. Run 'az login' and re-run.")
        return calls
    if coverage["partial"]:
        calls.append(
            "COVERAGE IS PARTIAL -- some Azure APIs were unreadable with this identity "
            f"(logs readable: {coverage['logs_readable']}, "
            f"metrics readable: {coverage['metrics_readable']}). Treat every number as a floor.")
    if L["workspaces"] > 0 and L["workspaces_with_traffic"] == 0:
        calls.append(
            f"{L['workspaces']} Log Analytics workspace(s) exist but none returned Usage data. "
            "That usually means the identity lacks Log Analytics Reader, not that the "
            "workspaces are empty -- log sizing here is almost certainly understated.")
    if M["dimensioned_metrics"] > 0 and M["dimension_factor"] == 1.0:
        calls.append(
            f"{M['dimensioned_metrics']:,} of the counted metrics carry dimensions, which "
            "Azure splits into multiple time series. This count assumes one series per "
            "metric, so real data-point volume will be HIGHER -- re-run with "
            "--dimension-factor 2 or 3 to see a realistic range.")
    if H["appservice_instances"] > 0:
        calls.append(
            f"{H['appservice_plans']} App Service Plan(s) carrying {H['appservice_sites']} "
            f"site(s) across {H['appservice_instances']} instance(s) are sized from SKU "
            "memory. Dynatrace monitors App Service through the site extension rather than "
            "a host OneAgent -- confirm the deployment model before quoting these as hosts.")
    if H["aks_node_count"] > 0:
        calls.append(
            f"{H['aks_clusters']} AKS cluster(s) with {H['aks_node_count']} node(s). AKS nodes "
            "live in scale sets and are already counted in the VMSS figure -- they are not "
            "added twice, but Kubernetes-native monitoring is a separate SKU line.")
    if H["vms_stopped"] > H["vms_running"] and H["vms_total"] > 0:
        calls.append(
            f"{H['vms_stopped']} of {H['vms_total']} VMs are deallocated or stopped. Sizing "
            "counts only running compute; confirm the stopped fleet is genuinely idle.")
    if M["allowance_covers_pct"] >= 99.9 and M["raw_dp_per_day"] > 0:
        calls.append(
            "Every Azure Monitor data point is absorbed by the included Full-Stack metric "
            f"allowance ({M['included_dp_allowance_per_day']:,.0f} DP/day earned by the "
            "monitored hosts). Do not quote a separate custom-metrics line.")
    elif M["allowance_covers_pct"] > 0:
        calls.append(
            f"The Full-Stack host allowance absorbs {M['allowance_covers_pct']:.0f}% of Azure "
            f"Monitor data points; only {M['billable_dp_per_day_after_allowance']:,.0f} DP/day "
            "are actually billable.")
    if L["eventhub_gib_per_day"] > L["ingest_gib_per_day"] and L["eventhub_gib_per_day"] > 0:
        calls.append(
            f"Event Hub throughput ({L['eventhub_gib_per_day']:.2f} GiB/day) exceeds Log "
            "Analytics ingest. If diagnostic settings stream to Event Hub for Dynatrace, "
            "log sizing should be based on that path instead.")
    return calls


AZURE_ASSUMPTIONS = [
    "Log ingest is the Log Analytics 'Usage' table (Quantity in MB), Azure's own ingest "
    "meter and the closest analogue to raw pre-parse bytes. Usage/Heartbeat/Operation/"
    "AzureMetrics tables are excluded as Azure Monitor's own plumbing, not customer logs.",
    "Metric series are counted as (metric definitions for a resource type) x (resource "
    "count of that type). Definitions are identical across instances of a type, so one "
    "representative resource per type is queried.",
    "Metrics that carry dimensions are counted as ONE series each unless --dimension-factor "
    "is raised. Azure splits dimensioned metrics into a series per dimension value, so the "
    "default is a deliberate lower bound on metric volume.",
    "VM Scale Set capacity is treated as running instances, and AKS nodes are counted once "
    "via their scale sets rather than again from the cluster's node pools.",
    "App Service Plans are sized from a static SKU->RAM table and counted only when the "
    "plan actually hosts sites.",
    "Azure Monitor platform metrics have 1-minute granularity, so a 1/min polling "
    "assumption matches Azure's native resolution.",
]


# --------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------

def render_text(s, args, top=15):
    L, M, H, V, C = s["logs"], s["metrics"], s["hosts"], s["verdict"], s["indicative_cost_usd"]
    cov = s["coverage"]
    o = []
    o.append("=" * 72)
    o.append(f"  DYNATRACE SIZING -- AZURE SUBSCRIPTION {s['account_name']}")
    o.append(f"  {s['account_id']}")
    o.append(f"  {s['window_days']}-day window | generated {s['generated_utc']}")
    o.append("=" * 72)
    if not cov["auth_ok"]:
        o.append("")
        o.append("  !! NOT SIZED -- no usable az credentials for this subscription.")
        o.append(f"     {cov['auth_error']}")
        o.append("     Run:  az login")
        return "\n".join(o)
    if cov["partial"]:
        o.append("")
        o.append("  !! PARTIAL COVERAGE -- some Azure APIs were unreadable.")
        o.append("     The figures below are a FLOOR for this subscription, not a total.")

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
    o.append(f"       {L['ingest_gib_per_day']:>14,.4f}  GiB/day")
    o.append(f"       {L['ingest_gib_per_day'] * 30.44:>14,.2f}  GiB/month")
    o.append(f"       {L['ingest_gib_per_day'] * 365:>14,.2f}  GiB/year")
    o.append(f"       Azure-billable subset: {L['billable_gib_per_day']:,.4f} GiB/day")
    o.append(f"       upper bound incl. Event Hub: {L['ingest_gib_per_day_upper']:,.4f} GiB/day")
    o.append("")
    o.append(f"  2. Metrics -- Ingest (custom metric data points @ "
             f"{M['poll_interval_seconds']}s polling)")
    o.append(f"       {M['raw_dp_per_day']:>14,.0f}  raw data points/day")
    o.append(f"       {M['raw_dp_per_month']:>14,.0f}  raw data points/month")
    o.append(f"       {M['raw_dp_per_year']:>14,.0f}  raw data points/year")
    o.append(f"       from {M['series_billable']:,} time series "
             f"(dimension factor {M['dimension_factor']})")
    o.append(f"       included Full-Stack allowance: "
             f"{M['included_dp_allowance_per_day']:>,.0f} DP/day "
             f"(covers {M['allowance_covers_pct']:.1f}%)")
    o.append(f"       NET BILLABLE: {M['billable_dp_per_day_after_allowance']:,.0f} DP/day")
    o.append(f"       at 5-min polling instead: {M['raw_dp_per_day_at_5min']:,.0f} DP/day")
    o.append("")
    o.append("  3. Full-Stack Monitoring -- host memory")
    o.append(f"       {H['gib_hr_per_day']:>14,.2f}  GiB-hr/day  ({args.host_uptime})")
    o.append(f"       {H['gib_hr_per_day'] * 30.44:>14,.2f}  GiB-hr/month")
    o.append(f"       {H['gib_hr_per_day'] * 365:>14,.2f}  GiB-hr/year")
    o.append(f"       {H['monitored_units']} monitored unit(s): {H['vms_running']} VM(s), "
             f"{H['vmss_instances']} scale-set instance(s), "
             f"{H['appservice_instances']} App Service instance(s)")
    o.append(f"       {H['running_ram_gib_raw']:.1f} GiB raw RAM -> "
             f"{H['running_ram_gib_dps_billable']:.2f} GiB DPS-billable "
             f"(0.25 GiB round-up, 4 GiB floor)")
    o.append(f"       equivalent to {H['host_equivalents_16gib']:.2f} x 16 GiB hosts at 24x7")

    o.append(rule("LOGS -- detail"))
    o.append(f"  Log Analytics workspaces: {L['workspaces']}  "
             f"({L['workspaces_with_traffic']} with measured traffic)")
    o.append(f"  Tables seen:              {L['tables']}  ({L['active_tables']} with data)")
    o.append(f"  Event Hub namespaces:     {L['eventhub_namespaces']}  "
             f"({L['eventhub_gib_per_day']:,.4f} GiB/day)")
    o.append(f"  Storage accts looking like log sinks: {L['storage_log_accounts']}")
    if L["by_workspace"]:
        o.append("")
        o.append("  Ingest by workspace:")
        for n, v in sorted(L["by_workspace"].items(), key=lambda x: -x[1])[:top]:
            ret = L["retention_days"].get(n, "?")
            o.append(f"     {v:>10.4f} GiB/day  {n[:44]:44s} retention={ret}d")
    if L["by_table"]:
        o.append("")
        o.append(f"  Top {top} tables by ingest:")
        for n, v in list(L["by_table"].items())[:top]:
            o.append(f"     {v:>10.4f} GiB/day  {n[:56]}")
    o.append(rule("METRICS -- detail"))
    o.append(f"  Resources total:          {M['resources_total']:,}")
    o.append(f"  Resource types seen:      {M['types_seen']:,} "
             f"({M['types_excluded']:,} excluded as non-metric)")
    o.append(f"  Resources with metrics:   {M['resources_metricable']:,}")
    o.append(f"  Metrics carrying dimensions: {M['dimensioned_metrics']:,} "
             f"(counted as 1 series each)")
    o.append(f"  = TIME SERIES:            {M['series_billable']:,}")
    if M["by_namespace"]:
        o.append("")
        o.append(f"  Series by provider namespace (top {top}):")
        for ns, c in list(M["by_namespace"].items())[:top]:
            o.append(f"     {c:>8,}  {ns}")
    if M["by_type"]:
        o.append("")
        o.append(f"  Series by resource type (top {top}):")
        for t, c in list(M["by_type"].items())[:top]:
            o.append(f"     {c:>8,}  {t}")

    o.append(rule("HOSTS -- detail"))
    o.append(f"  VMs:               {H['vms_total']:,} total | {H['vms_running']:,} running | "
             f"{H['vms_stopped']:,} stopped/deallocated")
    o.append(f"  VM Scale Sets:     {H['vmss_count']:,} ({H['vmss_instances']:,} instances)")
    o.append(f"  AKS:               {H['aks_clusters']:,} cluster(s), "
             f"{H['aks_node_count']:,} node(s) -- counted via scale sets, not added twice")
    o.append(f"  App Service Plans: {H['appservice_plans']:,} "
             f"({H['appservice_instances']:,} instances, {H['appservice_sites']:,} sites)")
    o.append(f"  GiB-hr/day observed: {H['gib_hr_per_day_observed']:,.2f}   "
             f"if 24x7: {H['gib_hr_per_day_24x7']:,.2f}")
    o.append(f"  Host-hr/day (Infrastructure Monitoring alternative): "
             f"{H['host_hr_per_day_observed']:,.2f}")
    if H["by_size"]:
        o.append("")
        o.append("  Sizes:")
        for t, c in list(H["by_size"].items())[:top]:
            o.append(f"     {c:>4} x {t}")

    o.append(rule("JUDGEMENT CALLS"))
    if V["judgement_calls"]:
        for c in V["judgement_calls"]:
            wrap_into(o, c)
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

    o.append(rule("ASSUMPTIONS"))
    for a in AZURE_ASSUMPTIONS + SHARED_ASSUMPTIONS:
        wrap_into(o, "* " + a)
    o.append("")
    return "\n".join(o)


def size_subscription(sub_id, sub_name, args):
    """Collect everything for one subscription and return the summary dict."""
    end = dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = end - dt.timedelta(days=args.days)
    s_iso, e_iso = start.strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        if az(["account", "show", "--subscription", sub_id], timeout=90) is None:
            raise AzureAuthError("could not read subscription (not found, or no access)")
        log(f"  {sub_name}: hosts...")
        hs = collect_hosts(sub_id, s_iso, e_iso, args.days,
                           args.host_uptime == "observed" and not args.no_uptime,
                           args.max_workers)
        log(f"  {sub_name}: logs...")
        lg = collect_logs(sub_id, args.days, not args.no_eventhub, not args.no_storage)
        log(f"  {sub_name}: metrics...")
        mt = collect_metrics(sub_id, args.dimension_factor, args.max_workers)
        return build_summary(sub_id, sub_name, lg, mt, hs, args)
    except AzureAuthError as e:
        log(f"  {sub_name}: AUTH FAILED -- {e}")
        return build_summary(sub_id, sub_name, AzureLogs(), AzureMetrics(), AzureHosts(),
                             args, auth_error=e)


def list_subscriptions():
    """Every subscription the current az login can see."""
    data = az(["account", "list", "--all"], timeout=120) or []
    return [(s["id"], s.get("name", "?"), s.get("state", "?")) for s in data]


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="dt_azure_sizing.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Size an Azure subscription for Dynatrace DPS using the az CLI.",
        epilog=textwrap.dedent("""\
            examples:
              python dt_azure_sizing.py --all-subscriptions
              python dt_azure_sizing.py --subscription 7a91e8b3-ee09-4906-91a2-f357b77a61fd
              python dt_azure_sizing.py --all-subscriptions --dimension-factor 3 --json az.json
        """))
    p.add_argument("--subscription", action="append", metavar="ID",
                   help="subscription ID (repeatable)")
    p.add_argument("--all-subscriptions", action="store_true",
                   help="size every subscription visible to the current az login")
    p.add_argument("--days", type=int, default=14, help="observation window (default: 14)")
    p.add_argument("--poll-interval", type=int, default=60, metavar="SECONDS",
                   help="assumed metric polling interval (default: 60)")
    p.add_argument("--dimension-factor", type=float, default=1.0,
                   help="multiplier for dimensioned metrics splitting into several series "
                        "(default: 1.0 = lower bound)")
    p.add_argument("--host-uptime", choices=["observed", "assume-24x7"], default="observed")
    p.add_argument("--no-uptime", action="store_true",
                   help="skip per-VM uptime metric calls (much faster, assumes 24x7 running)")
    p.add_argument("--no-eventhub", action="store_true", help="skip Event Hub throughput")
    p.add_argument("--no-storage", action="store_true", help="skip storage log-sink detection")
    p.add_argument("--count-eventhub", action="store_true",
                   help="add Event Hub throughput to the headline log figure")
    p.add_argument("--log-overhead", type=float, default=1.0)
    p.add_argument("--max-workers", type=int, default=8)
    p.add_argument("--top", type=int, default=15)
    p.add_argument("--json", metavar="PATH")
    p.add_argument("--quiet", action="store_true")
    a = p.parse_args(argv)
    a.rates = {}
    if not a.subscription and not a.all_subscriptions:
        p.error("pass --subscription ID or --all-subscriptions")
    return a


def main(argv=None):
    global _VERBOSE
    args = parse_args(argv)
    _VERBOSE = not args.quiet

    if args.all_subscriptions:
        subs = [(i, n) for i, n, st in list_subscriptions() if st == "Enabled"]
        if not subs:
            sys.exit("no enabled subscriptions visible -- run 'az login' first")
    else:
        known = {i: n for i, n, _ in list_subscriptions()}
        subs = [(i, known.get(i, i)) for i in args.subscription]

    log(f"sizing {len(subs)} subscription(s)")
    results = []
    for sub_id, sub_name in subs:
        log(f"[{sub_name}] {sub_id}")
        r = size_subscription(sub_id, sub_name, args)
        results.append(r)
        print(render_text(r, args, args.top))
        print()

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, default=str)
        log(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
