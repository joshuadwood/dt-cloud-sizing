"""Offline checks for the Azure sizing math and rendering (no Azure calls)."""
import argparse
import dt_azure_sizing as az
from dt_sizing_common import dps_billable_host_gib

# --- SKU table -------------------------------------------------------------------------
assert az.appservice_sku_gib("P1v3") == 8.0, "SKU lookup must be case-insensitive"
assert az.appservice_sku_gib("P1V3") == 8.0
assert az.appservice_sku_gib("b1") == 1.75
assert az.appservice_sku_gib("NOPE") is None

# --- DPS host rules --------------------------------------------------------------------
assert dps_billable_host_gib(1.75) == 4.0, "B1 (1.75 GiB) must hit the 4 GiB floor"
assert dps_billable_host_gib(8.0) == 8.0
assert dps_billable_host_gib(8.1) == 8.25, "must round up to the next 0.25 GiB"

# --- Synthetic subscription ------------------------------------------------------------
hosts = az.AzureHosts()
# 2 running D2s_v3 (8 GiB), 1 stopped
for i in range(2):
    b = dps_billable_host_gib(8.0)
    hosts.vms_total += 1; hosts.vms_running += 1
    hosts.running_mem_gib += 8.0; hosts.billable_mem_gib += b
    hosts.gib_hr_per_day_24x7 += b * 24
    hosts.gib_hr_per_day_observed += b * 24
    hosts.host_hr_per_day_observed += 24
hosts.vms_total += 1; hosts.vms_stopped += 1
# a 3-instance VMSS of 16 GiB nodes (AKS)
b = dps_billable_host_gib(16.0)
hosts.vmss_count, hosts.vmss_instances = 1, 3
hosts.running_mem_gib += 16.0 * 3; hosts.billable_mem_gib += b * 3
hosts.gib_hr_per_day_24x7 += b * 24 * 3
hosts.gib_hr_per_day_observed += b * 24 * 3
hosts.host_hr_per_day_observed += 24 * 3
hosts.aks_clusters, hosts.aks_node_count = 1, 3
# one P1v3 App Service Plan, 2 instances, 4 sites
b = dps_billable_host_gib(8.0)
hosts.appservice_plans, hosts.appservice_instances, hosts.appservice_sites = 1, 2, 4
hosts.running_mem_gib += 8.0 * 2; hosts.billable_mem_gib += b * 2
hosts.gib_hr_per_day_24x7 += b * 24 * 2
hosts.gib_hr_per_day_observed += b * 24 * 2
hosts.host_hr_per_day_observed += 24 * 2

logs = az.AzureLogs()
logs.workspaces, logs.workspaces_with_traffic = 2, 1
logs.ingest_gib_per_day = 12.5
logs.billable_gib_per_day = 11.0
logs.by_workspace = {"prod-law": 12.5}
logs.by_table = {"ContainerLog": 9.0, "AzureDiagnostics": 3.5}
logs.tables, logs.active_tables = 12, 8

mets = az.AzureMetrics()
mets.resources_total, mets.resources_metricable = 400, 210
mets.series_billable = 5200
mets.dimensioned_metrics = 900
mets.by_namespace = {"microsoft.compute": 3000, "microsoft.web": 2200}
mets.by_type = {"microsoft.compute/virtualmachines": 3000, "microsoft.web/sites": 2200}

args = argparse.Namespace(days=14, poll_interval=60, dimension_factor=1.0,
                          host_uptime="observed", log_overhead=1.0,
                          count_eventhub=False, rates={})
s = az.build_summary("00000000-0000-0000-0000-000000000000", "synthetic", logs, mets, hosts, args)

H, M, L = s["hosts"], s["metrics"], s["logs"]
expected_gib_hr = (8 * 24 * 2) + (16 * 24 * 3) + (8 * 24 * 2)   # 384 + 1152 + 384
assert H["gib_hr_per_day"] == expected_gib_hr, (H["gib_hr_per_day"], expected_gib_hr)
assert H["monitored_units"] == 2 + 3 + 2
assert M["raw_dp_per_day"] == 5200 * 1440
assert M["included_dp_allowance_per_day"] == expected_gib_hr * 4 * 900
assert L["ingest_gib_per_day"] == 12.5
print(f"gib_hr/day        = {H['gib_hr_per_day']:,}  (expected {expected_gib_hr:,})")
print(f"raw DP/day        = {M['raw_dp_per_day']:,.0f}")
print(f"allowance DP/day  = {M['included_dp_allowance_per_day']:,.0f}")
print(f"net billable DP/d = {M['billable_dp_per_day_after_allowance']:,.0f} "
      f"({M['allowance_covers_pct']:.1f}% covered)")
print(f"verdict           = {s['verdict']['overall']} ({s['verdict']['shape']})")

report = az.render_text(s, args)
assert "DYNATRACE SIZING -- AZURE SUBSCRIPTION synthetic" in report
assert "App Service Plan" in report
for section in ("VERDICT", "SKU SIZING", "LOGS -- detail", "METRICS -- detail",
                "HOSTS -- detail", "JUDGEMENT CALLS", "ASSUMPTIONS"):
    assert section in report, f"missing section: {section}"
print(f"report rendered   = {len(report.splitlines())} lines, all sections present")
print("\nALL AZURE LOGIC TESTS PASSED")
