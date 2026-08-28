# Cloud -> Dynatrace DPS sizing

Sizes AWS accounts and Azure subscriptions for Dynatrace Platform Subscription (DPS) SKUs,
converting what each cloud can tell you into the three units Dynatrace bills in:

| # | Dynatrace SKU | Unit | AWS source | Azure source |
|---|---|---|---|---|
| 1 | Log Management - Ingest & Process | **GiB/day** | CloudWatch Logs `IncomingBytes` | Log Analytics `Usage` table |
| 2 | Metrics - Ingest (custom metric data points) | **data points/day** | CloudWatch time series | Azure Monitor time series |
| 3 | Full-Stack Monitoring | **GiB-hr/day** | EC2 RAM x running hours | VM / VMSS / App Service Plan RAM x running hours |

Every script is **read-only** and finishes with an opinionated t-shirt size (XS-XXL) plus a
list of judgement calls -- things like "97 of 184 VMs are stopped" or "every metric data
point is already covered by the included Full-Stack allowance."

## Quick start

```bash
pip install boto3          # AWS only; Azure uses the az CLI directly
az login                   # Azure only, if you have Azure accounts to size
```

Fill in `accounts.csv` with your accounts (or copy it to your own file):

```csv
provider,account_id,name,enabled
aws,111111111111,Example AWS account,true
azure,00000000-0000-0000-0000-000000000000,Example Azure subscription,true
```

Then run the portfolio sizer, which sizes every enabled row and prints a roll-up:

```bash
python dt_cloud_sizing.py --accounts accounts.csv
```

Sanity-check the CSV without touching any cloud API first:

```bash
python dt_cloud_sizing.py --accounts accounts.csv --validate-only
```

Useful variants:

```bash
python dt_cloud_sizing.py --accounts accounts.csv --fast              # skip the slow extras
python dt_cloud_sizing.py --accounts accounts.csv --json portfolio.json
python dt_cloud_sizing.py --accounts accounts.csv --per-account-detail  # full report per account too
```

Each provider also runs standalone against a single account, with more provider-specific
flags (see the methodology sections below):

```bash
python dt_aws_sizing.py --creds-file aws-creds.txt
python dt_azure_sizing.py --subscription 00000000-0000-0000-0000-000000000000
```

## Files

| File | Purpose |
|---|---|
| `dt_cloud_sizing.py` | **Main entry point.** Reads a CSV of accounts, sizes each, prints a portfolio roll-up |
| `dt_aws_sizing.py` | AWS collectors + standalone per-account report |
| `dt_azure_sizing.py` | Azure collectors (via the `az` CLI) + standalone per-subscription report |
| `dt_sizing_common.py` | DPS units, rounding rules, allowance netting, t-shirt bands -- shared by both |
| `accounts.csv` | Template account list (safe to commit -- example IDs only) |
| `accounts.local.csv` | Your real account list -- gitignored, never committed |
| `test_azure_logic.py` | Offline checks for the Azure math and rendering (no cloud calls) |

## The account CSV

```csv
provider,account_id,name,enabled
aws,111111111111,Example AWS account,true
azure,00000000-0000-0000-0000-000000000000,Example Azure subscription,true
```

- `provider` - `aws` or `azure`
- `account_id` - **AWS: exactly 12 digits. Azure: a subscription UUID (8-4-4-4-12 hex).**
  Anything else is rejected by line number with a reason, and the run continues.
- `name` - optional label for the report
- `enabled` - set `false` to skip a row without deleting it

Column names are flexible (`cloud`/`platform` for provider, `subscription_id`/`uuid` for
account_id). Blank lines and `#` comments are ignored, and duplicates are sized once.

## Credentials

**AWS** - a standard shared-credentials file (default `aws-creds.txt`, gitignored), `--profile`,
or the ambient environment. The driver verifies the credentials actually belong to the
account ID in the CSV and refuses to size the wrong account.

**Azure** - whatever `az login` has cached. No az extensions are required: the Log Analytics
query goes through `az rest` rather than the `log-analytics` extension, so a bare `az` install
is enough.

Expired credentials are reported per account as `NOT SIZED`, never as zero. If nothing is
readable the portfolio verdict is `NO DATA` rather than `XS`.

## AWS methodology

### Logs -> GiB/day

Dynatrace bills log ingest on **raw, uncompressed bytes before enrichment and
transformation**. CloudWatch Logs' `IncomingBytes` metric is measured on exactly that basis,
so it is used directly rather than the compressed `storedBytes` figure.

Per-log-group `IncomingBytes` is summed over the window via `GetMetricData` and divided by
the window length. Log groups that hold stored data but emit no `IncomingBytes` metric are
estimated from `storedBytes / retentionInDays` (90 days assumed where retention is
never-expire). That fallback is **low confidence** -- it is reported as a separate line and
can be turned off with `--no-storedbytes-fallback`.

Firehose `IncomingBytes` and the daily growth of log-looking S3 buckets are collected too,
but kept out of the headline number because they usually *re-carry* logs already counted in
CloudWatch Logs. They appear in the "upper bound" figure instead.

### Metrics -> data points/day

Counting every series `ListMetrics` returns badly overstates the answer. Two filters are
applied:

1. **Liveness.** `RecentlyActive=PT3H` restricts to series that reported in the last three
   hours.
2. **Ingestibility.** AWS account-meta namespaces (`AWS/Usage`, `AWS/TrustedAdvisor`,
   `AWS/Billing`, `AWS/Config`, `AWS/ServiceQuotas`, `AWS/Health`, `AWS/CloudWatch`) are not
   ingested by the Dynatrace AWS integration and are dropped, as are CloudWatch *rollup*
   series (e.g. `AWS/EC2` aggregated by `InstanceType` rather than `InstanceId`) which would
   double count per-entity metrics.

`--metric-scope` controls how aggressive this is: `dt-default` (Dynatrace's default AWS
service set plus any custom namespaces), `dt-supported` (everything ingestible), or `all`
(no filtering at all -- the naive count, for comparison).

Data points/day = billable series x `86400 / --poll-interval`. The default is 60s because
that is the requested assumption; **Dynatrace's AWS integration actually polls CloudWatch
every 5 minutes by default**, so the headline figure is a deliberate 5x-conservative upper
bound. The 5-minute number is printed alongside it.

The script also nets off the **included allowance**: Full-Stack hosts earn 900 custom metric
data points per charged GiB per 15-minute interval, and unused allowance does not carry
over, so the comparison is done per interval rather than per day. On host-heavy accounts
this frequently absorbs all CloudWatch volume -- quoting CloudWatch data points at full
rate without this deduction significantly overstates cost.

### Hosts -> GiB-hr/day

Instance RAM comes from `DescribeInstanceTypes`. DPS Full-Stack rules are then applied:

- RAM rounded **up to the next multiple of 0.25 GiB**
- a **4 GiB per-host minimum** (a 1 GiB `t2.micro` bills as 4 GiB)
- monitored time rounded **up to whole 15-minute intervals**
- **no upper cap** -- the 16 GiB cap belongs to the legacy host-unit model, not DPS

Running hours are measured, not assumed: an EC2 instance only emits `CPUUtilization` while
it is running, so the count of hourly buckets containing a datapoint over the window is a
direct measure of uptime. `--host-uptime assume-24x7` switches to nameplate capacity
instead, and `--include-stopped-hosts` adds the stopped fleet to that projection.

Fargate tasks, Lambda functions and RDS instances are counted for context but deliberately
**not** sized: they have no host to put OneAgent on and bill under different SKUs.

## Azure methodology

### Logs -> GiB/day

The Log Analytics **`Usage` table** is Azure's own ingest meter (`Quantity` in MB, with an
`IsBillable` flag), which is the closest analogue to raw pre-parse bytes and matches how
Dynatrace measures log ingest. The query runs through `az rest` against
`api.loganalytics.io`.

The KQL query body is written to a temp file and passed as `--body @file` rather than on
the command line. KQL is full of `|` characters, and on Windows `az` is a batch file --
invoking it routes through `cmd.exe`, which treats an unescaped `|` in an argument as its
*own* pipe operator no matter how the argument was quoted, silently mangling the query.
Keeping the query text out of the command line entirely sidesteps this on every platform.

`Usage`, `Heartbeat`, `Operation` and `AzureMetrics` are excluded -- they are Azure Monitor's
own plumbing, not customer log content. Event Hub `IncomingBytes` and log-looking storage
accounts are collected separately as an upper bound, since diagnostic settings streaming to
Event Hub are the usual path for getting Azure logs into Dynatrace.

### Metrics -> data points/day

Azure metric definitions are identical for every instance of a resource type, so the script
asks Azure for definitions **once per type** using one representative resource, then
multiplies by the number of resources of that type. That turns an O(resources) problem into
O(types).

**This is a deliberate lower bound.** Metrics that carry dimensions get split by Azure into
one series per dimension value, and the script counts them as a single series. It reports
how many dimensioned metrics it saw and offers `--azure-dimension-factor` to model the
spread:

```bash
python dt_cloud_sizing.py --accounts accounts.csv --azure-dimension-factor 3
```

Azure Monitor platform metrics are natively 1-minute, so a 1/min polling assumption matches
Azure's real resolution -- unlike AWS, where Dynatrace polls every 5 minutes by default.

### Hosts -> GiB-hr/day

Three kinds of compute are summed, all through the same DPS rules (0.25 GiB round-up,
4 GiB floor, 15-minute intervals):

- **Virtual machines** -- RAM from `az vm list-sizes` per location; running hours measured
  from hourly `Percentage CPU` coverage, the same trick used for EC2.
- **VM Scale Sets** -- `sku.capacity` instances at the scale set's size. AKS node pools live
  in scale sets, so AKS nodes are counted here and deliberately **not** added again from
  `az aks list`.
- **App Service Plans** -- SKU memory from a static table x instance count, counted only when
  the plan actually hosts sites. Dynatrace instruments App Service through the site
  extension rather than a host OneAgent, so the report flags these for confirmation.

### Windows subprocess notes

`az` calls run through `Popen` with a hard timeout. If a call hangs, the whole process tree
is killed with `taskkill /F /T` rather than relying on `Popen.kill()`, which on Windows only
kills the immediate `cmd.exe` wrapper around `az.cmd` and leaves the actual Azure CLI process
(and its open pipes) running forever.

## How the t-shirt size is decided

Each dimension is banded independently:

| Band | Logs (GiB/day) | Metrics (DP/day) | Hosts (GiB-hr/day) |
|---|---|---|---|
| XS | < 1 | < 1M | < 1,920 (~5 x 16 GiB hosts) |
| S | < 10 | < 10M | < 9,600 (~25 hosts) |
| M | < 100 | < 100M | < 38,400 (~100 hosts) |
| L | < 500 | < 500M | < 153,600 (~400 hosts) |
| XL | < 2,000 | < 2B | < 576,000 (~1,500 hosts) |
| XXL | above | above | above |

The overall size is the **median** of the three, pulled up one step if any single dimension
sits two or more bands above that median -- one runaway dimension still drives the deal.
The report also names the *shape* (balanced / leaning / lopsided) and the dominant dimension.

## Unit definitions and prices

Unit-of-measure rules are from docs.dynatrace.com:

- [Full-Stack Monitoring consumption](https://docs.dynatrace.com/docs/license/capabilities/app-infra-observability/full-stack-monitoring) -- GiB-hour, 0.25 GiB rounding, 4 GiB minimum, 15-minute intervals, 900 DP/GiB/interval allowance
- [Infrastructure Monitoring](https://docs.dynatrace.com/docs/license/capabilities/host-monitoring/infrastructure-monitoring) -- host-hour, 1,500 DP/host/interval allowance
- [Log ingest](https://docs.dynatrace.com/docs/license/capabilities/log-management/dps-log-ingest) -- GiB, raw and uncompressed, pre-enrichment
- [Metrics ingest](https://docs.dynatrace.com/docs/license/capabilities/metrics/dps-metrics-ingest) -- data points; CloudWatch metrics bill as custom metric data points; histograms weigh 10
- [AWS CloudWatch metric polling](https://docs.dynatrace.com/docs/ingest-from/amazon-web-services/ingest-telemetry/aws-cloudwatch-metrics) -- 5-minute default interval

**Dynatrace does not publish list prices in its docs** -- the rate card is contractual. The
defaults in `LIST_PRICES` come from the public [pricing page](https://www.dynatrace.com/pricing/)
($0.20/GiB log ingest, $0.15/100k data points, $0.01/GiB-hr Full-Stack, $0.04/host-hr
Infrastructure) and exist only as a reference point. Override them with `--rate-*` (AWS) for
a real quote. The cost section is explicitly labelled indicative.

## Known limits

- One credential set at a time per provider. The AWS driver checks the credentials match the
  CSV's account ID and refuses to size the wrong account; for many AWS accounts, assume a role
  per account and re-run.
- Azure metric counts are a lower bound while `--azure-dimension-factor` is 1.0 (the default).
- `RecentlyActive=PT3H` misses AWS series that report less often than every three hours.
- The S3 log-bucket estimate infers write rate from `BucketSizeBytes` day-over-day growth, so
  buckets with lifecycle expiry are understated. It matches on bucket-name hints only.
- Log stream counts are capped at `--stream-group-cap` groups (default 400) to bound runtime.
- Nothing here predicts *application* telemetry -- traces, spans, RUM and Kubernetes-native
  monitoring are separate SKUs this script does not attempt to size.
