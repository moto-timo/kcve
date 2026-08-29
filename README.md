# kcve

A per-dot-release CVE ledger for Linux stable branches. One self-contained HTML
file: no server, no CDN, no JavaScript dependencies.

The kernel.org CNA is the only source that records **which stable release fixed a
given CVE**, so that is the spine of the data. Everything else is enrichment layered
on top.

## What it answers

Most CVE tools answer "is version X affected?". kcve answers two questions that are
harder to get at:

- **Where did each fix land?** Every CVE, bucketed into the exact dot release that
  carries its fix, per branch — the release train view.
- **What has *not* landed?** The backport gap: CVEs whose fix exists upstream but has
  never been backported to your branch. The CNA does not record this; see
  [Inferred, not stated](#inferred-not-stated).

## Quick start

Requires Python 3.8+ (tested through 3.14) and `git`. No third-party packages.

```bash
./kcve.py build                  # clone/refresh vulns.git, write kcve.html
```

First run clones the kernel CNA repository (~70 MB over the wire, ~480 MB on disk)
into `~/.cache/kcve/vulns`. Later runs update it in place.

```bash
./kcve.py demo                   # sample data, to look at the UI offline
```

## Commands

| Command | What it does |
|---|---|
| `build` | Write the dashboard to `--out` (default `kcve.html`) |
| `outstanding` | Print the backport gap as a table, worst first |
| `demo` | Build the UI from fictional sample records |
| `dump CVE-2026-12345` | Show how one record was parsed |

Useful flags: `--branches 6.18,7.2`, `--out`, `--no-sync` (use the existing checkout
as-is), `--nvd` (see below).

### The backport gap, without a browser

```bash
./kcve.py outstanding --branches 6.18
```

```
  CVE              BRANCH CVSS   EPSS MAINLINE SUBSYSTEM   TITLE
  CVE-2026-72493   6.18    9.9   0.3% 7.2      net/core    net: serialize netif_running() check ...
  CVE-2026-72200   6.18    9.8   0.6% 7.2      fs/ntfs     ntfs: detect mapping-pairs LCN accum ...
```

`MAINLINE` is the release carrying the fix, i.e. what to backport from. A leading `!`
marks a CVE in CISA's known-exploited catalogue. Rows go to stdout and the summary to
stderr, so the output pipes cleanly:

```bash
./kcve.py outstanding 2>/dev/null | awk '$3 >= 9.0'
```

In the dashboard, the same list is behind the outstanding count in each branch
header — click it to filter, then Export CSV.

## Where the data comes from

| | vulns.git | EPSS | CISA KEV | NVD |
|---|---|---|---|---|
| fixed-in release, introduced, mainline, files, commits | ✅ | | | |
| CVSS **high/critical** | ✅ | | | |
| CVSS **medium/low**, CWE | | | | ✅ |
| exploit probability | | ✅ | | |
| known exploited in the wild | | | ✅ | |
| cost | one shallow clone | one 2.5 MB file | one JSON file | one request *per CVE* |

EPSS and KEV are one bulk file each, take about four seconds combined, and need no
API key — so they run on every build rather than hiding behind a flag. Failures
degrade to empty columns.

`--nvd` is opt-in because it is slow: one request per CVE, so roughly 9 hours for a
full branch pair, or about 1 hour with `NVD_API_KEY` set. Its value is the scores the
CNA never publishes.

## Two things to read carefully

### Unscored is not low

The kernel CNA scores only **high and critical**. In a representative build, 2,268
scored records broke down as 1,841 high + 427 critical and **zero** medium or low.
So a blank CVSS column means *nobody has scored it*, not *it is minor*. `--nvd` is
what fills that in.

### Inferred, not stated

The CNA records where a fix **landed**, never where one is **missing**. There is no
"not backported" field to read — a status of `affected` with an open-ended range
appears **0 times in 60,686** version entries. So the backport gap is reconstructed:
a branch is outstanding when it predates the mainline fix, is new enough to contain
the buggy code, and has no release of its own carrying the fix.

That inference assumes a flaw reaches every branch after the one it was introduced
in. It is wrong for a bug confined to a single stable tree, which would need commit
archaeology to catch. Treat the list as a strong lead, not a verdict.

Bootlin's [sbom-cve-check](https://github.com/bootlin/sbom-cve-check) derives the
same thing independently, from the same CNA ranges, and reaches the same conclusions
— useful corroboration. It answers a different question (per-SBOM-component VEX
output rather than a per-branch ledger) and is worth a look if you need per-build
answers or SPDX export.

## Publishing

`.github/workflows/pages.yml` builds and deploys to GitHub Pages. Set
Settings → Pages → Source to **GitHub Actions**.

It runs two schedules: a daily rebuild, and an hourly one gated on `git ls-remote`
so it only pays for a clone when vulns.git has actually moved. The daily run is
deliberately ungated — EPSS is regenerated every day, so gating everything on
vulns.git would leave the risk columns stale while the page looked fresh.

The build output is **not** committed. It is ~8 MB (2.9 MB gzipped) and regenerates
on every run; Pages serves it from the workflow artifact instead.

## Tests

```bash
./test_kcve.py
```

Covers version parsing and the backport inference — the parts that can silently
produce a confidently wrong answer.
