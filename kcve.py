#!/usr/bin/env python3
"""
kcve - per-dot-release CVE ledger for Linux stable branches.

Spine of the data is the kernel.org CNA's own repository (vulns.git), because it
is the only source that records *which stable release fixed a given CVE*. It also
carries its own CVSS, but only for high/critical, so every build tops that up with
EPSS (FIRST) and the known-exploited catalogue (CISA) - one bulk file each. NVD is
opt-in and slow; its value is the medium/low scores the CNA never publishes.

  ./kcve.py build --branches 6.18,7.2
  ./kcve.py outstanding --branches 6.18  # backport gap, worst first, no browser
  ./kcve.py demo                       # sample data, to look at the UI offline
  ./kcve.py dump CVE-2026-12345        # show how one record was parsed

Stdlib only. Output is a single self-contained HTML file: no server, no CDN.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict

VULNS_GIT = "https://git.kernel.org/pub/scm/linux/security/vulns.git"
# kernel.org throttles clones; Google carries a full mirror of the same tree.
VULNS_MIRROR = "https://kernel.googlesource.com/pub/scm/linux/security/vulns"
# One file each, covering every CVE - cheaper and better covered than any per-CVE API.
EPSS_DUMP = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "kcve/1.0 (+kernel stable branch CVE ledger)"

DOT_RELEASE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
KERNEL_COMMIT = re.compile(r"git\.kernel\.org/stable/c/([0-9a-f]{8,40})")


# --------------------------------------------------------------------------- #
# fetch
# --------------------------------------------------------------------------- #

def sync_vulns(repo: pathlib.Path) -> None:
    """Shallow-clone or update the kernel CNA repository."""
    if (repo / ".git").exists():
        log(f"updating {repo}")
        if run(["git", "-C", str(repo), "fetch", "--depth", "1", "origin", "HEAD"]):
            run(["git", "-C", str(repo), "reset", "--hard", "FETCH_HEAD"], fatal=True)
            return
        log("fetch failed; leaving the existing checkout in place")
        return

    repo.parent.mkdir(parents=True, exist_ok=True)
    for url in (VULNS_GIT, VULNS_MIRROR):
        log(f"cloning {url} -> {repo} (shallow)")
        if run(["git", "clone", "--depth", "1", url, str(repo)]):
            return
        log("clone failed, trying the next source")
    sys.exit("could not clone vulns.git from either kernel.org or the mirror")


def run(cmd: list[str], fatal: bool = False) -> bool:
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL)
    if proc.returncode and fatal:
        sys.exit(f"command failed: {' '.join(cmd)}")
    return proc.returncode == 0


# --------------------------------------------------------------------------- #
# parse
# --------------------------------------------------------------------------- #

def branch_of(release: str) -> str | None:
    """'6.18.7' -> '6.18'. Mainline tags ('7.3', '6.19-rc1') are not dot releases."""
    m = DOT_RELEASE.match(release)
    return f"{m.group(1)}.{m.group(2)}" if m else None


def branch_tuple(version: str | None) -> tuple[int, int] | None:
    """'6.18.7' / '6.18' / '7.0' -> (6, 18) / (6, 18) / (7, 0)."""
    m = re.match(r"(\d+)\.(\d+)", version or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def outstanding_on(rec: dict, branch: str) -> bool:
    """True when `branch` carries the flaw but no backport has landed.

    The CNA never states this directly - it records where a fix *did* land, not
    where one is missing - so it has to be inferred: the branch predates the
    mainline fix, is new enough to contain the buggy code, and has no release of
    its own in `fixed`.
    """
    b = branch_tuple(branch)
    mainline = branch_tuple(rec.get("mainline"))
    if not b or not mainline or branch in rec["fixed"]:
        return False
    introduced = branch_tuple(rec.get("introduced"))
    # ponytail: assumes the flaw reaches every branch after `introduced`. Untrue
    # for a bug confined to one stable tree; catching those needs commit archaeology.
    return b < mainline and (introduced is None or introduced <= b)


def parse_record(doc: dict) -> dict | None:
    """Flatten one CVE JSON 5.x record from the kernel CNA."""
    meta = doc.get("cveMetadata", {})
    cve = meta.get("cveId")
    if not cve or meta.get("state") == "REJECTED":
        return None
    cna = doc.get("containers", {}).get("cna", {})

    fixed: dict[str, str] = {}     # branch -> first release containing the fix
    files: set[str] = set()
    introduced = mainline = None   # where the flaw appeared / where the fix landed upstream

    for aff in cna.get("affected", []):
        files.update(aff.get("programFiles") or [])
        for v in aff.get("versions", []):
            # git-hash ranges describe commits, not releases; skip them.
            if v.get("versionType") == "git":
                continue
            status = v.get("status")
            lt, lte, base = v.get("lessThan"), v.get("lessThanOrEqual"), v.get("version")

            if v.get("versionType") == "original_commit_for_fix":
                # the mainline release the fix first shipped in
                mainline = base or mainline
            elif status == "unaffected" and base == "0" and lt:
                # unaffected below `lt` -> the flaw was introduced in `lt`
                introduced = lt
            elif status == "affected" and lt:
                # affected from `base` up to (not including) `lt` -> `lt` carries the fix
                if b := branch_of(lt):
                    fixed[b] = lt
            elif status == "unaffected" and lte and lte.endswith(".*") and base:
                # unaffected from `base` through end of branch -> `base` carries the fix
                if b := branch_of(base):
                    fixed.setdefault(b, base)

    # The CNA scores a subset of its own records (high/critical only, in practice).
    # That is local, free and better covered than any API, so it is the default.
    score = severity = vector = None
    for entry in cna.get("metrics") or []:
        cvss = entry.get("cvssV4_0") or entry.get("cvssV3_1") or entry.get("cvssV3_0")
        if cvss:
            score = num(cvss.get("baseScore"))
            severity = cvss.get("baseSeverity")
            vector = cvss.get("vectorString")
            break

    commits = []
    for ref in cna.get("references", []):
        if m := KERNEL_COMMIT.search(ref.get("url", "")):
            commits.append(m.group(1))

    desc = ""
    for d in cna.get("descriptions", []):
        if d.get("lang", "en").startswith("en"):
            desc = d.get("value", "")
            break

    return {
        "cve": cve,
        "title": (cna.get("title") or "").strip(),
        "desc": desc.strip(),
        "published": meta.get("datePublished", "")[:10],
        "fixed": fixed,
        "score": score,
        "epss": None,
        "exploited": False,
        "severity": severity,
        "vector": vector,
        "introduced": introduced,
        "mainline": mainline or (max(fixed.values(), key=release_key) if fixed else None),
        "files": sorted(files)[:12],
        "subsys": subsystem(sorted(files)),
        "commits": commits[:8],
    }


def subsystem(files: list[str]) -> str:
    """Coarse subsystem label from the touched paths: 'drivers/net', 'fs/btrfs'."""
    if not files:
        return "unknown"
    parts = files[0].split("/")
    if parts[0] in ("drivers", "fs", "net", "arch", "sound", "tools") and len(parts) > 2:
        return "/".join(parts[:2])
    return parts[0]


def collect(repo: pathlib.Path, branches: list[str]) -> list[dict]:
    published = repo / "cve" / "published"
    if not published.is_dir():
        log(f"{published} not found; scanning {repo} for CVE records instead")
        published = repo
        if not any(published.rglob("CVE-*.json")):
            sys.exit(f"no CVE records under {repo} - is it really a vulns.git checkout?")

    wanted = set(branches)
    out, seen, scanned = [], set(), 0
    for path in published.rglob("CVE-*.json"):
        scanned += 1
        try:
            doc = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            log(f"skipping {path.name}: {exc}")
            continue
        rec = parse_record(doc)
        if not rec or rec["cve"] in seen:
            continue
        if wanted & set(rec["fixed"]) or any(outstanding_on(rec, b) for b in wanted):
            seen.add(rec["cve"])
            out.append(rec)
    log(f"scanned {scanned} records, {len(out)} touch {', '.join(branches)}")
    return out


# --------------------------------------------------------------------------- #
# enrich
# --------------------------------------------------------------------------- #

def get_json(url: str, headers: dict | None = None, retries: int = 3):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 503) and attempt < retries - 1:
                time.sleep(2 ** attempt * 3)
                continue
            return None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
                continue
            return None
    return None


class Cache:
    """Flat JSON cache so repeated runs don't re-hammer the APIs."""

    def __init__(self, path: pathlib.Path):
        self.path = path
        self.data = json.loads(path.read_text()) if path.exists() else {}

    def get(self, key):
        return self.data.get(key)

    def put(self, key, value):
        self.data[key] = value

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data))


def fetch_bytes(url: str, timeout: int = 30) -> bytes | None:
    """One shot, no retries: both callers are optional enrichment, not the spine."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log(f"{urllib.parse.urlsplit(url).netloc}: {exc}")
        return None


def enrich_epss(records: list[dict]) -> None:
    """Exploit-prediction scores for every CVE, in a single request.

    FIRST publishes the whole model output daily: ~2.5 MB gzipped, ~366k CVEs.
    Nothing to cache and nothing to rate-limit, so this just runs every build.
    """
    raw = fetch_bytes(EPSS_DUMP)
    if not raw:
        log("epss: unavailable, leaving the column empty")
        return
    scores = {}
    for line in gzip.decompress(raw).decode().splitlines():
        cve, _, epss = line.partition(",")
        if not cve.startswith("CVE-"):
            continue  # leading '#model_version:...' and the 'cve,epss,percentile' header
        try:
            scores[cve] = round(float(epss.split(",")[0]), 5)
        except ValueError:
            continue
    hit = 0
    for rec in records:
        if (score := scores.get(rec["cve"])) is not None:
            rec["epss"] = score
            hit += 1
    log(f"epss: {hit}/{len(records)} scored (dump covers {len(scores)} CVEs)")


def enrich_kev(records: list[dict]) -> None:
    """CISA's known-exploited catalogue: the only 'seen in the wild' signal here."""
    body = get_json(KEV_FEED, retries=1)
    if not body:
        log("kev: unavailable, no exploited flags set")
        return
    known = {v.get("cveID") for v in body.get("vulnerabilities") or []}
    hit = 0
    for rec in records:
        if rec["cve"] in known:
            rec["exploited"] = True
            hit += 1
    log(f"kev: {hit} of {len(records)} are known-exploited ({len(known)} in the catalogue)")


def enrich_nvd(records: list[dict], cache: Cache, key: str | None) -> None:
    """Worth the wait for one thing: the CNA scores only high/critical, so every
    medium and low score in the table can only have come from here. CWE too."""
    headers = {"apiKey": key} if key else {}
    delay = 0.7 if key else 6.5  # 50 req/30s with a key, 5 req/30s without
    todo = [r for r in records if cache.get("nvd:" + r["cve"]) is None]
    log(f"nvd: {len(records) - len(todo)} cached, {len(todo)} to fetch "
        f"(~{len(todo) * delay / 60:.0f} min)" + ("" if key else "; set NVD_API_KEY to go ~9x faster"))

    failed = 0
    for i, rec in enumerate(todo, 1):
        body = get_json(f"{NVD_API}?cveId={rec['cve']}", headers)
        if body is None:
            # A 429 or a timeout is not an answer. Caching {} here would bake
            # "NVD knows nothing about this CVE" in for good over a nine-hour run.
            failed += 1
        else:
            cache.put("nvd:" + rec["cve"],
                      ((body.get("vulnerabilities") or [{}])[0]).get("cve", {}))
        if i % 50 == 0:
            log(f"nvd: {i}/{len(todo)}")
            cache.save()
        time.sleep(delay)
    cache.save()
    if failed:
        log(f"nvd: {failed}/{len(todo)} requests failed and were left uncached; "
            f"re-run to pick them up")

    for rec in records:
        item = cache.get("nvd:" + rec["cve"]) or {}
        rec["nvd_status"] = item.get("vulnStatus")
        metrics = item.get("metrics", {})
        for family in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            if metrics.get(family):
                data = metrics[family][0].get("cvssData", {})
                if rec.get("score") is None:
                    rec["score"] = num(data.get("baseScore"))
                if not rec.get("vector"):
                    rec["vector"] = data.get("vectorString")
                break
        rec["cwe"] = next(
            (d.get("value") for w in item.get("weaknesses", [])
             for d in w.get("description", []) if str(d.get("value", "")).startswith("CWE")),
            None,
        )


def num(value):
    try:
        return round(float(value), 2)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# shape for the page
# --------------------------------------------------------------------------- #

def release_key(release: str) -> tuple:
    return tuple(int(p) for p in release.split("."))


def build_payload(records: list[dict], branches: list[str], sample: bool = False) -> dict:
    per_branch = {}
    for rec in records:
        rec["outstanding"] = []
    for branch in branches:
        releases = defaultdict(list)
        pending = []
        for rec in records:
            if rel := rec["fixed"].get(branch):
                releases[rel].append(rec["cve"])
            elif outstanding_on(rec, branch):
                pending.append(rec["cve"])
                rec.setdefault("outstanding", []).append(branch)
        per_branch[branch] = {
            "releases": [
                {"release": rel, "cves": sorted(releases[rel])}
                for rel in sorted(releases, key=release_key)
            ],
            "outstanding": sorted(pending),
        }

    return {
        "generated": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "branches": branches,
        "sample": sample,
        "byBranch": per_branch,
        "cves": {r["cve"]: r for r in records},
    }


def print_outstanding(records: list[dict], branches: list[str]) -> None:
    """The backport gap as a plain table, worst first.

    Same set the dashboard shows behind the outstanding count, for people on a
    build box with no browser. Rows go to stdout and the tally to stderr, so
    piping into awk/grep/fzf gets data and nothing else.
    """
    rows = [(b, r) for b in branches for r in records if outstanding_on(r, b)]
    if not rows:
        print(f"nothing outstanding on {', '.join(branches)}", file=sys.stderr)
        return
    rows.sort(key=lambda x: (-(x[1].get("score") or 0), -(x[1].get("epss") or 0), x[1]["cve"]))

    sub_w = max(9, max(len(r["subsys"]) for _, r in rows))
    br_w = max(6, max(len(b) for b, _ in rows))
    width = shutil.get_terminal_size((200, 24)).columns
    print(f"  {'CVE':<16} {'BRANCH':<{br_w}} {'CVSS':>4} {'EPSS':>6} "
          f"{'MAINLINE':<8} {'SUBSYSTEM':<{sub_w}} TITLE"[:width])
    for branch, r in rows:
        print(f"{'! ' if r.get('exploited') else '  '}"
              f"{r['cve']:<16} {branch:<{br_w}} "
              f"{'-' if r.get('score') is None else format(r['score'], '.1f'):>4} "
              f"{'-' if r.get('epss') is None else format(r['epss'] * 100, '.1f') + '%':>6} "
              f"{r.get('mainline') or '-':<8} {r['subsys']:<{sub_w}} {r['title']}"[:width])

    exploited = sum(1 for _, r in rows if r.get("exploited"))
    unscored = sum(1 for _, r in rows if r.get("score") is None)
    log(f"{len(rows)} outstanding on {', '.join(branches)} "
        f"({exploited} known-exploited, {unscored} unscored). "
        f"'MAINLINE' is the release carrying the fix to backport from.")


def render(payload: dict, out: pathlib.Path) -> None:
    template = (pathlib.Path(__file__).parent / "dashboard.html").read_text()
    blob = json.dumps(payload, separators=(",", ":")).replace("</", "<\\/")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(template.replace("/*__DATA__*/null", blob))
    log(f"wrote {out} ({out.stat().st_size / 1024:.0f} KB)")


def log(msg: str) -> None:
    print(f"  {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# sample data (shape-accurate, fictional IDs - for looking at the UI offline)
# --------------------------------------------------------------------------- #

def sample_records(branches: list[str]) -> list[dict]:
    import random

    rng = random.Random(7)
    subsystems = ["drivers/net", "drivers/gpu", "fs/btrfs", "net/ipv4", "mm",
                  "drivers/usb", "sound/soc", "fs/ext4", "kernel", "net/bluetooth"]
    plan = {b: [f"{b}.{z}" for z in range(1, n + 1)]
            for b, n in zip(branches, (11, 2))}
    records, serial = [], 40000
    for branch, releases in plan.items():
        for rel in releases:
            for _ in range(rng.randint(8, 70) if branch == branches[0] else rng.randint(30, 90)):
                serial += 1
                sub = rng.choice(subsystems)
                records.append({
                    "cve": f"CVE-2026-{serial}",
                    "title": f"{sub}: fix use-after-free in sample path",
                    "desc": "SAMPLE RECORD - not a real vulnerability. Generated by "
                            "`kcve.py demo` so the interface can be reviewed offline.",
                    "published": "2026-08-01",
                    "fixed": {branch: rel},
                    "introduced": branch, "mainline": branch,
                    "files": [f"{sub}/sample.c"],
                    "subsys": sub,
                    "commits": ["0" * 40],
                    "score": rng.choice([None, 4.4, 5.5, 6.1, 7.1, 7.8, 8.8, 9.1]),
                    "epss": round(rng.random() ** 4, 4),
                    "exploited": rng.random() < 0.01,
                    "nvd_status": rng.choice(["Deferred", "Awaiting Analysis", "Analyzed"]),
                })
    for branch in branches:
        major, minor = branch_tuple(branch)
        for _ in range(4):
            serial += 1
            records.append({
                "cve": f"CVE-2026-{serial}", "title": "mm: sample unbackported fix",
                "desc": "SAMPLE RECORD.", "published": "2026-08-20", "fixed": {},
                # affected from this branch, fixed only in the next one -> outstanding here
                "introduced": branch, "mainline": f"{major}.{minor + 1}",
                "files": ["mm/sample.c"], "subsys": "mm",
                "commits": [], "score": 7.0, "epss": 0.01, "exploited": False,
                "nvd_status": "Awaiting Analysis",
            })
    return records


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["build", "outstanding", "demo", "dump"])
    ap.add_argument("cve", nargs="?", help="CVE id, for `dump`")
    ap.add_argument("--branches", default="6.18,7.2")
    ap.add_argument("--repo", type=pathlib.Path,
                    default=pathlib.Path.home() / ".cache" / "kcve" / "vulns")
    ap.add_argument("--cache", type=pathlib.Path,
                    default=pathlib.Path.home() / ".cache" / "kcve" / "enrich.json")
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path("kcve.html"))
    ap.add_argument("--nvd", action="store_true", help="fill in the medium/low CVSS the kernel CNA omits, plus CWE, from NVD (slow; set NVD_API_KEY)")
    ap.add_argument("--no-sync", action="store_true", help="use the existing checkout as-is")
    args = ap.parse_args()

    branches = [b.strip() for b in args.branches.split(",") if b.strip()]

    if args.command == "demo":
        render(build_payload(sample_records(branches), branches, sample=True), args.out)
        return

    if args.command == "dump":
        if not args.cve:
            sys.exit("dump needs a CVE id")
        hits = list(args.repo.rglob(f"{args.cve}.json"))
        if not hits:
            sys.exit(f"{args.cve} not found under {args.repo}")
        print(json.dumps(parse_record(json.loads(hits[0].read_text())), indent=2))
        return

    if not args.no_sync:
        sync_vulns(args.repo)
    records = collect(args.repo, branches)
    enrich_epss(records)
    enrich_kev(records)
    if args.nvd:
        enrich_nvd(records, Cache(args.cache), os.environ.get("NVD_API_KEY"))

    if args.command == "outstanding":
        print_outstanding(records, branches)
    else:
        render(build_payload(records, branches), args.out)


if __name__ == "__main__":
    main()
