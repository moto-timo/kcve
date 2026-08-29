#!/usr/bin/env python3
# Copyright (C) 2026 Tim Orling
# Copyright (C) 2026 Konsulko Group
# SPDX-License-Identifier: GPL-2.0-or-later

"""Self-check for the parts of kcve that can silently produce a wrong answer:
version parsing and the outstanding-backport inference. Run: ./test_kcve.py"""

from kcve import branch_of, branch_tuple, outstanding_on, parse_record, build_payload

assert branch_of("6.18.7") == "6.18"
assert branch_of("7.1") is None and branch_of("6.19-rc1") is None
assert branch_tuple("6.18.7") == branch_tuple("6.18") == (6, 18)
assert branch_tuple("7.0") == (7, 0) and branch_tuple(None) is None
assert branch_tuple("6.9") < branch_tuple("6.18")  # not string order


def rec(fixed, introduced, mainline):
    return {"fixed": fixed, "introduced": introduced, "mainline": mainline}


# fixed on the branch itself -> nothing outstanding
assert not outstanding_on(rec({"6.18": "6.18.4"}, "5.12", "7.0"), "6.18")
# real shape of CVE-2025-71313: born in 5.12, fixed in 6.19.4 and mainline 7.0
r = rec({"6.19": "6.19.4"}, "5.12", "7.0")
assert outstanding_on(r, "6.18"), "6.18 predates the fix and carries the code"
assert not outstanding_on(r, "7.1"), "7.1 is past mainline, it already has the fix"
# branch older than the flaw never carried the buggy code
assert not outstanding_on(rec({"7.1": "7.1.2"}, "6.19", "7.2"), "6.18")
# fix already in mainline at or below the branch -> branch inherits it
assert not outstanding_on(rec({"5.16": "5.16.3"}, "5.12", "5.16"), "6.18")
# no mainline release recorded -> refuse to guess
assert not outstanding_on(rec({}, "5.12", None), "6.18")

# the CNA never writes `affected` + `X.*`, so the old direct read found nothing
doc = {
    "cveMetadata": {"cveId": "CVE-2026-00001", "datePublished": "2026-01-02T00:00:00"},
    "containers": {"cna": {"title": "t", "descriptions": [{"lang": "en", "value": "d"}],
        "affected": [{"programFiles": ["fs/ext4/inode.c"], "versions": [
            {"version": "a" * 40, "lessThan": "b" * 40, "versionType": "git"},
            {"version": "0", "lessThan": "5.12", "status": "unaffected", "versionType": "semver"},
            {"version": "6.19.4", "lessThanOrEqual": "6.19.*", "status": "unaffected"},
            {"version": "7.0", "lessThanOrEqual": "*", "status": "unaffected",
             "versionType": "original_commit_for_fix"}]}]}},
}
p = parse_record(doc)
assert p["fixed"] == {"6.19": "6.19.4"} and p["introduced"] == "5.12"
assert p["mainline"] == "7.0" and p["subsys"] == "fs/ext4"

payload = build_payload([p], ["6.18", "7.1"])
assert payload["byBranch"]["6.18"]["outstanding"] == ["CVE-2026-00001"]
assert payload["byBranch"]["7.1"]["outstanding"] == []
assert payload["cves"]["CVE-2026-00001"]["outstanding"] == ["6.18"]
assert build_payload([p], ["6.18"])["byBranch"]["6.18"]["outstanding"] == ["CVE-2026-00001"]

print("ok")
