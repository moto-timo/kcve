# Security

## Reporting a vulnerability in the Linux kernel

**Not here.** kcve only reports on kernel CVEs; it is not part of the kernel and
cannot act on them. Kernel vulnerabilities go to the kernel security team:

- Undisclosed vulnerabilities: <security@kernel.org>
  (see [Documentation/process/security-bugs.rst](https://docs.kernel.org/process/security-bugs.html))
- CVE assignment questions: <cve@kernel.org>
  (see [Documentation/process/cve.rst](https://docs.kernel.org/process/cve.html))

If you believe a CVE record itself is wrong — a missing backport, a bad version
range — that is a kernel CNA matter, not a kcve one. kcve renders what the CNA
publishes.

## Reporting a vulnerability in kcve

Open a private security advisory through the repository's Security tab, or email the
maintainer. Please do not open a public issue for a security bug.

The realistic attack surface is small but not empty:

- **Parsed input.** `kcve.py` parses CVE JSON from a cloned git repository and data
  from three HTTP endpoints. It uses `json` and `re` only, never `eval`, `pickle`, or
  `subprocess` on record contents.
- **Generated HTML.** CVE titles and descriptions from the CNA are embedded in the
  page as a JSON blob. As of the current revision: the DOM helper sets `textContent`,
  never `innerHTML`; the only two `innerHTML` assignments in the template build from
  static strings and integer counts, not record data; every outbound link is a fixed
  `https://` prefix with the CVE id appended as a path or query value, so a record
  cannot control a URL scheme; and `</` is escaped when embedding the payload, so a
  description cannot terminate the `<script>` block early. A report of a working
  injection through a crafted CVE record is in scope and welcome.
- **Network.** All fetches are HTTPS to fixed hosts. There is no authentication and
  no credential handling anywhere in the tool.

## Trust and limitations

kcve is an **informational tool**. It is not an audit, not a compliance artifact, and
not a substitute for tracking your own tree. Two limitations bear directly on
security decisions and are easy to misread:

### A blank CVSS does not mean low risk

The kernel CNA publishes scores only for **high and critical** severity. Everything
else it leaves unscored. An empty CVSS column means nobody scored it — it is not a
statement that the issue is minor. Run with `--nvd` to fill those in.

### The backport gap is inferred

The CNA records where a fix landed, never where one is missing; there is no field
stating "not backported". kcve reconstructs it from version ranges: a branch is
listed as outstanding when it predates the mainline fix, is new enough to contain the
buggy code, and has no release of its own carrying the fix.

This assumes a flaw reaches every branch released after the one it was introduced in.
That assumption fails for a bug confined to a single stable tree, which would need
commit-level archaeology to detect. **Do not treat the outstanding list as a complete
or authoritative account of your exposure.** Confirm against your own tree before
acting.

### Freshness

A generated page is a snapshot. Its build time and the branches it covers are in the
masthead. A page left up for a week is a week out of date; EPSS in particular is
recomputed daily.

## Supported versions

kcve is a single script with no release process. Only the current `main` is
supported; there are no backports of fixes to older revisions.
