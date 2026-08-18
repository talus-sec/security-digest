#!/usr/bin/env python3
"""
Security Digest -- Scoped Vulnerability Tracker + General News Roundup

Two independent halves, published as one dashboard:

TOP -- General Security News (unfiltered)
Every item from your configured static news feeds (BleepingComputer, The Hacker
News, Krebs, The Register, plus anything in CUSTOM_RSS_FEEDS), shown as-is
in columns by source. Not filtered, not summarized by an LLM -- just today's raw
headlines so you can scan everything, not just what matched a keyword.

BOTTOM -- Scoped Vulnerability Tracking
For each configured SCOPE (currently "Database" and "Cloud Security", with room
for more), pulls new/updated CVEs from NVD, cross-references CISA's KEV catalog
for confirmed-but-unscored exploited bugs, and pulls scope-matched news/forum
chatter. An LLM via OpenRouter's free router turns all of it into one structured
report per scope:
  - Summary
  - Affected Features / App Interoperability
  - Source
  - Actions (fix + workarounds + what workarounds break)
  - News & Community Mentions (separate, not treated as authoritative)

Adding a new scope: add an entry to the SCOPES dict below following the existing
shape ({"targets": {...}, "match_terms": {...}}) -- it flows through NVD querying,
KEV matching, news matching, the LLM prompt, and the dashboard automatically.
No other code changes needed.

Delivery: writes each day's page to docs/reports/YYYY-MM-DD.html and rebuilds
docs/index.html, which GitHub Pages serves as a free, no-app dashboard -- the
latest report shown in full up top, with a linked archive of every past day
below it. The raw Markdown for the scoped section is also kept in
reports/YYYY-MM-DD.md for reference.

Why CISA KEV matters: a CVE can sit in NVD as "awaiting analysis" with NO CVSS
score for days or weeks. KEV doesn't wait for a score -- a CVE is added the
moment CISA confirms real-world exploitation. This script checks KEV on its
own lookback window (by date-added, not NVD's lastModified) so an actively
exploited-but-unscored bug never gets missed.

Why OpenRouter: it's a single free API key with no Google Cloud project
setup, no billing account, no credit card. It routes to whichever model is
currently in its free pool via the "openrouter/free" router.

Env vars required:
  OPENROUTER_API_KEY - free key from https://openrouter.ai/keys (no card needed)
Optional:
  NVD_API_KEY       - free key from https://nvd.nist.gov/developers/request-an-api-key
                       (not required, but raises your rate limit substantially)
  LOOKBACK_HOURS    - defaults to 26 (small overlap so nothing slips through)
  KEV_LOOKBACK_DAYS - defaults to 7 (KEV additions to check each run)
  NEWS_LOOKBACK_HOURS - defaults to 48 (news/forum timestamps are looser than CVE data)
  ENABLE_NEWS_FEEDS - defaults to "true"; set to "false" to disable RSS entirely
  CUSTOM_RSS_FEEDS  - comma-separated list of additional RSS/Atom feed URLs
                       (e.g. a specific forum's RSS feed you want included)
"""

import os
import sys
import time
import json
import html as html_mod
import re
import datetime
import email.utils
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
from collections import Counter

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OPENROUTER_MODEL = "openrouter/free"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

MAX_ENTRIES_PER_SYSTEM = 10  # per system, per scope -- keeps the LLM prompt bounded
MAX_ITEMS_PER_NEWS_SOURCE = 15  # for the raw Top News columns

# ---------------------------------------------------------------------------
# SCOPES -- add a new scope here to track a new topic area. Each scope needs:
#   "targets"      -> {friendly system name: NVD keywordSearch term}
#   "match_terms"  -> {friendly system name: [lowercase substrings to match
#                       against KEV/news text]}
# That's it -- everything else (NVD queries, KEV cross-reference, news
# matching, LLM prompt sections, dashboard rendering) is scope-agnostic and
# picks up new entries automatically.
# ---------------------------------------------------------------------------
SCOPES = {
    "Database": {
        "targets": {
            "MySQL": "MySQL",
            "PostgreSQL": "PostgreSQL",
            "Oracle Database": "Oracle Database",
            "Microsoft SQL Server": "Microsoft SQL Server",
            "MongoDB": "MongoDB",
        },
        "match_terms": {
            "MySQL": ["mysql"],
            "PostgreSQL": ["postgres"],
            "Oracle Database": ["oracle database", "oracle db"],
            "Microsoft SQL Server": ["sql server", "mssql"],
            "MongoDB": ["mongodb", "mongo"],
        },
    },
    "Cloud Security": {
        "targets": {
            "AWS": "Amazon Web Services",
            "Microsoft Azure": "Microsoft Azure",
            "Google Cloud Platform": "Google Cloud Platform",
            "Kubernetes": "Kubernetes",
            "Docker": "Docker",
            "Terraform": "Terraform",
        },
        "match_terms": {
            "AWS": ["aws", "amazon web services"],
            "Microsoft Azure": ["azure"],
            "Google Cloud Platform": ["google cloud", "gcp"],
            "Kubernetes": ["kubernetes", "k8s"],
            "Docker": ["docker"],
            "Terraform": ["terraform"],
        },
    },
    # Reserved slots for future project scopes -- copy the shape above.
    # "Identity & Access Management": {"targets": {...}, "match_terms": {...}},
    # "Endpoint / EDR": {"targets": {...}, "match_terms": {...}},
}

# Three SEPARATE unfiltered news rows on the dashboard: Security, then Database,
# then Cloud. Same treatment for all three -- raw feed items, no keyword filtering,
# no LLM involved. Only the curated source list differs per row.

SECURITY_NEWS_FEEDS = [
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("SecurityWeek", "https://feeds.feedburner.com/securityweek"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("Beehiiv Newsletter", "https://rss.beehiiv.com/feeds/xgTKUmMmUm.xml"),
    # The Register's own "I want it all" feed -- every section (Security, Software/
    # Databases, Open Source tag included, etc.) in one stream, straight from their
    # official feeds page (theregister.com/design/page/feeds).
    ("The Register", "https://www.theregister.com/?lab_viewport=rss"),
]
# Reddit feeds removed for now (both the search endpoint and the plain /new/.rss
# listing were consistently hitting 429 rate limits from GitHub Actions' shared IPs).
# Re-add via CUSTOM_RSS_FEEDS if you want to try again later, or revisit if Reddit's
# rate limiting eases up. CUSTOM_RSS_FEEDS is appended to this row specifically.

DATABASE_NEWS_FEEDS = [
    ("DBTA (Database Trends & Applications)", "https://feeds.feedburner.com/DBTA-Articles"),
    ("Planet PostgreSQL", "https://planet.postgresql.org/rss20.xml"),
    ("Planet MySQL", "https://planet.mysql.com/rss20.xml"),
    ("Oracle Database Blog", "https://blogs.oracle.com/database/rss"),
    ("SQLServerCentral", "https://www.sqlservercentral.com/blogs/feed"),
]

CLOUD_NEWS_FEEDS = [
    ("AWS News Blog", "https://aws.amazon.com/blogs/aws/feed/"),
    ("Microsoft Azure Blog", "https://azure.microsoft.com/en-us/blog/feed/"),
    ("Google Cloud Blog", "https://cloudblog.withgoogle.com/rss"),
    ("Kubernetes Blog", "https://kubernetes.io/feed.xml"),
    ("The New Stack", "https://thenewstack.io/feed"),
]

LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "26"))
KEV_LOOKBACK_DAYS = int(os.environ.get("KEV_LOOKBACK_DAYS", "7"))
NEWS_LOOKBACK_HOURS = int(os.environ.get("NEWS_LOOKBACK_HOURS", "48"))
ENABLE_NEWS_FEEDS = os.environ.get("ENABLE_NEWS_FEEDS", "true").lower() != "false"



# ---------------------------------------------------------------------------
# Shared HTTP helper
# ---------------------------------------------------------------------------

def http_get(url: str, headers: dict = None, timeout: int = 30, retries: int = 2):
    """GET with a couple of retries on transient failure. Returns raw bytes or None."""
    headers = headers or {}
    headers.setdefault("User-Agent", "security-digest/1.0 (+https://github.com/)")
    last_err = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except Exception as e:
            last_err = e
            if attempt < retries:
                time.sleep(3 * (attempt + 1))
    print(f"  [!] GET failed after retries: {url} ({last_err})", file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

def nvd_fetch(keyword: str) -> list:
    """Query NVD for CVEs mentioning `keyword`, published or modified in the lookback window."""
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(hours=LOOKBACK_HOURS)

    params = {
        "keywordSearch": keyword,
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": "50",
    }
    url = f"{NVD_BASE}?{urllib.parse.urlencode(params)}"

    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    raw = http_get(url, headers=headers, timeout=30)
    if raw is None:
        return []

    try:
        data = json.loads(raw.decode())
    except Exception as e:
        print(f"  [!] NVD JSON parse failed for '{keyword}': {e}", file=sys.stderr)
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        descriptions = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        cvss_score, cvss_severity = None, None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_score = m.get("cvssData", {}).get("baseScore")
                cvss_severity = m.get("baseSeverity") or m.get("cvssData", {}).get("baseSeverity")
                break

        refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]

        results.append({
            "id": cve_id,
            "description": desc_en,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "references": refs[:5],
        })

    return results


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

def kev_fetch() -> list:
    """Pull CISA's full KEV catalog and return entries added within the lookback window.
    Fetched ONCE per run and reused across all scopes -- KEV matching is scope-specific,
    but the catalog itself isn't."""
    raw = http_get(KEV_URL, timeout=30)
    if raw is None:
        return []

    try:
        data = json.loads(raw.decode())
    except Exception as e:
        print(f"  [!] KEV JSON parse failed: {e}", file=sys.stderr)
        return []

    cutoff = datetime.date.today() - datetime.timedelta(days=KEV_LOOKBACK_DAYS)
    recent = []
    for vuln in data.get("vulnerabilities", []):
        try:
            date_added = datetime.date.fromisoformat(vuln.get("dateAdded", ""))
        except ValueError:
            continue
        if date_added >= cutoff:
            recent.append(vuln)
    return recent


def match_kev_to_scope(kev_entries: list, match_terms: dict) -> dict:
    """Bucket KEV entries under a scope's system labels using loose substring matching."""
    matched = {}
    for vuln in kev_entries:
        haystack = " ".join([
            vuln.get("vendorProject", ""),
            vuln.get("product", ""),
            vuln.get("vulnerabilityName", ""),
            vuln.get("shortDescription", ""),
        ]).lower()

        for label, terms in match_terms.items():
            if any(term in haystack for term in terms):
                matched.setdefault(label, []).append({
                    "id": vuln.get("cveID"),
                    "confirmed_exploited_by_cisa_kev": True,
                    "cvss_score": None,
                    "cvss_severity": "UNSCORED — CISA-confirmed active exploitation",
                    "vendor_project": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "vulnerability_name": vuln.get("vulnerabilityName"),
                    "description": vuln.get("shortDescription"),
                    "date_added_to_kev": vuln.get("dateAdded"),
                    "required_action": vuln.get("requiredAction"),
                    "due_date": vuln.get("dueDate"),
                    "known_ransomware_use": vuln.get("knownRansomwareCampaignUse"),
                    "references": [f"https://nvd.nist.gov/vuln/detail/{vuln.get('cveID')}"],
                })
    return matched


def merge_kev_into_collected(collected: dict, kev_matched: dict) -> dict:
    for label, kev_items in kev_matched.items():
        existing = collected.setdefault(label, [])
        existing_ids = {e["id"] for e in existing}
        for kev_item in kev_items:
            if kev_item["id"] in existing_ids:
                for e in existing:
                    if e["id"] == kev_item["id"]:
                        e["confirmed_exploited_by_cisa_kev"] = True
                        e["kev_required_action"] = kev_item.get("required_action")
                        e["kev_due_date"] = kev_item.get("due_date")
            else:
                existing.append(kev_item)
    return collected


def sort_entries_for_report(collected: dict) -> dict:
    """Sort each system's entries so the LLM never has to reason about ordering:
    KEV-confirmed first, then descending CVSS score (unscored entries sort last).
    Also caps each system at MAX_ENTRIES_PER_SYSTEM -- a free model handling a huge
    entry list in one prompt is what caused a real reasoning-loop failure previously."""
    for label, entries in collected.items():
        entries.sort(
            key=lambda e: (
                not e.get("confirmed_exploited_by_cisa_kev", False),
                -(e.get("cvss_score") or -1),
                e.get("id", ""),
            )
        )
        if len(entries) > MAX_ENTRIES_PER_SYSTEM:
            kept = entries[:MAX_ENTRIES_PER_SYSTEM]
            dropped = len(entries) - len(kept)
            print(f"    -> {label}: capping to top {MAX_ENTRIES_PER_SYSTEM} of {len(entries)} "
                  f"by priority ({dropped} lower-severity entries omitted from this run's report)")
            collected[label] = kept
    return collected


# ---------------------------------------------------------------------------
# RSS / news -- raw (Top section) and scope-matched (Bottom section) paths
# ---------------------------------------------------------------------------

def _parse_rss_datetime(raw: str):
    """Handle both RFC822 (RSS pubDate) and ISO 8601 (Atom updated/published)."""
    if not raw:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except (TypeError, ValueError):
        pass
    try:
        cleaned = raw.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except ValueError:
        return None


def parse_feed(url: str, source_label: str = None) -> list:
    """Minimal stdlib RSS 2.0 / Atom parser. Returns list of {title, link, published, summary, source}.
    source_label overrides the default domain-derived source name -- needed when multiple
    distinct feeds share a host (e.g. two different tag feeds from the same news API)."""
    raw = http_get(url, timeout=20)
    if raw is None:
        return []

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        print(f"  [!] RSS parse failed for {url}: {e}", file=sys.stderr)
        return []

    items = []
    source = source_label or urllib.parse.urlparse(url).netloc

    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub = item.findtext("pubDate")
        summary = (item.findtext("description") or "").strip()
        items.append({"title": title, "link": link, "published": pub, "summary": summary[:500], "source": source})

    ns = {"atom": "http://www.w3.org/2005/Atom"}
    for entry in root.findall(".//atom:entry", ns):
        title = (entry.findtext("atom:title", namespaces=ns) or "").strip()
        link_el = entry.find("atom:link", ns)
        link = link_el.get("href") if link_el is not None else ""
        pub = entry.findtext("atom:updated", namespaces=ns) or entry.findtext("atom:published", namespaces=ns)
        summary = (entry.findtext("atom:summary", namespaces=ns) or "").strip()
        items.append({"title": title, "link": link, "published": pub, "summary": summary[:500], "source": source})

    return items


def fetch_feed_list(labeled_urls: list, list_name: str, include_custom: bool = False) -> list:
    """Fetch a (label, url) feed list unfiltered by keyword -- shared by all three
    raw news rows (Security, Database, Cloud). Filtered only by recency, de-duped
    by link. include_custom appends CUSTOM_RSS_FEEDS (only wired to the Security
    row, since that's where it was originally requested)."""
    if not ENABLE_NEWS_FEEDS:
        print(f"[i] ENABLE_NEWS_FEEDS=false, skipping {list_name} news collection")
        return []

    labeled_urls = list(labeled_urls)
    if include_custom:
        custom = os.environ.get("CUSTOM_RSS_FEEDS", "").strip()
        if custom:
            # CUSTOM_RSS_FEEDS entries have no configured label, so they fall back to
            # domain-based naming inside parse_feed() (source_label=None there).
            labeled_urls += [(None, u.strip()) for u in custom.split(",") if u.strip()]

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=NEWS_LOOKBACK_HOURS)
    all_items = []
    seen_links = set()

    for label, url in labeled_urls:
        print(f"[*] Fetching {list_name} news feed: {label or url}")
        for item in parse_feed(url, source_label=label):
            link = item.get("link")
            if not link or link in seen_links:
                continue
            pub_dt = _parse_rss_datetime(item.get("published"))
            if pub_dt and pub_dt < cutoff:
                continue
            all_items.append(item)
            seen_links.add(link)
        time.sleep(1)

    print(f"[i] {len(all_items)} total raw {list_name} news item(s) collected")
    return all_items


def group_items_by_source(items: list) -> dict:
    """Group raw items by feed source, newest first, capped per source for display."""
    grouped = {}
    for item in items:
        grouped.setdefault(item["source"], []).append(item)

    for source, source_items in grouped.items():
        source_items.sort(
            key=lambda i: _parse_rss_datetime(i.get("published")) or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc),
            reverse=True,
        )
        grouped[source] = source_items[:MAX_ITEMS_PER_NEWS_SOURCE]

    return grouped


def build_google_news_feeds_for_scope(scope_targets: dict) -> dict:
    """One Google News RSS search feed per system in a scope, scoped to security terms.
    Returns {system_label: feed_url} since each feed is already system-specific --
    no further keyword matching needed on these results."""
    feeds = {}
    for label, keyword in scope_targets.items():
        q = urllib.parse.quote(f'"{keyword}" (vulnerability OR exploit OR CVE OR security patch)')
        feeds[label] = f"https://news.google.com/rss/search?q={q}%20when:2d&hl=en-US&gl=US&ceid=US:en"
    return feeds


def match_items_to_scope(items: list, match_terms: dict) -> dict:
    """Keyword-match a list of raw items against a scope's systems."""
    matched = {}
    for item in items:
        haystack = f"{item.get('title', '')} {item.get('summary', '')}".lower()
        for label, terms in match_terms.items():
            if any(term in haystack for term in terms):
                matched.setdefault(label, []).append(item)
                break
    return matched


MAX_NEWS_ITEMS_PER_SYSTEM = 5  # keeps prompt size bounded -- 33 uncapped items for one
                                 # system in a single run is what likely overwhelmed the
                                 # free model and triggered the reasoning-loop/null-content bug


def collect_news_for_scope(scope_cfg: dict, general_items: list) -> dict:
    """Combine scope-matched items from the general feed pool with dedicated
    per-system Google News searches for this scope. Capped per system -- news items
    were previously unbounded, which was a major contributor to prompt bloat."""
    if not ENABLE_NEWS_FEEDS:
        return {}

    matched = match_items_to_scope(general_items, scope_cfg["match_terms"])
    seen_links = {item["link"] for items in matched.values() for item in items}

    google_feeds = build_google_news_feeds_for_scope(scope_cfg["targets"])
    for label, url in google_feeds.items():
        for item in parse_feed(url):
            link = item.get("link")
            if not link or link in seen_links:
                continue
            matched.setdefault(label, []).append(item)
            seen_links.add(link)
        time.sleep(1)

    for label, items in matched.items():
        if len(items) > MAX_NEWS_ITEMS_PER_SYSTEM:
            print(f"    -> {label}: capping news mentions to {MAX_NEWS_ITEMS_PER_SYSTEM} of {len(items)}")
        # Trim summary to a short snippet (was up to 500 chars each -- unnecessary bulk
        # for what the LLM needs to write one summary line per item) and cap the count.
        matched[label] = [
            {**item, "summary": (item.get("summary") or "")[:150]}
            for item in items[:MAX_NEWS_ITEMS_PER_SYSTEM]
        ]

    return matched


# ---------------------------------------------------------------------------
# Collection orchestration
# ---------------------------------------------------------------------------

def collect_scope(scope_name: str, scope_cfg: dict, kev_entries: list, general_news_items: list) -> tuple:
    print(f"\n[*] === Scope: {scope_name} ===")
    collected = {}
    for label, keyword in scope_cfg["targets"].items():
        print(f"[*] Querying NVD for {label}...")
        entries = nvd_fetch(keyword)
        if entries:
            collected[label] = entries
            print(f"    -> {len(entries)} result(s)")
        else:
            print("    -> none")
        time.sleep(6)  # be polite to the public NVD rate limit

    kev_matched = match_kev_to_scope(kev_entries, scope_cfg["match_terms"])
    total_kev_hits = sum(len(v) for v in kev_matched.values())
    print(f"    -> {total_kev_hits} KEV match(es) for this scope")
    collected = merge_kev_into_collected(collected, kev_matched)
    collected = sort_entries_for_report(collected)

    news = collect_news_for_scope(scope_cfg, general_news_items)
    total_news = sum(len(v) for v in news.values())
    print(f"    -> {total_news} scope-matched news item(s)")

    return collected, news


def collect_all() -> tuple:
    """Returns (general_items, collected_by_scope, news_by_scope). general_items here
    means the Security row specifically -- that's what scope news-matching draws from,
    unchanged from before this row was split into three."""
    print("[*] Fetching Security news feeds (for the unfiltered Security row)...")
    general_items = fetch_feed_list(SECURITY_NEWS_FEEDS, "Security", include_custom=True)

    print("\n[*] Checking CISA KEV catalog (fetched once, matched per scope)...")
    kev_entries = kev_fetch()
    print(f"    -> {len(kev_entries)} total KEV addition(s) in the last {KEV_LOOKBACK_DAYS} day(s)")

    collected_by_scope = {}
    news_by_scope = {}
    for scope_name, scope_cfg in SCOPES.items():
        collected, news = collect_scope(scope_name, scope_cfg, kev_entries, general_items)
        collected_by_scope[scope_name] = collected
        news_by_scope[scope_name] = news

    return general_items, collected_by_scope, news_by_scope


# ---------------------------------------------------------------------------
# LLM prompt + call (Bottom section only -- Top section is rendered directly,
# no LLM involved, since it's just formatting raw feed items into columns)
#
# IMPORTANT: one prompt + one LLM call PER SCOPE, not one giant combined call.
# A single combined prompt covering 13+ systems across 2 scopes was too large
# for a free model to reliably handle -- it either got stuck in a reasoning
# loop or returned a null content field outright. Splitting per scope keeps
# each individual request small, and means a failure in one scope's report
# doesn't take down the other scope's (or the Top News section, which never
# touches the LLM at all).
# ---------------------------------------------------------------------------

def build_prompt_for_scope(scope_name: str, collected: dict, news: dict) -> str:
    return f"""You are a security analyst producing a daily internal digest for a cybersecurity
engineer who administers database systems and cloud infrastructure in a healthcare enterprise
environment, and who also runs a homelab with Postgres/Vault PKI/mTLS infrastructure.

IMPORTANT: Output ONLY the final Markdown report. Do not think out loud, do not show your
reasoning process, do not narrate how you're analyzing or sorting the data. Go straight to
the finished report text.

Produce a report for ONE scope: "{scope_name}". Use this exact structure:

## {scope_name}

One-paragraph executive summary, highlighting the single most urgent item (a CISA KEV-confirmed
entry always outranks a merely high-CVSS entry, since it's confirmed exploitation vs. theoretical
severity).

### Formal Vulnerabilities
Skip any system with no formal vulnerability entries. For EACH entry:

#### [System Name] — [CVE ID] (CVSS [score or "UNSCORED"] [severity]) [add "🔴 ACTIVELY EXPLOITED (CISA KEV)" if confirmed_exploited_by_cisa_kev is true]
**Summary:** Plain-English explanation in 1-3 sentences -- what it is, how it's triggered, who
can exploit it (auth required? network-reachable?). If it's a KEV entry with a due_date, state it.

**Affected Features / Interoperability:** What specific feature, service, module, or component
is impacted, and what downstream functionality or integrations could break (e.g. for databases:
replication, client drivers, extensions; for cloud: IAM policies, networking, orchestration). If
the raw data doesn't say, state that plainly rather than guessing.

**Source:** List the reference URL(s).

**Actions:**
- Fix: official patched version/release, if known
- Workaround: concrete interim mitigation if no immediate patch is possible
- Tradeoff: what the workaround itself breaks or degrades. Say "No significant tradeoff" if none.

### News & Community Mentions
Only include this subsection if there's news/forum data below. A short bullet list per system:
one line per item with a 1-sentence plain-English gist, the source name, and the link. Label
this unverified chatter, separate from the Formal Vulnerabilities above.

FORMAL VULNERABILITY DATA (from NVD + CISA KEV), grouped by system. Entries within each system
are ALREADY SORTED (KEV-confirmed first, then CVSS descending) -- present them in this order,
do not re-sort. If a system has more than {MAX_ENTRIES_PER_SYSTEM} entries, only the top
{MAX_ENTRIES_PER_SYSTEM} by priority are included; say so if relevant, don't imply completeness.
{json.dumps(collected, indent=2)}

NEWS/FORUM MENTIONS (supplementary, NOT authoritative -- do not invent CVE numbers from this
data). Capped at {MAX_NEWS_ITEMS_PER_SYSTEM} items per system.
{json.dumps(news, indent=2)}

Do not fabricate CVE IDs, scores, version numbers, or details beyond what's given above. If data
for an entry is too sparse for a real summary, say so.
"""


def strip_leaked_reasoning(text: str) -> str:
    """Some free/reasoning-tuned models leak internal chain-of-thought into the content
    field. Strip common patterns as a safety net."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)

    lines = text.split("\n")
    report_start_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith("## ") and any(s.lower() in line.lower() for s in SCOPES):
            report_start_idx = i
            break
    if report_start_idx is not None and report_start_idx > 0:
        text = "\n".join(lines[report_start_idx:])

    return text.strip()


def looks_like_broken_reasoning_dump(text: str, expected_entry_count: int) -> bool:
    """Heuristic for a model looping through analysis instead of producing a clean report.

    IMPORTANT distinction: with multiple scopes now covering 13+ systems, a LEGITIMATE
    report naturally repeats short boilerplate many times (e.g. "Tradeoff: No significant
    tradeoff." showing up 20 times across different CVE entries is normal, not a bug). The
    original version of this check counted total occurrences ANYWHERE in the document,
    which produced false positives on exactly that kind of normal repetition.

    A genuine stuck reasoning loop instead produces the same (or near-identical) line
    repeated CONSECUTIVELY, many times in a row -- that's the actual signature of a model
    stuck re-deriving the same thought over and over. So we check for runs of consecutive
    duplicate lines, not global frequency."""
    if len(text) > max(40000, expected_entry_count * 1200):
        return True

    lines = [l.strip() for l in text.split("\n") if l.strip()]

    max_consecutive_run = 1
    current_run = 1
    for i in range(1, len(lines)):
        if lines[i] == lines[i - 1]:
            current_run += 1
            max_consecutive_run = max(max_consecutive_run, current_run)
        else:
            current_run = 1

    # A real stuck loop repeats the exact same line back-to-back many times.
    # Legitimate reports essentially never have the same line twice in a row.
    if max_consecutive_run >= 6:
        return True

    return False


def call_llm(prompt: str, expected_entry_count: int = 0, label: str = "") -> str:
    """Call OpenRouter's free-model router. Returns the report text on success, or
    None on unrecoverable failure -- NEVER calls sys.exit(), so one scope's LLM call
    failing doesn't take down the whole script. The caller decides how to degrade."""
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        print("[!] OPENROUTER_API_KEY not set", file=sys.stderr)
        return None

    tag = f" [{label}]" if label else ""

    body = {
        "model": OPENROUTER_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 8192,
        "reasoning": {"exclude": True},
    }

    last_err = None
    for attempt in range(3):
        req = urllib.request.Request(
            OPENROUTER_URL,
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "HTTP-Referer": "https://github.com/",
                "X-Title": "security-digest",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                data = json.loads(resp.read().decode())
            content = data["choices"][0]["message"]["content"]

            # A free model can return a null content field outright (e.g. it burned
            # its whole token budget on reasoning and never produced a final answer).
            # This is NOT the same as a malformed string -- catch it explicitly so it
            # doesn't crash re.sub() downstream, and treat it as a retryable failure.
            if content is None:
                last_err = "model returned null content (likely exhausted its token budget on reasoning)"
                print(f"  [!]{tag} Attempt {attempt + 1}: {last_err}", file=sys.stderr)
                if attempt < 2:
                    time.sleep(10)
                    continue
                break

            content = strip_leaked_reasoning(content)

            if looks_like_broken_reasoning_dump(content, expected_entry_count):
                last_err = "response looked like a stuck reasoning loop, not a report"
                print(
                    f"  [!]{tag} Attempt {attempt + 1}: {last_err} "
                    f"(response length: {len(content)} chars, expected_entry_count: {expected_entry_count}), retrying...",
                    file=sys.stderr,
                )
                if attempt < 2:
                    time.sleep(10)
                    continue
                print(f"  [!]{tag} Gave up after 3 attempts, returning truncated content", file=sys.stderr)
                return content[:5000] + "\n\n*(Report was truncated -- the model's response looked malformed. Check the Action log.)*"

            print(f"[i]{tag} LLM response accepted ({len(content)} chars)")
            return content
        except urllib.error.HTTPError as e:
            err_body = e.read().decode() if e.fp else ""
            last_err = f"{e.code} {e.reason} {err_body}"
            if e.code in (429, 500, 502, 503) and attempt < 2:
                time.sleep(15 * (attempt + 1))
                continue
            break
        except (KeyError, IndexError) as e:
            # This means the response didn't have the expected {"choices": [...]} shape
            # at all -- often an error payload from OpenRouter's free-model pool being
            # temporarily overloaded/rate-limited, returned with a 200 status instead of
            # a proper error code, so it doesn't get caught by the HTTPError branch above.
            # Surface what we actually got back (truncated) so this is diagnosable instead
            # of just "unexpected response shape: 'choices'" with no context, and retry --
            # this looks transient rather than a permanent problem with the request itself.
            error_detail = data.get("error") if isinstance(data, dict) else None
            raw_snippet = json.dumps(data)[:500] if isinstance(data, dict) else str(data)[:500]
            last_err = f"unexpected response shape ({e}). error field: {error_detail}. raw (truncated): {raw_snippet}"
            print(f"  [!]{tag} Attempt {attempt + 1}: {last_err}", file=sys.stderr)
            if attempt < 2:
                time.sleep(15 * (attempt + 1))
                continue
            break
        except Exception as e:
            last_err = str(e)
            if attempt < 2:
                time.sleep(15 * (attempt + 1))
                continue
            break

    print(f"[!]{tag} OpenRouter call failed after all retries: {last_err}", file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# Rendering: Markdown -> HTML (Bottom section), raw news columns (Top section)
# ---------------------------------------------------------------------------

CVE_HEADER_RE = re.compile(
    r'^(?P<system>.+?)\s+—\s+(?P<cve>CVE-\d{4}-[\dNA]+)\s+\((?:CVSS\s+)?(?P<score>[\d.]+|UNSCORED)'
    r'(?:\s+(?P<sevword>[A-Za-z]+))?\)(?P<rest>.*)$'
)


def _classify_severity(score: str, sevword: str, rest_text: str) -> tuple:
    """Returns (severity_slug, is_kev). KEV always wins (confirmed exploitation
    outranks a theoretical score), then explicit severity word, then a CVSS-score
    fallback, then 'unscored' as a neutral default (not implying danger)."""
    is_kev = "ACTIVELY EXPLOITED" in rest_text.upper() or "🔴" in rest_text
    if is_kev:
        return "critical", True
    if sevword and sevword.lower() in ("critical", "high", "medium", "low"):
        return sevword.lower(), False
    if score and score != "UNSCORED":
        try:
            f = float(score)
            if f >= 9.0:
                return "critical", False
            if f >= 7.0:
                return "high", False
            if f >= 4.0:
                return "medium", False
            return "low", False
        except ValueError:
            pass
    return "unscored", False


def markdown_to_html(md: str) -> str:
    """Minimal, dependency-free Markdown -> HTML converter, tuned to this script's
    LLM prompt output (headers up to h4, bold, bullet lists, links, bare URLs).

    Special case: an h4 matching the "System — CVE-ID (CVSS score SEVERITY)" pattern
    this project's prompt always produces becomes a severity-coded incident card
    (colored left edge + CVE/CVSS/KEV badges) instead of a plain heading -- this is
    the dashboard's signature visual element, grounded in how CVSS severity is
    actually triaged in practice. Any other h4 (e.g. a per-system group header under
    "News & Community Mentions") stays a plain, differently-styled heading."""
    lines = md.split("\n")
    out = []
    in_list = False
    in_card = False

    def inline(text: str) -> str:
        text = html_mod.escape(text)
        text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
        text = re.sub(r"\[([^\]]+)\]\((https?://[^\s)]+)\)", r'<a href="\2">\1</a>', text)
        text = re.sub(r'(?<!href=")(?<!>)(https?://[^\s<]+)', r'<a href="\1">\1</a>', text)
        return text

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    def close_card():
        nonlocal in_card
        if in_card:
            out.append("</div></div>")
            in_card = False

    for raw_line in lines:
        stripped = raw_line.rstrip().strip()

        if stripped.startswith("#### "):
            heading_text = stripped[5:]
            m = CVE_HEADER_RE.match(heading_text)
            close_list()
            if m:
                close_card()
                system = inline(m.group("system"))
                cve = html_mod.escape(m.group("cve"))
                score = m.group("score")
                sevword = m.group("sevword")
                rest = m.group("rest") or ""
                severity, is_kev = _classify_severity(score, sevword, rest)
                score_label = f"CVSS {score}" if score != "UNSCORED" else "UNSCORED"
                if sevword and score != "UNSCORED":
                    score_label += f" · {sevword.upper()}"
                kev_badge = (
                    '<span class="badge badge-kev">Actively exploited · CISA KEV</span>'
                    if is_kev else ""
                )
                out.append(
                    f'<div class="vuln-card sev-{severity}"><div class="vuln-card-head">'
                    f'<span class="vuln-system">{system}</span>'
                    f'<span class="badge badge-cve">{cve}</span>'
                    f'<span class="badge badge-cvss sev-{severity}">{score_label}</span>'
                    f'{kev_badge}'
                    f'</div><div class="vuln-card-body">'
                )
                in_card = True
            else:
                close_card()
                out.append(f'<h4 class="mention-group">{inline(heading_text)}</h4>')
        elif stripped.startswith("### "):
            close_list()
            close_card()
            out.append(f"<h3>{inline(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            close_list()
            close_card()
            out.append(f"<h2>{inline(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            close_list()
            close_card()
            out.append(f"<h1>{inline(stripped[2:])}</h1>")
        elif stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(stripped[2:])}</li>")
        elif stripped == "":
            close_list()
        else:
            close_list()
            out.append(f"<p>{inline(stripped)}</p>")

    close_list()
    close_card()
    return "\n".join(out)


PAGE_CSS = """
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root {
  --bg: #0F1419;
  --surface: #161D26;
  --surface-2: #1E2730;
  --border: #2A343F;
  --text: #E8EDF2;
  --text-dim: #8B98A5;
  --text-faint: #5A6672;
  --link: #7DD3FC;
  --sev-critical: #FF5D5D;
  --sev-high: #FFA94D;
  --sev-medium: #FFD43B;
  --sev-low: #7C8B9A;
  --sev-unscored: #6B7C93;
  --row-security: #4FD1C5;
  --row-database: #F0B429;
  --row-cloud: #5EA8FF;
}

* { box-sizing: border-box; }

html { scroll-behavior: smooth; }
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  * { transition: none !important; animation: none !important; }
}

body {
  font-family: 'IBM Plex Sans', -apple-system, Segoe UI, Roboto, sans-serif;
  max-width: 1180px;
  margin: 0 auto;
  padding: 0 1.25rem 4rem;
  line-height: 1.6;
  color: var(--text);
  background: var(--bg);
  font-size: 15px;
}

.mono { font-family: 'IBM Plex Mono', ui-monospace, monospace; }

/* ---- Page header ---- */
.page-header {
  padding: 2rem 0 1.25rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 1.5rem;
}
.page-header .eyebrow {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.72rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--text-faint);
  margin: 0 0 0.4rem;
}
h1 { font-size: 1.6rem; font-weight: 700; margin: 0 0 0.35rem; letter-spacing: -0.01em; }
.page-header .meta { color: var(--text-dim); font-size: 0.85rem; margin: 0; }
.back-link {
  display: inline-block; margin-bottom: 1rem; color: var(--link);
  font-family: 'IBM Plex Mono', monospace; font-size: 0.82rem; text-decoration: none;
}
.back-link:hover { text-decoration: underline; }

/* ---- Sticky quick nav ---- */
.quick-nav {
  position: sticky; top: 0; z-index: 10;
  display: flex; gap: 0.5rem; flex-wrap: wrap;
  background: rgba(15, 20, 25, 0.92);
  backdrop-filter: blur(6px);
  padding: 0.75rem 0;
  border-bottom: 1px solid var(--border);
  margin-bottom: 2rem;
}
.quick-nav a {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.78rem;
  color: var(--text-dim);
  text-decoration: none;
  padding: 0.35rem 0.75rem;
  border: 1px solid var(--border);
  border-radius: 999px;
  transition: border-color 0.15s, color 0.15s;
}
.quick-nav a:hover { border-color: var(--link); color: var(--text); }

/* ---- Section headers (news rows + vuln tracking) ---- */
.row-header {
  display: flex; align-items: baseline; gap: 0.65rem;
  margin: 3rem 0 0.9rem; scroll-margin-top: 4.5rem;
}
.row-header .dot { width: 8px; height: 8px; border-radius: 50%; flex: none; }
.row-header h2 {
  margin: 0; font-size: 0.78rem; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.1em; color: var(--text);
  border: none; padding: 0;
}
.row-header .count {
  font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem; color: var(--text-faint);
}
.row-security .dot { background: var(--row-security); }
.row-database .dot { background: var(--row-database); }
.row-cloud .dot { background: var(--row-cloud); }

/* ---- Raw news columns (horizontal scroll) ---- */
.news-grid-wrapper { overflow-x: auto; -webkit-overflow-scrolling: touch; margin: 0 0 1rem; padding-bottom: 0.6rem; }
.news-grid { display: flex; gap: 1rem; width: max-content; }
.news-column {
  flex: 0 0 270px; background: var(--surface); border: 1px solid var(--border);
  border-top: 2px solid var(--row-accent, var(--border)); border-radius: 8px; padding: 0.9rem 1rem;
}
.row-security .news-column { --row-accent: var(--row-security); }
.row-database .news-column { --row-accent: var(--row-database); }
.row-cloud .news-column { --row-accent: var(--row-cloud); }
.news-column h4 {
  margin: 0 0 0.65rem; font-size: 0.82rem; font-weight: 600; color: var(--text);
  border: none; background: none; padding: 0;
}
.news-column ul { list-style: none; padding: 0; margin: 0; }
.news-column li { padding: 0.5rem 0; border-bottom: 1px solid var(--border); }
.news-column li:last-child { border-bottom: none; }
.news-column a { color: var(--text); text-decoration: none; font-size: 0.87rem; line-height: 1.45; }
.news-column a:hover { color: var(--link); }
.news-column .item-date {
  display: block; font-family: 'IBM Plex Mono', monospace; color: var(--text-faint);
  font-size: 0.7rem; margin-top: 0.25rem;
}

/* ---- Vulnerability tracking section ---- */
h2 { margin: 3rem 0 0.5rem; font-size: 1.15rem; font-weight: 700; color: var(--text); border: none; padding: 0; scroll-margin-top: 4.5rem; }
h2 + p { color: var(--text-dim); margin-top: 0; margin-bottom: 1.25rem; max-width: 68ch; }
h3 {
  margin: 2rem 0 0.9rem; font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.1em; color: var(--text-faint); border: none;
}
p { margin: 0.6rem 0; }
a { color: var(--link); }
ul { padding-left: 1.3rem; margin: 0.6rem 0; }
li { margin: 0.3rem 0; }

/* Incident (vuln) cards */
.vuln-card {
  background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--sev-unscored);
  border-radius: 6px; padding: 1rem 1.15rem; margin-bottom: 1rem;
}
.vuln-card.sev-critical { border-left-color: var(--sev-critical); }
.vuln-card.sev-high { border-left-color: var(--sev-high); }
.vuln-card.sev-medium { border-left-color: var(--sev-medium); }
.vuln-card.sev-low { border-left-color: var(--sev-low); }
.vuln-card-head { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; margin-bottom: 0.7rem; }
.vuln-system { font-weight: 600; font-size: 0.95rem; color: var(--text); }
.badge {
  font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem; padding: 0.18rem 0.55rem;
  border-radius: 4px; white-space: nowrap; font-weight: 500;
}
.badge-cve { background: var(--surface-2); color: var(--text-dim); border: 1px solid var(--border); }
.badge-cvss { color: var(--bg); font-weight: 600; }
.badge-cvss.sev-critical { background: var(--sev-critical); }
.badge-cvss.sev-high { background: var(--sev-high); }
.badge-cvss.sev-medium { background: var(--sev-medium); }
.badge-cvss.sev-low { background: var(--sev-low); color: var(--text); }
.badge-cvss.sev-unscored { background: var(--surface-2); color: var(--text-dim); border: 1px solid var(--border); }
.badge-kev {
  background: rgba(255, 93, 93, 0.15); color: var(--sev-critical); border: 1px solid rgba(255, 93, 93, 0.4);
  text-transform: uppercase; letter-spacing: 0.04em; font-size: 0.68rem;
}
.vuln-card-body p { color: var(--text-dim); font-size: 0.9rem; }
.vuln-card-body strong { color: var(--text); }
.vuln-card-body ul { font-size: 0.9rem; color: var(--text-dim); }
.vuln-card-body a { word-break: break-word; }
h4.mention-group {
  margin: 1.5rem 0 0.5rem; font-size: 0.82rem; font-weight: 600; color: var(--text);
  border: none; background: none; padding: 0;
}

/* ---- Archive ---- */
.archive-list { list-style: none; padding: 0; display: flex; flex-wrap: wrap; gap: 0.5rem; }
.archive-list li { margin: 0; }
.archive-list a {
  display: inline-block; font-family: 'IBM Plex Mono', monospace; font-size: 0.78rem;
  color: var(--text-dim); text-decoration: none; padding: 0.4rem 0.8rem;
  border: 1px solid var(--border); border-radius: 6px; transition: border-color 0.15s, color 0.15s;
}
.archive-list a:hover { border-color: var(--link); color: var(--text); }

@media (max-width: 640px) {
  body { font-size: 14px; }
  h1 { font-size: 1.3rem; }
  .quick-nav { overflow-x: auto; flex-wrap: nowrap; }
}
"""


def render_raw_news_columns_html(grouped_items: dict) -> str:
    """Render the Top section: every raw item from every configured feed, in columns
    by source. No filtering, no LLM -- this is deliberately just formatting."""
    if not grouped_items:
        return "<p><em>No news items collected this run.</em></p>"

    columns = []
    for source, items in sorted(grouped_items.items()):
        list_items = []
        for item in items:
            title = html_mod.escape(item.get("title", "(untitled)"))
            link = html_mod.escape(item.get("link", "#"))
            pub = item.get("published") or ""
            list_items.append(
                f'<li><a href="{link}">{title}</a><span class="item-date">{html_mod.escape(pub)}</span></li>'
            )
        columns.append(
            f'<div class="news-column"><h4>{html_mod.escape(source)}</h4><ul>{"".join(list_items)}</ul></div>'
        )

    return f'<div class="news-grid-wrapper"><div class="news-grid">{"".join(columns)}</div></div>'


def _row_header(anchor_id: str, label: str, count: int, row_class: str) -> str:
    """One news row's header: a colored dot (keyed to that row's accent), the label,
    and an item count -- used identically on the daily report page and the index."""
    noun = "item" if count == 1 else "items"
    return (
        f'<div class="row-header {row_class}" id="{anchor_id}">'
        f'<span class="dot"></span><h2>{html_mod.escape(label)}</h2>'
        f'<span class="count">{count} {noun}</span></div>'
    )


def _count_news_items(grouped_html: str) -> int:
    """Cheap item count for the row header, from already-rendered column HTML."""
    return grouped_html.count('<li><a href=')


QUICK_NAV = """<nav class="quick-nav">
<a href="#security-news">Security</a>
<a href="#database-news">Database</a>
<a href="#cloud-news">Cloud</a>
<a href="#vuln-tracking">Vulnerabilities</a>
<a href="#archive">Archive</a>
</nav>"""


def write_report_page(security_news_html: str, database_news_html: str, cloud_news_html: str,
                       bottom_report_md: str, date_str: str, docs_dir: str) -> str:
    reports_dir = os.path.join(docs_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    bottom_html = markdown_to_html(bottom_report_md)
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Digest — {date_str}</title>
<style>{PAGE_CSS}</style>
</head>
<body>
<a class="back-link" href="../index.html">&larr; All reports</a>
<div class="page-header">
<p class="eyebrow">Daily Digest</p>
<h1>Security Digest — {date_str}</h1>
</div>
{QUICK_NAV}
{_row_header("security-news", "Security News", _count_news_items(security_news_html), "row-security")}
{security_news_html}
{_row_header("database-news", "Database News", _count_news_items(database_news_html), "row-database")}
{database_news_html}
{_row_header("cloud-news", "Cloud News", _count_news_items(cloud_news_html), "row-cloud")}
{cloud_news_html}
<h2 id="vuln-tracking" style="scroll-margin-top:4.5rem;">Scoped Vulnerability Tracking</h2>
{bottom_html}
</body>
</html>"""

    rel_path = f"reports/{date_str}.html"
    with open(os.path.join(docs_dir, rel_path), "w") as f:
        f.write(page)
    return rel_path


def rebuild_dashboard_index(docs_dir: str, latest_date: str, security_news_html: str,
                             database_news_html: str, cloud_news_html: str, bottom_report_md: str):
    reports_dir = os.path.join(docs_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    existing = sorted(
        (f[:-5] for f in os.listdir(reports_dir) if f.endswith(".html")),
        reverse=True,
    )
    archive_items = "\n".join(
        f'<li><a href="reports/{d}.html">{d}</a></li>' for d in existing if d != latest_date
    )

    bottom_html = markdown_to_html(bottom_report_md)

    index = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Digest</title>
<style>{PAGE_CSS}</style>
</head>
<body>
<div class="page-header">
<p class="eyebrow">Updated daily</p>
<h1>Security Digest</h1>
<p class="meta">Latest run: {latest_date}</p>
</div>
{QUICK_NAV}
{_row_header("security-news", "Security News", _count_news_items(security_news_html), "row-security")}
{security_news_html}
{_row_header("database-news", "Database News", _count_news_items(database_news_html), "row-database")}
{database_news_html}
{_row_header("cloud-news", "Cloud News", _count_news_items(cloud_news_html), "row-cloud")}
{cloud_news_html}
<h2 id="vuln-tracking" style="scroll-margin-top:4.5rem;">Scoped Vulnerability Tracking</h2>
{bottom_html}
<h2 id="archive" style="scroll-margin-top:4.5rem;">Archive</h2>
<ul class="archive-list">
{archive_items}
</ul>
</body>
</html>"""

    with open(os.path.join(docs_dir, "index.html"), "w") as f:
        f.write(index)

    nojekyll_path = os.path.join(docs_dir, ".nojekyll")
    if not os.path.exists(nojekyll_path):
        open(nojekyll_path, "w").close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    general_items, collected_by_scope, news_by_scope = collect_all()

    date_str = datetime.date.today().isoformat()
    os.makedirs("reports", exist_ok=True)

    # Security row reuses general_items (already fetched in collect_all() since scope
    # news-matching also depends on it). Database and Cloud rows are fetched fresh here
    # since nothing else in the pipeline needs them.
    security_grouped = group_items_by_source(general_items)
    security_news_html = render_raw_news_columns_html(security_grouped)

    print("\n[*] Fetching Database news feeds (for the unfiltered Database row)...")
    database_items = fetch_feed_list(DATABASE_NEWS_FEEDS, "Database")
    database_news_html = render_raw_news_columns_html(group_items_by_source(database_items))

    print("\n[*] Fetching Cloud news feeds (for the unfiltered Cloud row)...")
    cloud_items = fetch_feed_list(CLOUD_NEWS_FEEDS, "Cloud")
    cloud_news_html = render_raw_news_columns_html(group_items_by_source(cloud_items))

    # One LLM call PER SCOPE (not one giant combined call -- see comment above
    # build_prompt_for_scope for why). Each scope's failure is isolated: if the
    # Database scope's LLM call fails after all retries, Cloud Security's report
    # still gets published, and so does the Top News section (which never touches
    # the LLM at all). The whole run only ever fails to produce a DASHBOARD if
    # literally every scope has nothing to report AND every LLM call failed --
    # and even then, main() still runs to completion and commits what it has.
    scope_reports = []
    any_scope_had_data = False
    any_scope_failed = False

    for scope_name in SCOPES:
        collected = collected_by_scope.get(scope_name, {})
        news = news_by_scope.get(scope_name, {})

        if not collected and not news:
            print(f"[i] {scope_name}: nothing to report this run, skipping LLM call")
            continue

        any_scope_had_data = True
        prompt = build_prompt_for_scope(scope_name, collected, news)
        total_entries = sum(len(v) for v in collected.values()) + sum(len(v) for v in news.values())

        result = call_llm(prompt, expected_entry_count=total_entries, label=scope_name)

        if result is None:
            any_scope_failed = True
            cve_count = sum(len(v) for v in collected.values())
            news_count = sum(len(v) for v in news.values())
            scope_reports.append(
                f"## {scope_name}\n\n"
                f"*Report generation failed for this scope after multiple retries -- see the "
                f"Action log for details. Raw data was still collected successfully: "
                f"{cve_count} formal vulnerability entries and {news_count} news/forum mentions "
                f"across this scope's systems, just not yet turned into a written report.*"
            )
        else:
            scope_reports.append(result)

    if not any_scope_had_data:
        bottom_md = (
            "No new CVEs, KEV entries, or scope-matched news/forum mentions found "
            "for any tracked scope in the configured lookback windows."
        )
    else:
        bottom_md = "\n\n".join(scope_reports)

    md_out_path = f"reports/{date_str}.md"
    with open(md_out_path, "w") as f:
        f.write(f"# Security Digest — {date_str}\n\n{bottom_md}")
    print(f"[i] Markdown archive written to {md_out_path}")

    docs_dir = "docs"
    write_report_page(security_news_html, database_news_html, cloud_news_html, bottom_md, date_str, docs_dir)
    rebuild_dashboard_index(docs_dir, date_str, security_news_html, database_news_html, cloud_news_html, bottom_md)
    print(f"[i] Dashboard updated: {docs_dir}/index.html")

    if any_scope_failed:
        # Exit non-zero so the Action run shows as failed/degraded in GitHub's UI --
        # you should notice and check the log -- but ONLY after everything that could
        # be published already has been. This is different from the old behavior,
        # which lost the entire day's output (including working scopes) on any single
        # LLM failure.
        print("[!] One or more scopes failed to generate a report this run (see above). "
              "Dashboard was still updated with everything that succeeded.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
