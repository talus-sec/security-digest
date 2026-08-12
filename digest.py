#!/usr/bin/env python3
"""
Daily DB Security Digest
Pulls new/updated CVEs for MySQL, PostgreSQL, Oracle Database, and NoSQL
(MongoDB, Redis, Cassandra) from the NVD API, cross-references CISA's KEV
catalog for confirmed-but-unscored exploited bugs, and pulls matching news/
forum chatter via RSS. An LLM via OpenRouter's free router turns all of it
into one structured Markdown report:
  - Summary
  - Affected Features / App Interoperability
  - Source
  - Actions (fix + workarounds + what workarounds break)
  - News & Community Mentions (separate section, not treated as authoritative)

Delivery: writes each day's report to docs/reports/YYYY-MM-DD.html and rebuilds
docs/index.html, which GitHub Pages serves as a free, no-app dashboard -- the
latest report shown in full up top, with a linked archive of every past day
below it. The raw Markdown is also kept in reports/YYYY-MM-DD.md for reference.

Why CISA KEV matters: a CVE can sit in NVD as "awaiting analysis" with NO CVSS
score for days or weeks. KEV doesn't wait for a score -- a CVE is added the
moment CISA confirms real-world exploitation. This script checks KEV on its
own lookback window (by date-added, not NVD's lastModified) so an actively
exploited-but-unscored bug never gets missed.

Why RSS matters: NVD/KEV only tell you what's been formally logged. News
outlets and forums (Reddit, Hacker News, security blogs) often report on
exploitation, PoCs, or vendor advisories before/alongside the formal CVE
record catches up, or add context NVD never includes. These are pulled
into a clearly-separated section and never used to fabricate CVE data.

Why OpenRouter: it's a single free API key with no Google Cloud project
setup, no billing account, no credit card. It routes to whichever model is
currently in its free pool via the "openrouter/free" router, which is what
this script uses -- you don't have to track which specific model is free
this week.

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
import datetime
import email.utils
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OPENROUTER_MODEL = "openrouter/free"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Keyword searches run against NVD's keywordSearch param.
TARGETS = {
    "MySQL": "MySQL",
    "PostgreSQL": "PostgreSQL",
    "Oracle Database": "Oracle Database",
    "Microsoft SQL Server": "Microsoft SQL Server",
    "MongoDB": "MongoDB",
    "Redis": "Redis",
    "Cassandra": "Cassandra",
}

# Loose substring match against KEV's vendorProject/product/vulnerabilityName fields.
KEV_MATCH_TERMS = {
    "MySQL": ["mysql"],
    "PostgreSQL": ["postgres"],
    "Microsoft SQL Server": ["sql server", "mssql"],
    "Oracle Database": ["oracle database", "oracle db"],
    "MongoDB": ["mongodb", "mongo"],
    "Redis": ["redis"],
    "Cassandra": ["cassandra"],
}

# Same substring buckets, reused for classifying RSS items by DB system.
NEWS_MATCH_TERMS = KEV_MATCH_TERMS

# Fixed security-news/forum feeds checked every run, plus a per-DB Google News
# search feed generated below. Add your own forum RSS URLs via CUSTOM_RSS_FEEDS.
STATIC_NEWS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://krebsonsecurity.com/feed/",
    "https://www.reddit.com/r/database/.rss",
    "https://www.reddit.com/r/sysadmin/search.rss?q=vulnerability&sort=new&restrict_sr=on",
]

LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "26"))
KEV_LOOKBACK_DAYS = int(os.environ.get("KEV_LOOKBACK_DAYS", "7"))
NEWS_LOOKBACK_HOURS = int(os.environ.get("NEWS_LOOKBACK_HOURS", "48"))
ENABLE_NEWS_FEEDS = os.environ.get("ENABLE_NEWS_FEEDS", "true").lower() != "false"


def http_get(url: str, headers: dict = None, timeout: int = 30, retries: int = 2):
    """GET with a couple of retries on transient failure. Returns raw bytes or None."""
    headers = headers or {}
    headers.setdefault("User-Agent", "db-security-digest/1.0 (+https://github.com/)")
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


def kev_fetch() -> list:
    """Pull CISA's full KEV catalog and return entries added within the lookback window."""
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


def match_kev_to_targets(kev_entries: list) -> dict:
    matched = {}
    for vuln in kev_entries:
        haystack = " ".join([
            vuln.get("vendorProject", ""),
            vuln.get("product", ""),
            vuln.get("vulnerabilityName", ""),
            vuln.get("shortDescription", ""),
        ]).lower()

        for label, terms in KEV_MATCH_TERMS.items():
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


# ---------- RSS / news & forum ingestion ----------

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


def parse_feed(url: str) -> list:
    """Minimal stdlib RSS 2.0 / Atom parser. Returns list of {title, link, published, summary, source}."""
    raw = http_get(url, timeout=20)
    if raw is None:
        return []

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        print(f"  [!] RSS parse failed for {url}: {e}", file=sys.stderr)
        return []

    items = []
    source = urllib.parse.urlparse(url).netloc

    # RSS 2.0: <rss><channel><item>...
    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub = item.findtext("pubDate")
        summary = (item.findtext("description") or "").strip()
        items.append({"title": title, "link": link, "published": pub, "summary": summary[:500], "source": source})

    # Atom: <feed><entry>...
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    for entry in root.findall(".//atom:entry", ns):
        title = (entry.findtext("atom:title", namespaces=ns) or "").strip()
        link_el = entry.find("atom:link", ns)
        link = link_el.get("href") if link_el is not None else ""
        pub = entry.findtext("atom:updated", namespaces=ns) or entry.findtext("atom:published", namespaces=ns)
        summary = (entry.findtext("atom:summary", namespaces=ns) or "").strip()
        items.append({"title": title, "link": link, "published": pub, "summary": summary[:500], "source": source})

    return items


def build_google_news_feeds() -> list:
    """One Google News RSS search feed per DB system, scoped to security terms."""
    feeds = []
    for label, keyword in TARGETS.items():
        q = urllib.parse.quote(f'"{keyword}" (vulnerability OR exploit OR CVE OR security patch)')
        feeds.append(f"https://news.google.com/rss/search?q={q}%20when:2d&hl=en-US&gl=US&ceid=US:en")
    return feeds


def collect_news() -> dict:
    """Fetch all configured feeds, filter by recency + DB keyword match, bucket by system."""
    if not ENABLE_NEWS_FEEDS:
        print("[i] ENABLE_NEWS_FEEDS=false, skipping RSS/news collection")
        return {}

    feed_urls = list(STATIC_NEWS_FEEDS) + build_google_news_feeds()
    custom = os.environ.get("CUSTOM_RSS_FEEDS", "").strip()
    if custom:
        feed_urls += [u.strip() for u in custom.split(",") if u.strip()]

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=NEWS_LOOKBACK_HOURS)
    matched = {}
    seen_links = set()

    for url in feed_urls:
        print(f"[*] Fetching news feed: {url}")
        for item in parse_feed(url):
            link = item.get("link")
            if not link or link in seen_links:
                continue

            pub_dt = _parse_rss_datetime(item.get("published"))
            if pub_dt and pub_dt < cutoff:
                continue  # too old, skip (undated items are kept -- better a false positive than a miss)

            haystack = f"{item.get('title', '')} {item.get('summary', '')}".lower()
            for label, terms in NEWS_MATCH_TERMS.items():
                if any(term in haystack for term in terms):
                    matched.setdefault(label, []).append({
                        "title": item["title"],
                        "link": link,
                        "published": item.get("published"),
                        "summary": item.get("summary"),
                        "source": item.get("source"),
                    })
                    seen_links.add(link)
                    break  # one bucket per item is enough
        time.sleep(1)  # light politeness pause between feeds

    total = sum(len(v) for v in matched.values())
    print(f"[i] {total} news/forum item(s) matched across all feeds")
    return matched


# ---------- collection orchestration ----------

def sort_entries_for_report(collected: dict) -> dict:
    """Sort each system's entries so the LLM never has to reason about ordering:
    KEV-confirmed first, then descending CVSS score (unscored entries sort last).
    This is the fix for a real failure mode we hit: asking a free model to sort
    a long list of entries itself caused it to think out loud in the output
    instead of just answering, producing a huge repetitive non-report.

    Also caps each system to MAX_ENTRIES_PER_SYSTEM after sorting -- a free model
    handling 25+ entries for one system in a single prompt is exactly the kind of
    prompt size that triggered the reasoning-loop failure. KEV-confirmed entries
    are always kept regardless of the cap; only lower-priority overflow is trimmed."""
    MAX_ENTRIES_PER_SYSTEM = 12

    for label, entries in collected.items():
        entries.sort(
            key=lambda e: (
                not e.get("confirmed_exploited_by_cisa_kev", False),  # False sorts before True -> KEV first
                -(e.get("cvss_score") or -1),  # higher score first; None/unscored goes last
                e.get("id", ""),
            )
        )
        if len(entries) > MAX_ENTRIES_PER_SYSTEM:
            kept = entries[:MAX_ENTRIES_PER_SYSTEM]
            dropped = len(entries) - len(kept)
            print(f"    -> {label}: capping to top {MAX_ENTRIES_PER_SYSTEM} of {len(entries)} "
                  f"by priority ({dropped} lower-severity entries omitted from this run's report; "
                  f"still visible in NVD directly if needed)")
            collected[label] = kept

    return collected


def collect_all() -> tuple:
    collected = {}
    for label, keyword in TARGETS.items():
        print(f"[*] Querying NVD for {label}...")
        entries = nvd_fetch(keyword)
        if entries:
            collected[label] = entries
            print(f"    -> {len(entries)} result(s)")
        else:
            print("    -> none")
        time.sleep(6)  # be polite to the public NVD rate limit

    print("[*] Checking CISA KEV catalog for actively exploited DB vulnerabilities...")
    kev_entries = kev_fetch()
    kev_matched = match_kev_to_targets(kev_entries)
    total_kev_hits = sum(len(v) for v in kev_matched.values())
    print(f"    -> {total_kev_hits} KEV match(es) in the last {KEV_LOOKBACK_DAYS} day(s)")
    collected = merge_kev_into_collected(collected, kev_matched)
    collected = sort_entries_for_report(collected)

    print("[*] Checking news/forum RSS feeds...")
    news = collect_news()

    return collected, news


def build_prompt(collected: dict, news: dict) -> str:
    if not collected and not news:
        return ""

    raw_block = json.dumps(collected, indent=2)
    news_block = json.dumps(news, indent=2) if news else "{}"

    return f"""You are a database security analyst producing a daily internal digest for a
cybersecurity engineer who administers MySQL, PostgreSQL, Oracle Database, and NoSQL
systems (MongoDB, Redis, Cassandra) in a healthcare enterprise environment, and who
also runs a homelab with Postgres/Vault PKI/mTLS infrastructure.

IMPORTANT: Output ONLY the final Markdown report. Do not think out loud, do not show your
reasoning process, do not narrate how you're analyzing or sorting the data. Go straight to
the finished report text.

SECTION 1 -- FORMAL VULNERABILITY DATA (authoritative)
Raw CVE data pulled from NVD for the last {LOOKBACK_HOURS} hours, plus CISA KEV catalog hits for the
last {KEV_LOOKBACK_DAYS} days, grouped by database system. The entries within each system are
ALREADY SORTED in the correct priority order (KEV-confirmed first, then by CVSS descending) --
simply present them in the order given below. Do not re-sort, do not re-evaluate priority, do not
reason about ordering at all. If a system has more than 12 entries in a given day, only the top 12
by priority are included below; lower-severity entries were intentionally omitted to keep this
report focused, not because they don't exist. A KEV match means CISA has confirmed real-world
exploitation -- this OVERRIDES a missing or low CVSS score in terms of urgency. A CVE with no CVSS
score is not necessarily low priority; it may simply be too new for NVD to have scored it,
especially if flagged confirmed_exploited_by_cisa_kev: true.

{raw_block}

SECTION 2 -- NEWS & FORUM MENTIONS (supplementary, NOT authoritative)
Raw RSS items from security news outlets and forums (Reddit, Hacker News, BleepingComputer, Krebs,
Google News) from the last {NEWS_LOOKBACK_HOURS} hours, matched by keyword to each DB system. These
are NOT verified CVE records -- treat them as "worth being aware of" context, not confirmed facts.
Do not invent a CVE number for something that only appears here.

{news_block}

---
Turn this into a clean Markdown report with two parts per database system:

PART A -- Formal Vulnerabilities (from Section 1 data only)
Skip any system with no Section 1 entries. The entries are already given to you in the correct
order (KEV-confirmed first, then by severity) -- present them in that same order, do not resort. For EACH entry:

### [DB System] — [CVE ID] (CVSS [score or "UNSCORED"] [severity]) [add "🔴 ACTIVELY EXPLOITED (CISA KEV)" if confirmed_exploited_by_cisa_kev is true]
**Summary:** Plain-English explanation in 1-3 sentences -- what it is, how it's triggered, who can
exploit it (auth required? network-reachable?). If it's a KEV entry with a due_date, state it.

**Affected Features / App Interoperability:** What specific feature, extension, module, protocol,
or component is impacted, and what downstream functionality or integrations could break (e.g.
replication, client drivers, specific extensions, ORMs, connection pooling). If the raw data doesn't
say, state that plainly rather than guessing.

**Source:** List the reference URL(s).

**Actions:**
- Fix: official patched version/release, if known
- Workaround: concrete interim mitigation if no immediate patch is possible
- Tradeoff: what the workaround itself breaks or degrades. Say "No significant tradeoff" if none.

PART B -- News & Community Mentions (from Section 2 data only, only if that system has any)
A short bullet list per system: one line per item with a 1-sentence plain-English gist, the source
name, and the link. Clearly label this whole part as unverified chatter, separate from Part A.

At the very top of the report, add a one-paragraph executive summary of the single most urgent item
across all systems (Part A items only -- KEV-confirmed beats high-CVSS beats everything else).

Do not fabricate CVE IDs, scores, version numbers, or details beyond what's given above. If data for
an entry is too sparse for a real summary, say so.
"""


def strip_leaked_reasoning(text: str) -> str:
    """Some free/reasoning-tuned models leak their internal chain-of-thought into the
    content field instead of (or before) the real answer, especially on multi-part
    tasks like this one. Strip common patterns as a safety net."""
    import re

    # Explicit <think>...</think> or similar tags some models use
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)

    # If there's a clear Markdown report starting further into the text (a line
    # starting with "# " after some preamble), cut everything before the LAST such
    # occurrence of a top-level heading that looks like the actual report title --
    # this handles a model that "thinks out loud" then finally writes the report.
    lines = text.split("\n")
    report_start_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith("# ") and ("digest" in line.lower() or "security" in line.lower()):
            report_start_idx = i  # keep the LAST match, in case of repeated false starts
    if report_start_idx is not None and report_start_idx > 0:
        text = "\n".join(lines[report_start_idx:])

    return text.strip()


def looks_like_broken_reasoning_dump(text: str, expected_entry_count: int) -> bool:
    """Heuristic check for the known failure mode: a model looping through analysis
    instead of producing a clean report. Flags responses that are suspiciously long
    relative to the data size, or that repeat the same short phrase many times."""
    if len(text) > max(20000, expected_entry_count * 800):
        return True

    # Repeated-phrase detector: if any single line appears an excessive number of
    # times, that's a strong signal of a stuck reasoning loop rather than a report.
    lines = [l.strip() for l in text.split("\n") if l.strip()]
    if lines:
        from collections import Counter
        counts = Counter(lines)
        most_common_line, most_common_count = counts.most_common(1)[0]
        if most_common_count > 15 and len(most_common_line) < 200:
            return True

    return False


def call_llm(prompt: str, expected_entry_count: int = 0) -> str:
    """Call OpenRouter's free-model router (OpenAI-compatible chat completions format)."""
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        print("[!] OPENROUTER_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    body = {
        "model": OPENROUTER_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 8192,
        # Ask providers that support it to keep chain-of-thought out of the response
        # entirely, rather than mixed into the content field we actually use.
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
                # Optional but recommended by OpenRouter for attribution/rate-limit context
                "HTTP-Referer": "https://github.com/",
                "X-Title": "db-security-digest",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                data = json.loads(resp.read().decode())
            content = data["choices"][0]["message"]["content"]
            content = strip_leaked_reasoning(content)

            if looks_like_broken_reasoning_dump(content, expected_entry_count):
                last_err = "response looked like a stuck reasoning loop, not a report"
                print(f"  [!] Attempt {attempt + 1}: {last_err}, retrying...", file=sys.stderr)
                if attempt < 2:
                    time.sleep(10)
                    continue
                # Out of retries -- return what we have rather than nothing, but the
                # length cap keeps a broken response from becoming a multi-MB commit.
                return content[:5000] + "\n\n*(Report was truncated -- the model's response looked malformed. Check the Action log.)*"

            return content
        except urllib.error.HTTPError as e:
            err_body = e.read().decode() if e.fp else ""
            last_err = f"{e.code} {e.reason} {err_body}"
            # 429 = rate limited, 5xx = transient upstream issue -- both worth a retry
            if e.code in (429, 500, 502, 503) and attempt < 2:
                time.sleep(15 * (attempt + 1))
                continue
            break
        except (KeyError, IndexError) as e:
            last_err = f"unexpected response shape: {e}"
            break
        except Exception as e:
            last_err = str(e)
            if attempt < 2:
                time.sleep(15 * (attempt + 1))
                continue
            break

    print(f"[!] OpenRouter call failed: {last_err}", file=sys.stderr)
    sys.exit(1)


def markdown_to_html(md: str) -> str:
    """Minimal, dependency-free Markdown -> HTML converter, tuned to what this script's
    LLM prompt actually produces (headers, bold, bullet lists, links, bare URLs, emoji).
    Not a general-purpose Markdown engine -- just enough for this report's structure."""
    import re
    import html as html_mod

    lines = md.split("\n")
    out = []
    in_list = False

    def inline(text: str) -> str:
        text = html_mod.escape(text)
        text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
        # Markdown-style links first, so bare-URL linkification below doesn't double-wrap them
        text = re.sub(r"\[([^\]]+)\]\((https?://[^\s)]+)\)", r'<a href="\2">\1</a>', text)
        text = re.sub(
            r'(?<!href=")(?<!>)(https?://[^\s<]+)',
            r'<a href="\1">\1</a>',
            text,
        )
        return text

    for raw_line in lines:
        line = raw_line.rstrip()
        stripped = line.strip()

        if stripped.startswith("### "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<h3>{inline(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<h2>{inline(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<h1>{inline(stripped[2:])}</h1>")
        elif stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(stripped[2:])}</li>")
        elif stripped == "":
            if in_list:
                out.append("</ul>")
                in_list = False
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<p>{inline(stripped)}</p>")

    if in_list:
        out.append("</ul>")

    return "\n".join(out)


PAGE_CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 900px;
       margin: 2rem auto; padding: 0 1rem; line-height: 1.55; color: #1a1a1a; background: #fafafa; }
h1 { border-bottom: 3px solid #c0392b; padding-bottom: 0.4rem; }
h2 { margin-top: 2rem; color: #c0392b; }
h3 { margin-top: 1.5rem; background: #fff; padding: 0.5rem 0.75rem; border-left: 4px solid #c0392b;
     border-radius: 2px; }
a { color: #2980b9; }
ul { padding-left: 1.4rem; }
li { margin: 0.3rem 0; }
.archive-list { list-style: none; padding-left: 0; }
.archive-list li { padding: 0.5rem 0; border-bottom: 1px solid #ddd; }
.archive-list a { font-weight: 600; text-decoration: none; font-size: 1.05rem; }
.back-link { display: inline-block; margin-bottom: 1rem; }
"""


def write_report_page(report_md: str, date_str: str, docs_dir: str) -> str:
    """Write one date's report as a standalone HTML page. Returns the relative path."""
    reports_dir = os.path.join(docs_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    body_html = markdown_to_html(report_md)
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DB Security Digest — {date_str}</title>
<style>{PAGE_CSS}</style>
</head>
<body>
<a class="back-link" href="../index.html">&larr; All reports</a>
{body_html}
</body>
</html>"""

    rel_path = f"reports/{date_str}.html"
    with open(os.path.join(docs_dir, rel_path), "w") as f:
        f.write(page)
    return rel_path


def rebuild_dashboard_index(docs_dir: str, latest_date: str, latest_report_md: str):
    """Rebuild docs/index.html: latest report shown in full, plus a linked archive list
    of every past report found in docs/reports/."""
    reports_dir = os.path.join(docs_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    existing = sorted(
        (f[:-5] for f in os.listdir(reports_dir) if f.endswith(".html")),
        reverse=True,
    )

    archive_items = "\n".join(
        f'<li><a href="reports/{d}.html">{d}</a></li>' for d in existing if d != latest_date
    )

    latest_html = markdown_to_html(latest_report_md)

    index = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DB Security Digest</title>
<style>{PAGE_CSS}</style>
</head>
<body>
<p style="color:#666;">Updated daily &middot; latest run: {latest_date}</p>
{latest_html}
<h2>Archive</h2>
<ul class="archive-list">
{archive_items}
</ul>
</body>
</html>"""

    with open(os.path.join(docs_dir, "index.html"), "w") as f:
        f.write(index)

    # Tells GitHub Pages not to run Jekyll processing on this folder -- we're serving
    # plain static HTML we generated ourselves, so Jekyll would only get in the way.
    nojekyll_path = os.path.join(docs_dir, ".nojekyll")
    if not os.path.exists(nojekyll_path):
        open(nojekyll_path, "w").close()


def main():
    collected, news = collect_all()

    date_str = datetime.date.today().isoformat()
    os.makedirs("reports", exist_ok=True)
    out_path = f"reports/{date_str}.md"

    if not collected and not news:
        report = (
            f"# DB Security Digest — {date_str}\n\n"
            f"No new CVEs, KEV entries, or news/forum mentions found for tracked systems "
            f"in the configured lookback windows."
        )
    else:
        prompt = build_prompt(collected, news)
        total_entries = sum(len(v) for v in collected.values()) + sum(len(v) for v in news.values())
        body = call_llm(prompt, expected_entry_count=total_entries)
        report = f"# DB Security Digest — {date_str}\n\n{body}"

    with open(out_path, "w") as f:
        f.write(report)
    print(f"[i] Report written to {out_path}")

    docs_dir = "docs"
    write_report_page(report, date_str, docs_dir)
    rebuild_dashboard_index(docs_dir, date_str, report)
    print(f"[i] Dashboard updated: {docs_dir}/index.html")


if __name__ == "__main__":
    main()
