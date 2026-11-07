#!/usr/bin/env python3
"""Free Legal Compute Hunter: read public catalogs + check explicitly supplied policy links.

No mining, port scanning, account creation, login, IP scanning, or provider exploitation.
Only fetch public HTTP(S) documentation, respect robots.txt, with conservative limits.
No paid API or third-party Python packages are required.
"""
from __future__ import annotations
import argparse
import csv
import html
import json
import re
import ssl
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.robotparser import RobotFileParser

ROOT = Path(__file__).resolve().parent
CATALOG_URL = 'https://raw.githubusercontent.com/ripienaar/free-for-dev/master/README.md'
USER_AGENT = 'FreeLegalComputeHunter/0.1 (+public-policy-research; no-device-scan)'
WATCH_SECTIONS = {'Major Cloud Providers', 'IaaS', 'PaaS', 'Web Hosting', 'CI and CD', 'Docker Related', 'APIs, Data and ML'}
MAX_DOWNLOAD = 800_000
PROHIBIT = [
    r'(?:prohibit|forbid|disallow|not allow|must not|may not|is not permitted|strictly prohibited)[^.!?\n]{0,120}(?:cryptocurrency|crypto(?:\s|-)?mining|cryptomining)',
    r'(?:cryptocurrency|crypto(?:\s|-)?mining|cryptomining)[^.!?\n]{0,90}(?:prohibit|forbid|disallow|not allowed|not permitted|strictly prohibited)',
]
ALLOW = [
    r'(?:cryptocurrency|crypto(?:\s|-)?mining|cryptomining)[^.!?\n]{0,100}(?:not a prohibited activity|is permitted|is allowed)',
    r'(?:allow|permit)[^.!?\n]{0,80}(?:cryptocurrency|cryptomining|crypto(?:\s|-)?mining)',
]


def fetch(url: str, timeout: int = 15, robots: bool = True) -> str:
    p = urlparse(url)
    if p.scheme != 'https' or not p.hostname:
        raise ValueError('Only public HTTPS URLs are supported')
    if robots:
        rp = RobotFileParser()
        rp.set_url(f'{p.scheme}://{p.netloc}/robots.txt')
        try:
            rp.read()
        except Exception as exc:
            raise RuntimeError('robots.txt could not be checked') from exc
        if not rp.can_fetch(USER_AGENT, url):
            raise PermissionError('Blocked by robots.txt')
    req = Request(url, headers={'User-Agent': USER_AGENT, 'Accept': 'text/html,text/plain,*/*'})
    with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
        resolved = urlparse(r.geturl())
        if resolved.scheme != 'https':
            raise RuntimeError('Refusing non-HTTPS redirect')
        if 'pdf' in r.headers.get('Content-Type', '').lower():
            raise RuntimeError('PDF requires manual review; not automatically parsed')
        data = r.read(MAX_DOWNLOAD + 1)
        if len(data) > MAX_DOWNLOAD:
            raise RuntimeError('Document too large; ignored')
        charset = r.headers.get_content_charset() or 'utf-8'
        return data.decode(charset, errors='replace')


class TextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.chunks = []
        self.skip = 0
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'noscript'): self.skip += 1
    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'noscript'): self.skip = max(0, self.skip - 1)
    def handle_data(self, data):
        if not self.skip: self.chunks.append(data)


def visible_text(markup: str) -> str:
    parser = TextParser()
    parser.feed(markup)
    return re.sub(r'\s+', ' ', ' '.join(parser.chunks))


def classify(text: str) -> tuple[str, str]:
    """Only triage. Never auto-grant authorization to deploy mining."""
    norm = re.sub(r'\s+', ' ', text.lower())
    # The phrase 'mining is not a prohibited activity' is permission-language,
    # not a prohibition. Classify it before other broad phrase matches.
    explicit_exception = re.search(r'(?:cryptocurrency(?:\s+mining)?|crypto(?:\s|-)?mining|cryptomining)\s+(?:is|are)\s+not\s+(?:a\s+)?prohibited activity', norm, re.I)
    if explicit_exception:
        m = explicit_exception
        return 'possible_permission_review', norm[max(0,m.start()-75):min(len(norm),m.end()+75)]
    for pattern in PROHIBIT:
        m = re.search(pattern, norm, flags=re.I)
        if m:
            return 'possible_prohibition_review', norm[max(0, m.start()-75):min(len(norm), m.end()+75)]
    for pattern in ALLOW:
        m = re.search(pattern, norm, flags=re.I)
        if m:
            return 'possible_permission_review', norm[max(0, m.start()-75):min(len(norm), m.end()+75)]
    return 'no_explicit_mining_permission_found', ''


def parse_catalog(doc: str) -> list[dict]:
    section = ''
    seen = set()
    items = []
    for line in doc.splitlines():
        h = re.match(r'^##\s+(.+?)\s*$', line)
        if h:
            section = h.group(1).strip()
        if section not in WATCH_SECTIONS: continue
        if not re.match(r'^\s*\*\s+', line): continue
        match = re.search(r'\[([^\]]{2,100})\]\((https://[^)]+)\)', line)
        if not match: continue
        name, url = match.groups()
        p = urlparse(url)
        if p.hostname in seen or not p.hostname: continue
        seen.add(p.hostname)
        items.append({'name': name.strip(), 'section': section, 'url': url, 'origin': CATALOG_URL})
    return items


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, columns, extrasaction='ignore')
        writer.writeheader(); writer.writerows(rows)


def read_curated() -> list[dict]:
    with (ROOT/'data'/'reviewed_opportunities.csv').open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def report(curated: list[dict], found: list[dict], checked: list[dict], issue: str) -> None:
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    labels = ('permission_unverified', 'possible_permission_review')
    confirmed = [x for x in curated if x.get('zero_cost_compute') == 'yes' and x.get('verdict') == 'confirmed_mining_allowed_free']
    csvpath = ROOT/'docs'/'candidates.csv'
    write_csv(csvpath, found, ['name', 'section', 'url', 'origin'])
    write_csv(ROOT/'docs'/'public_policy_checks.csv', checked, ['name', 'url', 'result', 'evidence_excerpt', 'error'])
    summary = {
        'generated_utc': now,
        'catalog_discovered_candidates': len(found),
        'manually_reviewed_records': len(curated),
        'free_mining_permissions_confirmed': len(confirmed),
        'public_policy_checks_attempted': len(checked),
        'catalog_fetch_issue': issue,
        'note': 'A keyword match is not authorization. No deployment is performed.'
    }
    (ROOT/'docs'/'summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf8')
    rows = []
    for x in curated:
        url = html.escape(x['source_url'], quote=True)
        rows.append('<tr><td>%s</td><td>%s</td><td>%s</td><td><a href="%s">policy / evidence</a></td><td>%s</td></tr>' % (
            html.escape(x['name']), html.escape(x['zero_cost_compute']),
            html.escape(x['verdict']), url, html.escape(x['notes'])
        ))
    content = f'''<!doctype html><html lang="en"><meta charset="utf-8">
<title>Free Legal Compute Hunter</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font-family:system-ui,sans-serif;max-width:1080px;margin:auto;padding:24px;color:#20242b;background:#fafbfd}}h1{{font-size:1.8rem}}p{{line-height:1.65}}.stat{{display:inline-block;border:1px solid #dfe4ea;border-radius:12px;padding:14px;margin:7px;background:white}}table{{border-collapse:collapse;width:100%;background:white}}td,th{{border-bottom:1px solid #e6e8eb;padding:10px;text-align:left;vertical-align:top;font-size:14px}}th{{background:#f2f5f8}}a{{color:#087a77}}.scroll{{overflow:auto}}.muted{{color:#68717d}}</style>
<h1>Free Legal Compute Hunter</h1>
<p class="muted">Updated: {html.escape(now)}. Research only. No mining, probing devices, or unattended installs.</p>
<div class="stat"><strong>{len(confirmed)}</strong> confirmed zero-cost mining placements</div>
<div class="stat"><strong>{len(found)}</strong> catalog candidates found (not verified)</div>
<div class="stat"><strong>{len(curated)}</strong> curated research records</div>
<p>Findings are not legal advice. Terms can change. A platform's public compute/free plan does not authorize cryptocurrency mining.</p>
<p><a href="candidates.csv">Discovery candidates CSV</a> · <a href="public_policy_checks.csv">Policy keyword checks CSV</a> · <a href="summary.json">Summary JSON</a></p>
<h2>Reviewed evidence</h2><div class="scroll"><table><thead><tr><th>Provider</th><th>Zero-cost compute?</th><th>Verdict</th><th>Source</th><th>Reason</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
<p class="muted">Catalog issue: {html.escape(issue or 'none')}. Policy matches require human review. Do not mine until provider consent is verified.</p>
</html>'''
    (ROOT/'docs'/'index.html').write_text(content, encoding='utf8')
    print(json.dumps(summary, indent=2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-policy-checks', type=int, default=12, help='Maximum curated text documents fetched per run (0 disables)')
    ap.add_argument('--offline', action='store_true', help='Use curated data only, no web requests')
    args = ap.parse_args()
    curated = read_curated()
    candidates, checked, issue = [], [], ''
    if not args.offline:
        try:
            candidates = parse_catalog(fetch(CATALOG_URL, robots=False))
        except Exception as e:
            issue = f'{type(e).__name__}: {str(e)[:160]}'
        for record in curated:
            if len(checked) >= max(0, args.max_policy_checks): break
            url = record['source_url']
            if '.pdf' in url.lower(): continue
            item = {'name': record['name'], 'url': url, 'result': '', 'evidence_excerpt': '', 'error': ''}
            try:
                doc = fetch(url)
                item['result'], item['evidence_excerpt'] = classify(visible_text(doc))
            except Exception as e:
                item['result'] = 'unavailable_requires_manual_review'
                item['error'] = f'{type(e).__name__}: {str(e)[:120]}'
            checked.append(item)
            time.sleep(1.5)  # respectful rate limit
    report(curated, candidates, checked, issue or ('offline mode' if args.offline else ''))


if __name__ == '__main__': main()
