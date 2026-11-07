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


# Additional public free-tier catalogs; these are only discovery directories.
CATALOGS = {
    'free-for-dev': CATALOG_URL,
    'free-services': 'https://raw.githubusercontent.com/dereknguyen269/free-services/main/README.md',
    'free-tier-hub': 'https://raw.githubusercontent.com/ePlus-DEV/free-tier-hub/main/README.md',
}


def parse_secondary_catalog(doc: str, source: str) -> list[dict]:
    """Find public hosting and compute products, not machines or IP addresses."""
    section, results = '', []
    for line in doc.splitlines():
        heading = re.match(r'^#{1,4}\s+(.+)$', line)
        if heading:
            section = heading.group(1).strip()
            continue
        relevant = re.search(r'hosting|compute|vps|serverless|notebook|iaas|paas|container|ai\s*&\s*ml', section, re.I)
        if not relevant and 'at a glance' not in section.lower():
            continue
        if 'at a glance' in section.lower() and not re.search(r'host|compute|worker|vps|gpu|instance|cloud run|container|serverless', line, re.I):
            continue
        if 'self-host' in section.lower() or not line.lstrip().startswith(('|', '* ', '- ')):
            continue
        m = re.search(r'\[([^\]]{2,90})\]\((https://[^)\s]+)\)', line)
        if not m:
            continue
        name, url = m.groups()
        parsed = urlparse(url)
        if not parsed.hostname or parsed.hostname == 'github.com':
            continue
        if name.lower() in ('guide', 'browse', 'docs', 'learn more'):
            continue
        results.append({'name': name, 'section': section, 'url': url, 'origin': source})
    return results


def merge_catalogs(groups: list[list[dict]]) -> list[dict]:
    seen = {}
    for items in groups:
        for item in items:
            host = (urlparse(item['url']).hostname or '').removeprefix('www.')
            if not host:
                continue
            if host in seen:
                seen[host]['mentions'] += 1
                continue
            item = dict(item)
            item['mentions'] = 1
            item['research_priority'] = 'high' if re.search(r'gpu|vps|vm\b|cpu|compute|notebook|iaas', item['name'] + ' ' + item['section'], re.I) else 'normal'
            item['mining_permission'] = 'unverified'
            seen[host] = item
    return sorted(seen.values(), key=lambda r: (r['research_priority'] != 'high', -r['mentions'], r['name'].lower()))


class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            value = dict(attrs).get('href')
            if value:
                self.hrefs.append(value)


def discover_policy_links(markup: str, url: str) -> list[str]:
    """Only follows legal/terms links advertised by the provider on its homepage."""
    from urllib.parse import urljoin
    parser = LinkExtractor()
    parser.feed(markup)
    origin_host = (urlparse(url).hostname or '').removeprefix('www.')
    results = []
    for href in parser.hrefs:
        if not re.search(r'(?:aup|acceptable.use|terms|policy|policies|legal)', href, re.I):
            continue
        link = urljoin(url, href).split('#')[0]
        p = urlparse(link)
        host = (p.hostname or '').removeprefix('www.')
        if p.scheme == 'https' and (host == origin_host or host.endswith('.' + origin_host)) and link not in results:
            results.append(link)
    return results[:3]


def review_next_candidates(candidates: list[dict], count: int) -> list[dict]:
    """Small, rotating public policy review. Never log in, probe, or deploy."""
    if not candidates or count <= 0:
        return []
    state_file = ROOT/'docs'/'scan_state.json'
    try:
        cursor = int(json.loads(state_file.read_text(encoding='utf8')).get('cursor', 0))
    except (OSError, ValueError, TypeError):
        cursor = 0
    rows = []
    for j in range(min(count, len(candidates))):
        item = candidates[(cursor+j) % len(candidates)]
        original = urlparse(item['url'])
        home = f'https://{original.netloc}/'
        row = {'name':item['name'], 'homepage':home, 'policy_url':'', 'triage':'unknown', 'evidence_excerpt':'', 'error':''}
        try:
            html_page = fetch(home)
            links = discover_policy_links(html_page, home)
            if links:
                row['policy_url'] = links[0]
                text_doc = fetch(links[0])
                row['triage'], row['evidence_excerpt'] = classify(visible_text(text_doc))
            else:
                row['triage'] = 'no_homepage_policy_link'
        except Exception as exc:
            row['triage'] = 'manual_review_required'
            row['error'] = f'{type(exc).__name__}: {str(exc)[:130]}'
        rows.append(row)
        time.sleep(1.0)
    state_file.write_text(json.dumps({'cursor': (cursor+len(rows)) % len(candidates)}), encoding='utf8')
    return rows


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, columns, extrasaction='ignore')
        writer.writeheader(); writer.writerows(rows)


def read_curated() -> list[dict]:
    with (ROOT/'data'/'reviewed_opportunities.csv').open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def report(curated: list[dict], found: list[dict], checked: list[dict], issue: str,
           catalog_stats: list[dict] | None = None, leads: list[dict] | None = None) -> None:
    catalog_stats = catalog_stats or []
    leads = leads or []
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    labels = ('permission_unverified', 'possible_permission_review')
    confirmed = [x for x in curated if x.get('zero_cost_compute') == 'yes' and x.get('verdict') == 'confirmed_mining_allowed_free']
    csvpath = ROOT/'docs'/'candidates.csv'
    write_csv(csvpath, found, ['name', 'section', 'url', 'origin', 'mentions', 'research_priority', 'mining_permission'])
    write_csv(ROOT/'docs'/'new_policy_leads.csv', leads, ['name','homepage','policy_url','triage','evidence_excerpt','error'])
    write_csv(ROOT/'docs'/'public_policy_checks.csv', checked, ['name', 'url', 'result', 'evidence_excerpt', 'error'])
    summary = {
        'generated_utc': now,
        'catalog_discovered_candidates': len(found),
        'manually_reviewed_records': len(curated),
        'free_mining_permissions_confirmed': len(confirmed),
        'public_policy_checks_attempted': len(checked),
        'catalog_fetch_issue': issue,
        'catalogs_checked': len(catalog_stats),
        'catalogs_loaded': sum(1 for r in catalog_stats if r.get('status')=='ok'),
        'catalog_sources': catalog_stats,
        'new_policy_leads_reviewed': len(leads),
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
    candidate_html = ''.join('<tr><td>%s</td><td>%s</td><td>%s</td><td><a href="%s">source</a></td><td>unverified</td></tr>' % (
        html.escape(r['name']), html.escape(r.get('research_priority','normal')),
        r.get('mentions',1), html.escape(r['url'], quote=True)) for r in found[:75])
    leads_html = ''.join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
        html.escape(r['name']), html.escape(r['triage']),
        '<a href="%s">policy link</a>' % html.escape(r['policy_url'],quote=True) if r['policy_url'] else 'not discovered',
        html.escape((r.get('error') or r.get('evidence_excerpt') or '')[:130])) for r in leads)
    block = (
        '<h2>v0.2 — Multiple public directories</h2>'
        '<p>Candidate count is not a count of authorized mining servers. Results are de-duplicated by website hostname.</p>'
        '<p><a href="new_policy_leads.csv">New policy leads CSV</a> · '
        '<a href="candidates.csv">All catalog candidates CSV</a></p>'
        f'<p><strong>{len(catalog_stats)}</strong> catalogs attempted; <strong>{len(leads)}</strong> new public policy leads screened. '
        'Links with permission keywords require manual, plan-specific confirmation.</p>'
        '<h2>Public policy leads checked this run</h2><div class="scroll"><table>'
        '<tr><th>Provider</th><th>Keyword triage</th><th>Policy URL</th><th>Excerpt/error</th></tr>'
        + leads_html + '</table></div>'
        '<h2>Top 75 discovery candidates — NOT APPROVED</h2><div class="scroll"><table>'
        '<tr><th>Service</th><th>Research priority</th><th>Catalog mentions</th><th>Source</th><th>Mining permission</th></tr>'
        + candidate_html + '</table></div>'
    )
    content = content.replace('<h2>Reviewed evidence</h2>', block + '<h2>Reviewed evidence</h2>')
    (ROOT/'docs'/'index.html').write_text(content, encoding='utf8')
    print(json.dumps(summary, indent=2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-policy-checks', type=int, default=12)
    ap.add_argument('--max-new-leads', type=int, default=5)
    ap.add_argument('--offline', action='store_true')
    args = ap.parse_args()
    curated = read_curated()
    catalogs, checked, source_status, errors = [], [], [], []
    if not args.offline:
        for name, url in CATALOGS.items():
            try:
                source = fetch(url, robots=False)
                items = parse_catalog(source) if name == 'free-for-dev' else parse_secondary_catalog(source, url)
                catalogs.append(items)
                source_status.append({'name': name, 'status': 'ok', 'entries': len(items)})
            except Exception as exc:
                source_status.append({'name': name, 'status': 'failed', 'entries': 0})
                errors.append(f'{name}: {type(exc).__name__}: {str(exc)[:90]}')
        for record in curated:
            if len(checked) >= max(0, min(20, args.max_policy_checks)):
                break
            url = record['source_url']
            if '.pdf' in url.lower():
                continue
            item = {'name': record['name'], 'url': url, 'result': '', 'evidence_excerpt': '', 'error': ''}
            try:
                item['result'], item['evidence_excerpt'] = classify(visible_text(fetch(url)))
            except Exception as exc:
                item['result'] = 'unavailable_requires_manual_review'
                item['error'] = f'{type(exc).__name__}: {str(exc)[:120]}'
            checked.append(item)
            time.sleep(1)
    found = merge_catalogs(catalogs)
    leads = review_next_candidates(found, max(0, min(8, args.max_new_leads))) if not args.offline else []
    report(curated, found, checked, '; '.join(errors) if errors else ('offline mode' if args.offline else ''), source_status, leads)


if __name__ == '__main__':
    main()
