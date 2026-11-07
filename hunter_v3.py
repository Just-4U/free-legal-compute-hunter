#!/usr/bin/env python3
"""Free Legal Compute Hunter v0.3: more public discovery sources, no deployment.

Requires the existing hunter_v2.py in the same repository folder.
Research ONLY: reads public free-tier directories and public provider policy pages.
No port/IP scanning, account access, miner, or code installation.
"""
from __future__ import annotations
import re
import html
from urllib.parse import urlparse
import hunter_v2 as core

BASE = 'https://raw.githubusercontent.com/ePlus-DEV/free-tier-hub/main/docs/'

# Instead of reading the free-tier-hub landing page (which lists categories but
# no provider entries), read its actual source tables.
CATALOGS_V3 = {
    'free-for-dev': core.CATALOG_URL,
    'free-services': core.CATALOGS['free-services'],
    'hub-cloud-vps': BASE + 'cloud-vps.md',
    'hub-app-hosting': BASE + 'app-hosting.md',
    'hub-serverless': BASE + 'serverless.md',
    'hub-ai-ml': BASE + 'ai-ml.md',
    'free-cloud-notebooks': (
        'https://raw.githubusercontent.com/dhaulagani/'
        'awesome-free-cloud-notebooks/main/README.md'
    ),
}

ORIGINAL_SECONDARY_PARSE = core.parse_secondary_catalog
ORIGINAL_REPORT = core.report


def parse_source_table(doc: str, source: str) -> list[dict]:
    """Parse official-source links in public Markdown directory tables.

    This is candidate discovery only. Listed free plans are NOT mining consent.
    Service terms, paywalls and zero-card eligibility still need verification.
    """
    name_of_source = source.split('/')[-1].replace('.md', '')
    items: list[dict] = []
    for line in doc.splitlines():
        if not line.lstrip().startswith('|'):
            continue
        match = re.match(
            r'^\s*\|\s*\[([^\]]{2,130})\]\((https://[^)\s]+)\)\s*\|', line
        )
        if not match:
            continue
        name, url = match.groups()
        host = urlparse(url).hostname or ''
        if not host or host.endswith('github.com') or host == 'localhost':
            continue
        # Self-hosted free SOFTWARE is not a free third-party compute placement.
        if re.search(r'\bself.host(?:ed|ing)?\b|\bbring.your.own\b', name + ' ' + line, re.I):
            continue
        # Keep only direct computing resources in the broad AI catalog, not
        # free LLM API tokens, monitoring, dashboards, or static site tools.
        if name_of_source == 'ai-ml' and not re.search(
            r'\b(cpu|gpu|compute|hosting|runtime|containers?|notebooks?|instances?)\b',
            name + ' ' + line, re.I
        ):
            continue
        # Purely static website hosting doesn't provide CPU for a miner.
        if re.search(r'\bonly\s+static\b|\bstatic\s+html\b|\bwithout managed runtime compute\b', line, re.I):
            continue
        values = [v.strip() for v in line.strip().strip('|').split('|')]
        # Hosted tier entries describe the provider offer, not evidence of mining consent.
        offer = values[1] if len(values) > 1 else ''
        card = values[4] if len(values) > 4 else ''
        if re.search(r'time.limited|promotional|trial', offer, re.I):
            offer_status = 'temporary_offer'
        elif re.search(r'ongoing|recurring', offer, re.I):
            offer_status = 'ongoing_or_recurring'
        else:
            offer_status = 'unclear'
        items.append({
            'name': name.strip(),
            'url': url,
            'section': 'Free Tier Hub / ' + name_of_source,
            'origin': source,
            'free_offer_status': offer_status,
            'payment_card_requirement': card,
            'mining_permission': 'unverified',
        })
    return items


def parse_notebook_directory(doc: str, source: str) -> list[dict]:
    """Parse entries from a free notebook directory, for *review only*."""
    items = parse_source_table(doc, source)
    for item in items:
        item['section'] = 'Free notebook / GPU directories'
        item['free_offer_status'] = 'unverified_from_directory'
        item['payment_card_requirement'] = 'unverified_from_directory'
    return items


def parse_secondary_v3(doc: str, source: str) -> list[dict]:
    if '/free-tier-hub/main/docs/' in source:
        return parse_source_table(doc, source)
    if '/awesome-free-cloud-notebooks/' in source:
        return parse_notebook_directory(doc, source)
    return ORIGINAL_SECONDARY_PARSE(doc, source)


def report_v3(curated, found, checked, issue, catalog_stats=None, leads=None):
    """Reuse the existing dashboard and show which new sources produced leads."""
    ORIGINAL_REPORT(curated, found, checked, issue, catalog_stats, leads)
    rows = []
    for src in catalog_stats or []:
        name = html.escape(str(src.get('name', 'unknown')))
        status = html.escape(str(src.get('status', 'unknown')))
        count = int(src.get('entries', 0))
        rows.append(f'<tr><td>{name}</td><td>{count}</td><td>{status}</td></tr>')
    overview = (
        '<h2>v0.3 — Targeted compute catalog discovery</h2>'
        '<p>New sources include actual VPS, hosting, serverless, AI runtime and notebook listings. '
        'They are research leads only; <strong>no provider is automatically authorized for mining.</strong></p>'
        '<div class="scroll"><table><tr><th>Public directory</th><th>Entries parsed</th><th>Status</th></tr>'
        + ''.join(rows) + '</table></div>'
    )
    page = core.ROOT / 'docs' / 'index.html'
    markup = page.read_text(encoding='utf-8')
    markup = markup.replace('<h2>v0.2 — Multiple public directories</h2>', '<h2>Candidate policy screening</h2>')
    markup = markup.replace('<h2>Candidate policy screening</h2>', overview + '<h2>Candidate policy screening</h2>')
    page.write_text(markup, encoding='utf-8')


def run() -> None:
    # Keep v0.2's conservative network limits, robots checks, policy triage,
    # and manually reviewed seed evidence unchanged.
    core.CATALOGS = CATALOGS_V3
    core.parse_secondary_catalog = parse_secondary_v3
    core.report = report_v3
    core.main()


if __name__ == '__main__':
    run()
