"""Listing 41: Microsoft CVE monthly series from CVEProject/cvelistV5.

CVSS source per listing spec: CISA-ADP "CISA ADP Vulnrichment" container.
Reality: in this CNA the Vulnrichment container carries SSVC/KEV only, not
CVSS base scores. Where the Vulnrichment container omits a CVSS score, this
script falls back to the CNA's own cvssV3_1 in the same record. Both paths
are reported separately so a stranger can audit the substitution.
"""
import collections
import json
import os
import sys

COMMIT = '14795867cc3aae0d6c8e165ed09692e951125efc'
ROOT = os.environ.get('CVELIST', '/opt/data/cve')
WINDOW = [f'{y}-{m:02d}' for y, m in
          [(2025, 9), (2025, 10), (2025, 11), (2025, 12),
           (2026, 1), (2026, 2), (2026, 3), (2026, 4),
           (2026, 5), (2026, 6), (2026, 7), (2026, 8)]]
CVSS_KEYS = ('cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0')


def walk():
    for dp, _dn, fns in os.walk(ROOT):
        if '/.git' in dp:
            continue
        for fn in fns:
            if fn.endswith('.json') and fn.startswith('CVE-'):
                yield os.path.join(dp, fn)


def base_score(metrics):
    """Return (source_label, score) from the first CVSS metric in a list."""
    for m in metrics or []:
        for k in CVSS_KEYS:
            v = m.get(k)
            if isinstance(v, dict) and isinstance(v.get('baseScore'), (int, float)):
                return k, float(v['baseScore'])
    return None, None


def main():
    months = {w: collections.Counter() for w in WINDOW}
    rows = []
    for f in walk():
        try:
            d = json.load(open(f))
        except Exception:
            continue
        md = d.get('cveMetadata', {})
        if md.get('assignerShortName') != 'microsoft':
            continue
        if md.get('state') != 'PUBLISHED':
            continue
        dp = md.get('datePublished')
        if not dp:
            continue
        w = dp[:7]
        if w not in months:
            continue
        c = months[w]
        c['n'] += 1
        cont = d.get('containers') or {}
        src, score = None, None
        # 1. CISA-ADP Vulnrichment (spec-preferred)
        for a in cont.get('adp') or []:
            if a.get('title') != 'CISA ADP Vulnrichment':
                continue
            s, v = base_score(a.get('metrics'))
            if v is not None:
                src, score = 'adp:CISA ADP Vulnrichment:' + s, v
                break
        # 2. fallback: CNA's own metric in the same record
        if score is None:
            s, v = base_score((cont.get('cna') or {}).get('metrics'))
            if v is not None:
                src, score = 'cna:' + s, v
        if score is not None:
            c['rated'] += 1
            c['sum'] += score
            c[src] += 1
            rows.append((md.get('cveId'), w, score, src))
        else:
            c['unrated'] += 1
            rows.append((md.get('cveId'), w, None, 'none'))
    print(f'# cvelistV5 commit {COMMIT}')
    print('# selection: cveMetadata.assignerShortName == "microsoft" AND state == "PUBLISHED"')
    print('# bucket key: cveMetadata.datePublished[:7] (UTC month)')
    print(f'# CVSS path (preferred): containers.adp[title=="CISA ADP Vulnrichment"].metrics[].cvssV3_1.baseScore')
    print(f'# CVSS path (fallback):  containers.cna.metrics[].cvssV3_1.baseScore')
    print()
    print('month      n   rated  unrated    sum     mean')
    tn = tr = 0
    ts = 0.0
    for w in WINDOW:
        c = months[w]
        n, r = c['n'], c['rated']
        s = round(c['sum'], 1)
        mean = round(c['sum'] / r, 2) if r else 0.0
        tn += n
        tr += r
        ts += c['sum']
        print(f'{w} {n:5d} {r:6d} {c["unrated"]:7d} {s:7.1f} {mean:7.2f}')
    print(f'TOTAL   {tn:5d} {tr:6d} {tn - tr:7d} {round(ts, 1):7.1f} '
          f'{round(ts / tr, 2) if tr else 0.0:7.2f}')
    print(f'# coverage {tr}/{tn} = {tr / tn:.4f}')
    srcs = collections.Counter()
    for _id, _w, _s, src in rows:
        srcs[src] += 1
    print('# score sources:', dict(srcs))
    json.dump({'commit': COMMIT, 'months': {w: dict(months[w]) for w in WINDOW},
               'rows': rows},
              open('/opt/data/msft/table41.json', 'w'))


if __name__ == '__main__':
    sys.exit(main())
