#!/usr/bin/env python3
"""
generate_js_report.py
Generate a single-file HTML report from an OUT/<target> harvest folder.

Usage:
  python3 generate_js_report.py /path/to/OUT/example.com -o /path/to/out/report.html
  python3 generate_js_report.py /path/to/OUT/example.com --open

No external dependencies (stdlib only).
"""

import sys, os, argparse, html, webbrowser, pathlib, datetime, json

def read_file_lines(path):
    try:
        with open(path, encoding='utf-8', errors='ignore') as f:
            return [line.rstrip('\n') for line in f if line.strip()]
    except Exception:
        return []

def find_glob_lines(folder, glob_pattern):
    res = []
    for p in pathlib.Path(folder).glob(glob_pattern):
        if p.is_file():
            res += read_file_lines(str(p))
    return res

def make_clickable_lines(lines):
    out = []
    for l in lines:
        esc = html.escape(l)
        if l.startswith('http://') or l.startswith('https://'):
            out.append(f'<a href="{html.escape(l)}" target="_blank" rel="noopener">{esc}</a>')
        else:
            out.append(esc)
    return out

def shortname(p, base):
    try:
        return os.path.relpath(p, base)
    except Exception:
        return os.path.basename(p)

def build_report(root_dir, out_html, open_after=False, max_show=1000):
    root = pathlib.Path(root_dir)
    if not root.exists():
        print("ERROR: path not found:", root_dir)
        sys.exit(1)

    findings = root / 'findings'
    jsdir = root / 'js'

    # Files we try to read
    files = {
        'all': findings / 'all_endpoints_uniq.txt',
        'validated': findings / 'validated_endpoints.txt',
        'params': findings / 'params.txt',
        'api': findings / 'api_endpoints.txt',
        'admin': findings / 'admin_endpoints.txt',
        'upload': findings / 'upload_endpoints.txt',
        'params_wordlist': findings / 'params_wordlist.txt',
        'candidates': findings / 'candidates.txt',
        'discovered_urls': findings / 'discovered_urls.txt',
        'discovered_paths': findings / 'discovered_paths.txt',
        'fallback_secrets': findings / 'secrets' / 'fallback_secrets.txt',
    }

    data = {}
    for k,p in files.items():
        data[k] = read_file_lines(str(p)) if p.exists() else []

    # LinkFinder outputs
    linkfinder_lines = find_glob_lines(findings / 'linkfinder', '*.txt') if (findings / 'linkfinder').exists() else []
    data['linkfinder'] = linkfinder_lines

    # SecretFinder outputs
    secretfinder_lines = find_glob_lines(findings / 'secrets', '*.txt') if (findings / 'secrets').exists() else []
    data['secretfinder'] = secretfinder_lines

    # JS files list
    js_files = sorted([str(p) for p in (jsdir.glob('*.js') if jsdir.exists() else [])])
    data['js_files'] = js_files

    # Extra: download_map, validated candidates, validated_candidates
    dm = read_file_lines(str(jsdir.parent / 'download_map.txt')) if (jsdir.parent / 'download_map.txt').exists() else []
    data['download_map'] = dm
    validated_candidates = read_file_lines(str(findings / 'validated_candidates.txt')) if (findings / 'validated_candidates.txt').exists() else []
    data['validated_candidates'] = validated_candidates

    # counts
    counts = {k: len(v) for k,v in data.items()}

    # time
    now = datetime.datetime.utcnow().isoformat() + 'Z'

    # Build HTML
    title = f"JS Endpoint Harvester Report — {html.escape(root_dir)}"
    html_parts = []
    html_parts.append(f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{title}</title>')
    html_parts.append('''<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:Inter,Segoe UI,Roboto,Arial,sans-serif;background:#f7fafc;color:#111;margin:18px}
.container{max-width:1200px;margin:0 auto}
.header{display:flex;justify-content:space-between;align-items:center}
h1{margin:6px 0}
.card{background:#fff;border:1px solid #e6edf3;padding:12px;border-radius:8px;margin:10px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}
.pre{background:#0b1a22;color:#e6f1f5;padding:10px;border-radius:6px;overflow:auto;max-height:320px}
a{color:#0b69a5}
.small{font-size:0.9rem;color:#555}
.searchbox{margin:8px 0;padding:8px;border-radius:6px;border:1px solid #ddd;width:100%}
.count{font-weight:600}
.link{word-break:break-all}
button.copy{padding:6px 10px;border-radius:6px;border:1px solid #ddd;background:#fff;cursor:pointer}
.flex{display:flex;gap:8px;align-items:center}
.badge{background:#eef6ff;padding:4px 8px;border-radius:6px;border:1px solid #d6e9ff}
</style>
</head><body><div class="container">''')

    # Header
    html_parts.append(f'<div class="header"><div><h1>JS Endpoint Harvester Report</h1><div class="small">Generated: {now} — Source: {html.escape(str(root))}</div></div>')
    html_parts.append('<div class="flex"><button class="copy" onclick="copyReport()">Copy Report HTML</button></div></div>')

    # Summary cards
    html_parts.append('<div class="card grid">')
    html_parts.append(f'<div class="small">Harvested endpoints <div class="count">{counts.get("all",0)}</div></div>')
    html_parts.append(f'<div class="small">Validated endpoints <div class="count">{counts.get("validated",0)}</div></div>')
    html_parts.append(f'<div class="small">JS candidates <div class="count">{counts.get("js_files",0)}</div></div>')
    html_parts.append(f'<div class="small">Downloaded JS files <div class="count">{len(data["js_files"])}</div></div>')
    html_parts.append(f'<div class="small">LinkFinder matches <div class="count">{counts.get("linkfinder",0)}</div></div>')
    html_parts.append(f'<div class="small">Secrets (fallback) <div class="count">{counts.get("fallback_secrets",0)}</div></div>')
    html_parts.append('</div>')  # end grid

    # Search box for filtering endpoints
    html_parts.append('<div class="card"><input id="filter" class="searchbox" placeholder="Filter endpoints / JS / secrets (type & press Enter)" onkeydown="if(event.key==\'Enter\') applyFilter()"><div class="small">Tip: filter by <code>/api/</code>, <code>/admin</code>, domain names, or keywords.</div></div>')

    # Sections: API / Admin / Upload / All
    def section(title, iden, items, clickable=True, max_show=max_show):
        html_parts.append(f'<div class="card"><h2>{html.escape(title)} <span class="badge">{len(items)}</span></h2>')
        if not items:
            html_parts.append('<div class="small">None found</div></div>')
            return
        html_parts.append(f'<div id="{iden}" class="pre">')
        shown=0
        for line in items:
            if shown >= max_show:
                html_parts.append(f'... ({len(items)-max_show} more lines)'); break
            if clickable and (line.startswith('http://') or line.startswith('https://')):
                html_parts.append(f'<div class="link"><a href="{html.escape(line)}" target="_blank" rel="noopener">{html.escape(line)}</a></div>')
            else:
                # If local js file path, make file:// link
                if os.path.isabs(line) and os.path.exists(line):
                    html_parts.append(f'<div class="link"><a href="file://{html.escape(line)}">{html.escape(shortname(line,str(root)))}</a> &nbsp; <small class="small">{html.escape(line)}</small></div>')
                else:
                    html_parts.append(f'<div>{html.escape(line)}</div>')
            shown += 1
        html_parts.append('</div></div>')

    # Prepare content arrays
    api_lines = read_file_lines(str(findings / 'api_endpoints.txt')) if (findings := root / 'findings') else []
    admin_lines = read_file_lines(str(findings / 'admin_endpoints.txt')) if (findings := root / 'findings') else []
    upload_lines = read_file_lines(str(findings / 'upload_endpoints.txt')) if (findings := root / 'findings') else []
    all_lines = data.get('all', [])
    validated_lines = data.get('validated', [])
    candidates_lines = data.get('candidates', [])
    js_candidates_lines = read_file_lines(str(root / 'js' / 'js_candidates.txt')) if (root / 'js' / 'js_candidates.txt').exists() else []
    discovered_urls = data.get('discovered_urls', [])
    fallback_secrets = read_file_lines(str(findings / 'secrets' / 'fallback_secrets.txt')) if (findings / 'secrets' / 'fallback_secrets.txt').exists() else []
    linkfinder_lines = data.get('linkfinder', [])
    secretfinder_lines = data.get('secretfinder', [])
    js_files_local = data.get('js_files', [])

    section("API Endpoints", "api", api_lines)
    section("Admin Endpoints", "admin", admin_lines)
    section("Upload Endpoints", "upload", upload_lines)
    section("Validated Endpoints", "validated", validated_lines)
    section("All Candidate Endpoints", "all", all_lines)
    section("Candidates (synthesized)", "cands", candidates_lines)
    section("Discovered URLs (from JS)", "durls", discovered_urls)
    section("Discovered Paths", "dpaths", read_file_lines(str(findings / 'discovered_paths.txt')) if (findings / 'discovered_paths.txt').exists() else [])
    section("JS Candidates (from harvesting)", "jscand", js_candidates_lines)
    section("JS files (downloaded)", "jsfiles", js_files_local, clickable=False)
    section("LinkFinder findings", "lf", linkfinder_lines)
    section("SecretFinder findings", "sf", secretfinder_lines)
    section("Fallback secrets (regex)", "fs", fallback_secrets)

    # small utilities and scripts
    html_parts.append('''
<div class="card">
<h2>Tools</h2>
<div class="small">You can filter and copy sections. Use the filter box to narrow down results.</div>
</div>
<script>
function applyFilter(){
  var q = document.getElementById('filter').value.trim().toLowerCase();
  if(!q){ // show all
    var pres = document.querySelectorAll('.pre'); for(var i=0;i<pres.length;i++) pres[i].style.display='block'; return;
  }
  var pres = document.querySelectorAll('.pre');
  for(var i=0;i<pres.length;i++){
    var text = pres[i].innerText.toLowerCase();
    pres[i].style.display = text.indexOf(q) !== -1 ? 'block' : 'none';
  }
}
function copyReport(){
  navigator.clipboard && navigator.clipboard.writeText(document.documentElement.outerHTML).then(()=>alert('Report HTML copied to clipboard'));
}
</script>
''')

    html_parts.append('</div></body></html>')

    # write file
    with open(out_html, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html_parts))
    print("Wrote HTML report to:", out_html)
    if open_after:
        webbrowser.open('file://' + os.path.abspath(out_html))

def main():
    ap = argparse.ArgumentParser(description='Generate HTML report from JS harvester outputs')
    ap.add_argument('outdir', help='Path to OUT/<target> directory (the folder that contains js/ and findings/)')
    ap.add_argument('-o','--output', help='Output HTML file (default: <outdir>/findings/report.html)', default=None)
    ap.add_argument('--open', help='Open the report after generation (uses default system browser)', action='store_true')
    ap.add_argument('--max', help='Max lines shown per block in HTML (default 1000)', type=int, default=1000)
    args = ap.parse_args()

    outdir = args.outdir
    output = args.output or os.path.join(outdir, 'findings', 'report.html')
    build_report(outdir, output, open_after=args.open, max_show=args.max)

if __name__ == '__main__':
    main()
