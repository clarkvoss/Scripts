#!/usr/bin/env python3
# js_url_param_miner.py
# Usage: python3 js_url_param_miner.py <js_dir> <out_dir>
# Example: python3 js_url_param_miner.py OUT/example.com/js OUT/example.com/findings

import os, re, sys
from urllib.parse import urljoin, urlparse

if len(sys.argv) != 3:
    print("Usage: python3 js_url_param_miner.py <js_dir> <out_dir>")
    sys.exit(1)

js_dir = sys.argv[1]
out_dir = sys.argv[2]
os.makedirs(out_dir, exist_ok=True)

# Patterns
URL_RE = re.compile(r'https?://[^\s"\'<>)]+', re.IGNORECASE)
PATH_RE = re.compile(r'(?:(?<=["\']))(/[A-Za-z0-9_\-./]{3,300})(?=["\'])')  # quoted paths
SINGLE_PATH_RE = re.compile(r'(?<![:/])(/[A-Za-z0-9_\-./]{3,300})')  # unquoted paths
STR_LIT_RE = re.compile(r'["\']([A-Za-z0-9_\-_/.:?=,&%{}"\'\[\]\(\)]{3,300})["\']')
OBJ_KEY_RE = re.compile(r'["\']([A-Za-z_][A-Za-z0-9_]{2,})["\']\s*:')
# Param-like token
PARAM_RE = re.compile(r'\b([A-Za-z]{2,20}(?:_?|-?)[A-Za-z0-9]{0,20})\b', re.IGNORECASE)

found_urls = set()
found_paths = set()
param_candidates = set()
string_literals = set()

def collect_from_file(path):
    try:
        text = open(path, encoding='utf-8', errors='ignore').read()
    except Exception as e:
        return
    # URLs
    for m in URL_RE.findall(text):
        found_urls.add(m.strip().rstrip('",);'))

    # quoted paths
    for m in PATH_RE.findall(text):
        found_paths.add(m.strip())

    # more loose paths (unquoted)
    for m in SINGLE_PATH_RE.findall(text):
        # filter out protocol/urls already matched
        if m.startswith('//') or m.startswith('/http'):
            continue
        if len(m) > 3:
            found_paths.add(m.strip())

    # string literals (for extracting param-like tokens)
    for m in STR_LIT_RE.findall(text):
        if len(m) >= 3 and len(m) <= 300:
            string_literals.add(m)

    # object keys
    for k in OBJ_KEY_RE.findall(text):
        if len(k) >= 2 and len(k) <= 30:
            param_candidates.add(k)

# Walk directory
for root, dirs, files in os.walk(js_dir):
    for f in files:
        if f.endswith('.js') or f.endswith('.jsx') or f.endswith('.mjs') or f.endswith('.ts') or f.endswith('.tsx'):
            collect_from_file(os.path.join(root, f))

# From string literals extract token-like words (filter common words)
COMMON_NOISE = {'function','return','var','const','let','true','false','null','Object','window','document'}
for s in string_literals:
    for token in re.findall(PARAM_RE, s):
        token_l = token.strip('_-')
        if len(token_l) >= 2 and token_l.lower() not in COMMON_NOISE:
            # filter out full paths / urls
            if '/' in token or ':' in token:
                continue
            # likely parameter-like words
            if re.match(r'^[A-Za-z_][A-Za-z0-9_]{1,30}$', token_l):
                param_candidates.add(token_l)

# Heuristic expand params with common suffixes
common_params = {'id','uid','user','token','key','auth','session','page','limit','offset','q','query','redirect','next','lang','locale','email','sort','filter'}
param_candidates |= common_params

# Build candidate endpoints
# Normalize found_urls to get bases
bases = set()
for u in found_urls:
    try:
        p = urlparse(u)
        base = f"{p.scheme}://{p.netloc}"
        bases.add(base)
    except:
        continue

# If no explicit base, try target root (if any found in PATHS we cannot join yet)
candidates = set()

# Add discovered absolute urls
for u in found_urls:
    candidates.add(u)

# Add discovered paths combined with bases
for b in bases:
    for p in found_paths:
        cand = urljoin(b, p)
        candidates.add(cand)

# Add permutations: base + path + ?param=FUZZ
SAMPLE_VALUE = "FUZZ"
for b in bases:
    for p in found_paths:
        for param in sorted(param_candidates)[:80]:  # limit explosion
            candidates.add(f"{urljoin(b,p)}?{param}={SAMPLE_VALUE}")

# Save outputs
with open(os.path.join(out_dir, 'discovered_urls.txt'), 'w') as fh:
    for u in sorted(found_urls):
        fh.write(u + "\n")

with open(os.path.join(out_dir, 'discovered_paths.txt'), 'w') as fh:
    for p in sorted(found_paths):
        fh.write(p + "\n")

with open(os.path.join(out_dir, 'params_wordlist.txt'), 'w') as fh:
    for p in sorted(param_candidates):
        fh.write(p + "\n")

with open(os.path.join(out_dir, 'candidates.txt'), 'w') as fh:
    for c in sorted(candidates):
        fh.write(c + "\n")

print("Done.")
print("Results written to:", out_dir)
print(" - discovered_urls.txt  (absolute urls)")
print(" - discovered_paths.txt (path-like strings)")
print(" - params_wordlist.txt  (param name candidates)")
print(" - candidates.txt       (synthesized candidates)")
