import re
import requests
from requests.exceptions import RequestException
from datetime import datetime
import json
import os
from collections import Counter
import logging
import argparse
import tldextract

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def is_valid_domain(domain):
    ext = tldextract.extract(domain)
    return bool(ext.domain and ext.suffix)

def get_base_domain(domain):
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"

def fetch_url(url, retries=3, timeout=10):
    for attempt in range(1, retries + 1):
        try:
            logging.debug(f"Fetching {url} (attempt {attempt})")
            r = requests.get(url, timeout=timeout)
            r.raise_for_status()
            return r.text
        except RequestException as e:
            logging.warning(f"Error fetching {url}: {e}")
    logging.error(f"Failed to fetch {url} after {retries} attempts.")
    return ""

def parse_hosts_file(content):
    rules = set()
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(('#', '!')):
            continue

        if line.startswith('0.0.0.0') and not line.startswith('0.0.0.0 '):
            line = line.replace('0.0.0.0', '0.0.0.0 ', 1)

        parts = re.split(r'\s+', line, maxsplit=2)
        if not parts:
            continue

        # take last token as domain candidate
        domain = parts[-1]
        if domain.startswith('||') and domain.endswith('^'):
            domain = domain[2:-1]  # strip wrapper
        if is_valid_domain(domain):
            rules.add(f'||{domain}^')
    return rules

def generate_filter(file_contents, filter_type, deduplicate=True, minify=True):
    raw_rules = set()
    for content in file_contents:
        raw_rules |= parse_hosts_file(content)

    if not raw_rules:
        logging.info(f"No domains found for {filter_type}. Skipping filter generation.")
        return "", 0, 0

    seen_base = set()
    final = []
    duplicates_removed = 0
    redundant_removed = 0

    for rule in sorted(raw_rules):
        base = get_base_domain(rule[2:-1])
        if minify and base in seen_base:
            redundant_removed += 1
            continue
        seen_base.add(base)
        final.append(rule)

    header = generate_header(len(final), len(raw_rules) - len(final), redundant_removed, filter_type)
    if filter_type == 'whitelist':
        final = ['@@' + r for r in final]

    return "\n".join([header, '', *final]), len(raw_rules) - len(final), redundant_removed

def generate_header(count, removed_dupes, removed_redund, filter_type):
    date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    title = f"Kin9Loui3's Compiled {'Blacklist' if filter_type=='blacklist' else 'Whitelist'}"
    return (
        f"# Title: {title}\n"
        f"# Description: Compiled {filter_type} filter\n"
        f"# Last Modified: {date_time}\n"
        f"# Domain Count: {count}\n"
        f"# Duplicates Removed: {removed_dupes}\n"
        f"# Domains Compressed: {removed_redund}\n"
        f"#=================================================================="
    )

def process_config(config_file):
    logging.info(f"Processing config: {config_file}")
    with open(config_file) as f:
        cfg = json.load(f)

    dedup = cfg.get('deduplicate', True)
    mini = cfg.get('minify',    True)
    bl_urls = cfg.get('blacklist_urls', [])
    wl_urls = cfg.get('whitelist_urls', [])
    bl_fname = cfg.get('blacklist_filename', 'blacklist.txt')
    wl_fname = cfg.get('whitelist_filename', 'whitelist.txt')

    bl_contents = [fetch_url(u) for u in bl_urls]
    wl_contents = [fetch_url(u) for u in wl_urls]

    bl_filter, bl_dupes, bl_redund = generate_filter(bl_contents, 'blacklist', dedup, mini)
    wl_filter, wl_dupes, wl_redund = generate_filter(wl_contents, 'whitelist', dedup, mini)

    if bl_filter:
        with open(bl_fname, 'w') as f:
            f.write(bl_filter)
        logging.info(f"Wrote blacklist ({len(bl_filter.splitlines())} lines) to {bl_fname}")
    if wl_filter:
        with open(wl_fname, 'w') as f:
            f.write(wl_filter)
        logging.info(f"Wrote whitelist ({len(wl_filter.splitlines())} lines) to {wl_fname}")

def main():
    parser = argparse.ArgumentParser(description="Adblock filter generator")
    parser.add_argument('configs', nargs='*', help="config JSON files", default=[f for f in os.listdir() if f.startswith('config') and f.endswith('.json')])
    args = parser.parse_args()

    for cfg in args.configs:
        if os.path.isfile(cfg):
            process_config(cfg)
        else:
            logging.error(f"Config file not found: {cfg}")

if __name__ == "__main__":
    main()
