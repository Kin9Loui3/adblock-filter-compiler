import re
import requests
from datetime import datetime
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# Pre-compiled regex for performance
domain_regex = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
)

def is_valid_domain(domain):
    return bool(domain_regex.fullmatch(domain))

def normalize_domain(domain):
    return domain.lower().lstrip("www.") if domain.startswith("www.") else domain.lower()

def parse_hosts_file(content):
    adblock_rules = set()
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith(('#', '!')):
            continue
        if line.startswith('||') and line.endswith('^'):
            domain = normalize_domain(line[2:-1])
            adblock_rules.add(f'||{domain}^')
        else:
            parts = line.split()
            domain = parts[-1]
            if is_valid_domain(domain):
                domain = normalize_domain(domain)
                adblock_rules.add(f'||{domain}^')
    return adblock_rules

def is_subdomain(sub, parent):
    return sub == parent or sub.endswith('.' + parent)

def generate_filter(file_contents, filter_type, deduplicate=False, minify=False):
    duplicates_removed = 0
    redundant_rules_removed = 0

    all_rules = []
    seen_rules = set()

    for content in file_contents:
        for rule in parse_hosts_file(content):
            if rule in seen_rules:
                duplicates_removed += 1
            else:
                all_rules.append(rule)
                seen_rules.add(rule)

    all_rules.sort(key=lambda r: r[2:-1].count('.'))
    final_rules = []
    base_domains = set()

    for rule in all_rules:
        domain = rule[2:-1]

        if minify and any(is_subdomain(domain, bd) for bd in base_domains):
            redundant_rules_removed += 1
            continue

        base_domains.add(domain)
        final_rules.append(rule)

    sorted_rules = sorted(final_rules)
    header = generate_header(len(sorted_rules), duplicates_removed, redundant_rules_removed, filter_type)

    if filter_type == 'whitelist':
        sorted_rules = ['@@' + rule for rule in sorted_rules]

    return '\n'.join([header, '', *sorted_rules]), duplicates_removed, redundant_rules_removed

def generate_header(domain_count, duplicates_removed, redundant_rules_removed, filter_type):
    date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    title = {
        "blacklist": "Kin9Loui3's Compiled Blacklist",
        "whitelist": "Kin9Loui3's Compiled Whitelist"
    }.get(filter_type, "Filter")
    return f"""# Title: {title}
# Description: Python script that generates adblock filters by combining {filter_type}s, host files, and domain lists.
# Last Modified: {date_time}
# Domain Count: {domain_count}
# Duplicates Removed: {duplicates_removed}
# Domains Compressed: {redundant_rules_removed}
#=================================================================="""

def fetch_url(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")
        return ""

def fetch_all(urls):
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in urls}
        for future in as_completed(future_to_url):
            results.append(future.result())
    return results

def process_config(config_file):
    with open(config_file, 'r') as f:
        config = json.load(f)

    deduplicate = config.get('deduplicate', True)
    minify = config.get('minify', True)

    blacklist_urls = config.get('blacklist_urls', [])
    whitelist_urls = config.get('whitelist_urls', [])
    blacklist_filename = config.get('blacklist_filename', 'blacklist.txt')
    whitelist_filename = config.get('whitelist_filename', 'whitelist.txt')

    # Multithreaded fetch
    blacklist_contents = fetch_all(blacklist_urls)
    whitelist_contents = fetch_all(whitelist_urls)

    blacklist_output, _, _ = generate_filter(blacklist_contents, 'blacklist', deduplicate, minify)
    whitelist_output, _, _ = generate_filter(whitelist_contents, 'whitelist', deduplicate, minify)

    with open(blacklist_filename, 'w') as f:
        f.write(blacklist_output)
    with open(whitelist_filename, 'w') as f:
        f.write(whitelist_output)

def main():
    config_files = [f for f in os.listdir() if f.startswith('config') and f.endswith('.json')]
    for config_file in config_files:
        process_config(config_file)

if __name__ == '__main__':
    main()
