import re
import requests
from datetime import datetime
import json
import os
from collections import Counter

# Pre-compiled regular expression for performance
domain_regex = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
)

def is_valid_domain(domain):
    return bool(domain_regex.fullmatch(domain))

def parse_hosts_file(content):
    adblock_rules = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line[0] in ('#', '!'):
            continue
        if line.startswith('||') and line.endswith('^'):
            adblock_rules.append(line)
        else:
            parts = line.split()
            domain = parts[-1]
            if is_valid_domain(domain):
                adblock_rules.append(f'||{domain}^')
    return adblock_rules

def get_base_domain(domain):
    return '.'.join(domain.rsplit('.', 2)[-2:])

def generate_filter(file_contents, filter_type, deduplicate=False, minify=False):
    duplicates_removed = 0
    redundant_rules_removed = 0

    raw_rules = []
    for content in file_contents:
        raw_rules.extend(parse_hosts_file(content))

    rule_counter = Counter(raw_rules)
    seen_rules = set()
    seen_base_domains = set()

    removed_duplicates = []
    removed_compressed = []
    final_rules = []

    for rule in raw_rules:
        domain = rule[2:-1]
        base_domain = get_base_domain(domain)

        if deduplicate and rule in seen_rules:
            duplicates_removed += 1
            removed_duplicates.append(rule)
            continue

        if minify and base_domain in seen_base_domains:
            redundant_rules_removed += 1
            removed_compressed.append(rule)
            continue

        seen_rules.add(rule)
        seen_base_domains.add(base_domain)
        final_rules.append(rule)

    sorted_rules = sorted(set(final_rules))
    header = generate_header(len(sorted_rules), duplicates_removed, redundant_rules_removed, filter_type)

    if filter_type == 'whitelist':
        sorted_rules = ['@@' + rule for rule in sorted_rules]

    filter_content = '\n'.join([header, '', *sorted_rules])
    return filter_content, duplicates_removed, redundant_rules_removed

def generate_header(domain_count, duplicates_removed, redundant_rules_removed, filter_type):
    date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if filter_type == 'blacklist':
        title = "Kin9Loui3's Compiled Blacklist"
    elif filter_type == 'whitelist':
        title = "Kin9Loui3's Compiled Whitelist"
    else:
        title = "Filter"
    return f"""# Title: {title}
# Description: Python script that generates adblock filters by combining {filter_type}s, host files, and domain lists.
# Last Modified: {date_time}
# Domain Count: {domain_count}
# Duplicates Removed: {duplicates_removed}
# Domains Compressed: {redundant_rules_removed}
#=================================================================="""

def process_config(config_file):
    with open(config_file, 'r') as f:
        config_data = json.load(f)

    deduplicate = config_data.get('deduplicate', True)
    minify = config_data.get('minify', True)

    blacklist_urls = config_data.get('blacklist_urls', [])
    whitelist_urls = config_data.get('whitelist_urls', [])
    blacklist_filename = config_data.get('blacklist_filename', 'blacklist.txt')
    whitelist_filename = config_data.get('whitelist_filename', 'whitelist.txt')

    blacklist_contents = [requests.get(url).text for url in blacklist_urls]
    whitelist_contents = [requests.get(url).text for url in whitelist_urls]

    blacklist_content, _, _ = generate_filter(blacklist_contents, 'blacklist', deduplicate, minify)
    whitelist_content, _, _ = generate_filter(whitelist_contents, 'whitelist', deduplicate, minify)

    with open(blacklist_filename, 'w') as f:
        f.write(blacklist_content)

    with open(whitelist_filename, 'w') as f:
        f.write(whitelist_content)

def main():
    config_files = [file for file in os.listdir() if file.startswith('config') and file.endswith('.json')]
    for config_file in config_files:
        process_config(config_file)

if __name__ == "__main__":
    main()
