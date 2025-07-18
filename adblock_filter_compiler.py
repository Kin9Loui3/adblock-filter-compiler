import re
import requests
from datetime import datetime
import json
import os

# Pre-compiled regular expression for performance
domain_regex = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
)

def is_valid_domain(domain):
    """Checks if a string is a valid domain."""
    return bool(domain_regex.fullmatch(domain))

def parse_hosts_file(content):
    """Parses a host file content into AdBlock rules."""
    adblock_rules = set()
    for line in content.split('\n'):
        line = line.strip()
        if not line or line[0] in ('#', '!'):
            continue
        if line.startswith('||') and line.endswith('^'):
            adblock_rules.add(line)
        else:
            parts = line.split()
            domain = parts[-1]
            if is_valid_domain(domain):
                adblock_rules.add(f'||{domain}^')
    return adblock_rules

def is_domain_covered(domain, covered_domains):
    """Check if domain or any parent domain is in covered_domains set."""
    parts = domain.split('.')
    for i in range(len(parts)):
        candidate = '.'.join(parts[i:])
        if candidate in covered_domains:
            return True
    return False

def generate_filter(file_contents, filter_type, deduplicate=False, minify=False):
    """Generates filter content with deduplication and improved domain compression."""
    duplicates_removed = 0
    redundant_rules_removed = 0
    
    all_rules = set()
    for content in file_contents:
        all_rules.update(parse_hosts_file(content))

    final_rules = set()
    covered_domains = set()  # Track domains that cover subdomains

    for rule in sorted(all_rules):
        domain = rule[2:-1]  # Strip '||' and '^'

        # Deduplicate check
        if deduplicate and rule in final_rules:
            duplicates_removed += 1
            continue

        # Compression using parent domain check
        if minify and is_domain_covered(domain, covered_domains):
            redundant_rules_removed += 1
            continue

        final_rules.add(rule)
        covered_domains.add(domain)  # Mark this domain as covering subdomains

    sorted_rules = sorted(final_rules)
    header = generate_header(len(sorted_rules), duplicates_removed, redundant_rules_removed, filter_type)

    if filter_type == 'whitelist':
        whitelist_rules = ['@@' + rule for rule in sorted_rules]
        filter_content = '\n'.join([header, '', *whitelist_rules])
    else:
        filter_content = '\n'.join([header, '', *sorted_rules])

    return filter_content, duplicates_removed, redundant_rules_removed

def generate_header(domain_count, duplicates_removed, redundant_rules_removed, filter_type):
    """Generates header with stats."""
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
