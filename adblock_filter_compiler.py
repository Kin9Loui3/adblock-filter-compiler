import re
import requests
from datetime import datetime
import json
import os

# Pre-compiled regex for IPs and valid domain names
domain_regex = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    r"|^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)

# Simplified public suffix list for collapsing domains
COMMON_SUFFIXES = {
    "com", "org", "net", "edu", "gov", "mil", "co.uk", "org.uk", "ac.uk",
    "co", "us", "ca", "de", "fr", "jp", "br", "au", "in", "it", "ru", "cn"
}

def is_valid_domain(domain):
    return bool(domain_regex.fullmatch(domain.lower()))

def get_registered_domain(domain):
    """Reduce domain to its registered form using suffix list."""
    parts = domain.lower().split('.')
    for i in range(len(parts) - 1):
        possible_suffix = '.'.join(parts[i+1:])
        if possible_suffix in COMMON_SUFFIXES or parts[-1] in COMMON_SUFFIXES:
            return '.'.join(parts[i:])
    return domain

def parse_hosts_file(content):
    """Parses host content and returns cleaned AdBlock rules."""
    rules = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '!')):
            continue
        if line.startswith('||') and line.endswith('^'):
            domain = line[2:-1]
        else:
            parts = line.split()
            domain = parts[-1] if parts else ""
        if is_valid_domain(domain):
            rules.add(f"||{domain.lower()}^")
    return rules

def generate_filter(file_contents, filter_type):
    """Deduplicates and collapses domain rules."""
    rules = set()
    registered_seen = set()
    duplicates_removed = 0
    redundant_removed = 0

    for content in file_contents:
        for rule in parse_hosts_file(content):
            domain = rule[2:-1]
            reg_domain = get_registered_domain(domain)
            if rule in rules:
                duplicates_removed += 1
                continue
            if reg_domain in registered_seen:
                redundant_removed += 1
                continue
            rules.add(rule)
            registered_seen.add(reg_domain)

    sorted_rules = sorted(rules)
    header = generate_header(len(sorted_rules), duplicates_removed, redundant_removed, filter_type)
    if filter_type == "whitelist":
        sorted_rules = ['@@' + rule for rule in sorted_rules]
    return '\n'.join([header, '', *sorted_rules]), duplicates_removed, redundant_removed

def generate_header(domain_count, dupes, collapsed, filter_type):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    title = f"Kin9Loui3's Compiled {filter_type.capitalize()}"
    return f"""# Title: {title}
# Description: Python script that generates adblock filters by combining {filter_type}s, host files, and domain lists.
# Last Modified: {now}
# Domain Count: {domain_count}
# Duplicates Removed: {dupes}
# Domains Compressed: {collapsed}
#=================================================================="""

def process_config(config_file):
    with open(config_file) as f:
        config = json.load(f)

    blacklist_urls = config.get("blacklist_urls", [])
    whitelist_urls = config.get("whitelist_urls", [])
    blacklist_filename = config.get("blacklist_filename", "blacklist.txt")
    whitelist_filename = config.get("whitelist_filename", "whitelist.txt")

    blacklist_contents = [requests.get(url).text for url in blacklist_urls]
    whitelist_contents = [requests.get(url).text for url in whitelist_urls]

    bl_content, _, _ = generate_filter(blacklist_contents, "blacklist")
    wl_content, _, _ = generate_filter(whitelist_contents, "whitelist")

    with open(blacklist_filename, 'w') as f:
        f.write(bl_content)
    with open(whitelist_filename, 'w') as f:
        f.write(wl_content)

def main():
    for file in os.listdir():
        if file.startswith('config') and file.endswith('.json'):
            process_config(file)

if __name__ == "__main__":
    main()
