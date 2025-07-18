import re
import requests
from datetime import datetime
import json
import os

# Pre-compiled regular expression for performance
domain_regex = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    r"|^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)

def is_valid_domain(domain):
    return bool(domain_regex.fullmatch(domain.lower()))

def parse_hosts_file(content):
    """Parses host file content into AdBlock rules."""
    adblock_rules = set()
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith(('#', '!')):
            continue
        if line.startswith('||') and line.endswith('^'):
            adblock_rules.add(line.lower())
        else:
            parts = line.split()
            domain = parts[-1].lower()
            if is_valid_domain(domain):
                adblock_rules.add(f'||{domain}^')
    return adblock_rules

# Trie node for domain compression
class DomainTrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False

class DomainTrie:
    def __init__(self):
        self.root = DomainTrieNode()

    def add(self, domain):
        parts = domain.split('.')[::-1]
        node = self.root
        for part in parts:
            node = node.children.setdefault(part, DomainTrieNode())
        node.is_end = True

    def is_covered(self, domain):
        parts = domain.split('.')[::-1]
        node = self.root
        for part in parts:
            if node.is_end:
                return True
            if part not in node.children:
                return False
            node = node.children[part]
        return node.is_end

def generate_filter(file_contents, filter_type):
    """Generates filter content from file_contents with deduplication and domain compression."""
    all_rules = set()
    for content in file_contents:
        all_rules.update(parse_hosts_file(content))

    adblock_rules_set = set()
    duplicates_removed = 0
    redundant_rules_removed = 0
    trie = DomainTrie()

    # Sort rules to prioritize parent domains first
    sorted_input = sorted(all_rules, key=lambda rule: rule[2:-1].count('.'))

    for rule in sorted_input:
        domain = rule[2:-1]
        if rule in adblock_rules_set:
            duplicates_removed += 1
            continue
        if trie.is_covered(domain):
            redundant_rules_removed += 1
            continue
        adblock_rules_set.add(rule)
        trie.add(domain)

    sorted_rules = sorted(adblock_rules_set)
    header = generate_header(len(sorted_rules), duplicates_removed, redundant_rules_removed, filter_type)

    if filter_type == 'whitelist':
        sorted_rules = ['@@' + rule for rule in sorted_rules]

    return '\n'.join([header, '', *sorted_rules]), duplicates_removed, redundant_rules_removed

def generate_header(domain_count, duplicates_removed, redundant_rules_removed, filter_type):
    date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    title = {
        'blacklist': "Kin9Loui3's Compiled Blacklist",
        'whitelist': "Kin9Loui3's Compiled Whitelist"
    }.get(filter_type, "Filter")
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

    blacklist_urls = config_data.get('blacklist_urls', [])
    whitelist_urls = config_data.get('whitelist_urls', [])
    blacklist_filename = config_data.get('blacklist_filename', 'blacklist.txt')
    whitelist_filename = config_data.get('whitelist_filename', 'whitelist.txt')

    blacklist_contents = [requests.get(url).text for url in blacklist_urls]
    whitelist_contents = [requests.get(url).text for url in whitelist_urls]

    blacklist_content, _, _ = generate_filter(blacklist_contents, 'blacklist')
    whitelist_content, _, _ = generate_filter(whitelist_contents, 'whitelist')

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
