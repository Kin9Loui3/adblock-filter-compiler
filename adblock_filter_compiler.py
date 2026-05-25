import re
import requests
from requests.exceptions import RequestException
from datetime import datetime
import json
import os
from collections import Counter
import logging
import argparse
import sys

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Simple domain validator
domain_regex = re.compile(
    r"^(?=.{1,253}$)(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,63}$"
)

def is_valid_domain(domain):
    """Validate domain format"""
    return bool(domain_regex.fullmatch(domain))

def get_base_domain(domain):
    """Extract base domain (e.g., example.com from sub.example.com)"""
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

def fetch_url(url, retries=3, timeout=10):
    """Fetch URL with retry logic"""
    for attempt in range(1, retries + 1):
        try:
            logging.debug(f"Fetching {url} (attempt {attempt}/{retries})")
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            logging.info(f"Successfully fetched {url}")
            return response.text
        except RequestException as e:
            logging.warning(f"Attempt {attempt}/{retries} failed for {url}: {e}")
    
    logging.error(f"Failed to fetch {url} after {retries} attempts.")
    return ""

def parse_hosts_file(content):
    """Parse hosts file format and extract domains"""
    rules = set()
    
    for raw_line in content.splitlines():
        line = raw_line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith(('#', '!')):
            continue

        # Normalize 0.0.0.0 format
        if line.startswith('0.0.0.0') and not line.startswith('0.0.0.0 '):
            line = line.replace('0.0.0.0', '0.0.0.0 ', 1)

        # Split and extract domain
        parts = re.split(r'\s+', line, maxsplit=2)
        if not parts:
            continue

        domain = parts[-1].strip()
        
        # Handle adblock format
        if domain.startswith('||') and domain.endswith('^'):
            domain = domain[2:-1]
        
        # Validate and add
        if is_valid_domain(domain):
            rules.add(f'||{domain}^')
    
    return rules

def generate_filter(file_contents, filter_type, deduplicate=True, minify=True):
    """Generate compiled filter list"""
    raw_rules = set()
    
    # Collect all rules
    for content in file_contents:
        if content:  # Skip empty content
            raw_rules |= parse_hosts_file(content)

    if not raw_rules:
        logging.info(f"No domains found for {filter_type}. Skipping filter generation.")
        return "", 0, 0

    seen_base = set()
    final = []
    duplicates_removed = 0
    redundant_removed = 0

    # Deduplicate and minify
    for rule in sorted(raw_rules):
        domain = rule[2:-1]  # Remove ||domain^
        base = get_base_domain(domain)
        
        if minify and base in seen_base:
            redundant_removed += 1
            continue
        
        seen_base.add(base)
        final.append(rule)

    # Generate header
    header = generate_header(
        len(final), 
        len(raw_rules) - len(final), 
        redundant_removed, 
        filter_type
    )
    
    # Add whitelist prefix if needed
    if filter_type == 'whitelist':
        final = ['@@' + r for r in final]

    output = "\n".join([header, '', *final])
    return output, len(raw_rules) - len(final), redundant_removed

def generate_header(count, removed_dupes, removed_redund, filter_type):
    """Generate filter list header"""
    date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    title = f"Kin9Loui3's Compiled {'Blacklist' if filter_type == 'blacklist' else 'Whitelist'}"
    
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
    """Process a single config file"""
    logging.info(f"Processing config: {config_file}")
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logging.error(f"Error reading {config_file}: {e}")
        return

    # Extract config values
    dedup = cfg.get('deduplicate', True)
    mini = cfg.get('minify', True)
    bl_urls = cfg.get('blacklist_urls', [])
    wl_urls = cfg.get('whitelist_urls', [])
    bl_fname = cfg.get('blacklist_filename', 'black
