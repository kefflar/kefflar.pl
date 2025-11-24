#!/usr/bin/env python3
"""
WHOIS Domain Checker

A simple application to check domain information from WHOIS servers.
Reads a list of domains from a file and queries WHOIS data for each.
"""

import socket
import sys
import os
from datetime import datetime


# WHOIS server mappings for different TLDs
WHOIS_SERVERS = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'info': 'whois.afilias.net',
    'biz': 'whois.biz',
    'pl': 'whois.dns.pl',
    'de': 'whois.denic.de',
    'uk': 'whois.nic.uk',
    'co.uk': 'whois.nic.uk',
    'eu': 'whois.eu',
    'io': 'whois.nic.io',
    'co': 'whois.nic.co',
    'me': 'whois.nic.me',
    'us': 'whois.nic.us',
    'ca': 'whois.cira.ca',
    'au': 'whois.auda.org.au',
    'fr': 'whois.nic.fr',
    'it': 'whois.nic.it',
    'nl': 'whois.domain-registry.nl',
    'be': 'whois.dns.be',
    'ch': 'whois.nic.ch',
    'at': 'whois.nic.at',
    'ru': 'whois.tcinet.ru',
    'jp': 'whois.jprs.jp',
    'cn': 'whois.cnnic.cn',
    'in': 'whois.registry.in',
    'br': 'whois.registro.br',
}

DEFAULT_WHOIS_SERVER = 'whois.iana.org'

# Indicators that suggest a domain is available (not registered)
AVAILABLE_INDICATORS = [
    'no match', 'not found', 'no entries found',
    'no data found', 'domain not found', 'available'
]


def get_tld(domain):
    """Extract the top-level domain from a domain name."""
    parts = domain.lower().strip().split('.')
    if len(parts) >= 2:
        # Check for two-part TLDs like co.uk
        two_part = '.'.join(parts[-2:])
        if two_part in WHOIS_SERVERS:
            return two_part
        return parts[-1]
    return None


def get_whois_server(domain):
    """Get the appropriate WHOIS server for a domain."""
    tld = get_tld(domain)
    if tld and tld in WHOIS_SERVERS:
        return WHOIS_SERVERS[tld]
    return DEFAULT_WHOIS_SERVER


def query_whois(domain, whois_server, port=43, timeout=10):
    """
    Query a WHOIS server for domain information.
    
    Args:
        domain: The domain name to query
        whois_server: The WHOIS server to query
        port: WHOIS port (default 43)
        timeout: Socket timeout in seconds
    
    Returns:
        WHOIS response as string, or error message
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((whois_server, port))
        
        # Send query
        query = domain + '\r\n'
        sock.send(query.encode('utf-8'))
        
        # Receive response
        response = b''
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        
        return response.decode('utf-8', errors='ignore')
    
    except socket.timeout:
        return f"Error: Connection to {whois_server} timed out"
    except socket.gaierror:
        return f"Error: Could not resolve WHOIS server {whois_server}"
    except ConnectionRefusedError:
        return f"Error: Connection refused by {whois_server}"
    except OSError as e:
        return f"Error: {str(e)}"
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def parse_whois_info(whois_response):
    """
    Parse basic information from WHOIS response.
    
    Returns a dictionary with parsed fields.
    """
    info = {
        'registrar': None,
        'creation_date': None,
        'expiration_date': None,
        'updated_date': None,
        'status': [],
        'name_servers': []
    }
    
    lines = whois_response.lower().split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Registrar
        if 'registrar:' in line and not info['registrar']:
            info['registrar'] = line.split(':', 1)[-1].strip()
        
        # Creation date
        if any(x in line for x in ['creation date:', 'created:', 'registered:']):
            if not info['creation_date']:
                info['creation_date'] = line.split(':', 1)[-1].strip()
        
        # Expiration date
        if any(x in line for x in ['expir', 'renewal date:']):
            if ':' in line and not info['expiration_date']:
                info['expiration_date'] = line.split(':', 1)[-1].strip()
        
        # Updated date
        if any(x in line for x in ['updated date:', 'last updated:', 'modified:']):
            if not info['updated_date']:
                info['updated_date'] = line.split(':', 1)[-1].strip()
        
        # Status
        if 'status:' in line or 'domain status:' in line:
            status = line.split(':', 1)[-1].strip()
            if status and status not in info['status']:
                info['status'].append(status)
        
        # Name servers
        if 'name server:' in line or 'nserver:' in line:
            ns = line.split(':', 1)[-1].strip()
            if ns and ns not in info['name_servers']:
                info['name_servers'].append(ns)
    
    return info


def check_domain(domain):
    """
    Check a single domain and return formatted results.
    """
    domain = domain.lower().strip()
    whois_server = get_whois_server(domain)
    
    print(f"\n{'='*60}")
    print(f"Domain: {domain}")
    print(f"WHOIS Server: {whois_server}")
    print(f"{'='*60}")
    
    response = query_whois(domain, whois_server)
    
    if response.startswith('Error:'):
        print(response)
        return None
    
    info = parse_whois_info(response)
    
    # Print parsed information
    if info['registrar']:
        print(f"Registrar: {info['registrar']}")
    if info['creation_date']:
        print(f"Created: {info['creation_date']}")
    if info['expiration_date']:
        print(f"Expires: {info['expiration_date']}")
    if info['updated_date']:
        print(f"Updated: {info['updated_date']}")
    if info['status']:
        print(f"Status: {', '.join(info['status'][:3])}")
    if info['name_servers']:
        print(f"Name Servers: {', '.join(info['name_servers'][:4])}")
    
    # Check if domain appears to be available
    if any(indicator in response.lower() for indicator in AVAILABLE_INDICATORS):
        print("\n*** Domain appears to be AVAILABLE ***")
    else:
        print("\n*** Domain is REGISTERED ***")
    
    return response


def load_domains(filename):
    """
    Load domain list from a file.
    
    Args:
        filename: Path to the domains file
    
    Returns:
        List of domain names
    """
    domains = []
    
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        return domains
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    # Remove common prefixes
                    domain = line.lower()
                    domain = domain.replace('http://', '').replace('https://', '')
                    domain = domain.replace('www.', '')
                    domain = domain.split('/')[0]  # Remove path
                    domains.append(domain)
    except PermissionError:
        print(f"Error: Permission denied reading '{filename}'")
    except UnicodeDecodeError:
        print(f"Error: Unable to decode '{filename}' - invalid encoding")
    except IOError as e:
        print(f"Error reading file '{filename}': {e}")
    
    return domains


def main():
    """Main entry point for the WHOIS checker."""
    print("=" * 60)
    print("WHOIS Domain Checker")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Determine the domains file path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_domains_file = os.path.join(script_dir, 'domains.txt')
    
    # Check command line arguments
    if len(sys.argv) > 1:
        # If argument is a file, use it
        if os.path.exists(sys.argv[1]):
            domains_file = sys.argv[1]
            domains = load_domains(domains_file)
        else:
            # Treat arguments as domain names
            domains = sys.argv[1:]
    else:
        domains_file = default_domains_file
        domains = load_domains(domains_file)
    
    if not domains:
        print("\nNo domains to check.")
        print("\nUsage:")
        print(f"  {sys.argv[0]} [domains.txt]  - Check domains from file")
        print(f"  {sys.argv[0]} domain1 domain2 - Check specific domains")
        return 1
    
    print(f"\nChecking {len(domains)} domain(s)...")
    
    results = {}
    for domain in domains:
        try:
            results[domain] = check_domain(domain)
        except KeyboardInterrupt:
            print("\n\nInterrupted by user.")
            break
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Domains checked: {len(results)}")
    print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
