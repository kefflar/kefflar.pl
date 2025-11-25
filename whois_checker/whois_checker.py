#!/usr/bin/env python3
"""
WHOIS domain checker script.

Queries WHOIS information for domains and can output results to CSV.
"""

import argparse
import csv
import os
import socket
import sys
from datetime import datetime

# Common indicators that a domain is available
AVAILABLE_INDICATORS = [
    "No match for",
    "NOT FOUND",
    "No entries found",
    "No Data Found",
    "AVAILABLE",
    "Status: free",
    "is free",
    "Domain not found",
]

# Default WHOIS server
DEFAULT_WHOIS_SERVER = "whois.verisign-grs.com"

# WHOIS servers for different TLDs
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "biz": "whois.biz",
    "us": "whois.nic.us",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "pl": "whois.dns.pl",
    "eu": "whois.eu",
    "nl": "whois.domain-registry.nl",
    "fr": "whois.nic.fr",
    "ru": "whois.tcinet.ru",
    "ch": "whois.nic.ch",
    "at": "whois.nic.at",
    "be": "whois.dns.be",
    "ca": "whois.cira.ca",
    "au": "whois.auda.org.au",
    "jp": "whois.jprs.jp",
    "cn": "whois.cnnic.cn",
    "in": "whois.registry.in",
    "br": "whois.registro.br",
    "mx": "whois.mx",
    "es": "whois.nic.es",
    "it": "whois.nic.it",
    "se": "whois.iis.se",
    "no": "whois.norid.no",
    "fi": "whois.fi",
    "dk": "whois.dk-hostmaster.dk",
}


def get_whois_server(domain):
    """Get the appropriate WHOIS server for a domain's TLD."""
    tld = domain.rsplit(".", 1)[-1].lower()
    return WHOIS_SERVERS.get(tld, DEFAULT_WHOIS_SERVER)


def query_whois(domain, whois_server=None, timeout=10):
    """
    Query WHOIS information for a domain.

    Args:
        domain: The domain name to query
        whois_server: Optional WHOIS server to use
        timeout: Socket timeout in seconds

    Returns:
        String containing WHOIS response or error message starting with "Error:"
    """
    if whois_server is None:
        whois_server = get_whois_server(domain)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((whois_server, 43))
        sock.send((domain + "\r\n").encode("utf-8"))

        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()

        return response.decode("utf-8", errors="replace")
    except socket.timeout:
        return f"Error: Connection to {whois_server} timed out"
    except socket.gaierror as e:
        return f"Error: DNS resolution failed for {whois_server}: {e}"
    except ConnectionRefusedError:
        return f"Error: Connection refused by {whois_server}"
    except OSError as e:
        return f"Error: {e}"


def parse_whois_response(response):
    """
    Parse WHOIS response to extract common fields.

    Args:
        response: Raw WHOIS response string

    Returns:
        Dictionary with parsed fields
    """
    parsed = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "status": [],
        "name_servers": [],
        "whois_server": None,
    }

    if not response or response.startswith("Error:"):
        return parsed

    lines = response.split("\n")
    for line in lines:
        line = line.strip()
        lower_line = line.lower()

        # Registrar
        if (
            lower_line.startswith("registrar:")
            or lower_line.startswith("sponsoring registrar:")
            or lower_line.startswith("registrar name:")
        ):
            value = line.split(":", 1)[-1].strip()
            if value and not parsed["registrar"]:
                parsed["registrar"] = value

        # Creation date
        if any(
            x in lower_line
            for x in [
                "creation date:",
                "created:",
                "created on:",
                "registration date:",
                "domain registration date:",
            ]
        ):
            value = line.split(":", 1)[-1].strip()
            if value and not parsed["creation_date"]:
                parsed["creation_date"] = value

        # Expiration date
        if any(
            x in lower_line
            for x in [
                "expiration date:",
                "expiry date:",
                "expires:",
                "expires on:",
                "registry expiry date:",
                "registrar registration expiration date:",
                "paid-till:",
            ]
        ):
            value = line.split(":", 1)[-1].strip()
            if value and not parsed["expiration_date"]:
                parsed["expiration_date"] = value

        # Updated date
        if any(
            x in lower_line
            for x in [
                "updated date:",
                "last updated:",
                "last modified:",
                "modified:",
                "changed:",
            ]
        ):
            value = line.split(":", 1)[-1].strip()
            if value and not parsed["updated_date"]:
                parsed["updated_date"] = value

        # Status
        if lower_line.startswith("domain status:") or lower_line.startswith("status:"):
            value = line.split(":", 1)[-1].strip()
            if value:
                parsed["status"].append(value)

        # Name servers
        if lower_line.startswith("name server:") or lower_line.startswith("nserver:"):
            value = line.split(":", 1)[-1].strip()
            if value:
                parsed["name_servers"].append(value)

        # WHOIS server
        if lower_line.startswith("whois server:") or lower_line.startswith(
            "registrar whois server:"
        ):
            value = line.split(":", 1)[-1].strip()
            if value and not parsed["whois_server"]:
                parsed["whois_server"] = value

    return parsed


def check_availability(response):
    """
    Check if a domain is available based on WHOIS response.

    Args:
        response: WHOIS response string

    Returns:
        "AVAILABLE", "REGISTERED", or "ERROR"
    """
    if not response:
        return "ERROR"

    if response.startswith("Error:"):
        return "ERROR"

    for indicator in AVAILABLE_INDICATORS:
        if indicator.lower() in response.lower():
            return "AVAILABLE"

    return "REGISTERED"


def check_domain(domain, verbose=True):
    """
    Check WHOIS information for a domain.

    Args:
        domain: Domain name to check
        verbose: Whether to print detailed output

    Returns:
        Dictionary with all parsed fields and metadata:
        - domain: the domain name
        - registrar: registrar name or None
        - creation_date: creation date string or None
        - expiration_date: expiration date string or None
        - updated_date: last updated date string or None
        - status: list of domain statuses
        - name_servers: list of name servers
        - whois_server: WHOIS server used or None
        - availability: "AVAILABLE", "REGISTERED", or "ERROR"
        - error_message: error message if any, or None
        - raw_response: full WHOIS response string
        - timestamp: ISO format timestamp of when check was performed
    """
    timestamp = datetime.now().isoformat()
    whois_server = get_whois_server(domain)

    if verbose:
        print(f"\n{'='*60}")
        print(f"Checking domain: {domain}")
        print(f"Using WHOIS server: {whois_server}")
        print(f"{'='*60}")

    response = query_whois(domain, whois_server)
    availability = check_availability(response)
    parsed = parse_whois_response(response)

    error_message = None
    if response.startswith("Error:"):
        error_message = response
    elif availability == "ERROR":
        error_message = "Unknown error or empty response"

    result = {
        "domain": domain,
        "registrar": parsed["registrar"],
        "creation_date": parsed["creation_date"],
        "expiration_date": parsed["expiration_date"],
        "updated_date": parsed["updated_date"],
        "status": parsed["status"],
        "name_servers": parsed["name_servers"],
        "whois_server": parsed["whois_server"] or whois_server,
        "availability": availability,
        "error_message": error_message,
        "raw_response": response,
        "timestamp": timestamp,
    }

    if verbose:
        print(f"\nAvailability: {availability}")
        if error_message:
            print(f"Error: {error_message}")
        else:
            print("\nParsed Fields:")
            print(f"  Registrar: {parsed['registrar']}")
            print(f"  Creation Date: {parsed['creation_date']}")
            print(f"  Expiration Date: {parsed['expiration_date']}")
            print(f"  Updated Date: {parsed['updated_date']}")
            status_str = ', '.join(parsed['status']) if parsed['status'] else 'N/A'
            print(f"  Status: {status_str}")
            ns_str = ', '.join(parsed['name_servers']) if parsed['name_servers'] else 'N/A'
            print(f"  Name Servers: {ns_str}")
            print(f"  WHOIS Server: {parsed['whois_server']}")
            print("\nRaw WHOIS Response:")
            print("-" * 40)
            print(response[:2000] if len(response) > 2000 else response)
            if len(response) > 2000:
                print(f"\n... (truncated, {len(response)} total characters)")

    return result


def save_results_csv(results, output_file, append=False):
    """
    Save results to a CSV file.

    Args:
        results: List of result dictionaries from check_domain()
        output_file: Path to the output CSV file
        append: If True and file exists, append rows; otherwise overwrite

    Raises:
        IOError, PermissionError: If file cannot be written
    """
    fieldnames = [
        "domain",
        "availability",
        "registrar",
        "creation_date",
        "expiration_date",
        "updated_date",
        "status",
        "name_servers",
        "whois_server",
        "error_message",
        "timestamp",
    ]

    file_exists = os.path.exists(output_file)
    mode = "a" if append and file_exists else "w"
    write_header = not (append and file_exists)

    # Check if existing file has header when appending
    if append and file_exists:
        try:
            with open(output_file, "r", encoding="utf-8", newline="") as f:
                reader = csv.reader(f)
                first_row = next(reader, None)
                # If first row matches our fieldnames, it's a header
                if first_row == fieldnames:
                    write_header = False
                else:
                    write_header = False  # Don't add duplicate headers
        except (IOError, StopIteration):
            pass

    with open(output_file, mode, encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")

        if write_header:
            writer.writeheader()

        for result in results:
            row = {
                "domain": result.get("domain", ""),
                "availability": result.get("availability", ""),
                "registrar": result.get("registrar") or "",
                "creation_date": result.get("creation_date") or "",
                "expiration_date": result.get("expiration_date") or "",
                "updated_date": result.get("updated_date") or "",
                "status": ";".join(result.get("status", [])) if result.get("status") else "",
                "name_servers": ";".join(result.get("name_servers", []))
                if result.get("name_servers")
                else "",
                "whois_server": result.get("whois_server") or "",
                "error_message": result.get("error_message") or "",
                "timestamp": result.get("timestamp", ""),
            }
            writer.writerow(row)


def load_domains_from_file(filepath):
    """
    Load domain names from a file, one per line.

    Args:
        filepath: Path to the file containing domain names

    Returns:
        List of domain names
    """
    domains = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith("#"):
                domains.append(line)
    return domains


def main():
    """Main entry point for the WHOIS checker."""
    parser = argparse.ArgumentParser(
        description="Check WHOIS information for domains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com example.org
  %(prog)s domains.txt
  %(prog)s -o results.csv example.com example.org
  %(prog)s domains.txt -o results.csv --append
  %(prog)s -v example.com
""",
    )

    parser.add_argument(
        "domains",
        nargs="*",
        help="Domain names to check, or a single file path containing domains",
    )

    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Path to CSV file to write results (default: None)",
    )

    parser.add_argument(
        "--append",
        action="store_true",
        help="If output file exists, append rows instead of overwriting",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print detailed WHOIS output to stdout",
    )

    args = parser.parse_args()

    # Determine domains to check
    domains_to_check = []

    if args.domains:
        # Check if single argument that is a file path
        if len(args.domains) == 1 and os.path.isfile(args.domains[0]):
            try:
                domains_to_check = load_domains_from_file(args.domains[0])
                print(f"Loaded {len(domains_to_check)} domains from {args.domains[0]}")
            except IOError as e:
                print(f"Error reading file {args.domains[0]}: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            # Treat arguments as domain names
            domains_to_check = args.domains
    else:
        # Fall back to default domains.txt in script directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        default_file = os.path.join(script_dir, "domains.txt")
        if os.path.isfile(default_file):
            try:
                domains_to_check = load_domains_from_file(default_file)
                print(f"Loaded {len(domains_to_check)} domains from {default_file}")
            except IOError as e:
                print(f"Error reading file {default_file}: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print("No domains specified and no default domains.txt found.", file=sys.stderr)
            print("Usage: python whois_checker.py <domain1> [domain2] ... [-o output.csv]")
            sys.exit(1)

    if not domains_to_check:
        print("No domains to check.", file=sys.stderr)
        sys.exit(1)

    # Check each domain
    results = []
    total = len(domains_to_check)

    for i, domain in enumerate(domains_to_check, 1):
        # Print minimal progress even when not verbose
        if not args.verbose:
            print(f"[{i}/{total}] Checking {domain}...")

        result = check_domain(domain, verbose=args.verbose)
        results.append(result)

        # Print minimal status when not verbose
        if not args.verbose:
            status_msg = result["availability"]
            if result["error_message"]:
                status_msg = f"ERROR: {result['error_message'][:50]}"
            print(f"  -> {status_msg}")

    # Save to CSV if output file specified
    if args.output:
        try:
            save_results_csv(results, args.output, append=args.append)
            print(f"\nResults saved to {args.output}")
        except PermissionError as e:
            print(f"Error: Permission denied writing to {args.output}: {e}", file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(f"Error: Failed to write to {args.output}: {e}", file=sys.stderr)
            sys.exit(1)

    # Print summary
    print(f"\n{'='*60}")
    print("Summary:")
    available_count = sum(1 for r in results if r["availability"] == "AVAILABLE")
    registered_count = sum(1 for r in results if r["availability"] == "REGISTERED")
    error_count = sum(1 for r in results if r["availability"] == "ERROR")
    print(f"  Total domains checked: {total}")
    print(f"  Available: {available_count}")
    print(f"  Registered: {registered_count}")
    print(f"  Errors: {error_count}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
