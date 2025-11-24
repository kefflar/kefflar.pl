# WHOIS Domain Checker

A simple Python application to check domain information from WHOIS servers.

## Features

- Query WHOIS information for multiple domains
- Support for many common TLDs (.com, .net, .org, .pl, .eu, etc.)
- Parse and display key domain information:
  - Registrar
  - Creation date
  - Expiration date
  - Domain status
  - Name servers
- Check if domains are available or registered
- Read domain list from file or command line

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only standard library)

## Usage

### Check domains from file

Create a `domains.txt` file with one domain per line:

```
example.com
google.com
kefflar.pl
```

Then run:

```bash
python whois_checker.py
```

Or specify a custom file:

```bash
python whois_checker.py my_domains.txt
```

### Check specific domains

```bash
python whois_checker.py example.com google.com kefflar.pl
```

## Domain List Format

The `domains.txt` file supports:
- One domain per line
- Comments starting with `#`
- Domains with or without `www.` or `http://` prefixes (automatically cleaned)

Example:

```
# My domains to check
kefflar.pl
example.com

# Other domains
google.com
```

## Supported TLDs

The checker includes WHOIS server mappings for many common TLDs:

- Generic: .com, .net, .org, .info, .biz
- Country: .pl, .de, .uk, .fr, .it, .nl, .be, .ch, .at, .ru, .jp, .cn, .in, .br, .ca, .au, .us
- New: .io, .co, .me, .eu

For unsupported TLDs, the checker falls back to IANA's WHOIS server.

## Example Output

```
============================================================
WHOIS Domain Checker
Started at: 2025-01-15 10:30:00
============================================================

Checking 2 domain(s)...

============================================================
Domain: example.com
WHOIS Server: whois.verisign-grs.com
============================================================
Registrar: reserved-internet assigned numbers authority
Created: 1995-08-14t04:00:00z
Expires: 2025-08-13t04:00:00z
Status: clientdeleteprohibited
Name Servers: a.iana-servers.net, b.iana-servers.net

*** Domain is REGISTERED ***

============================================================
SUMMARY
============================================================
Domains checked: 2
Completed at: 2025-01-15 10:30:05
```

## License

This project is open source and available for personal and commercial use.
