# Domain Validator

A comprehensive Python tool for validating domain names by checking their DNS records, connectivity, and identifying parked domains.

## Overview

This script analyzes domains to determine if they are valid, active, and not parked. It performs multiple checks:

1. DNS record validation (MX and A records, with SPF and DMARC collection but not validation)
2. Live connectivity testing (HTTP/HTTPS/Socket)
3. Parked domain detection
4. Content analysis for parking indicators

The results are saved in a CSV file with detailed status information for each domain, allowing for better analysis of potential false positives.

## Requirements

- Python 3.6+
- Required Python packages:
  - dnspython
  - requests
  - beautifulsoup4

## Installation

Install required packages:

```bash
pip install dnspython requests beautifulsoup4
```

## Usage

```bash
python3 email-domain-validator-modified.py your_domain_list.csv [max_workers]
```

Where:
- `your_domain_list.csv` is a text file containing one domain per line
- `max_workers` (optional) is the number of concurrent threads to use (default: 10)

Example:
```bash
python3 email-domain-validator-modified.py domaintest.csv 20
```

## Output

The script generates a timestamped CSV file with the following columns:

- **DOMAIN**: The domain name
- **MX RECORD**: Whether the domain has MX records (True/False)
- **A RECORD**: Whether the domain has A records (True/False)
- **SITE LIVE**: Whether the domain's website is accessible (True/False)
- **PARKED DOMAIN**: Whether the domain appears to be parked (True/False)
- **STATUS**: "Valid", "Invalid", or "Risky"
- **NOTES**: Detailed information about the validation result

Example filename: `domain_validation_results_20250318-123045.csv`

## Validation Categories

Domains are now categorized into three clear statuses:

- **Valid**: Domain passes all checks - has DNS records, site is live, and isn't parked
- **Invalid**: Domain fails basic checks or is parked - includes domains with no DNS records, parked domains, unreachable domains with no MX records
- **Risky**: Domain has MX records (could potentially receive email) but the site isn't live - these domains require manual review

## Features

- Multi-threaded processing for faster validation
- Comprehensive domain status checks
- Detailed parking detection algorithms
- Root domain fallback for subdomains
- Progress indicator during processing with status-based emoji indicators (✅, ❌, ⚠️)
- Enhanced CSV output with detailed status attributes for better analysis of potential false positives

## Email Security Records

The script collects but does not use for validation:

- **SPF Records**: Collects Sender Policy Framework records that specify authorized email senders
- **DMARC Records**: Collects Domain-based Message Authentication, Reporting & Conformance records

These are collected for informational purposes but aren't used to invalidate domains since many legitimate domains may not have these configured.

## Parking Detection

The script uses multiple methods to detect parked domains:

1. Known parking MX record patterns
2. Parking service URL detection
3. Content analysis for parking keywords
4. Common parking page patterns (Whois lookup, related searches, etc.)
5. Registration placeholder page detection

## Understanding Results

The expanded CSV format provides more granular information to help identify potential false positives:

- If a domain has **MX RECORD = True** but **SITE LIVE = False**, it's marked as "Risky" since it may still be used for email even without a website
- Domains with **PARKED DOMAIN = True** are always "Invalid" regardless of other factors
- Domains need both DNS records and a live site to be marked "Valid"

## Troubleshooting

If you encounter false positives/negatives, you can adjust:

1. The `PARKING_KEYWORDS` list for keyword-based detection
2. The `PARKING_MX_PATTERNS` list for MX-record based detection
3. The parking pattern indicators in the `check_if_parked` method
4. The classification logic in the `check_domain_validity` method

## Changelog from Previous Version

- Added new status category "Risky" for domains with MX records but no live site
- Expanded CSV output to include detailed check results (MX records, A records, site liveness, parking status)
- Simplified status classification to three categories: Valid, Invalid, Risky
- Improved console output with status-specific emoji indicators
- Enhanced handling of domains that have email capability but no website
