# Domain Validator

A comprehensive Python tool for validating domain names by checking their DNS records, connectivity, and identifying parked domains.

## Overview

This script analyzes domains to determine if they are valid, active, and not parked. It performs multiple checks:

1. DNS record validation (MX and A records, with SPF and DMARC collection but not validation)
2. Live connectivity testing (HTTP/HTTPS/Socket)
3. Parked domain detection
4. Content analysis for parking indicators

The results are saved in a CSV file with detailed status information for each domain.

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
python3 email-domain-validator-new.py your_domain_list.csv [max_workers]
```

Where:
- `your_domain_list.csv` is a text file containing one domain per line
- `max_workers` (optional) is the number of concurrent threads to use (default: 10)

Example:
```bash
python3 email-domain-validator-new.py domaintest.csv 20
```

## Output

The script generates a timestamped CSV file with the following columns:
- **DOMAIN**: The domain name
- **STATUS**: Either "VALID" or "INVALID"
- **NOTES**: Detailed information about the validation result

Example filename: `domain_validation_results_20250314-123045.csv`

## Validation Categories

Domains can be categorized as:

- **Valid**: Active domain with proper DNS records
- **Invalid - invalid_format**: Domain name doesn't follow proper format
- **Invalid - no_dns_records**: Domain has no MX or A records
- **Invalid - parking_mx**: Domain uses MX records typical of parked domains
- **Invalid - restrictive_spf**: (Removed in current version) Previously flagged domains with restrictive SPF policies
- **Invalid - dead_domain**: Domain doesn't respond to connection attempts
- **Invalid - parked_domain**: Domain appears to be parked/unused
- **Invalid - error**: Error occurred during validation

## Features

- Multi-threaded processing for faster validation
- Comprehensive domain status checks
- Detailed parking detection algorithms
- Root domain fallback for subdomains
- Progress indicator during processing
- CSV output for easy analysis

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

## Troubleshooting

If you encounter false positives/negatives, you can adjust:

1. The `PARKING_KEYWORDS` list for keyword-based detection
2. The `PARKING_MX_PATTERNS` list for MX-record based detection
3. The parking pattern indicators in the `check_if_parked` method
