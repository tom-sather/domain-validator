import dns.resolver
import requests
import sys
import re
import socket
import concurrent.futures
import time
import csv
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class DomainValidator:
    def __init__(self):
        # Common parking page indicators - more specific to avoid false positives
        self.PARKING_KEYWORDS = [
            "domain is for sale", "buy this domain", 
            "domain parking", "parked domain", 
            "domain may be for sale", "domain auction",
            "this web page is parked", "this domain is parked", 
            "purchase this domain", "inquire about this domain",
            "domain broker", "domain for purchase",
            "coming soon", "register.com", "domain registration",
            "related searches", "whois lookup", "domain name",
            "this domain is available", "pending renewal or deletion",
            "under construction", "page is under construction", "coming soon",
            "networksolutions", "this page is under construction",
            "digi-searches", "why am i seeing this", "trademark free notice"
        ]

    def check_domain_validity(self, domain):
        """Comprehensive check of domain including DNS records and domain status."""
        try:
            # Basic format validation
            if not re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$", domain):
                return {
                    "domain": domain,
                    "valid": False,
                    "mx_records": False,
                    "a_records": False,
                    "site_live": False,
                    "parked_domain": False,
                    "status": "Invalid",
                    "reason": "Invalid domain format"
                }
            
            domain = domain.strip().lower()
            
            results = {
                "domain": domain,
                "mx_records": False,
                "a_records": False,
                "spf_record": None,
                "dmarc_record": None,
                "site_live": False,
                "parked_domain": False,
                "valid": False,
                "status": "Unknown",
                "reason": ""
            }
            
            # VERY specific parking MX patterns to avoid false positives
            PARKING_MX_PATTERNS = [
                "park-mx.above.com", 
                "sedoparking.com",
                "h-email.net",
                "parkingcrew.net",
                "bodis.com/parking",
                "fabulous.com/park"
            ]
            
            # Check MX records
            mx_parking_detected = False
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                results["mx_records"] = True
                
                # Check for parking MX patterns (much more specific now)
                for record in mx_records:
                    mx_host = record.exchange.to_text().lower()
                    for pattern in PARKING_MX_PATTERNS:
                        if pattern in mx_host:
                            mx_parking_detected = True
                            results["parking_mx"] = mx_host
                            break
                    if mx_parking_detected:
                        break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.DNSException):
                pass
                
            # Check A records if no MX records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                results["a_records"] = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.DNSException):
                pass
                
            # Check SPF record (but don't invalidate for restrictive SPF)
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                for record in txt_records:
                    record_text = record.to_text()
                    if "v=spf1" in record_text:
                        results["spf_record"] = record_text
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.DNSException):
                pass
                
            # Check DMARC record
            try:
                dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
                for record in dmarc_records:
                    record_text = record.to_text()
                    if "v=DMARC1" in record_text:
                        results["dmarc_record"] = record_text
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.DNSException):
                pass
                
            # Decision logic for DNS records - only invalidate for no DNS records or clear parking
            if not results["mx_records"] and not results["a_records"]:
                results["status"] = "Invalid"
                results["reason"] = "No MX or A records found"
                return results
            
            if results.get("parking_mx", False):
                results["parked_domain"] = True
                results["status"] = "Invalid"
                results["reason"] = f"Domain uses parking MX: {results['parking_mx']}"
                return results
            
            # If we've made it here, the domain passes DNS checks
            # Now check if the domain is actually live
            domain_status = self.check_domain_liveness(domain)
            
            # Set site_live based on domain status
            results["site_live"] = domain_status["status"] == "live"
            results["domain_details"] = domain_status["details"]
            
            # Check if the domain is parked
            if domain_status["status"] == "parked":
                results["parked_domain"] = True
                results["status"] = "Invalid"
                results["reason"] = domain_status["details"]
            elif domain_status["status"] == "dead":
                # Site is not live
                if results["mx_records"]:
                    # MX records exist but site is dead - Risky
                    results["status"] = "Risky"
                    results["reason"] = "Has MX records but site isn't live"
                else:
                    # No MX and site is dead - Invalid
                    results["status"] = "Invalid"
                    results["reason"] = domain_status["details"]
            else:
                # Domain is live and not parked - Valid
                results["status"] = "Valid"
                results["reason"] = "Domain passed all checks"
            
            # Determine validity based on status
            results["valid"] = results["status"] == "Valid"
            
            return results
        
        except Exception as e:
            return {
                "domain": domain,
                "mx_records": False,
                "a_records": False,
                "site_live": False,
                "parked_domain": False,
                "valid": False,
                "status": "Invalid",
                "reason": f"Error checking records: {str(e)}"
            }

    def check_domain_liveness(self, domain):
        """Check if a domain is live, dead, or parked. Also checks root domain if subdomain is dead."""
        domain = domain.strip().lower()
        
        # Try the actual domain first
        domain_status = self._check_single_domain(domain)
        
        # If domain is dead and it's a subdomain, try checking the root domain
        if domain_status["status"] == "dead" and domain.count('.') > 1:
            # Extract the root domain (last two parts of the domain)
            parts = domain.split('.')
            root_domain = '.'.join(parts[-2:])
            
            # Check if there are enough parts to consider it a subdomain
            if len(parts) > 2:
                print(f"  Checking root domain {root_domain} for {domain}...")
                root_status = self._check_single_domain(root_domain)
                
                # If root domain is live, mark as "subdomain_dead"
                if root_status["status"] == "live":
                    return {
                        "status": "subdomain_dead", 
                        "details": f"Subdomain is dead, but root domain {root_domain} is live"
                    }
        
        return domain_status
    
    def _check_single_domain(self, domain):
        """Check if a single domain is live, dead, or parked."""
        
        # Try HTTPS first
        try:
            response = requests.get(f"https://{domain}", timeout=10, allow_redirects=True, 
                                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            
            if response.status_code < 400:
                is_parked, parking_reason = self.check_if_parked(domain, response)
                if is_parked:
                    return {"status": "parked", "details": parking_reason}
                return {"status": "live", "details": f"HTTPS: {response.status_code}"}
        except requests.exceptions.SSLError:
            # SSL error, try HTTP
            pass
        except requests.exceptions.RequestException:
            # Other errors, try HTTP
            pass
        
        # Try HTTP if HTTPS failed
        try:
            response = requests.get(f"http://{domain}", timeout=10, allow_redirects=True,
                                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            
            if response.status_code < 400:
                is_parked, parking_reason = self.check_if_parked(domain, response)
                if is_parked:
                    return {"status": "parked", "details": parking_reason}
                return {"status": "live", "details": f"HTTP: {response.status_code}"}
        except requests.exceptions.RequestException:
            pass
        
        # Check if server responds to socket connection
        try:
            socket.create_connection((domain, 80), timeout=5)
            return {"status": "live", "details": "Socket connection successful, but HTTP failed"}
        except (socket.timeout, socket.error):
            try:
                socket.create_connection((domain, 443), timeout=5)
                return {"status": "live", "details": "Socket connection successful, but HTTP failed"}
            except (socket.timeout, socket.error):
                return {"status": "dead", "details": "Failed all connection attempts"}

    def check_if_parked(self, domain, response=None):
        """Check if a domain appears to be parked based on content analysis."""
        try:
            if not response:
                try:
                    response = requests.get(f"http://{domain}", timeout=10, 
                                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
                except:
                    return False, "Could not analyze content"
            
            # Check for common parking service redirects - very specific
            parking_services = [
                "sedoparking.com", "hugedomains.com/domain_profile", "godaddyparking.com", 
                "parkingcrew.net", "parklogic.com", "fabulous.com/park", "bodis.com/parking",
                "register.com/domain", "registrar.godaddy.com", "networksolutions.com/manage-it",
                "domainsponsor", "domaincontrol.com", "namesilo.com/domain",
                "namedrive.com", "crazydomains.com", "buydomains.com", "parked.namecheap.com",
                "i2.cdn-image.com", "digi-searches.com", "cdn-image.com", "cdn.consentmanager.net", 
                "delivery.consentmanager.net"
            ]
            
            if any(parking_service in response.url.lower() for parking_service in parking_services):
                return True, "Redirects to parking service"
            
            # Check content for parking indicators
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract text from title and body
                title = soup.title.text.lower() if soup.title else ""
                
                # Look for very specific parking indicators in title
                for keyword in self.PARKING_KEYWORDS:
                    if keyword.lower() in title:
                        return True, f"Contains parking keyword in title: '{keyword}'"
                
                # More strict checks to avoid false positives
                body_text = soup.get_text().lower()
                parking_phrase_count = 0
                
                for keyword in self.PARKING_KEYWORDS:
                    if keyword.lower() in body_text:
                        parking_phrase_count += 1
                
                # Need multiple parking phrases to consider it parked
                if parking_phrase_count >= 3:
                    return True, f"Contains multiple parking keywords ({parking_phrase_count})"
                
                # Additional content checks for Network Solutions and similar 'under construction' pages
                network_solutions_indicators = [
                    "related searches" in body_text and "under construction" in body_text,
                    "page is under construction" in body_text and len(soup.find_all('a')) > 5,
                    "this domain" in body_text and "under construction" in body_text,
                    "cdn-image.com" in str(soup) or "digi-searches.com" in str(soup),
                    "networksolutions.com" in str(soup) and "under construction" in body_text,
                    "trademark free notice" in body_text.lower(),
                    soup.find('img', {'src': re.compile(r'.*cdn-image\.com.*')}) is not None,
                    soup.find('a', {'href': re.compile(r'.*digi-searches\.com.*')}) is not None,
                    "trademark" in body_text and "notice" in body_text and "networksolutions" in str(soup).lower(),
                    "why am i seeing this" in body_text.lower() and "under construction" in body_text.lower()
                ]
                
                if any(network_solutions_indicators):
                    return True, "Detected Network Solutions 'Under Construction' page"
                
                # Also check for standard parking patterns
                parking_indicators = [
                    "coming soon" in body_text and "register" in body_text and "domain" in body_text,
                    "related searches" in body_text and len(soup.find_all(['a'])) > 10,
                    "domain" in title.lower() and "register" in body_text and ("for sale" in body_text or "parked" in body_text),
                    "whois lookup" in body_text and "domain registration" in body_text,
                    "copyright" in body_text and "register.com" in body_text,
                    len(body_text.strip()) < 300 and len(soup.find_all(['a'])) > 15 and "domain" in body_text,
                    "coming soon" in title.lower() and "domain" in title.lower(),
                    "parked" in title.lower(),
                    soup.find('a', string=re.compile(r'Whois\s+Lookup', re.I)) is not None and len(body_text.strip()) < 800
                ]
                
                if any(parking_indicators):
                    return True, "Detected parking page pattern"
                
            except Exception as e:
                return False, f"Could not parse HTML content: {str(e)}"
                
            return False, "Not parked"
        
        except Exception as e:
            return False, f"Error checking parking status: {str(e)}"

    def process_domain_list(self, filename, max_workers=10):
        """Process a list of domains and check their validity."""
        try:
            with open(filename, 'r') as f:
                domains = [line.strip() for line in f if line.strip() and '.' in line.strip()]
            
            print(f"Loaded {len(domains)} domains from {filename}")
            
            results = {
                "Valid": [],
                "Invalid": [],
                "Risky": []
            }
            
            # Store the full results for CSV export
            detailed_results = []
            
            # Use ThreadPoolExecutor for concurrent checks
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_domain = {executor.submit(self.check_domain_validity, domain): domain for domain in domains}
                
                # Process results as they complete
                for i, future in enumerate(concurrent.futures.as_completed(future_to_domain)):
                    domain = future_to_domain[future]
                    try:
                        result = future.result()
                        status = result["status"]
                        
                        # Add to the appropriate category
                        if status in results:
                            results[status].append((result["domain"], result["reason"]))
                        
                        # Add to detailed results for CSV export
                        detailed_results.append(result)
                        
                        # Print progress with appropriate emoji
                        emoji_map = {"Valid": "✅", "Invalid": "❌", "Risky": "⚠️"}
                        emoji = emoji_map.get(status, "❓")
                        print(f"[{i+1}/{len(domains)}] {emoji} {status}: {result['domain']} ({result['reason']})")
                            
                    except Exception as e:
                        print(f"[{i+1}/{len(domains)}] ❌ ERROR: {domain} ({str(e)})")
                        results["Invalid"].append((domain, str(e)))
                        
                        # Add error result to detailed results
                        detailed_results.append({
                            "domain": domain,
                            "mx_records": False,
                            "a_records": False,
                            "site_live": False,
                            "parked_domain": False,
                            "status": "Invalid",
                            "reason": str(e)
                        })
            
            # Print summary
            print("\n" + "="*50)
            print("SUMMARY:")
            print("="*50)
            print(f"Total domains: {len(domains)}")
            print(f"Valid domains: {len(results['Valid'])}")
            print(f"Risky domains: {len(results['Risky'])}")
            print(f"Invalid domains: {len(results['Invalid'])}")
            
            # Generate filename with timestamp
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            csv_filename = f'domain_validation_results_{timestamp}.csv'
            
            # Write results to CSV file with new columns
            with open(csv_filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['DOMAIN', 'MX RECORD', 'A RECORD', 'SITE LIVE', 'PARKED DOMAIN', 'STATUS', 'NOTES'])
                
                # Write all domains
                for result in detailed_results:
                    writer.writerow([
                        result["domain"],
                        "True" if result.get("mx_records", False) else "False",
                        "True" if result.get("a_records", False) else "False",
                        "True" if result.get("site_live", False) else "False",
                        "True" if result.get("parked_domain", False) else "False",
                        result["status"],
                        result["reason"]
                    ])
            
            print(f"\nResults saved to '{csv_filename}'")
            
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found.")
            sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("Usage: python domain_validator.py domains.txt [max_workers]")
        sys.exit(1)
    
    filename = sys.argv[1]
    max_workers = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    validator = DomainValidator()
    
    start_time = time.time()
    validator.process_domain_list(filename, max_workers)
    elapsed_time = time.time() - start_time
    
    print(f"\nCompleted in {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()
