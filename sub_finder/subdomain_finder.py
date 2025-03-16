import logging
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import time
import re
import dns.resolver
import socket
from bs4 import BeautifulSoup # type: ignore

def chunk_list(lst, chunk_size):
    """Split a list into smaller chunks"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def search_wayback_machine(domain):
    """
    Enhanced Wayback Machine search with concurrent processing and pagination.
    """
    subdomains = set()
    try:
        url = f"http://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "page": "/",
            "limit": 100000
        }
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, params=params, headers=headers, timeout=30)
        if response.status_code != 200:
            logging.error(f"Wayback Machine returned status code: {response.status_code}")
            return list(subdomains)
            
        try:
            data = json.loads(response.text)
            if len(data) <= 1:  # Only header row present or empty
                return list(subdomains)
            urls = [line[0] for line in data[1:]]
        except json.JSONDecodeError:
            logging.error("Failed to parse Wayback Machine response")
            return list(subdomains)
        
        def process_url(url):
            try:
                parsed = urlparse(url)
                if parsed.netloc and parsed.netloc.endswith(domain):
                    return parsed.netloc.lower()
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(process_url, url) for url in urls]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and is_valid_subdomain(result, domain):
                        subdomains.add(result)
                except Exception as e:
                    logging.debug(f"Error processing URL: {str(e)}")
    
    except Exception as e:
        logging.error(f"Error in Wayback Machine search: {str(e)}")
    
    return list(subdomains)

def is_valid_subdomain(subdomain, domain):
    """
    Validate subdomain format and domain membership.
    """
    try:
        if not subdomain or not domain:
            return False
        if not subdomain.endswith(domain):
            return False
        subdomain_part = subdomain[:-len(domain)-1]
        if not subdomain_part:
            return False
        if len(subdomain) > 253 or len(subdomain_part) > 63:
            return False
        pattern = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
        if not pattern.match(subdomain_part):
            return False
        if '--' in subdomain_part:
            return False
        return True
    except Exception:
        return False

def ct_logs_subdomains(domain: str) -> list[str]:
    """
    Search Certificate Transparency logs for subdomains.
    """
    subdomains = set()
    ct_sources = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q=%.%.{domain}&output=json"
    ]

    def fetch_ct_data(url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, timeout=30, headers=headers)
            if response.status_code != 200:
                return
                
            try:
                data = response.json()
            except json.JSONDecodeError:
                logging.error(f"Failed to parse JSON from {url}")
                return

            for entry in data:
                names = []
                if isinstance(entry, dict):  # Verify entry is a dictionary
                    if "name_value" in entry:
                        names.extend(entry["name_value"].replace("*.", "").split("\n"))
                    if "common_name" in entry:
                        names.extend(entry["common_name"].replace("*.", "").split("\n"))
                    
                    for name in names:
                        name = name.strip().lower()
                        if name and name.endswith(domain) and "*" not in name:
                            if is_valid_subdomain(name, domain):
                                subdomains.add(name)
                                
        except Exception as e:
            logging.error(f"Error fetching CT data from {url}: {str(e)}")

    for url in ct_sources:
        fetch_ct_data(url)
        time.sleep(2)  # Rate limiting
    
    return list(subdomains)

def check_alive_parallel(subdomains, timeout=5):
    """
    Check if subdomains are alive using parallel processing.
    """
    results = {}
    
    def check_subdomain(subdomain):
        try:
            # Try DNS resolution first
            dns.resolver.resolve(subdomain, 'A')
            try:
                # Try connecting to the host
                socket.create_connection((subdomain, 80), timeout=timeout)
                return subdomain, True
            except:
                try:
                    # Try HTTPS if HTTP fails
                    socket.create_connection((subdomain, 443), timeout=timeout)
                    return subdomain, True
                except:
                    return subdomain, False
        except:
            return subdomain, False

    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain 
                             for subdomain in subdomains}
        
        for future in as_completed(future_to_subdomain):
            try:
                subdomain, is_alive = future.result()
                results[subdomain] = is_alive
            except Exception as e:
                subdomain = future_to_subdomain[future]
                results[subdomain] = False
                logging.debug(f"Error checking {subdomain}: {str(e)}")

    return results

class SubdomainFinder:
    def __init__(self, domain):
        self.domain = domain
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.timeout = 30

    def search_alienvault(self):
        subdomains = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "").lower()
                    if hostname and is_valid_subdomain(hostname, self.domain):
                        subdomains.add(hostname)
        except Exception as e:
            logging.error(f"Error in Alienvault search: {str(e)}")
        return list(subdomains)

    def search_certspotter(self):
        subdomains = set()
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    for dns_name in cert.get("dns_names", []):
                        if dns_name.lower().endswith(self.domain) and is_valid_subdomain(dns_name, self.domain):
                            subdomains.add(dns_name.lower())
        except Exception as e:
            logging.error(f"Error in Certspotter search: {str(e)}")
        return list(subdomains)

    def search_hackertarget(self):
        subdomains = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if ',' in line:
                        hostname = line.split(',')[0].lower()
                        if hostname and is_valid_subdomain(hostname, self.domain):
                            subdomains.add(hostname)
        except Exception as e:
            logging.error(f"Error in HackerTarget search: {str(e)}")
        return list(subdomains)

    def search_rapiddns(self):
        subdomains = set()
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}"
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                table = soup.find('table', {'class': 'table'})
                if table:
                    for row in table.find_all('tr'):
                        cols = row.find_all('td')
                        if cols and len(cols) > 0:
                            hostname = cols[0].text.strip().lower()
                            if hostname and is_valid_subdomain(hostname, self.domain):
                                subdomains.add(hostname)
        except Exception as e:
            logging.error(f"Error in RapidDNS search: {str(e)}")
        return list(subdomains)

def search_all_sources(domain):
    """
    Search all available sources for subdomains
    """
    finder = SubdomainFinder(domain)
    all_subdomains = set()
    
    # Define search functions
    search_functions = [
        (finder.search_alienvault, "Alienvault"),
        (finder.search_certspotter, "Certspotter"),
        (finder.search_hackertarget, "HackerTarget"),
        (finder.search_rapiddns, "RapidDNS"),
        (search_wayback_machine, "Wayback Machine"),
        (ct_logs_subdomains, "CT Logs")
    ]
    
    # Execute searches in parallel
    with ThreadPoolExecutor(max_workers=len(search_functions)) as executor:
        future_to_source = {
            executor.submit(func, domain) if func in [search_wayback_machine, ct_logs_subdomains] else executor.submit(func): 
            name for func, name in search_functions
        }
        
        for future in as_completed(future_to_source):
            source_name = future_to_source[future]
            try:
                result = future.result()
                if result:
                    new_count = len(set(result) - all_subdomains)
                    all_subdomains.update(result)
                    logging.info(f"Found {new_count} new subdomains from {source_name}")
            except Exception as e:
                logging.error(f"Error in {source_name} search: {str(e)}")
    
    return sorted(all_subdomains)
