import logging
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import time
import re
from multiprocessing import Pool, cpu_count
import random

def chunk_list(lst, chunk_size):
    """Split a list into smaller chunks"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def search_wayback_machine(domain):
    """
    Enhanced Wayback Machine search with concurrent processing and pagination.
    """
    subdomains = set()
    try:
        # First, get the CDX API results
        url = f"http://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "page": "/",
            "limit": 100000  # Increased limit for more results
        }
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        try:
            response = requests.get(url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP error during Wayback Machine request: {e}")
            return list(subdomains)
        except requests.exceptions.RequestException as e:
            logging.error(f"Request error during Wayback Machine request: {e}")
            return list(subdomains)
        
        # Process URLs in parallel using ThreadPoolExecutor
        try:
            urls = [line[0] for line in json.loads(response.text)[1:]]  # Skip header row
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding Wayback Machine JSON response: {e}")
            return list(subdomains)
        
        def process_url(url):
            try:
                parsed = urlparse(url)
                if parsed.netloc and parsed.netloc.endswith(domain):
                    return parsed.netloc
            except Exception as e:
                logging.error(f"Error processing URL {url}: {e}")
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(process_url, url) for url in urls]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        subdomains.add(result)
                except Exception as e:
                    logging.error(f"Error getting result from future: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred in search_wayback_machine: {e}")
    
    return list(subdomains)

def is_valid_subdomain(subdomain, domain):
    """
    Validate if a subdomain is properly formatted and belongs to the domain.
    
    Args:
        subdomain (str): The subdomain to validate
        domain (str): The parent domain
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        # Basic validation
        if not subdomain or not domain:
            return False
            
        # Check if it's actually a subdomain of the target domain
        if not subdomain.endswith(domain):
            return False
            
        # Remove the base domain to check the subdomain part
        subdomain_part = subdomain[:-len(domain)-1]  # -1 for the dot
        if not subdomain_part:
            return False
            
        # Check length constraints
        if len(subdomain) > 253:  # Maximum length of a domain name
            return False
        if len(subdomain_part) > 63:  # Maximum length of a label
            return False
            
        # Check for valid characters and format
        valid_pattern = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
        if not valid_pattern.match(subdomain_part):
            return False
            
        # Check for consecutive hyphens
        if '--' in subdomain_part:
            return False
            
        return True
        
    except Exception:
        return False

def ct_logs_subdomains(domain: str) -> list[str]:
    """
    Enhanced Certificate Transparency logs search with rate limiting handling
    and exponential backoff.
    
    Args:
        domain: Target domain to search subdomains for
        
    Returns:
        List of valid subdomains found in CT logs
    """
    subdomains = set()
    
    # Configure CT log sources with updated endpoints
    ct_sources = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q=%.%.{domain}&output=json",
        f"https://crt.sh/?Identity=%.{domain}&output=json"
    ]
    
    def fetch_ct_data(url: str, retry_count: int = 0, max_retries: int = 3, 
                     initial_delay: int = 5) -> None:
        """Fetch CT data with exponential backoff and jitter"""
        headers = {
            'User-Agent': 'SpyPy SubdomainFinder/1.0 (+https://github.com/yourrepo)',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'no-cache'
        }
        
        try:
            if retry_count > 0:
                delay = initial_delay * (2 ** (retry_count - 1))  # Exponential backoff
                logging.info(f"Retrying after {delay} seconds (attempt {retry_count + 1}/{max_retries})")
                time.sleep(delay)
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 429:  # Too Many Requests
                if retry_count < max_retries:
                    return fetch_ct_data(url, retry_count + 1, max_retries, initial_delay)
                else:
                    logging.error(f"Max retries reached for {url}")
                    return
                    
            response.raise_for_status()
            
            if "crt.sh" in url:
                data = json.loads(response.text)
                for entry in data:
                    # Handle both single names and comma-separated names
                    names = []
                    if "name_value" in entry:
                        names.extend(entry["name_value"].replace("*.", "").split("\n"))
                    if "common_name" in entry:
                        names.extend(entry["common_name"].replace("*.", "").split("\n"))
                    
                    for name in names:
                        name = name.strip().lower()
                        if name.endswith(domain) and "*" not in name:
                            if is_valid_subdomain(name, domain):
                                subdomains.add(name)
                                
        except requests.exceptions.RequestException as e:
            if retry_count < max_retries:
                return fetch_ct_data(url, retry_count + 1, max_retries, initial_delay)
            logging.error(f"Error fetching CT logs from {url}: {e}")
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding CT logs JSON from {url}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error while processing {url}: {e}")

    # Process sources sequentially with proper delays
    for url in ct_sources:
        fetch_ct_data(url)
        time.sleep(2)  # Add delay between different queries
    
    # Additional processing to extract subdomains from common patterns
    processed_subdomains = set()
    pattern = re.compile(rf'[a-z0-9][a-z0-9-]*[a-z0-9]\.{re.escape(domain)}')
    
    for subdomain in subdomains:
        matches = pattern.findall(subdomain.lower())
        processed_subdomains.update(matches)
    
    # Remove any invalid or duplicate entries
    final_subdomains = {s for s in processed_subdomains if is_valid_subdomain(s, domain)}
    
    return list(final_subdomains)

def check_rate_limit(response):
    """Check if we're being rate limited"""
    if response.status_code == 429:
        retry_after = int(response.headers.get('Retry-After', 30))
        time.sleep(retry_after)
        return True
    return False

def check_single_subdomain(args):
    """
    Helper function for parallel DNS brute forcing.
    
    Args:
        args (tuple): (subdomain, domain)
    Returns:
        str or None: subdomain if found, None otherwise
    """
    subdomain, domain = args
    full_domain = f"{subdomain}.{domain}"
    try:
        socket.gethostbyname(full_domain)
        logging.debug(f"Found subdomain: {full_domain}")
        return full_domain
    except socket.gaierror:
        return None

def dns_brute_force(domain, wordlist_path):
    """
    Performs parallel DNS brute-forcing to find subdomains.

    Args:
        domain (str): The target domain name (e.g., example.com).
        wordlist_path (str): Path to the wordlist file.

    Returns:
        list: A list of subdomains found.
    """
    subdomains = []
    try:
        with open(wordlist_path, "r") as f:
            wordlist = [line.strip() for line in f]
        
        # Create a pool of workers
        pool = Pool(processes=cpu_count())
        
        # Prepare arguments for parallel processing
        args = [(subdomain, domain) for subdomain in wordlist]
        
        # Run the check_single_subdomain function in parallel
        results = pool.map(check_single_subdomain, args)
        
        # Close the pool and wait for all processes to complete
        pool.close()
        pool.join()
        
        # Filter out None results and add valid subdomains to the list
        subdomains = [result for result in results if result is not None]
        
    except FileNotFoundError:
        logging.error(f"Wordlist file not found: {wordlist_path}")
        return []
    
    return subdomains

def parallel_is_alive(subdomain):
    """
    Parallel version of is_alive check.
    """
    try:
        try:
            response = requests.get(f"https://{subdomain}", timeout=5, allow_redirects=True)
            return subdomain, f"{response.status_code} {response.reason}"
        except requests.exceptions.SSLError:
            response = requests.get(f"http://{subdomain}", timeout=5, allow_redirects=True)
            return subdomain, f"{response.status_code} {response.reason}"
    except requests.exceptions.RequestException as e:
        return subdomain, str(e)

def check_alive_parallel(subdomains):
    """
    Check multiple subdomains in parallel.

    Args:
        subdomains (list): List of subdomains to check.
    Returns:
        dict: Dictionary mapping subdomains to their status.
    """
    with Pool(processes=cpu_count()) as pool:
        results = pool.map(parallel_is_alive, subdomains)
    return dict(results)

def search_dns_records(domain):
    """
    Search for subdomains using various DNS record types.
    """
    subdomains = set()
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
    
    try:
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    if record_type == 'MX':
                        # Extract subdomain from MX record
                        mx_domain = str(rdata.exchange).rstrip('.')
                        if domain in mx_domain:
                            subdomains.add(mx_domain)
                    elif record_type == 'NS':
                        # Extract subdomain from NS record
                        ns_domain = str(rdata).rstrip('.')
                        if domain in ns_domain:
                            subdomains.add(ns_domain)
                    elif record_type == 'CNAME':
                        # Extract subdomain from CNAME record
                        cname = str(rdata.target).rstrip('.')
                        if domain in cname:
                            subdomains.add(cname)
            except dns.exception.DNSException:
                continue
    except Exception as e:
        logging.error(f"Error during DNS records search: {e}")
    
    return list(subdomains)

def try_zone_transfer(domain):
    """
    Attempt DNS zone transfer to discover subdomains.
    """
    subdomains = set()
    
    try:
        # First, get the nameservers for the domain
        answers = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(rdata).rstrip('.') for rdata in answers]
        
        for ns in nameservers:
            try:
                # Attempt zone transfer
                z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                if z:
                    for name, node in z.nodes.items():
                        name = str(name)
                        if name != '@' and name != '*':
                            subdomain = f"{name}.{domain}".rstrip('.')
                            subdomains.add(subdomain)
            except Exception:
                continue
    except Exception as e:
        logging.error(f"Error during zone transfer attempt: {e}")
    
    return list(subdomains)

def search_web_archives(domain):
    """
    Search various web archives for subdomains.
    """
    subdomains = set()
    archives = [
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey",
        f"http://index.commoncrawl.org/CC-MAIN-2023-14-index?url=*.{domain}&output=json",
        f"https://arquivo.pt/textsearch?q=site%3A{domain}&prettyPrint=true"
    ]
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    for archive_url in archives:
        try:
            response = requests.get(archive_url, headers=headers, timeout=30)
            if response.status_code == 200:
                try:
                    if 'web.archive.org' in archive_url:
                        data = response.json()
                        for item in data[1:]:  # Skip header row
                            url = item[0]
                            parsed = urlparse(url)
                            if parsed.netloc and domain in parsed.netloc:
                                subdomains.add(parsed.netloc)
                    elif 'commoncrawl.org' in archive_url:
                        for line in response.text.splitlines():
                            if line:
                                data = json.loads(line)
                                url = data.get('url', '')
                                parsed = urlparse(url)
                                if parsed.netloc and domain in parsed.netloc:
                                    subdomains.add(parsed.netloc)
                    elif 'arquivo.pt' in archive_url:
                        data = response.json()
                        for item in data.get('response_items', []):
                            url = item.get('originalURL', '')
                            parsed = urlparse(url)
                            if parsed.netloc and domain in parsed.netloc:
                                subdomains.add(parsed.netloc)
                except json.JSONDecodeError:
                    continue
            
            time.sleep(2)  # Be nice to the archives
            
        except Exception as e:
            logging.error(f"Error searching web archive {archive_url}: {e}")
    
    return list(subdomains)

def search_certificate_sources(domain):
    """
    Search additional certificate transparency logs.
    """
    subdomains = set()
    ct_sources = [
        f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
        f"https://google.transparencyreport.com/api/v1/certificatetransparency/ct/search?domain={domain}",
        f"https://api.facebook.com/v11.0/certificates?query={domain}"
    ]
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    for source in ct_sources:
        try:
            response = requests.get(source, headers=headers, timeout=30)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'certspotter' in source:
                        for cert in data:
                            for dns_name in cert.get('dns_names', []):
                                if domain in dns_name and is_valid_subdomain(dns_name, domain):
                                    subdomains.add(dns_name)
                    # Add parsing for other sources as needed
                except json.JSONDecodeError:
                    continue
            
            time.sleep(2)  # Rate limiting
            
        except Exception as e:
            logging.error(f"Error searching certificate source {source}: {e}")
    
    return list(subdomains)
