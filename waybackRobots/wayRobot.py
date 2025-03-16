import requests
import logging
import concurrent.futures
from urllib.parse import urljoin
from pathlib import Path
import json
import time

class RobotsTxtScanner:
    def __init__(self, timeout=10):
        """
        Initialize the RobotsTxtScanner.

        Args:
            timeout (int): Request timeout in seconds (default: 10)
        """
        self.timeout = timeout
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.results = {}

    def scan_robots_txt(self, subdomain):
        """
        Scan a single subdomain for robots.txt file.

        Args:
            subdomain (str): The subdomain to scan (e.g., 'example.com')

        Returns:
            tuple: (subdomain, results_dict) containing the scan results
        """
        results = {
            'status': 'not found',
            'content': None,
            'disallow_paths': [],
            'allow_paths': [],
            'sitemaps': [],
            'error': None
        }

        try:
            # Try HTTPS first, then HTTP if HTTPS fails
            for protocol in ['https', 'http']:
                url = f"{protocol}://{subdomain}/robots.txt"
                try:
                    response = requests.get(url, 
                                         headers=self.headers, 
                                         timeout=self.timeout,
                                         allow_redirects=True)
                    
                    if response.status_code == 200:
                        content = response.text
                        results['status'] = 'found'
                        results['content'] = content
                        
                        # Parse robots.txt content
                        for line in content.splitlines():
                            line = line.strip().lower()
                            if line.startswith('disallow:'):
                                path = line.split(':', 1)[1].strip()
                                if path:
                                    results['disallow_paths'].append(path)
                            elif line.startswith('allow:'):
                                path = line.split(':', 1)[1].strip()
                                if path:
                                    results['allow_paths'].append(path)
                            elif line.startswith('sitemap:'):
                                sitemap = line.split(':', 1)[1].strip()
                                if sitemap:
                                    results['sitemaps'].append(sitemap)
                        
                        break  # Exit protocol loop if successful
                    
                except requests.exceptions.SSLError:
                    continue  # Try next protocol
                except requests.exceptions.RequestException as e:
                    continue  # Try next protocol

        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)

        return subdomain, results

    def scan_subdomains(self, subdomains, max_workers=10):
        """
        Scan multiple subdomains concurrently.

        Args:
            subdomains (list): List of subdomains to scan
            max_workers (int): Maximum number of concurrent workers (default: 10)
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_subdomain = {
                executor.submit(self.scan_robots_txt, subdomain): subdomain 
                for subdomain in subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    subdomain, result = future.result()
                    self.results[subdomain] = result
                except Exception as e:
                    logging.error(f"Error scanning {subdomain}: {str(e)}")

    def save_results(self, output_file):
        """
        Save scan results to a JSON file.

        Args:
            output_file (str): Path to the output JSON file
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=4)

def scan_from_file(input_file, output_file, max_workers=10):
    """
    Scan robots.txt for subdomains listed in a file.

    Args:
        input_file (str): Path to input file containing subdomains
        output_file (str): Path to output JSON file for results
        max_workers (int): Maximum number of concurrent workers

    Returns:
        dict: Scan results
    """
    # Read subdomains from input file
    subdomains = []
    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('Status:'):  # Skip status lines
                subdomains.append(line)

    # Initialize scanner and run scan
    scanner = RobotsTxtScanner()
    logging.info(f"Starting robots.txt scan for {len(subdomains)} subdomains...")
    start_time = time.time()
    
    scanner.scan_subdomains(subdomains, max_workers)
    
    # Save results
    scanner.save_results(output_file)
    
    # Print summary
    found_count = sum(1 for result in scanner.results.values() if result['status'] == 'found')
    elapsed_time = time.time() - start_time
    
    logging.info(f"Scan completed in {elapsed_time:.2f} seconds")
    logging.info(f"Found robots.txt in {found_count} out of {len(subdomains)} subdomains")
    logging.info(f"Results saved to {output_file}")

    return scanner.results

if __name__ == "__main__":
    import argparse
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Scan subdomains for robots.txt files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with default settings
  python wayRobot.py -i subdomains.txt -o results.json

  # Scan with increased concurrent workers
  python wayRobot.py -i subdomains.txt -o results.json -w 20

  # Typical workflow with subdomain_finder
  python ../sub_finder/subdomain_finder.py -d example.com -o subdomains.txt
  python wayRobot.py -i subdomains.txt -o robots_results.json
        """
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Input file containing list of subdomains"
    )
    parser.add_argument(
        "-o", "--output",
        required=True,
        help="Output JSON file for results"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=10,
        help="Number of worker threads (default: 10)"
    )
    
    args = parser.parse_args()
    
    # Run the scan
    scan_from_file(args.input, args.output, args.workers)