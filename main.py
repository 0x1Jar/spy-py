import argparse
import logging
import sub_finder.subdomain_finder as sf
from multiprocessing import freeze_support
import time
from sub_finder.config import Config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    start_time = time.time()  # Start timing
    
    parser = argparse.ArgumentParser(description="Find subdomains of a target domain using multiple sources.")
    parser.add_argument("-d", "--domain", required=True, help="The target domain name (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to the wordlist file")
    parser.add_argument("-o", "--output", help="Path to the output file (default: stdout)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--check-alive", action="store_true", help="Check if the subdomain is alive")
    # Source arguments
    parser.add_argument("--wayback", action="store_true", help="Use Wayback Machine for discovery")
    parser.add_argument("--crtsh", action="store_true", help="Use crt.sh for discovery")
    parser.add_argument("--bruteforce", action="store_true", help="Use DNS bruteforce")
    parser.add_argument("--search-engines", action="store_true", help="Use search engines for discovery")
    # API keys for search engines
    parser.add_argument("--google-api-key", help="Google Custom Search API key")
    parser.add_argument("--google-cx", help="Google Custom Search Engine ID")
    parser.add_argument("--bing-api-key", help="Bing API key")
    
    args = parser.parse_args()

    logging.info(f"Target domain: {args.domain}")
    if args.wordlist:
        logging.info(f"Wordlist: {args.wordlist}")
    if args.output:
        logging.info(f"Output file: {args.output}")

    all_subdomains = set()  # Changed to set for faster deduplication

    # Load API keys from config
    config = Config()
    google_config = config.get_api_key('google')
    bing_config = config.get_api_key('bing')

    # Override config with command-line arguments if provided
    google_api_key = args.google_api_key or google_config.get('api_key')
    google_cx = args.google_cx or google_config.get('cx')
    bing_api_key = args.bing_api_key or bing_config.get('api_key')

    # Only run selected sources
    if args.wayback:
        logging.info("Starting Wayback Machine search...")
        wayback_subdomains = sf.search_wayback_machine(args.domain)
        all_subdomains.update(wayback_subdomains)
        logging.info(f"Found {len(wayback_subdomains)} subdomains using Wayback Machine.")

    if args.crtsh:
        logging.info("Starting Certificate Transparency Logs search...")
        ct_subdomains = sf.ct_logs_subdomains(args.domain)
        all_subdomains.update(ct_subdomains)
        logging.info(f"Found {len(ct_subdomains)} subdomains using Certificate Transparency Logs.")

    if args.search_engines:
        logging.info("Starting search engine enumeration...")
        search_subdomains = sf.search_search_engines(
            args.domain,
            google_api_key=google_api_key,
            google_cx=google_cx,
            bing_api_key=bing_api_key
        )
        all_subdomains.update(search_subdomains)
        logging.info(f"Found {len(search_subdomains)} subdomains using search engines.")

    if args.bruteforce and args.wordlist:
        logging.info("Starting parallel DNS brute force...")
        dns_subdomains = sf.dns_brute_force(args.domain, args.wordlist)
        logging.info(f"Found {len(dns_subdomains)} subdomains using DNS brute force.")
        all_subdomains.update(dns_subdomains)
    elif args.wordlist and not args.bruteforce:
        logging.warning("Wordlist provided but bruteforce not enabled. Use --bruteforce to enable DNS bruteforce.")

    # If no source is selected, use DNS bruteforce by default if wordlist is provided
    if not any([args.wayback, args.crtsh, args.bruteforce, args.search_engines]) and args.wordlist:
        logging.info("No source selected, defaulting to DNS brute force...")
        dns_subdomains = sf.dns_brute_force(args.domain, args.wordlist)
        logging.info(f"Found {len(dns_subdomains)} subdomains using DNS brute force.")
        all_subdomains.update(dns_subdomains)

    unique_subdomains = list(all_subdomains)  # Convert set back to list
    logging.info(f"Found a total of {len(unique_subdomains)} unique subdomains.")

    if args.check_alive:
        logging.info("Checking subdomain status in parallel...")
        alive_status = sf.check_alive_parallel(unique_subdomains)

    if args.output:
        try:
            with open(args.output, "w") as f:
                for subdomain in unique_subdomains:
                    f.write(subdomain + "\n")
                    if args.check_alive:
                        f.write(f"  [+] {subdomain} is alive: {alive_status[subdomain]}\n")
            logging.info(f"Subdomains written to {args.output}")
        except Exception as e:
            logging.error(f"Error writing to output file: {e}")
    else:
        for subdomain in unique_subdomains:
            print(subdomain)
            if args.check_alive:
                print(f"  [+] {subdomain} is alive: {alive_status[subdomain]}")

    # Calculate and display elapsed time
    end_time = time.time()
    elapsed_time = end_time - start_time
    hours = int(elapsed_time // 3600)
    minutes = int((elapsed_time % 3600) // 60)
    seconds = int(elapsed_time % 60)
    
    time_msg = f"Scan completed in "
    if hours > 0:
        time_msg += f"{hours} hours, "
    if minutes > 0:
        time_msg += f"{minutes} minutes, "
    time_msg += f"{seconds} seconds"
    
    logging.info(time_msg)

if __name__ == "__main__":
    freeze_support()  # Required for Windows support
    main()
