import argparse
import logging
import sub_finder.subdomain_finder as sf
from multiprocessing import freeze_support
import time
import sys
from pathlib import Path

def setup_logging(verbose):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

def format_time(seconds):
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    seconds = int(seconds % 60)
    
    parts = []
    if hours > 0:
        parts.append(f"{hours} hours")
    if minutes > 0:
        parts.append(f"{minutes} minutes")
    if seconds > 0 or not parts:
        parts.append(f"{seconds} seconds")
    
    return ", ".join(parts)

def main():
    parser = argparse.ArgumentParser(
        description="Find subdomains using Wayback Machine and Certificate Transparency Logs",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-d", "--domain", required=True, 
                       help="Target domain name (e.g., example.com)")
    parser.add_argument("-o", "--output", type=Path,
                       help="Path to output file (default: stdout)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose logging")
    parser.add_argument("--check-alive", action="store_true",
                       help="Check if discovered subdomains are alive")

    args = parser.parse_args()
    setup_logging(args.verbose)
    
    try:
        start_time = time.time()
        
        logging.info(f"Starting subdomain enumeration for: {args.domain}")
        
        # Collect subdomains from Wayback Machine
        logging.info("Searching Wayback Machine...")
        wayback_subdomains = sf.search_wayback_machine(args.domain)
        logging.info(f"Found {len(wayback_subdomains)} subdomains from Wayback Machine")
        
        # Collect subdomains from CT logs
        logging.info("Searching Certificate Transparency logs...")
        ct_subdomains = sf.ct_logs_subdomains(args.domain)
        logging.info(f"Found {len(ct_subdomains)} subdomains from CT logs")
        
        # Combine and deduplicate results
        all_subdomains = sorted(set(wayback_subdomains) | set(ct_subdomains))
        logging.info(f"Total unique subdomains found: {len(all_subdomains)}")
        
        # Check if subdomains are alive if requested
        alive_status = {}
        if args.check_alive and all_subdomains:
            logging.info("Checking subdomain status...")
            alive_status = sf.check_alive_parallel(all_subdomains)
            alive_count = sum(1 for status in alive_status.values() if status)
            logging.info(f"Found {alive_count} active subdomains")
        
        # Output results
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with open(args.output, "w") as f:
                for subdomain in all_subdomains:
                    f.write(f"{subdomain}\n")
                    if args.check_alive:
                        status = "Active" if alive_status.get(subdomain) else "Inactive"
                        f.write(f"Status: {status}\n")
            logging.info(f"Results written to: {args.output}")
        else:
            for subdomain in all_subdomains:
                print(subdomain)
                if args.check_alive:
                    status = "Active" if alive_status.get(subdomain) else "Inactive"
                    print(f"Status: {status}")
        
        # Show completion time
        elapsed_time = time.time() - start_time
        logging.info(f"Scan completed in {format_time(elapsed_time)}")
        
    except KeyboardInterrupt:
        logging.info("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        if args.verbose:
            logging.exception("Detailed error information:")
        sys.exit(1)

if __name__ == "__main__":
    freeze_support()
    main()
