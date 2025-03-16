import argparse
import logging
import sub_finder.subdomain_finder as sf
from multiprocessing import freeze_support
import time
import sys
from pathlib import Path
import re
import os

def validate_domain(domain):
    """Validate domain format"""
    if not domain:
        return False
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(pattern.match(domain))

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

def check_dependencies():
    """Check if all required packages are installed"""
    required = {
        'requests': 'requests',
        'beautifulsoup4': 'bs4',  # beautifulsoup4 diimpor sebagai bs4
        'dnspython': 'dns',
        'pyyaml': 'yaml'
    }
    
    missing = []
    for package_name, import_name in required.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package_name)
    
    if missing:
        print("Missing required packages:", ", ".join(missing))
        print("Please install using: pip install -r requirements.txt")
        sys.exit(1)

def main():
    # ASCII Banner
    banner = """
\033[1;32m
░▒▓███████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░  🕶️ SPY-PY v1.0 by 0x1jar ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░  
       ░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░         ░▒▓█▓▒░     🔍 Multi-source intelligence
       ░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░         ░▒▓█▓▒░     ⚡ Live validation
░▒▓███████▓▒░░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░         ░▒▓█▓▒░     🔒 Cross-source aggregation
\033[0m
    """
    print(banner)

    parser = argparse.ArgumentParser(
        description="Find subdomains using multiple sources including Wayback Machine, CT Logs, Alienvault, Certspotter, and more",
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
    parser.add_argument(
        '-w', '--wordlist',
        type=str,
        default='wordlists/subdomains.txt',
        help='Path to custom subdomain wordlist'
    )
    parser.add_argument(
        '--wordlist-only',
        action='store_true',
        help='Use only wordlist for subdomain enumeration (disable other sources)'
    )
    parser.add_argument(
        '--mixed-mode',
        action='store_true',
        help='Combine wordlist with external sources'
    )

    args = parser.parse_args()
    
    # Check if wordlist exists
    if not os.path.exists(args.wordlist):
        logging.error(f"Wordlist file not found: {args.wordlist}")
        sys.exit(1)
        
    # Validate domain before proceeding
    if not validate_domain(args.domain):
        logging.error(f"Invalid domain format: {args.domain}")
        sys.exit(1)
        
    setup_logging(args.verbose)
    
    start_time = time.time()
    logging.info(f"🚀 Starting subdomain enumeration for: {args.domain} 🔍")

    all_subdomains = set()

    # Handle different modes
    if args.wordlist_only:
        logging.info("Using wordlist-only mode")
        # Add function to handle wordlist-based enumeration
        all_subdomains.update(sf.enumerate_from_wordlist(args.domain, args.wordlist))
    else:
        # Search all sources
        all_subdomains.update(sf.search_all_sources(args.domain))

    logging.info(f"✅ Total unique subdomains found: {len(all_subdomains)} ✨")

    # Check if subdomains are alive if requested
    if args.check_alive and all_subdomains:
        logging.info("Checking subdomain status...")
        alive_status = sf.check_alive_parallel(all_subdomains)
        alive_count = sum(1 for status in alive_status.values() if status)
        logging.info(f"✅ Found {alive_count} active subdomains 💡")

    # Output results
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with open(args.output, "w") as f:
                for subdomain in all_subdomains:
                    f.write(f"{subdomain}\n")
                    if args.check_alive:
                        status = "Active" if alive_status.get(subdomain) else "Inactive"
                        f.write(f"Status: {status}\n")
            logging.info(f"Results written to: {args.output}")
        except PermissionError:
            logging.error(f"Permission denied when writing to: {args.output}")
            sys.exit(1)
        except IOError as e:
            logging.error(f"Error writing to output file: {e}")
            sys.exit(1)
    else:
        for subdomain in all_subdomains:
            print(subdomain)
            if args.check_alive:
                status = "Active" if alive_status.get(subdomain) else "Inactive"
                print(f"Status: {status}")

    # Show completion time
    elapsed_time = time.time() - start_time
    logging.info(f"Scan completed in {format_time(elapsed_time)}")

if __name__ == "__main__":
    check_dependencies()
    freeze_support()
    main()
