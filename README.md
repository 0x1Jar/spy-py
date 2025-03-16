# Spy-Py Subdomain Scanner

## Features
- 🛠️ 10+ data sources including Censys, Shodan, VirusTotal, and Wayback Machine
- 🔍 Parallelized subdomain discovery
- ⚡ Live subdomain validation with socket checks
- 📝 Clear output formatting with status markers
- 🔒 Environment variable-based API key management
- 🤖 Wayback Robots.txt Scanner:
  - Automatic robots.txt discovery
  - Disallow/Allow paths extraction
  - Sitemap URL discovery
  - Multi-protocol support (HTTPS/HTTP)
  - Concurrent scanning capability
- 📚 Multiple enumeration modes:
  - Wordlist-based scanning
  - Multi-source intelligence gathering
  - Mixed-mode (combining wordlist and external sources)
- ⚙️ Customizable wordlist support
- 🚀 Concurrent subdomain validation
- 🕒 Real-time progress tracking

## Quick Start
```bash
# 1. Clone repository
git clone https://github.com/your-username/spy-py.git
cd spy-py

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API keys
cp .env.example .env
echo "CENSYS_API_KEY=your_censys_key" >> .env
echo "SHODAN_API_KEY=your_shodan_key" >> .env
echo "VIRUSTOTAL_API_KEY=your_virustotal_key" >> .env

# 4. Run the scanner
python main.py -d example.com -o results.txt --check-alive
```

## Installation
1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/spy-py.git
   cd spy-py
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure API keys**
   - Copy the example environment file:
     ```bash
     cp .env.example .env
     ```
   - Edit `.env` and replace placeholder values with your actual API keys.

## Usage
```bash
python main.py [OPTIONS]
```

**Key Options**:
- `-d, --domain` (required): Target domain (e.g., example.com)
- `-o, --output`: Save results to file
- `-v, --verbose`: Enable debug logging
- `--check-alive`: Validate subdomain reachability
- `-w, --wordlist`: Specify custom wordlist file (default: wordlists/subdomains.txt)
- `--wordlist-only`: Use only wordlist for enumeration (disable other sources)
- `--mixed-mode`: Combine wordlist with external sources

**Example Commands**:
```bash
# Basic scan using all sources
python main.py -d example.com

# Wordlist-only mode
python main.py -d example.com -w wordlists/subdomains.txt --wordlist-only

# Mixed mode (wordlist + external sources)
python main.py -d example.com -w wordlists/subdomains.txt --mixed-mode

# Save output with status checks
python main.py -d example.com -o results.txt --check-alive

# Verbose mode with custom wordlist
python main.py -d example.com -v -w custom_wordlist.txt
```

## Configuration
Set these environment variables in `.env`:
```env
CENSYS_API_KEY=
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
```

## Scan Modes

### 1. Multi-Source Mode (Default)
Uses multiple external sources to discover subdomains:
- Censys
- Shodan
- VirusTotal
- Wayback Machine
- Certificate Transparency Logs
- And more...

### 2. Wordlist Mode
- Uses only wordlist-based enumeration
- Faster for basic reconnaissance
- Customizable wordlist support
- DNS validation included

### 3. Mixed Mode
- Combines wordlist-based scanning with external sources
- Comprehensive coverage
- Ideal for thorough enumeration

## Advanced Features

### Wayback Robots.txt Scanner
The Wayback Robots Scanner module (`waybackRobots/wayRobot.py`) provides comprehensive robots.txt analysis:

```bash
# Basic robots.txt scan
python waybackRobots/wayRobot.py -i subdomains.txt -o robots_results.json

# Scan with increased concurrent workers
python waybackRobots/wayRobot.py -i subdomains.txt -o robots_results.json -w 20
```

**Features**:
- 🔍 Automatic discovery of robots.txt files
- 📋 Extraction of:
  - Disallow paths
  - Allow paths
  - Sitemap URLs
- ⚡ Concurrent scanning with adjustable workers
- 🔄 Protocol fallback (HTTPS → HTTP)
- 💾 JSON output format
- 📊 Scan statistics and summary

**Example Workflow**:
```bash
# 1. Find subdomains
python main.py -d example.com -o subdomains.txt

# 2. Scan for robots.txt
python waybackRobots/wayRobot.py -i subdomains.txt -o robots_results.json

# 3. Analyze results
cat robots_results.json
```

**Output Format**:
```json
{
    "subdomain.example.com": {
        "status": "found",
        "content": "User-agent: *\nDisallow: /admin/\nAllow: /public/\nSitemap: https://example.com/sitemap.xml",
        "disallow_paths": ["/admin/"],
        "allow_paths": ["/public/"],
        "sitemaps": ["https://example.com/sitemap.xml"],
        "error": null
    }
}
```

## Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a pull request

## License
MIT License - see [LICENSE](LICENSE) file

## Disclaimer
This tool is for educational and authorized penetration testing purposes only. Ensure proper authorization before scanning any domains.
