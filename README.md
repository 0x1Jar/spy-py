# Spy-Py Subdomain Scanner

## Features
- 🛠️ 10+ data sources including Censys, Shodan, VirusTotal, and Wayback Machine
- 🔍 Parallelized subdomain discovery
- ⚡ Live subdomain validation with socket checks
- 📝 Clear output formatting with status markers
- 🔒 Environment variable-based API key management

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

## Dependencies
- **Python 3.8+** (Tested on Python 3.13)
- **Required Packages**:
  ```bash
  requests
  beautifulsoup4
  dnspython
  pyyaml
  ```
- **Optional Dependencies**:
  - `censys` (for Censys API)
  - `virustotal-python` (for VirusTotal API)

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

**Example Commands**:
```bash
# Basic scan
python main.py -d example.com

# Save output with status checks
python main.py -d example.com -o results.txt --check-alive

# Verbose mode
python main.py -d example.com -v
```

## Configuration
Set these environment variables in `.env`:
```env
CENSYS_API_KEY=
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
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
