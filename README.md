# Spy-Py Subdomain Enumeration Tool 🔍

## Security Setup with Environment Variables 🛡️

### Why Secure API Keys? ❓
To prevent accidental exposure of sensitive credentials on GitHub, we use **environment variables**. 🔒

### Steps Taken 🚀
✅ **1. `.gitignore` Configuration**  
Added entries to exclude `.env` files:  
```plaintext
.env
.venv/
```
🚫 This stops sensitive files from being committed.

✅ **2. Example `.env` File**  
Created `.env.example` with placeholders:  
```env
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
```
📝 Rename to `.env` and fill your keys.

✅ **3. Code Modifications**  
`subdomain_finder.py` now reads keys from environment variables:  
```python
import os
api_key = os.getenv('SHODAN_API_KEY')  # 🔑 Secure access
```

## How to Use 🏃♂️
1. Copy `.env.example` to `.env` and add your API keys.  
2. Run the tool:  
```bash
python main.py target-domain.com  
```
3. Results will be saved in `logs/`. 📂

## Contributing ✨
Feel free to suggest improvements! Open an issue or PR.  

*Stay secure and automate wisely!* 🔒🚀
