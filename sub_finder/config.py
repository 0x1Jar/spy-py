import os
import json
import logging
from pathlib import Path
from collections import defaultdict
import time
import requests

class Config:
    def __init__(self):
        self.config_file = os.path.join(str(Path.home()), '.subfinder', 'config.json')
        self.config = self._load_config()
        self.RATE_LIMITS = {
            'wayback': {'max_requests': 30, 'delay': 1.2},
            'crtsh': {'max_requests': 120, 'delay': 0.5}
        }
        self.rate_limiter = RateLimiter(self.config)  # Pass config to RateLimiter

    def _load_config(self):
        """Load configuration from file"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return {}

    def _save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving config: {e}")

    def set_api_config(self, service, api_key=None, max_requests=None, delay=None, auto_detect=True, fallback=None):
        """[...] (same as before)"""

    # (remaining methods remain unchanged)

class RateLimiter:
    def __init__(self, config):
        self.config = config
        self.request_history = defaultdict(list)

    def analyze_response(self, service, response):
        """Extract rate limits from HTTP headers"""
        rate_limits = {}
        if 'X-RateLimit-Limit' in response.headers:
            rate_limits['max_requests'] = int(response.headers.get('X-RateLimit-Limit', '0'))
            rate_limits['remaining'] = int(response.headers.get('X-RateLimit-Remaining', '0'))
            rate_limits['reset'] = int(response.headers.get('X-RateLimit-Reset', '0'))
        return rate_limits or self.config[service]['fallback']

    def get_delay(self, service):
        """Calculate optimal delay using history and current limits"""
        now = time.time()
        recent_requests = [t for t in self.request_history[service] if now - t < 60]
        
        if len(recent_requests) >= self.config[service]['max_requests']:
            return self.config[service]['delay'] * 1.5  # Backoff
        
        return max(
            self.config[service]['delay'],
            (60 - (now - recent_requests[0])) / self.config[service]['max_requests']
        )
