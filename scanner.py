# scanner.py
import requests
import time
import random
import os
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from playwright.sync_api import sync_playwright
from nmapAutomator import NmapAutomator # Import the new class

# ... (keep all payloads, helper functions, and AdvancedCrawler class) ...

class VulnerabilityScanner:
    def __init__(self, target_url, options, emit_callback):
        self.target_url = target_url
        self.options = options
        self.emit = emit_callback
        self.session = requests.Session()
        self.vulnerabilities = []
        self.stop_scan = False
        self.recon_results = {} # Store recon results here

    def log(self, message, log_type="info"):
        self.emit('log', {'message': message, 'type': log_type})

    def run(self):
        """Main entry point for the automated scan."""
        self.log(f"--- WebVulnX Pro - Starting Automated Scan on {self.target_url} ---", "success")
        
        # --- Stage 1: Network Reconnaissance using the Python module ---
        try:
            target_ip = socket.gethostbyname(self.target_url)
        except socket.gaierror:
            self.log(f"Could not resolve {self.target_url} to an IP. Aborting scan.", "error")
            return

        output_dir = f"recon_results/{target_ip}"
        automator = NmapAutomator(target_ip, output_dir, emit_callback=self.emit)
        
        self.recon_results = automator.run_automated_recon()
        if self.stop_scan: return

        # --- Stage 2: Web Vulnerability Scan ---
        self.log("--- Stage 2: Analyzing results for web services ---", "info")
        open_ports = self.recon_results.get("open_ports", [])
        web_ports = [80, 443, 8080, 8443, 8000, 3000, 5000, 9000]
        found_web_ports = [p for p in open_ports if p in web_ports]

        if not found_web_ports:
            self.log("No common web ports found. Skipping web vulnerability scan.", "warning")
            self.emit('scan_complete', {
                'target': self.target_url, 
                'vulnerabilities': self.vulnerabilities,
                'recon_results': self.recon_results
            })
            return

        self.log(f"Found web ports: {', '.join(map(str, found_web_ports))}. Starting web vulnerability scan...", "success")
        
        for port in found_web_ports:
            if self.stop_scan: break
            protocol = 'https' if port in [443, 8443] else 'http'
            web_target = f"{protocol}://{target_ip}:{port}"
            self.log(f"[*] Scanning web target: {web_target}", "info")
            
            crawler = AdvancedCrawler(web_target, self.session, self.options.get('depth', 2))
            urls, forms, api_endpoints = crawler.crawl()
            self.log(f"[*] Discovered {len(urls)} URLs and {len(forms)} forms on {web_target}.", "info")

            self.log(f"[*] Starting vulnerability scans on {web_target}...", "info")
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for url in urls:
                    parsed_url = urlparse(url)
                    params = parse_qs(parsed_url.query)
                    if params:
                        futures.append(executor.submit(self._scan_endpoint, 'GET', url, params))
                for form in forms:
                    futures.append(executor.submit(self._scan_endpoint, form['method'], form['url'], form['params']))
                
                for future in as_completed(futures):
                    if self.stop_scan: break
                    result = future.result()
                    if result:
                        self.vulnerabilities.append(result)
                        self.emit('vulnerability_found', result)

        # --- Final Report ---
        if not self.stop_scan:
            self.log("--- Full Automated Scan Complete ---", "success")
            self.emit('scan_complete', {
                'target': self.target_url, 
                'vulnerabilities': self.vulnerabilities,
                'recon_results': self.recon_results # Send recon results for the report
            })

    # ... (keep all the _scan_endpoint, _test_payload, and _check_* methods) ...
