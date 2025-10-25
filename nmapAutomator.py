# nmapAutomator.py
import subprocess
import re
import os
import time
import socket
from urllib.parse import urlparse

class NmapAutomator:
    def __init__(self, target, output_dir, emit_callback=None):
        self.target = target
        self.output_dir = output_dir
        self.emit = emit_callback  # Callback for real-time logging
        self.nmap_path = self._find_nmap()
        self.open_ports = []
        self.os_info = "Unknown"
        self.script_results = ""

    def _find_nmap(self):
        """Finds the nmap executable."""
        try:
            return subprocess.run(['which', 'nmap'], capture_output=True, text=True, check=True).stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            if self.emit: self.emit("Nmap not found. Please install it.", "error")
            raise FileNotFoundError("Nmap executable not found in PATH.")

    def _log(self, message, level="info"):
        """Logs a message to the callback or console."""
        if self.emit:
            self.emit(message, level)
        else:
            print(f"[{level.upper()}] {message}")

    def _run_nmap(self, command):
        """Runs an nmap command and returns its output."""
        self._log(f"Executing: {' '.join(command)}")
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            self._log(f"Nmap command failed: {e.stderr}", "error")
            return ""

    def _parse_ports(self, nmap_output):
        """Parses open ports from nmap grepable output."""
        ports = re.findall(r'(\d+)/tcp\s+open\s+', nmap_output)
        return [int(p) for p in ports]

    def _parse_os(self, nmap_output):
        """Parses OS information from nmap output."""
        match = re.search(r'Aggressive OS guesses: ([^\n]+)', nmap_output)
        if match:
            return match.group(1)
        return "Unknown"

    def ping_scan(self):
        """Performs a quick ping scan to check if host is up."""
        self._log(f"[*] Pinging {self.target}...")
        try:
            # Use a simple ping command
            param = '-n' if os.name == 'nt' else '-c'
            command = ['ping', param, '1', self.target]
            response = subprocess.run(command, capture_output=True, text=True, timeout=5)
            return response.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def port_scan(self):
        """Performs a fast scan on the top 1000 ports."""
        self._log("--- Starting Nmap Port Scan ---", "success")
        output_file = os.path.join(self.output_dir, "port_scan.nmap")
        os.makedirs(self.output_dir, exist_ok=True)
        
        command = [
            self.nmap_path, '-sV', '-T4', '--open',
            '-oN', output_file, '-oX', output_file.replace('.nmap', '.xml'),
            self.target
        ]
        
        nmap_output = self._run_nmap(command)
        self.open_ports = self._parse_ports(nmap_output)
        self._log(f"[*] Port scan finished. Found open ports: {self.open_ports}")
        return nmap_output

    def script_scan(self, ports):
        """Runs default scripts on the specified ports."""
        if not ports:
            self._log("[*] No ports to run scripts on.", "warning")
            return ""
        self._log("--- Starting Nmap Script Scan ---", "success")
        output_file = os.path.join(self.output_dir, "script_scan.nmap")
        port_str = ','.join(map(str, ports))

        command = [
            self.nmap_path, '-sCV', '-p', port_str, '--open',
            '-oN', output_file, '-oX', output_file.replace('.nmap', '.xml'),
            self.target
        ]
        
        self.script_results = self._run_nmap(command)
        self.os_info = self._parse_os(self.script_results)
        self._log(f"[*] Script scan finished. Likely OS: {self.os_info}")
        return self.script_results

    def full_scan(self):
        """Performs a full port scan (1-65535)."""
        self._log("--- Starting Nmap Full Port Scan ---", "success")
        output_file = os.path.join(self.output_dir, "full_scan.nmap")
        
        command = [
            self.nmap_path, '-p-', '-T4', '--open',
            '-oN', output_file, '-oX', output_file.replace('.nmap', '.xml'),
            self.target
        ]
        
        nmap_output = self._run_nmap(command)
        all_ports = self._parse_ports(nmap_output)
        self.open_ports = list(set(self.open_ports + all_ports))
        self._log(f"[*] Full scan finished. Total open ports: {self.open_ports}")
        return nmap_output

    def run_automated_recon(self):
        """Runs the standard reconnaissance workflow."""
        is_host_up = self.ping_scan()
        if not is_host_up:
            self._log(f"Host {self.target} appears to be down or not responding to pings.", "warning")
            # Continue with scan anyway, as it might be blocking pings
            self._log("Proceeding with scan anyway...", "info")

        # Stage 1: Fast port scan
        self.port_scan()
        
        # Stage 2: Script scan on found ports
        self.script_scan(self.open_ports)
        
        # Stage 3: (Optional) Full scan if few ports are found
        if len(self.open_ports) < 5:
            self._log("[*] Few ports found, running a full port scan to be thorough.", "info")
            self.full_scan()
            # Re-run script scan on any newly found ports
            new_ports = [p for p in self.open_ports if p not in self._parse_ports(self.script_results)]
            if new_ports:
                self.script_scan(new_ports)

        return {
            "open_ports": self.open_ports,
            "os_info": self.os_info,
            "script_output": self.script_results,
            "port_scan_file": os.path.join(self.output_dir, "port_scan.nmap"),
            "script_scan_file": os.path.join(self.output_dir, "script_scan.nmap")
        }
