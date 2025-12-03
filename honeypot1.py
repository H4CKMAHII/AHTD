#!/usr/bin/env python3

import requests
import time
import socket
import sys
from urllib.parse import urlparse
from typing import Dict, Any
import warnings
from requests.exceptions import ConnectTimeout
from socket import gaierror

# ====== COLORS FOR CLI BANNER ======
RED = "\033[31m"
RESET = "\033[0m"


def logo():
    print(f"""{RED}
          _____                    _____                _____                    _____          
         /\    \                  /\    \              /\    \                  /\    \         
        /::\    \                /::\____\            /::\    \                /::\    \        
       /::::\    \              /:::/    /            \:::\    \              /::::\    \       
      /::::::\    \            /:::/    /              \:::\    \            /::::::\    \      
     /:::/\:::\    \          /:::/    /                \:::\    \          /:::/\:::\    \     
    /:::/__\:::\    \        /:::/____/                  \:::\    \        /:::/  \:::\    \    
   /::::\   \:::\    \      /::::\    \                  /::::\    \      /:::/    \:::\    \   
  /::::::\   \:::\    \    /::::::\    \   _____        /::::::\    \    /:::/    / \:::\    \  
 /:::/\:::\   \:::\    \  /:::/\:::\    \ /\    \      /:::/\:::\    \  /:::/    /   \:::\ ___\ 
/:::/  \:::\   \:::\____\/:::/  \:::\    /::\____\    /:::/  \:::\____\/:::/____/     \:::|    |
\::/    \:::\  /:::/    /\::/    \:::\  /:::/    /   /:::/    \::/    /\:::\    \     /:::|____|
 \/____/ \:::\/:::/    /  \/____/ \:::\/:::/    /   /:::/    / \/____/  \:::\    \   /:::/    / 
          \::::::/    /            \::::::/    /   /:::/    /            \:::\    \ /:::/    /  
           \::::/    /              \::::/    /   /:::/    /              \:::\    /:::/    /   
           /:::/    /               /:::/    /    \::/    /                \:::\  /:::/    /    
          /:::/    /               /:::/    /      \/____/                  \:::\/:::/    /     
         /:::/    /               /:::/    /                                 \::::::/    /      
        /:::/    /               /:::/    /                                   \::::/    /       
        \::/    /                \::/    /                                     \::/____/        
         \/____/                  \/____/                                       ~~              
                                                                                                    
{RESET}""")



warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

try:
    from scapy.all import IP, ICMP, TCP, sr1, Ether, ARP, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: Scapy not found. Low-level probes (A.1, A.2, A.4, A.5) will be skipped.")


VM_MAC_PREFIXES = {
    '00:05:69': 'VMware ESX/vSphere/Workstation',
    '00:0C:29': 'VMware ESX/vSphere/Workstation',
    '00:50:56': 'VMware ESX/vSphere/Workstation',
    '08:00:27': 'Oracle/VirtualBox',
    '00:03:FF': 'Microsoft Hyper-V/Virtual Server',
    '00:1C:42': 'Microsoft Hyper-V/Virtual Server',
    '52:54:00': 'QEMU/KVM/Red Hat',
}


class AdvancedHoneyTrapDetector:
    def __init__(self, target_host: str, target_port: int = 80, timeout: int = 10):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.report = {"deception_score": 0, "alerts": [], "warnings": []}
        
    def _add_alert(self, message: str, score_points: int, low_level: bool = False):
        self.report["alerts"].append(f"[{'L-LVL' if low_level else 'B-LVL'} / Score +{score_points}] {message}")
        self.report["deception_score"] += score_points

    def probe_a1_ttl_analysis(self):
        if not SCAPY_AVAILABLE: 
            return

        print(f"[*] A.1 Probe: Sending ICMP Echo Request for TTL analysis...")
        
        try:
            ping_reply = sr1(IP(dst=self.target_host)/ICMP(), timeout=self.timeout / 2, verbose=0)
            
            if ping_reply:
                initial_ttls = {64: 'Linux/Unix/MacOS', 128: 'Windows', 32: 'Old Windows/Embedded'}
                final_ttl = ping_reply.ttl
                
                closest_ttl = min(
                    initial_ttls.keys(),
                    key=lambda x: x - final_ttl if x > final_ttl else float('inf')
                )
                self._add_alert(
                    f"OS/TTL Guess: Target replies with TTL {final_ttl}. "
                    f"Estimated OS ({initial_ttls.get(closest_ttl, 'Unknown')}).",
                    0,
                    low_level=True
                )
                self.report["ttl_value"] = final_ttl
            else:
                self._add_alert(
                    "TTL Probe failed (Filtering/Blocking suspected). No ICMP reply received.",
                    3,
                    low_level=True
                )

        except Exception as e:
            self.report["warnings"].append(f"A.1 Probe Error: {e}")

    def probe_a2_protocol_inconsistency(self):
        if not SCAPY_AVAILABLE: 
            return

        print(f"[*] A.2 Probe: Sending 'Christmas Tree' TCP scan...")
        
        try:
            xmas_packet = IP(dst=self.target_host)/TCP(dport=self.target_port, flags="FPU")
            response = sr1(xmas_packet, timeout=self.timeout / 2, verbose=0)
            
            if response:
                flags = response.getlayer(TCP).flags if response.haslayer(TCP) else 0 
                self._add_alert(f"Non-Standard Response: Got TCP Flags '{flags}' back for FPU probe.", 0, low_level=True)
                
                if response.haslayer(TCP) and response.getlayer(TCP).flags not in [0x04, 0x14]: 
                    self._add_alert(
                        f"Protocol Inconsistency: Unexpected response flags ({flags}). "
                        f"Very high chance of Low-Interaction Honeypot.",
                        5,
                        low_level=True
                    )
            else:
                self._add_alert("A.2 Probe: No reply received (Aggressive Firewalling/Stealth).", 3, low_level=True)
                            
        except Exception as e:
            self.report["warnings"].append(f"A.2 Probe Error: {e}")

    def probe_fin_scan(self):
        if not SCAPY_AVAILABLE: 
            return

        print("[*] FIN Scan Probe running...")

        try:
            fin_packet = IP(dst=self.target_host)/TCP(dport=self.target_port, flags="F")
            resp = sr1(fin_packet, timeout=self.timeout/2, verbose=0)

            if resp:
                flags = resp.getlayer(TCP).flags if resp.haslayer(TCP) else 0
                if flags not in [0x04, 0x14]:  
                    self._add_alert(f"FIN Scan Anomaly: Unexpected response flags {flags}.", 4, low_level=True)
            else:
                self._add_alert("FIN Scan: No reply (possible stealth or filtering).", 2, low_level=True)
        except Exception as e:
            self.report["warnings"].append(f"FIN Scan Error: {e}")

    def probe_null_scan(self):
        if not SCAPY_AVAILABLE: 
            return

        print("[*] Null Scan Probe...")

        try:
            null_packet = IP(dst=self.target_host)/TCP(dport=self.target_port, flags="")
            resp = sr1(null_packet, timeout=self.timeout/2, verbose=0)

            if resp:
                flags = resp.getlayer(TCP).flags if resp.haslayer(TCP) else 0
                if flags not in [0x04, 0x14]:
                    self._add_alert(f"Null Scan Inconsistency: unexpected flags {flags}", 4, low_level=True)
            else:
                self._add_alert("Null Scan: Silent drop detected.", 2, low_level=True)
        except Exception as e:
            self.report["warnings"].append(f"Null Scan Error: {e}")

    def probe_window_size(self):
        if not SCAPY_AVAILABLE: 
            return

        print("[*] Window Size Probe...")

        try:
            syn = IP(dst=self.target_host)/TCP(dport=self.target_port, flags="S")
            resp = sr1(syn, timeout=self.timeout/2, verbose=0)

            if resp and resp.haslayer(TCP):
                win = resp.getlayer(TCP).window
                if win in [512, 1024, 2048]:
                    self._add_alert(f"Suspicious fixed TCP window size: {win}.", 4, low_level=True)
                else:
                    self.report["tcp_window"] = win
        except Exception as e:
            self.report["warnings"].append(f"Window Probe Error: {e}")

    def probe_tcp_options(self):
        if not SCAPY_AVAILABLE: 
            return

        print("[*] TCP Options Fingerprint Probe...")
        try:
            syn = IP(dst=self.target_host)/TCP(dport=self.target_port, flags="S")
            resp = sr1(syn, timeout=self.timeout/2, verbose=0)

            if resp and resp.haslayer(TCP):
                options = resp[TCP].options
                self.report["tcp_options"] = options
                
                if len(options) < 2: 
                    self._add_alert("Very few TCP options returned. Likely low-interaction emulation.", 5, low_level=True)
        except Exception as e:
            self.report["warnings"].append(f"TCP Options Error: {e}")

    def probe_honeypot_banner_fingerprint(self, http_url: str):
        print("[*] Honeypot Banner Fingerprint Probe...")

        try:
            r = requests.get(http_url, timeout=self.timeout, verify=False)
            body = r.text.lower()

            signatures = ["cowrie", "dionaea", "kippo", "honeyd"]

            for sig in signatures:
                if sig in body:
                    self._add_alert(f"Honeypot signature detected: {sig}", 10)
        except Exception:
            pass

    def probe_a3_behavioral_timing(self, http_url: str):
        print("[*] A.3 Probe: Comparing successful (200) vs error (404) response times.")
        try:
            start_ok = time.time()
            requests.get(http_url, timeout=self.timeout, verify=False)
            time_ok = time.time() - start_ok

            start_error = time.time()
            requests.get(http_url + "/ahtd-non-existent-path-12345", timeout=self.timeout, verify=False)
            time_error = time.time() - start_error

            timing_delta_ms = abs(time_ok - time_error) * 1000
            self.report["timing_delta_ms"] = f"{timing_delta_ms:.2f}"

            if time_error * 1000 < 50 and time_ok * 1000 > 200:
                self._add_alert(
                    "Error response was extremely fast. Indicates a pre-canned WAF/Honeypot "
                    "response without backend processing.",
                    5
                )

        except ConnectTimeout:
            self._add_alert(
                "A.3 Connection Abort: HTTP/S connection attempt timed out "
                "(Aggressive Block/Connection-Level WAF). Score adjusted.",
                7
            )
        except Exception as e:
            self.report["warnings"].append(f"A.3 Probe Error on URL {http_url}: {e}")

    def probe_a4_vm_mac_check(self):
        if not SCAPY_AVAILABLE: 
            return

        print(f"[*] A.4 Probe: Performing ARP scan for MAC Address check...")
        
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.target_host)
            answered, _ = srp(arp_request, timeout=2, verbose=0) 
            
            if answered:
                mac_address = answered[0][1].hwsrc
                mac_oui = mac_address[:8].upper()
                
                vendor = VM_MAC_PREFIXES.get(mac_oui)

                if vendor:
                    self._add_alert(
                        f"VM Artefact Detected: MAC OUI ({mac_oui}) belongs to {vendor}. "
                        f"Target is likely running in a VM/Virtualized environment.",
                        7,
                        low_level=True
                    )
                else:
                    self._add_alert(f"MAC OUI ({mac_oui}) not found in known VM Vendor list.", 0, low_level=True)
                
                self.report["mac_address"] = mac_address
            else:
                self._add_alert(
                    "A.4 Probe: ARP probe failed (Target outside local network or ARP is blocked).",
                    0,
                    low_level=True
                )

        except Exception as e:
            self.report["warnings"].append(f"A.4 Probe Error: {e}")

    def probe_a5_unassigned_port(self):
        if not SCAPY_AVAILABLE: 
            return

        try:
            UNASSIGNED_PORT = 55555 
            print(f"[*] A.5 Probe: Checking response for unassigned port {UNASSIGNED_PORT}...")
            
            syn_packet = IP(dst=self.target_host)/TCP(dport=UNASSIGNED_PORT, flags="S")
            response = sr1(syn_packet, timeout=self.timeout / 2, verbose=0)
            
            if response:
                flags = response.getlayer(TCP).flags if response.haslayer(TCP) else 0

                if flags == 0x12:
                    self._add_alert(
                        f"Port Anomaly: Unassigned Port {UNASSIGNED_PORT} returned SYN/ACK (OPEN). "
                        f"Strong sign of Low-Interaction Honeypot/Misconfigured emulation.",
                        6,
                        low_level=True
                    )
                elif flags not in [0x04, 0x14]:
                    self._add_alert(
                        f"Port Anomaly: Unexpected flags ({flags}) on unassigned port. "
                        f"Medium-Interaction Honeypot suspected.",
                        3,
                        low_level=True
                    )
            else:
                self._add_alert("A.5 Probe: No reply received (Stealth/High Port Filtering).", 3, low_level=True)
                
        except Exception as e:
            self.report["warnings"].append(f"A.5 Probe Error: {e}")

    def probe_a6_xff_check(self, http_url: str):
        print("[*] A.6 Probe: Checking for X-Forwarded-For reflection (Proxy/WAF check)...")
        TEST_IP = "1.1.1.1" 
        headers = {'X-Forwarded-For': TEST_IP, 'User-Agent': 'AHTD v1.0'}
        
        try:
            response = requests.get(http_url, headers=headers, timeout=self.timeout / 2, verify=False)
            
            reflected_in_headers = any(TEST_IP in v for v in response.headers.values() if v)
            reflected_in_body = TEST_IP in response.text
           
            if reflected_in_headers or reflected_in_body:
                self._add_alert(
                    f"Proxy Artefact: Test IP '{TEST_IP}' reflected in response headers/body. "
                    f"Target is behind a Proxy/CDN/WAF.",
                    3
                )
            else:
                self._add_alert("A.6 Probe: XFF value not immediately reflected (Proxy layer may be transparent or filtered).", 0)
                
        except Exception as e:
            self.report["warnings"].append(f"A.6 Probe Error on URL {http_url}: {e}")

    def run_detection(self, http_target_url: str) -> Dict[str, Any]:
        self.report = {"deception_score": 0, "alerts": [], "warnings": []} 

        print(f"\n--- Starting Advanced HoneyTrap Detector (AHTD) for {self.target_host} ---")
        
        self.probe_a4_vm_mac_check()
        self.probe_a1_ttl_analysis()
        self.probe_a2_protocol_inconsistency()
        self.probe_fin_scan()
        self.probe_null_scan()
        self.probe_window_size()
        self.probe_tcp_options()
        self.probe_a5_unassigned_port()
        self.probe_a6_xff_check(http_target_url)
        self.probe_honeypot_banner_fingerprint(http_target_url)
        self.probe_a3_behavioral_timing(http_target_url)

        score = self.report["deception_score"]
        
        level = "NORMAL SERVER"
        if any("[Score +7]" in a for a in self.report["alerts"]):
            level = "CONNECTION-BLOCK / VM-BASED"
        elif any("[Score +6]" in a for a in self.report["alerts"]):
            level = "LOW-INT. EMULATION FAILURE"
        elif any("[Score +5]" in a for a in self.report["alerts"]):
            level = "PROTOCOL / CANNED-RESPONSE ANOMALY"
        elif any("[Score +3]" in a for a in self.report["alerts"]):
            level = "AGGRESSIVE FIREWALLING / STEALTH MODE"

        if score > 15:
            conclusion = f"CRITICAL SUSPICION. {level} Honeypot/Deception Layer likely."
        elif score > 8:
            conclusion = f"HIGH SUSPICION. {level} Deception Layer indicated."
        elif score > 3:
            conclusion = f"MODERATE SUSPICION. {level} flags raised. Exercise caution."
        else:
            conclusion = "LOW SUSPICION. Target behaves consistently with a normal system."
            
        self.report["final_conclusion"] = conclusion
        return self.report


if __name__ == "__main__":
    # Print banner first
    logo()
    
    if len(sys.argv) < 2:
        print("Usage: sudo python3 honeypot.py <target_url>")
        print("Example: sudo python3 honeypot.py https://mitacsc.ac.in/")
        sys.exit(1)
        
    target_url_input = sys.argv[1]
    
    parsed_url = urlparse(target_url_input)
    target_host_hostname = parsed_url.hostname
    
    try:
        target_host_ip = socket.gethostbyname(target_host_hostname) 
        print(f"[INFO] Resolved {target_host_hostname} to IP {target_host_ip}")
            
    except gaierror as e:
        print(f"FATAL: DNS resolution failed for {target_host_hostname}. Cannot proceed.")
        print(f"Error: {e}")
        sys.exit(1)
        
    target_port = parsed_url.port if parsed_url.port else (443 if parsed_url.scheme == 'https' else 80)

    print("--- Note: A.1, A.2, A.4, and A.5 probes require 'scapy' and root/administrator privileges. ---")
    
    detector = AdvancedHoneyTrapDetector(target_host=target_host_ip, target_port=target_port, timeout=10)
    final_report = detector.run_detection(http_target_url=target_url_input)

    print("\n" + "="*60)
    print("FINAL HONEYTRAP DETECTION REPORT")
    print("="*60)
    
    print(f"Target Host: {target_host_hostname} ({target_host_ip}):{target_port}")
    print(f"Total Deception Score: {final_report['deception_score']}")
    print(f"Conclusion: {final_report['final_conclusion']}")
    
    print("\n--- Alerts and Triggers ---")
    if final_report.get('warnings'):
        for warn in final_report['warnings']:
            print(f"[Warning] {warn}")
            
    if final_report['alerts']:
        for alert in final_report['alerts']:
            print(f"* {alert}")
    else:
        print("* No significant deception alerts raised.")
        
    print("\n--- Technical Details ---")
    print(f"MAC Address: {final_report.get('mac_address', 'N/A')}") 
    print(f"TTL Value: {final_report.get('ttl_value', 'N/A')}")
    print(f"Timing Delta: {final_report.get('timing_delta_ms', 'N/A')} ms")
    if "tcp_window" in final_report:
        print(f"TCP Window Size: {final_report.get('tcp_window')}")
    if "tcp_options" in final_report:
        print(f"TCP Options: {final_report.get('tcp_options')}")

