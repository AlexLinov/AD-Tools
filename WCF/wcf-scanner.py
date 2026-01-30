#!/usr/bin/env python3
"""
WCF Service Scanner
Usage:
    python3 wcf_scanner.py -t 10.10.10.10
    python3 wcf_scanner.py -t 10.10.10.10 -p 8000,8080,9000
    python3 wcf_scanner.py -f targets.txt -o results.json
    python3 wcf_scanner.py -t 10.10.10.10 --deep
"""

import argparse
import requests
import socket
import re
import json
import csv
import sys
import concurrent.futures
from urllib.parse import urljoin, urlparse
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
import xml.etree.ElementTree as ET
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore')


@dataclass
class WCFEndpoint:
    """Represents a discovered WCF endpoint"""
    url: str
    port: int
    wsdl_url: Optional[str] = None
    service_name: Optional[str] = None
    namespace: Optional[str] = None
    methods: List[str] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    binding_type: Optional[str] = None
    server_header: Optional[str] = None
    indicators: List[str] = field(default_factory=list)
    confidence: str = "Low"
    vulnerable_indicators: List[str] = field(default_factory=list)
    raw_wsdl: Optional[str] = None


@dataclass 
class ScanResult:
    """Complete scan result for a target"""
    target: str
    scan_time: str
    ports_scanned: List[int] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    wcf_endpoints: List[WCFEndpoint] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class WCFScanner:
    """WCF Service Detection and Enumeration Scanner"""
    
    # Common WCF/SOAP ports
    DEFAULT_PORTS = [80, 443, 8000, 8080, 8443, 9000, 9001, 9090, 8001, 8888, 5000]
    
    # WCF-specific URL paths to check
    WCF_PATHS = [
        '/',
        '/service',
        '/Service',
        '/api',
        '/ws',
        '/soap',
        '/services',
        '/WebService',
        '/webservice',
        '/MonitorService',
        '/DataService',
        '/AuthService',
    ]
    
    # File extensions indicating WCF/SOAP
    WCF_EXTENSIONS = ['.svc', '.asmx', '.wsdl']
    
    # WSDL endpoint suffixes
    WSDL_SUFFIXES = ['?wsdl', '?singleWsdl', '?WSDL', '/mex', '?xsd=xsd0']
    
    # Indicators in responses suggesting WCF
    WCF_INDICATORS = {
        'high': [
            'http://tempuri.org/',
            'System.ServiceModel',
            'BasicHttpBinding',
            'wsHttpBinding',
            'netTcpBinding',
            'WCF',
            '.svc',
            'IMetadataExchange',
            'wsdl:definitions',
            'schemas.xmlsoap.org/wsdl',
        ],
        'medium': [
            'Microsoft-HTTPAPI',
            'soap:Envelope',
            'soap:Body',
            'schemas.xmlsoap.org/soap',
            'SOAP-ENV',
            'xmlns:soap',
            'soapAction',
        ],
        'low': [
            'text/xml',
            'application/soap+xml',
            'XML Web Service',
        ]
    }
    
    # Patterns that might indicate vulnerabilities
    VULN_INDICATORS = [
        ('Command', 'Possible command execution method'),
        ('Execute', 'Possible command execution method'),
        ('Run', 'Possible code execution method'),
        ('Process', 'Possible process manipulation'),
        ('Kill', 'Possible process termination'),
        ('Shell', 'Possible shell access'),
        ('Cmd', 'Possible command interface'),
        ('Admin', 'Administrative function'),
        ('Upload', 'File upload functionality'),
        ('Download', 'File download functionality'),
        ('File', 'File operation method'),
        ('Path', 'Path manipulation possible'),
        ('Query', 'Possible injection point'),
        ('Sql', 'Possible SQL operation'),
        ('Eval', 'Possible code evaluation'),
        ('System', 'System-level operation'),
        ('Config', 'Configuration access'),
        ('Password', 'Password-related function'),
        ('Credential', 'Credential handling'),
        ('Token', 'Token/auth handling'),
    ]

    def __init__(self, timeout=10, threads=10, verbose=False, deep_scan=False):
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.deep_scan = deep_scan
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/xml,application/xml,*/*',
        })
        self.session.verify = False

    def log(self, message, level='info'):
        """Print log message if verbose"""
        colors = {
            'info': '\033[94m[*]\033[0m',
            'success': '\033[92m[+]\033[0m',
            'warning': '\033[93m[!]\033[0m',
            'error': '\033[91m[-]\033[0m',
            'vuln': '\033[95m[V]\033[0m',
        }
        prefix = colors.get(level, '[*]')
        if self.verbose or level in ['success', 'warning', 'vuln', 'error']:
            print(f"{prefix} {message}")

    def check_port(self, host, port, timeout=3):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

    def scan_ports(self, host, ports=None):
        """Scan ports on target host"""
        if ports is None:
            ports = self.DEFAULT_PORTS
        
        self.log(f"Scanning {len(ports)} ports on {host}")
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.check_port, host, port): port for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        self.log(f"Port {port} is open", 'success')
                except:
                    pass
        
        return sorted(open_ports)

    def check_http_service(self, url):
        """Check HTTP service and collect headers"""
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return {
                'status_code': resp.status_code,
                'headers': dict(resp.headers),
                'content': resp.text[:5000],
                'url': resp.url
            }
        except Exception as e:
            return None

    def check_wsdl(self, base_url):
        """Try to fetch WSDL from various endpoints"""
        wsdl_content = None
        wsdl_url = None
        
        for suffix in self.WSDL_SUFFIXES:
            url = base_url.rstrip('/') + suffix
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    content = resp.text
                    if any(ind in content for ind in ['wsdl:', 'definitions', 'portType', 'binding']):
                        self.log(f"WSDL found at {url}", 'success')
                        wsdl_content = content
                        wsdl_url = url
                        break
            except:
                continue
        
        return wsdl_url, wsdl_content

    def parse_wsdl(self, wsdl_content):
        """Parse WSDL to extract service information"""
        result = {
            'service_name': None,
            'namespace': None,
            'methods': [],
            'parameters': {},
            'binding_type': None
        }
        
        if not wsdl_content:
            return result
        
        try:
            # Extract namespace
            ns_match = re.search(r'targetNamespace="([^"]+)"', wsdl_content)
            if ns_match:
                result['namespace'] = ns_match.group(1)
            
            # Extract service name
            service_match = re.search(r'<wsdl:service\s+name="([^"]+)"', wsdl_content)
            if not service_match:
                service_match = re.search(r'<service\s+name="([^"]+)"', wsdl_content)
            if service_match:
                result['service_name'] = service_match.group(1)
            
            # Extract port type / interface name
            port_match = re.search(r'<wsdl:portType\s+name="([^"]+)"', wsdl_content)
            if not port_match:
                port_match = re.search(r'<portType\s+name="([^"]+)"', wsdl_content)
            
            # Extract operations/methods
            operations = re.findall(r'<wsdl:operation\s+name="([^"]+)"', wsdl_content)
            if not operations:
                operations = re.findall(r'<operation\s+name="([^"]+)"', wsdl_content)
            result['methods'] = list(set(operations))
            
            # Extract binding type
            if 'basicHttpBinding' in wsdl_content.lower():
                result['binding_type'] = 'BasicHttpBinding'
            elif 'wsHttpBinding' in wsdl_content.lower():
                result['binding_type'] = 'wsHttpBinding'
            elif 'netTcpBinding' in wsdl_content.lower():
                result['binding_type'] = 'netTcpBinding'
            
            # Try to extract parameters from XSD
            for method in result['methods']:
                params = []
                # Look for element definitions
                pattern = rf'{method}[^<]*<[^>]*sequence[^>]*>(.*?)</[^>]*sequence>'
                match = re.search(pattern, wsdl_content, re.DOTALL | re.IGNORECASE)
                if match:
                    param_matches = re.findall(r'element[^>]*name="([^"]+)"', match.group(1))
                    params = param_matches
                result['parameters'][method] = params
            
        except Exception as e:
            self.log(f"WSDL parsing error: {e}", 'warning')
        
        return result

    def analyze_indicators(self, response_data, wsdl_content=None):
        """Analyze response for WCF indicators"""
        indicators = []
        confidence = 'Low'
        confidence_score = 0
        
        content_to_check = ''
        headers_str = ''
        
        if response_data:
            content_to_check = response_data.get('content', '')
            headers_str = str(response_data.get('headers', {}))
        
        if wsdl_content:
            content_to_check += wsdl_content
        
        all_content = content_to_check + headers_str
        
        # Check for high confidence indicators
        for indicator in self.WCF_INDICATORS['high']:
            if indicator.lower() in all_content.lower():
                indicators.append(f"[HIGH] {indicator}")
                confidence_score += 3
        
        # Check for medium confidence indicators
        for indicator in self.WCF_INDICATORS['medium']:
            if indicator.lower() in all_content.lower():
                indicators.append(f"[MED] {indicator}")
                confidence_score += 2
        
        # Check for low confidence indicators
        for indicator in self.WCF_INDICATORS['low']:
            if indicator.lower() in all_content.lower():
                indicators.append(f"[LOW] {indicator}")
                confidence_score += 1
        
        # Determine overall confidence
        if confidence_score >= 6:
            confidence = 'High'
        elif confidence_score >= 3:
            confidence = 'Medium'
        else:
            confidence = 'Low'
        
        return indicators, confidence

    def check_vulnerable_methods(self, methods, parameters):
        """Check for potentially vulnerable method names"""
        vulns = []
        
        all_names = methods + [p for params in parameters.values() for p in params]
        
        for name in all_names:
            for pattern, desc in self.VULN_INDICATORS:
                if pattern.lower() in name.lower():
                    vulns.append(f"{name}: {desc}")
                    break
        
        return list(set(vulns))

    def scan_endpoint(self, host, port, protocol='http'):
        """Scan a single endpoint for WCF services"""
        base_url = f"{protocol}://{host}:{port}"
        endpoints = []
        
        paths_to_check = self.WCF_PATHS.copy()
        
        # Also try common .svc paths if deep scanning
        if self.deep_scan:
            paths_to_check.extend([
                '/Service.svc',
                '/WebService.svc',
                '/DataService.svc',
                '/api/Service.svc',
            ])
        
        for path in paths_to_check:
            url = base_url + path
            self.log(f"Checking {url}")
            
            # Check base URL
            response_data = self.check_http_service(url)
            if not response_data:
                continue
            
            # Check for WSDL
            wsdl_url, wsdl_content = self.check_wsdl(url)
            
            # Analyze indicators
            indicators, confidence = self.analyze_indicators(response_data, wsdl_content)
            
            # Skip if no WCF indicators found
            if not indicators and not wsdl_content:
                continue
            
            # Parse WSDL if found
            wsdl_data = self.parse_wsdl(wsdl_content) if wsdl_content else {}
            
            # Check for vulnerable methods
            vuln_indicators = self.check_vulnerable_methods(
                wsdl_data.get('methods', []),
                wsdl_data.get('parameters', {})
            )
            
            # Create endpoint object
            endpoint = WCFEndpoint(
                url=url,
                port=port,
                wsdl_url=wsdl_url,
                service_name=wsdl_data.get('service_name'),
                namespace=wsdl_data.get('namespace'),
                methods=wsdl_data.get('methods', []),
                parameters=wsdl_data.get('parameters', {}),
                binding_type=wsdl_data.get('binding_type'),
                server_header=response_data.get('headers', {}).get('Server'),
                indicators=indicators,
                confidence=confidence,
                vulnerable_indicators=vuln_indicators,
                raw_wsdl=wsdl_content[:2000] if wsdl_content else None
            )
            
            endpoints.append(endpoint)
            
            if confidence in ['High', 'Medium']:
                self.log(f"WCF Service found: {url} (Confidence: {confidence})", 'success')
                if wsdl_data.get('methods'):
                    self.log(f"  Methods: {', '.join(wsdl_data['methods'][:5])}{'...' if len(wsdl_data['methods']) > 5 else ''}", 'info')
                if vuln_indicators:
                    for vuln in vuln_indicators[:3]:
                        self.log(f"  Potential vuln: {vuln}", 'vuln')
        
        return endpoints

    def scan_target(self, target, ports=None):
        """Scan a single target"""
        self.log(f"\n{'='*60}", 'info')
        self.log(f"Scanning target: {target}", 'info')
        self.log(f"{'='*60}", 'info')
        
        result = ScanResult(
            target=target,
            scan_time=datetime.now().isoformat(),
            ports_scanned=ports or self.DEFAULT_PORTS
        )
        
        # Parse target
        if '://' in target:
            parsed = urlparse(target)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            ports = [port]
        else:
            host = target
        
        try:
            # Scan ports
            if ports:
                result.ports_scanned = ports
            result.open_ports = self.scan_ports(host, result.ports_scanned)
            
            if not result.open_ports:
                self.log(f"No open ports found on {target}", 'warning')
                return result
            
            # Scan each open port
            for port in result.open_ports:
                # Try HTTPS first for 443, then HTTP
                protocols = ['https'] if port == 443 else ['http']
                if port in [8443, 443]:
                    protocols = ['https', 'http']
                elif port in [80, 8080, 8000, 9000]:
                    protocols = ['http', 'https']
                
                for protocol in protocols:
                    try:
                        endpoints = self.scan_endpoint(host, port, protocol)
                        result.wcf_endpoints.extend(endpoints)
                        if endpoints:
                            break  # Found something, don't try other protocol
                    except Exception as e:
                        self.log(f"Error scanning {protocol}://{host}:{port}: {e}", 'error')
            
        except Exception as e:
            result.errors.append(str(e))
            self.log(f"Error scanning {target}: {e}", 'error')
        
        return result

    def scan_targets(self, targets, ports=None):
        """Scan multiple targets"""
        results = []
        
        for target in targets:
            target = target.strip()
            if not target or target.startswith('#'):
                continue
            result = self.scan_target(target, ports)
            results.append(result)
        
        return results

    def print_summary(self, results):
        """Print scan summary"""
        print("\n" + "="*70)
        print("SCAN SUMMARY")
        print("="*70)
        
        total_endpoints = 0
        high_confidence = 0
        potential_vulns = 0
        
        for result in results:
            if result.wcf_endpoints:
                print(f"\n\033[92m[+] {result.target}\033[0m")
                for ep in result.wcf_endpoints:
                    total_endpoints += 1
                    if ep.confidence == 'High':
                        high_confidence += 1
                    if ep.vulnerable_indicators:
                        potential_vulns += len(ep.vulnerable_indicators)
                    
                    conf_color = {'High': '\033[91m', 'Medium': '\033[93m', 'Low': '\033[94m'}
                    print(f"  └─ {ep.url}")
                    print(f"     Confidence: {conf_color.get(ep.confidence, '')}{ep.confidence}\033[0m")
                    if ep.service_name:
                        print(f"     Service: {ep.service_name}")
                    if ep.methods:
                        print(f"     Methods ({len(ep.methods)}): {', '.join(ep.methods[:5])}{'...' if len(ep.methods) > 5 else ''}")
                    if ep.wsdl_url:
                        print(f"     WSDL: {ep.wsdl_url}")
                    if ep.vulnerable_indicators:
                        print(f"     \033[95m⚠ Potential vulnerabilities:\033[0m")
                        for v in ep.vulnerable_indicators[:5]:
                            print(f"       - {v}")
            else:
                print(f"\n\033[90m[-] {result.target} - No WCF services found\033[0m")
        
        print("\n" + "-"*70)
        print(f"Total WCF endpoints found: {total_endpoints}")
        print(f"High confidence findings: {high_confidence}")
        print(f"Potential vulnerabilities: {potential_vulns}")
        print("-"*70)

    def export_json(self, results, filename):
        """Export results to JSON"""
        output = []
        for result in results:
            r = {
                'target': result.target,
                'scan_time': result.scan_time,
                'open_ports': result.open_ports,
                'endpoints': []
            }
            for ep in result.wcf_endpoints:
                r['endpoints'].append(asdict(ep))
            output.append(r)
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\n[+] Results exported to {filename}")

    def export_csv(self, results, filename):
        """Export results to CSV"""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Target', 'Port', 'URL', 'Service Name', 'Confidence',
                'Methods', 'WSDL URL', 'Vulnerable Indicators'
            ])
            for result in results:
                for ep in result.wcf_endpoints:
                    writer.writerow([
                        result.target,
                        ep.port,
                        ep.url,
                        ep.service_name or '',
                        ep.confidence,
                        '; '.join(ep.methods),
                        ep.wsdl_url or '',
                        '; '.join(ep.vulnerable_indicators)
                    ])
        print(f"\n[+] Results exported to {filename}")


def print_banner():
    banner = """
\033[94m
╔═══════════════════════════════════════════════════════════════════╗
║                    WCF Service Scanner v1.0                       ║
║         Windows Communication Foundation Detection Tool           ║
╚═══════════════════════════════════════════════════════════════════╝
\033[0m"""
    print(banner)


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='WCF Service Scanner - Detect and enumerate WCF/SOAP services',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -t 10.10.10.10
  %(prog)s -t 10.10.10.10 -p 8000,8080,9000
  %(prog)s -f targets.txt --deep -o results.json
  %(prog)s -t 192.168.1.0/24 -p 8000 --threads 50
  %(prog)s -t http://target.com:8000/Service -v
        '''
    )
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', help='Single target (IP, hostname, or URL)')
    target_group.add_argument('-f', '--file', help='File containing targets (one per line)')
    parser.add_argument('-p', '--ports', help='Ports to scan (comma-separated, default: common WCF ports)')
    parser.add_argument('--deep', action='store_true', help='Deep scan - check more paths and extensions')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Output file (supports .json and .csv)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    ports = None
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    
    scanner = WCFScanner(
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
        deep_scan=args.deep
    )
    
    if args.target:
        targets = [args.target]
    else:
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    print(f"[*] Targets: {len(targets)}")
    print(f"[*] Ports: {ports or scanner.DEFAULT_PORTS}")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] Deep scan: {args.deep}")
    
    results = scanner.scan_targets(targets, ports)
    
    scanner.print_summary(results)
    
    if args.output:
        if args.output.endswith('.json'):
            scanner.export_json(results, args.output)
        elif args.output.endswith('.csv'):
            scanner.export_csv(results, args.output)
        else:
            scanner.export_json(results, args.output + '.json')


if __name__ == '__main__':
    main()
