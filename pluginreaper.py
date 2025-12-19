#!/usr/bin/env python3
"""
PluginReaper - WordPress Plugin Vulnerability Hunter
Harvests vulnerable plugins from Exploit-DB GHDB and reaps them from live WordPress sites
"""

import requests
import re
import json
import subprocess
import argparse
import time
from typing import List, Dict, Optional, Set
from pathlib import Path
import sys

# ASCII Art Banner
BANNER = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██████╗ ██╗     ██╗   ██╗ ██████╗ ██╗███╗   ██╗         ║
║   ██╔══██╗██║     ██║   ██║██╔════╝ ██║████╗  ██║         ║
║   ██████╔╝██║     ██║   ██║██║  ███╗██║██╔██╗ ██║         ║
║   ██╔═══╝ ██║     ██║   ██║██║   ██║██║██║╚██╗██║         ║
║   ██║     ███████╗╚██████╔╝╚██████╔╝██║██║ ╚████║         ║
║   ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝         ║
║                                                           ║
║   ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗         ║
║   ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗        ║
║   ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝        ║
║   ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗        ║
║   ██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║        ║
║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝        ║
║                                                           ║
║          WordPress Plugin Vulnerability Hunter v1.0       ║
║          Exploit-DB GHDB + WPScan Integration             ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""

VERSION = "1.0"
AUTHOR = "Security Research Tool"

class ExploitDBAPI:
    """
    Interface to Exploit-DB's GHDB DataTables API
    """
    def __init__(self, debug=False):
        self.base_url = "https://www.exploit-db.com/google-hacking-database"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': 'https://www.exploit-db.com/google-hacking-database'
        })
        self.debug = debug
    
    def search_ghdb(self, search_term: str, max_results: int = 150) -> List[Dict]:
        """
        Search GHDB using the DataTables API
        """
        all_results = []
        start = 0
        length = 15
        
        print(f"\n[*] Searching GHDB API for: '{search_term}'")
        print(f"[*] Maximum results to fetch: {max_results}")
        
        while start < max_results:
            try:
                params = {
                    'draw': 1,
                    'columns[0][data]': 'date',
                    'columns[0][name]': 'date',
                    'columns[0][searchable]': 'true',
                    'columns[0][orderable]': 'true',
                    'columns[0][search][value]': '',
                    'columns[0][search][regex]': 'false',
                    'columns[1][data]': 'url_title',
                    'columns[1][name]': 'url_title',
                    'columns[1][searchable]': 'true',
                    'columns[1][orderable]': 'false',
                    'columns[1][search][value]': '',
                    'columns[1][search][regex]': 'false',
                    'columns[2][data]': 'cat_id',
                    'columns[2][name]': 'cat_id',
                    'columns[2][searchable]': 'true',
                    'columns[2][orderable]': 'false',
                    'columns[2][search][value]': '',
                    'columns[2][search][regex]': 'false',
                    'columns[3][data]': 'author_id',
                    'columns[3][name]': 'author_id',
                    'columns[3][searchable]': 'false',
                    'columns[3][orderable]': 'false',
                    'columns[3][search][value]': '',
                    'columns[3][search][regex]': 'false',
                    'order[0][column]': '0',
                    'order[0][dir]': 'desc',
                    'start': start,
                    'length': length,
                    'search[value]': search_term,
                    'search[regex]': 'false',
                    'author': '',
                    'category': '',
                    '_': str(int(time.time() * 1000))
                }
                
                print(f"[*] Fetching entries {start}-{start+length}...", end=' ')
                
                response = self.session.get(self.base_url, params=params, timeout=15)
                response.raise_for_status()
                
                data = response.json()
                entries = data.get('data', [])
                total_records = data.get('recordsFiltered', 0)
                
                if not entries:
                    print("No more entries")
                    break
                
                print(f"Found {len(entries)} entries (Total: {total_records})")
                
                for entry in entries:
                    if self.debug and len(all_results) == 0:
                        print(f"\n[DEBUG] First entry structure:")
                        print(f"Keys: {entry.keys()}")
                        for key, value in entry.items():
                            print(f"  {key}: {type(value).__name__} = {str(value)[:100]}")
                    
                    processed_entry = self._process_entry(entry)
                    if processed_entry:
                        all_results.append(processed_entry)
                
                if start + length >= total_records:
                    break
                
                start += length
                time.sleep(1)
                
            except Exception as e:
                print(f"\n[!] Error: {e}")
                break
        
        print(f"\n[+] Retrieved {len(all_results)} GHDB entries")
        return all_results
    
    def _process_entry(self, entry: Dict) -> Optional[Dict]:
        """
        Process a single GHDB entry from the API response
        """
        try:
            def to_string(value):
                if isinstance(value, list):
                    return ' '.join(str(v) for v in value)
                return str(value) if value else ''
            
            entry_id = entry.get('id', '')
            if isinstance(entry_id, list):
                entry_id = entry_id[0] if entry_id else ''
            
            date_val = to_string(entry.get('date', ''))
            url_title_val = to_string(entry.get('url_title', ''))
            cat_id_val = to_string(entry.get('cat_id', ''))
            
            return {
                'id': str(entry_id),
                'date': self._extract_text(date_val),
                'title': self._extract_text(url_title_val),
                'url': f"https://www.exploit-db.com/ghdb/{entry_id}",
                'category': self._extract_text(cat_id_val),
                'raw_html': url_title_val
            }
        except Exception as e:
            if self.debug:
                print(f"\n[!] Error processing entry: {e}")
            return None
    
    def _extract_text(self, html_string: str) -> str:
        """Extract plain text from HTML string"""
        text = re.sub(r'<[^>]+>', '', html_string)
        return text.strip()


class WPScanCLI:
    """
    Interface to WPScan CLI for actual site scanning
    """
    def __init__(self):
        self.wpscan_available = self._check_wpscan()
    
    def _check_wpscan(self) -> bool:
        """Check if WPScan is installed"""
        try:
            result = subprocess.run(['wpscan', '--version'], 
                                   capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                version = result.stdout.strip()
                print(f"[+] WPScan detected: {version}")
                return True
        except FileNotFoundError:
            print("[!] WPScan not found. Install with: gem install wpscan")
            return False
        except Exception as e:
            print(f"[!] Error checking WPScan: {e}")
            return False
        return False
    
    def enumerate_plugins(self, target_url: str, aggressive: bool = False, debug: bool = False) -> Dict[str, Dict]:
        """
        Enumerate WordPress plugins on target site using WPScan
        Returns dict of {plugin_slug: {version: str, vulnerabilities: []}}
        """
        if not self.wpscan_available:
            print("[!] WPScan is not available")
            return {}
        
        print(f"\n[*] Scanning {target_url} for WordPress plugins...")
        print("[*] This may take a few minutes...")
        
        # Build WPScan command
        cmd = [
            'wpscan',
            '--url', target_url,
            '-e', 'p',  # Enumerate plugins
            '--no-update',
            '--no-banner',  # Suppress WPScan logo
            '--random-user-agent',
            '--format', 'json',
            '--plugins-detection', 'aggressive' if aggressive else 'passive'
        ]
        
        if debug:
            print(f"[DEBUG] Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if debug:
                print(f"[DEBUG] Return code: {result.returncode}")
                print(f"[DEBUG] STDOUT length: {len(result.stdout)}")
                print(f"[DEBUG] STDERR length: {len(result.stderr)}")
            
            if result.returncode != 0 and result.returncode != 4:
                # Return code 4 means vulnerabilities found (success for us)
                print(f"[!] WPScan returned error code: {result.returncode}")
                if result.stderr:
                    print(f"[!] Error: {result.stderr[:500]}")
                if debug and result.stdout:
                    print(f"[DEBUG] Output: {result.stdout[:1000]}")
                return {}
            
            # Parse JSON output
            if not result.stdout or not result.stdout.strip():
                print("[!] WPScan returned empty output")
                if result.stderr:
                    print(f"[!] STDERR: {result.stderr[:500]}")
                return {}
            
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                print(f"[!] Failed to parse WPScan JSON output: {e}")
                if debug:
                    print(f"[DEBUG] First 1000 chars of output:")
                    print(result.stdout[:1000])
                return {}
            
            if debug:
                print(f"[DEBUG] JSON keys: {data.keys() if data else 'None'}")
            
            # Extract plugins
            plugins = {}
            
            # Check if it's a WordPress site
            if not data:
                print("[!] WPScan returned empty data")
                return {}
            
            version_data = data.get('version')
            if not version_data:
                print("[!] Target does not appear to be a WordPress site")
                if debug:
                    print(f"[DEBUG] Available keys: {list(data.keys())}")
                return {}
            
            # Handle version data - it might be a dict or direct value
            if isinstance(version_data, dict):
                wp_version = version_data.get('number', 'Unknown')
            else:
                wp_version = str(version_data)
            
            print(f"[+] WordPress version: {wp_version}")
            
            # Extract plugin information
            plugins_data = data.get('plugins')
            
            if not plugins_data:
                print("[!] No plugins detected")
                if debug:
                    print(f"[DEBUG] Available data keys: {list(data.keys())}")
                return {}
            
            if not isinstance(plugins_data, dict):
                print(f"[!] Unexpected plugins data type: {type(plugins_data)}")
                return {}
            
            print(f"[+] Found {len(plugins_data)} plugins")
            
            # Check if vulnerability data is available
            vuln_api_info = data.get('vuln_api', {})
            if vuln_api_info.get('error'):
                print("\n[!] Note: WPScan API token not configured")
                print("[!] Vulnerability data from WPScan will be limited")
                print("[i] Get free API token at: https://wpscan.com/register")
                print("[i] Use: wpscan --url TARGET --api-token YOUR_TOKEN")
                print("[i] Cross-referencing with GHDB database will still work!\n")
            
            for plugin_slug, plugin_info in plugins_data.items():
                if not isinstance(plugin_info, dict):
                    if debug:
                        print(f"[DEBUG] Skipping {plugin_slug} - not a dict: {type(plugin_info)}")
                    continue
                
                # Extract version - handle different formats
                version_info = plugin_info.get('version')
                
                if version_info is None:
                    # Version is null/None
                    version = 'Unknown'
                elif isinstance(version_info, dict):
                    # Version is a dict with 'number' field
                    version = version_info.get('number', 'Unknown')
                elif isinstance(version_info, str):
                    # Version is a string
                    version = version_info
                else:
                    version = 'Unknown'
                
                vulnerabilities = plugin_info.get('vulnerabilities', [])
                
                plugins[plugin_slug] = {
                    'version': version,
                    'location': plugin_info.get('location', ''),
                    'latest_version': plugin_info.get('latest_version'),
                    'outdated': plugin_info.get('outdated', False),
                    'vulnerabilities': vulnerabilities if isinstance(vulnerabilities, list) else []
                }
                
                status = "🔴 VULNERABLE" if vulnerabilities else "✓"
                version_str = f"v{version}" if version != 'Unknown' else "version unknown"
                outdated_marker = " [OUTDATED]" if plugin_info.get('outdated') else ""
                print(f"  {status} {plugin_slug} ({version_str}){outdated_marker}")
                
                if vulnerabilities and isinstance(vulnerabilities, list):
                    for vuln in vulnerabilities[:3]:  # Show first 3
                        if isinstance(vuln, dict):
                            print(f"      - {vuln.get('title', 'No title')}")
            
            return plugins
            
        except subprocess.TimeoutExpired:
            print("[!] WPScan timed out (>5 minutes)")
            return {}
        except Exception as e:
            print(f"[!] Error running WPScan: {e}")
            if debug:
                import traceback
                traceback.print_exc()
            return {}


class VulnerabilityMatcher:
    """
    Matches installed plugins against GHDB vulnerability database
    """
    def __init__(self, ghdb_plugins: Dict[str, Dict]):
        self.ghdb_plugins = ghdb_plugins
    
    def match_vulnerabilities(self, installed_plugins: Dict[str, Dict]) -> Dict:
        """
        Cross-reference installed plugins with GHDB vulnerability data
        """
        results = {
            'vulnerable': {},
            'potentially_vulnerable': {},
            'clean': {}
        }
        
        print(f"\n[*] Cross-referencing {len(installed_plugins)} installed plugins with GHDB database...")
        
        for plugin_slug, plugin_info in installed_plugins.items():
            # Check if plugin is in our GHDB database
            if plugin_slug in self.ghdb_plugins:
                ghdb_info = self.ghdb_plugins[plugin_slug]
                
                # Plugin found in vulnerability database
                if plugin_info['vulnerabilities']:
                    # WPScan already found vulnerabilities
                    results['vulnerable'][plugin_slug] = {
                        'installed_version': plugin_info['version'],
                        'wpscan_vulnerabilities': plugin_info['vulnerabilities'],
                        'ghdb_entries': ghdb_info['ghdb_entries'],
                        'confidence': 'HIGH'
                    }
                else:
                    # In GHDB but WPScan didn't flag it
                    results['potentially_vulnerable'][plugin_slug] = {
                        'installed_version': plugin_info['version'],
                        'ghdb_entries': ghdb_info['ghdb_entries'],
                        'confidence': 'MEDIUM',
                        'note': 'Found in GHDB but not flagged by WPScan'
                    }
            else:
                # Not in GHDB database
                if plugin_info['vulnerabilities']:
                    # WPScan found vulns but not in our GHDB
                    results['vulnerable'][plugin_slug] = {
                        'installed_version': plugin_info['version'],
                        'wpscan_vulnerabilities': plugin_info['vulnerabilities'],
                        'ghdb_entries': [],
                        'confidence': 'HIGH'
                    }
                else:
                    # Clean
                    results['clean'][plugin_slug] = {
                        'installed_version': plugin_info['version']
                    }
        
        return results


class PluginReaper:
    """
    Main scanner orchestrator
    """
    def __init__(self, debug: bool = False):
        self.exploitdb = ExploitDBAPI(debug=debug)
        self.wpscan = WPScanCLI()
        self.ghdb_entries = []
        self.plugins = {}
        self.debug = debug
    
    def build_vulnerability_database(self, search_term: str = "inurl:wp-content/plugins/", 
                                    max_results: int = 150):
        """
        Build vulnerability database from GHDB
        """
        self.ghdb_entries = self.exploitdb.search_ghdb(search_term, max_results)
        
        if not self.ghdb_entries:
            print("[!] Failed to build vulnerability database")
            return
        
        # Extract plugin names
        print("\n[*] Extracting plugin names from GHDB entries...")
        for entry in self.ghdb_entries:
            self._extract_plugins_from_entry(entry)
        
        print(f"[+] Built database with {len(self.plugins)} vulnerable plugins")
    
    def _extract_plugins_from_entry(self, entry: Dict):
        """Extract plugin names from GHDB entry"""
        text = entry.get('title', '') + ' ' + entry.get('raw_html', '')
        
        patterns = [
            r'wp-content/plugins/([a-zA-Z0-9_-]+)',
            r'/plugins/([a-zA-Z0-9_-]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                plugin_name = match.strip('/').lower()
                if plugin_name and len(plugin_name) > 2 and plugin_name not in ['plugins']:
                    if plugin_name not in self.plugins:
                        self.plugins[plugin_name] = {
                            'name': plugin_name,
                            'ghdb_entries': []
                        }
                    
                    self.plugins[plugin_name]['ghdb_entries'].append({
                        'id': entry['id'],
                        'title': entry['title'],
                        'url': entry['url'],
                        'date': entry.get('date', '')
                    })
    
    def scan_target(self, target_url: str, aggressive: bool = False) -> Dict:
        """
        Scan a WordPress site and match against vulnerability database
        """
        # Enumerate plugins on target
        installed_plugins = self.wpscan.enumerate_plugins(target_url, aggressive, self.debug)
        
        if not installed_plugins:
            print("[!] No plugins found or scan failed")
            return {}
        
        # Match against GHDB database
        matcher = VulnerabilityMatcher(self.plugins)
        results = matcher.match_vulnerabilities(installed_plugins)
        
        return results
    
    def generate_report(self, target_url: str, scan_results: Dict, output_dir: str = "reports"):
        """
        Generate comprehensive scan report
        """
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        # Sanitize URL for filename
        safe_url = re.sub(r'[^\w\-]', '_', target_url)
        
        print(f"\n[*] Generating reports...")
        
        # JSON Report
        json_file = output_path / f"pluginreaper_{safe_url}_{timestamp}.json"
        report_data = {
            'target': target_url,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'results': scan_results,
            'ghdb_database_size': len(self.plugins),
            'tool': 'PluginReaper',
            'version': VERSION
        }
        
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        print(f"  ✓ {json_file}")
        
        # Markdown Report
        md_file = output_path / f"pluginreaper_{safe_url}_{timestamp}.md"
        with open(md_file, 'w') as f:
            f.write(f"# PluginReaper Security Scan Report\n\n")
            f.write(f"**Target:** {target_url}\n")
            f.write(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Tool:** PluginReaper v{VERSION}\n\n")
            
            # Summary
            vuln_count = len(scan_results.get('vulnerable', {}))
            potential_count = len(scan_results.get('potentially_vulnerable', {}))
            clean_count = len(scan_results.get('clean', {}))
            
            f.write("## Summary\n\n")
            f.write(f"- 🔴 **Vulnerable Plugins:** {vuln_count}\n")
            f.write(f"- 🟡 **Potentially Vulnerable:** {potential_count}\n")
            f.write(f"- 🟢 **Clean Plugins:** {clean_count}\n\n")
            
            # Vulnerable plugins
            if scan_results.get('vulnerable'):
                f.write("## 🔴 Vulnerable Plugins (HIGH RISK)\n\n")
                for plugin, info in scan_results['vulnerable'].items():
                    f.write(f"### {plugin}\n\n")
                    f.write(f"**Installed Version:** {info['installed_version']}\n")
                    f.write(f"**Confidence:** {info['confidence']}\n\n")
                    
                    if info.get('wpscan_vulnerabilities'):
                        f.write("**Known Vulnerabilities (WPScan):**\n")
                        for vuln in info['wpscan_vulnerabilities']:
                            f.write(f"- **{vuln.get('title', 'No title')}**\n")
                            if vuln.get('references'):
                                f.write(f"  - References: {', '.join(vuln['references'].get('url', [])[:3])}\n")
                        f.write("\n")
                    
                    if info.get('ghdb_entries'):
                        f.write("**GHDB References:**\n")
                        for entry in info['ghdb_entries'][:5]:
                            f.write(f"- [{entry['title']}]({entry['url']})\n")
                        f.write("\n")
            
            # Potentially vulnerable
            if scan_results.get('potentially_vulnerable'):
                f.write("## 🟡 Potentially Vulnerable Plugins\n\n")
                for plugin, info in scan_results['potentially_vulnerable'].items():
                    f.write(f"### {plugin}\n\n")
                    f.write(f"**Installed Version:** {info['installed_version']}\n")
                    f.write(f"**Note:** {info['note']}\n\n")
                    
                    f.write("**GHDB References:**\n")
                    for entry in info['ghdb_entries'][:5]:
                        f.write(f"- [{entry['title']}]({entry['url']})\n")
                    f.write("\n")
            
            # Clean plugins
            if scan_results.get('clean'):
                f.write("## 🟢 Clean Plugins\n\n")
                for plugin, info in scan_results['clean'].items():
                    f.write(f"- {plugin} ({info['installed_version']})\n")
        
        print(f"  ✓ {md_file}")
        
        return output_path


def print_banner():
    """Display the tool banner"""
    print(BANNER)


def main():
    parser = argparse.ArgumentParser(
        description='PluginReaper - WordPress Plugin Vulnerability Hunter',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a WordPress site
  %(prog)s --url https://target-site.com
  
  # Aggressive plugin detection
  %(prog)s --url https://target-site.com --aggressive
  
  # Build larger vulnerability database
  %(prog)s --url https://target-site.com --max-results 300
  
  # Just build the vulnerability database (no scan)
  %(prog)s --build-only
  
  # Test WPScan configuration
  %(prog)s --url https://target-site.com --test-wpscan
        """
    )
    
    parser.add_argument('-u', '--url',
                       help='Target WordPress URL to scan')
    parser.add_argument('-m', '--max-results', type=int, default=150,
                       help='Maximum GHDB results to fetch (default: 150)')
    parser.add_argument('-s', '--search', default='inurl:wp-content/plugins/',
                       help='GHDB search term (default: inurl:wp-content/plugins/)')
    parser.add_argument('-o', '--output', default='reports',
                       help='Output directory for reports (default: reports)')
    parser.add_argument('--aggressive', action='store_true',
                       help='Use aggressive plugin detection (slower but more thorough)')
    parser.add_argument('--build-only', action='store_true',
                       help='Only build vulnerability database, don\'t scan')
    parser.add_argument('--test-wpscan', action='store_true',
                       help='Test WPScan and show raw output (requires --url)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output')
    parser.add_argument('--no-banner', action='store_true',
                       help='Suppress banner display')
    
    args = parser.parse_args()
    
    # Display banner unless suppressed
    if not args.no_banner:
        print_banner()
    
    # Special case: test WPScan
    if args.test_wpscan:
        if not args.url:
            parser.error("--test-wpscan requires --url")
        
        print("\n[*] Testing WPScan Configuration...")
        print("=" * 70)
        
        scanner = WPScanCLI()
        if not scanner.wpscan_available:
            print("[!] WPScan is not installed")
            sys.exit(1)
        
        cmd = [
            'wpscan',
            '--url', args.url,
            '-e', 'p',
            '--no-update',
            '--no-banner',
            '--random-user-agent',
            '--format', 'json'
        ]
        
        print(f"\n[*] Running: {' '.join(cmd)}")
        print("[*] Please wait...\n")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            print(f"Return Code: {result.returncode}")
            print(f"\n{'='*70}")
            print("STDOUT:")
            print('='*70)
            print(result.stdout)
            
            if result.stderr:
                print(f"\n{'='*70}")
                print("STDERR:")
                print('='*70)
                print(result.stderr)
            
            # Try to parse JSON
            print(f"\n{'='*70}")
            print("JSON Parsing Test:")
            print('='*70)
            try:
                data = json.loads(result.stdout)
                print(f"✓ Valid JSON")
                print(f"Keys: {list(data.keys())}")
                if 'version' in data:
                    print(f"Version data type: {type(data['version'])}")
                    print(f"Version data: {data['version']}")
                if 'plugins' in data:
                    print(f"Plugins count: {len(data.get('plugins', {}))}")
                    print(f"Plugin names: {list(data.get('plugins', {}).keys())}")
            except json.JSONDecodeError as e:
                print(f"✗ Invalid JSON: {e}")
                
        except subprocess.TimeoutExpired:
            print("[!] Timeout after 5 minutes")
        except Exception as e:
            print(f"[!] Error: {e}")
            import traceback
            traceback.print_exc()
        
        sys.exit(0)
    
    if not args.build_only and not args.url:
        parser.error("--url is required unless using --build-only")
    
    # Initialize scanner
    scanner = PluginReaper(debug=args.debug)
    
    # Build vulnerability database from GHDB
    scanner.build_vulnerability_database(
        search_term=args.search,
        max_results=args.max_results
    )
    
    if args.build_only:
        # Save database
        db_file = Path(args.output) / "vulnerability_database.json"
        Path(args.output).mkdir(exist_ok=True)
        with open(db_file, 'w') as f:
            json.dump({
                'plugins': scanner.plugins,
                'ghdb_entries': scanner.ghdb_entries,
                'built_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'tool': 'PluginReaper',
                'version': VERSION
            }, f, indent=2)
        print(f"\n[+] Vulnerability database saved to: {db_file}")
        return
    
    # Scan target site
    scan_results = scanner.scan_target(args.url, args.aggressive)
    
    if scan_results:
        # Generate reports
        output_dir = scanner.generate_report(args.url, scan_results, args.output)
        
        # Print summary
        print("\n" + "=" * 70)
        print("Scan Summary")
        print("=" * 70)
        
        vuln_count = len(scan_results.get('vulnerable', {}))
        potential_count = len(scan_results.get('potentially_vulnerable', {}))
        clean_count = len(scan_results.get('clean', {}))
        
        print(f"🔴 Vulnerable: {vuln_count}")
        print(f"🟡 Potentially Vulnerable: {potential_count}")
        print(f"🟢 Clean: {clean_count}")
        
        if vuln_count > 0:
            print("\n⚠️  CRITICAL: Vulnerable plugins detected!")
            print("Review the report for details and remediation steps.")
        
        print(f"\nReports saved to: {output_dir.absolute()}/")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
