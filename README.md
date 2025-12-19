# PluginReaper - WordPress Plugin Vulnerability Hunter

**Harvest vulnerable plugins from Exploit-DB GHDB and reap them from live WordPress sites**

```
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ██████╗ ██╗     ██╗   ██╗ ██████╗ ██╗███╗   ██╗               ║
║   ██╔══██╗██║     ██║   ██║██╔════╝ ██║████╗  ██║               ║
║   ██████╔╝██║     ██║   ██║██║  ███╗██║██╔██╗ ██║               ║
║   ██╔═══╝ ██║     ██║   ██║██║   ██║██║██║╚██╗██║               ║
║   ██║     ███████╗╚██████╔╝╚██████╔╝██║██║ ╚████║               ║
║   ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝               ║
║                                                                   ║
║   ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗                ║
║   ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗               ║
║   ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝               ║
║   ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗               ║
║   ██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║               ║
║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝               ║
║                                                                   ║
║          WordPress Plugin Vulnerability Hunter v3.0              ║
║          Exploit-DB GHDB + WPScan Integration                    ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

## 🎯 What is PluginReaper?

PluginReaper is an automated WordPress security scanner that:

1. **Harvests** vulnerable plugin information from Exploit-DB's Google Hacking Database
2. **Scans** live WordPress sites using WPScan CLI
3. **Reaps** vulnerabilities by cross-referencing installed plugins with the vulnerability database
4. **Reports** findings with actionable intelligence

**No WPScan API token required!** Uses the free WPScan CLI tool for complete functionality.

## ✨ Features

- 🔍 **GHDB Integration** - Automatically builds vulnerability database from Exploit-DB
- 🎯 **Live Site Scanning** - Enumerates actual plugins on target WordPress sites
- 🔄 **Smart Cross-Referencing** - Matches installed plugins against vulnerability data
- 📊 **Risk Classification** - Three-tier risk system (HIGH/MEDIUM/LOW)
- 📝 **Comprehensive Reports** - JSON and Markdown formats
- 🚀 **No API Limits** - Uses WPScan CLI, no rate limiting
- 🎨 **Clean Output** - Suppresses WPScan banner for cleaner results

## 🔧 Installation

### Prerequisites
```bash
# Python 3.7+
python3 --version

# Ruby (for WPScan)
ruby --version

# Install WPScan
gem install wpscan
```

### Install PluginReaper
```bash
# Install Python dependencies
pip install requests

# Make executable
chmod +x pluginreaper.py

# Test installation
./pluginreaper.py --help
```

## 🚀 Quick Start

### Basic Scan
```bash
# Scan a WordPress site
python3 pluginreaper.py --url https://target-site.com
```

### Aggressive Scan
```bash
# More thorough plugin detection (slower)
python3 pluginreaper.py --url https://target-site.com --aggressive
```

### Build Large Database
```bash
# Fetch more GHDB entries for comprehensive coverage
python3 pluginreaper.py --url https://target-site.com --max-results 300
```

## 📚 Usage Examples

### Test Your Setup
```bash
# Verify WPScan is working correctly
python3 pluginreaper.py --url https://wordpress.org --test-wpscan
```

### Build Vulnerability Database Only
```bash
# Create database without scanning (for offline use)
python3 pluginreaper.py --build-only --max-results 500
```

### Custom Output Directory
```bash
# Save reports to specific directory
python3 pluginreaper.py --url https://target.com --output /path/to/reports
```

### Debug Mode
```bash
# Enable verbose output for troubleshooting
python3 pluginreaper.py --url https://target.com --debug
```

### Suppress Banner
```bash
# Clean output for automation/scripting
python3 pluginreaper.py --url https://target.com --no-banner
```

## Command-Line Options

```
-u, --url URL              Target WordPress URL to scan
-m, --max-results N        Max GHDB entries to fetch (default: 150)
-s, --search TERM          GHDB search term (default: inurl:wp-content/plugins/)
-o, --output DIR           Output directory (default: reports)
--aggressive               Aggressive plugin detection
--build-only               Only build database, don't scan
--test-wpscan              Test WPScan configuration
--debug                    Enable debug output
--no-banner                Suppress ASCII banner
```

## 📊 Understanding Results

### Risk Levels

#### 🔴 Vulnerable (HIGH RISK)
- Plugin confirmed in GHDB vulnerability database
- WPScan detected known vulnerabilities
- **Action Required:** Update or remove immediately

#### 🟡 Potentially Vulnerable (MEDIUM RISK)
- Plugin found in GHDB but not flagged by WPScan
- May be older vulnerabilities or version-specific
- **Action Recommended:** Investigate and update if possible

#### 🟢 Clean (LOW RISK)
- Not in vulnerability database
- No known issues detected
- **Action:** Continue monitoring for updates

### Sample Output

```
[+] WordPress version: 5.9.12
[+] Found 14 plugins

[!] Note: WPScan API token not configured
[i] Cross-referencing with GHDB database will still work!

  ✓ elementor (v3.16.4)
  ✓ cookie-law-info (v3.0.8)
  🔴 VULNERABLE popup-maker (v1.18.2) [OUTDATED]
  ✓ wp-job-openings (v3.2.1) [OUTDATED]

[*] Cross-referencing 14 installed plugins with GHDB database...

[*] Generating reports...
  ✓ reports/pluginreaper_target_com_20231219_143022.json
  ✓ reports/pluginreaper_target_com_20231219_143022.md

======================================================================
Scan Summary
======================================================================
🔴 Vulnerable: 1
🟡 Potentially Vulnerable: 2
🟢 Clean: 11

⚠️  CRITICAL: Vulnerable plugins detected!
Review the report for details and remediation steps.

Reports saved to: /home/user/reports/
```

## 📁 Output Files

### JSON Report (`pluginreaper_*.json`)
Complete scan data including:
- All GHDB entries and references
- Plugin versions and locations
- Vulnerability details from WPScan
- Cross-reference results
- Metadata and timestamps

### Markdown Report (`pluginreaper_*.md`)
Human-readable report with:
- Executive summary
- Risk-categorized findings
- GHDB and CVE references
- Remediation recommendations

## 🔄 Workflow

```
1. HARVEST          2. SCAN              3. REAP              4. REPORT
   ↓                   ↓                    ↓                    ↓
[Exploit-DB]  →   [WPScan CLI]   →   [Cross-Reference]  →  [JSON + MD]
   GHDB API          Live Site          Match Plugins         Reports
```

## Use Cases

### Security Auditing
```bash
# Comprehensive security audit
python3 pluginreaper.py --url https://client-site.com --aggressive --max-results 500
```

### Penetration Testing
```bash
# Quick vulnerability assessment
python3 pluginreaper.py --url https://target.com
```

### Bulk Scanning
```bash
#!/bin/bash
# Scan multiple WordPress sites
while IFS= read -r site; do
    echo "[*] Scanning $site..."
    python3 pluginreaper.py --url "$site" --output "reports/$(date +%Y%m%d)" --no-banner
    sleep 10
done < sites.txt
```

### Continuous Monitoring
```bash
# Daily automated scan
0 2 * * * /path/to/pluginreaper.py --url https://mysite.com --output /var/reports --no-banner
```

## 🛠️ Advanced Usage

### Custom GHDB Searches
```bash
# Search for specific plugin types
python3 pluginreaper.py --url https://target.com \
    --search "inurl:wp-content/plugins/ inurl:upload"

# Search for themes instead
python3 pluginreaper.py --url https://target.com \
    --search "inurl:wp-content/themes/"
```

### Integration with Other Tools
```bash
# Export plugin list for use with other scanners
cat reports/pluginreaper_*.json | jq -r '.results.vulnerable | keys[]' > vulnerable.txt

# Feed to custom scanner
cat vulnerable.txt | while read plugin; do
    echo "[*] Deep scanning: $plugin"
    custom-scanner --plugin "$plugin"
done
```

## 🐛 Troubleshooting

### "WPScan not found"
```bash
# Install WPScan
gem install wpscan

# Verify installation
wpscan --version
```

### "No plugins detected"
- Site may be using security plugins that hide plugin information
- Try `--aggressive` mode
- Verify site is actually WordPress: `curl -I https://site.com/wp-admin/`

### Slow Scans
- Normal for large sites or aggressive mode
- Reduce `--max-results` if GHDB fetch is slow
- Target site may be rate-limiting requests

### Empty GHDB Results
- Exploit-DB API may have changed
- Use `--debug` to see raw API responses
- Check network connectivity to exploit-db.com

## ⚠️ Legal & Ethical Use

**IMPORTANT:** Only scan websites you own or have explicit written permission to test.

- Unauthorized scanning may violate computer fraud laws
- Always obtain proper authorization before testing
- Respect robots.txt and site policies
- Use responsibly for security research and defense
- Not responsible for misuse of this tool

## 🔒 Security Best Practices

After using PluginReaper:
1. ✅ Update all outdated plugins immediately
2. ✅ Remove unused or abandoned plugins
3. ✅ Enable automatic updates where possible
4. ✅ Implement Web Application Firewall (WAF)
5. ✅ Monitor security advisories regularly
6. ✅ Schedule regular scans (weekly/monthly)
7. ✅ Keep WordPress core updated
8. ✅ Use security hardening plugins

## 🤝 Contributing

Suggestions for improvements:
- Additional vulnerability sources (CVE databases, etc.)
- WordPress.org API integration
- Automated patch verification
- Multi-threaded scanning
- Database caching system

## 📄 License

This tool is provided for educational and authorized security research purposes only.

## 🙏 Credits

- **Exploit-DB** - Vulnerability data via GHDB
- **WPScan Team** - WordPress security scanner
- **WordPress.org** - Plugin information

---

**PluginReaper** - *Hunt vulnerabilities, harvest security.*

For issues or questions, use responsibly and always test with proper authorization.
