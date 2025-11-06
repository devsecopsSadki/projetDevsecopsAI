# parsca.py
"""
Prépare un .txt lisible par LLM depuis un rapport SCA Snyk (dépendances).
Format simplifié avec informations essentielles uniquement.
Usage:
    python parsca.py <sca-raw.json> <out.txt>
"""
import sys
import json
from pathlib import Path

def parse_snyk_report(report_path: str):
    """Parse raw Snyk JSON report and extract vulnerabilities."""
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        vulnerabilities = []
        snyk_vulns = data.get('vulnerabilities', [])
        
        for v in snyk_vulns:
            # Extract package name and current version
            pkg_name = v.get('packageName', 'unknown')
            current_version = v.get('version', 'unknown')
            
            # Get recommended version
            recommended_version = get_fixed_version(v)
            
            vuln = {
                'package': pkg_name,
                'current_version': current_version,
                'recommended_version': recommended_version,
                'title': v.get('title', 'No title'),
                'severity': v.get('severity', 'unknown').upper(),
                'cve': v.get('identifiers', {}).get('CVE', ['N/A'])[0] if v.get('identifiers', {}).get('CVE') else 'N/A',
                'cvss': v.get('cvssScore'),
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    except FileNotFoundError:
        print(f"Error: File not found - {report_path}")
        return []
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {report_path}")
        return []

def get_fixed_version(vuln):
    """Extract fixed version from Snyk vulnerability."""
    # Try fixedIn first
    if vuln.get('fixedIn'):
        return vuln['fixedIn'][0]
    
    # Try upgradePath
    upgrade_path = vuln.get('upgradePath', [])
    for version in reversed(upgrade_path):
        if version and version != False:
            return version
    
    return "No fix available"

def format_sca_simple(v, idx):
    """Format a single SCA vulnerability in simplified format."""
    severity_emoji = {
        'CRITICAL': '****',
        'HIGH': '***',
        'MEDIUM': '**',
        'LOW': '*',
        'UNKNOWN': '-'
    }
    
    emoji = severity_emoji.get(v['severity'], '-')
    cvss_str = f"{v['cvss']}" if v['cvss'] is not None else 'N/A'
    
    text = (
        f"[{idx}] {emoji} {v['severity']}\n"
        f"Package: {v['package']}\n"
        f"Current Version: {v['current_version']}\n"
        f"Fix Version: {v['recommended_version']}\n"
        f"Issue: {v['title']}\n"
        f"CVE: {v['cve']} | CVSS: {cvss_str}\n"
    )
    
    return text

def generate_summary(vulns):
    """Generate a summary of vulnerabilities by severity."""
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    for v in vulns:
        severity = v['severity']
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    summary = "=" * 60 + "\n"
    summary += "SECURITY VULNERABILITIES SUMMARY\n"
    summary += "=" * 60 + "\n"
    summary += f"Total Vulnerabilities: {len(vulns)}\n"
    summary += f"  **** Critical: {severity_counts['CRITICAL']}\n"
    summary += f"  *** High: {severity_counts['HIGH']}\n"
    summary += f"  ** Medium: {severity_counts['MEDIUM']}\n"
    summary += f"  * Low: {severity_counts['LOW']}\n"
    summary += "=" * 60 + "\n\n"
    
    return summary

def prepare_sca_text(report_path: str, out_path: str):
    """Main function to parse Snyk report and generate simplified LLM-ready text."""
    vulns = parse_snyk_report(report_path)
    
    if not vulns:
        output = "No SCA vulnerabilities found.\n"
    else:
        # Sort by severity (Critical -> High -> Medium -> Low)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
        vulns.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        # Generate output
        parts = [generate_summary(vulns)]
        
        for i, v in enumerate(vulns, 1):
            parts.append(format_sca_simple(v, i))
            parts.append("\n")
        
        output = "".join(parts)
    
    # Write to file
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(output, encoding="utf-8")
    
    # Print summary to console
    print(f"[OK] SCA report generated: {out_path}")
    print(f"     Total vulnerabilities: {len(vulns)}")
    if vulns:
        severity_counts = {}
        for v in vulns:
            severity_counts[v['severity']] = severity_counts.get(v['severity'], 0) + 1
        for severity, count in sorted(severity_counts.items()):
            print(f"     {severity}: {count}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python parsca.py <sca-raw.json> <out.txt>")
        sys.exit(1)
    prepare_sca_text(sys.argv[1], sys.argv[2])
