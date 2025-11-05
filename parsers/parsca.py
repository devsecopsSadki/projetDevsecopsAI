# parsca.py
"""
Prépare un .txt lisible par LLM depuis un rapport SCA Snyk (dépendances).
Usage:
    python parsca.py <sca-raw.json> <out.txt>
"""
import sys
import json
from pathlib import Path

MAX_CHARS_PER_ITEM = 5000

def parse_snyk_report(report_path: str):
    """Parse raw Snyk JSON report and extract vulnerabilities."""
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        vulnerabilities = []
        snyk_vulns = data.get('vulnerabilities', [])
        
        for v in snyk_vulns:
            vuln = {
                'type': 'SCA',
                'location': f"{v.get('packageName', 'unknown')}@{v.get('version', 'unknown')}",
                'title': v.get('title', 'No title'),
                'description': v.get('description', ''),
                'cve': v.get('identifiers', {}).get('CVE', ['N/A'])[0] if v.get('identifiers', {}).get('CVE') else 'N/A',
                'cvss': v.get('cvssScore'),
                'severity': v.get('severity', 'unknown'),
                'recommendation': get_recommendation(v)
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    except FileNotFoundError:
        print(f"Error: File not found - {report_path}")
        return []
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {report_path}")
        return []

def get_recommendation(vuln):
    """Extract upgrade recommendation from Snyk vulnerability."""
    # Try fixedIn first
    if vuln.get('fixedIn'):
        return f"Upgrade to version {vuln['fixedIn'][0]}"
    
    # Try upgradePath
    upgrade_path = vuln.get('upgradePath', [])
    for version in reversed(upgrade_path):
        if version and version != False:
            return f"Upgrade to version {version}"
    
    return "Mettre à jour le package ou appliquer le correctif recommandé."

def format_sca(v, idx):
    """Format a single SCA vulnerability for LLM."""
    pkg_loc = v.get('location', 'package@version')
    title = v.get('title', pkg_loc)
    desc = (v.get('description') or '').strip()
    cve = v.get('cve', 'N/A')
    cvss = v.get('cvss')
    cvss_str = str(cvss) if cvss is not None else 'N/A'
    severity = v.get('severity', 'unknown')
    rec = v.get('recommendation', 'Mettre à jour le package ou appliquer le correctif recommandé.')
    
    text = (
        f"--- Dependency Finding #{idx} ---\n"
        f"Package: {pkg_loc}\n"
        f"Title: {title}\n"
        f"Severity: {severity}\n"
        f"CVE: {cve}\n"
        f"CVSS: {cvss_str}\n"
        f"Description: {desc}\n"
        f"Recommendation: {rec}\n"
    )
    
    if len(text) > MAX_CHARS_PER_ITEM:
        text = text[:MAX_CHARS_PER_ITEM-12] + "\n[...truncated]\n"
    
    return text

def prepare_sca_text(report_path: str, out_path: str):
    """Main function to parse Snyk report and generate LLM-ready text."""
    vulns = parse_snyk_report(report_path)
    
    header = "Résumé SCA — vulnérabilités de dépendances (formaté pour LLM)\n\n"
    parts = [header]
    
    if not vulns:
        parts.append("Aucune vulnérabilité SCA trouvée.\n")
    else:
        for i, v in enumerate(vulns, 1):
            parts.append(format_sca(v, i))
            parts.append("\n")
    
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text("".join(parts), encoding="utf-8")
    print(f"[OK] SCA .txt généré: {out_path} ({len(vulns)} vulnérabilités)")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python parsca.py <sca-raw.json> <out.txt>")
        sys.exit(1)
    prepare_sca_text(sys.argv[1], sys.argv[2])
