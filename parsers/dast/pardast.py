"""
Prépare un .txt lisible par LLM depuis un rapport DAST (OWASP ZAP, etc.).
Usage:
    python pardast.py <report.json> <out.txt>
"""
import sys
import json
from pathlib import Path

MAX_CHARS_PER_ITEM = 5000

def parse_zap_json(report_path: str):
    """
    Parse OWASP ZAP JSON format
    Returns list of vulnerabilities in standard format
    """
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to parse JSON: {e}")
        return []
    
    vulns = []
    
    # ZAP format: site -> alerts
    sites = data.get('site', [])
    for site in sites:
        alerts = site.get('alerts', [])
        for alert in alerts:
            vuln = {
                'type': 'DAST',
                'title': alert.get('alert', 'Unknown vulnerability'),
                'description': alert.get('desc', ''),
                'location': alert.get('instances', [{}])[0].get('uri', 'N/A') if alert.get('instances') else 'N/A',
                'recommendation': alert.get('solution', 'Vérifier la configuration et corriger la vulnérabilité.'),
                'severity': alert.get('riskdesc', 'Unknown'),
                'confidence': alert.get('confidence', 'Unknown'),
                'cweid': alert.get('cweid', 'N/A'),
                'wascid': alert.get('wascid', 'N/A')
            }
            vulns.append(vuln)
    
    return vulns

def format_dast(v, idx):
    """Format a single DAST vulnerability for LLM"""
    title = v.get("title") or v.get("id") or "DAST finding"
    desc = (v.get("description") or "").strip()
    uri = v.get("location") or "N/A"
    rec = v.get("recommendation") or "Vérifier la configuration et corriger la vulnérabilité."
    severity = v.get("severity", "Unknown")
    confidence = v.get("confidence", "Unknown")
    
    text = (
        f"--- DAST Finding #{idx} ---\n"
        f"Vulnerability: {title}\n"
        f"Severity: {severity}\n"
        f"Confidence: {confidence}\n"
        f"Target (URL/Endpoint): {uri}\n"
        f"Description: {desc}\n"
        f"Recommendation: {rec}\n"
    )
    
    # Add CWE/WASC if available
    if v.get("cweid") and v.get("cweid") != "N/A":
        text += f"CWE ID: {v.get('cweid')}\n"
    if v.get("wascid") and v.get("wascid") != "N/A":
        text += f"WASC ID: {v.get('wascid')}\n"
    
    if len(text) > MAX_CHARS_PER_ITEM:
        text = text[:MAX_CHARS_PER_ITEM-12] + "\n[...truncated]\n"
    return text

def prepare_dast_text(report_path: str, out_path: str):
    """Main function to parse DAST report and generate LLM-friendly text"""
    # Parse the ZAP JSON report
    vulns = parse_zap_json(report_path)
    
    header = "Résumé DAST — tests dynamiques (formaté pour LLM)\n"
    header += "Source: OWASP ZAP Baseline Scan\n\n"
    
    parts = [header]
    
    if not vulns:
        parts.append("Aucune vulnérabilité DAST trouvée.\n")
        parts.append("L'application a passé le scan dynamique de base avec succès.\n")
    else:
        parts.append(f"Total des vulnérabilités trouvées: {len(vulns)}\n\n")
        for i, v in enumerate(vulns, 1):
            parts.append(format_dast(v, i))
            parts.append("\n")
    
    # Create output directory if needed
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Write the output
    Path(out_path).write_text("".join(parts), encoding="utf-8")
    print(f"[OK] DAST .txt généré: {out_path}")
    print(f"[INFO] Nombre de vulnérabilités: {len(vulns)}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python pardast.py <dast_report.json> <out.txt>")
        sys.exit(1)
    
    report_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Check if report exists
    if not Path(report_file).exists():
        print(f"[ERROR] Report file not found: {report_file}")
        sys.exit(1)
    
    prepare_dast_text(report_file, output_file)